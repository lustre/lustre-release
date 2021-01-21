/*
 * Copyright (C) 2012 Cray, Inc.
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 *   Author: Nic Henke <nic@cray.com>
 *   Author: James Shimek <jshimek@cray.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "gnilnd.h"
#include <linux/swap.h>

void
kgnilnd_setup_smsg_attr(gni_smsg_attr_t *smsg_attr)
{
	smsg_attr->mbox_maxcredit = *kgnilnd_tunables.kgn_mbox_credits;
	smsg_attr->msg_maxsize = GNILND_MAX_MSG_SIZE;
	smsg_attr->msg_type = GNI_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
}

int
kgnilnd_map_fmablk(kgn_device_t *device, kgn_fma_memblock_t *fma_blk)
{
	gni_return_t            rrc;
	__u32                   flags = GNI_MEM_READWRITE;
	static unsigned long    reg_to;
	int                     rfto = *kgnilnd_tunables.kgn_reg_fail_timeout;

	if (fma_blk->gnm_state == GNILND_FMABLK_PHYS) {
		flags |= GNI_MEM_PHYS_CONT;
	}

	fma_blk->gnm_hold_timeout = 0;

	/* make sure we are mapping a clean block */
	LASSERTF(fma_blk->gnm_hndl.qword1 == 0UL, "fma_blk %p dirty\n", fma_blk);

	rrc = kgnilnd_mem_register(device->gnd_handle, (__u64)fma_blk->gnm_block,
				   fma_blk->gnm_blk_size, device->gnd_rcv_fma_cqh,
				   flags, &fma_blk->gnm_hndl);
	if (rrc != GNI_RC_SUCCESS) {
		if (rfto != GNILND_REGFAILTO_DISABLE) {
			if (reg_to == 0) {
				reg_to = jiffies + cfs_time_seconds(rfto);
			} else if (time_after(jiffies, reg_to)) {
				CERROR("FATAL:fmablk registration has failed "
				       "for %ld seconds.\n",
				       cfs_duration_sec(jiffies - reg_to) +
						rfto);
				LBUG();
			}
		}

		CNETERR("register fmablk failed 0x%p mbox_size %d flags %u\n",
			fma_blk, fma_blk->gnm_mbox_size, flags);
		RETURN(-ENOMEM);
	}

	reg_to = 0;

	/* PHYS_CONT memory isn't really mapped, at least not in GART -
	 *  but all mappings chew up a MDD
	 */
	if (fma_blk->gnm_state != GNILND_FMABLK_PHYS) {
		atomic64_add(fma_blk->gnm_blk_size, &device->gnd_nbytes_map);
	}

	atomic_inc(&device->gnd_n_mdd);
	/* nfmablk is live (mapped) blocks */
	atomic_inc(&device->gnd_nfmablk);

	RETURN(0);
}

int
kgnilnd_alloc_fmablk(kgn_device_t *device, int use_phys)
{
	int                     rc = 0;
	int                     num_mbox;
	kgn_fma_memblock_t     *fma_blk;
	gni_smsg_attr_t         smsg_attr;
	unsigned long           fmablk_vers;

#if defined(CONFIG_CRAY_XT) && !defined(CONFIG_CRAY_COMPUTE)
	/* We allocate large blocks of memory here potentially leading
	 * to memory exhaustion during massive reconnects during a network
	 * outage. Limit the amount of fma blocks to use by always keeping
	 * a percent of pages free initially set to 25% of total memory. */
	if (nr_free_pages() < kgnilnd_data.free_pages_limit) {
		LCONSOLE_INFO("Exceeding free page limit of %ld. "
			      "Free pages available %ld\n",
			      kgnilnd_data.free_pages_limit,
			      nr_free_pages());
		return -ENOMEM;
	}
#endif
	/* we'll use fmablk_vers and the gnd_fmablk_mutex to gate access
	 * to this allocation code. Everyone will sample the version
	 * before and after getting the mutex. If it has changed,
	 * we'll bail out to check the lists again - this indicates that
	 * some sort of change was made to the lists and it is possible
	 * that there is a mailbox for us to find now. This should prevent
	 * a ton of spinning in the case where there are lots of threads
	 * that need a yet-to-be-allocated mailbox for a connection. */

	fmablk_vers = atomic_read(&device->gnd_fmablk_vers);
	mutex_lock(&device->gnd_fmablk_mutex);

	if (fmablk_vers != atomic_read(&device->gnd_fmablk_vers)) {
		/* version changed while we were waiting for semaphore,
		 * we'll recheck the lists assuming something nice happened */
		mutex_unlock(&device->gnd_fmablk_mutex);
		return 0;
	}

	LIBCFS_ALLOC(fma_blk, sizeof(kgn_fma_memblock_t));
	if (fma_blk == NULL) {
		CNETERR("could not allocate fma block descriptor\n");
		rc = -ENOMEM;
		GOTO(out, rc);
	}

	INIT_LIST_HEAD(&fma_blk->gnm_bufflist);

	kgnilnd_setup_smsg_attr(&smsg_attr);

	gni_smsg_buff_size_needed(&smsg_attr, &fma_blk->gnm_mbox_size);

	LASSERTF(fma_blk->gnm_mbox_size, "mbox size %d\n", fma_blk->gnm_mbox_size);

	/* gni_smsg_buff_size_needed calculates the base mailbox size and since
	 * we want to hold kgn_peer_credits worth of messages in both directions,
	 * we add PAYLOAD to grow the mailbox size
	 */

	fma_blk->gnm_mbox_size += GNILND_MBOX_PAYLOAD;

	/* we'll only use physical during preallocate at startup -- this keeps it nice and
	 * clean for runtime decisions. We'll keep the PHYS ones around until shutdown
	 * as reallocating them is tough if there is memory fragmentation */

	if (use_phys) {
		fma_blk->gnm_block = kmem_cache_alloc(kgnilnd_data.kgn_mbox_cache, GFP_ATOMIC);
		if (fma_blk->gnm_block == NULL) {
			CNETERR("could not allocate physical SMSG mailbox memory\n");
			rc = -ENOMEM;
			GOTO(free_desc, rc);
		}
		fma_blk->gnm_blk_size = GNILND_MBOX_SIZE;
		num_mbox = fma_blk->gnm_blk_size / fma_blk->gnm_mbox_size;

		LASSERTF(num_mbox >= 1,
			 "num_mbox %d blk_size %u mbox_size %d\n",
			  num_mbox, fma_blk->gnm_blk_size, fma_blk->gnm_mbox_size);

		fma_blk->gnm_state = GNILND_FMABLK_PHYS;

	} else {
		num_mbox = *kgnilnd_tunables.kgn_mbox_per_block;
		fma_blk->gnm_blk_size = num_mbox * fma_blk->gnm_mbox_size;

		LASSERTF(num_mbox >= 1 && num_mbox >= *kgnilnd_tunables.kgn_mbox_per_block,
			 "num_mbox %d blk_size %u mbox_size %d tunable %d\n",
			 num_mbox, fma_blk->gnm_blk_size, fma_blk->gnm_mbox_size,
			 *kgnilnd_tunables.kgn_mbox_per_block);

		fma_blk->gnm_block = kgnilnd_vzalloc(fma_blk->gnm_blk_size);
		if (fma_blk->gnm_block == NULL) {
			CNETERR("could not allocate virtual SMSG mailbox memory, %d bytes\n", fma_blk->gnm_blk_size);
			rc = -ENOMEM;
			GOTO(free_desc, rc);
		}

		fma_blk->gnm_state = GNILND_FMABLK_VIRT;
	}

	/* allocate just enough space for the bits to track the mailboxes */
	CFS_ALLOC_PTR_ARRAY(fma_blk->gnm_bit_array, BITS_TO_LONGS(num_mbox));
	if (fma_blk->gnm_bit_array == NULL) {
		CNETERR("could not allocate mailbox bitmask, %lu bytes for %d mbox\n",
		       sizeof(unsigned long) * BITS_TO_LONGS(num_mbox), num_mbox);
		rc = -ENOMEM;
		GOTO(free_blk, rc);
	}
	bitmap_zero(fma_blk->gnm_bit_array, num_mbox);

	/* now that the num_mbox is set based on allocation type, get debug
	 * info setup
	 * */
	CFS_ALLOC_PTR_ARRAY(fma_blk->gnm_mbox_info, num_mbox);
	if (fma_blk->gnm_mbox_info == NULL) {
		CNETERR("could not allocate mailbox debug, %lu bytes for %d mbox\n",
		       sizeof(kgn_mbox_info_t) * num_mbox, num_mbox);
		rc = -ENOMEM;
		GOTO(free_bit, rc);
	}

	rc = kgnilnd_map_fmablk(device, fma_blk);
	if (rc) {
		GOTO(free_info, rc);
	}

	fma_blk->gnm_next_avail_mbox = 0;
	fma_blk->gnm_avail_mboxs = fma_blk->gnm_num_mboxs = num_mbox;

	CDEBUG(D_MALLOC, "alloc fmablk 0x%p num %d msg_maxsize %d credits %d "
		"mbox_size %d MDD %#llx.%#llx\n",
		fma_blk, num_mbox, smsg_attr.msg_maxsize, smsg_attr.mbox_maxcredit,
		fma_blk->gnm_mbox_size, fma_blk->gnm_hndl.qword1,
		fma_blk->gnm_hndl.qword2);

	/* lock Is protecting data structures, not semaphore */

	spin_lock(&device->gnd_fmablk_lock);
	list_add_tail(&fma_blk->gnm_bufflist, &device->gnd_fma_buffs);

	/* toggle under the lock so once they change the list is also
	 * ready for others to traverse */
	atomic_inc(&device->gnd_fmablk_vers);

	spin_unlock(&device->gnd_fmablk_lock);

	mutex_unlock(&device->gnd_fmablk_mutex);

	return 0;

free_info:
	CFS_FREE_PTR_ARRAY(fma_blk->gnm_mbox_info, num_mbox);
free_bit:
	CFS_FREE_PTR_ARRAY(fma_blk->gnm_bit_array, BITS_TO_LONGS(num_mbox));
free_blk:
	if (fma_blk->gnm_state == GNILND_FMABLK_VIRT) {
		kgnilnd_vfree(fma_blk->gnm_block, fma_blk->gnm_blk_size);
	} else {
		kmem_cache_free(kgnilnd_data.kgn_mbox_cache, fma_blk->gnm_block);
	}
free_desc:
	LIBCFS_FREE(fma_blk, sizeof(kgn_fma_memblock_t));
out:
	mutex_unlock(&device->gnd_fmablk_mutex);
	return rc;
}

void
kgnilnd_unmap_fmablk(kgn_device_t *dev, kgn_fma_memblock_t *fma_blk)
{
	gni_return_t            rrc;

	/* if some held, set hold_timeout from conn timeouts used in this block
	 * but not during shutdown, then just nuke and pave
	 * During a stack reset, we need to deregister with a hold timeout
	 * set so we don't use the same mdd after reset is complete */
	if ((fma_blk->gnm_held_mboxs && !kgnilnd_data.kgn_shutdown) ||
	    kgnilnd_data.kgn_in_reset) {
		fma_blk->gnm_hold_timeout = GNILND_TIMEOUT2DEADMAN;
	}

	/* we are changing the state of a block, tickle version to tell
	 * proc code list is stale now */
	atomic_inc(&dev->gnd_fmablk_vers);

	rrc = kgnilnd_mem_deregister(dev->gnd_handle, &fma_blk->gnm_hndl, fma_blk->gnm_hold_timeout);

	CDEBUG(rrc == GNI_RC_SUCCESS ? D_MALLOC : D_CONSOLE|D_NETERROR,
	       "unmap fmablk 0x%p@%s sz %u total %d avail %d held %d mbox_size %d "
		"hold_timeout %d\n",
	       fma_blk, kgnilnd_fmablk_state2str(fma_blk->gnm_state),
	       fma_blk->gnm_blk_size, fma_blk->gnm_num_mboxs,
	       fma_blk->gnm_avail_mboxs, fma_blk->gnm_held_mboxs,
	       fma_blk->gnm_mbox_size, fma_blk->gnm_hold_timeout);

	LASSERTF(rrc == GNI_RC_SUCCESS,
		"tried to double unmap or something bad, fma_blk %p (rrc %d)\n",
		fma_blk, rrc);

	if (fma_blk->gnm_hold_timeout &&
	    !(kgnilnd_data.kgn_in_reset &&
	      fma_blk->gnm_state == GNILND_FMABLK_PHYS)) {
		atomic_inc(&dev->gnd_n_mdd_held);
	} else {
		atomic_dec(&dev->gnd_n_mdd);
	}

	/* PHYS blocks don't get mapped */
	if (fma_blk->gnm_state != GNILND_FMABLK_PHYS) {
		atomic64_sub(fma_blk->gnm_blk_size, &dev->gnd_nbytes_map);
		fma_blk->gnm_state = GNILND_FMABLK_IDLE;
	} else if (kgnilnd_data.kgn_in_reset) {
		/* in stack reset, clear MDD handle for PHYS blocks, as we'll
		 * re-use the fma_blk after reset so we don't have to drop/allocate
		 * all of those physical blocks */
		fma_blk->gnm_hndl.qword1 = fma_blk->gnm_hndl.qword2 = 0UL;
	}

	/* Decrement here as this is the # of mapped blocks */
	atomic_dec(&dev->gnd_nfmablk);
}


/* needs lock on gnd_fmablk_lock to cover gnd_fma_buffs */
void
kgnilnd_free_fmablk_locked(kgn_device_t *dev, kgn_fma_memblock_t *fma_blk)
{
	LASSERTF(fma_blk->gnm_avail_mboxs == fma_blk->gnm_num_mboxs,
		 "fma_blk %p@%d free in bad state (%d): blk total %d avail %d held %d\n",
		 fma_blk, fma_blk->gnm_state, fma_blk->gnm_hold_timeout, fma_blk->gnm_num_mboxs,
		fma_blk->gnm_avail_mboxs, fma_blk->gnm_held_mboxs);

	atomic_inc(&dev->gnd_fmablk_vers);

	if (fma_blk->gnm_hold_timeout) {
		CDEBUG(D_MALLOC, "mdd release fmablk 0x%p sz %u avail %d held %d "
			"mbox_size %d\n",
			fma_blk, fma_blk->gnm_blk_size, fma_blk->gnm_avail_mboxs,
			fma_blk->gnm_held_mboxs, fma_blk->gnm_mbox_size);

		/* We leave MDD dangling over stack reset */
		if (!kgnilnd_data.kgn_in_reset) {
			kgnilnd_mem_mdd_release(dev->gnd_handle, &fma_blk->gnm_hndl);
		}
		/* ignoring the return code - if kgni/ghal can't find it
		 * it must be released already */
		atomic_dec(&dev->gnd_n_mdd_held);
		atomic_dec(&dev->gnd_n_mdd);
	}

	/* we cant' free the gnm_block until all the conns have released their
	 * purgatory holds. While we have purgatory holds, we might check the conn
	 * RX mailbox during the CLOSING process. It is possible that kgni might
	 * try to look into the RX side for credits when sending the CLOSE msg too */
	CDEBUG(D_MALLOC, "fmablk %p free buffer %p mbox_size %d\n",
		fma_blk, fma_blk->gnm_block, fma_blk->gnm_mbox_size);

	if (fma_blk->gnm_state == GNILND_FMABLK_PHYS) {
		kmem_cache_free(kgnilnd_data.kgn_mbox_cache, fma_blk->gnm_block);
	} else {
		kgnilnd_vfree(fma_blk->gnm_block, fma_blk->gnm_blk_size);
	}
	fma_blk->gnm_state = GNILND_FMABLK_FREED;

	list_del(&fma_blk->gnm_bufflist);

	CFS_FREE_PTR_ARRAY(fma_blk->gnm_mbox_info, fma_blk->gnm_num_mboxs);
	CFS_FREE_PTR_ARRAY(fma_blk->gnm_bit_array,
			   BITS_TO_LONGS(fma_blk->gnm_num_mboxs));
	LIBCFS_FREE(fma_blk, sizeof(kgn_fma_memblock_t));
}

void
kgnilnd_find_free_mbox(kgn_conn_t *conn)
{
	kgn_device_t            *dev = conn->gnc_device;
	gni_smsg_attr_t         *smsg_attr = &conn->gnpr_smsg_attr;
	kgn_fma_memblock_t      *fma_blk;
	kgn_mbox_info_t         *mbox = NULL;
	int                     id;

	spin_lock(&dev->gnd_fmablk_lock);

	list_for_each_entry(fma_blk, &conn->gnc_device->gnd_fma_buffs,
			    gnm_bufflist) {
		if (fma_blk->gnm_avail_mboxs <= 0 ||
		    fma_blk->gnm_state <= GNILND_FMABLK_IDLE) {
			continue;
		}
		/* look in bitarray for available mailbox */
		do {
			id = find_next_zero_bit(
				fma_blk->gnm_bit_array,
				fma_blk->gnm_num_mboxs,
				fma_blk->gnm_next_avail_mbox);
		      if (id == fma_blk->gnm_num_mboxs &&
			  fma_blk->gnm_next_avail_mbox != 0) {
				/* wrap around */
				fma_blk->gnm_next_avail_mbox = 0;
			} else {
				break;
			}
		} while (1);

		LASSERTF(id < fma_blk->gnm_num_mboxs, "id %d max %d\n",
			 id, fma_blk->gnm_num_mboxs);
		set_bit(id, (volatile unsigned long *)fma_blk->gnm_bit_array);
		conn->gnc_mbox_id = id;

		fma_blk->gnm_next_avail_mbox =
			(id == (fma_blk->gnm_num_mboxs - 1)) ? 0 : (id + 1);
		fma_blk->gnm_avail_mboxs--;
		conn->gnc_fma_blk = fma_blk;

		kgnilnd_setup_smsg_attr(smsg_attr);

		smsg_attr->msg_buffer = fma_blk->gnm_block;
		smsg_attr->mbox_offset = fma_blk->gnm_mbox_size * id;
		smsg_attr->mem_hndl = fma_blk->gnm_hndl;
		smsg_attr->buff_size = fma_blk->gnm_mbox_size;

		/* We'll set the hndl to zero for PHYS blocks unmapped during stack
		 * reset and re-use the same fma_blk after stack reset. This ensures we've
		 * properly mapped it before we use it */
		LASSERTF(fma_blk->gnm_hndl.qword1 != 0UL, "unmapped fma_blk %p, state %d\n",
			 fma_blk, fma_blk->gnm_state);

		CDEBUG(D_NET, "conn %p smsg %p fmablk %p "
			"allocating SMSG mbox %d buf %p "
			"offset %u hndl %#llx.%#llx\n",
			conn, smsg_attr, fma_blk, id,
			smsg_attr->msg_buffer, smsg_attr->mbox_offset,
			fma_blk->gnm_hndl.qword1,
			fma_blk->gnm_hndl.qword2);

		mbox = &fma_blk->gnm_mbox_info[id];
		mbox->mbx_create_conn_memset = jiffies;
		mbox->mbx_nallocs++;
		mbox->mbx_nallocs_total++;

		/* zero mbox to remove any old data from our last use.
		 * this better be safe, if not our purgatory timers
		 * are too short or a peer really is misbehaving */
		memset(smsg_attr->msg_buffer + smsg_attr->mbox_offset,
		       0, smsg_attr->buff_size);
		break;
	}

	spin_unlock(&dev->gnd_fmablk_lock);
}

int
kgnilnd_setup_mbox(kgn_conn_t *conn)
{
	gni_smsg_attr_t         *smsg_attr = &conn->gnpr_smsg_attr;
	int                      err = 0;

	smsg_attr->msg_buffer = NULL;
	/* Look for available mbox */
	do {
		kgnilnd_find_free_mbox(conn);

		/* nothing in the existing buffers, make a new one */
		if (smsg_attr->msg_buffer == NULL) {
			/* for runtime allocations, we only want vmalloc */
			err = kgnilnd_alloc_fmablk(conn->gnc_device, 0);
			if (err) {
				break;
			}
		}
	} while (smsg_attr->msg_buffer == NULL);

	if (err)
		CNETERR("couldn't allocate SMSG mbox for conn %p Error: %d\n",
			conn, err);
	return err;
}

void
kgnilnd_release_mbox(kgn_conn_t *conn, int purgatory_hold)
{
	kgn_device_t           *dev = conn->gnc_device;
	gni_smsg_attr_t        *smsg_attr = &conn->gnpr_smsg_attr;
	kgn_fma_memblock_t     *fma_blk = NULL;
	kgn_mbox_info_t        *mbox = NULL;
	int                     found = 0;
	int                     id;

	/* if we failed to setup mbox and now destroying conn */
	if (smsg_attr->msg_buffer == NULL) {
		return;
	}

	id = conn->gnc_mbox_id;

	spin_lock(&dev->gnd_fmablk_lock);
	/* make sure our conn points at a valid fma_blk
	 * We use this instead of a mem block search out of smsg_attr
	 * because we could have freed a block for fma_blk #1 but the fma_blk
	 * is still in the list for a purgatory hold. This would induce a false
	 * match if that same block gets reallocated to fma_blk #2 */
	list_for_each_entry(fma_blk, &dev->gnd_fma_buffs, gnm_bufflist) {
		if (fma_blk == conn->gnc_fma_blk) {
			found = 1;
			break;
		}
	}
	LASSERTF(found, "unable to find conn 0x%p with gnc_fma_blk %p "
		 "anywhere in the world\n", conn, conn->gnc_fma_blk);

	LASSERTF(id < fma_blk->gnm_num_mboxs,
		"bad id %d max %d\n",
		id, fma_blk->gnm_num_mboxs);

	/* < 0 - was held, now free it
	 * == 0 - just free it
	 * > 0 - hold it for now */
	if (purgatory_hold == 0) {
		CDEBUG(D_NET, "conn %p smsg %p fmablk %p freeing SMSG mbox %d "
			"hndl %#llx.%#llx\n",
			conn, smsg_attr, fma_blk, id,
			fma_blk->gnm_hndl.qword1, fma_blk->gnm_hndl.qword2);
		fma_blk->gnm_avail_mboxs++;

	} else if (purgatory_hold > 0) {
		CDEBUG(D_NET, "conn %p smsg %p fmablk %p holding SMSG mbox %d "
			"hndl %#llx.%#llx\n",
			conn, smsg_attr, fma_blk, id,
			fma_blk->gnm_hndl.qword1, fma_blk->gnm_hndl.qword2);

		fma_blk->gnm_held_mboxs++;
		fma_blk->gnm_max_timeout = max_t(long, fma_blk->gnm_max_timeout,
						 conn->gnc_timeout);
	} else {
		CDEBUG(D_NET, "conn %p smsg %p fmablk %p release SMSG mbox %d "
			"hndl %#llx.%#llx\n",
			conn, smsg_attr, fma_blk, id,
			fma_blk->gnm_hndl.qword1, fma_blk->gnm_hndl.qword2);

		fma_blk->gnm_held_mboxs--;
		fma_blk->gnm_avail_mboxs++;
	}

	if (purgatory_hold <= 0) {
		/* if kgni is retransmitting, freeing the smsg block before the EP
		 * is destroyed gets messy. Bug 768295. */
		LASSERTF(conn->gnc_ephandle == NULL,
			 "can't release mbox before EP is nuked. conn 0x%p\n", conn);

		mbox = &fma_blk->gnm_mbox_info[id];
		mbox->mbx_release_from_purgatory = jiffies;

		/* clear conn gnc_fmablk if it is gone - this allows us to
		 * not worry about state so much in kgnilnd_destroy_conn
		 * and makes the guaranteed cleanup of the resources easier */
		LASSERTF(test_and_clear_bit(id, fma_blk->gnm_bit_array),
			"conn %p bit %d already cleared in fma_blk %p\n",
			 conn, id, fma_blk);
		conn->gnc_fma_blk = NULL;
		mbox->mbx_nallocs--;
	}

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_FMABLK_AVAIL)) {
		CERROR("LBUGs in your future: forcibly marking fma_blk %p "
		       "as mapped\n", fma_blk);
		fma_blk->gnm_state = GNILND_FMABLK_VIRT;
	}

	/* we don't release or unmap PHYS blocks as part of the normal cycle --
	 * those are controlled manually from startup/shutdown */
	if (fma_blk->gnm_state != GNILND_FMABLK_PHYS) {
		/* we can unmap once all are unused (held or avail)
		 * but check hold_timeout to make sure we are not trying to double
		 * unmap this buffer. If there was no hold_timeout set due to
		 * held_mboxs, we'll free the mobx here shortly and won't have to
		 * worry about catching a double free for a 'clean' fma_blk */
		if (((fma_blk->gnm_avail_mboxs + fma_blk->gnm_held_mboxs) == fma_blk->gnm_num_mboxs) &&
		    (!fma_blk->gnm_hold_timeout)) {
			kgnilnd_unmap_fmablk(dev, fma_blk);
		}

		/* But we can only free once they are all avail */
		if (fma_blk->gnm_avail_mboxs == fma_blk->gnm_num_mboxs &&
		    fma_blk->gnm_held_mboxs == 0) {
			/* all mailboxes are released, free fma_blk */
			kgnilnd_free_fmablk_locked(dev, fma_blk);
		}
	}

	spin_unlock(&dev->gnd_fmablk_lock);
}

int
kgnilnd_count_phys_mbox(kgn_device_t *device)
{
	int                     i = 0;
	kgn_fma_memblock_t     *fma_blk;

	spin_lock(&device->gnd_fmablk_lock);

	list_for_each_entry(fma_blk, &device->gnd_fma_buffs, gnm_bufflist) {
		if (fma_blk->gnm_state == GNILND_FMABLK_PHYS)
			i += fma_blk->gnm_num_mboxs;
	}
	spin_unlock(&device->gnd_fmablk_lock);

	RETURN(i);
}

int
kgnilnd_allocate_phys_fmablk(kgn_device_t *device)
{
	int     rc;

	while (kgnilnd_count_phys_mbox(device) < *kgnilnd_tunables.kgn_nphys_mbox) {

		rc = kgnilnd_alloc_fmablk(device, 1);
		if (rc) {
			CERROR("failed phys mbox allocation, stopping at %d, rc %d\n",
				kgnilnd_count_phys_mbox(device), rc);
			RETURN(rc);
		}
	}
	RETURN(0);
}

int
kgnilnd_map_phys_fmablk(kgn_device_t *device)
{

	int                     rc = 0;
	kgn_fma_memblock_t     *fma_blk;

	/* use mutex to gate access to single thread, just in case */
	mutex_lock(&device->gnd_fmablk_mutex);

	spin_lock(&device->gnd_fmablk_lock);

	list_for_each_entry(fma_blk, &device->gnd_fma_buffs, gnm_bufflist) {
		if (fma_blk->gnm_state == GNILND_FMABLK_PHYS) {
			rc = kgnilnd_map_fmablk(device, fma_blk);
			if (rc)
				break;
		}
	}
	spin_unlock(&device->gnd_fmablk_lock);

	mutex_unlock(&device->gnd_fmablk_mutex);

	RETURN(rc);
}

void
kgnilnd_unmap_fma_blocks(kgn_device_t *device)
{

	kgn_fma_memblock_t      *fma_blk;

	/* use mutex to gate access to single thread, just in case */
	mutex_lock(&device->gnd_fmablk_mutex);

	spin_lock(&device->gnd_fmablk_lock);

	list_for_each_entry(fma_blk, &device->gnd_fma_buffs, gnm_bufflist) {
		kgnilnd_unmap_fmablk(device, fma_blk);
	}
	spin_unlock(&device->gnd_fmablk_lock);

	mutex_unlock(&device->gnd_fmablk_mutex);
}

void
kgnilnd_free_phys_fmablk(kgn_device_t *device)
{

	kgn_fma_memblock_t      *fma_blk, *fma_blkN;

	/* use mutex to gate access to single thread, just in case */
	mutex_lock(&device->gnd_fmablk_mutex);

	spin_lock(&device->gnd_fmablk_lock);

	list_for_each_entry_safe(fma_blk, fma_blkN, &device->gnd_fma_buffs, gnm_bufflist) {
		if (fma_blk->gnm_state == GNILND_FMABLK_PHYS)
			kgnilnd_free_fmablk_locked(device, fma_blk);
	}
	spin_unlock(&device->gnd_fmablk_lock);

	mutex_unlock(&device->gnd_fmablk_mutex);
}

/* kgnilnd dgram nid->struct managment */

static inline struct list_head *
kgnilnd_nid2dgramlist(kgn_device_t *dev, lnet_nid_t nid)
{
	unsigned int hash = ((unsigned int)nid) % *kgnilnd_tunables.kgn_peer_hash_size;

	RETURN(&dev->gnd_dgrams[hash]);
}


/* needs dev->gnd_dgram_lock held */
kgn_dgram_t *
kgnilnd_find_dgram_locked(kgn_device_t *dev, lnet_nid_t dst_nid)
{
	struct list_head *dgram_list = kgnilnd_nid2dgramlist(dev, dst_nid);
	kgn_dgram_t      *dgram;

	list_for_each_entry(dgram, dgram_list, gndg_list) {

		/* if state > POSTED, we are already handling cancel/completion */
		if ((dgram->gndg_conn_out.gncr_dstnid != dst_nid) ||
		     dgram->gndg_state > GNILND_DGRAM_POSTED)
			continue;

		CDEBUG(D_NET, "got dgram [%p] -> %s\n",
		       dgram, libcfs_nid2str(dst_nid));
		return dgram;
	}
	return NULL;
}

int
kgnilnd_find_and_cancel_dgram(kgn_device_t *dev, lnet_nid_t dst_nid)
{
	kgn_dgram_t     *dgram;

	spin_lock(&dev->gnd_dgram_lock);
	dgram = kgnilnd_find_dgram_locked(dev, dst_nid);

	if (dgram) {
		kgnilnd_cancel_dgram_locked(dgram);
	}
	spin_unlock(&dev->gnd_dgram_lock);

	RETURN(!!(dgram == NULL));
}

int
kgnilnd_pack_connreq(kgn_connreq_t *connreq, kgn_conn_t *conn,
		     lnet_nid_t srcnid, lnet_nid_t dstnid,
		     kgn_connreq_type_t type)
{
	int err = 0;

	/* ensure we haven't violated max datagram size */
	BUILD_BUG_ON(sizeof(kgn_connreq_t) > GNI_DATAGRAM_MAXSIZE);

	/* no need to zero out, we do that when allocating dgram */
	connreq->gncr_magic     = GNILND_MSG_MAGIC;

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PACK_SRCNID)) {
		srcnid = 0xABADBABE;
	} else if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PACK_DSTNID)) {
		dstnid = 0xDEFEC8ED;
	}

	connreq->gncr_srcnid    = srcnid;
	connreq->gncr_dstnid    = dstnid;

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CONNREQ_PROTO)) {
		connreq->gncr_version = 99;
	} else {
		connreq->gncr_version   = GNILND_CONNREQ_VERSION;
	}
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CONNREQ_PROTO)) {
		connreq->gncr_type = 99;
	} else {
		connreq->gncr_type      = type;
	}
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CONNREQ_PROTO)) {
		connreq->gncr_peerstamp = 0;
	} else {
		connreq->gncr_peerstamp = kgnilnd_data.kgn_peerstamp;
	}
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CONNREQ_PROTO)) {
		connreq->gncr_connstamp = 0;
	} else {
		connreq->gncr_connstamp = conn->gnc_my_connstamp;
	}
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CONNREQ_PROTO)) {
		connreq->gncr_timeout = 0;
	} else {
		connreq->gncr_timeout   = conn->gnc_timeout;
	}

	/* the rest pack the data into the payload in other places */
	if (type == GNILND_CONNREQ_REQ) {
		kgn_gniparams_t       *req_params = &connreq->gncr_gnparams;
		req_params->gnpr_host_id = conn->gnc_device->gnd_host_id;
		req_params->gnpr_cqid = conn->gnc_cqid;

		/* allocate mailbox for this connection */
		err = kgnilnd_setup_mbox(conn);
		if (err != 0) {
			CERROR("Failed to setup FMA mailbox (%d)\n", err);
		}
		req_params->gnpr_smsg_attr = conn->gnpr_smsg_attr;
	}

	/* XXX Nic: TBD - checksum computation */

	return err;
}

int
kgnilnd_unpack_connreq(kgn_dgram_t *dgram)
{
	kgn_connreq_t           *connreq = &dgram->gndg_conn_in;
	int                      swab, rc = 0;
	kgn_net_t               *net;

	/* the following fields must be handled in a backwards compatible
	 * manner to ensure we can always send and interpret NAKs */

	if (connreq->gncr_magic != GNILND_MSG_MAGIC &&
	    connreq->gncr_magic != __swab32(GNILND_MSG_MAGIC)) {
		/* Unexpected magic! */
		CERROR("Unexpected magic %08x\n",
		       connreq->gncr_magic);
		return -EBADF;
	}

	swab = (connreq->gncr_magic == __swab32(GNILND_MSG_MAGIC));
	if (swab) {
		__swab32s(&connreq->gncr_magic);
		__swab32s(&connreq->gncr_cksum);
		__swab16s(&connreq->gncr_type);
		__swab16s(&connreq->gncr_version);
		__swab32s(&connreq->gncr_timeout);
		__swab64s(&connreq->gncr_srcnid);
		__swab64s(&connreq->gncr_dstnid);
		__swab64s(&connreq->gncr_peerstamp);
		__swab64s(&connreq->gncr_connstamp);
	}

	/* Do NOT return anything but -EBADF before we munge
	 * connreq->gncr_srcnid - we need that to send the nak */

	if (dgram->gndg_conn_out.gncr_dstnid != LNET_NID_ANY) {
		lnet_nid_t      incoming = connreq->gncr_srcnid;

		/* even if the incoming packet is hosed, we know who we sent
		 * the original and can set the srcnid so that we can properly
		 * look up our peer to close the loop on this connreq. We still use
		 * -EBADF to prevent a NAK - just in case there are issues with
		 * the payload coming from a random spot, etc. */
		connreq->gncr_srcnid = dgram->gndg_conn_out.gncr_dstnid;

		if (LNET_NIDADDR(dgram->gndg_conn_out.gncr_dstnid) !=
				LNET_NIDADDR(incoming)) {
			/* we got a datagram match for the wrong nid... */
			CERROR("matched datagram 0x%p with srcnid %s "
				"(%x), expecting %s (%x)\n",
				dgram,
				libcfs_nid2str(incoming),
				LNET_NIDADDR(incoming),
				libcfs_nid2str(dgram->gndg_conn_out.gncr_dstnid),
				LNET_NIDADDR(dgram->gndg_conn_out.gncr_dstnid));
			return -EBADF;
		}
	} else {
		/* if we have a wildcard datagram it should match an
		 * incoming "active" datagram that should have a fully formed
		 * srcnid and dstnid. If we couldn't unpack it, we drop as
		 * corrupted packet, otherwise we'll just verify that the dstnid
		 * matches the NID for the NET that the dgram was posted */

		/* make sure their wildcard didn't match ours, that is unpossible */
		LASSERTF(connreq->gncr_dstnid != LNET_NID_ANY,
			 "dgram 0x%p from %s, connreq 0x%p; "
			 "wildcard matched wildcard \n", dgram,
			 libcfs_nid2str(connreq->gncr_srcnid), connreq);

		rc = kgnilnd_find_net(connreq->gncr_dstnid, &net);

		if (rc == -ESHUTDOWN) {
			CERROR("Looking up network: device is in shutdown\n");
			return rc;
		} else if (rc == -ENONET) {
			CERROR("Connection data from %s: she sent "
			"dst_nid %s, but net lookup failed on "
			"dgram 0x%p@%s\n",
			libcfs_nid2str(connreq->gncr_srcnid),
			libcfs_nid2str(connreq->gncr_dstnid),
			dgram, kgnilnd_dgram_type2str(dgram));
			return rc;
		}

		if (net->gnn_ni->ni_nid != connreq->gncr_dstnid) {
			CERROR("Bad connection data from %s: she sent "
			       "dst_nid %s, but I am %s with dgram 0x%p@%s\n",
			       libcfs_nid2str(connreq->gncr_srcnid),
			       libcfs_nid2str(connreq->gncr_dstnid),
			       libcfs_nid2str(net->gnn_ni->ni_nid),
			       dgram, kgnilnd_dgram_type2str(dgram));
			kgnilnd_net_decref(net);
			return -EBADSLT;
		}

		/* kgnilnd_find_net takes a ref on the net it finds, You need to decref it when not needed. */
		kgnilnd_net_decref(net);
	}

	if (connreq->gncr_version != GNILND_CONNREQ_VERSION) {
		CERROR("Unexpected version %d\n", connreq->gncr_version);
		return -EPROTO;
	}

	/* XXX Nic: TBD - checksum validation */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CONNREQ_DROP)) {
		return -EBADF;
	}

	if (swab && connreq->gncr_type == GNILND_CONNREQ_REQ) {
		__u64 msg_addr = (__u64) connreq->gncr_gnparams.gnpr_smsg_attr.msg_buffer;

		__swab32s(&connreq->gncr_gnparams.gnpr_host_id);
		__swab32s(&connreq->gncr_gnparams.gnpr_cqid);
		__swab32s(&connreq->gncr_gnparams.gnpr_smsg_attr.buff_size);
		__swab16s(&connreq->gncr_gnparams.gnpr_smsg_attr.mbox_maxcredit);
		__swab32s(&connreq->gncr_gnparams.gnpr_smsg_attr.mbox_offset);
		__swab64s(&connreq->gncr_gnparams.gnpr_smsg_attr.mem_hndl.qword1);
		__swab64s(&connreq->gncr_gnparams.gnpr_smsg_attr.mem_hndl.qword2);
		__swab64s(&msg_addr);
		__swab32s(&connreq->gncr_gnparams.gnpr_smsg_attr.msg_maxsize);
		__swab32s(&connreq->gncr_gnparams.gnpr_smsg_attr.msg_type);
	} else if (swab && connreq->gncr_type == GNILND_CONNREQ_NAK) {
		__swab32s(&connreq->gncr_nakdata.gnnd_errno);
	}

	/* since we use a unique instance ID for each network, the driver
	 * will take care of dropping datagrams if we don't have that network.
	 */

	/* few more idiot software or configuration checks */

	switch (connreq->gncr_type) {
	case GNILND_CONNREQ_REQ:
		/* wire up EP and SMSG block - this will check the incoming data
		 * and barf a NAK back if need to */
		rc = kgnilnd_set_conn_params(dgram);
		if (rc)
			return rc;
		break;
	case GNILND_CONNREQ_NAK:
	case GNILND_CONNREQ_CLOSE:
		break;
	default:
		CERROR("unknown connreq packet type %d\n", connreq->gncr_type);
		return -EPROTO;
	}

	if (connreq->gncr_peerstamp == 0 || connreq->gncr_connstamp == 0) {
		CERROR("Recived bad timestamps peer %llu conn %llu\n",
		connreq->gncr_peerstamp, connreq->gncr_connstamp);
		return -EPROTO;
	}

	if (connreq->gncr_timeout < GNILND_MIN_TIMEOUT) {
		CERROR("Received timeout %d < MIN %d\n",
		       connreq->gncr_timeout, GNILND_MIN_TIMEOUT);
		return -EPROTO;
	}

	return 0;
}

int
kgnilnd_alloc_dgram(kgn_dgram_t **dgramp, kgn_device_t *dev, kgn_dgram_type_t type)
{
	kgn_dgram_t         *dgram;

	dgram = kmem_cache_zalloc(kgnilnd_data.kgn_dgram_cache, GFP_ATOMIC);
	if (dgram == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&dgram->gndg_list);
	dgram->gndg_state = GNILND_DGRAM_USED;
	dgram->gndg_type = type;
	dgram->gndg_magic = GNILND_DGRAM_MAGIC;

	atomic_inc(&dev->gnd_ndgrams);

	CDEBUG(D_MALLOC|D_NETTRACE, "slab-alloced 'dgram': %lu at %p %s ndgrams"
		" %d\n",
		sizeof(*dgram), dgram, kgnilnd_dgram_type2str(dgram),
		atomic_read(&dev->gnd_ndgrams));

	*dgramp = dgram;
	return 0;
}

/* call this on a dgram that came back from kgnilnd_ep_postdata_test_by_id
 * returns < 0 on dgram to be cleaned up
 * > 0 on dgram that isn't done yet
 * == 0 on dgram that is ok and needs connreq processing */
int
kgnilnd_process_dgram(kgn_dgram_t *dgram, gni_post_state_t post_state)
{
	int rc = 0;

	switch (post_state) {
	case GNI_POST_COMPLETED:
		/* normal state for dgrams that need actual processing */
		/* GOTO to avoid processing dgram as canceled/done */
		GOTO(process_out, rc);

	case GNI_POST_PENDING:
		/* we should only see this if we are testing a WC dgram after a
		 * cancel - it means that it needs a full cycle of waiting
		 * for kgni_sm_task to finish moving it to TERMINATED */
		LASSERTF((dgram->gndg_type == GNILND_DGRAM_WC_REQ) &&
			  (dgram->gndg_state == GNILND_DGRAM_CANCELED),
			 "POST_PENDING dgram 0x%p with bad type %d(%s) or state %d(%s)\n",
			 dgram, dgram->gndg_type, kgnilnd_dgram_type2str(dgram),
			 dgram->gndg_state, kgnilnd_dgram_state2str(dgram));

		/* positive RC as this dgram isn't done yet */
		rc = EINPROGRESS;

		/* GOTO as this isn't done yet */
		GOTO(process_out, rc);
		break;

	case GNI_POST_TERMINATED:
		/* we've called cancel and it is done or remote guy called cancel and
		 * we've receved it on a WC dgram */
#if 0
		/* we are seeing weird terminations on non WC dgrams when we have not
		 * canceled them */

		LASSERTF(dgram->gndg_state == GNILND_DGRAM_CANCELED ||
			 dgram->gndg_conn_out.gncr_dstnid == LNET_NID_ANY,
			"dgram 0x%p with bad state %d(%s) or dst nid %s\n",
			dgram, dgram->gndg_state, kgnilnd_dgram_state2str(dgram),
			libcfs_nid2str(dgram->gndg_conn_out.gncr_dstnid));
#endif

		CDEBUG(D_NETTRACE, "dgram 0x%p saw %s, cleaning it up\n", dgram,
		       dgram->gndg_state == GNILND_DGRAM_CANCELED ?  "canceled" : "terminated");

		rc =  -ECANCELED;
		break;

	case GNI_POST_TIMEOUT:
		/* we could have a timeout on a wildcard dgram too - if
		 * we got the incoming request but the remote node beefed
		 * before kgni could send the match data back. We'll just error
		 * on the active case and bail out gracefully */
		if (dgram->gndg_conn_out.gncr_dstnid != LNET_NID_ANY) {
			CNETERR("hardware timeout for connect to "
			       "%s after %lu seconds. Is node dead?\n",
			       libcfs_nid2str(dgram->gndg_conn_out.gncr_dstnid),
			       cfs_duration_sec(jiffies - dgram->gndg_post_time));
		}

		rc = -ETIMEDOUT;
		break;

	default:
		CERROR("dgram 0x%p with bad post_state %d\n", dgram, post_state);
		LBUG();
	}

	/* now finish cleaning up a dgram that is canceled/terminated and needs to
	 * go away */

	/* If this was actively canceled, drop the count now that we are processing */
	if (dgram->gndg_state == GNILND_DGRAM_CANCELED) {
		atomic_dec(&dgram->gndg_conn->gnc_device->gnd_canceled_dgrams);
		/* caller responsible for gndg_list removal */
	}

process_out:

	RETURN(rc);
}

/* needs dev->gnd_dgram_lock held */
void
kgnilnd_cancel_dgram_locked(kgn_dgram_t *dgram)
{
	gni_return_t            grc;

	if (dgram->gndg_state != GNILND_DGRAM_POSTED) {
		return;
	}

	LASSERTF(dgram->gndg_conn != NULL,
		 "dgram 0x%p with NULL conn\n", dgram);

	/* C.E - WC dgrams could be canceled immediately but
	 * if there was some match pending, we need to call
	 * test_by_id to clear it out. If that test returns
	 * POST_PENDING, it is half done and needs to go along
	 * with the rest of dgrams and go through a kgni_sm_task cycle
	 * and deliver a GNI_POST_TERMINATED event before they
	 * are actually canceled */

	dgram->gndg_state = GNILND_DGRAM_CANCELED;

	if (dgram->gndg_conn->gnc_state >= GNILND_CONN_ESTABLISHED) {
		/* we don't need to cancel_by_id if the datagram was good */
		return;
	}

	/* let folks know there are outstanding cancels */
	atomic_inc(&dgram->gndg_conn->gnc_device->gnd_canceled_dgrams);
	/* leave on nid list until cancel is done for debugging fun */
	grc = kgnilnd_ep_postdata_cancel_by_id(dgram->gndg_conn->gnc_ephandle, (__u64) dgram);

	/* if we don't get success here, we have hosed up the dgram tracking
	 * code and need to bail out */
	LASSERTF(grc == GNI_RC_SUCCESS,
		 "postdata_cancel returned %d for conn 0x%p to %s\n",
		 grc, dgram->gndg_conn,
		 dgram->gndg_conn->gnc_peer ?
		  libcfs_nid2str(dgram->gndg_conn->gnc_peer->gnp_nid)
		  : "<?>");

	CDEBUG(D_NETTRACE,
		"canceled dgram 0x%p conn 0x%p ephandle 0x%p\n",
		dgram, dgram->gndg_conn,
		dgram->gndg_conn->gnc_ephandle);

	if (dgram->gndg_type == GNILND_DGRAM_WC_REQ) {
		gni_post_state_t         post_state;
		int                      rc = 0;
		__u32                    remote_addr = 0, remote_id = 0;

		grc = kgnilnd_ep_postdata_test_by_id(dgram->gndg_conn->gnc_ephandle,
						     (__u64)dgram, &post_state,
						     &remote_addr, &remote_id);

		LASSERTF(grc == GNI_RC_NO_MATCH || grc == GNI_RC_SUCCESS,
			 "bad grc %d from test_by_id on dgram 0x%p\n",
			grc, dgram);

		/* if WC was canceled immediately, we get NO_MATCH, if needs to go
		 * through full cycle, we get SUCCESS and need to parse post_state */

		CDEBUG(D_NET, "grc %d dgram 0x%p type %s post_state %d "
			"remote_addr %u remote_id %u\n", grc, dgram,
			kgnilnd_dgram_type2str(dgram),
			post_state, remote_addr, remote_id);

		if (grc == GNI_RC_NO_MATCH) {
			/* she's gone, reduce count and move along */
			dgram->gndg_state = GNILND_DGRAM_DONE;
			atomic_dec(&dgram->gndg_conn->gnc_device->gnd_canceled_dgrams);
			RETURN_EXIT;
		}

		rc = kgnilnd_process_dgram(dgram, post_state);

		if (rc <= 0) {
			/* if for some weird reason we get a valid dgram back, just mark as done
			 * so we can drop it and move along.
			 * C.E - if it was completed, we'll just release the conn/mbox
			 * back into the pool and it'll get reused. That said, we should only
			 * be canceling a WC dgram on stack rest or shutdown, so that is moot */
			dgram->gndg_state = GNILND_DGRAM_DONE;
			atomic_dec(&dgram->gndg_conn->gnc_device->gnd_canceled_dgrams);

			/* caller context responsible for calling kgnilnd_release_dgram() */
		} else {
			/* still pending, let it simmer until golden brown and delicious */
		}
	}

	/* for non WC dgrams, they are still on the nid list but marked canceled waiting
	 * for kgni to return their ID to us via probe - that is when we'll complete their
	 * cancel processing */
}

void
kgnilnd_cleanup_dgram(kgn_dgram_t *dgram)
{
	/* release the dgram ref on conn */
	if (dgram->gndg_conn) {
		kgnilnd_conn_decref(dgram->gndg_conn);
		dgram->gndg_conn = NULL;
	}
}

void
kgnilnd_free_dgram(kgn_device_t *dev, kgn_dgram_t *dgram)
{
	LASSERTF(dgram->gndg_state == GNILND_DGRAM_USED ||
		 dgram->gndg_state == GNILND_DGRAM_DONE,
		 "dgram 0x%p with bad state %s\n",
		 dgram, kgnilnd_dgram_state2str(dgram));

	/* bit of poisoning to help detect bad driver data */
	dgram->gndg_magic = 0x6f5a6b5f;
	atomic_dec(&dev->gnd_ndgrams);

	kmem_cache_free(kgnilnd_data.kgn_dgram_cache, dgram);
	CDEBUG(D_MALLOC|D_NETTRACE, "slab-freed 'dgram': %lu at %p %s"
	       " ndgrams %d\n",
	       sizeof(*dgram), dgram, kgnilnd_dgram_type2str(dgram),
	       atomic_read(&dev->gnd_ndgrams));
}

int
kgnilnd_post_dgram(kgn_device_t *dev, lnet_nid_t dstnid, kgn_connreq_type_t type,
		   int data_rc)
{
	int              rc = 0;
	kgn_dgram_t     *dgram = NULL;
	kgn_dgram_t     *tmpdgram;
	kgn_dgram_type_t dgtype;
	gni_return_t     grc;
	__u64            srcnid;
	ENTRY;

	switch (type) {
	case GNILND_CONNREQ_REQ:
		if (dstnid == LNET_NID_ANY)
			dgtype = GNILND_DGRAM_WC_REQ;
		else
			dgtype = GNILND_DGRAM_REQ;
		break;
	case GNILND_CONNREQ_NAK:
		LASSERTF(dstnid != LNET_NID_ANY, "can't NAK to LNET_NID_ANY\n");
		dgtype = GNILND_DGRAM_NAK;
		break;
	default:
		CERROR("unknown connreq type %d\n", type);
		LBUG();
	}

	rc = kgnilnd_alloc_dgram(&dgram, dev, dgtype);
	if (rc < 0) {
		rc = -ENOMEM;
		GOTO(post_failed, rc);
	}

	rc = kgnilnd_create_conn(&dgram->gndg_conn, dev);
	if (rc) {
		GOTO(post_failed, rc);
	}

	if (dgram->gndg_type == GNILND_DGRAM_WC_REQ) {
		/* clear buffer for sanity on reuse of wildcard */
		memset(&dgram->gndg_conn_in, 0, sizeof(kgn_connreq_t));
	}

	if (dstnid == LNET_NID_ANY) {
		/* set here to reset any dgram re-use */
		dgram->gndg_conn->gnc_state = GNILND_CONN_LISTEN;
	} else {
		__u32            host_id;

		rc = kgnilnd_nid_to_nicaddrs(LNET_NIDADDR(dstnid), 1, &host_id);
		if (rc <= 0) {
			rc = -ESRCH;
			GOTO(post_failed, rc);
		}

		dgram->gndg_conn->gnc_state = GNILND_CONN_CONNECTING;

		/* don't need to serialize, there are no CQs for the dgram
		 * EP on the kgn_net_t */
		grc = kgnilnd_ep_bind(dgram->gndg_conn->gnc_ephandle, host_id, dev->gnd_id);

		if (grc != GNI_RC_SUCCESS) {
			rc = -ECONNABORTED;
			GOTO(post_failed, rc);
		}

	}

	/* If we are posting wildcards post using a net of 0, otherwise we'll use the
	 * net of the destination node.
	 */

	if (dstnid == LNET_NID_ANY) {
		srcnid = LNET_MKNID(LNET_MKNET(GNILND, 0), dev->gnd_nid);
	} else {
		srcnid = LNET_MKNID(LNET_NIDNET(dstnid), dev->gnd_nid);
	}

	rc = kgnilnd_pack_connreq(&dgram->gndg_conn_out, dgram->gndg_conn,
				  srcnid, dstnid, type);
	if (rc) {
		GOTO(post_failed, rc);
	}

	if (type == GNILND_CONNREQ_NAK)
		dgram->gndg_conn_out.gncr_nakdata.gnnd_errno = data_rc;

	dgram->gndg_post_time = jiffies;

	/* XXX Nic: here is where we'd add in logical network multiplexing */

	CDEBUG(D_NETTRACE, "dgram 0x%p type %s %s->%s cdm %d\n",
	       dgram, kgnilnd_dgram_type2str(dgram),
	       libcfs_nid2str(srcnid),
	       libcfs_nid2str(dstnid), dev->gnd_id);

	/* this allocates memory, can't hold locks across */
	grc = kgnilnd_ep_postdata_w_id(dgram->gndg_conn->gnc_ephandle,
				   &dgram->gndg_conn_out, sizeof(kgn_connreq_t),
				   &dgram->gndg_conn_in, sizeof(kgn_connreq_t),
				   (__u64)dgram);

	if (grc != GNI_RC_SUCCESS) {
		CNETERR("dropping failed dgram post id 0x%p type %s"
			" reqtype %s to %s: rc %d\n",
			dgram, kgnilnd_dgram_type2str(dgram),
			kgnilnd_connreq_type2str(&dgram->gndg_conn_out),
			libcfs_nid2str(dstnid), grc);
		rc = (grc == GNI_RC_ERROR_NOMEM) ? -ENOMEM : -EBADR;
		GOTO(post_failed, rc);
	}

	/* we don't need to add earlier - if someone does del_peer during post,
	 * that peer will get marked as unlinked and the callers wil take care of it.
	 * The dgram code is largely kgn_peer_t ignorant, so at worst, we'll just drop
	 * the completed dgram later when we cant find a peer to stuff it into */

	spin_lock(&dev->gnd_dgram_lock);

	/* make sure we are not double posting targeted dgrams
	 * - we can multiple post WC dgrams to help with processing speed */
	if (dstnid != LNET_NID_ANY) {
		tmpdgram = kgnilnd_find_dgram_locked(dev, dstnid);

		LASSERTF(tmpdgram == NULL,
			"dgram 0x%p->%s already posted\n",
			 dgram, libcfs_nid2str(dstnid));
	}

	/* unmunge dstnid to help processing code cope... */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PACK_DSTNID)) {
		dgram->gndg_conn_out.gncr_dstnid = dstnid;
	}

	list_add_tail(&dgram->gndg_list, kgnilnd_nid2dgramlist(dev, dstnid));
	dgram->gndg_state = GNILND_DGRAM_POSTED;
	spin_unlock(&dev->gnd_dgram_lock);

post_failed:
	if (rc < 0 && dgram != NULL) {
		kgnilnd_cleanup_dgram(dgram);
		kgnilnd_free_dgram(dev, dgram);
	}

	RETURN(rc);
}

/* The shutdown flag is set from the shutdown and stack reset threads. */
void
kgnilnd_release_dgram(kgn_device_t *dev, kgn_dgram_t *dgram, int shutdown)
{
	/* The conns of canceled active dgrams need to be put in purgatory so
	 * we don't reuse the mailbox */
	if (unlikely(dgram->gndg_state == GNILND_DGRAM_CANCELED)) {
		kgn_peer_t *peer;
		kgn_conn_t *conn = dgram->gndg_conn;
		lnet_nid_t nid = dgram->gndg_conn_out.gncr_dstnid;

		dgram->gndg_state = GNILND_DGRAM_DONE;

		/* During shutdown we've already removed the peer so we don't
		 * need to add a peer. During stack reset we don't care about
		 * MDDs since they are all released. */
		if (!shutdown) {
			write_lock(&kgnilnd_data.kgn_peer_conn_lock);
			peer = kgnilnd_find_peer_locked(nid);

			if (peer != NULL) {
				CDEBUG(D_NET, "adding peer's conn with nid %s "
					"to purgatory\n", libcfs_nid2str(nid));
				kgnilnd_conn_addref(conn);
				conn->gnc_peer = peer;
				kgnilnd_peer_addref(peer);
				kgnilnd_admin_addref(conn->gnc_peer->gnp_dirty_eps);
				conn->gnc_state = GNILND_CONN_CLOSED;
				list_add_tail(&conn->gnc_list,
					      &peer->gnp_conns);
				kgnilnd_add_purgatory_locked(conn,
							     conn->gnc_peer);
				kgnilnd_schedule_conn(conn);
			}
			write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		}
	}

	spin_lock(&dev->gnd_dgram_lock);
	kgnilnd_cancel_dgram_locked(dgram);
	spin_unlock(&dev->gnd_dgram_lock);

	kgnilnd_cleanup_dgram(dgram);

	/* if the dgram is 'canceled' it needs to be wait until the event
	 * comes up from kgni that tells us it is safe to release */
	if (dgram->gndg_state != GNILND_DGRAM_CANCELED) {
		dgram->gndg_state = GNILND_DGRAM_DONE;

		LASSERTF(list_empty(&dgram->gndg_list), "dgram 0x%p on list\n", dgram);

		/* if it is a wildcard and we are in an appropriate state, repost
		 * the wildcard */

		if ((dgram->gndg_type == GNILND_DGRAM_WC_REQ) &&
		    (!kgnilnd_data.kgn_wc_kill && !kgnilnd_data.kgn_in_reset)) {
			int     rerc;

			rerc = kgnilnd_post_dgram(dev, LNET_NID_ANY, GNILND_CONNREQ_REQ, 0);
			if (rerc != 0) {
				/* We failed to repost the WC dgram for some reason
				 * mark it so the repost system attempts to repost */
				kgnilnd_admin_addref(dev->gnd_nwcdgrams);
			}
		}

		/* always free the old dgram */
		kgnilnd_free_dgram(dev, dgram);
	}
}


int
kgnilnd_probe_for_dgram(kgn_device_t *dev, kgn_dgram_t **dgramp)
{
	kgn_dgram_t             *dgram = NULL;
	gni_post_state_t         post_state;
	gni_return_t             grc;
	int                      rc = 0;
	__u64                    readyid;
	__u32                    remote_addr = 0, remote_id = 0;
	ENTRY;

	/* Probe with the lock held. That way if we get a dgram we dont have it canceled
	 * between finding the ready dgram and grabbing the lock to remove it from the
	 * list. Otherwise we could be left in an inconsistent state. We own the dgram
	 * once its off the list so we don't need to worry about others changing it at
	 * that point. */
	spin_lock(&dev->gnd_dgram_lock);
	grc = kgnilnd_postdata_probe_by_id(dev->gnd_handle, &readyid);
	if (grc != GNI_RC_SUCCESS) {
		spin_unlock(&dev->gnd_dgram_lock);
		/* return 0 to indicate nothing happened */
		RETURN(0);
	}

	CDEBUG(D_NET, "ready %#llx on device 0x%p\n",
		readyid, dev);

	dgram = (kgn_dgram_t *)readyid;

	LASSERTF(dgram->gndg_magic == GNILND_DGRAM_MAGIC,
		 "dgram 0x%p from id %#llx with bad magic %x\n",
		 dgram, readyid, dgram->gndg_magic);

	LASSERTF(dgram->gndg_state == GNILND_DGRAM_POSTED ||
		 dgram->gndg_state == GNILND_DGRAM_CANCELED,
		 "dgram 0x%p with bad state %s\n",
		 dgram, kgnilnd_dgram_state2str(dgram));

	LASSERTF(!list_empty(&dgram->gndg_list),
		 "dgram 0x%p with bad list state %s type %s\n",
		 dgram, kgnilnd_dgram_state2str(dgram),
		 kgnilnd_dgram_type2str(dgram));

	/* now we know that the datagram structure is ok, so pull off list */
	list_del_init(&dgram->gndg_list);

	/* while we have the gnn_dgram_lock and BEFORE we call test_by_id
	 * change the state from POSTED to PROCESSING to ensure that
	 * nobody cancels it after we've pulled it from the wire */
	if (dgram->gndg_state == GNILND_DGRAM_POSTED) {
		dgram->gndg_state = GNILND_DGRAM_PROCESSING;
	}

	LASSERTF(dgram->gndg_conn != NULL,
		"dgram 0x%p with NULL conn\n", dgram);

	grc = kgnilnd_ep_postdata_test_by_id(dgram->gndg_conn->gnc_ephandle,
					     (__u64)dgram, &post_state,
					     &remote_addr, &remote_id);

	/* we now "own" this datagram */
	spin_unlock(&dev->gnd_dgram_lock);

	LASSERTF(grc != GNI_RC_NO_MATCH, "kgni lied! probe_by_id told us that"
		 " id %llu was ready\n", readyid);

	CDEBUG(D_NET, "grc %d dgram 0x%p type %s post_state %d "
		"remote_addr %u remote_id %u\n", grc, dgram,
		kgnilnd_dgram_type2str(dgram),
		post_state, remote_addr, remote_id);

	if (unlikely(grc != GNI_RC_SUCCESS)) {
		CNETERR("getting data for dgram 0x%p->%s failed rc %d. Dropping it\n",
			dgram, libcfs_nid2str(dgram->gndg_conn_out.gncr_dstnid),
			grc);
		rc = -EINVAL;
		GOTO(probe_for_out, rc);
	}

	rc = kgnilnd_process_dgram(dgram, post_state);

	/* we should never get probe finding a dgram for us and then it
	 * being a WC dgram that is still in the middle of processing */
	LASSERTF(rc <= 0, "bad rc %d from process_dgram 0x%p state %d\n",
		 rc, dgram, post_state);

	if (rc == 0) {
		/* dgram is good enough for the data to be used */
		dgram->gndg_state = GNILND_DGRAM_PROCESSING;
		/* fake rc to mark that we've done something */
		rc = 1;
	} else {
		/* let kgnilnd_release_dgram take care of canceled dgrams */
		if (dgram->gndg_state != GNILND_DGRAM_CANCELED) {
			dgram->gndg_state = GNILND_DGRAM_DONE;
		}
	}

	*dgramp = dgram;
	RETURN(rc);

probe_for_out:

	kgnilnd_release_dgram(dev, dgram, 0);
	RETURN(rc);
}

int
kgnilnd_setup_wildcard_dgram(kgn_device_t *dev)
{
	/* if kgn_wildcard is zero, return error */
	int     rc = -ENOENT, i;
	ENTRY;

	for (i = 0; i < *kgnilnd_tunables.kgn_nwildcard; i++) {
		rc = kgnilnd_post_dgram(dev, LNET_NID_ANY, GNILND_CONNREQ_REQ, 0);
		if (rc < 0) {
			CERROR("error %d: could not post wildcard datagram # %d\n",
				rc, i);
			rc = -EINVAL;
			GOTO(failed, rc);
		}
	}

failed:
	RETURN(rc);
}

int
kgnilnd_cancel_net_dgrams(kgn_net_t *net)
{
	kgn_dgram_t *dg, *dgN;
	LIST_HEAD(zombies);
	int i;
	ENTRY;

	/* we want to cancel any outstanding dgrams - we don't want to rely
	 * on del_peer_or_conn catching all of them. This helps protect us in cases
	 * where we don't quite keep the peer->dgram mapping in sync due to some
	 * race conditions */

	LASSERTF(net->gnn_shutdown || kgnilnd_data.kgn_in_reset,
		 "called with LND invalid state: net shutdown %d "
		 "in reset %d\n", net->gnn_shutdown,
		 kgnilnd_data.kgn_in_reset);

	spin_lock(&net->gnn_dev->gnd_dgram_lock);

	for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++) {
		list_for_each_entry_safe(dg, dgN, &net->gnn_dev->gnd_dgrams[i], gndg_list) {

			/* skip nids not on our net or are wildcards */


			if (dg->gndg_type == GNILND_DGRAM_WC_REQ ||
				net->gnn_netnum != LNET_NETNUM(LNET_NIDNET(dg->gndg_conn_out.gncr_dstnid)))
				continue;

			kgnilnd_cancel_dgram_locked(dg);
		}
	}

	spin_unlock(&net->gnn_dev->gnd_dgram_lock);

	RETURN(0);
}

int
kgnilnd_cancel_wc_dgrams(kgn_device_t *dev)
{
	kgn_dgram_t *dg, *dgN;
	LIST_HEAD(zombies);
	ENTRY;

	/* Time to kill the outstanding WC's
	 * WC's exist on net 0 only but match on any net...
	 */

	LASSERTF(kgnilnd_data.kgn_in_reset || kgnilnd_data.kgn_wc_kill,
		"called with LND invalid state: WC shutdown %d "
		"in reset %d\n", kgnilnd_data.kgn_wc_kill,
		kgnilnd_data.kgn_in_reset);

	spin_lock(&dev->gnd_dgram_lock);

	do {
		dg = kgnilnd_find_dgram_locked(dev, LNET_NID_ANY);
		if (dg != NULL) {
			LASSERTF(dg->gndg_type == GNILND_DGRAM_WC_REQ,
				 "dgram 0x%p->%s with bad type %d (%s)\n",
				dg, libcfs_nid2str(dg->gndg_conn_out.gncr_dstnid),
				dg->gndg_type, kgnilnd_dgram_type2str(dg));

			kgnilnd_cancel_dgram_locked(dg);

			/* WC could be DONE already, check and if so add to list to be released */
			if (dg->gndg_state == GNILND_DGRAM_DONE)
				list_move_tail(&dg->gndg_list, &zombies);
		}
	} while (dg != NULL);

	spin_unlock(&dev->gnd_dgram_lock);

	list_for_each_entry_safe(dg, dgN, &zombies, gndg_list) {
		list_del_init(&dg->gndg_list);
		kgnilnd_release_dgram(dev, dg, 1);
	}
	RETURN(0);

}

int
kgnilnd_cancel_dgrams(kgn_device_t *dev)
{
	kgn_dgram_t *dg, *dgN;
	int i;
	ENTRY;

	/* Cancel any outstanding non wildcard datagrams regardless
	 * of which net they are on as we are in base shutdown and
	 * dont care about connecting anymore.
	 */

	LASSERTF(kgnilnd_data.kgn_wc_kill == 1,"We didnt get called from base shutdown\n");

	spin_lock(&dev->gnd_dgram_lock);

	for (i = 0; i < (*kgnilnd_tunables.kgn_peer_hash_size -1); i++) {
		list_for_each_entry_safe(dg, dgN, &dev->gnd_dgrams[i], gndg_list) {
			if (dg->gndg_type != GNILND_DGRAM_WC_REQ)
				kgnilnd_cancel_dgram_locked(dg);
		}
	}

	spin_unlock(&dev->gnd_dgram_lock);

	RETURN(0);
}


void
kgnilnd_wait_for_canceled_dgrams(kgn_device_t *dev)
{
	int             i = 4;
	int             rc;
	gni_return_t    grc;
	__u64           readyid;
	kgn_dgram_t    *dgram;

	/* use do while to get at least one check run to allow
	 * regression test for 762072 to hit bug if there */

	/* This function races with the dgram mover during shutdown so it is possible for
	 * a dgram to be seen in kgnilnd_postdata_probe_wait_by_id but be handled in the
	 * dgram mover thread instead of inside of this function.
	 */

	/* This should only be called from within shutdown, baseshutdown, or stack reset.
	 * there are no assertions here to verify since base_shutdown has nothing in it we can check
	 * the net is gone by then.
	 */

	do {
		i++;
		CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET,
			"Waiting for %d canceled datagrams to clear on device %d\n",
			atomic_read(&dev->gnd_canceled_dgrams), dev->gnd_id);

		/* check once a second */
		grc = kgnilnd_postdata_probe_wait_by_id(dev->gnd_handle,
		       250, &readyid);

		if (grc != GNI_RC_SUCCESS)
			continue;

		CDEBUG(D_NET, "ready %#llx on device %d->0x%p\n",
			readyid, dev->gnd_id, dev);

		rc = kgnilnd_probe_for_dgram(dev, &dgram);
		if (rc != 0) {
			/* if we got a valid dgram or one that is now done, clean up */
			kgnilnd_release_dgram(dev, dgram, 1);
		}
	} while (atomic_read(&dev->gnd_canceled_dgrams));
}

int
kgnilnd_start_connect(kgn_peer_t *peer)
{
	int              rc = 0;
	/* sync point for kgnilnd_del_peer_locked - do an early check to
	 * catch the most common hits where del_peer is done by the
	 * time we get here */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_GNP_CONNECTING1)) {
		while (CFS_FAIL_TIMEOUT(CFS_FAIL_GNI_GNP_CONNECTING1, 1)) {};
	}

	write_lock(&kgnilnd_data.kgn_peer_conn_lock);
	if (!kgnilnd_peer_active(peer) || peer->gnp_connecting != GNILND_PEER_CONNECT) {
		/* raced with peer getting unlinked */
		write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		rc = ESTALE;
		GOTO(out, rc);
	}
	peer->gnp_connecting = GNILND_PEER_POSTING;
	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	set_mb(peer->gnp_last_dgram_time, jiffies);
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_GNP_CONNECTING2)) {
		while (CFS_FAIL_TIMEOUT(CFS_FAIL_GNI_GNP_CONNECTING2, 1)) {};
	}

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_GNP_CONNECTING3)) {
		while (CFS_FAIL_TIMEOUT(CFS_FAIL_GNI_GNP_CONNECTING3, 1)) {};
		rc = cfs_fail_val ? cfs_fail_val : -ENOMEM;
	} else {
		rc = kgnilnd_post_dgram(peer->gnp_net->gnn_dev,
					peer->gnp_nid, GNILND_CONNREQ_REQ, 0);
	}
	if (rc < 0) {
		set_mb(peer->gnp_last_dgram_errno, rc);
		GOTO(failed, rc);
	}

	/* while we're posting someone could have decided this peer/dgram needed to
	 * die a quick death, so we check for state change and process accordingly */

	write_lock(&kgnilnd_data.kgn_peer_conn_lock);
	if (!kgnilnd_peer_active(peer) || peer->gnp_connecting == GNILND_PEER_NEEDS_DEATH) {
		if (peer->gnp_connecting == GNILND_PEER_NEEDS_DEATH) {
			peer->gnp_connecting = GNILND_PEER_KILL;
		}
		write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		/* positive RC to avoid dgram cleanup - we'll have to
		 * wait for the kgni GNI_POST_TERMINATED event to
		 * finish cleaning up */
		rc = ESTALE;
		kgnilnd_find_and_cancel_dgram(peer->gnp_net->gnn_dev, peer->gnp_nid);
		GOTO(out, rc);
	}
	peer->gnp_connecting = GNILND_PEER_POSTED;
	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
	/* reaper thread will take care of any timeouts */
	CDEBUG(D_NET, "waiting for connect to finish to %s rc %d\n",
	       libcfs_nid2str(peer->gnp_nid), rc);

	RETURN(rc);

failed:
	CDEBUG(D_NET, "connect to %s failed: rc %d \n",
	       libcfs_nid2str(peer->gnp_nid), rc);
out:
	RETURN(rc);
}

int
kgnilnd_finish_connect(kgn_dgram_t *dgram)
{
	kgn_conn_t        *conn = dgram->gndg_conn;
	lnet_nid_t         her_nid = dgram->gndg_conn_in.gncr_srcnid;
	kgn_peer_t        *new_peer, *peer = NULL;
	kgn_tx_t          *tx;
	kgn_tx_t          *txn;
	kgn_mbox_info_t   *mbox;
	int                rc;
	int                nstale;

	/* try to find a peer that matches the nid we got in the connreq
	 * kgnilnd_unpack_connreq makes sure that conn_in.gncr_srcnid is
	 * HER and conn_out.gncr_srcnid is ME for both active and WC dgrams */

	/* assume this is a new peer  - it makes locking cleaner when it isn't */
	/* no holding kgn_net_rw_sem - already are at the kgnilnd_dgram_mover level */

	rc = kgnilnd_create_peer_safe(&new_peer, her_nid, NULL, GNILND_PEER_UP);
	if (rc != 0) {
		CERROR("Can't create peer for %s\n", libcfs_nid2str(her_nid));
		return rc;
	}

	write_lock(&kgnilnd_data.kgn_peer_conn_lock);

	/* this transfers ref from create_peer to the kgn_peer table */
	kgnilnd_add_peer_locked(her_nid, new_peer, &peer);

	/* if we found an existing peer, is it really ready for a new conn ? */
	if (peer != new_peer) {
		/* if this was an active connect attempt but we can't find a peer waiting for it
		 * we will dump in the trash */

		if (peer->gnp_connecting == GNILND_PEER_IDLE && dgram->gndg_conn_out.gncr_dstnid != LNET_NID_ANY) {
			CDEBUG(D_NET, "dropping completed connreq for %s peer 0x%p->%s\n",
			       libcfs_nid2str(her_nid), peer, libcfs_nid2str(peer->gnp_nid));
			write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			rc = ECANCELED;
			GOTO(out, rc);
		}

		/* check to see if we can catch a connecting peer before it is
		 * removed from the connd_peers list - if not, we need to
		 * let the connreqs race and be handled by kgnilnd_conn_isdup_locked() */
		if (peer->gnp_connecting != GNILND_PEER_IDLE) {
			spin_lock(&peer->gnp_net->gnn_dev->gnd_connd_lock);
			if (!list_empty(&peer->gnp_connd_list)) {
				list_del_init(&peer->gnp_connd_list);
				/* drop connd ref */
				kgnilnd_peer_decref(peer);
			}
			spin_unlock(&peer->gnp_net->gnn_dev->gnd_connd_lock);
			/* clear rc to make sure we don't have fake error */
			rc = 0;
		}

		/* no matter what, we are no longer waiting to connect this peer now */
		peer->gnp_connecting = GNILND_PEER_IDLE;

		/* Refuse to duplicate an existing connection (both sides might try to
		 * connect at once).  NB we return success!  We _are_ connected so we
		 * _don't_ have any blocked txs to complete with failure. */
		rc = kgnilnd_conn_isdup_locked(peer, conn);
		if (rc != 0) {
			write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			CDEBUG(D_NET, "Not creating duplicate connection to %s: %d\n",
			      libcfs_nid2str(her_nid), rc);
			rc = EALREADY;
			GOTO(out, rc);
		}
	}

	if (peer->gnp_state == GNILND_PEER_DOWN) {
		CNETERR("Received connection request from down nid %s\n",
			libcfs_nid2str(her_nid));
	}

	peer->gnp_state = GNILND_PEER_UP;
	nstale = kgnilnd_close_stale_conns_locked(peer, conn);

	/* either way with peer (new or existing), we are ok with ref counts here as the
	 * kgnilnd_add_peer_locked will use our ref on new_peer (from create_peer_safe) as the
	 * ref for the peer table. */

	/* at this point, the connection request is a winner */

	/* mark 'DONE' to avoid cancel being called from release */
	dgram->gndg_state = GNILND_DGRAM_DONE;

	/* initialise timestamps before reaper looks at them */
	conn->gnc_last_rx = conn->gnc_last_rx_cq = jiffies;

	/* last_tx is initialized to jiffies - (keepalive*2) so that if the NOOP fails it will
	 * immediatly send a NOOP in the reaper thread during the call to
	 * kgnilnd_check_conn_timeouts_locked
	 */
	conn->gnc_last_tx = jiffies - (cfs_time_seconds(GNILND_TO2KA(conn->gnc_timeout)) * 2);
	conn->gnc_state = GNILND_CONN_ESTABLISHED;

	/* save the dgram type used to establish this connection */
	conn->gnc_dgram_type = dgram->gndg_type;

	/* refs are not transferred from dgram to tables, so increment to
	 * take ownership */
	kgnilnd_conn_addref(conn);
	kgnilnd_peer_addref(peer);
	conn->gnc_peer = peer;
	list_add_tail(&conn->gnc_list, &peer->gnp_conns);

	kgnilnd_conn_addref(conn);               /* +1 ref for conn table */
	list_add_tail(&conn->gnc_hashlist,
		      kgnilnd_cqid2connlist(conn->gnc_cqid));
	kgnilnd_data.kgn_conn_version++;

	/* Dont send NOOP if fail_loc is set
	 */
	if (!CFS_FAIL_CHECK(CFS_FAIL_GNI_ONLY_NOOP)) {
		tx = kgnilnd_new_tx_msg(GNILND_MSG_NOOP, peer->gnp_net->gnn_ni->ni_nid);
		if (tx == NULL) {
			CNETERR("can't get TX to initiate NOOP to %s\n",
				libcfs_nid2str(peer->gnp_nid));
		} else {
			kgnilnd_queue_tx(conn, tx);
		}
	}

	/* Schedule all packets blocking for a connection */
	list_for_each_entry_safe(tx, txn, &peer->gnp_tx_queue, tx_list) {
		/* lock held here is the peer_conn lock */
		kgnilnd_tx_del_state_locked(tx, peer, NULL, GNILND_TX_ALLOCD);
		kgnilnd_queue_tx(conn, tx);
	}

	/* If this is an active connection lets mark its timestamp on the MBoX */
	if (dgram->gndg_conn_out.gncr_dstnid != LNET_NID_ANY) {
		mbox = &conn->gnc_fma_blk->gnm_mbox_info[conn->gnc_mbox_id];
		/* conn->gnc_last_rx is jiffies it better exist as it was just set */
		mbox->mbx_release_purg_active_dgram = conn->gnc_last_rx;
	}

	/* Bug 765042: wake up scheduler for a race with finish_connect and
	 * complete_conn_closed with a conn in purgatory
	 * since we can't use CFS_RACE due to mutex_holds in kgnilnd_process_conns,
	 * we just check for set and then clear */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_FINISH_PURG)) {
		cfs_fail_loc = 0x0;
		/* get scheduler thread moving again */
		kgnilnd_schedule_device(conn->gnc_device);
	}

	CDEBUG(D_NET, "New conn 0x%p->%s dev %d\n",
	       conn, libcfs_nid2str(her_nid), conn->gnc_device->gnd_id);

	/* make sure we reset peer reconnect interval now that we have a good conn */
	kgnilnd_peer_alive(peer);
	peer->gnp_reconnect_interval = 0;

	/* clear the unlink attribute if we dont clear it kgnilnd_del_conn_or_peer will wait
	 * on the atomic forever
	 */
	if (peer->gnp_pending_unlink) {
		peer->gnp_pending_unlink = 0;
		kgnilnd_admin_decref(kgnilnd_data.kgn_npending_unlink);
		CDEBUG(D_NET, "Clearing peer unlink %p\n",peer);
	}

	/* add ref to make it hang around until after we drop the lock */
	kgnilnd_conn_addref(conn);

	/* Once the peer_conn lock is dropped, the conn could actually move into
	 * CLOSING->CLOSED->DONE in the scheduler thread, so hold the
	 * lock until we are really done */
	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	/* Notify LNET that we now have a working connection to this peer.
	 * This is a Cray extension to the "standard" LND behavior.
	 */
	lnet_notify(peer->gnp_net->gnn_ni, peer->gnp_nid, true, true,
		    ktime_get_seconds());

	/* drop our 'hold' ref */
	kgnilnd_conn_decref(conn);

out:
	RETURN(rc);
}

void
kgnilnd_send_nak(kgn_device_t *dev, lnet_nid_t dst_nid, int error)
{
	int              rc = 0;
	ENTRY;

	LASSERTF(dst_nid != LNET_NID_ANY, "bad dst_nid %s\n", libcfs_nid2str(dst_nid));

	CDEBUG(D_NET, "NAK to %s errno %d\n", libcfs_nid2str(dst_nid), error);

	rc = kgnilnd_post_dgram(dev, dst_nid, GNILND_CONNREQ_NAK, error);

	if (rc < 0) {
		CDEBUG(D_NET, "NAK to %s failed: rc %d \n", libcfs_nid2str(dst_nid), rc);
	}
	EXIT;
}

int
kgnilnd_process_nak(kgn_dgram_t *dgram)
{
	kgn_connreq_t     *connreq = &dgram->gndg_conn_in;
	lnet_nid_t         src_nid = connreq->gncr_srcnid;
	int                errno = connreq->gncr_nakdata.gnnd_errno;
	kgn_peer_t        *peer;
	int                rc = 0;

	write_lock(&kgnilnd_data.kgn_peer_conn_lock);

	peer = kgnilnd_find_peer_locked(src_nid);
	if (peer == NULL) {
		/* we likely dropped him from bad data when we processed
		 * the original REQ */
		write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		return -EBADSLT;
	}

	/* need to check peerstamp/connstamp against the ones we find
	 * to make sure we don't close new (and good?) conns that we
	 * formed after this connreq failed */
	if (peer->gnp_connecting == GNILND_PEER_IDLE) {
		kgn_conn_t        conn;

		if (list_empty(&peer->gnp_conns)) {
			/* assume already procced datagram and it barfed up
			 * on this side too */
			CDEBUG(D_NET, "dropping NAK from %s; "
			       "peer %s is already not connected\n",
				libcfs_nid2str(connreq->gncr_srcnid),
				libcfs_nid2str(connreq->gncr_dstnid));
			write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			return 0;
		}

		/* stub up a connection with the connreq XXX_stamps to allow
		 * use to use close_stale_conns_locked */
		conn.gnc_peerstamp = connreq->gncr_peerstamp;
		conn.gnc_my_connstamp = connreq->gncr_connstamp;
		conn.gnc_peer_connstamp = connreq->gncr_connstamp;
		conn.gnc_device = peer->gnp_net->gnn_dev;

		rc = kgnilnd_close_stale_conns_locked(peer, &conn);

		LCONSOLE_INFO("Received NAK from %s for %s errno %d; "
			"closed %d connections\n",
			libcfs_nid2str(connreq->gncr_srcnid),
			libcfs_nid2str(connreq->gncr_dstnid), errno, rc);
	} else {
		spin_lock(&dgram->gndg_conn->gnc_device->gnd_connd_lock);

		if (list_empty(&peer->gnp_connd_list)) {
			/* if peer isn't on waiting list, try to find one to nuke */
			rc = kgnilnd_find_and_cancel_dgram(peer->gnp_net->gnn_dev,
							   peer->gnp_nid);

			if (rc) {
				LCONSOLE_INFO("Received NAK from %s for %s errno %d; "
					"canceled pending connect request\n",
					libcfs_nid2str(connreq->gncr_srcnid),
					libcfs_nid2str(connreq->gncr_dstnid), errno);
			}

			/* if we can't find a waiting dgram, we just drop the nak - the conn
			 * connect must have failed (didn't find conn above and clear connecting
			 * -- so nothing to do besides drop */
		} else {
			/* peer is on list, meaning it is a new connect attempt from the one
			 * we started that generated the NAK - so just drop NAK */

			/* use negative to prevent error message */
			rc = -EAGAIN;
		}
		spin_unlock(&dgram->gndg_conn->gnc_device->gnd_connd_lock);
	}

	/* success! we found a peer and at least marked pending_nak */
	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	return rc;
}

int
kgnilnd_process_connreq(kgn_dgram_t *dgram, int *needs_nak)
{
	int                      rc;

	rc = kgnilnd_unpack_connreq(dgram);
	if (rc < 0) {
		if (rc != -EBADF) {
			/* only NAK if we have good srcnid to use */
			*needs_nak = 1;
		}
		goto connreq_out;
	}

	switch (dgram->gndg_conn_in.gncr_type) {
	case GNILND_CONNREQ_REQ:
		/* wire up peer & conn, send queued TX */
		rc = kgnilnd_finish_connect(dgram);

		/* don't nak when the nid is hosed */
		if ((rc < 0)) {
			*needs_nak = 1;
		}

		break;
	case GNILND_CONNREQ_NAK:
		rc = kgnilnd_process_nak(dgram);
		/* return early to prevent reconnect bump */
		return rc;
	default:
		CERROR("unexpected connreq type %s (%d) from %s\n",
			kgnilnd_connreq_type2str(&dgram->gndg_conn_in),
			dgram->gndg_conn_in.gncr_type,
			libcfs_nid2str(dgram->gndg_conn_in.gncr_srcnid));
		rc = -EINVAL;
		*needs_nak = 1;
		break;
	}

connreq_out:
	RETURN(rc);
}

int
kgnilnd_probe_and_process_dgram(kgn_device_t *dev)
{
	int                      rc;
	int                      needs_nak = 0;
	lnet_nid_t               nak_dstnid = LNET_NID_ANY;
	lnet_nid_t               orig_dstnid;
	kgn_dgram_t             *dgram = NULL;
	kgn_peer_t              *peer;
	ENTRY;

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PAUSE_DGRAM_COMP)) {
		rc = 0;
	} else {
		rc = kgnilnd_probe_for_dgram(dev, &dgram);
	}

	if (rc == 0) {
		RETURN(0);
	} else if (rc < 0) {
		GOTO(inform_peer, rc);
	} else {
		/* rc > 1 means it did something, reset for this func  */
		rc = 0;
	}

	switch (dgram->gndg_type) {
	case GNILND_DGRAM_WC_REQ:
	case GNILND_DGRAM_REQ:
		rc = kgnilnd_process_connreq(dgram, &needs_nak);
		break;
	case GNILND_DGRAM_NAK:
		CDEBUG(D_NETTRACE, "NAK to %s done\n",
			libcfs_nid2str(dgram->gndg_conn_out.gncr_dstnid));
		break;
	default:
		CERROR("unknown datagram type %s (%d)\n",
		       kgnilnd_dgram_type2str(dgram), dgram->gndg_type);
		break;
	}

	/* stash data to use after releasing current datagram */
	/* don't stash net - we are operating on a net already,
	 * so the lock on rw_net_lock is sufficient */

	nak_dstnid = dgram->gndg_conn_in.gncr_srcnid;

inform_peer:
	LASSERTF(dgram != NULL, "dgram 0x%p rc %d needs_nak %d\n", dgram, rc, needs_nak);

	orig_dstnid = dgram->gndg_conn_out.gncr_dstnid;

	kgnilnd_release_dgram(dev, dgram, 0);

	CDEBUG(D_NET, "cleaning up dgram to %s, rc %d\n",
	       libcfs_nid2str(orig_dstnid), rc);

	/* if this was a WC_REQ that matched an existing peer, it'll get marked done
	 * in kgnilnd_finish_connect - if errors are from before we get to there,
	 * we just drop as it is a WC_REQ - the peer CAN'T be waiting for it */
	if ((orig_dstnid != LNET_NID_ANY) && (rc < 0)) {
		/* if we have a negative rc, we want to find a peer to inform about
		 * the bad connection attempt. Sorry buddy, better luck next time! */

		write_lock(&kgnilnd_data.kgn_peer_conn_lock);
		peer = kgnilnd_find_peer_locked(orig_dstnid);

		if (peer != NULL) {
			/* add ref to make sure he stays around past the possible unlink
			 * so we can tell LNet about him */
			kgnilnd_peer_addref(peer);

			/* if he still cares about the outstanding connect */
			if (peer->gnp_connecting >= GNILND_PEER_CONNECT) {
				/* check if he is on the connd list and remove.. */
				spin_lock(&peer->gnp_net->gnn_dev->gnd_connd_lock);
				if (!list_empty(&peer->gnp_connd_list)) {
					list_del_init(&peer->gnp_connd_list);
					/* drop connd ref */
					kgnilnd_peer_decref(peer);
				}
				spin_unlock(&peer->gnp_net->gnn_dev->gnd_connd_lock);

				/* clear gnp_connecting so we don't have a non-connecting peer
				 * on gnd_connd_list */
				peer->gnp_connecting = GNILND_PEER_IDLE;

				set_mb(peer->gnp_last_dgram_errno, rc);

				kgnilnd_peer_increase_reconnect_locked(peer);
			}
		}
		write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

		/* now that we are outside the lock, tell Mommy */
		if (peer != NULL) {
			kgnilnd_peer_notify(peer, rc, 0);
			kgnilnd_peer_decref(peer);
		}
	}

	if (needs_nak) {
		kgnilnd_send_nak(dev, nak_dstnid, rc);
	}

	RETURN(1);
}

void
kgnilnd_reaper_dgram_check(kgn_device_t *dev)
{
	kgn_dgram_t    *dgram, *tmp;
	int             i;

	spin_lock(&dev->gnd_dgram_lock);

	for (i = 0; i < (*kgnilnd_tunables.kgn_peer_hash_size - 1); i++) {
		list_for_each_entry_safe(dgram, tmp, &dev->gnd_dgrams[i], gndg_list) {
			unsigned long            now = jiffies;
			unsigned long            timeout;

			/* don't timeout stuff if the network is mucked or shutting down */
			if (kgnilnd_check_hw_quiesce()) {
				break;
			}

			if ((dgram->gndg_state != GNILND_DGRAM_POSTED) ||
			    (dgram->gndg_type == GNILND_DGRAM_WC_REQ)) {
				continue;
			}
			CDEBUG(D_NETTRACE, "checking dgram 0x%p type %s "
				"state %s conn 0x%p to %s age %lus\n",
				dgram, kgnilnd_dgram_type2str(dgram),
				kgnilnd_dgram_state2str(dgram), dgram->gndg_conn,
				libcfs_nid2str(dgram->gndg_conn_out.gncr_dstnid),
				cfs_duration_sec(now - dgram->gndg_post_time));

			timeout = cfs_time_seconds(*kgnilnd_tunables.kgn_timeout);

			if (time_before(now, (dgram->gndg_post_time + timeout)))
				continue;

			CNETERR("%s datagram to %s timed out @ %lus dgram "
				"0x%p state %s conn 0x%p\n",
				kgnilnd_dgram_type2str(dgram),
				libcfs_nid2str(dgram->gndg_conn_out.gncr_dstnid),
				cfs_duration_sec(now - dgram->gndg_post_time),
				dgram, kgnilnd_dgram_state2str(dgram),
				dgram->gndg_conn);

			kgnilnd_cancel_dgram_locked(dgram);
		}
	}
	spin_unlock(&dev->gnd_dgram_lock);
}


/* use a thread for the possibly long-blocking wait_by_id to prevent
 * stalling the global workqueues */
int
kgnilnd_dgram_waitq(void *arg)
{
	kgn_device_t     *dev = (kgn_device_t *) arg;
	char              name[16];
	gni_return_t      grc;
	__u64             readyid;
	DEFINE_WAIT(mover_done);

	snprintf(name, sizeof(name), "kgnilnd_dgn_%02d", dev->gnd_id);

	/* all gnilnd threads need to run fairly urgently */
	set_user_nice(current, *kgnilnd_tunables.kgn_nice);

	/* we dont shut down until the device shuts down ... */
	while (!kgnilnd_data.kgn_shutdown) {
		/* to quiesce or to not quiesce, that is the question */
		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			KGNILND_SPIN_QUIESCE;
		}

		while (CFS_FAIL_TIMEOUT(CFS_FAIL_GNI_PAUSE_DGRAM_COMP, 1)) {}

		/* check once a second */
		grc = kgnilnd_postdata_probe_wait_by_id(dev->gnd_handle,
						       1000, &readyid);

		if (grc == GNI_RC_SUCCESS) {
			CDEBUG(D_INFO, "waking up dgram mover thread\n");
			kgnilnd_schedule_dgram(dev);

			/* wait for dgram thread to ping us before spinning again */
			prepare_to_wait(&dev->gnd_dgping_waitq, &mover_done,
					TASK_INTERRUPTIBLE);

			/* don't sleep if we need to quiesce */
			if (likely(!kgnilnd_data.kgn_quiesce_trigger)) {
				schedule();
			}
			finish_wait(&dev->gnd_dgping_waitq, &mover_done);
		}
	}

	kgnilnd_thread_fini();
	return 0;
}

int
kgnilnd_start_outbound_dgrams(kgn_device_t *dev, unsigned long deadline)
{
	int                      did_something = 0, rc;
	kgn_peer_t              *peer = NULL;

	spin_lock(&dev->gnd_connd_lock);

	/* Active connect - we added this in kgnilnd_launch_tx */
	while (!list_empty(&dev->gnd_connd_peers) && time_before(jiffies, deadline)) {
		peer = list_first_entry(&dev->gnd_connd_peers,
					kgn_peer_t, gnp_connd_list);

		/* ref for connd removed in if/else below */
	       list_del_init(&peer->gnp_connd_list);

		/* gnp_connecting and membership on gnd_connd_peers should be
		 * done coherently to avoid double adding, etc */
		/* don't need kgnilnd_data.kgn_peer_conn_lock here as that is only needed
		 * to get the peer to gnp_connecting in the first place. We just need to
		 * rely on gnd_connd_lock to serialize someone pulling him from the list
		 * BEFORE clearing gnp_connecting */
		LASSERTF(peer->gnp_connecting != GNILND_PEER_IDLE, "peer 0x%p->%s not connecting\n",
			 peer, libcfs_nid2str(peer->gnp_nid));

		spin_unlock(&dev->gnd_connd_lock);

		CDEBUG(D_NET, "processing connect to %s\n",
		       libcfs_nid2str(peer->gnp_nid));

		did_something += 1;
		rc = kgnilnd_start_connect(peer);

		if (likely(rc >= 0)) {
			/* 0 on success, positive on 'just drop peer' errors */
			kgnilnd_peer_decref(peer);
		} else if (rc == -ENOMEM) {
			/* if we are out of wildcards, add back to
			 * connd_list - then break out and we'll try later
			 * if other errors, we'll bail & cancel pending tx */
			write_lock(&kgnilnd_data.kgn_peer_conn_lock);
			if (peer->gnp_connecting == GNILND_PEER_POSTING) {
				peer->gnp_connecting = GNILND_PEER_CONNECT;
				spin_lock(&dev->gnd_connd_lock);
				list_add_tail(&peer->gnp_connd_list,
					      &dev->gnd_connd_peers);
			} else {
				/* connecting changed while we were posting */

				LASSERTF(peer->gnp_connecting == GNILND_PEER_NEEDS_DEATH, "Peer is in invalid"
					" state 0x%p->%s, connecting %d\n",
					peer, libcfs_nid2str(peer->gnp_nid), peer->gnp_connecting);
				peer->gnp_connecting = GNILND_PEER_KILL;
				spin_lock(&dev->gnd_connd_lock);
				/* remove the peer ref frrom the cond list */
				kgnilnd_peer_decref(peer);
				/* let the system handle itself */
			}
			write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			/* the datagrams are a global pool,
			 * so break out of trying and hope some free
			 * up soon */
			did_something -= 1;
			break;
		} else {
			/* something bad happened, you lose */
			CNETERR("could not start connecting to %s "
				"rc %d: Will retry until TX timeout\n",
			       libcfs_nid2str(peer->gnp_nid), rc);
			/* It didnt post so just set connecting back to zero now.
			 * The reaper will reattempt the connection if it needs too.
			 * If the peer needs death set it so the reaper will cleanup.
			 */
			write_lock(&kgnilnd_data.kgn_peer_conn_lock);
			if (peer->gnp_connecting == GNILND_PEER_POSTING) {
				peer->gnp_connecting = GNILND_PEER_IDLE;
				kgnilnd_peer_increase_reconnect_locked(peer);
			} else {
				LASSERTF(peer->gnp_connecting == GNILND_PEER_NEEDS_DEATH, "Peer is in invalid"
					" state 0x%p->%s, connecting %d\n",
					peer, libcfs_nid2str(peer->gnp_nid), peer->gnp_connecting);
				peer->gnp_connecting = GNILND_PEER_KILL;
			}
			write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

			/* hold onto ref until we are really done - if it was
			 * unlinked this could result in a destroy */
			kgnilnd_peer_decref(peer);
		}
		spin_lock(&dev->gnd_connd_lock);
	}

	spin_unlock(&dev->gnd_connd_lock);
	RETURN(did_something);
}

int
kgnilnd_repost_wc_dgrams(kgn_device_t *dev)
{
	int did_something = 0, to_repost, i;
	to_repost = atomic_read(&dev->gnd_nwcdgrams);
	ENTRY;

	for (i = 0; i < to_repost; ++i) {
		int	rerc;
		rerc = kgnilnd_post_dgram(dev, LNET_NID_ANY, GNILND_CONNREQ_REQ, 0);
		if (rerc == 0) {
			kgnilnd_admin_decref(dev->gnd_nwcdgrams);
			did_something += 1;
		} else {
			CDEBUG(D_NETERROR, "error %d: dev %d could not post wildcard datagram\n",
				rerc, dev->gnd_id);
			break;
		}
	}

	RETURN(did_something);
}

struct kgnilnd_dgram_timer {
	struct timer_list timer;
	kgn_device_t *dev;
};

static void
kgnilnd_dgram_poke_with_stick(cfs_timer_cb_arg_t arg)
{
	struct kgnilnd_dgram_timer *t = cfs_from_timer(t, arg, timer);

	wake_up(&t->dev->gnd_dgram_waitq);
}

/* use single thread for dgrams - should be sufficient for performance */
int
kgnilnd_dgram_mover(void *arg)
{
	kgn_device_t            *dev = (kgn_device_t *)arg;
	char                     name[16];
	int                      rc, did_something;
	unsigned long            next_purge_check = jiffies - 1;
	unsigned long            timeout;
	struct kgnilnd_dgram_timer timer;
	unsigned long deadline = 0;
	DEFINE_WAIT(wait);

	snprintf(name, sizeof(name), "kgnilnd_dg_%02d", dev->gnd_id);

	/* all gnilnd threads need to run fairly urgently */
	set_user_nice(current, *kgnilnd_tunables.kgn_nice);

	/* we are ok not locking for these variables as the dgram waitq threads
	 * will block both due to tying up net (kgn_shutdown) and the completion
	 * event for the dgram_waitq (kgn_quiesce_trigger) */
	deadline = jiffies + cfs_time_seconds(*kgnilnd_tunables.kgn_dgram_timeout);
	while (!kgnilnd_data.kgn_shutdown) {
		/* Safe: kgn_shutdown only set when quiescent */

		/* race with stack reset - we want to hold off seeing any new incoming dgrams
		 * so we can force a dirty WC dgram for Bug 762072 - put right before
		 * quiesce check so that it'll go right into that and not do any
		 * dgram mucking */
		CFS_RACE(CFS_FAIL_GNI_WC_DGRAM_FREE);

		/* to quiesce or to not quiesce, that is the question */
		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			KGNILND_SPIN_QUIESCE;
		}
		did_something = 0;

		CFS_RACE(CFS_FAIL_GNI_QUIESCE_RACE);

		/* process any newly completed dgrams */
		down_read(&kgnilnd_data.kgn_net_rw_sem);

		rc = kgnilnd_probe_and_process_dgram(dev);
		if (rc > 0) {
			did_something += rc;
		}

		up_read(&kgnilnd_data.kgn_net_rw_sem);

		CFS_FAIL_TIMEOUT(CFS_FAIL_GNI_DGRAM_DEADLINE,
			(*kgnilnd_tunables.kgn_dgram_timeout + 1));
		/* start new outbound dgrams */
		did_something += kgnilnd_start_outbound_dgrams(dev, deadline);

		/* find dead dgrams */
		if (time_after_eq(jiffies, next_purge_check)) {
			/* these don't need to be checked that often */
			kgnilnd_reaper_dgram_check(dev);

			next_purge_check = (long) jiffies +
				      cfs_time_seconds(kgnilnd_data.kgn_new_min_timeout / 4);
		}

		did_something += kgnilnd_repost_wc_dgrams(dev);

		/* careful with the jiffy wrap... */
		timeout = (long)(next_purge_check - jiffies);

		CDEBUG(D_INFO, "did %d timeout %lu next %lu jiffies %lu\n",
		       did_something, timeout, next_purge_check, jiffies);

		if ((did_something || timeout <= 0) && time_before(jiffies, deadline)) {
			did_something = 0;
			continue;
		}

		prepare_to_wait(&dev->gnd_dgram_waitq, &wait, TASK_INTERRUPTIBLE);

		cfs_timer_setup(&timer.timer,
				kgnilnd_dgram_poke_with_stick,
				dev, 0);
		timer.dev = dev;
		mod_timer(&timer.timer, (long) jiffies + timeout);

		/* last second chance for others to poke us */
		did_something += xchg(&dev->gnd_dgram_ready, GNILND_DGRAM_IDLE);

		/* check flag variables before committing even if we
		 * did something; if we are after the deadline call
		 * schedule */
		if ((!did_something || time_after(jiffies, deadline)) &&
		    !kgnilnd_data.kgn_shutdown &&
		    !kgnilnd_data.kgn_quiesce_trigger) {
			CDEBUG(D_INFO, "schedule timeout %ld (%lu sec)\n",
			       timeout, cfs_duration_sec(timeout));
			wake_up(&dev->gnd_dgping_waitq);
			schedule();
			CDEBUG(D_INFO, "awake after schedule\n");
			deadline = jiffies + cfs_time_seconds(*kgnilnd_tunables.kgn_dgram_timeout);
		}

		del_singleshot_timer_sync(&timer.timer);
		finish_wait(&dev->gnd_dgram_waitq, &wait);
	}

	kgnilnd_thread_fini();
	return 0;
}
