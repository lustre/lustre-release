/*
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *
 * Copyright (C) 2009-2012 Cray, Inc.
 *
 *   Derived from work by Eric Barton <eric@bartonsoftware.com>
 *   Author: James Shimek <jshimek@cray.com>
 *   Author: Nic Henke <nic@cray.com>
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

#include <asm/page.h>
#include <linux/nmi.h>
#include "gnilnd.h"

/* this is useful when needed to debug wire corruption. */
static void
kgnilnd_dump_blob(int level, char *prefix, void *buf, int len) {
	__u64 *ptr;

	ptr = (__u64 *) buf;

	while (len > 0) {
		if (len >= 32) {
			CDEBUG(level,
			       "%s 0x%p: 0x%16.16llx 0x%16.16llx 0x%16.16llx 0x%16.16llx\n",
			       prefix, ptr, *(ptr), *(ptr + 1), *(ptr + 2), *(ptr + 3));
			ptr += 4;
			len -= 32;
		} else if (len >= 16) {
			CDEBUG(level,
			       "%s 0x%p: 0x%16.16llx 0x%16.16llx\n",
			       prefix, ptr, *(ptr), *(ptr + 1));
			ptr += 2;
			len -= 16;
		} else {
			CDEBUG(level, "%s 0x%p: 0x%16.16llx\n",
			       prefix, ptr, *(ptr));
			ptr++;
			len -= 8;
		}
	}
}

static void
kgnilnd_dump_msg(int mask, kgn_msg_t *msg)
{
	CDEBUG(mask, "0x%8.8x 0x%4.4x 0x%4.4x 0x%16.16llx"
		" 0x%16.16llx 0x%8.8x 0x%4.4x 0x%4.4x 0x%8.8x\n",
		msg->gnm_magic, msg->gnm_version,
		msg->gnm_type, msg->gnm_srcnid,
		msg->gnm_connstamp, msg->gnm_seq,
		msg->gnm_cksum, msg->gnm_payload_cksum,
		msg->gnm_payload_len);
}

void
kgnilnd_schedule_device(kgn_device_t *dev)
{
	short         already_live = 0;

	/* we'll only want to wake if the scheduler thread
	 * has come around and set ready to zero */
	already_live = cmpxchg(&dev->gnd_ready, GNILND_DEV_IDLE, GNILND_DEV_IRQ);

	if (!already_live) {
		wake_up_all(&dev->gnd_waitq);
	}
	return;
}

void kgnilnd_schedule_device_timer(unsigned long arg)
{
	kgn_device_t *dev = (kgn_device_t *) arg;

	kgnilnd_schedule_device(dev);
}

void
kgnilnd_device_callback(__u32 devid, __u64 arg)
{
	kgn_device_t *dev;
	int           index = (int) arg;

	if (index >= kgnilnd_data.kgn_ndevs) {
		/* use _EMERG instead of an LBUG to prevent LBUG'ing in
		 * interrupt context. */
		LCONSOLE_EMERG("callback for unknown device %d->%d\n",
				devid, index);
		return;
	}

	dev = &kgnilnd_data.kgn_devices[index];
	/* just basic sanity */
	if (dev->gnd_id == devid) {
		kgnilnd_schedule_device(dev);
	} else {
		LCONSOLE_EMERG("callback for bad device %d devid %d\n",
				dev->gnd_id, devid);
	}
}

/* sched_intent values:
 * < 0 : do not reschedule under any circumstances
 * == 0: reschedule if someone marked him WANTS_SCHED
 * > 0 : force a reschedule */
/* Return code 0 means it did not schedule the conn, 1
 * means it successfully scheduled the conn.
 */

int
kgnilnd_schedule_process_conn(kgn_conn_t *conn, int sched_intent)
{
	int     conn_sched;

	/* move back to IDLE but save previous state.
	 * if we see WANTS_SCHED, we'll call kgnilnd_schedule_conn and
	 * let the xchg there handle any racing callers to get it
	 * onto gnd_ready_conns */

	conn_sched = xchg(&conn->gnc_scheduled, GNILND_CONN_IDLE);
	LASSERTF(conn_sched == GNILND_CONN_WANTS_SCHED ||
		 conn_sched == GNILND_CONN_PROCESS,
		 "conn %p after process in bad state: %d\n",
		 conn, conn_sched);

	if (sched_intent >= 0) {
		if ((sched_intent > 0 || (conn_sched == GNILND_CONN_WANTS_SCHED))) {
			return kgnilnd_schedule_conn_refheld(conn, 1);
		}
	}
	return 0;
}

/* Return of 0 for conn not scheduled, 1 returned if conn was scheduled or marked
 * as scheduled */

int
_kgnilnd_schedule_conn(kgn_conn_t *conn, const char *caller, int line, int refheld)
{
	kgn_device_t        *dev = conn->gnc_device;
	int                  sched;
	int		     rc;

	sched = xchg(&conn->gnc_scheduled, GNILND_CONN_WANTS_SCHED);
	/* we only care about the last person who marked want_sched since they
	 * are most likely the culprit
	 */
	memcpy(conn->gnc_sched_caller, caller, sizeof(conn->gnc_sched_caller));
	conn->gnc_sched_line = line;
	/* if we are IDLE, add to list - only one guy sees IDLE and "wins"
	 * the chance to put it onto gnd_ready_conns.
	 * otherwise, leave marked as WANTS_SCHED and the thread that "owns"
	 *  the conn in process_conns will take care of moving it back to
	 *  SCHED when it is done processing */

	if (sched == GNILND_CONN_IDLE) {
		/* if the conn is already scheduled, we've already requested
		 * the scheduler thread wakeup */
		if (!refheld) {
			/* Add a reference to the conn if we are not holding a reference
			 * already from the exisiting scheduler. We now use the same
			 * reference if we need to reschedule a conn while in a scheduler
			 * thread.
			 */
			kgnilnd_conn_addref(conn);
		}
		LASSERTF(list_empty(&conn->gnc_schedlist), "conn %p already sched state %d\n",
			 conn, sched);

		CDEBUG(D_INFO, "scheduling conn 0x%p caller %s:%d\n", conn, caller, line);

		spin_lock(&dev->gnd_lock);
		list_add_tail(&conn->gnc_schedlist, &dev->gnd_ready_conns);
		spin_unlock(&dev->gnd_lock);
		set_mb(conn->gnc_last_sched_ask, jiffies);
		rc = 1;
	} else {
		CDEBUG(D_INFO, "not scheduling conn 0x%p: %d caller %s:%d\n", conn, sched, caller, line);
		rc = 0;
	}

	/* make sure thread(s) going to process conns - but let it make
	 * separate decision from conn schedule */
	kgnilnd_schedule_device(dev);
	return rc;
}

void
kgnilnd_schedule_dgram(kgn_device_t *dev)
{
	int                  wake;

	wake = xchg(&dev->gnd_dgram_ready, GNILND_DGRAM_SCHED);
	if (wake != GNILND_DGRAM_SCHED)  {
		wake_up(&dev->gnd_dgram_waitq);
	} else {
		CDEBUG(D_NETTRACE, "not waking: %d\n", wake);
	}
}

void
kgnilnd_free_tx(kgn_tx_t *tx)
{
	/* taken from kgnilnd_tx_add_state_locked */

	LASSERTF((tx->tx_list_p == NULL &&
		  tx->tx_list_state == GNILND_TX_ALLOCD) &&
		list_empty(&tx->tx_list),
		"tx %p with bad state %s (list_p %p) tx_list %s\n",
		tx, kgnilnd_tx_state2str(tx->tx_list_state), tx->tx_list_p,
		list_empty(&tx->tx_list) ? "empty" : "not empty");

	atomic_dec(&kgnilnd_data.kgn_ntx);

	/* we only allocate this if we need to */
	if (tx->tx_phys != NULL) {
		kmem_cache_free(kgnilnd_data.kgn_tx_phys_cache, tx->tx_phys);
		CDEBUG(D_MALLOC, "slab-freed 'tx_phys': %lu at %p.\n",
		       LNET_MAX_IOV * sizeof(gni_mem_segment_t), tx->tx_phys);
	}

	/* Only free the buffer if we used it */
	if (tx->tx_buffer_copy != NULL) {
		vfree(tx->tx_buffer_copy);
		tx->tx_buffer_copy = NULL;
		CDEBUG(D_MALLOC, "vfreed buffer2\n");
	}
#if 0
	KGNILND_POISON(tx, 0x5a, sizeof(kgn_tx_t));
#endif
	CDEBUG(D_MALLOC, "slab-freed 'tx': %lu at %p.\n", sizeof(*tx), tx);
	kmem_cache_free(kgnilnd_data.kgn_tx_cache, tx);
}

kgn_tx_t *
kgnilnd_alloc_tx (void)
{
	kgn_tx_t	*tx = NULL;

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_ALLOC_TX))
		return tx;

	tx = kmem_cache_alloc(kgnilnd_data.kgn_tx_cache, GFP_ATOMIC);
	if (tx == NULL) {
		CERROR("failed to allocate tx\n");
		return NULL;
	}
	CDEBUG(D_MALLOC, "slab-alloced 'tx': %lu at %p.\n",
	       sizeof(*tx), tx);

	/* need this memset, cache alloc'd memory is not cleared */
	memset(tx, 0, sizeof(*tx));

	/* setup everything here to minimize time under the lock */
	tx->tx_buftype = GNILND_BUF_NONE;
	tx->tx_msg.gnm_type = GNILND_MSG_NONE;
	INIT_LIST_HEAD(&tx->tx_list);
	INIT_LIST_HEAD(&tx->tx_map_list);
	tx->tx_list_state = GNILND_TX_ALLOCD;

	atomic_inc(&kgnilnd_data.kgn_ntx);

	return tx;
}

/* csum_fold needs to be run on the return value before shipping over the wire */
#define _kgnilnd_cksum(seed, ptr, nob)  csum_partial(ptr, nob, seed)

/* we don't use offset as every one is passing a buffer reference that already
 * includes the offset into the base address -
 *  see kgnilnd_setup_virt_buffer and kgnilnd_setup_immediate_buffer */
static inline __u16
kgnilnd_cksum(void *ptr, size_t nob)
{
	__u16   sum;

	sum = csum_fold(_kgnilnd_cksum(0, ptr, nob));

	/* don't use magic 'no checksum' value */
	if (sum == 0)
		sum = 1;

	CDEBUG(D_INFO, "cksum 0x%x for ptr 0x%p sz %zu\n",
	       sum, ptr, nob);

	return sum;
}

inline __u16
kgnilnd_cksum_kiov(unsigned int nkiov, lnet_kiov_t *kiov,
		    unsigned int offset, unsigned int nob, int dump_blob)
{
	__wsum             cksum = 0;
	__wsum             tmpck;
	__u16              retsum;
	void              *addr;
	unsigned int       fraglen;
	int                i, odd;

	LASSERT(nkiov > 0);
	LASSERT(nob > 0);

	CDEBUG(D_BUFFS, "calc cksum for kiov 0x%p nkiov %u offset %u nob %u, dump %d\n",
	       kiov, nkiov, offset, nob, dump_blob);

	/* if loops changes, please change kgnilnd_setup_phys_buffer */

	while (offset >= kiov->kiov_len) {
		offset -= kiov->kiov_len;
		nkiov--;
		kiov++;
		LASSERT(nkiov > 0);
	}

	/* ignore nob here, if nob < (kiov_len - offset), kiov == 1 */
	odd = (unsigned long) (kiov[0].kiov_len - offset) & 1;

	if ((odd || *kgnilnd_tunables.kgn_vmap_cksum) && nkiov > 1) {
		struct page **pages = kgnilnd_data.kgn_cksum_map_pages[get_cpu()];

		LASSERTF(pages != NULL, "NULL pages for cpu %d map_pages 0x%p\n",
			 get_cpu(), kgnilnd_data.kgn_cksum_map_pages);

		CDEBUG(D_BUFFS, "odd %d len %u offset %u nob %u\n",
		       odd, kiov[0].kiov_len, offset, nob);

		for (i = 0; i < nkiov; i++) {
			pages[i] = kiov[i].kiov_page;
		}

		addr = vmap(pages, nkiov, VM_MAP, PAGE_KERNEL);
		if (addr == NULL) {
			CNETERR("Couldn't vmap %d frags on %d bytes to avoid odd length fragment in cksum\n",
				nkiov, nob);
			/* return zero to avoid killing tx - we'll just get warning on console
			 * when remote end sees zero checksum */
			RETURN(0);
		}
		atomic_inc(&kgnilnd_data.kgn_nvmap_cksum);

		tmpck = _kgnilnd_cksum(0, (void *) addr + kiov[0].kiov_offset + offset, nob);
		cksum = tmpck;

		if (dump_blob) {
			kgnilnd_dump_blob(D_BUFFS, "flat kiov RDMA payload",
					  (void *)addr + kiov[0].kiov_offset + offset, nob);
		}
		CDEBUG(D_BUFFS, "cksum 0x%x (+0x%x) for addr 0x%p+%u len %u offset %u\n",
		       cksum, tmpck, addr, kiov[0].kiov_offset, nob, offset);
		vunmap(addr);
	} else {
		do {
			fraglen = min(kiov->kiov_len - offset, nob);

			/* make dang sure we don't send a bogus checksum if somehow we get
			 * an odd length fragment on anything but the last entry in a kiov  -
			 * we know from kgnilnd_setup_rdma_buffer that we can't have non
			 * PAGE_SIZE pages in the middle, so if nob < PAGE_SIZE, it is the last one */
			LASSERTF(!(fraglen&1) || (nob < PAGE_SIZE),
				 "odd fraglen %u on nkiov %d, nob %u kiov_len %u offset %u kiov 0x%p\n",
				 fraglen, nkiov, nob, kiov->kiov_len, offset, kiov);

			addr = (void *)kmap(kiov->kiov_page) + kiov->kiov_offset + offset;
			tmpck = _kgnilnd_cksum(cksum, addr, fraglen);

			CDEBUG(D_BUFFS,
			       "cksum 0x%x (+0x%x) for page 0x%p+%u (0x%p) len %u offset %u\n",
			       cksum, tmpck, kiov->kiov_page, kiov->kiov_offset, addr,
			       fraglen, offset);

			cksum = tmpck;

			if (dump_blob)
				kgnilnd_dump_blob(D_BUFFS, "kiov cksum", addr, fraglen);

			kunmap(kiov->kiov_page);

			kiov++;
			nkiov--;
			nob -= fraglen;
			offset = 0;

			/* iov must not run out before end of data */
			LASSERTF(nob == 0 || nkiov > 0, "nob %u nkiov %u\n", nob, nkiov);

		} while (nob > 0);
	}

	retsum = csum_fold(cksum);

	/* don't use magic 'no checksum' value */
	if (retsum == 0)
		retsum = 1;

	CDEBUG(D_BUFFS, "retsum 0x%x from cksum 0x%x\n", retsum, cksum);

	return retsum;
}

void
kgnilnd_init_msg(kgn_msg_t *msg, int type, lnet_nid_t source)
{
	msg->gnm_magic = GNILND_MSG_MAGIC;
	msg->gnm_version = GNILND_MSG_VERSION;
	msg->gnm_type = type;
	msg->gnm_payload_len = 0;
	msg->gnm_srcnid = source;
	/* gnm_connstamp gets set when FMA is sent */
	/* gnm_srcnid is set on creation via function argument
	 * The right interface/net and nid is passed in when the message
	 * is created.
	 */
}

kgn_tx_t *
kgnilnd_new_tx_msg(int type, lnet_nid_t source)
{
	kgn_tx_t *tx = kgnilnd_alloc_tx();

	if (tx != NULL) {
		kgnilnd_init_msg(&tx->tx_msg, type, source);
	} else {
		CERROR("couldn't allocate new tx type %s!\n",
		       kgnilnd_msgtype2str(type));
	}

	return tx;
}

static void
kgnilnd_nak_rdma(kgn_conn_t *conn, int rx_type, int error, __u64 cookie, lnet_nid_t source) {
	kgn_tx_t        *tx;

	int		nak_type;

	switch (rx_type) {
	case GNILND_MSG_GET_REQ:
	case GNILND_MSG_GET_DONE:
		nak_type = GNILND_MSG_GET_NAK;
		break;
	case GNILND_MSG_PUT_REQ:
	case GNILND_MSG_PUT_ACK:
	case GNILND_MSG_PUT_DONE:
		nak_type = GNILND_MSG_PUT_NAK;
		break;
	case GNILND_MSG_PUT_REQ_REV:
	case GNILND_MSG_PUT_DONE_REV:
		nak_type = GNILND_MSG_PUT_NAK_REV;
		break;
	case GNILND_MSG_GET_REQ_REV:
	case GNILND_MSG_GET_ACK_REV:
	case GNILND_MSG_GET_DONE_REV:
		nak_type = GNILND_MSG_GET_NAK_REV;
		break;
	default:
		CERROR("invalid msg type %s (%d)\n",
			kgnilnd_msgtype2str(rx_type), rx_type);
		LBUG();
	}
	/* only allow NAK on error and truncate to zero */
	LASSERTF(error <= 0, "error %d conn 0x%p, cookie "LPU64"\n",
		 error, conn, cookie);

	tx = kgnilnd_new_tx_msg(nak_type, source);
	if (tx == NULL) {
		CNETERR("can't get TX to NAK RDMA to %s\n",
			libcfs_nid2str(conn->gnc_peer->gnp_nid));
		return;
	}

	tx->tx_msg.gnm_u.completion.gncm_retval = error;
	tx->tx_msg.gnm_u.completion.gncm_cookie = cookie;
	kgnilnd_queue_tx(conn, tx);
}

int
kgnilnd_setup_immediate_buffer(kgn_tx_t *tx, unsigned int niov,
			       struct kvec *iov, lnet_kiov_t *kiov,
			       unsigned int offset, unsigned int nob)
{
	kgn_msg_t       *msg = &tx->tx_msg;
	int              i;

	/* To help save on MDDs for short messages, we'll vmap a kiov to allow
	 * gni_smsg_send to send that as the payload */

	LASSERT(tx->tx_buftype == GNILND_BUF_NONE);

	if (nob == 0) {
		tx->tx_buffer = NULL;
	} else if (kiov != NULL) {

		if ((niov > 0) && unlikely(niov > (nob/PAGE_SIZE))) {
			niov = ((nob + offset + kiov->kiov_offset + PAGE_SIZE - 1) /
				PAGE_SIZE);
		}

		LASSERTF(niov > 0 && niov < GNILND_MAX_IMMEDIATE/PAGE_SIZE,
			"bad niov %d msg %p kiov %p iov %p offset %d nob%d\n",
			niov, msg, kiov, iov, offset, nob);

		while (offset >= kiov->kiov_len) {
			offset -= kiov->kiov_len;
			niov--;
			kiov++;
			LASSERT(niov > 0);
		}
		for (i = 0; i < niov; i++) {
			/* We can't have a kiov_offset on anything but the first entry,
			 * otherwise we'll have a hole at the end of the mapping as we only map
			 * whole pages.
			 * Also, if we have a kiov_len < PAGE_SIZE but we need to map more
			 * than kiov_len, we will also have a whole at the end of that page
			 * which isn't allowed */
			if ((kiov[i].kiov_offset != 0 && i > 0) ||
			    (kiov[i].kiov_offset + kiov[i].kiov_len != PAGE_SIZE && i < niov - 1)) {
				CNETERR("Can't make payload contiguous in I/O VM:"
				       "page %d, offset %u, nob %u, kiov_offset %u kiov_len %u \n",
				       i, offset, nob, kiov->kiov_offset, kiov->kiov_len);
				RETURN(-EINVAL);
			}
			tx->tx_imm_pages[i] = kiov[i].kiov_page;
		}

		/* hijack tx_phys for the later unmap */
		if (niov == 1) {
			/* tx->phyx being equal to NULL is the signal for unmap to discern between kmap and vmap */
			tx->tx_phys = NULL;
			tx->tx_buffer = (void *)kmap(tx->tx_imm_pages[0]) + kiov[0].kiov_offset + offset;
			atomic_inc(&kgnilnd_data.kgn_nkmap_short);
			GNIDBG_TX(D_NET, tx, "kmapped page for %d bytes for kiov 0x%p, buffer 0x%p",
				nob, kiov, tx->tx_buffer);
		} else {
			tx->tx_phys = vmap(tx->tx_imm_pages, niov, VM_MAP, PAGE_KERNEL);
			if (tx->tx_phys == NULL) {
				CNETERR("Couldn't vmap %d frags on %d bytes\n", niov, nob);
				RETURN(-ENOMEM);

			}
			atomic_inc(&kgnilnd_data.kgn_nvmap_short);
			/* make sure we take into account the kiov offset as the start of the buffer */
			tx->tx_buffer = (void *)tx->tx_phys + kiov[0].kiov_offset + offset;
			GNIDBG_TX(D_NET, tx, "mapped %d pages for %d bytes from kiov 0x%p to 0x%p, buffer 0x%p",
				niov, nob, kiov, tx->tx_phys, tx->tx_buffer);
		}
		tx->tx_buftype = GNILND_BUF_IMMEDIATE_KIOV;
		tx->tx_nob = nob;

	} else {
		/* For now this is almost identical to kgnilnd_setup_virt_buffer, but we
		 * could "flatten" the payload into a single contiguous buffer ready
		 * for sending direct over an FMA if we ever needed to. */

		LASSERT(niov > 0);

		while (offset >= iov->iov_len) {
			offset -= iov->iov_len;
			niov--;
			iov++;
			LASSERT(niov > 0);
		}

		if (nob > iov->iov_len - offset) {
			CERROR("Can't handle multiple vaddr fragments\n");
			return -EMSGSIZE;
		}

		tx->tx_buffer = (void *)(((unsigned long)iov->iov_base) + offset);

		tx->tx_buftype = GNILND_BUF_IMMEDIATE;
		tx->tx_nob = nob;
	}

	/* checksum payload early - it shouldn't be changing after lnd_send */
	if (*kgnilnd_tunables.kgn_checksum >= 2) {
		msg->gnm_payload_cksum = kgnilnd_cksum(tx->tx_buffer, nob);
		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_SMSG_CKSUM2)) {
			msg->gnm_payload_cksum += 0xe00e;
		}
		if (*kgnilnd_tunables.kgn_checksum_dump > 1) {
			kgnilnd_dump_blob(D_BUFFS, "payload checksum",
					  tx->tx_buffer, nob);
		}
	} else {
		msg->gnm_payload_cksum = 0;
	}

	return 0;
}

int
kgnilnd_setup_virt_buffer(kgn_tx_t *tx,
			  unsigned int niov, struct kvec *iov,
			  unsigned int offset, unsigned int nob)

{
	LASSERT(nob > 0);
	LASSERT(niov > 0);
	LASSERT(tx->tx_buftype == GNILND_BUF_NONE);

	while (offset >= iov->iov_len) {
		offset -= iov->iov_len;
		niov--;
		iov++;
		LASSERT(niov > 0);
	}

	if (nob > iov->iov_len - offset) {
		CERROR("Can't handle multiple vaddr fragments\n");
		return -EMSGSIZE;
	}

	tx->tx_buftype = GNILND_BUF_VIRT_UNMAPPED;
	tx->tx_nob = nob;
	tx->tx_buffer = (void *)(((unsigned long)iov->iov_base) + offset);
	return 0;
}

int
kgnilnd_setup_phys_buffer(kgn_tx_t *tx, int nkiov, lnet_kiov_t *kiov,
			  unsigned int offset, unsigned int nob)
{
	gni_mem_segment_t *phys;
	int		rc = 0;
	unsigned int	fraglen;

	GNIDBG_TX(D_NET, tx, "niov %d kiov 0x%p offset %u nob %u", nkiov, kiov, offset, nob);

	LASSERT(nob > 0);
	LASSERT(nkiov > 0);
	LASSERT(tx->tx_buftype == GNILND_BUF_NONE);

	/* only allocate this if we are going to use it */
	tx->tx_phys = kmem_cache_alloc(kgnilnd_data.kgn_tx_phys_cache,
					      GFP_ATOMIC);
	if (tx->tx_phys == NULL) {
		CERROR("failed to allocate tx_phys\n");
		rc = -ENOMEM;
		GOTO(error, rc);
	}

	CDEBUG(D_MALLOC, "slab-alloced 'tx->tx_phys': %lu at %p.\n",
	       LNET_MAX_IOV * sizeof(gni_mem_segment_t), tx->tx_phys);

	/* if loops changes, please change kgnilnd_cksum_kiov
	 *   and kgnilnd_setup_immediate_buffer */

	while (offset >= kiov->kiov_len) {
		offset -= kiov->kiov_len;
		nkiov--;
		kiov++;
		LASSERT(nkiov > 0);
	}

	/* at this point, kiov points to the first page that we'll actually map
	 * now that we've seeked into the koiv for offset and dropped any
	 * leading pages that fall entirely within the offset */
	tx->tx_buftype = GNILND_BUF_PHYS_UNMAPPED;
	tx->tx_nob = nob;

	/* kiov_offset is start of 'valid' buffer, so index offset past that */
	tx->tx_buffer = (void *)((unsigned long)(kiov->kiov_offset + offset));
	phys = tx->tx_phys;

	CDEBUG(D_NET, "tx 0x%p buffer 0x%p map start kiov 0x%p+%u niov %d offset %u\n",
	       tx, tx->tx_buffer, kiov, kiov->kiov_offset, nkiov, offset);

	do {
		fraglen = min(kiov->kiov_len - offset, nob);

		/* We can't have a kiov_offset on anything but the first entry,
		 * otherwise we'll have a hole at the end of the mapping as we only map
		 * whole pages. Only the first page is allowed to have an offset -
		 * we'll add that into tx->tx_buffer and that will get used when we
		 * map in the segments (see kgnilnd_map_buffer).
		 * Also, if we have a kiov_len < PAGE_SIZE but we need to map more
		 * than kiov_len, we will also have a whole at the end of that page
		 * which isn't allowed */
		if ((phys != tx->tx_phys) &&
		    ((kiov->kiov_offset != 0) ||
		     ((kiov->kiov_len < PAGE_SIZE) && (nob > kiov->kiov_len)))) {
			CERROR("Can't make payload contiguous in I/O VM:"
			       "page %d, offset %u, nob %u, kiov_offset %u kiov_len %u \n",
			       (int)(phys - tx->tx_phys),
			       offset, nob, kiov->kiov_offset, kiov->kiov_len);
			rc = -EINVAL;
			GOTO(error, rc);
		}

		if ((phys - tx->tx_phys) == LNET_MAX_IOV) {
			CERROR ("payload too big (%d)\n", (int)(phys - tx->tx_phys));
			rc = -EMSGSIZE;
			GOTO(error, rc);
		}

		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PHYS_SETUP)) {
			rc = -EINVAL;
			GOTO(error, rc);
		}

		CDEBUG(D_BUFFS, "page 0x%p kiov_offset %u kiov_len %u nob %u "
			       "nkiov %u offset %u\n",
		      kiov->kiov_page, kiov->kiov_offset, kiov->kiov_len, nob, nkiov, offset);

		phys->address = page_to_phys(kiov->kiov_page);
		phys++;
		kiov++;
		nkiov--;
		nob -= fraglen;
		offset = 0;

		/* iov must not run out before end of data */
		LASSERTF(nob == 0 || nkiov > 0, "nob %u nkiov %u\n", nob, nkiov);

	} while (nob > 0);

	tx->tx_phys_npages = phys - tx->tx_phys;

	return 0;

error:
	if (tx->tx_phys != NULL) {
		kmem_cache_free(kgnilnd_data.kgn_tx_phys_cache, tx->tx_phys);
		CDEBUG(D_MALLOC, "slab-freed 'tx_phys': %lu at %p.\n",
		       sizeof(*tx->tx_phys), tx->tx_phys);
		tx->tx_phys = NULL;
	}
	return rc;
}

static inline int
kgnilnd_setup_rdma_buffer(kgn_tx_t *tx, unsigned int niov,
			  struct kvec *iov, lnet_kiov_t *kiov,
			  unsigned int offset, unsigned int nob)
{
	int     rc;

	LASSERTF((iov == NULL) != (kiov == NULL), "iov 0x%p, kiov 0x%p, tx 0x%p,"
						" offset %d, nob %d, niov %d\n"
						, iov, kiov, tx, offset, nob, niov);

	if (kiov != NULL) {
		rc = kgnilnd_setup_phys_buffer(tx, niov, kiov, offset, nob);
	} else {
		rc = kgnilnd_setup_virt_buffer(tx, niov, iov, offset, nob);
	}
	return rc;
}

/* kgnilnd_parse_lnet_rdma()
 * lntmsg - message passed in from lnet.
 * niov, kiov, offset - see lnd_t in lib-types.h for descriptions.
 * nob - actual number of bytes to in this message.
 * put_len - It is possible for PUTs to have a different length than the
 *           length stored in lntmsg->msg_len since LNET can adjust this
 *           length based on it's buffer size and offset.
 *           lnet_try_match_md() sets the mlength that we use to do the RDMA
 *           transfer.
 */
static void
kgnilnd_parse_lnet_rdma(lnet_msg_t *lntmsg, unsigned int *niov,
			unsigned int *offset, unsigned int *nob,
			lnet_kiov_t **kiov, int put_len)
{
	/* GETs are weird, see kgnilnd_send */
	if (lntmsg->msg_type == LNET_MSG_GET) {
		if ((lntmsg->msg_md->md_options & LNET_MD_KIOV) == 0) {
			*kiov = NULL;
		} else {
			*kiov = lntmsg->msg_md->md_iov.kiov;
		}
		*niov = lntmsg->msg_md->md_niov;
		*nob = lntmsg->msg_md->md_length;
		*offset = 0;
	} else {
		*kiov = lntmsg->msg_kiov;
		*niov = lntmsg->msg_niov;
		*nob = put_len;
		*offset = lntmsg->msg_offset;
	}
}

static inline void
kgnilnd_compute_rdma_cksum(kgn_tx_t *tx, int put_len)
{
	unsigned int     niov, offset, nob;
	lnet_kiov_t     *kiov;
	lnet_msg_t      *lntmsg = tx->tx_lntmsg[0];
	int              dump_cksum = (*kgnilnd_tunables.kgn_checksum_dump > 1);

	GNITX_ASSERTF(tx, ((tx->tx_msg.gnm_type == GNILND_MSG_PUT_DONE) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_GET_DONE) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_PUT_DONE_REV) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_GET_DONE_REV) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_GET_ACK_REV) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_PUT_REQ_REV)),
		      "bad type %s", kgnilnd_msgtype2str(tx->tx_msg.gnm_type));

	if ((tx->tx_msg.gnm_type == GNILND_MSG_PUT_DONE_REV) ||
	    (tx->tx_msg.gnm_type == GNILND_MSG_GET_DONE_REV)) {
		tx->tx_msg.gnm_payload_cksum = 0;
		return;
	}
	if (*kgnilnd_tunables.kgn_checksum < 3) {
		tx->tx_msg.gnm_payload_cksum = 0;
		return;
	}

	GNITX_ASSERTF(tx, lntmsg, "no LNet message!", NULL);

	kgnilnd_parse_lnet_rdma(lntmsg, &niov, &offset, &nob, &kiov,
				put_len);

	if (kiov != NULL) {
		tx->tx_msg.gnm_payload_cksum = kgnilnd_cksum_kiov(niov, kiov, offset, nob, dump_cksum);
	} else {
		tx->tx_msg.gnm_payload_cksum = kgnilnd_cksum(tx->tx_buffer, nob);
		if (dump_cksum) {
			kgnilnd_dump_blob(D_BUFFS, "peer RDMA payload", tx->tx_buffer, nob);
		}
	}

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_SMSG_CKSUM3)) {
		tx->tx_msg.gnm_payload_cksum += 0xd00d;
	}
}

/* kgnilnd_verify_rdma_cksum()
 * tx - PUT_DONE/GET_DONE matched tx.
 * rx_cksum - received checksum to compare against.
 * put_len - see kgnilnd_parse_lnet_rdma comments.
 */
static inline int
kgnilnd_verify_rdma_cksum(kgn_tx_t *tx, __u16 rx_cksum, int put_len)
{
	int              rc = 0;
	__u16            cksum;
	unsigned int     niov, offset, nob;
	lnet_kiov_t     *kiov;
	lnet_msg_t      *lntmsg = tx->tx_lntmsg[0];
	int dump_on_err = *kgnilnd_tunables.kgn_checksum_dump;

	/* we can only match certain requests */
	GNITX_ASSERTF(tx, ((tx->tx_msg.gnm_type == GNILND_MSG_GET_REQ) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_PUT_ACK) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_PUT_REQ_REV) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_GET_ACK_REV) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_GET_DONE_REV) ||
			   (tx->tx_msg.gnm_type == GNILND_MSG_PUT_DONE_REV)),
		      "bad type %s", kgnilnd_msgtype2str(tx->tx_msg.gnm_type));

	if ((tx->tx_msg.gnm_type == GNILND_MSG_PUT_REQ_REV) ||
	    (tx->tx_msg.gnm_type == GNILND_MSG_GET_ACK_REV)) {
		return 0;
	}

	if (rx_cksum == 0)  {
		if (*kgnilnd_tunables.kgn_checksum >= 3) {
			GNIDBG_MSG(D_WARNING, &tx->tx_msg,
				   "no RDMA payload checksum when enabled");
		}
		return 0;
	}

	GNITX_ASSERTF(tx, lntmsg, "no LNet message!", NULL);

	kgnilnd_parse_lnet_rdma(lntmsg, &niov, &offset, &nob, &kiov, put_len);

	if (kiov != NULL) {
		cksum = kgnilnd_cksum_kiov(niov, kiov, offset, nob, 0);
	} else {
		cksum = kgnilnd_cksum(tx->tx_buffer, nob);
	}

	if (cksum != rx_cksum) {
		GNIDBG_MSG(D_NETERROR, &tx->tx_msg,
			   "Bad RDMA payload checksum (%x expected %x); "
			   "kiov 0x%p niov %d nob %u offset %u",
			    cksum, rx_cksum, kiov, niov, nob, offset);
		switch (dump_on_err) {
		case 2:
			if (kiov != NULL) {
				kgnilnd_cksum_kiov(niov, kiov, offset, nob, 1);
			} else {
				kgnilnd_dump_blob(D_BUFFS, "RDMA payload",
						  tx->tx_buffer, nob);
			}
			/* fall through to dump log */
		case 1:
			libcfs_debug_dumplog();
			break;
		default:
			break;
		}
		rc = -ENOKEY;
		/* kgnilnd_check_fma_rx will close conn, kill tx with error */
	}
	return rc;
}

void
kgnilnd_mem_add_map_list(kgn_device_t *dev, kgn_tx_t *tx)
{
	int     bytes;

	GNITX_ASSERTF(tx, list_empty(&tx->tx_map_list),
		"already mapped!", NULL);

	spin_lock(&dev->gnd_map_lock);
	switch (tx->tx_buftype) {
	default:
		GNIDBG_TX(D_EMERG, tx,
			"SOFTWARE BUG: invalid mapping %d", tx->tx_buftype);
		spin_unlock(&dev->gnd_map_lock);
		LBUG();
		break;

	case GNILND_BUF_PHYS_MAPPED:
		bytes = tx->tx_phys_npages * PAGE_SIZE;
		dev->gnd_map_nphys++;
		dev->gnd_map_physnop += tx->tx_phys_npages;
		break;

	case GNILND_BUF_VIRT_MAPPED:
		bytes = tx->tx_nob;
		dev->gnd_map_nvirt++;
		dev->gnd_map_virtnob += tx->tx_nob;
		break;
	}

	if (tx->tx_msg.gnm_type == GNILND_MSG_PUT_ACK ||
	    tx->tx_msg.gnm_type == GNILND_MSG_GET_REQ) {
		atomic64_add(bytes, &dev->gnd_rdmaq_bytes_out);
		GNIDBG_TX(D_NETTRACE, tx, "rdma ++ %d to "LPD64"",
			  bytes, atomic64_read(&dev->gnd_rdmaq_bytes_out));
	}

	atomic_inc(&dev->gnd_n_mdd);
	atomic64_add(bytes, &dev->gnd_nbytes_map);

	/* clear retrans to prevent any SMSG goofiness as that code uses the same counter */
	tx->tx_retrans = 0;

	/* we only get here in the valid cases */
	list_add_tail(&tx->tx_map_list, &dev->gnd_map_list);
	dev->gnd_map_version++;
	spin_unlock(&dev->gnd_map_lock);
}

void
kgnilnd_mem_del_map_list(kgn_device_t *dev, kgn_tx_t *tx)
{
	int     bytes;

	GNITX_ASSERTF(tx, !list_empty(&tx->tx_map_list),
		"not mapped!", NULL);
	spin_lock(&dev->gnd_map_lock);

	switch (tx->tx_buftype) {
	default:
		GNIDBG_TX(D_EMERG, tx,
			"SOFTWARE BUG: invalid mapping %d", tx->tx_buftype);
		spin_unlock(&dev->gnd_map_lock);
		LBUG();
		break;

	case GNILND_BUF_PHYS_UNMAPPED:
		bytes = tx->tx_phys_npages * PAGE_SIZE;
		dev->gnd_map_nphys--;
		dev->gnd_map_physnop -= tx->tx_phys_npages;
		break;

	case GNILND_BUF_VIRT_UNMAPPED:
		bytes = tx->tx_nob;
		dev->gnd_map_nvirt--;
		dev->gnd_map_virtnob -= tx->tx_nob;
		break;
	}

	if (tx->tx_msg.gnm_type == GNILND_MSG_PUT_ACK ||
	    tx->tx_msg.gnm_type == GNILND_MSG_GET_REQ) {
		atomic64_sub(bytes, &dev->gnd_rdmaq_bytes_out);
		LASSERTF(atomic64_read(&dev->gnd_rdmaq_bytes_out) >= 0,
			 "bytes_out negative! %ld\n", atomic64_read(&dev->gnd_rdmaq_bytes_out));
		GNIDBG_TX(D_NETTRACE, tx, "rdma -- %d to "LPD64"",
			  bytes, atomic64_read(&dev->gnd_rdmaq_bytes_out));
	}

	atomic_dec(&dev->gnd_n_mdd);
	atomic64_sub(bytes, &dev->gnd_nbytes_map);

	/* we only get here in the valid cases */
	list_del_init(&tx->tx_map_list);
	dev->gnd_map_version++;
	spin_unlock(&dev->gnd_map_lock);
}

int
kgnilnd_map_buffer(kgn_tx_t *tx)
{
	kgn_conn_t       *conn = tx->tx_conn;
	kgn_device_t     *dev = conn->gnc_device;
	__u32             flags = GNI_MEM_READWRITE;
	gni_return_t      rrc;

	/* The kgnilnd_mem_register(_segments) Gemini Driver functions can
	 * be called concurrently as there are internal locks that protect
	 * any data structures or HW resources. We just need to ensure
	 * that our concurrency doesn't result in the kgn_device_t
	 * getting nuked while we are in here */

	LASSERTF(conn != NULL, "tx %p with NULL conn, someone forgot"
		" to set tx_conn before calling %s\n", tx, __FUNCTION__);

	if (unlikely(CFS_FAIL_CHECK(CFS_FAIL_GNI_MAP_TX)))
		RETURN(-ENOMEM);

	if (*kgnilnd_tunables.kgn_bte_relaxed_ordering) {
		flags |= GNI_MEM_RELAXED_PI_ORDERING;
	}

	switch (tx->tx_buftype) {
	default:
		LBUG();

	case GNILND_BUF_NONE:
	case GNILND_BUF_IMMEDIATE:
	case GNILND_BUF_IMMEDIATE_KIOV:
	case GNILND_BUF_PHYS_MAPPED:
	case GNILND_BUF_VIRT_MAPPED:
		return 0;

	case GNILND_BUF_PHYS_UNMAPPED:
		GNITX_ASSERTF(tx, tx->tx_phys != NULL, "physical buffer not there!", NULL);
		rrc = kgnilnd_mem_register_segments(dev->gnd_handle,
			tx->tx_phys, tx->tx_phys_npages, NULL,
			GNI_MEM_PHYS_SEGMENTS | flags,
			&tx->tx_map_key);
		/* could race with other uses of the map counts, but this is ok
		 * - this needs to turn into a non-fatal error soon to allow
		 *  GART resource, etc starvation handling */
		if (rrc != GNI_RC_SUCCESS) {
			GNIDBG_TX(D_NET, tx, "Can't map %d pages: dev %d "
				"phys %u pp %u, virt %u nob "LPU64"",
				tx->tx_phys_npages, dev->gnd_id,
				dev->gnd_map_nphys, dev->gnd_map_physnop,
				dev->gnd_map_nvirt, dev->gnd_map_virtnob);
			RETURN(rrc == GNI_RC_ERROR_RESOURCE ? -ENOMEM : -EINVAL);
		}

		tx->tx_buftype = GNILND_BUF_PHYS_MAPPED;
		kgnilnd_mem_add_map_list(dev, tx);
		return 0;

	case GNILND_BUF_VIRT_UNMAPPED:
		rrc = kgnilnd_mem_register(dev->gnd_handle,
			(__u64)tx->tx_buffer, tx->tx_nob,
			NULL, flags, &tx->tx_map_key);
		if (rrc != GNI_RC_SUCCESS) {
			GNIDBG_TX(D_NET, tx, "Can't map %u bytes: dev %d "
				"phys %u pp %u, virt %u nob "LPU64"",
				tx->tx_nob, dev->gnd_id,
				dev->gnd_map_nphys, dev->gnd_map_physnop,
				dev->gnd_map_nvirt, dev->gnd_map_virtnob);
			RETURN(rrc == GNI_RC_ERROR_RESOURCE ? -ENOMEM : -EINVAL);
		}

		tx->tx_buftype = GNILND_BUF_VIRT_MAPPED;
		kgnilnd_mem_add_map_list(dev, tx);
		if (tx->tx_msg.gnm_type == GNILND_MSG_PUT_ACK ||
		    tx->tx_msg.gnm_type == GNILND_MSG_GET_REQ) {
			atomic64_add(tx->tx_nob, &dev->gnd_rdmaq_bytes_out);
			GNIDBG_TX(D_NETTRACE, tx, "rdma ++ %d to %ld\n",
			       tx->tx_nob, atomic64_read(&dev->gnd_rdmaq_bytes_out));
		}

		return 0;
	}
}

void
kgnilnd_add_purgatory_tx(kgn_tx_t *tx)
{
	kgn_conn_t		*conn = tx->tx_conn;
	kgn_mdd_purgatory_t	*gmp;

	LIBCFS_ALLOC(gmp, sizeof(*gmp));
	LASSERTF(gmp != NULL, "couldn't allocate MDD purgatory member;"
		" asserting to avoid data corruption\n");
	if (tx->tx_buffer_copy)
		gmp->gmp_map_key = tx->tx_buffer_copy_map_key;
	else
		gmp->gmp_map_key = tx->tx_map_key;

	atomic_inc(&conn->gnc_device->gnd_n_mdd_held);

	/* ensure that we don't have a blank purgatory - indicating the
	 * conn is not already on purgatory lists - we'd never recover these
	 * MDD if that were the case */
	GNITX_ASSERTF(tx, conn->gnc_in_purgatory,
		"conn 0x%p->%s with NULL purgatory",
		conn, libcfs_nid2str(conn->gnc_peer->gnp_nid));

	/* link 'er up! - only place we really need to lock for
	 * concurrent access */
	spin_lock(&conn->gnc_list_lock);
	list_add_tail(&gmp->gmp_list, &conn->gnc_mdd_list);
	spin_unlock(&conn->gnc_list_lock);
}

void
kgnilnd_unmap_buffer(kgn_tx_t *tx, int error)
{
	kgn_device_t     *dev;
	gni_return_t      rrc;
	int               hold_timeout = 0;

	/* code below relies on +1 relationship ... */
	CLASSERT(GNILND_BUF_PHYS_MAPPED == (GNILND_BUF_PHYS_UNMAPPED + 1));
	CLASSERT(GNILND_BUF_VIRT_MAPPED == (GNILND_BUF_VIRT_UNMAPPED + 1));

	switch (tx->tx_buftype) {
	default:
		LBUG();

	case GNILND_BUF_NONE:
	case GNILND_BUF_IMMEDIATE:
	case GNILND_BUF_PHYS_UNMAPPED:
	case GNILND_BUF_VIRT_UNMAPPED:
		break;
	case GNILND_BUF_IMMEDIATE_KIOV:
		if (tx->tx_phys != NULL) {
			vunmap(tx->tx_phys);
		} else if (tx->tx_phys == NULL && tx->tx_buffer != NULL) {
			kunmap(tx->tx_imm_pages[0]);
		}
		/* clear to prevent kgnilnd_free_tx from thinking
		 * this is a RDMA descriptor */
		tx->tx_phys = NULL;
		break;

	case GNILND_BUF_PHYS_MAPPED:
	case GNILND_BUF_VIRT_MAPPED:
		LASSERT(tx->tx_conn != NULL);

		dev = tx->tx_conn->gnc_device;

		/* only want to hold if we are closing conn without
		 * verified peer notification  - the theory is that
		 * a TX error can be communicated in all other cases */
		if (tx->tx_conn->gnc_state != GNILND_CONN_ESTABLISHED &&
		    error != -GNILND_NOPURG &&
		    kgnilnd_check_purgatory_conn(tx->tx_conn)) {
			kgnilnd_add_purgatory_tx(tx);

			/* The timeout we give to kgni is a deadman stop only.
			 *  we are setting high to ensure we don't have the kgni timer
			 *  fire before ours fires _and_ is handled */
			hold_timeout = GNILND_TIMEOUT2DEADMAN;

			GNIDBG_TX(D_NET, tx,
				 "dev %p delaying MDD release for %dms key "LPX64"."LPX64"",
				 tx->tx_conn->gnc_device, hold_timeout,
				 tx->tx_map_key.qword1, tx->tx_map_key.qword2);
		}
		if (tx->tx_buffer_copy != NULL) {
			rrc = kgnilnd_mem_deregister(dev->gnd_handle, &tx->tx_buffer_copy_map_key, hold_timeout);
			LASSERTF(rrc == GNI_RC_SUCCESS, "rrc %d\n", rrc);
			rrc = kgnilnd_mem_deregister(dev->gnd_handle, &tx->tx_map_key, 0);
			LASSERTF(rrc == GNI_RC_SUCCESS, "rrc %d\n", rrc);
		} else {
			rrc = kgnilnd_mem_deregister(dev->gnd_handle, &tx->tx_map_key, hold_timeout);
			LASSERTF(rrc == GNI_RC_SUCCESS, "rrc %d\n", rrc);
		}

		tx->tx_buftype--;
		kgnilnd_mem_del_map_list(dev, tx);
		break;
	}
}

void
kgnilnd_tx_done(kgn_tx_t *tx, int completion)
{
	lnet_msg_t      *lntmsg0, *lntmsg1;
	int             status0, status1;
	lnet_ni_t       *ni = NULL;
	kgn_conn_t      *conn = tx->tx_conn;

	LASSERT(!in_interrupt());

	lntmsg0 = tx->tx_lntmsg[0]; tx->tx_lntmsg[0] = NULL;
	lntmsg1 = tx->tx_lntmsg[1]; tx->tx_lntmsg[1] = NULL;

	if (completion &&
	    !(tx->tx_state & GNILND_TX_QUIET_ERROR) &&
	    !kgnilnd_conn_clean_errno(completion)) {
		GNIDBG_TOMSG(D_NETERROR, &tx->tx_msg,
		       "error %d on tx 0x%p->%s id %u/%d state %s age %ds",
		       completion, tx, conn ?
		       libcfs_nid2str(conn->gnc_peer->gnp_nid) : "<?>",
		       tx->tx_id.txe_smsg_id, tx->tx_id.txe_idx,
		       kgnilnd_tx_state2str(tx->tx_list_state),
		       cfs_duration_sec((unsigned long)jiffies - tx->tx_qtime));
	}

	/* The error codes determine if we hold onto the MDD */
	kgnilnd_unmap_buffer(tx, completion);

	/* we have to deliver a reply on lntmsg[1] for the GET, so make sure
	 * we play nice with the error codes to avoid delivering a failed
	 * REQUEST and then a REPLY event as well */

	/* return -EIO to lnet - it is the magic value for failed sends */
	if (tx->tx_msg.gnm_type == GNILND_MSG_GET_REQ) {
		status0 = 0;
		status1 = completion;
	} else {
		status0 = status1 = completion;
	}

	tx->tx_buftype = GNILND_BUF_NONE;
	tx->tx_msg.gnm_type = GNILND_MSG_NONE;

	/* lnet_finalize doesn't do anything with the *ni, so ok for us to
	 * set NULL when we are a tx without a conn */
	if (conn != NULL) {
		ni = conn->gnc_peer->gnp_net->gnn_ni;

		spin_lock(&conn->gnc_tx_lock);

		LASSERTF(test_and_clear_bit(tx->tx_id.txe_idx,
			(volatile unsigned long *)&conn->gnc_tx_bits),
			"conn %p tx %p bit %d already cleared\n",
			conn, tx, tx->tx_id.txe_idx);

		LASSERTF(conn->gnc_tx_ref_table[tx->tx_id.txe_idx] != NULL,
			 "msg_id %d already NULL\n", tx->tx_id.txe_idx);

		conn->gnc_tx_ref_table[tx->tx_id.txe_idx] = NULL;
		spin_unlock(&conn->gnc_tx_lock);
	}

	kgnilnd_free_tx(tx);

	/* finalize AFTER freeing lnet msgs */

	/* warning - we should hold no locks here - calling lnet_finalize
	 * could free up lnet credits, resulting in a call chain back into
	 * the LND via kgnilnd_send and friends */

	lnet_finalize(ni, lntmsg0, status0);

	if (lntmsg1 != NULL) {
		lnet_finalize(ni, lntmsg1, status1);
	}
}

void
kgnilnd_txlist_done(struct list_head *txlist, int error)
{
	kgn_tx_t        *tx, *txn;
	int              err_printed = 0;

	if (list_empty(txlist))
		return;

	list_for_each_entry_safe(tx, txn, txlist, tx_list) {
		/* only print the first error */
		if (err_printed)
			tx->tx_state |= GNILND_TX_QUIET_ERROR;
		list_del_init(&tx->tx_list);
		kgnilnd_tx_done(tx, error);
		err_printed++;
	}
}
int
kgnilnd_set_tx_id(kgn_tx_t *tx, kgn_conn_t *conn)
{
	int     id;

	spin_lock(&conn->gnc_tx_lock);

	/* ID zero is NOT ALLOWED!!! */

search_again:
	id = find_next_zero_bit((unsigned long *)&conn->gnc_tx_bits,
				 GNILND_MAX_MSG_ID, conn->gnc_next_tx);
	if (id == GNILND_MAX_MSG_ID) {
		if (conn->gnc_next_tx != 1) {
			/* we only searched from next_tx to end and didn't find
			 * one, so search again from start */
			conn->gnc_next_tx = 1;
			goto search_again;
		}
		/* couldn't find one! */
		spin_unlock(&conn->gnc_tx_lock);
		return -E2BIG;
	}

	/* bump next_tx to prevent immediate reuse */
	conn->gnc_next_tx = id + 1;

	set_bit(id, (volatile unsigned long *)&conn->gnc_tx_bits);
	LASSERTF(conn->gnc_tx_ref_table[id] == NULL,
		 "tx 0x%p already at id %d\n",
		 conn->gnc_tx_ref_table[id], id);

	/* delay these until we have a valid ID - prevents bad clear of the bit
	 * in kgnilnd_tx_done */
	tx->tx_conn = conn;
	tx->tx_id.txe_cqid = conn->gnc_cqid;

	tx->tx_id.txe_idx = id;
	conn->gnc_tx_ref_table[id] = tx;

	/* Using jiffies to help differentiate against TX reuse - with
	 * the usual minimum of a 250HZ clock, we wrap jiffies on the same TX
	 * if we are sending to the same node faster than 256000/sec.
	 * To help guard against this, we OR in the tx_seq - that is 32 bits */

	tx->tx_id.txe_chips = (__u32)(jiffies | atomic_read(&conn->gnc_tx_seq));

	GNIDBG_TX(D_NET, tx, "set cookie/id/bits", NULL);

	spin_unlock(&conn->gnc_tx_lock);
	return 0;
}

static inline int
kgnilnd_tx_should_retry(kgn_conn_t *conn, kgn_tx_t *tx)
{
	int             max_retrans = *kgnilnd_tunables.kgn_max_retransmits;
	int             log_retrans;
	int             log_retrans_level;

	/* I need kgni credits to send this.  Replace tx at the head of the
	 * fmaq and I'll get rescheduled when credits appear */
	tx->tx_state = 0;
	tx->tx_retrans++;
	conn->gnc_tx_retrans++;
	log_retrans = ((tx->tx_retrans < 25) || ((tx->tx_retrans % 25) == 0) ||
			(tx->tx_retrans > (max_retrans / 2)));
	log_retrans_level = tx->tx_retrans < (max_retrans / 2) ? D_NET : D_NETERROR;

	/* Decision time - either error, warn or just retransmit */

	/* we don't care about TX timeout - it could be that the network is slower
	 * or throttled. We'll keep retranmitting - so if the network is so slow
	 * that we fill up our mailbox, we'll keep trying to resend that msg
	 * until we exceed the max_retrans _or_ gnc_last_rx expires, indicating
	 * that he hasn't send us any traffic in return */

	if (tx->tx_retrans > max_retrans) {
		/* this means we are not backing off the retransmits
		 * in a healthy manner and are likely chewing up the
		 * CPU cycles quite badly */
		GNIDBG_TOMSG(D_ERROR, &tx->tx_msg,
			"SOFTWARE BUG: too many retransmits (%d) for tx id %x "
			"conn 0x%p->%s\n",
			tx->tx_retrans, tx->tx_id, conn,
			libcfs_nid2str(conn->gnc_peer->gnp_nid));

		/* yes - double errors to help debug this condition */
		GNIDBG_TOMSG(D_NETERROR, &tx->tx_msg, "connection dead. "
			"unable to send to %s for %lu secs (%d tries)",
			libcfs_nid2str(tx->tx_conn->gnc_peer->gnp_nid),
			cfs_duration_sec(jiffies - tx->tx_cred_wait),
			tx->tx_retrans);

		kgnilnd_close_conn(conn, -ETIMEDOUT);

		/* caller should terminate */
		RETURN(0);
	} else {
		/* some reasonable throttling of the debug message */
		if (log_retrans) {
			unsigned long now = jiffies;
			/* XXX Nic: Mystical TX debug here... */
			GNIDBG_SMSG_CREDS(log_retrans_level, conn);
			GNIDBG_TOMSG(log_retrans_level, &tx->tx_msg,
				"NOT_DONE on conn 0x%p->%s id %x retrans %d wait %dus"
				" last_msg %uus/%uus last_cq %uus/%uus",
				conn, libcfs_nid2str(conn->gnc_peer->gnp_nid),
				tx->tx_id, tx->tx_retrans,
				jiffies_to_usecs(now - tx->tx_cred_wait),
				jiffies_to_usecs(now - conn->gnc_last_tx),
				jiffies_to_usecs(now - conn->gnc_last_rx),
				jiffies_to_usecs(now - conn->gnc_last_tx_cq),
				jiffies_to_usecs(now - conn->gnc_last_rx_cq));
		}
		/* caller should retry */
		RETURN(1);
	}
}

/* caller must be holding gnd_cq_mutex and not unlock it afterwards, as we need to drop it
 * to avoid bad ordering with state_lock */

static inline int
kgnilnd_sendmsg_nolock(kgn_tx_t *tx, void *immediate, unsigned int immediatenob,
		spinlock_t *state_lock, kgn_tx_list_state_t state)
{
	kgn_conn_t      *conn = tx->tx_conn;
	kgn_msg_t       *msg = &tx->tx_msg;
	int              retry_send;
	gni_return_t     rrc;
	unsigned long    newest_last_rx, timeout;
	unsigned long    now;

	LASSERTF((msg->gnm_type == GNILND_MSG_IMMEDIATE) ?
		immediatenob <= *kgnilnd_tunables.kgn_max_immediate :
		immediatenob == 0,
		"msg 0x%p type %d wrong payload size %d\n",
		msg, msg->gnm_type, immediatenob);

	/* make sure we catch all the cases where we'd send on a dirty old mbox
	 * but allow case for sending CLOSE. Since this check is within the CQ
	 * mutex barrier and the close message is only sent through
	 * kgnilnd_send_conn_close the last message out the door will be the
	 * close message.
	 */
	if (atomic_read(&conn->gnc_peer->gnp_dirty_eps) != 0 && msg->gnm_type != GNILND_MSG_CLOSE) {
		kgnilnd_conn_mutex_unlock(&conn->gnc_smsg_mutex);
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		/* Return -ETIME, we are closing the connection already so we dont want to
		 * have this tx hit the wire. The tx will be killed by the calling function.
		 * Once the EP is marked dirty the close message will be the last
		 * thing to hit the wire */
		return -ETIME;
	}

	now = jiffies;
	timeout = cfs_time_seconds(conn->gnc_timeout);

	newest_last_rx = GNILND_LASTRX(conn);

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_SEND_TIMEOUT)) {
		now = now + (GNILND_TIMEOUTRX(timeout) * 2);
	}

	if (time_after_eq(now, newest_last_rx + GNILND_TIMEOUTRX(timeout))) {
		GNIDBG_CONN(D_NETERROR|D_CONSOLE, conn,
			    "Cant send to %s after timeout lapse of %lu; TO %lu\n",
		libcfs_nid2str(conn->gnc_peer->gnp_nid),
		cfs_duration_sec(now - newest_last_rx),
		cfs_duration_sec(GNILND_TIMEOUTRX(timeout)));
		kgnilnd_conn_mutex_unlock(&conn->gnc_smsg_mutex);
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		return -ETIME;
	}

	GNITX_ASSERTF(tx, (conn != NULL) && (tx->tx_id.txe_idx != 0), "tx id unset!", NULL);
	/* msg->gnm_srcnid is set when the message is initialized by whatever function is
	 * creating the message this allows the message to contain the correct LNET NID/NET needed
	 * instead of the one that the peer/conn uses for sending the data.
	 */
	msg->gnm_connstamp = conn->gnc_my_connstamp;
	msg->gnm_payload_len = immediatenob;
	msg->gnm_seq = atomic_read(&conn->gnc_tx_seq);

	/* always init here - kgn_checksum is a /sys module tunable
	 * and can be flipped at any point, even between msg init and sending */
	msg->gnm_cksum = 0;
	if (*kgnilnd_tunables.kgn_checksum) {
		/* We must set here and not in kgnilnd_init_msg,
		 * we could resend this msg many times
		 * (NOT_DONE from gni_smsg_send below) and wouldn't pass
		 * through init_msg again */
		msg->gnm_cksum = kgnilnd_cksum(msg, sizeof(kgn_msg_t));
		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_SMSG_CKSUM1)) {
			msg->gnm_cksum += 0xf00f;
		}
	}

	GNIDBG_TOMSG(D_NET, msg, "tx 0x%p conn 0x%p->%s sending SMSG sz %u id %x/%d [%p for %u]",
	       tx, conn, libcfs_nid2str(conn->gnc_peer->gnp_nid),
	       sizeof(kgn_msg_t), tx->tx_id.txe_smsg_id,
	       tx->tx_id.txe_idx, immediate, immediatenob);

	if (unlikely(tx->tx_state & GNILND_TX_FAIL_SMSG)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_NOT_DONE;
	} else {
		rrc = kgnilnd_smsg_send(conn->gnc_ephandle,
					msg, sizeof(*msg), immediate,
					immediatenob,
					tx->tx_id.txe_smsg_id);
	}

	switch (rrc) {
	case GNI_RC_SUCCESS:
		atomic_inc(&conn->gnc_tx_seq);
		conn->gnc_last_tx = jiffies;
		/* no locking here as LIVE isn't a list */
		kgnilnd_tx_add_state_locked(tx, NULL, conn, GNILND_TX_LIVE_FMAQ, 1);

		/* this needs to be checked under lock as it might be freed from a completion
		 * event.
		 */
		if (msg->gnm_type == GNILND_MSG_NOOP) {
			set_mb(conn->gnc_last_noop_sent, jiffies);
		}

		/* serialize with seeing CQ events for completion on this, as well as
		 * tx_seq */
		kgnilnd_conn_mutex_unlock(&conn->gnc_smsg_mutex);
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);

		atomic_inc(&conn->gnc_device->gnd_short_ntx);
		atomic64_add(immediatenob, &conn->gnc_device->gnd_short_txbytes);
		kgnilnd_peer_alive(conn->gnc_peer);
		GNIDBG_SMSG_CREDS(D_NET, conn);
		return 0;

	case GNI_RC_NOT_DONE:
		/* XXX Nic: We need to figure out how to track this
		 * - there are bound to be good reasons for it,
		 * but we want to know when it happens */
		kgnilnd_conn_mutex_unlock(&conn->gnc_smsg_mutex);
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		/* We'll handle this error inline - makes the calling logic much more
		 * clean */

		/* If no lock, caller doesn't want us to retry */
		if (state_lock == NULL) {
			return -EAGAIN;
		}

		retry_send = kgnilnd_tx_should_retry(conn, tx);
		if (retry_send) {
			/* add to head of list for the state and retries */
			spin_lock(state_lock);
			kgnilnd_tx_add_state_locked(tx, conn->gnc_peer, conn, state, 0);
			spin_unlock(state_lock);

			/* We only reschedule for a certain number of retries, then
			 * we will wait for the CQ events indicating a release of SMSG
			 * credits */
			if (tx->tx_retrans < (*kgnilnd_tunables.kgn_max_retransmits/4)) {
				kgnilnd_schedule_conn(conn);
				return 0;
			} else {
				/* CQ event coming in signifies either TX completed or
				 * RX receive. Either of these *could* free up credits
				 * in the SMSG mbox and we should try sending again */
				GNIDBG_TX(D_NET, tx, "waiting for CQID %u event to resend",
					 tx->tx_conn->gnc_cqid);
				/* use +ve return code to let upper layers know they
				 * should stop looping on sends */
				return EAGAIN;
			}
		} else {
			return -EAGAIN;
		}
	default:
		/* handle bad retcode gracefully */
		kgnilnd_conn_mutex_unlock(&conn->gnc_smsg_mutex);
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		return -EIO;
	}
}

/* kgnilnd_sendmsg has hard wait on gnd_cq_mutex */
static inline int
kgnilnd_sendmsg(kgn_tx_t *tx, void *immediate, unsigned int immediatenob,
		spinlock_t *state_lock, kgn_tx_list_state_t state)
{
	kgn_device_t    *dev = tx->tx_conn->gnc_device;
	unsigned long    timestamp;
	int              rc;

	timestamp = jiffies;
	kgnilnd_gl_mutex_lock(&dev->gnd_cq_mutex);
	kgnilnd_conn_mutex_lock(&tx->tx_conn->gnc_smsg_mutex);
	/* delay in jiffies - we are really concerned only with things that
	 * result in a schedule() or really holding this off for long times .
	 * NB - mutex_lock could spin for 2 jiffies before going to sleep to wait */
	dev->gnd_mutex_delay += (long) jiffies - timestamp;

	rc = kgnilnd_sendmsg_nolock(tx, immediate, immediatenob, state_lock, state);

	RETURN(rc);
}


/* returns -EAGAIN for lock miss, anything else < 0 is hard error, >=0 for success */
static inline int
kgnilnd_sendmsg_trylock(kgn_tx_t *tx, void *immediate, unsigned int immediatenob,
		spinlock_t *state_lock, kgn_tx_list_state_t state)
{
	kgn_conn_t      *conn = tx->tx_conn;
	kgn_device_t    *dev = conn->gnc_device;
	unsigned long    timestamp;
	int              rc;

	timestamp = jiffies;

	/* technically we are doing bad things with the read_lock on the peer_conn
	 * table, but we shouldn't be sleeping inside here - and we don't sleep/block
	 * for the mutex. I bet lockdep is gonna flag this one though... */

	/* there are a few cases where we don't want the immediate send - like
	 * when we are in the scheduler thread and it'd harm the latency of
	 * getting messages up to LNet */

	/* rmb for gnd_ready */
	smp_rmb();
	if (conn->gnc_device->gnd_ready == GNILND_DEV_LOOP) {
		rc = 0;
		atomic_inc(&conn->gnc_device->gnd_fast_block);
	} else if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
	       /* dont hit HW during quiesce */
		rc = 0;
	} else if (unlikely(atomic_read(&conn->gnc_peer->gnp_dirty_eps))) {
	       /* dont hit HW if stale EPs and conns left to close */
		rc = 0;
	} else {
		atomic_inc(&conn->gnc_device->gnd_fast_try);
		rc = kgnilnd_trylock(&conn->gnc_device->gnd_cq_mutex,
				     &conn->gnc_smsg_mutex);
	}
	if (!rc) {
		rc = -EAGAIN;
	} else {
		/* we got the mutex and weren't blocked */

		/* delay in jiffies - we are really concerned only with things that
		 * result in a schedule() or really holding this off for long times .
		 * NB - mutex_lock could spin for 2 jiffies before going to sleep to wait */
		dev->gnd_mutex_delay += (long) jiffies - timestamp;

		atomic_inc(&conn->gnc_device->gnd_fast_ok);
		tx->tx_qtime = jiffies;
		tx->tx_state = GNILND_TX_WAITING_COMPLETION;
		rc = kgnilnd_sendmsg_nolock(tx, tx->tx_buffer, tx->tx_nob, &conn->gnc_list_lock, GNILND_TX_FMAQ);
		/* _nolock unlocks the mutex for us */
	}

	RETURN(rc);
}

/* lets us know if we can push this RDMA through now */
inline int
kgnilnd_auth_rdma_bytes(kgn_device_t *dev, kgn_tx_t *tx)
{
	long    bytes_left;

	bytes_left = atomic64_sub_return(tx->tx_nob, &dev->gnd_rdmaq_bytes_ok);

	if (bytes_left < 0) {
		atomic64_add(tx->tx_nob, &dev->gnd_rdmaq_bytes_ok);
		atomic_inc(&dev->gnd_rdmaq_nstalls);
		smp_wmb();

		CDEBUG(D_NET, "no bytes to send, turning on timer for %lu\n",
		       dev->gnd_rdmaq_deadline);
		mod_timer(&dev->gnd_rdmaq_timer, dev->gnd_rdmaq_deadline);
		/* we never del this timer - at worst it schedules us.. */
		return -EAGAIN;
	} else {
		return 0;
	}
}

/* this adds a TX to the queue pending throttling authorization before
 * we allow our remote peer to launch a PUT at us */
void
kgnilnd_queue_rdma(kgn_conn_t *conn, kgn_tx_t *tx)
{
	int     rc;

	/* we cannot go into send_mapped_tx from here as we are holding locks
	 * and mem registration might end up allocating memory in kgni.
	 * That said, we'll push this as far as we can into the queue process */
	rc = kgnilnd_auth_rdma_bytes(conn->gnc_device, tx);

	if (rc < 0) {
		spin_lock(&conn->gnc_device->gnd_rdmaq_lock);
		kgnilnd_tx_add_state_locked(tx, NULL, conn, GNILND_TX_RDMAQ, 0);
		/* lets us know how delayed RDMA is */
		tx->tx_qtime = jiffies;
		spin_unlock(&conn->gnc_device->gnd_rdmaq_lock);
	} else {
		/* we have RDMA authorized, now it just needs a MDD and to hit the wire */
		spin_lock(&tx->tx_conn->gnc_device->gnd_lock);
		kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_MAPQ, 0);
		/* lets us know how delayed mapping is */
		tx->tx_qtime = jiffies;
		spin_unlock(&tx->tx_conn->gnc_device->gnd_lock);
	}

	/* make sure we wake up sched to run this */
	kgnilnd_schedule_device(tx->tx_conn->gnc_device);
}

/* push TX through state machine */
void
kgnilnd_queue_tx(kgn_conn_t *conn, kgn_tx_t *tx)
{
	int            rc = 0;
	int            add_tail = 1;

	/* set the tx_id here, we delay it until we have an actual conn
	 * to fiddle with
	 * in some cases, the tx_id is already set to provide for things
	 * like RDMA completion cookies, etc */
	if (tx->tx_id.txe_idx == 0) {
		rc = kgnilnd_set_tx_id(tx, conn);
		if (rc != 0) {
			kgnilnd_tx_done(tx, rc);
			return;
		}
	}

	CDEBUG(D_NET, "%s to conn %p for %s\n", kgnilnd_msgtype2str(tx->tx_msg.gnm_type),
		conn, libcfs_nid2str(conn->gnc_peer->gnp_nid));

	/* Only let NOOPs to be sent while fail loc is set, otherwise kill the tx.
	 */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_ONLY_NOOP) && (tx->tx_msg.gnm_type != GNILND_MSG_NOOP)) {
		kgnilnd_tx_done(tx, rc);
		return;
	}

	switch (tx->tx_msg.gnm_type) {
	case GNILND_MSG_PUT_ACK:
	case GNILND_MSG_GET_REQ:
	case GNILND_MSG_PUT_REQ_REV:
	case GNILND_MSG_GET_ACK_REV:
		/* hijacking time! If this messages will authorize our peer to
		 * send his dirty little bytes in an RDMA, we need to get permission */
		kgnilnd_queue_rdma(conn, tx);
		break;
	case GNILND_MSG_IMMEDIATE:
		/* try to send right now, can help reduce latency */
		rc = kgnilnd_sendmsg_trylock(tx, tx->tx_buffer, tx->tx_nob, &conn->gnc_list_lock, GNILND_TX_FMAQ);

		if (rc >= 0) {
			/* it was sent, break out of switch to avoid default case of queueing */
			break;
		}
		/* needs to queue to try again, so fall through to default case */
	case GNILND_MSG_NOOP:
		/* Just make sure this goes out first for this conn */
		add_tail = 0;
		/* fall through... */
	default:
		spin_lock(&conn->gnc_list_lock);
		kgnilnd_tx_add_state_locked(tx, conn->gnc_peer, conn, GNILND_TX_FMAQ, add_tail);
		tx->tx_qtime = jiffies;
		spin_unlock(&conn->gnc_list_lock);
		kgnilnd_schedule_conn(conn);
	}
}

void
kgnilnd_launch_tx(kgn_tx_t *tx, kgn_net_t *net, lnet_process_id_t *target)
{
	kgn_peer_t      *peer;
	kgn_peer_t      *new_peer = NULL;
	kgn_conn_t      *conn = NULL;
	int              rc;
	int              node_state;

	ENTRY;

	/* If I get here, I've committed to send, so I complete the tx with
	 * failure on any problems */

	GNITX_ASSERTF(tx, tx->tx_conn == NULL,
		      "tx already has connection %p", tx->tx_conn);

	/* do all of the peer & conn searching in one swoop - this avoids
	 * nastiness when dropping locks and needing to maintain a sane state
	 * in the face of stack reset or something else nuking peers & conns */

	/* I expect to find him, so only take a read lock */
	read_lock(&kgnilnd_data.kgn_peer_conn_lock);

	peer = kgnilnd_find_peer_locked(target->nid);
	if (peer != NULL) {
		conn = kgnilnd_find_conn_locked(peer);
		/* this could be NULL during quiesce */
		if (conn != NULL)  {
			/* Connection exists; queue message on it */
			kgnilnd_queue_tx(conn, tx);
			read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			RETURN_EXIT;
		}

		/* don't create a connection if the peer is marked down */
		if (peer->gnp_down == GNILND_RCA_NODE_DOWN) {
			read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			rc = -ENETRESET;
			GOTO(no_peer, rc);
		}
	}

	/* creating peer or conn; I'll need a write lock... */
	read_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	CFS_RACE(CFS_FAIL_GNI_FIND_TARGET);

	node_state = kgnilnd_get_node_state(LNET_NIDADDR(target->nid));

	/* NB - this will not block during normal operations -
	 * the only writer of this is in the startup/shutdown path. */
	rc = down_read_trylock(&kgnilnd_data.kgn_net_rw_sem);
	if (!rc) {
		rc = -ESHUTDOWN;
		GOTO(no_peer, rc);
	}

	/* ignore previous peer entirely - we cycled the lock, so we
	 * will create new peer and at worst drop it if peer is still
	 * in the tables */
	rc = kgnilnd_create_peer_safe(&new_peer, target->nid, net, node_state);
	if (rc != 0) {
		up_read(&kgnilnd_data.kgn_net_rw_sem);
		GOTO(no_peer, rc);
	}

	write_lock(&kgnilnd_data.kgn_peer_conn_lock);
	up_read(&kgnilnd_data.kgn_net_rw_sem);

	/* search for peer again now that we have the lock
	 * if we don't find it, add our new one to the list */
	kgnilnd_add_peer_locked(target->nid, new_peer, &peer);

	/* don't create a connection if the peer is not up */
	if (peer->gnp_down != GNILND_RCA_NODE_UP) {
		write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		rc = -ENETRESET;
		GOTO(no_peer, rc);
	}

	conn = kgnilnd_find_or_create_conn_locked(peer);

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_DGRAM_DROP_TX)) {
		write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		GOTO(no_peer, rc);
	}

	if (conn != NULL) {
		/* oh hey, found a conn now... magical */
		kgnilnd_queue_tx(conn, tx);
	} else {
		/* no conn, must be trying to connect - so we queue for now */
		tx->tx_qtime = jiffies;
		kgnilnd_tx_add_state_locked(tx, peer, NULL, GNILND_TX_PEERQ, 1);
	}
	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
	RETURN_EXIT;
no_peer:
	kgnilnd_tx_done(tx, rc);
	RETURN_EXIT;
}

int
kgnilnd_rdma(kgn_tx_t *tx, int type,
	    kgn_rdma_desc_t *sink, unsigned int nob, __u64 cookie)
{
	kgn_conn_t   *conn = tx->tx_conn;
	unsigned long timestamp;
	gni_post_type_t post_type;
	gni_return_t  rrc;
	int rc = 0;
	unsigned int desc_nob = nob;
	void *desc_buffer = tx->tx_buffer;
	gni_mem_handle_t desc_map_key = tx->tx_map_key;
	LASSERTF(kgnilnd_tx_mapped(tx),
		"unmapped tx %p\n", tx);
	LASSERTF(conn != NULL,
		"NULL conn on tx %p, naughty, naughty\n", tx);
	LASSERTF(nob <= sink->gnrd_nob,
		"nob %u > sink->gnrd_nob %d (%p)\n",
		nob, sink->gnrd_nob, sink);
	LASSERTF(nob <= tx->tx_nob,
		"nob %d > tx(%p)->tx_nob %d\n",
		nob, tx, tx->tx_nob);

	switch (type) {
	case GNILND_MSG_GET_DONE:
	case GNILND_MSG_PUT_DONE:
		post_type = GNI_POST_RDMA_PUT;
		break;
	case GNILND_MSG_GET_DONE_REV:
	case GNILND_MSG_PUT_DONE_REV:
		post_type = GNI_POST_RDMA_GET;
		break;
	default:
		CERROR("invalid msg type %s (%d)\n",
			kgnilnd_msgtype2str(type), type);
		LBUG();
	}
	if (post_type == GNI_POST_RDMA_GET) {
		/* Check for remote buffer / local buffer / length alignment. All must be 4 byte
		 * aligned. If the local buffer is not aligned correctly using the copy buffer
		 * will fix that issue. If length is misaligned copy buffer will also fix the issue, we end
		 * up transferring extra bytes into the buffer but only copy the correct nob into the original
		 * buffer.  Remote offset correction is done through a combination of adjusting the offset,
		 * making sure the length and addr are aligned and copying the data into the correct location
		 * once the transfer has completed.
		 */
		if ((((__u64)((unsigned long)tx->tx_buffer)) & 3) ||
		      (sink->gnrd_addr & 3) ||
		      (nob & 3)) {

			tx->tx_offset = ((__u64)((unsigned long)sink->gnrd_addr)) & 3;
			if (tx->tx_offset)
				kgnilnd_admin_addref(kgnilnd_data.kgn_rev_offset);

			if ((nob + tx->tx_offset) & 3) {
				desc_nob = ((nob + tx->tx_offset) + (4 - ((nob + tx->tx_offset) & 3)));
				kgnilnd_admin_addref(kgnilnd_data.kgn_rev_length);
			} else {
				desc_nob = (nob + tx->tx_offset);
			}

			if (tx->tx_buffer_copy == NULL) {
				/* Allocate the largest copy buffer we will need, this will prevent us from overwriting data
				 * and require at most we allocate a few extra bytes. */
				tx->tx_buffer_copy = vmalloc(desc_nob);

				if (!tx->tx_buffer_copy) {
					/* allocation of buffer failed nak the rdma */
					kgnilnd_nak_rdma(tx->tx_conn, tx->tx_msg.gnm_type, -EFAULT, cookie, tx->tx_msg.gnm_srcnid);
					kgnilnd_tx_done(tx, -EFAULT);
					return 0;
				}
				kgnilnd_admin_addref(kgnilnd_data.kgn_rev_copy_buff);
				rc = kgnilnd_mem_register(conn->gnc_device->gnd_handle, (__u64)tx->tx_buffer_copy, desc_nob, NULL, GNI_MEM_READWRITE, &tx->tx_buffer_copy_map_key);
				if (rc != GNI_RC_SUCCESS) {
					/* Registration Failed nak rdma and kill the tx. */
					vfree(tx->tx_buffer_copy);
					tx->tx_buffer_copy = NULL;
					kgnilnd_nak_rdma(tx->tx_conn, tx->tx_msg.gnm_type, -EFAULT, cookie, tx->tx_msg.gnm_srcnid);
					kgnilnd_tx_done(tx, -EFAULT);
					return 0;
				}
			}
			desc_map_key = tx->tx_buffer_copy_map_key;
			desc_buffer = tx->tx_buffer_copy;
		}
	}

	memset(&tx->tx_rdma_desc, 0, sizeof(tx->tx_rdma_desc));
	tx->tx_rdma_desc.post_id = tx->tx_id.txe_cookie;
	tx->tx_rdma_desc.type = post_type;
	tx->tx_rdma_desc.cq_mode = GNI_CQMODE_GLOBAL_EVENT;
	tx->tx_rdma_desc.local_addr = (__u64)((unsigned long)desc_buffer);
	tx->tx_rdma_desc.local_mem_hndl = desc_map_key;
	tx->tx_rdma_desc.remote_addr = sink->gnrd_addr - tx->tx_offset;
	tx->tx_rdma_desc.remote_mem_hndl = sink->gnrd_key;
	tx->tx_rdma_desc.length = desc_nob;
	tx->tx_nob_rdma = nob;
	if (*kgnilnd_tunables.kgn_bte_dlvr_mode)
		tx->tx_rdma_desc.dlvr_mode = *kgnilnd_tunables.kgn_bte_dlvr_mode;
	/* prep final completion message */
	kgnilnd_init_msg(&tx->tx_msg, type, tx->tx_msg.gnm_srcnid);
	tx->tx_msg.gnm_u.completion.gncm_cookie = cookie;
	/* send actual size RDMA'd in retval */
	tx->tx_msg.gnm_u.completion.gncm_retval = nob;

	kgnilnd_compute_rdma_cksum(tx, nob);

	if (nob == 0) {
		kgnilnd_queue_tx(conn, tx);
		return 0;
	}

	/* Don't lie (CLOSE == RDMA idle) */
	LASSERTF(!conn->gnc_close_sent, "tx %p on conn %p after close sent %d\n",
		 tx, conn, conn->gnc_close_sent);

	GNIDBG_TX(D_NET, tx, "Post RDMA type 0x%02x conn %p dlvr_mode "
		"0x%x cookie:"LPX64,
		type, conn, tx->tx_rdma_desc.dlvr_mode, cookie);

	/* set CQ dedicated for RDMA */
	tx->tx_rdma_desc.src_cq_hndl = conn->gnc_device->gnd_snd_rdma_cqh;

	timestamp = jiffies;
	kgnilnd_conn_mutex_lock(&conn->gnc_rdma_mutex);
	kgnilnd_gl_mutex_lock(&conn->gnc_device->gnd_cq_mutex);
	/* delay in jiffies - we are really concerned only with things that
	 * result in a schedule() or really holding this off for long times .
	 * NB - mutex_lock could spin for 2 jiffies before going to sleep to wait */
	conn->gnc_device->gnd_mutex_delay += (long) jiffies - timestamp;

	rrc = kgnilnd_post_rdma(conn->gnc_ephandle, &tx->tx_rdma_desc);

	if (rrc == GNI_RC_ERROR_RESOURCE) {
		kgnilnd_conn_mutex_unlock(&conn->gnc_rdma_mutex);
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		kgnilnd_unmap_buffer(tx, 0);

		if (tx->tx_buffer_copy != NULL) {
			vfree(tx->tx_buffer_copy);
			tx->tx_buffer_copy = NULL;
		}

		spin_lock(&tx->tx_conn->gnc_device->gnd_lock);
		kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn,
					    GNILND_TX_MAPQ, 0);
		spin_unlock(&tx->tx_conn->gnc_device->gnd_lock);
		kgnilnd_schedule_device(tx->tx_conn->gnc_device);
		return -EAGAIN;
	}

	spin_lock(&conn->gnc_list_lock);
	kgnilnd_tx_add_state_locked(tx, conn->gnc_peer, conn, GNILND_TX_LIVE_RDMAQ, 1);
	tx->tx_qtime = jiffies;
	spin_unlock(&conn->gnc_list_lock);
	kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
	kgnilnd_conn_mutex_unlock(&conn->gnc_rdma_mutex);

	/* XXX Nic: is this a place we should handle more errors for
	 * robustness sake */
	LASSERT(rrc == GNI_RC_SUCCESS);
	return 0;
}

kgn_rx_t *
kgnilnd_alloc_rx(void)
{
	kgn_rx_t	*rx;

	rx = kmem_cache_alloc(kgnilnd_data.kgn_rx_cache, GFP_ATOMIC);
	if (rx == NULL) {
		CERROR("failed to allocate rx\n");
		return NULL;
	}
	CDEBUG(D_MALLOC, "slab-alloced 'rx': %lu at %p.\n",
	       sizeof(*rx), rx);

	/* no memset to zero, we'll always fill all members */
	return rx;
}

/* release is to just free connection resources
 * we use this for the eager path after copying */
void
kgnilnd_release_msg(kgn_conn_t *conn)
{
	gni_return_t    rrc;
	unsigned long   timestamp;

	CDEBUG(D_NET, "consuming %p\n", conn);

	timestamp = jiffies;
	kgnilnd_gl_mutex_lock(&conn->gnc_device->gnd_cq_mutex);
	/* delay in jiffies - we are really concerned only with things that
	 * result in a schedule() or really holding this off for long times .
	 * NB - mutex_lock could spin for 2 jiffies before going to sleep to wait */
	conn->gnc_device->gnd_mutex_delay += (long) jiffies - timestamp;

	rrc = kgnilnd_smsg_release(conn->gnc_ephandle);
	kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);

	LASSERTF(rrc == GNI_RC_SUCCESS, "bad rrc %d\n", rrc);
	GNIDBG_SMSG_CREDS(D_NET, conn);

	return;
}

void
kgnilnd_consume_rx(kgn_rx_t *rx)
{
	kgn_conn_t      *conn = rx->grx_conn;
	kgn_msg_t       *rxmsg = rx->grx_msg;

	/* if we are eager, free the cache alloc'd msg */
	if (unlikely(rx->grx_eager)) {
		LIBCFS_FREE(rxmsg, sizeof(*rxmsg) + *kgnilnd_tunables.kgn_max_immediate);
		atomic_dec(&kgnilnd_data.kgn_neager_allocs);

		/* release ref from eager_recv */
		kgnilnd_conn_decref(conn);
	} else {
		GNIDBG_MSG(D_NET, rxmsg, "rx %p processed", rx);
		kgnilnd_release_msg(conn);
	}

	kmem_cache_free(kgnilnd_data.kgn_rx_cache, rx);
	CDEBUG(D_MALLOC, "slab-freed 'rx': %lu at %p.\n",
	       sizeof(*rx), rx);

	return;
}

int
kgnilnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
	lnet_hdr_t       *hdr = &lntmsg->msg_hdr;
	int               type = lntmsg->msg_type;
	lnet_process_id_t target = lntmsg->msg_target;
	int               target_is_router = lntmsg->msg_target_is_router;
	int               routing = lntmsg->msg_routing;
	unsigned int      niov = lntmsg->msg_niov;
	struct kvec      *iov = lntmsg->msg_iov;
	lnet_kiov_t      *kiov = lntmsg->msg_kiov;
	unsigned int      offset = lntmsg->msg_offset;
	unsigned int      nob = lntmsg->msg_len;
	unsigned int      msg_vmflush = lntmsg->msg_vmflush;
	kgn_net_t        *net = ni->ni_data;
	kgn_tx_t         *tx;
	int               rc = 0;
	int               mpflag = 0;
	int               reverse_rdma_flag = *kgnilnd_tunables.kgn_reverse_rdma;

	/* NB 'private' is different depending on what we're sending.... */
	LASSERT(!in_interrupt());

	CDEBUG(D_NET, "sending msg type %d with %d bytes in %d frags to %s\n",
	       type, nob, niov, libcfs_id2str(target));

	LASSERTF(nob == 0 || niov > 0,
		"lntmsg %p nob %d niov %d\n", lntmsg, nob, niov);
	LASSERTF(niov <= LNET_MAX_IOV,
		"lntmsg %p niov %d\n", lntmsg, niov);

	/* payload is either all vaddrs or all pages */
	LASSERTF(!(kiov != NULL && iov != NULL),
		"lntmsg %p kiov %p iov %p\n", lntmsg, kiov, iov);

	if (msg_vmflush)
		mpflag = cfs_memory_pressure_get_and_set();

	switch (type) {
	default:
		CERROR("lntmsg %p with unexpected type %d\n",
			lntmsg, type);
		LBUG();

	case LNET_MSG_ACK:
		LASSERTF(nob == 0, "lntmsg %p nob %d\n",
			lntmsg, nob);
		break;

	case LNET_MSG_GET:
		LASSERT(niov == 0);
		LASSERT(nob == 0);

		if (routing || target_is_router)
			break;                  /* send IMMEDIATE */

		/* it is safe to do direct GET with out mapping buffer for RDMA as we
		 * check the eventual sink buffer here - if small enough, remote
		 * end is perfectly capable of returning data in short message -
		 * The magic is that we call lnet_parse in kgnilnd_recv with rdma_req=0
		 * for IMMEDIATE messages which will have it send a real reply instead
		 * of doing kgnilnd_recv to have the RDMA continued */
		if (lntmsg->msg_md->md_length <= *kgnilnd_tunables.kgn_max_immediate)
		       break;

		if ((reverse_rdma_flag & GNILND_REVERSE_GET) == 0)
			tx = kgnilnd_new_tx_msg(GNILND_MSG_GET_REQ, ni->ni_nid);
		else
			tx = kgnilnd_new_tx_msg(GNILND_MSG_GET_REQ_REV, ni->ni_nid);

		if (tx == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		/* slightly different options as we might actually have a GET with a
		 * MD_KIOV set but a non-NULL md_iov.iov */
		if ((lntmsg->msg_md->md_options & LNET_MD_KIOV) == 0)
			rc = kgnilnd_setup_rdma_buffer(tx, lntmsg->msg_md->md_niov,
						      lntmsg->msg_md->md_iov.iov, NULL,
						      0, lntmsg->msg_md->md_length);
		else
			rc = kgnilnd_setup_rdma_buffer(tx, lntmsg->msg_md->md_niov,
						      NULL, lntmsg->msg_md->md_iov.kiov,
						      0, lntmsg->msg_md->md_length);
		if (rc != 0) {
			CERROR("unable to setup buffer: %d\n", rc);
			kgnilnd_tx_done(tx, rc);
			rc = -EIO;
			goto out;
		}

		tx->tx_lntmsg[1] = lnet_create_reply_msg(ni, lntmsg);
		if (tx->tx_lntmsg[1] == NULL) {
			CERROR("Can't create reply for GET to %s\n",
			       libcfs_nid2str(target.nid));
			kgnilnd_tx_done(tx, rc);
			rc = -EIO;
			goto out;
		}

		tx->tx_lntmsg[0] = lntmsg;
		if ((reverse_rdma_flag & GNILND_REVERSE_GET) == 0)
			tx->tx_msg.gnm_u.get.gngm_hdr = *hdr;
		else
			tx->tx_msg.gnm_u.putreq.gnprm_hdr = *hdr;

		/* rest of tx_msg is setup just before it is sent */
		kgnilnd_launch_tx(tx, net, &target);
		goto out;
	case LNET_MSG_REPLY:
	case LNET_MSG_PUT:
		/* to save on MDDs, we'll handle short kiov by vmap'ing
		 * and sending via SMSG */
		if (nob <= *kgnilnd_tunables.kgn_max_immediate)
		       break;

		if ((reverse_rdma_flag & GNILND_REVERSE_PUT) == 0)
			tx = kgnilnd_new_tx_msg(GNILND_MSG_PUT_REQ, ni->ni_nid);
		else
			tx = kgnilnd_new_tx_msg(GNILND_MSG_PUT_REQ_REV, ni->ni_nid);

		if (tx == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		rc = kgnilnd_setup_rdma_buffer(tx, niov, iov, kiov, offset, nob);
		if (rc != 0) {
			kgnilnd_tx_done(tx, rc);
			rc = -EIO;
			goto out;
		}

		tx->tx_lntmsg[0] = lntmsg;
		if ((reverse_rdma_flag & GNILND_REVERSE_PUT) == 0)
			tx->tx_msg.gnm_u.putreq.gnprm_hdr = *hdr;
		else
			tx->tx_msg.gnm_u.get.gngm_hdr = *hdr;

		/* rest of tx_msg is setup just before it is sent */
		kgnilnd_launch_tx(tx, net, &target);
		goto out;
	}

	/* send IMMEDIATE */

	LASSERTF(nob <= *kgnilnd_tunables.kgn_max_immediate,
		"lntmsg 0x%p too large %d\n", lntmsg, nob);

	tx = kgnilnd_new_tx_msg(GNILND_MSG_IMMEDIATE, ni->ni_nid);
	if (tx == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = kgnilnd_setup_immediate_buffer(tx, niov, iov, kiov, offset, nob);
	if (rc != 0) {
		kgnilnd_tx_done(tx, rc);
		goto out;
	}

	tx->tx_msg.gnm_u.immediate.gnim_hdr = *hdr;
	tx->tx_lntmsg[0] = lntmsg;
	kgnilnd_launch_tx(tx, net, &target);

out:
	/* use stored value as we could have already finalized lntmsg here from a failed launch */
	if (msg_vmflush)
		cfs_memory_pressure_restore(mpflag);
	return rc;
}

void
kgnilnd_setup_rdma(lnet_ni_t *ni, kgn_rx_t *rx, lnet_msg_t *lntmsg, int mlen)
{
	kgn_conn_t    *conn = rx->grx_conn;
	kgn_msg_t     *rxmsg = rx->grx_msg;
	unsigned int   niov = lntmsg->msg_niov;
	struct kvec   *iov = lntmsg->msg_iov;
	lnet_kiov_t   *kiov = lntmsg->msg_kiov;
	unsigned int   offset = lntmsg->msg_offset;
	unsigned int   nob = lntmsg->msg_len;
	int            done_type;
	kgn_tx_t      *tx;
	int            rc = 0;

	switch (rxmsg->gnm_type) {
	case GNILND_MSG_PUT_REQ_REV:
		done_type = GNILND_MSG_PUT_DONE_REV;
		nob = mlen;
		break;
	case GNILND_MSG_GET_REQ:
		done_type = GNILND_MSG_GET_DONE;
		break;
	default:
		CERROR("invalid msg type %s (%d)\n",
			kgnilnd_msgtype2str(rxmsg->gnm_type),
			rxmsg->gnm_type);
		LBUG();
	}

	tx = kgnilnd_new_tx_msg(done_type, ni->ni_nid);
	if (tx == NULL)
		goto failed_0;

	rc = kgnilnd_set_tx_id(tx, conn);
	if (rc != 0)
		goto failed_1;

	rc = kgnilnd_setup_rdma_buffer(tx, niov, iov, kiov, offset, nob);
	if (rc != 0)
		goto failed_1;

	tx->tx_lntmsg[0] = lntmsg;
	tx->tx_getinfo = rxmsg->gnm_u.get;

	/* we only queue from kgnilnd_recv - we might get called from other contexts
	 * and we don't want to block the mutex in those cases */

	spin_lock(&tx->tx_conn->gnc_device->gnd_lock);
	kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_MAPQ, 1);
	spin_unlock(&tx->tx_conn->gnc_device->gnd_lock);
	kgnilnd_schedule_device(tx->tx_conn->gnc_device);

	return;

 failed_1:
	kgnilnd_tx_done(tx, rc);
	kgnilnd_nak_rdma(conn, done_type, rc, rxmsg->gnm_u.get.gngm_cookie, ni->ni_nid);
 failed_0:
	lnet_finalize(ni, lntmsg, rc);
}

int
kgnilnd_eager_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
		   void **new_private)
{
	kgn_rx_t        *rx = private;
	kgn_conn_t      *conn = rx->grx_conn;
	kgn_msg_t       *rxmsg = rx->grx_msg;
	kgn_msg_t       *eagermsg = NULL;
	kgn_peer_t	*peer = NULL;
	kgn_conn_t	*found_conn = NULL;

	GNIDBG_MSG(D_NET, rxmsg, "eager recv for conn %p, rxmsg %p, lntmsg %p",
		conn, rxmsg, lntmsg);

	if (rxmsg->gnm_payload_len > *kgnilnd_tunables.kgn_max_immediate) {
		GNIDBG_MSG(D_ERROR, rxmsg, "payload too large %d",
			rxmsg->gnm_payload_len);
		return -EPROTO;
	}
	/* Grab a read lock so the connection doesnt disappear on us
	 * while we look it up
	 */
	read_lock(&kgnilnd_data.kgn_peer_conn_lock);

	peer = kgnilnd_find_peer_locked(rxmsg->gnm_srcnid);
	if (peer != NULL)
		found_conn = kgnilnd_find_conn_locked(peer);


	/* Verify the connection found is the same one that the message
	 * is supposed to be using, if it is not output an error message
	 * and return.
	 */
	if (!peer || !found_conn
	    || found_conn->gnc_peer_connstamp != rxmsg->gnm_connstamp) {
		read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		CERROR("Couldnt find matching peer %p or conn %p / %p\n",
			peer, conn, found_conn);
		if (found_conn) {
			CERROR("Unexpected connstamp "LPX64"("LPX64" expected)"
				" from %s", rxmsg->gnm_connstamp,
				found_conn->gnc_peer_connstamp,
				libcfs_nid2str(peer->gnp_nid));
		}
		return -ENOTCONN;
	}

	/* add conn ref to ensure it doesn't go away until all eager
	 * messages processed */
	kgnilnd_conn_addref(conn);

	/* Now that we have verified the connection is valid and added a
	 * reference we can remove the read_lock on the peer_conn_lock */
	read_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	/* we have no credits or buffers for this message, so copy it
	 * somewhere for a later kgnilnd_recv */
	if (atomic_read(&kgnilnd_data.kgn_neager_allocs) >=
			*kgnilnd_tunables.kgn_eager_credits) {
		CERROR("Out of eager credits to %s\n",
			libcfs_nid2str(conn->gnc_peer->gnp_nid));
		return -ENOMEM;
	}

	atomic_inc(&kgnilnd_data.kgn_neager_allocs);

	LIBCFS_ALLOC(eagermsg, sizeof(*eagermsg) + *kgnilnd_tunables.kgn_max_immediate);
	if (eagermsg == NULL) {
		kgnilnd_conn_decref(conn);
		CERROR("couldn't allocate eager rx message for conn %p to %s\n",
			conn, libcfs_nid2str(conn->gnc_peer->gnp_nid));
		return -ENOMEM;
	}

	/* copy msg and payload */
	memcpy(eagermsg, rxmsg, sizeof(*rxmsg) + rxmsg->gnm_payload_len);
	rx->grx_msg = eagermsg;
	rx->grx_eager = 1;

	/* stash this for lnet_finalize on cancel-on-conn-close */
	rx->grx_lntmsg = lntmsg;

	/* keep the same rx_t, it just has a new grx_msg now */
	*new_private = private;

	/* release SMSG buffer */
	kgnilnd_release_msg(conn);

	return 0;
}

int
kgnilnd_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
	     int delayed, unsigned int niov,
	     struct kvec *iov, lnet_kiov_t *kiov,
	     unsigned int offset, unsigned int mlen, unsigned int rlen)
{
	kgn_rx_t    *rx = private;
	kgn_conn_t  *conn = rx->grx_conn;
	kgn_msg_t   *rxmsg = rx->grx_msg;
	kgn_tx_t    *tx;
	int          rc = 0;
	__u32        pload_cksum;
	ENTRY;

	LASSERT(!in_interrupt());
	LASSERTF(mlen <= rlen, "%d <= %d\n", mlen, rlen);
	/* Either all pages or all vaddrs */
	LASSERTF(!(kiov != NULL && iov != NULL), "kiov %p iov %p\n",
		kiov, iov);

	GNIDBG_MSG(D_NET, rxmsg, "conn %p, rxmsg %p, lntmsg %p"
		" niov=%d kiov=%p iov=%p offset=%d mlen=%d rlen=%d",
		conn, rxmsg, lntmsg,
		niov, kiov, iov, offset, mlen, rlen);

	/* we need to lock here as recv can be called from any context */
	read_lock(&kgnilnd_data.kgn_peer_conn_lock);
	if (rx->grx_eager && conn->gnc_state != GNILND_CONN_ESTABLISHED) {
		read_unlock(&kgnilnd_data.kgn_peer_conn_lock);

		/* someone closed the conn after we copied this out, nuke it */
		kgnilnd_consume_rx(rx);
		lnet_finalize(ni, lntmsg, conn->gnc_error);
		RETURN(0);
	}
	read_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	switch (rxmsg->gnm_type) {
	default:
		GNIDBG_MSG(D_NETERROR, rxmsg, "conn %p, rx %p, rxmsg %p, lntmsg %p"
		" niov=%d kiov=%p iov=%p offset=%d mlen=%d rlen=%d",
		conn, rx, rxmsg, lntmsg, niov, kiov, iov, offset, mlen, rlen);
		LBUG();

	case GNILND_MSG_IMMEDIATE:
		if (mlen > rxmsg->gnm_payload_len) {
			GNIDBG_MSG(D_ERROR, rxmsg,
				"Immediate message from %s too big: %d > %d",
				libcfs_nid2str(conn->gnc_peer->gnp_nid), mlen,
				rxmsg->gnm_payload_len);
			rc = -EINVAL;
			kgnilnd_consume_rx(rx);
			RETURN(rc);
		}

		/* rxmsg[1] is a pointer to the payload, sitting in the buffer
		 * right after the kgn_msg_t header - so just 'cute' way of saying
		 * rxmsg + sizeof(kgn_msg_t) */

		/* check payload checksum if sent */

		if (*kgnilnd_tunables.kgn_checksum >= 2 &&
			!rxmsg->gnm_payload_cksum &&
			rxmsg->gnm_payload_len != 0)
			GNIDBG_MSG(D_WARNING, rxmsg, "no msg payload checksum when enabled");

		if (rxmsg->gnm_payload_cksum != 0) {
			/* gnm_payload_len set in kgnilnd_sendmsg from tx->tx_nob,
			 * which is what is used to calculate the cksum on the TX side */
			pload_cksum = kgnilnd_cksum(&rxmsg[1], rxmsg->gnm_payload_len);

			if (rxmsg->gnm_payload_cksum != pload_cksum) {
				GNIDBG_MSG(D_NETERROR, rxmsg,
					   "Bad payload checksum (%x expected %x)",
					    pload_cksum, rxmsg->gnm_payload_cksum);
				switch (*kgnilnd_tunables.kgn_checksum_dump) {
				case 2:
					kgnilnd_dump_blob(D_BUFFS, "bad payload checksum",
							  &rxmsg[1], rxmsg->gnm_payload_len);
					/* fall through to dump */
				case 1:
					libcfs_debug_dumplog();
					break;
				default:
					break;
				}
				rc = -ENOKEY;
				/* checksum problems are fatal, kill the conn */
				kgnilnd_consume_rx(rx);
				kgnilnd_close_conn(conn, rc);
				RETURN(rc);
			}
		}

		if (kiov != NULL)
			lnet_copy_flat2kiov(
				niov, kiov, offset,
				*kgnilnd_tunables.kgn_max_immediate,
				&rxmsg[1], 0, mlen);
		else
			lnet_copy_flat2iov(
				niov, iov, offset,
				*kgnilnd_tunables.kgn_max_immediate,
				&rxmsg[1], 0, mlen);

		kgnilnd_consume_rx(rx);
		lnet_finalize(ni, lntmsg, 0);
		RETURN(0);

	case GNILND_MSG_PUT_REQ:
		/* LNET wants to truncate or drop transaction, sending NAK */
		if (mlen == 0) {
			kgnilnd_consume_rx(rx);
			lnet_finalize(ni, lntmsg, 0);

			/* only error if lntmsg == NULL, otherwise we are just
			 * short circuiting the rdma process of 0 bytes */
			kgnilnd_nak_rdma(conn, rxmsg->gnm_type,
					lntmsg == NULL ? -ENOENT : 0,
					rxmsg->gnm_u.get.gngm_cookie,
					ni->ni_nid);
			RETURN(0);
		}
		/* sending ACK with sink buff. info */
		tx = kgnilnd_new_tx_msg(GNILND_MSG_PUT_ACK, ni->ni_nid);
		if (tx == NULL) {
			kgnilnd_consume_rx(rx);
			RETURN(-ENOMEM);
		}

		rc = kgnilnd_set_tx_id(tx, conn);
		if (rc != 0) {
			GOTO(nak_put_req, rc);
		}

		rc = kgnilnd_setup_rdma_buffer(tx, niov, iov, kiov, offset, mlen);
		if (rc != 0) {
			GOTO(nak_put_req, rc);
		}

		tx->tx_msg.gnm_u.putack.gnpam_src_cookie =
			rxmsg->gnm_u.putreq.gnprm_cookie;
		tx->tx_msg.gnm_u.putack.gnpam_dst_cookie = tx->tx_id.txe_cookie;
		tx->tx_msg.gnm_u.putack.gnpam_desc.gnrd_addr =
			(__u64)((unsigned long)tx->tx_buffer);
		tx->tx_msg.gnm_u.putack.gnpam_desc.gnrd_nob = mlen;

		tx->tx_lntmsg[0] = lntmsg; /* finalize this on RDMA_DONE */
		tx->tx_qtime = jiffies;
		/* we only queue from kgnilnd_recv - we might get called from other contexts
		 * and we don't want to block the mutex in those cases */

		spin_lock(&tx->tx_conn->gnc_device->gnd_lock);
		kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_MAPQ, 1);
		spin_unlock(&tx->tx_conn->gnc_device->gnd_lock);
		kgnilnd_schedule_device(tx->tx_conn->gnc_device);

		kgnilnd_consume_rx(rx);
		RETURN(0);

nak_put_req:
		/* make sure we send an error back when the PUT fails */
		kgnilnd_nak_rdma(conn, rxmsg->gnm_type, rc, rxmsg->gnm_u.get.gngm_cookie, ni->ni_nid);
		kgnilnd_tx_done(tx, rc);
		kgnilnd_consume_rx(rx);

		/* return magic LNet network error */
		RETURN(-EIO);
	case GNILND_MSG_GET_REQ_REV:
		/* LNET wants to truncate or drop transaction, sending NAK */
		if (mlen == 0) {
			kgnilnd_consume_rx(rx);
			lnet_finalize(ni, lntmsg, 0);

			/* only error if lntmsg == NULL, otherwise we are just
			 * short circuiting the rdma process of 0 bytes */
			kgnilnd_nak_rdma(conn, rxmsg->gnm_type,
					lntmsg == NULL ? -ENOENT : 0,
					rxmsg->gnm_u.get.gngm_cookie,
					ni->ni_nid);
			RETURN(0);
		}
		/* lntmsg can be null when parsing a LNET_GET */
		if (lntmsg != NULL) {
			/* sending ACK with sink buff. info */
			tx = kgnilnd_new_tx_msg(GNILND_MSG_GET_ACK_REV, ni->ni_nid);
			if (tx == NULL) {
				kgnilnd_consume_rx(rx);
				RETURN(-ENOMEM);
			}

			rc = kgnilnd_set_tx_id(tx, conn);
			if (rc != 0)
				GOTO(nak_get_req_rev, rc);


			rc = kgnilnd_setup_rdma_buffer(tx, niov, iov, kiov, offset, mlen);
			if (rc != 0)
				GOTO(nak_get_req_rev, rc);


			tx->tx_msg.gnm_u.putack.gnpam_src_cookie =
				rxmsg->gnm_u.putreq.gnprm_cookie;
			tx->tx_msg.gnm_u.putack.gnpam_dst_cookie = tx->tx_id.txe_cookie;
			tx->tx_msg.gnm_u.putack.gnpam_desc.gnrd_addr =
				(__u64)((unsigned long)tx->tx_buffer);
			tx->tx_msg.gnm_u.putack.gnpam_desc.gnrd_nob = mlen;

			tx->tx_lntmsg[0] = lntmsg; /* finalize this on RDMA_DONE */

			/* we only queue from kgnilnd_recv - we might get called from other contexts
			 * and we don't want to block the mutex in those cases */

			spin_lock(&tx->tx_conn->gnc_device->gnd_lock);
			kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_MAPQ, 1);
			spin_unlock(&tx->tx_conn->gnc_device->gnd_lock);
			kgnilnd_schedule_device(tx->tx_conn->gnc_device);
		} else {
			/* No match */
			kgnilnd_nak_rdma(conn, rxmsg->gnm_type,
					-ENOENT,
					rxmsg->gnm_u.get.gngm_cookie,
					ni->ni_nid);
		}

		kgnilnd_consume_rx(rx);
		RETURN(0);

nak_get_req_rev:
		/* make sure we send an error back when the GET fails */
		kgnilnd_nak_rdma(conn, rxmsg->gnm_type, rc, rxmsg->gnm_u.get.gngm_cookie, ni->ni_nid);
		kgnilnd_tx_done(tx, rc);
		kgnilnd_consume_rx(rx);

		/* return magic LNet network error */
		RETURN(-EIO);


	case GNILND_MSG_PUT_REQ_REV:
		/* LNET wants to truncate or drop transaction, sending NAK */
		if (mlen == 0) {
			kgnilnd_consume_rx(rx);
			lnet_finalize(ni, lntmsg, 0);

			/* only error if lntmsg == NULL, otherwise we are just
			 * short circuiting the rdma process of 0 bytes */
			kgnilnd_nak_rdma(conn, rxmsg->gnm_type,
					lntmsg == NULL ? -ENOENT : 0,
					rxmsg->gnm_u.get.gngm_cookie,
					ni->ni_nid);
			RETURN(0);
		}

		if (lntmsg != NULL) {
			/* Matched! */
			kgnilnd_setup_rdma(ni, rx, lntmsg, mlen);
		} else {
			/* No match */
			kgnilnd_nak_rdma(conn, rxmsg->gnm_type,
					-ENOENT,
					rxmsg->gnm_u.get.gngm_cookie,
					ni->ni_nid);
		}
		kgnilnd_consume_rx(rx);
		RETURN(0);
	case GNILND_MSG_GET_REQ:
		if (lntmsg != NULL) {
			/* Matched! */
			kgnilnd_setup_rdma(ni, rx, lntmsg, mlen);
		} else {
			/* No match */
			kgnilnd_nak_rdma(conn, rxmsg->gnm_type,
					-ENOENT,
					rxmsg->gnm_u.get.gngm_cookie,
					ni->ni_nid);
		}
		kgnilnd_consume_rx(rx);
		RETURN(0);
	}
	RETURN(0);
}

/* needs write_lock on kgn_peer_conn_lock held */
int
kgnilnd_check_conn_timeouts_locked(kgn_conn_t *conn)
{
	unsigned long      timeout, keepalive;
	unsigned long      now = jiffies;
	unsigned long      newest_last_rx;
	kgn_tx_t          *tx;

	/* given that we found this conn hanging off a peer, it better damned
	 * well be connected */
	LASSERTF(conn->gnc_state == GNILND_CONN_ESTABLISHED,
		 "conn 0x%p->%s with bad state%s\n", conn,
		 conn->gnc_peer ? libcfs_nid2str(conn->gnc_peer->gnp_nid)
			       : "<?>",
		 kgnilnd_conn_state2str(conn));

	CDEBUG(D_NET, "checking conn %p->%s timeout %d keepalive %d "
		      "rx_diff %lu tx_diff %lu\n",
		conn, libcfs_nid2str(conn->gnc_peer->gnp_nid),
		conn->gnc_timeout, GNILND_TO2KA(conn->gnc_timeout),
		cfs_duration_sec(now - conn->gnc_last_rx_cq),
		cfs_duration_sec(now - conn->gnc_last_tx));

	timeout = cfs_time_seconds(conn->gnc_timeout);
	keepalive = cfs_time_seconds(GNILND_TO2KA(conn->gnc_timeout));

	/* just in case our lack of RX msg processing is gumming up the works - give the
	 * remove an extra chance */

	newest_last_rx = GNILND_LASTRX(conn);

	if (time_after_eq(now, newest_last_rx + timeout)) {
		uint32_t level = D_CONSOLE|D_NETERROR;

		if (conn->gnc_peer->gnp_down == GNILND_RCA_NODE_DOWN) {
			level = D_NET;
		}
			GNIDBG_CONN(level, conn,
			"No gnilnd traffic received from %s for %lu "
			"seconds, terminating connection. Is node down? ",
			libcfs_nid2str(conn->gnc_peer->gnp_nid),
			cfs_duration_sec(now - newest_last_rx));
		return -ETIMEDOUT;
	}

	/* we don't timeout on last_tx stalls - we are going to trust the
	 * underlying network to let us know when sends are failing.
	 * At worst, the peer will timeout our RX stamp and drop the connection
	 * at that point. We'll then see his CLOSE or at worst his RX
	 * stamp stop and drop the connection on our end */

	if (time_after_eq(now, conn->gnc_last_tx + keepalive)) {
		CDEBUG(D_NET, "sending NOOP -> %s (%p idle %lu(%lu)) "
		       "last %lu/%lu/%lu %lus/%lus/%lus\n",
		       libcfs_nid2str(conn->gnc_peer->gnp_nid), conn,
		       cfs_duration_sec(jiffies - conn->gnc_last_tx),
		       keepalive,
		       conn->gnc_last_noop_want, conn->gnc_last_noop_sent,
		       conn->gnc_last_noop_cq,
		       cfs_duration_sec(jiffies - conn->gnc_last_noop_want),
		       cfs_duration_sec(jiffies - conn->gnc_last_noop_sent),
		       cfs_duration_sec(jiffies - conn->gnc_last_noop_cq));
		set_mb(conn->gnc_last_noop_want, jiffies);
		atomic_inc(&conn->gnc_reaper_noop);
		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_NOOP_SEND))
			return 0;

		tx = kgnilnd_new_tx_msg(GNILND_MSG_NOOP, conn->gnc_peer->gnp_net->gnn_ni->ni_nid);
		if (tx == NULL)
			return 0;
		kgnilnd_queue_tx(conn, tx);
	}

	return 0;
}

/* needs write_lock on kgn_peer_conn_lock held */
void
kgnilnd_check_peer_timeouts_locked(kgn_peer_t *peer, struct list_head *todie,
				    struct list_head *souls)
{
	unsigned long           timeout;
	kgn_conn_t             *conn, *connN = NULL;
	kgn_tx_t               *tx, *txN;
	int                     rc = 0;
	int                     count = 0;
	int                     reconnect;
	int                     to_reconn;
	short                   releaseconn = 0;
	unsigned long           first_rx = 0;
	int                     purgatory_conn_cnt = 0;

	CDEBUG(D_NET, "checking peer 0x%p->%s for timeouts; interval %lus\n",
		peer, libcfs_nid2str(peer->gnp_nid),
		peer->gnp_reconnect_interval);

	timeout = cfs_time_seconds(MAX(*kgnilnd_tunables.kgn_timeout,
				       GNILND_MIN_TIMEOUT));

	conn = kgnilnd_find_conn_locked(peer);
	if (conn) {
		/* if there is a valid conn, check the queues for timeouts */
		rc = kgnilnd_check_conn_timeouts_locked(conn);
		if (rc) {
			if (CFS_FAIL_CHECK(CFS_FAIL_GNI_RX_CLOSE_CLOSING)) {
				/* simulate a RX CLOSE after the timeout but before
				 * the scheduler thread gets it */
				conn->gnc_close_recvd = GNILND_CLOSE_INJECT1;
				conn->gnc_peer_error = -ETIMEDOUT;
			}
			/* Once we mark closed, any of the scheduler threads could
			 * get it and move through before we hit the fail loc code */
			kgnilnd_close_conn_locked(conn, rc);
		} else {
			/* first_rx is used to decide when to release a conn from purgatory.
			 */
			first_rx = conn->gnc_first_rx;
		}
	}

	/* now regardless of starting new conn, find tx on peer queue that
	 * are old and smell bad - do this first so we don't trigger
	 * reconnect on empty queue if we timeout all */
	list_for_each_entry_safe(tx, txN, &peer->gnp_tx_queue, tx_list) {
		if (time_after_eq(jiffies, tx->tx_qtime + timeout)) {
			if (count == 0) {
				LCONSOLE_INFO("could not send to %s due to connection"
				       " setup failure after %lu seconds\n",
				       libcfs_nid2str(peer->gnp_nid),
				       cfs_duration_sec(jiffies - tx->tx_qtime));
			}
			kgnilnd_tx_del_state_locked(tx, peer, NULL,
						   GNILND_TX_ALLOCD);
			list_add_tail(&tx->tx_list, todie);
			count++;
		}
	}

	if (count || peer->gnp_connecting == GNILND_PEER_KILL) {
		CDEBUG(D_NET, "canceling %d tx for peer 0x%p->%s\n",
			count, peer, libcfs_nid2str(peer->gnp_nid));
		/* if we nuked all the TX, stop peer connection attempt (if there is one..) */
		if (list_empty(&peer->gnp_tx_queue) ||
			peer->gnp_connecting == GNILND_PEER_KILL) {
			/* we pass down todie to use a common function - but we know there are
			 * no TX to add */
			kgnilnd_cancel_peer_connect_locked(peer, todie);
		}
	}

	/* Don't reconnect if we are still trying to clear out old conns.
	 * This prevents us sending traffic on the new mbox before ensuring we are done
	 * with the old one */
	reconnect = (peer->gnp_down == GNILND_RCA_NODE_UP) &&
		    (atomic_read(&peer->gnp_dirty_eps) == 0);

	/* fast reconnect after a timeout */
	to_reconn = !conn &&
		    (peer->gnp_last_errno == -ETIMEDOUT) &&
		    *kgnilnd_tunables.kgn_fast_reconn;

	/* if we are not connected and there are tx on the gnp_tx_queue waiting
	 * to be sent, we'll check the reconnect interval and fire up a new
	 * connection request */

	if (reconnect &&
	    (peer->gnp_connecting == GNILND_PEER_IDLE) &&
	    (time_after_eq(jiffies, peer->gnp_reconnect_time)) &&
	    (!list_empty(&peer->gnp_tx_queue) || to_reconn)) {

		CDEBUG(D_NET, "starting connect to %s\n",
			libcfs_nid2str(peer->gnp_nid));
		LASSERTF(peer->gnp_connecting == GNILND_PEER_IDLE, "Peer was idle and we"
			"have a write_lock, state issue %d\n", peer->gnp_connecting);

		peer->gnp_connecting = GNILND_PEER_CONNECT;
		kgnilnd_peer_addref(peer); /* extra ref for connd */

		spin_lock(&peer->gnp_net->gnn_dev->gnd_connd_lock);
		list_add_tail(&peer->gnp_connd_list,
			      &peer->gnp_net->gnn_dev->gnd_connd_peers);
		spin_unlock(&peer->gnp_net->gnn_dev->gnd_connd_lock);

		kgnilnd_schedule_dgram(peer->gnp_net->gnn_dev);
	}

	/* fail_loc to allow us to delay release of purgatory */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PURG_REL_DELAY))
		return;

	/* This check allows us to verify that the new conn is actually being used. This allows us to
	 * pull the old conns out of purgatory if they have actually seen traffic.
	 * We only release a conn from purgatory during stack reset, admin command, or when a peer reconnects
	 */
	if (first_rx &&
		time_after(jiffies, first_rx + cfs_time_seconds(*kgnilnd_tunables.kgn_hardware_timeout))) {
		CDEBUG(D_INFO, "We can release peer %s conn's from purgatory %lu\n",
			libcfs_nid2str(peer->gnp_nid), first_rx + cfs_time_seconds(*kgnilnd_tunables.kgn_hardware_timeout));
		releaseconn = 1;
	}

	list_for_each_entry_safe (conn, connN, &peer->gnp_conns, gnc_list) {
	/* check for purgatory timeouts */
		if (conn->gnc_in_purgatory) {
			/* We cannot detach this conn from purgatory if it has not been closed so we reschedule it
			 * that way the next time we check it we can detach it from purgatory
			 */

			if (conn->gnc_state != GNILND_CONN_DONE) {
				/* Skip over conns that are currently not DONE. If they arent already scheduled
				 * for completion something in the state machine is broken.
				 */
				continue;
			}

			/* We only detach a conn that is in purgatory if we have received a close message,
			 * we have a new valid connection that has successfully received data, or an admin
			 * command tells us we need to detach.
			 */

			if (conn->gnc_close_recvd || releaseconn || conn->gnc_needs_detach) {
				unsigned long   waiting;

				waiting = (long) jiffies - conn->gnc_last_rx_cq;

				/* C.E: The remote peer is expected to close the
				 * connection (see kgnilnd_check_conn_timeouts)
				 * via the reaper thread and nuke out the MDD and
				 * FMA resources after conn->gnc_timeout has expired
				 * without an FMA RX */
				CDEBUG(D_NET, "Reconnected to %s in %lds or admin forced detach, dropping "
					" held resources\n",
					libcfs_nid2str(conn->gnc_peer->gnp_nid),
					cfs_duration_sec(waiting));

				kgnilnd_detach_purgatory_locked(conn, souls);
			} else {
				purgatory_conn_cnt++;
			}
		}
	}

	/* If we have too many connections in purgatory we could run out of
	 * resources. Limit the number of connections to a tunable number,
	 * clean up to the minimum all in one fell swoop... there are
	 * situations where dvs will retry tx's and we can eat up several
	 * hundread connection requests at once.
	 */
	if (purgatory_conn_cnt > *kgnilnd_tunables.kgn_max_purgatory) {
		list_for_each_entry_safe(conn, connN, &peer->gnp_conns,
					 gnc_list) {
			if (conn->gnc_in_purgatory &&
			    conn->gnc_state == GNILND_CONN_DONE) {
				CDEBUG(D_NET, "Dropping Held resource due to"
					      " resource limits being hit\n");
				kgnilnd_detach_purgatory_locked(conn, souls);

				if (purgatory_conn_cnt-- <
				    *kgnilnd_tunables.kgn_max_purgatory)
					break;
			}
		}
	}

	return;
}

void
kgnilnd_reaper_check(int idx)
{
	struct list_head  *peers = &kgnilnd_data.kgn_peers[idx];
	struct list_head  *ctmp, *ctmpN;
	struct list_head   geriatrics;
	struct list_head   souls;

	INIT_LIST_HEAD(&geriatrics);
	INIT_LIST_HEAD(&souls);

	write_lock(&kgnilnd_data.kgn_peer_conn_lock);

	list_for_each_safe(ctmp, ctmpN, peers) {
		kgn_peer_t        *peer = NULL;

		/* don't timeout stuff if the network is mucked or shutting down */
		if (kgnilnd_check_hw_quiesce()) {
			break;
		}
		peer = list_entry(ctmp, kgn_peer_t, gnp_list);

		kgnilnd_check_peer_timeouts_locked(peer, &geriatrics, &souls);
	}

	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	kgnilnd_txlist_done(&geriatrics, -EHOSTUNREACH);
	kgnilnd_release_purgatory_list(&souls);
}

void
kgnilnd_update_reaper_timeout(long timeout)
{
	LASSERT(timeout > 0);

	spin_lock(&kgnilnd_data.kgn_reaper_lock);

	if (timeout < kgnilnd_data.kgn_new_min_timeout)
		kgnilnd_data.kgn_new_min_timeout = timeout;

	spin_unlock(&kgnilnd_data.kgn_reaper_lock);
}

static void
kgnilnd_reaper_poke_with_stick(unsigned long arg)
{
	wake_up(&kgnilnd_data.kgn_reaper_waitq);
}

int
kgnilnd_reaper(void *arg)
{
	long               timeout;
	int                i;
	int                hash_index = 0;
	unsigned long      next_check_time = jiffies;
	long               current_min_timeout = MAX_SCHEDULE_TIMEOUT;
	struct timer_list  timer;
	DEFINE_WAIT(wait);

	cfs_block_allsigs();

	/* all gnilnd threads need to run fairly urgently */
	set_user_nice(current, *kgnilnd_tunables.kgn_nice);
	spin_lock(&kgnilnd_data.kgn_reaper_lock);

	while (!kgnilnd_data.kgn_shutdown) {
		/* I wake up every 'p' seconds to check for timeouts on some
		 * more peers.  I try to check every connection 'n' times
		 * within the global minimum of all keepalive and timeout
		 * intervals, to ensure I attend to every connection within
		 * (n+1)/n times its timeout intervals. */
		const int     p = GNILND_REAPER_THREAD_WAKE;
		const int     n = GNILND_REAPER_NCHECKS;
		int           chunk;
		/* to quiesce or to not quiesce, that is the question */
		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			spin_unlock(&kgnilnd_data.kgn_reaper_lock);
			KGNILND_SPIN_QUIESCE;
			spin_lock(&kgnilnd_data.kgn_reaper_lock);
		}

		/* careful with the jiffy wrap... */
		timeout = (long)(next_check_time - jiffies);

		if (timeout > 0) {
			prepare_to_wait(&kgnilnd_data.kgn_reaper_waitq, &wait,
					TASK_INTERRUPTIBLE);
			spin_unlock(&kgnilnd_data.kgn_reaper_lock);
			setup_timer(&timer, kgnilnd_reaper_poke_with_stick,
				    next_check_time);
			mod_timer(&timer, (long) jiffies + timeout);

			/* check flag variables before committing */
			if (!kgnilnd_data.kgn_shutdown &&
			    !kgnilnd_data.kgn_quiesce_trigger) {
				CDEBUG(D_INFO, "schedule timeout %ld (%lu sec)\n",
				       timeout, cfs_duration_sec(timeout));
				schedule();
				CDEBUG(D_INFO, "awake after schedule\n");
			}

			del_singleshot_timer_sync(&timer);
			spin_lock(&kgnilnd_data.kgn_reaper_lock);
			finish_wait(&kgnilnd_data.kgn_reaper_waitq, &wait);
			continue;
		}

		/* new_min_timeout is set from the conn timeouts and keepalive
		 * this should end up with a min timeout of
		 * GNILND_TIMEOUT2KEEPALIVE(t) or roughly LND_TIMEOUT/2 */
		if (kgnilnd_data.kgn_new_min_timeout < current_min_timeout) {
			current_min_timeout = kgnilnd_data.kgn_new_min_timeout;
			CDEBUG(D_NET, "Set new min timeout %ld\n",
			       current_min_timeout);
		}

		spin_unlock(&kgnilnd_data.kgn_reaper_lock);

		/* Compute how many table entries to check now so I get round
		 * the whole table fast enough given that I do this at fixed
		 * intervals of 'p' seconds) */
		chunk = *kgnilnd_tunables.kgn_peer_hash_size;
		if (kgnilnd_data.kgn_new_min_timeout > n * p)
			chunk = (chunk * n * p) /
				kgnilnd_data.kgn_new_min_timeout;
		if (chunk == 0)
			chunk = 1;
		for (i = 0; i < chunk; i++) {
			kgnilnd_reaper_check(hash_index);
			hash_index = (hash_index + 1) %
				*kgnilnd_tunables.kgn_peer_hash_size;
		}
		next_check_time = (long) jiffies + cfs_time_seconds(p);
		CDEBUG(D_INFO, "next check at %lu or in %d sec\n", next_check_time, p);

		spin_lock(&kgnilnd_data.kgn_reaper_lock);
	}

	spin_unlock(&kgnilnd_data.kgn_reaper_lock);

	kgnilnd_thread_fini();
	return 0;
}

int
kgnilnd_recv_bte_get(kgn_tx_t *tx) {
	unsigned niov, offset, nob;
	lnet_kiov_t	*kiov;
	lnet_msg_t *lntmsg = tx->tx_lntmsg[0];
	kgnilnd_parse_lnet_rdma(lntmsg, &niov, &offset, &nob, &kiov, tx->tx_nob_rdma);

	if (kiov != NULL) {
		lnet_copy_flat2kiov(
			niov, kiov, offset,
			nob,
			tx->tx_buffer_copy + tx->tx_offset, 0, nob);
	} else {
		memcpy(tx->tx_buffer, tx->tx_buffer_copy + tx->tx_offset, nob);
	}
	return 0;
}


int
kgnilnd_check_rdma_cq(kgn_device_t *dev)
{
	gni_return_t           rrc;
	gni_post_descriptor_t *desc;
	__u64                  event_data;
	kgn_tx_ev_id_t         ev_id;
	char                   err_str[256];
	int                    should_retry, rc;
	long                   num_processed = 0;
	kgn_conn_t            *conn = NULL;
	kgn_tx_t              *tx = NULL;
	kgn_rdma_desc_t       *rdesc;
	unsigned int           rnob;
	__u64                  rcookie;

	for (;;) {
		/* make sure we don't keep looping if we need to reset */
		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			return num_processed;
		}
		rc = kgnilnd_mutex_trylock(&dev->gnd_cq_mutex);
		if (!rc) {
			/* we didn't get the mutex, so return that there is still work
			 * to be done */
			return 1;
		}
		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_DELAY_RDMA)) {
			/* a bit gross - but we need a good way to test for
			 * delayed RDMA completions and the easiest way to do
			 * that is to delay the RDMA CQ events */
			rrc = GNI_RC_NOT_DONE;
		} else {
			rrc = kgnilnd_cq_get_event(dev->gnd_snd_rdma_cqh, &event_data);
		}

		if (rrc == GNI_RC_NOT_DONE) {
			kgnilnd_gl_mutex_unlock(&dev->gnd_cq_mutex);
			CDEBUG(D_INFO, "SEND RDMA CQ %d empty processed %ld\n",
			       dev->gnd_id, num_processed);
			return num_processed;
		}
		dev->gnd_sched_alive = jiffies;
		num_processed++;

		LASSERTF(!GNI_CQ_OVERRUN(event_data),
			"this is bad, somehow our credits didn't protect us"
			" from CQ overrun\n");
		LASSERTF(GNI_CQ_GET_TYPE(event_data) == GNI_CQ_EVENT_TYPE_POST,
			"rrc %d, GNI_CQ_GET_TYPE("LPX64") = "LPX64"\n", rrc,
			event_data, GNI_CQ_GET_TYPE(event_data));

		rrc = kgnilnd_get_completed(dev->gnd_snd_rdma_cqh, event_data,
					    &desc);
		kgnilnd_gl_mutex_unlock(&dev->gnd_cq_mutex);

		/* XXX Nic: Need better error handling here... */
		LASSERTF((rrc == GNI_RC_SUCCESS) ||
			  (rrc == GNI_RC_TRANSACTION_ERROR),
			 "rrc %d\n", rrc);

		ev_id.txe_cookie = desc->post_id;

		kgnilnd_validate_tx_ev_id(&ev_id, &tx, &conn);

		if (conn == NULL || tx == NULL) {
			/* either conn or tx was already nuked and this is a "late"
			 * completion, so drop it */
			continue;
		}

		GNITX_ASSERTF(tx, tx->tx_msg.gnm_type == GNILND_MSG_PUT_DONE ||
			tx->tx_msg.gnm_type == GNILND_MSG_GET_DONE ||
			tx->tx_msg.gnm_type == GNILND_MSG_PUT_DONE_REV ||
			tx->tx_msg.gnm_type == GNILND_MSG_GET_DONE_REV,
			"tx %p with type %d\n", tx, tx->tx_msg.gnm_type);

		GNIDBG_TX(D_NET, tx, "RDMA completion for %d bytes", tx->tx_nob);

		if (tx->tx_msg.gnm_type == GNILND_MSG_GET_DONE_REV) {
			lnet_set_reply_msg_len(NULL, tx->tx_lntmsg[1],
					       tx->tx_msg.gnm_u.completion.gncm_retval);
		}

		rc = 0;
		if (tx->tx_msg.gnm_type == GNILND_MSG_GET_DONE_REV && desc->status == GNI_RC_SUCCESS) {
			if (tx->tx_buffer_copy != NULL)
				kgnilnd_recv_bte_get(tx);
			rc = kgnilnd_verify_rdma_cksum(tx, tx->tx_putinfo.gnpam_payload_cksum, tx->tx_nob_rdma);
		}

		if (tx->tx_msg.gnm_type == GNILND_MSG_PUT_DONE_REV && desc->status == GNI_RC_SUCCESS) {
			if (tx->tx_buffer_copy != NULL)
				kgnilnd_recv_bte_get(tx);
			rc = kgnilnd_verify_rdma_cksum(tx, tx->tx_getinfo.gngm_payload_cksum, tx->tx_nob_rdma);
		}

		/* remove from rdmaq */
		kgnilnd_conn_mutex_lock(&conn->gnc_rdma_mutex);
		spin_lock(&conn->gnc_list_lock);
		kgnilnd_tx_del_state_locked(tx, NULL, conn, GNILND_TX_ALLOCD);
		spin_unlock(&conn->gnc_list_lock);
		kgnilnd_conn_mutex_unlock(&conn->gnc_rdma_mutex);

		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_RDMA_CQ_ERROR)) {
			event_data = 1LL << 48;
			rc = 1;
		}

		if (likely(desc->status == GNI_RC_SUCCESS) && rc == 0) {
			atomic_inc(&dev->gnd_rdma_ntx);
			atomic64_add(tx->tx_nob, &dev->gnd_rdma_txbytes);
			/* transaction succeeded, add into fmaq */
			kgnilnd_queue_tx(conn, tx);
			kgnilnd_peer_alive(conn->gnc_peer);

			/* drop ref from kgnilnd_validate_tx_ev_id */
			kgnilnd_admin_decref(conn->gnc_tx_in_use);
			kgnilnd_conn_decref(conn);

			continue;
		}

		/* fall through to the TRANSACTION_ERROR case */
		tx->tx_retrans++;

		/* get stringified version for log messages */
		kgnilnd_cq_error_str(event_data, &err_str, 256);
		kgnilnd_cq_error_recoverable(event_data, &should_retry);

		/* make sure we are not off in the weeds with this tx */
		if (tx->tx_retrans >
			*kgnilnd_tunables.kgn_max_retransmits) {
			GNIDBG_TX(D_NETERROR, tx,
			       "giving up on TX, too many retries", NULL);
			should_retry = 0;
		}

		GNIDBG_TX(D_NETERROR, tx, "RDMA %s error (%s)",
			should_retry ? "transient" : "unrecoverable", err_str);

		if (tx->tx_msg.gnm_type == GNILND_MSG_PUT_DONE ||
		    tx->tx_msg.gnm_type == GNILND_MSG_GET_DONE_REV) {
			rdesc    = &tx->tx_putinfo.gnpam_desc;
			rnob     = tx->tx_putinfo.gnpam_desc.gnrd_nob;
			rcookie  = tx->tx_putinfo.gnpam_dst_cookie;
		} else {
			rdesc    = &tx->tx_getinfo.gngm_desc;
			rnob     = tx->tx_lntmsg[0]->msg_len;
			rcookie  = tx->tx_getinfo.gngm_cookie;
		}

		if (should_retry) {
			kgnilnd_rdma(tx,
				     tx->tx_msg.gnm_type,
				     rdesc,
				     rnob, rcookie);
		} else {
			kgnilnd_nak_rdma(conn,
					 tx->tx_msg.gnm_type,
					 -EFAULT,
					 rcookie,
					 tx->tx_msg.gnm_srcnid);
			kgnilnd_tx_done(tx, -GNILND_NOPURG);
			kgnilnd_close_conn(conn, -ECOMM);
		}

		/* drop ref from kgnilnd_validate_tx_ev_id */
		kgnilnd_admin_decref(conn->gnc_tx_in_use);
		kgnilnd_conn_decref(conn);
	}
}

int
kgnilnd_check_fma_send_cq(kgn_device_t *dev)
{
	gni_return_t           rrc;
	__u64                  event_data;
	kgn_tx_ev_id_t         ev_id;
	kgn_tx_t              *tx = NULL;
	kgn_conn_t            *conn = NULL;
	int                    queued_fma, saw_reply, rc;
	long                   num_processed = 0;

	for (;;) {
		/* make sure we don't keep looping if we need to reset */
		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			return num_processed;
		}

		rc = kgnilnd_mutex_trylock(&dev->gnd_cq_mutex);
		if (!rc) {
			/* we didn't get the mutex, so return that there is still work
			 * to be done */
			return 1;
		}

		rrc = kgnilnd_cq_get_event(dev->gnd_snd_fma_cqh, &event_data);
		kgnilnd_gl_mutex_unlock(&dev->gnd_cq_mutex);

		if (rrc == GNI_RC_NOT_DONE) {
			CDEBUG(D_INFO,
			       "SMSG send CQ %d not ready (data "LPX64") "
			       "processed %ld\n", dev->gnd_id, event_data,
			       num_processed);
			return num_processed;
		}

		dev->gnd_sched_alive = jiffies;
		num_processed++;

		LASSERTF(!GNI_CQ_OVERRUN(event_data),
			"this is bad, somehow our credits didn't "
			"protect us from CQ overrun\n");
		LASSERTF(GNI_CQ_GET_TYPE(event_data) == GNI_CQ_EVENT_TYPE_SMSG,
			"rrc %d, GNI_CQ_GET_TYPE("LPX64") = "LPX64"\n", rrc,
			event_data, GNI_CQ_GET_TYPE(event_data));

		/* if SMSG couldn't handle an error, time for conn to die */
		if (unlikely(rrc == GNI_RC_TRANSACTION_ERROR)) {
			char            err_str[256];

			/* need to take the write_lock to ensure atomicity
			 * on the conn state if we need to close it */
			write_lock(&kgnilnd_data.kgn_peer_conn_lock);
			conn = kgnilnd_cqid2conn_locked(GNI_CQ_GET_INST_ID(event_data));
			if (conn == NULL) {
				/* Conn was destroyed? */
				CDEBUG(D_NET,
					"SMSG CQID lookup "LPX64" failed\n",
					GNI_CQ_GET_INST_ID(event_data));
				write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
				continue;
			}

			kgnilnd_cq_error_str(event_data, &err_str, 256);
			CNETERR("SMSG send error to %s: rc %d (%s)\n",
			       libcfs_nid2str(conn->gnc_peer->gnp_nid),
			       rrc, err_str);
			kgnilnd_close_conn_locked(conn, -ECOMM);

			write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

			/* no need to process rest of this tx -
			 * it is getting canceled */
			continue;
		}

		/* fall through to GNI_RC_SUCCESS case */
		ev_id.txe_smsg_id = GNI_CQ_GET_MSG_ID(event_data);

		kgnilnd_validate_tx_ev_id(&ev_id, &tx, &conn);
		if (conn == NULL || tx == NULL) {
			/* either conn or tx was already nuked and this is a "late"
			 * completion, so drop it */
			continue;
		}

		tx->tx_conn->gnc_last_tx_cq = jiffies;
		if (tx->tx_msg.gnm_type == GNILND_MSG_NOOP) {
			set_mb(conn->gnc_last_noop_cq, jiffies);
		}

		/* lock tx_list_state and tx_state */
		kgnilnd_conn_mutex_lock(&conn->gnc_smsg_mutex);
		spin_lock(&tx->tx_conn->gnc_list_lock);

		GNITX_ASSERTF(tx, tx->tx_list_state == GNILND_TX_LIVE_FMAQ,
				"state not GNILND_TX_LIVE_FMAQ", NULL);
		GNITX_ASSERTF(tx, tx->tx_state & GNILND_TX_WAITING_COMPLETION,
			"not waiting for completion", NULL);

		GNIDBG_TX(D_NET, tx, "SMSG complete tx_state %x rc %d",
			tx->tx_state, rrc);

		tx->tx_state &= ~GNILND_TX_WAITING_COMPLETION;

		/* This will trigger other FMA sends that were
		 * pending this completion */
		queued_fma = !list_empty(&tx->tx_conn->gnc_fmaq);

		/* we either did not expect reply or we already got it */
		saw_reply = !(tx->tx_state & GNILND_TX_WAITING_REPLY);

		spin_unlock(&tx->tx_conn->gnc_list_lock);
		kgnilnd_conn_mutex_unlock(&conn->gnc_smsg_mutex);

		if (queued_fma) {
			CDEBUG(D_NET, "scheduling conn 0x%p->%s for fmaq\n",
			       conn,
			       libcfs_nid2str(conn->gnc_peer->gnp_nid));
			kgnilnd_schedule_conn(conn);
		}

		/* If saw_reply is false as soon as gnc_list_lock is dropped the tx could be nuked
		 * If saw_reply is true we know that the tx is safe to use as the other thread
		 * is already finished with it.
		 */

		if (saw_reply) {
			/* no longer need to track on the live_fmaq */
			kgnilnd_tx_del_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_ALLOCD);

			if (tx->tx_state & GNILND_TX_PENDING_RDMA) {
				/* we already got reply & were waiting for
				 * completion of initial send */
				/* to initiate RDMA transaction */
				GNIDBG_TX(D_NET, tx,
					 "Pending RDMA 0x%p type 0x%02x",
					 tx->tx_msg.gnm_type);
				tx->tx_state &= ~GNILND_TX_PENDING_RDMA;
				rc = kgnilnd_send_mapped_tx(tx, 0);
				GNITX_ASSERTF(tx, rc == 0, "RDMA send failed: %d\n", rc);
			} else {
				/* we are done with this tx */
				GNIDBG_TX(D_NET, tx,
					 "Done with tx type 0x%02x",
					 tx->tx_msg.gnm_type);
				kgnilnd_tx_done(tx, tx->tx_rc);
			}
		}

		/* drop ref from kgnilnd_validate_tx_ev_id */
		kgnilnd_admin_decref(conn->gnc_tx_in_use);
		kgnilnd_conn_decref(conn);

		/* if we are waiting for a REPLY, we'll handle the tx then */
	} /* end for loop */
}

int
kgnilnd_check_fma_rcv_cq(kgn_device_t *dev)
{
	kgn_conn_t         *conn;
	gni_return_t        rrc;
	__u64               event_data;
	long                num_processed = 0;
	struct list_head   *conns;
	struct list_head   *tmp;
	int                 rc;

	for (;;) {
		/* make sure we don't keep looping if we need to reset */
		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			return num_processed;
		}

		rc = kgnilnd_mutex_trylock(&dev->gnd_cq_mutex);
		if (!rc) {
			/* we didn't get the mutex, so return that there is still work
			 * to be done */
			return 1;
		}
		rrc = kgnilnd_cq_get_event(dev->gnd_rcv_fma_cqh, &event_data);
		kgnilnd_gl_mutex_unlock(&dev->gnd_cq_mutex);

		if (rrc == GNI_RC_NOT_DONE) {
			CDEBUG(D_INFO, "SMSG RX CQ %d empty data "LPX64" "
				"processed %ld\n",
				dev->gnd_id, event_data, num_processed);
			return num_processed;
		}
		dev->gnd_sched_alive = jiffies;
		num_processed++;

		/* this is the only CQ that can really handle transient
		 * CQ errors */
		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CQ_GET_EVENT)) {
			rrc = cfs_fail_val ? cfs_fail_val
					   : GNI_RC_ERROR_RESOURCE;
			if (rrc == GNI_RC_ERROR_RESOURCE) {
				/* set overrun too */
				event_data |= (1UL << 63);
				LASSERTF(GNI_CQ_OVERRUN(event_data),
					 "(1UL << 63) is no longer the bit to"
					 "set to indicate CQ_OVERRUN\n");
			}
		}
		/* sender should get error event too and take care
		of failed transaction by re-transmitting */
		if (rrc == GNI_RC_TRANSACTION_ERROR) {
			CDEBUG(D_NET, "SMSG RX CQ error "LPX64"\n", event_data);
			continue;
		}

		if (likely(!GNI_CQ_OVERRUN(event_data))) {
			read_lock(&kgnilnd_data.kgn_peer_conn_lock);
			conn = kgnilnd_cqid2conn_locked(
						 GNI_CQ_GET_INST_ID(event_data));
			if (conn == NULL) {
				CDEBUG(D_NET, "SMSG RX CQID lookup "LPU64" "
					"failed, dropping event "LPX64"\n",
					GNI_CQ_GET_INST_ID(event_data),
					event_data);
			} else {
				CDEBUG(D_NET, "SMSG RX: CQID "LPU64" "
				       "conn %p->%s\n",
					GNI_CQ_GET_INST_ID(event_data),
					conn, conn->gnc_peer ?
					libcfs_nid2str(conn->gnc_peer->gnp_nid) :
					"<?>");

				conn->gnc_last_rx_cq = jiffies;

				/* stash first rx so we can clear out purgatory.
				 */
				if (conn->gnc_first_rx == 0) {
					conn->gnc_first_rx = jiffies;
				}
				kgnilnd_peer_alive(conn->gnc_peer);
				kgnilnd_schedule_conn(conn);
			}
			read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			continue;
		}

		/* FMA CQ has overflowed: check ALL conns */
		CNETERR("SMSG RX CQ overflow: scheduling ALL "
		       "conns on device %d\n", dev->gnd_id);

		for (rc = 0; rc < *kgnilnd_tunables.kgn_peer_hash_size; rc++) {

			read_lock(&kgnilnd_data.kgn_peer_conn_lock);
			conns = &kgnilnd_data.kgn_conns[rc];

			list_for_each(tmp, conns) {
				conn = list_entry(tmp, kgn_conn_t,
						  gnc_hashlist);

				if (conn->gnc_device == dev) {
					kgnilnd_schedule_conn(conn);
					conn->gnc_last_rx_cq = jiffies;
				}
			}

			/* don't block write lockers for too long... */
			read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		}
	}
}

/* try_map_if_full should only be used when processing TX from list of
 * backlog TX waiting on mappings to free up
 *
 * Return Codes:
 *  try_map_if_full = 0: 0 (sent or queued), (-|+)errno failure of kgnilnd_sendmsg
 *  try_map_if_full = 1: 0 (sent), -ENOMEM for caller to requeue, (-|+)errno failure of kgnilnd_sendmsg */

int
kgnilnd_send_mapped_tx(kgn_tx_t *tx, int try_map_if_full)
{
	/* slight bit of race if multiple people calling, but at worst we'll have
	 * order altered just a bit... which would not be determenistic anyways */
	int     rc = atomic_read(&tx->tx_conn->gnc_device->gnd_nq_map);

	GNIDBG_TX(D_NET, tx, "try %d nq_map %d", try_map_if_full, rc);

	/* We know that we have a GART reservation that should guarantee forward progress.
	 * This means we don't need to take any extraordinary efforts if we are failing
	 * mappings here - even if we are holding a very small number of these. */

	if (try_map_if_full || (rc == 0)) {
		rc = kgnilnd_map_buffer(tx);
	}

	/* rc should be 0 if we mapped successfully here, if non-zero
	 * we are queueing */
	if (rc != 0) {
		/* if try_map_if_full set, they handle requeuing */
		if (unlikely(try_map_if_full)) {
			RETURN(rc);
		} else {
			spin_lock(&tx->tx_conn->gnc_device->gnd_lock);
			kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_MAPQ, 1);
			spin_unlock(&tx->tx_conn->gnc_device->gnd_lock);
			/* make sure we wake up sched to run this */
			kgnilnd_schedule_device(tx->tx_conn->gnc_device);
			/* return 0 as this is now queued for later sending */
			RETURN(0);
		}
	}

	switch (tx->tx_msg.gnm_type) {
	default:
		LBUG();
		break;
	/* GET_REQ and PUT_ACK are outbound messages sending our mapping key to
	 * remote node where the RDMA will be started
	 * Special case -EAGAIN logic - this should just queued as if the mapping couldn't
	 * be satisified. The rest of the errors are "hard" errors that require
	 * upper layers to handle themselves.
	 * If kgnilnd_post_rdma returns a resource error, kgnilnd_rdma will put
	 * the tx back on the TX_MAPQ. When this tx is pulled back off the MAPQ,
	 * it's gnm_type will now be GNILND_MSG_PUT_DONE or
	 * GNILND_MSG_GET_DONE_REV.
	 */
	case GNILND_MSG_GET_REQ:
		tx->tx_msg.gnm_u.get.gngm_desc.gnrd_key = tx->tx_map_key;
		tx->tx_msg.gnm_u.get.gngm_cookie = tx->tx_id.txe_cookie;
		tx->tx_msg.gnm_u.get.gngm_desc.gnrd_addr = (__u64)((unsigned long)tx->tx_buffer);
		tx->tx_msg.gnm_u.get.gngm_desc.gnrd_nob = tx->tx_nob;
		tx->tx_state = GNILND_TX_WAITING_COMPLETION | GNILND_TX_WAITING_REPLY;
		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_GET_REQ_AGAIN)) {
			tx->tx_state |= GNILND_TX_FAIL_SMSG;
		}
		/* redirect to FMAQ on failure, no need to infinite loop here in MAPQ */
		rc = kgnilnd_sendmsg(tx, NULL, 0, &tx->tx_conn->gnc_list_lock, GNILND_TX_FMAQ);
		break;
	case GNILND_MSG_PUT_ACK:
		tx->tx_msg.gnm_u.putack.gnpam_desc.gnrd_key = tx->tx_map_key;
		tx->tx_state = GNILND_TX_WAITING_COMPLETION | GNILND_TX_WAITING_REPLY;
		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PUT_ACK_AGAIN)) {
			tx->tx_state |= GNILND_TX_FAIL_SMSG;
		}
		/* redirect to FMAQ on failure, no need to infinite loop here in MAPQ */
		rc = kgnilnd_sendmsg(tx, NULL, 0, &tx->tx_conn->gnc_list_lock, GNILND_TX_FMAQ);
		break;

	/* PUT_REQ and GET_DONE are where we do the actual RDMA */
	case GNILND_MSG_PUT_DONE:
	case GNILND_MSG_PUT_REQ:
		rc = kgnilnd_rdma(tx, GNILND_MSG_PUT_DONE,
			     &tx->tx_putinfo.gnpam_desc,
			     tx->tx_putinfo.gnpam_desc.gnrd_nob,
			     tx->tx_putinfo.gnpam_dst_cookie);
		RETURN(try_map_if_full ? rc : 0);
		break;
	case GNILND_MSG_GET_DONE:
		rc = kgnilnd_rdma(tx, GNILND_MSG_GET_DONE,
			     &tx->tx_getinfo.gngm_desc,
			     tx->tx_lntmsg[0]->msg_len,
			     tx->tx_getinfo.gngm_cookie);
		RETURN(try_map_if_full ? rc : 0);
		break;
	case GNILND_MSG_PUT_REQ_REV:
		tx->tx_msg.gnm_u.get.gngm_desc.gnrd_key = tx->tx_map_key;
		tx->tx_msg.gnm_u.get.gngm_cookie = tx->tx_id.txe_cookie;
		tx->tx_msg.gnm_u.get.gngm_desc.gnrd_addr = (__u64)((unsigned long)tx->tx_buffer);
		tx->tx_msg.gnm_u.get.gngm_desc.gnrd_nob = tx->tx_nob;
		tx->tx_state = GNILND_TX_WAITING_COMPLETION | GNILND_TX_WAITING_REPLY;
		kgnilnd_compute_rdma_cksum(tx, tx->tx_nob);
		tx->tx_msg.gnm_u.get.gngm_payload_cksum = tx->tx_msg.gnm_payload_cksum;

		rc = kgnilnd_sendmsg(tx, NULL, 0, &tx->tx_conn->gnc_list_lock, GNILND_TX_FMAQ);
		break;
	case GNILND_MSG_PUT_DONE_REV:
		rc = kgnilnd_rdma(tx, GNILND_MSG_PUT_DONE_REV,
			     &tx->tx_getinfo.gngm_desc,
			     tx->tx_nob,
			     tx->tx_getinfo.gngm_cookie);
		RETURN(try_map_if_full ? rc : 0);
		break;
	case GNILND_MSG_GET_ACK_REV:
		tx->tx_msg.gnm_u.putack.gnpam_desc.gnrd_key = tx->tx_map_key;
		tx->tx_state = GNILND_TX_WAITING_COMPLETION | GNILND_TX_WAITING_REPLY;
		/* LNET_GETS are a special case for parse */
		kgnilnd_compute_rdma_cksum(tx, tx->tx_msg.gnm_u.putack.gnpam_desc.gnrd_nob);
		tx->tx_msg.gnm_u.putack.gnpam_payload_cksum = tx->tx_msg.gnm_payload_cksum;

		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PUT_ACK_AGAIN))
			tx->tx_state |= GNILND_TX_FAIL_SMSG;

		/* redirect to FMAQ on failure, no need to infinite loop here in MAPQ */
		rc = kgnilnd_sendmsg(tx, NULL, 0, &tx->tx_conn->gnc_list_lock, GNILND_TX_FMAQ);
		break;
	case GNILND_MSG_GET_DONE_REV:
	case GNILND_MSG_GET_REQ_REV:
		rc = kgnilnd_rdma(tx, GNILND_MSG_GET_DONE_REV,
				&tx->tx_putinfo.gnpam_desc,
				tx->tx_putinfo.gnpam_desc.gnrd_nob,
				tx->tx_putinfo.gnpam_dst_cookie);
		RETURN(try_map_if_full ? rc : 0);
		break;
	}

	RETURN(rc);
}

void
kgnilnd_process_fmaq(kgn_conn_t *conn)
{
	int           more_to_do = 0;
	kgn_tx_t     *tx = NULL;
	void         *buffer = NULL;
	unsigned int  nob = 0;
	int           rc;

	/* NB 1. kgnilnd_sendmsg() may fail if I'm out of credits right now.
	 *       However I will be rescheduled by an FMA completion event
	 *       when I eventually get some.
	 * NB 2. Sampling gnc_state here races with setting it elsewhere.
	 *       But it doesn't matter if I try to send a "real" message just
	 *       as I start closing because I'll get scheduled to send the
	 *       close anyway. */

	/* Short circuit if the ep_handle is null we cant send anyway. */
	if (conn->gnc_ephandle == NULL)
		return;

	LASSERTF(!conn->gnc_close_sent, "Conn %p close was sent\n", conn);

	spin_lock(&conn->gnc_list_lock);

	if (list_empty(&conn->gnc_fmaq)) {
		int     keepalive = GNILND_TO2KA(conn->gnc_timeout);

		spin_unlock(&conn->gnc_list_lock);

		if (time_after_eq(jiffies, conn->gnc_last_tx + cfs_time_seconds(keepalive))) {
			CDEBUG(D_NET, "sending NOOP -> %s (%p idle %lu(%d)) "
			       "last %lu/%lu/%lu %lus/%lus/%lus\n",
			       libcfs_nid2str(conn->gnc_peer->gnp_nid), conn,
			       cfs_duration_sec(jiffies - conn->gnc_last_tx),
			       keepalive,
			       conn->gnc_last_noop_want, conn->gnc_last_noop_sent,
			       conn->gnc_last_noop_cq,
			       cfs_duration_sec(jiffies - conn->gnc_last_noop_want),
			       cfs_duration_sec(jiffies - conn->gnc_last_noop_sent),
			       cfs_duration_sec(jiffies - conn->gnc_last_noop_cq));
			atomic_inc(&conn->gnc_sched_noop);
			set_mb(conn->gnc_last_noop_want, jiffies);

			if (CFS_FAIL_CHECK(CFS_FAIL_GNI_NOOP_SEND))
				return;

			tx = kgnilnd_new_tx_msg(GNILND_MSG_NOOP, conn->gnc_peer->gnp_net->gnn_ni->ni_nid);
			if (tx != NULL) {
				int     rc;

				rc = kgnilnd_set_tx_id(tx, conn);
				if (rc != 0) {
					kgnilnd_tx_done(tx, rc);
					return;
				}
			}
		}
	} else {
		tx = list_first_entry(&conn->gnc_fmaq, kgn_tx_t, tx_list);
		/* move from fmaq to allocd, kgnilnd_sendmsg will move to live_fmaq */
		kgnilnd_tx_del_state_locked(tx, NULL, conn, GNILND_TX_ALLOCD);
		more_to_do = !list_empty(&conn->gnc_fmaq);
		spin_unlock(&conn->gnc_list_lock);
	}

	/* if there is no real TX or no NOOP to send, bail */
	if (tx == NULL) {
		return;
	}

	if (!tx->tx_retrans)
		tx->tx_cred_wait = jiffies;

	GNITX_ASSERTF(tx, tx->tx_id.txe_smsg_id != 0,
		      "tx with zero id", NULL);

	CDEBUG(D_NET, "sending regular msg: %p, type %s(0x%02x), cookie "LPX64"\n",
	       tx, kgnilnd_msgtype2str(tx->tx_msg.gnm_type),
	       tx->tx_msg.gnm_type, tx->tx_id.txe_cookie);

	rc = 0;

	switch (tx->tx_msg.gnm_type) {
	default:
		LBUG();

	case GNILND_MSG_NOOP:
	case GNILND_MSG_CLOSE:
	case GNILND_MSG_IMMEDIATE:
		tx->tx_state = GNILND_TX_WAITING_COMPLETION;
		buffer = tx->tx_buffer;
		nob = tx->tx_nob;
		break;

	case GNILND_MSG_GET_DONE:
	case GNILND_MSG_PUT_DONE:
	case GNILND_MSG_PUT_DONE_REV:
	case GNILND_MSG_GET_DONE_REV:
	case GNILND_MSG_PUT_NAK:
	case GNILND_MSG_GET_NAK:
	case GNILND_MSG_GET_NAK_REV:
	case GNILND_MSG_PUT_NAK_REV:
		tx->tx_state = GNILND_TX_WAITING_COMPLETION;
		break;

	case GNILND_MSG_PUT_REQ:
	case GNILND_MSG_GET_REQ_REV:
		tx->tx_msg.gnm_u.putreq.gnprm_cookie = tx->tx_id.txe_cookie;

	case GNILND_MSG_PUT_ACK:
	case GNILND_MSG_PUT_REQ_REV:
	case GNILND_MSG_GET_ACK_REV:
	case GNILND_MSG_GET_REQ:
		/* This is really only to handle the retransmit of SMSG once these
		 * two messages are setup in send_mapped_tx */
		tx->tx_state = GNILND_TX_WAITING_COMPLETION | GNILND_TX_WAITING_REPLY;
		break;
	}

	if (likely(rc == 0)) {
		rc = kgnilnd_sendmsg(tx, buffer, nob, &conn->gnc_list_lock, GNILND_TX_FMAQ);
	}

	if (rc > 0) {
		/* don't explicitly reschedule here - we are short credits and will rely on
		 * kgnilnd_sendmsg to resched the conn if need be */
		more_to_do = 0;
	} else if (rc < 0) {
		/* bail: it wasn't sent and we didn't get EAGAIN indicating we should retrans
		 * almost certainly a software bug, but lets play nice with the other kids */
		kgnilnd_tx_done(tx, rc);
		/* just for fun, kick peer in arse - resetting conn might help to correct
		 * this almost certainly buggy software caused return code */
		kgnilnd_close_conn(conn, rc);
	}

	if (more_to_do) {
		CDEBUG(D_NET, "Rescheduling %p (more to do)\n", conn);
		kgnilnd_schedule_conn(conn);
	}
}

int
kgnilnd_process_rdmaq(kgn_device_t *dev)
{
	int               found_work = 0;
	kgn_tx_t         *tx;

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_DELAY_RDMAQ)) {
		RETURN(found_work);
	}

	if (time_after_eq(jiffies, dev->gnd_rdmaq_deadline)) {
		unsigned long           dead_bump;
		long                    new_ok;

		/* if we think we need to adjust, take lock to serialize and recheck */
		spin_lock(&dev->gnd_rdmaq_lock);
		if (time_after_eq(jiffies, dev->gnd_rdmaq_deadline)) {
			del_singleshot_timer_sync(&dev->gnd_rdmaq_timer);

			dead_bump = cfs_time_seconds(1) / *kgnilnd_tunables.kgn_rdmaq_intervals;

			/* roll the bucket forward */
			dev->gnd_rdmaq_deadline = jiffies + dead_bump;

			if (kgnilnd_data.kgn_rdmaq_override &&
				(*kgnilnd_tunables.kgn_rdmaq_intervals != 0)) {
				new_ok = kgnilnd_data.kgn_rdmaq_override / *kgnilnd_tunables.kgn_rdmaq_intervals;
			}  else {
				new_ok = ~0UL >> 1;
			}

			/* roll current outstanding forward to make sure we carry outstanding
			 * committment forward
			 * new_ok starts out as the whole interval value
			 *  - first subtract bytes_out from last interval, as that would push us over
			 *    strict limits for this interval
			 *  - second, set bytes_ok to new_ok to ensure it doesn't exceed the current auth
			 *
			 * there is a small race here if someone is actively processing mappings and
			 * adding to rdmaq_bytes_out, but it should be small as the mappings are triggered
			 * quite quickly after kgnilnd_auth_rdma_bytes gives us the go-ahead
			 * - if this gives us problems in the future, we could use a read/write lock
			 * to protect the resetting of these values */
			new_ok -= atomic64_read(&dev->gnd_rdmaq_bytes_out);
			atomic64_set(&dev->gnd_rdmaq_bytes_ok, new_ok);

			CDEBUG(D_NET, "resetting rdmaq bytes to %ld, deadline +%lu -> %lu, "
				       "current out %ld\n",
			       atomic64_read(&dev->gnd_rdmaq_bytes_ok), dead_bump, dev->gnd_rdmaq_deadline,
			       atomic64_read(&dev->gnd_rdmaq_bytes_out));
		}
		spin_unlock(&dev->gnd_rdmaq_lock);
	}

	spin_lock(&dev->gnd_rdmaq_lock);
	while (!list_empty(&dev->gnd_rdmaq)) {
		int     rc;

		/* make sure we break out early on quiesce */
		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			/* always break with lock held - we unlock outside loop */
			break;
		}

		tx = list_first_entry(&dev->gnd_rdmaq, kgn_tx_t, tx_list);
		kgnilnd_tx_del_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_ALLOCD);
		found_work++;

		/* sample with lock held, serializing with kgnilnd_complete_closed_conn */
		if (tx->tx_conn->gnc_state != GNILND_CONN_ESTABLISHED) {
			/* if conn is dying, mark tx in tx_ref_table for
			 * kgnilnd_complete_closed_conn to finish up */
			kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_DYING, 1);

			/* tx was moved to DYING, get next */
			continue;
		}
		spin_unlock(&dev->gnd_rdmaq_lock);

		rc = kgnilnd_auth_rdma_bytes(dev, tx);
		spin_lock(&dev->gnd_rdmaq_lock);

		if (rc < 0) {
			/* no ticket! add back to head */
			kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_RDMAQ, 0);
			/* clear found_work so scheduler threads wait for timer */
			found_work = 0;
			break;
		} else {
			/* TX is GO for launch */
			tx->tx_qtime = jiffies;
			kgnilnd_send_mapped_tx(tx, 0);
			found_work++;
		}
	}
	spin_unlock(&dev->gnd_rdmaq_lock);

	RETURN(found_work);
}

static inline void
kgnilnd_swab_rdma_desc(kgn_rdma_desc_t *d)
{
	__swab64s(&d->gnrd_key.qword1);
	__swab64s(&d->gnrd_key.qword2);
	__swab64s(&d->gnrd_addr);
	__swab32s(&d->gnrd_nob);
}

#define kgnilnd_match_reply_either(w, x, y, z) _kgnilnd_match_reply(w, x, y, z)
#define kgnilnd_match_reply(x, y, z) _kgnilnd_match_reply(x, y, GNILND_MSG_NONE, z)

kgn_tx_t *
_kgnilnd_match_reply(kgn_conn_t *conn, int type1, int type2, __u64 cookie)
{
	kgn_tx_ev_id_t    ev_id;
	kgn_tx_t         *tx;

	/* we use the cookie from the original TX, so we can find the match
	 * by parsing that and using the txe_idx */
	ev_id.txe_cookie = cookie;

	tx = conn->gnc_tx_ref_table[ev_id.txe_idx];

	if (tx != NULL) {
		/* check tx to make sure kgni didn't eat it */
		GNITX_ASSERTF(tx, tx->tx_msg.gnm_magic == GNILND_MSG_MAGIC,
			      "came back from kgni with bad magic %x\n", tx->tx_msg.gnm_magic);

		GNITX_ASSERTF(tx, ((tx->tx_id.txe_idx == ev_id.txe_idx) &&
				  (tx->tx_id.txe_cookie = cookie)),
			      "conn 0x%p->%s tx_ref_table hosed: wanted "
			      "txe_cookie "LPX64" txe_idx %d "
			      "found tx %p cookie "LPX64" txe_idx %d\n",
			      conn, libcfs_nid2str(conn->gnc_peer->gnp_nid),
			      cookie, ev_id.txe_idx,
			      tx, tx->tx_id.txe_cookie, tx->tx_id.txe_idx);

		LASSERTF((((tx->tx_msg.gnm_type == type1) || (tx->tx_msg.gnm_type == type2)) &&
			(tx->tx_state & GNILND_TX_WAITING_REPLY)),
			"Unexpected TX type (%x, %x or %x) "
			"or state (%x, expected +%x) "
			"matched reply from %s\n",
			tx->tx_msg.gnm_type, type1, type2,
			tx->tx_state, GNILND_TX_WAITING_REPLY,
			libcfs_nid2str(conn->gnc_peer->gnp_nid));
	} else {
		CWARN("Unmatched reply %02x, or %02x/"LPX64" from %s\n",
		      type1, type2, cookie, libcfs_nid2str(conn->gnc_peer->gnp_nid));
	}
	return tx;
}

static inline void
kgnilnd_complete_tx(kgn_tx_t *tx, int rc)
{
	int             complete = 0;
	kgn_conn_t      *conn = tx->tx_conn;
	__u64 nob = tx->tx_nob;
	__u32 physnop = tx->tx_phys_npages;
	int   id = tx->tx_id.txe_smsg_id;
	int buftype = tx->tx_buftype;
	gni_mem_handle_t hndl;
	hndl.qword1 = tx->tx_map_key.qword1;
	hndl.qword2 = tx->tx_map_key.qword2;

	spin_lock(&conn->gnc_list_lock);

	GNITX_ASSERTF(tx, tx->tx_state & GNILND_TX_WAITING_REPLY,
		"not waiting for reply", NULL);

	tx->tx_rc = rc;
	tx->tx_state &= ~GNILND_TX_WAITING_REPLY;

	if (rc == -EFAULT) {
		CDEBUG(D_NETERROR, "Error %d TX data: TX %p tx_id %x nob %16"LPF64"u physnop %8d buffertype %#8x MemHandle "LPX64"."LPX64"x\n",
			rc, tx, id, nob, physnop, buftype, hndl.qword1, hndl.qword2);

		if(*kgnilnd_tunables.kgn_efault_lbug) {
			GNIDBG_TOMSG(D_NETERROR, &tx->tx_msg,
			"error %d on tx 0x%p->%s id %u/%d state %s age %ds",
			rc, tx, conn ?
			libcfs_nid2str(conn->gnc_peer->gnp_nid) : "<?>",
			tx->tx_id.txe_smsg_id, tx->tx_id.txe_idx,
			kgnilnd_tx_state2str(tx->tx_list_state),
			cfs_duration_sec((unsigned long) jiffies - tx->tx_qtime));
			LBUG();
		}
	}

	if (!(tx->tx_state & GNILND_TX_WAITING_COMPLETION)) {
		kgnilnd_tx_del_state_locked(tx, NULL, conn, GNILND_TX_ALLOCD);
		/* sample under lock as follow on steps require gnc_list_lock
		 * - or call kgnilnd_tx_done which requires no locks held over
		 *   call to lnet_finalize */
		complete = 1;
	}
	spin_unlock(&conn->gnc_list_lock);

	if (complete) {
		kgnilnd_tx_done(tx, tx->tx_rc);
	}
}

static inline void
kgnilnd_finalize_rx_done(kgn_tx_t *tx, kgn_msg_t *msg)
{
	int              rc;
	kgn_conn_t      *conn = tx->tx_conn;

	atomic_inc(&conn->gnc_device->gnd_rdma_nrx);
	atomic64_add(tx->tx_nob, &conn->gnc_device->gnd_rdma_rxbytes);

	/* the gncm_retval is passed in for PUTs */
	rc = kgnilnd_verify_rdma_cksum(tx, msg->gnm_payload_cksum,
				       msg->gnm_u.completion.gncm_retval);

	kgnilnd_complete_tx(tx, rc);
}

void
kgnilnd_check_fma_rx(kgn_conn_t *conn)
{
	__u32         seq;
	kgn_tx_t     *tx;
	kgn_rx_t     *rx;
	kgn_msg_t    *msg;
	void         *prefix;
	gni_return_t  rrc;
	kgn_peer_t   *peer = conn->gnc_peer;
	kgn_net_t    *net;
	int           rc = 0;
	__u16         tmp_cksum = 0, msg_cksum = 0;
	int           repost = 1, saw_complete;
	unsigned long timestamp, newest_last_rx, timeout;
	int           last_seq;
	ENTRY;

	/* Short circuit if the ep_handle is null.
	 * It's likely that its about to be closed as stale.
	 */
	if (conn->gnc_ephandle == NULL)
		RETURN_EXIT;

	timestamp = jiffies;
	kgnilnd_gl_mutex_lock(&conn->gnc_device->gnd_cq_mutex);
	/* delay in jiffies - we are really concerned only with things that
	 * result in a schedule() or really holding this off for long times .
	 * NB - mutex_lock could spin for 2 jiffies before going to sleep to wait */
	conn->gnc_device->gnd_mutex_delay += (long) jiffies - timestamp;

	/* Resample current time as we have no idea how long it took to get the mutex */
	timestamp = jiffies;

	/* We check here when the last time we received an rx, we do this before
	 * we call getnext in case the thread has been blocked for a while. If we
	 * havent received an rx since our timeout value we close the connection
	 * as we should assume the other side has closed the connection. This will
	 * stop us from sending replies to a mailbox that is already in purgatory.
	 */

	timeout = cfs_time_seconds(conn->gnc_timeout);
	newest_last_rx = GNILND_LASTRX(conn);

	/* Error injection to validate that timestamp checking works and closing the conn */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_RECV_TIMEOUT)) {
		timestamp = timestamp + (GNILND_TIMEOUTRX(timeout) * 2);
	}

	if (time_after_eq(timestamp, newest_last_rx + (GNILND_TIMEOUTRX(timeout)))) {
		GNIDBG_CONN(D_NETERROR|D_CONSOLE, conn, "Cant receive from %s after timeout lapse of %lu; TO %lu",
		libcfs_nid2str(conn->gnc_peer->gnp_nid),
		cfs_duration_sec(timestamp - newest_last_rx),
		cfs_duration_sec(GNILND_TIMEOUTRX(timeout)));
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		rc = -ETIME;
		kgnilnd_close_conn(conn, rc);
		RETURN_EXIT;
	}

	rrc = kgnilnd_smsg_getnext(conn->gnc_ephandle, &prefix);

	if (rrc == GNI_RC_NOT_DONE) {
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		CDEBUG(D_INFO, "SMSG RX empty conn 0x%p\n", conn);
		RETURN_EXIT;
	}

	/* Instead of asserting when we get mailbox corruption lets attempt to
	 * close the conn and recover. We can put the conn/mailbox into
	 * purgatory and let purgatory deal with the problem. If we see
	 * this NETTERROR reported on production systems in large amounts
	 * we will need to revisit the state machine to see if we can tighten
	 * it up further to improve data protection.
	 */

	if (rrc == GNI_RC_INVALID_STATE) {
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		GNIDBG_CONN(D_NETERROR | D_CONSOLE, conn, "Mailbox corruption "
			"detected closing conn %p from peer %s\n", conn,
			libcfs_nid2str(conn->gnc_peer->gnp_nid));
		rc = -EIO;
		kgnilnd_close_conn(conn, rc);
		RETURN_EXIT;
	}

	LASSERTF(rrc == GNI_RC_SUCCESS,
		"bad rc %d on conn %p from peer %s\n",
		rrc, conn, libcfs_nid2str(peer->gnp_nid));

	msg = (kgn_msg_t *)prefix;

	rx = kgnilnd_alloc_rx();
	if (rx == NULL) {
		kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		kgnilnd_release_msg(conn);
		GNIDBG_MSG(D_NETERROR, msg, "Dropping SMSG RX from 0x%p->%s, no RX memory",
			   conn, libcfs_nid2str(peer->gnp_nid));
		RETURN_EXIT;
	}

	GNIDBG_MSG(D_INFO, msg, "SMSG RX on %p", conn);

	timestamp = conn->gnc_last_rx;
	seq = last_seq = atomic_read(&conn->gnc_rx_seq);
	atomic_inc(&conn->gnc_rx_seq);

	conn->gnc_last_rx = jiffies;
	/* stash first rx so we can clear out purgatory
	 */
	if (conn->gnc_first_rx == 0)
		conn->gnc_first_rx = jiffies;

	/* needs to linger to protect gnc_rx_seq like we do with gnc_tx_seq */
	kgnilnd_gl_mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
	kgnilnd_peer_alive(conn->gnc_peer);

	rx->grx_msg = msg;
	rx->grx_conn = conn;
	rx->grx_eager = 0;
	rx->grx_received = current_kernel_time();

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_NET_LOOKUP)) {
		rc = -ENONET;
	} else {
		rc = kgnilnd_find_net(msg->gnm_srcnid, &net);
	}

	if (rc < 0) {
		GOTO(out, rc);
	} else {
		kgnilnd_net_decref(net);
	}

	if (*kgnilnd_tunables.kgn_checksum && !msg->gnm_cksum)
		GNIDBG_MSG(D_WARNING, msg, "no msg header checksum when enabled");

	/* XXX Nic: Do we need to swab cksum */
	if (msg->gnm_cksum != 0) {
		msg_cksum = msg->gnm_cksum;
		msg->gnm_cksum = 0;
		tmp_cksum = kgnilnd_cksum(msg, sizeof(kgn_msg_t));

		if (tmp_cksum != msg_cksum) {
			GNIDBG_MSG(D_NETERROR, msg, "Bad hdr checksum (%x expected %x)",
					tmp_cksum, msg_cksum);
			kgnilnd_dump_msg(D_BUFFS, msg);
			rc = -ENOKEY;
			GOTO(out, rc);
		}
	}
	/* restore checksum for future debug messages */
	msg->gnm_cksum = tmp_cksum;

	if (msg->gnm_magic != GNILND_MSG_MAGIC) {
		if (__swab32(msg->gnm_magic) != GNILND_MSG_MAGIC) {
			GNIDBG_MSG(D_NETERROR, msg, "Unexpected magic %08x from %s",
			       msg->gnm_magic, libcfs_nid2str(peer->gnp_nid));
			rc = -EPROTO;
			GOTO(out, rc);
		}

		__swab32s(&msg->gnm_magic);
		__swab16s(&msg->gnm_version);
		__swab16s(&msg->gnm_type);
		__swab64s(&msg->gnm_srcnid);
		__swab64s(&msg->gnm_connstamp);
		__swab32s(&msg->gnm_seq);

		/* NB message type checked below; NOT here... */
		switch (msg->gnm_type) {
		case GNILND_MSG_GET_ACK_REV:
		case GNILND_MSG_PUT_ACK:
			kgnilnd_swab_rdma_desc(&msg->gnm_u.putack.gnpam_desc);
			break;

		case GNILND_MSG_PUT_REQ_REV:
		case GNILND_MSG_GET_REQ:
			kgnilnd_swab_rdma_desc(&msg->gnm_u.get.gngm_desc);
			break;

		default:
			break;
		}
	}

	if (msg->gnm_version != GNILND_MSG_VERSION) {
		GNIDBG_MSG(D_NETERROR, msg, "Unexpected protocol version %d from %s",
		       msg->gnm_version, libcfs_nid2str(peer->gnp_nid));
		rc = -EPROTO;
		GOTO(out, rc);
	}

	if (LNET_NIDADDR(msg->gnm_srcnid) != LNET_NIDADDR(peer->gnp_nid)) {
		GNIDBG_MSG(D_NETERROR, msg, "Unexpected peer %s from %s",
		       libcfs_nid2str(msg->gnm_srcnid),
		       libcfs_nid2str(peer->gnp_nid));
		rc = -EPROTO;
		GOTO(out, rc);
	}

	if (msg->gnm_connstamp != conn->gnc_peer_connstamp) {
		GNIDBG_MSG(D_NETERROR, msg, "Unexpected connstamp "LPX64"("LPX64
		       " expected) from %s",
		       msg->gnm_connstamp, conn->gnc_peer_connstamp,
		       libcfs_nid2str(peer->gnp_nid));
		rc = -EPROTO;
		GOTO(out, rc);
	}

	if (msg->gnm_seq != seq) {
		GNIDBG_MSG(D_NETERROR, msg, "Unexpected sequence number %d(%d expected) from %s",
		       msg->gnm_seq, seq, libcfs_nid2str(peer->gnp_nid));
		rc = -EPROTO;
		GOTO(out, rc);
	}

	atomic_inc(&conn->gnc_device->gnd_short_nrx);

	if (msg->gnm_type == GNILND_MSG_CLOSE) {
		CDEBUG(D_NETTRACE, "%s sent us CLOSE msg\n",
			      libcfs_nid2str(conn->gnc_peer->gnp_nid));
		write_lock(&kgnilnd_data.kgn_peer_conn_lock);
		conn->gnc_close_recvd = GNILND_CLOSE_RX;
		conn->gnc_peer_error = msg->gnm_u.completion.gncm_retval;
		/* double check state with lock held */
		if (conn->gnc_state == GNILND_CONN_ESTABLISHED) {
			/* only error if we are not already closing */
			if (conn->gnc_peer_error == -ETIMEDOUT) {
				unsigned long           now = jiffies;
				CNETERR("peer 0x%p->%s closed connection 0x%p due to timeout. "
				       "Is node down? "
				       "RX %d @ %lus/%lus; TX %d @ %lus/%lus; "
				       "NOOP %lus/%lus/%lus; sched %lus/%lus/%lus ago\n",
				       conn->gnc_peer, libcfs_nid2str(conn->gnc_peer->gnp_nid),
				       conn, last_seq,
				       cfs_duration_sec(now - timestamp),
				       cfs_duration_sec(now - conn->gnc_last_rx_cq),
				       atomic_read(&conn->gnc_tx_seq),
				       cfs_duration_sec(now - conn->gnc_last_tx),
				       cfs_duration_sec(now - conn->gnc_last_tx_cq),
				       cfs_duration_sec(now - conn->gnc_last_noop_want),
				       cfs_duration_sec(now - conn->gnc_last_noop_sent),
				       cfs_duration_sec(now - conn->gnc_last_noop_cq),
				       cfs_duration_sec(now - conn->gnc_last_sched_ask),
				       cfs_duration_sec(now - conn->gnc_last_sched_do),
				       cfs_duration_sec(now - conn->gnc_device->gnd_sched_alive));
			}
			kgnilnd_close_conn_locked(conn, -ECONNRESET);
		}
		write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		GOTO(out, rc);
	}

	if (conn->gnc_close_recvd) {
		GNIDBG_MSG(D_NETERROR, msg, "Unexpected message %s(%d/%d) after CLOSE from %s",
		       kgnilnd_msgtype2str(msg->gnm_type),
		       msg->gnm_type, conn->gnc_close_recvd,
		       libcfs_nid2str(conn->gnc_peer->gnp_nid));
		rc = -EPROTO;
		GOTO(out, rc);
	}

	if (conn->gnc_state != GNILND_CONN_ESTABLISHED) {
		/* XXX Nic: log message received on bad connection state */
		GOTO(out, rc);
	}

	switch (msg->gnm_type) {
	case GNILND_MSG_NOOP:
		/* Nothing to do; just a keepalive */
		break;

	case GNILND_MSG_IMMEDIATE:
		/* only get SMSG payload for IMMEDIATE */
		atomic64_add(msg->gnm_payload_len, &conn->gnc_device->gnd_short_rxbytes);
		rc = lnet_parse(net->gnn_ni, &msg->gnm_u.immediate.gnim_hdr,
				msg->gnm_srcnid, rx, 0);
		repost = rc < 0;
		break;
	case GNILND_MSG_GET_REQ_REV:
	case GNILND_MSG_PUT_REQ:
		rc = lnet_parse(net->gnn_ni, &msg->gnm_u.putreq.gnprm_hdr,
				msg->gnm_srcnid, rx, 1);
		repost = rc < 0;
		break;
	case GNILND_MSG_GET_NAK_REV:
		tx = kgnilnd_match_reply_either(conn, GNILND_MSG_GET_REQ_REV, GNILND_MSG_GET_ACK_REV,
					msg->gnm_u.completion.gncm_cookie);
		if (tx == NULL)
			break;

		kgnilnd_complete_tx(tx, msg->gnm_u.completion.gncm_retval);
		break;
	case GNILND_MSG_PUT_NAK:
		tx = kgnilnd_match_reply_either(conn, GNILND_MSG_PUT_REQ, GNILND_MSG_PUT_ACK,
					msg->gnm_u.completion.gncm_cookie);
		if (tx == NULL)
			break;

		kgnilnd_complete_tx(tx, msg->gnm_u.completion.gncm_retval);
		break;
	case GNILND_MSG_PUT_ACK:
		tx = kgnilnd_match_reply(conn, GNILND_MSG_PUT_REQ,
					msg->gnm_u.putack.gnpam_src_cookie);
		if (tx == NULL)
			break;

		/* store putack data for later: deferred rdma or re-try */
		tx->tx_putinfo = msg->gnm_u.putack;

		saw_complete = 0;
		spin_lock(&tx->tx_conn->gnc_list_lock);

		GNITX_ASSERTF(tx, tx->tx_state & GNILND_TX_WAITING_REPLY,
			"not waiting for reply", NULL);

		tx->tx_state &= ~GNILND_TX_WAITING_REPLY;

		if (likely(!(tx->tx_state & GNILND_TX_WAITING_COMPLETION))) {
			kgnilnd_tx_del_state_locked(tx, NULL, conn, GNILND_TX_ALLOCD);
			/* sample under lock as follow on steps require gnc_list_lock
			 * - or call kgnilnd_tx_done which requires no locks held over
			 *   call to lnet_finalize */
			saw_complete = 1;
		} else {
			/* cannot launch rdma if still waiting for fma-msg completion */
			CDEBUG(D_NET, "tx 0x%p type 0x%02x will need to "
				       "wait for SMSG completion\n", tx, tx->tx_msg.gnm_type);
			tx->tx_state |= GNILND_TX_PENDING_RDMA;
		}
		spin_unlock(&tx->tx_conn->gnc_list_lock);

		if (saw_complete) {
			rc = kgnilnd_send_mapped_tx(tx, 0);
			if (rc < 0)
				kgnilnd_tx_done(tx, rc);
		}
		break;
	case GNILND_MSG_GET_ACK_REV:
		tx = kgnilnd_match_reply(conn, GNILND_MSG_GET_REQ_REV,
					msg->gnm_u.putack.gnpam_src_cookie);
		if (tx == NULL)
			break;

		/* store putack data for later: deferred rdma or re-try */
		tx->tx_putinfo = msg->gnm_u.putack;
		saw_complete = 0;
		spin_lock(&tx->tx_conn->gnc_list_lock);

		GNITX_ASSERTF(tx, tx->tx_state & GNILND_TX_WAITING_REPLY,
			"not waiting for reply", NULL);

		tx->tx_state &= ~GNILND_TX_WAITING_REPLY;

		if (likely(!(tx->tx_state & GNILND_TX_WAITING_COMPLETION))) {
			kgnilnd_tx_del_state_locked(tx, NULL, conn, GNILND_TX_ALLOCD);
			/* sample under lock as follow on steps require gnc_list_lock
			 * - or call kgnilnd_tx_done which requires no locks held over
			 *   call to lnet_finalize */
			saw_complete = 1;
		} else {
			/* cannot launch rdma if still waiting for fma-msg completion */
			CDEBUG(D_NET, "tx 0x%p type 0x%02x will need to "
					"wait for SMSG completion\n", tx, tx->tx_msg.gnm_type);
			tx->tx_state |= GNILND_TX_PENDING_RDMA;
		}
		spin_unlock(&tx->tx_conn->gnc_list_lock);

		if (saw_complete) {
			rc = kgnilnd_send_mapped_tx(tx, 0);
			if (rc < 0)
				kgnilnd_tx_done(tx, rc);
		}
		break;
	case GNILND_MSG_PUT_DONE:
		tx = kgnilnd_match_reply(conn, GNILND_MSG_PUT_ACK,
					msg->gnm_u.completion.gncm_cookie);
		if (tx == NULL)
			break;

		GNITX_ASSERTF(tx, tx->tx_buftype == GNILND_BUF_PHYS_MAPPED ||
			       tx->tx_buftype == GNILND_BUF_VIRT_MAPPED,
			       "bad tx buftype %d", tx->tx_buftype);

		kgnilnd_finalize_rx_done(tx, msg);
		break;
	case GNILND_MSG_PUT_REQ_REV:
	case GNILND_MSG_GET_REQ:
		rc = lnet_parse(net->gnn_ni, &msg->gnm_u.get.gngm_hdr,
				msg->gnm_srcnid, rx, 1);
		repost = rc < 0;
		break;

	case GNILND_MSG_GET_NAK:
		tx = kgnilnd_match_reply(conn, GNILND_MSG_GET_REQ,
					msg->gnm_u.completion.gncm_cookie);
		if (tx == NULL)
			break;

		GNITX_ASSERTF(tx, tx->tx_buftype == GNILND_BUF_PHYS_MAPPED ||
			       tx->tx_buftype == GNILND_BUF_VIRT_MAPPED,
			       "bad tx buftype %d", tx->tx_buftype);

		kgnilnd_complete_tx(tx, msg->gnm_u.completion.gncm_retval);
		break;

	case GNILND_MSG_GET_DONE:
		tx = kgnilnd_match_reply(conn, GNILND_MSG_GET_REQ,
					msg->gnm_u.completion.gncm_cookie);
		if (tx == NULL)
			break;

		GNITX_ASSERTF(tx, tx->tx_buftype == GNILND_BUF_PHYS_MAPPED ||
			       tx->tx_buftype == GNILND_BUF_VIRT_MAPPED,
			       "bad tx buftype %d", tx->tx_buftype);

		lnet_set_reply_msg_len(net->gnn_ni, tx->tx_lntmsg[1],
				       msg->gnm_u.completion.gncm_retval);

		kgnilnd_finalize_rx_done(tx, msg);
		break;
	case GNILND_MSG_GET_DONE_REV:
		tx = kgnilnd_match_reply(conn, GNILND_MSG_GET_ACK_REV,
					msg->gnm_u.completion.gncm_cookie);
		if (tx == NULL)
			break;

		GNITX_ASSERTF(tx, tx->tx_buftype == GNILND_BUF_PHYS_MAPPED ||
				tx->tx_buftype == GNILND_BUF_VIRT_MAPPED,
				"bad tx buftype %d", tx->tx_buftype);

		kgnilnd_finalize_rx_done(tx, msg);
		break;

	case GNILND_MSG_PUT_DONE_REV:
		tx = kgnilnd_match_reply(conn, GNILND_MSG_PUT_REQ_REV,
					msg->gnm_u.completion.gncm_cookie);

		if (tx == NULL)
			break;

		GNITX_ASSERTF(tx, tx->tx_buftype == GNILND_BUF_PHYS_MAPPED ||
			       tx->tx_buftype == GNILND_BUF_VIRT_MAPPED,
			       "bad tx buftype %d", tx->tx_buftype);

		kgnilnd_finalize_rx_done(tx, msg);
		break;
	case GNILND_MSG_PUT_NAK_REV:
		tx = kgnilnd_match_reply(conn, GNILND_MSG_PUT_REQ_REV,
					msg->gnm_u.completion.gncm_cookie);

		if (tx == NULL)
			break;

		GNITX_ASSERTF(tx, tx->tx_buftype == GNILND_BUF_PHYS_MAPPED ||
			       tx->tx_buftype == GNILND_BUF_VIRT_MAPPED,
				"bad tx buftype %d", tx->tx_buftype);

		kgnilnd_complete_tx(tx, msg->gnm_u.completion.gncm_retval);
		break;
	}

 out:
	if (rc < 0)                             /* protocol/comms error */
		kgnilnd_close_conn(conn, rc);

	if (repost && rx != NULL) {
		kgnilnd_consume_rx(rx);
	}

	/* we got an event so assume more there and call for reschedule */
	if (rc >= 0)
		kgnilnd_schedule_conn(conn);
	EXIT;
}

/* Do the failure injections that we need to affect conn processing in the following function.
 * When writing tests that use this function make sure to use a fail_loc with a fail mask.
 * If you dont you can cause the scheduler threads to spin on the conn without it leaving
 * process_conns.
 *
 * intent is used to signal the calling function whether or not the conn needs to be rescheduled.
 */

static inline int
kgnilnd_check_conn_fail_loc(kgn_device_t *dev, kgn_conn_t *conn, int *intent)
{
	int     rc = 0;

	/* short circuit out when not set */
	if (likely(!cfs_fail_loc)) {
		RETURN(rc);
	}

	/* failure injection to test for stack reset clean ups */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_DROP_CLOSING)) {
		/* we can't rely on busy loops being nice enough to get the
		 *  stack reset triggered - it'd just spin on this conn */
		CFS_RACE(CFS_FAIL_GNI_DROP_CLOSING);
		rc = 1;
		*intent = 1;
		GOTO(did_fail_loc, rc);
	}

	if (conn->gnc_state == GNILND_CONN_DESTROY_EP) {
		/* DESTROY_EP set in kgnilnd_conn_decref on gnc_refcount = 1 */

		if (CFS_FAIL_CHECK(CFS_FAIL_GNI_DROP_DESTROY_EP)) {
			CFS_RACE(CFS_FAIL_GNI_DROP_DESTROY_EP);
			rc = 1;
			*intent = 1;
			GOTO(did_fail_loc, rc);
		}
	}

	/* CFS_FAIL_GNI_FINISH_PURG2 is used to stop a connection from fully closing. This scheduler
	 * will spin on the CFS_FAIL_TIMEOUT until the fail_loc is cleared at which time the connection
	 * will be closed by kgnilnd_complete_closed_conn.
	 */
	if ((conn->gnc_state == GNILND_CONN_CLOSED) && CFS_FAIL_CHECK(CFS_FAIL_GNI_FINISH_PURG2)) {
		while (CFS_FAIL_TIMEOUT(CFS_FAIL_GNI_FINISH_PURG2, 1)) {};
		rc = 1;
		*intent = 1;
		GOTO(did_fail_loc, rc);
	}

	/* this one is a bit gross - we can't hold the mutex from process_conns
	 * across a CFS_RACE here - it'd block the conn threads from doing an ep_bind
	 * and moving onto finish_connect
	 * so, we'll just set the rc - kgnilnd_process_conns will clear
	 * found_work on a fail_loc, getting the scheduler thread to call schedule()
	 * and effectively getting this thread to sleep */
	if ((conn->gnc_state == GNILND_CONN_CLOSED) && CFS_FAIL_CHECK(CFS_FAIL_GNI_FINISH_PURG)) {
		rc = 1;
		*intent = 1;
		GOTO(did_fail_loc, rc);
	}

did_fail_loc:
	RETURN(rc);
}

static inline void
kgnilnd_send_conn_close(kgn_conn_t *conn)
{
	kgn_tx_t        *tx;

	/* we are closing the conn - we will try to send the CLOSE msg
	 * but will not wait for anything else to flush */

	/* send the close if not already done so or received one */
	if (!conn->gnc_close_sent && !conn->gnc_close_recvd) {
		/* set close_sent regardless of the success of the
		 * CLOSE message. We are going to try once and then
		 * kick him out of the sandbox */
		conn->gnc_close_sent = 1;
		mb();

		/* EP might be null already if remote side initiated a new connection.
		 * kgnilnd_finish_connect destroys existing ep_handles before wiring up the new connection,
		 * so this check is here to make sure we dont attempt to send with a null ep_handle.
		 */
		if (conn->gnc_ephandle != NULL) {
			int rc = 0;

			tx = kgnilnd_new_tx_msg(GNILND_MSG_CLOSE, conn->gnc_peer->gnp_net->gnn_ni->ni_nid);
			if (tx != NULL) {
				tx->tx_msg.gnm_u.completion.gncm_retval = conn->gnc_error;
				tx->tx_state = GNILND_TX_WAITING_COMPLETION;
				tx->tx_qtime = jiffies;

				if (tx->tx_id.txe_idx == 0) {
					rc = kgnilnd_set_tx_id(tx, conn);
					if (rc != 0) {
						kgnilnd_tx_done(tx, rc);
					}
				}

				CDEBUG(D_NETTRACE, "sending close with errno %d\n",
						conn->gnc_error);

				if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CLOSE_SEND)) {
					kgnilnd_tx_done(tx, -EAGAIN);
				} else if (!rc) {
					rc = kgnilnd_sendmsg(tx, NULL, 0, NULL, GNILND_TX_FMAQ);
					if (rc) {
						/* It wasnt sent and we dont care. */
						kgnilnd_tx_done(tx, rc);
					}
				}

			}
		}
	}

	/* When changing gnc_state we need to take the kgn_peer_conn_lock */
	write_lock(&kgnilnd_data.kgn_peer_conn_lock);
	conn->gnc_state = GNILND_CONN_CLOSED;
	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
	/* mark this conn as CLOSED now that we processed it
	 * do after TX, so we can use CLOSING in asserts */

	mb();

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_RX_CLOSE_CLOSED)) {
		/* simulate a RX CLOSE after the timeout but before
		 * the scheduler thread gets it */
		conn->gnc_close_recvd = GNILND_CLOSE_INJECT2;
		conn->gnc_peer_error = -ETIMEDOUT;
	}
	/* schedule to allow potential CLOSE and get the complete phase run */
	kgnilnd_schedule_conn(conn);
}

int
kgnilnd_process_mapped_tx(kgn_device_t *dev)
{
	int		found_work = 0;
	int		rc = 0;
	kgn_tx_t	*tx;
	int              fast_remaps = GNILND_FAST_MAPPING_TRY;
	int		log_retrans, log_retrans_level;
	static int	last_map_version;
	ENTRY;

	spin_lock(&dev->gnd_lock);
	if (list_empty(&dev->gnd_map_tx)) {
		/* if the list is empty make sure we dont have a timer running */
		del_singleshot_timer_sync(&dev->gnd_map_timer);
		spin_unlock(&dev->gnd_lock);
		RETURN(0);
	}

	dev->gnd_sched_alive = jiffies;

	/* we'll retry as fast as possible up to 25% of the limit, then we start
	 * backing off until our map version changes - indicating we unmapped
	 * something */
	tx = list_first_entry(&dev->gnd_map_tx, kgn_tx_t, tx_list);
	if (likely(dev->gnd_map_attempt == 0) ||
		time_after_eq(jiffies, dev->gnd_next_map) ||
		last_map_version != dev->gnd_map_version) {

		/* if this is our first attempt at mapping set last mapped to current
		 * jiffies so we can timeout our attempt correctly.
		 */
		if (dev->gnd_map_attempt == 0)
			dev->gnd_last_map = jiffies;
	} else {
		GNIDBG_TX(D_NET, tx, "waiting for mapping event event to retry", NULL);
		spin_unlock(&dev->gnd_lock);
		RETURN(0);
	}

	/* delete the previous timer if it exists */
	del_singleshot_timer_sync(&dev->gnd_map_timer);
	/* stash the last map version to let us know when a good one was seen */
	last_map_version = dev->gnd_map_version;

	/* we need to to take the lock and continually refresh the head of the list as
	 * kgnilnd_complete_closed_conn might be nuking stuff and we are cycling the lock
	 * allowing them to squeeze in */

	while (!list_empty(&dev->gnd_map_tx)) {
		/* make sure we break out early on quiesce */
		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			/* always break with lock held - we unlock outside loop */
			break;
		}

		tx = list_first_entry(&dev->gnd_map_tx, kgn_tx_t, tx_list);

		kgnilnd_tx_del_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_ALLOCD);
		found_work++;

		/* sample with lock held, serializing with kgnilnd_complete_closed_conn */
		if (tx->tx_conn->gnc_state != GNILND_CONN_ESTABLISHED) {
			/* if conn is dying, mark tx in tx_ref_table for
			 * kgnilnd_complete_closed_conn to finish up */
			kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_DYING, 1);
			found_work++;

			/* tx was moved to DYING, get next */
			continue;
		}

		spin_unlock(&dev->gnd_lock);
		rc = kgnilnd_send_mapped_tx(tx, 1);

		/* We made it! skip error handling.. */
		if (rc >= 0) {
			/* OK to continue on +ve errors as it won't get seen until
			 * this function is called again - we operate on a copy of the original
			 * list and not the live list */
			spin_lock(&dev->gnd_lock);
			/* reset map attempts back to zero we successfully
			 * mapped so we can reset our timers */
			dev->gnd_map_attempt = 0;
			continue;
		} else if (rc == -EAGAIN) {
			spin_lock(&dev->gnd_lock);
			mod_timer(&dev->gnd_map_timer, dev->gnd_next_map);
			spin_unlock(&dev->gnd_lock);
			GOTO(get_out_mapped, rc);
		} else if (rc != -ENOMEM) {
			/* carp, failure we can't handle */
			kgnilnd_tx_done(tx, rc);
			spin_lock(&dev->gnd_lock);
			/* reset map attempts back to zero we dont know what happened but it
			 * wasnt a failed mapping
			 */
			dev->gnd_map_attempt = 0;
			continue;
		}

		/* time to handle the retry cases..  lock so we dont have 2 threads
		 * mucking with gnd_map_attempt, or gnd_next_map at the same time.
		 */
		spin_lock(&dev->gnd_lock);
		dev->gnd_map_attempt++;
		if (dev->gnd_map_attempt < fast_remaps) {
			/* do nothing we just want it to go as fast as possible.
			 * just set gnd_next_map to current jiffies so it will process
			 * as fast as possible.
			 */
			dev->gnd_next_map = jiffies;
		} else {
			/* Retry based on GNILND_MAP_RETRY_RATE */
			dev->gnd_next_map = jiffies + GNILND_MAP_RETRY_RATE;
		}

		/* only log occasionally once we've retried fast_remaps */
		log_retrans = (dev->gnd_map_attempt >= fast_remaps) &&
			      ((dev->gnd_map_attempt % fast_remaps) == 0);
		log_retrans_level = log_retrans ? D_NETERROR : D_NET;

		/* make sure we are not off in the weeds with this tx */
		if (time_after(jiffies, dev->gnd_last_map + GNILND_MAP_TIMEOUT)) {
		       GNIDBG_TX(D_NETERROR, tx,
			       "giving up on TX, too many retries", NULL);
		       spin_unlock(&dev->gnd_lock);
		       if (tx->tx_msg.gnm_type == GNILND_MSG_PUT_REQ ||
			   tx->tx_msg.gnm_type == GNILND_MSG_GET_REQ_REV) {
			       kgnilnd_nak_rdma(tx->tx_conn, tx->tx_msg.gnm_type,
						-ENOMEM,
						tx->tx_putinfo.gnpam_dst_cookie,
						tx->tx_msg.gnm_srcnid);
			} else {
				kgnilnd_nak_rdma(tx->tx_conn, tx->tx_msg.gnm_type,
						-ENOMEM,
						tx->tx_getinfo.gngm_cookie,
						tx->tx_msg.gnm_srcnid);
			}
		       kgnilnd_tx_done(tx, -ENOMEM);
		       GOTO(get_out_mapped, rc);
		} else {
		       GNIDBG_TX(log_retrans_level, tx,
				"transient map failure #%d %d pages/%d bytes phys %u@%u "
				"virt %u@"LPU64" "
				"nq_map %d mdd# %d/%d GART %ld",
				dev->gnd_map_attempt, tx->tx_phys_npages, tx->tx_nob,
				dev->gnd_map_nphys, dev->gnd_map_physnop * PAGE_SIZE,
				dev->gnd_map_nvirt, dev->gnd_map_virtnob,
				atomic_read(&dev->gnd_nq_map),
				atomic_read(&dev->gnd_n_mdd), atomic_read(&dev->gnd_n_mdd_held),
				atomic64_read(&dev->gnd_nbytes_map));
		}

		/* we need to stop processing the rest of the list, so add it back in */
		/* set timer to wake device when we need to schedule this tx */
		mod_timer(&dev->gnd_map_timer, dev->gnd_next_map);
		kgnilnd_tx_add_state_locked(tx, NULL, tx->tx_conn, GNILND_TX_MAPQ, 0);
		spin_unlock(&dev->gnd_lock);
		GOTO(get_out_mapped, rc);
	}
	spin_unlock(&dev->gnd_lock);
get_out_mapped:
	RETURN(found_work);
}

int
kgnilnd_process_conns(kgn_device_t *dev, unsigned long deadline)
{
	int              found_work = 0;
	int              conn_sched;
	int              intent = 0;
	int		 error_inject = 0;
	int		 rc = 0;
	kgn_conn_t      *conn;

	spin_lock(&dev->gnd_lock);
	while (!list_empty(&dev->gnd_ready_conns) && time_before(jiffies, deadline)) {
		dev->gnd_sched_alive = jiffies;
		error_inject = 0;
		rc = 0;

		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			/* break with lock held */
			break;
		}

		conn = list_first_entry(&dev->gnd_ready_conns, kgn_conn_t, gnc_schedlist);
		list_del_init(&conn->gnc_schedlist);
		spin_unlock(&dev->gnd_lock);

		conn_sched = xchg(&conn->gnc_scheduled, GNILND_CONN_PROCESS);

		LASSERTF(conn_sched != GNILND_CONN_IDLE &&
			 conn_sched != GNILND_CONN_PROCESS,
			 "conn %p on ready list but in bad state: %d\n",
			 conn, conn_sched);

		CDEBUG(D_INFO, "conn %p@%s for processing\n",
			conn, kgnilnd_conn_state2str(conn));

		found_work++;
		set_mb(conn->gnc_last_sched_do, jiffies);

		if (kgnilnd_check_conn_fail_loc(dev, conn, &intent)) {

			/* based on intent see if we should run again. */
			rc = kgnilnd_schedule_process_conn(conn, intent);
			error_inject = 1;
			/* drop ref from gnd_ready_conns */
			if (atomic_read(&conn->gnc_refcount) == 1 && rc != 1) {
				down_write(&dev->gnd_conn_sem);
				kgnilnd_conn_decref(conn);
				up_write(&dev->gnd_conn_sem);
			} else if (rc != 1) {
			kgnilnd_conn_decref(conn);
			}
			/* clear this so that scheduler thread doesn't spin */
			found_work = 0;
			/* break with lock held... */
			spin_lock(&dev->gnd_lock);
			break;
		}

		if (unlikely(conn->gnc_state == GNILND_CONN_CLOSED)) {
			down_write(&dev->gnd_conn_sem);

			/* CONN_CLOSED set in procces_fmaq when CLOSE is sent */
			if (unlikely(atomic_read(&conn->gnc_tx_in_use))) {
				/* If there are tx's currently in use in another
				 * thread we dont want to complete the close
				 * yet. Cycle this conn back through
				 * the scheduler. */
				kgnilnd_schedule_conn(conn);
			} else {
				kgnilnd_complete_closed_conn(conn);
			}
			up_write(&dev->gnd_conn_sem);
		} else if (unlikely(conn->gnc_state == GNILND_CONN_DESTROY_EP)) {
			/* DESTROY_EP set in kgnilnd_conn_decref on gnc_refcount = 1 */
			/* serialize SMSG CQs with ep_bind and smsg_release */
			down_write(&dev->gnd_conn_sem);
			kgnilnd_destroy_conn_ep(conn);
			up_write(&dev->gnd_conn_sem);
		} else if (unlikely(conn->gnc_state == GNILND_CONN_CLOSING)) {
		       /* if we need to do some CLOSE sending, etc done here do it */
			down_write(&dev->gnd_conn_sem);
			kgnilnd_send_conn_close(conn);
			kgnilnd_check_fma_rx(conn);
			up_write(&dev->gnd_conn_sem);
		} else if (atomic_read(&conn->gnc_peer->gnp_dirty_eps) == 0) {
			/* start moving traffic if the old conns are cleared out */
			down_read(&dev->gnd_conn_sem);
			kgnilnd_check_fma_rx(conn);
			kgnilnd_process_fmaq(conn);
			up_read(&dev->gnd_conn_sem);
		}

		rc = kgnilnd_schedule_process_conn(conn, 0);

		/* drop ref from gnd_ready_conns */
		if (atomic_read(&conn->gnc_refcount) == 1 && rc != 1) {
			down_write(&dev->gnd_conn_sem);
			kgnilnd_conn_decref(conn);
			up_write(&dev->gnd_conn_sem);
		} else if (rc != 1) {
		kgnilnd_conn_decref(conn);
		}

		/* check list again with lock held */
		spin_lock(&dev->gnd_lock);
	}

	/* If we are short circuiting due to timing we want to be scheduled
	 * as soon as possible.
	 */
	if (!list_empty(&dev->gnd_ready_conns) && !error_inject)
		found_work++;

	spin_unlock(&dev->gnd_lock);

	RETURN(found_work);
}

int
kgnilnd_scheduler(void *arg)
{
	int               threadno = (long)arg;
	kgn_device_t		*dev;
	int			busy_loops = 0;
	unsigned long	  deadline = 0;
	DEFINE_WAIT(wait);

	dev = &kgnilnd_data.kgn_devices[(threadno + 1) % kgnilnd_data.kgn_ndevs];

	cfs_block_allsigs();

	/* all gnilnd threads need to run fairly urgently */
	set_user_nice(current, *kgnilnd_tunables.kgn_sched_nice);
	deadline = jiffies + cfs_time_seconds(*kgnilnd_tunables.kgn_sched_timeout);
	while (!kgnilnd_data.kgn_shutdown) {
		int     found_work = 0;
		/* Safe: kgn_shutdown only set when quiescent */

		/* to quiesce or to not quiesce, that is the question */

		if (unlikely(kgnilnd_data.kgn_quiesce_trigger)) {
			KGNILND_SPIN_QUIESCE;
		}

		/* tracking for when thread goes AWOL */
		dev->gnd_sched_alive = jiffies;

		CFS_FAIL_TIMEOUT(CFS_FAIL_GNI_SCHED_DEADLINE,
			(*kgnilnd_tunables.kgn_sched_timeout + 1));
		/* let folks know we are up and kicking
		 * - they can use this for latency savings, etc
		 * - only change if IRQ, if IDLE leave alone as that
		 *   schedule_device calls to put us back to IRQ */
		(void)cmpxchg(&dev->gnd_ready, GNILND_DEV_IRQ, GNILND_DEV_LOOP);

		down_read(&dev->gnd_conn_sem);
		/* always check these - they are super low cost  */
		found_work += kgnilnd_check_fma_send_cq(dev);
		found_work += kgnilnd_check_fma_rcv_cq(dev);

		/* rdma CQ doesn't care about eps */
		found_work += kgnilnd_check_rdma_cq(dev);

		/* move some RDMA ? */
		found_work += kgnilnd_process_rdmaq(dev);

		/* map some pending RDMA requests ? */
		found_work += kgnilnd_process_mapped_tx(dev);

		/* the EP for a conn is not destroyed until all the references
		 * to it are gone, so these checks should be safe
		 * even if run in parallel with the CQ checking functions
		 * _AND_ a thread that processes the CLOSED->DONE
		 * transistion
		 * ...should.... */

		up_read(&dev->gnd_conn_sem);

		/* process all conns ready now */
		found_work += kgnilnd_process_conns(dev, deadline);

		/* do an eager check to avoid the IRQ disabling in
		 * prepare_to_wait and friends */

		if (found_work &&
		   (busy_loops++ < *kgnilnd_tunables.kgn_loops) &&
		   time_before(jiffies, deadline)) {
			found_work = 0;
			if ((busy_loops % 10) == 0) {
				/* tickle heartbeat and watchdog to ensure our
				 * piggishness doesn't turn into heartbeat failure */
				touch_nmi_watchdog();
				kgnilnd_hw_hb();
			}
			continue;
		}

		/* if we got here, found_work was zero or busy_loops means we
		 * need to take a break. We'll clear gnd_ready but we'll check
		 * one last time if there is an IRQ that needs processing */

		prepare_to_wait(&dev->gnd_waitq, &wait, TASK_INTERRUPTIBLE);

		/* the first time this will go LOOP -> IDLE and let us do one final check
		 * during which we might get an IRQ, then IDLE->IDLE and schedule()
		 * - this might allow other threads to block us for a bit if they
		 *   try to get the mutex, but that is good as we'd need to wake
		 *   up soon to handle the CQ or other processing anyways */

		found_work += xchg(&dev->gnd_ready, GNILND_DEV_IDLE);

		if ((busy_loops >= *kgnilnd_tunables.kgn_loops) ||
		   time_after_eq(jiffies, deadline)) {
			CDEBUG(D_INFO,
			       "yeilding: found_work %d busy_loops %d\n",
			       found_work, busy_loops);
			busy_loops = 0;
			/* use yield if we are bailing due to busy_loops
			 * - this will ensure we wake up soonish. This closes
			 * a race with kgnilnd_device_callback - where it'd
			 * not call wake_up() because gnd_ready == 1, but then
			 * we come down and schedule() because of busy_loops.
			 * We'd not be woken up until something poked our waitq
			 * again. yield() ensures we wake up without another
			 * waitq poke in that case */
			atomic_inc(&dev->gnd_n_yield);
			kgnilnd_data.kgn_last_condresched = jiffies;
			yield();
			CDEBUG(D_INFO, "awake after yeild\n");
			deadline = jiffies + cfs_time_seconds(*kgnilnd_tunables.kgn_sched_timeout);
		} else if (found_work == GNILND_DEV_IDLE) {
			/* busy_loops is low and there is nothing to do,
			 * go to sleep and wait for a waitq poke */
			CDEBUG(D_INFO,
			       "scheduling: found_work %d busy_loops %d\n",
			       found_work, busy_loops);
			atomic_inc(&dev->gnd_n_schedule);
			kgnilnd_data.kgn_last_scheduled = jiffies;
			schedule();
			CDEBUG(D_INFO, "awake after schedule\n");
			deadline = jiffies + cfs_time_seconds(*kgnilnd_tunables.kgn_sched_timeout);
		}
		finish_wait(&dev->gnd_waitq, &wait);
	}

	kgnilnd_thread_fini();
	return 0;
}
