/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/ralnd/ralnd_cb.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include <asm/page.h>
#include "ralnd.h"

void
kranal_device_callback(RAP_INT32 devid, RAP_PVOID arg)
{
        kra_device_t *dev;
        int           i;
        unsigned long flags;

        CDEBUG(D_NET, "callback for device %d\n", devid);

        for (i = 0; i < kranal_data.kra_ndevs; i++) {

                dev = &kranal_data.kra_devices[i];
                if (dev->rad_id != devid)
                        continue;

		spin_lock_irqsave(&dev->rad_lock, flags);

		if (!dev->rad_ready) {
			dev->rad_ready = 1;
			wake_up(&dev->rad_waitq);
		}

		spin_unlock_irqrestore(&dev->rad_lock, flags);
                return;
        }

        CWARN("callback for unknown device %d\n", devid);
}

void
kranal_schedule_conn(kra_conn_t *conn)
{
        kra_device_t    *dev = conn->rac_device;
        unsigned long    flags;

	spin_lock_irqsave(&dev->rad_lock, flags);

	if (!conn->rac_scheduled) {
		kranal_conn_addref(conn);       /* +1 ref for scheduler */
		conn->rac_scheduled = 1;
		cfs_list_add_tail(&conn->rac_schedlist, &dev->rad_ready_conns);
		wake_up(&dev->rad_waitq);
	}

	spin_unlock_irqrestore(&dev->rad_lock, flags);
}

kra_tx_t *
kranal_get_idle_tx (void)
{
        unsigned long  flags;
        kra_tx_t      *tx;

	spin_lock_irqsave(&kranal_data.kra_tx_lock, flags);

        if (cfs_list_empty(&kranal_data.kra_idle_txs)) {
		spin_unlock_irqrestore(&kranal_data.kra_tx_lock, flags);
                return NULL;
        }

        tx = cfs_list_entry(kranal_data.kra_idle_txs.next, kra_tx_t, tx_list);
        cfs_list_del(&tx->tx_list);

        /* Allocate a new completion cookie.  It might not be needed, but we've
         * got a lock right now... */
        tx->tx_cookie = kranal_data.kra_next_tx_cookie++;

	spin_unlock_irqrestore(&kranal_data.kra_tx_lock, flags);

        LASSERT (tx->tx_buftype == RANAL_BUF_NONE);
        LASSERT (tx->tx_msg.ram_type == RANAL_MSG_NONE);
        LASSERT (tx->tx_conn == NULL);
        LASSERT (tx->tx_lntmsg[0] == NULL);
        LASSERT (tx->tx_lntmsg[1] == NULL);

        return tx;
}

void
kranal_init_msg(kra_msg_t *msg, int type)
{
        msg->ram_magic = RANAL_MSG_MAGIC;
        msg->ram_version = RANAL_MSG_VERSION;
        msg->ram_type = type;
        msg->ram_srcnid = kranal_data.kra_ni->ni_nid;
        /* ram_connstamp gets set when FMA is sent */
}

kra_tx_t *
kranal_new_tx_msg (int type)
{
        kra_tx_t *tx = kranal_get_idle_tx();

        if (tx != NULL)
                kranal_init_msg(&tx->tx_msg, type);

        return tx;
}

int
kranal_setup_immediate_buffer (kra_tx_t *tx, 
                               unsigned int niov, struct iovec *iov,
                               int offset, int nob)

{
        /* For now this is almost identical to kranal_setup_virt_buffer, but we
         * could "flatten" the payload into a single contiguous buffer ready
         * for sending direct over an FMA if we ever needed to. */

        LASSERT (tx->tx_buftype == RANAL_BUF_NONE);
        LASSERT (nob >= 0);

        if (nob == 0) {
                tx->tx_buffer = NULL;
        } else {
                LASSERT (niov > 0);

                while (offset >= iov->iov_len) {
                        offset -= iov->iov_len;
                        niov--;
                        iov++;
                        LASSERT (niov > 0);
                }

                if (nob > iov->iov_len - offset) {
                        CERROR("Can't handle multiple vaddr fragments\n");
                        return -EMSGSIZE;
                }

                tx->tx_buffer = (void *)(((unsigned long)iov->iov_base) + offset);
        }

        tx->tx_buftype = RANAL_BUF_IMMEDIATE;
        tx->tx_nob = nob;
        return 0;
}

int
kranal_setup_virt_buffer (kra_tx_t *tx, 
                          unsigned int niov, struct iovec *iov,
                          int offset, int nob)

{
        LASSERT (nob > 0);
        LASSERT (niov > 0);
        LASSERT (tx->tx_buftype == RANAL_BUF_NONE);

        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                niov--;
                iov++;
                LASSERT (niov > 0);
        }

        if (nob > iov->iov_len - offset) {
                CERROR("Can't handle multiple vaddr fragments\n");
                return -EMSGSIZE;
        }

        tx->tx_buftype = RANAL_BUF_VIRT_UNMAPPED;
        tx->tx_nob = nob;
        tx->tx_buffer = (void *)(((unsigned long)iov->iov_base) + offset);
        return 0;
}

int
kranal_setup_phys_buffer (kra_tx_t *tx, int nkiov, lnet_kiov_t *kiov,
                          int offset, int nob)
{
        RAP_PHYS_REGION *phys = tx->tx_phys;
        int              resid;

        CDEBUG(D_NET, "niov %d offset %d nob %d\n", nkiov, offset, nob);

        LASSERT (nob > 0);
        LASSERT (nkiov > 0);
        LASSERT (tx->tx_buftype == RANAL_BUF_NONE);

        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                nkiov--;
                kiov++;
                LASSERT (nkiov > 0);
        }

        tx->tx_buftype = RANAL_BUF_PHYS_UNMAPPED;
        tx->tx_nob = nob;
        tx->tx_buffer = (void *)((unsigned long)(kiov->kiov_offset + offset));

	phys->Address = page_to_phys(kiov->kiov_page);
        phys++;

        resid = nob - (kiov->kiov_len - offset);
        while (resid > 0) {
                kiov++;
                nkiov--;
                LASSERT (nkiov > 0);

                if (kiov->kiov_offset != 0 ||
                    ((resid > PAGE_SIZE) &&
                     kiov->kiov_len < PAGE_SIZE)) {
                        /* Can't have gaps */
                        CERROR("Can't make payload contiguous in I/O VM:"
                               "page %d, offset %d, len %d \n",
                               (int)(phys - tx->tx_phys),
                               kiov->kiov_offset, kiov->kiov_len);
                        return -EINVAL;
                }

                if ((phys - tx->tx_phys) == LNET_MAX_IOV) {
                        CERROR ("payload too big (%d)\n", (int)(phys - tx->tx_phys));
                        return -EMSGSIZE;
                }

		phys->Address = page_to_phys(kiov->kiov_page);
                phys++;

                resid -= PAGE_SIZE;
        }

        tx->tx_phys_npages = phys - tx->tx_phys;
        return 0;
}

static inline int
kranal_setup_rdma_buffer (kra_tx_t *tx, unsigned int niov,
                          struct iovec *iov, lnet_kiov_t *kiov,
                          int offset, int nob)
{
        LASSERT ((iov == NULL) != (kiov == NULL));

        if (kiov != NULL)
                return kranal_setup_phys_buffer(tx, niov, kiov, offset, nob);

        return kranal_setup_virt_buffer(tx, niov, iov, offset, nob);
}

int
kranal_map_buffer (kra_tx_t *tx)
{
        kra_conn_t     *conn = tx->tx_conn;
        kra_device_t   *dev = conn->rac_device;
        RAP_RETURN      rrc;

        LASSERT (current == dev->rad_scheduler);

        switch (tx->tx_buftype) {
        default:
                LBUG();

        case RANAL_BUF_NONE:
        case RANAL_BUF_IMMEDIATE:
        case RANAL_BUF_PHYS_MAPPED:
        case RANAL_BUF_VIRT_MAPPED:
                return 0;

        case RANAL_BUF_PHYS_UNMAPPED:
                rrc = RapkRegisterPhys(dev->rad_handle,
                                       tx->tx_phys, tx->tx_phys_npages,
                                       &tx->tx_map_key);
                if (rrc != RAP_SUCCESS) {
                        CERROR ("Can't map %d pages: dev %d "
                                "phys %u pp %u, virt %u nob %lu\n",
                                tx->tx_phys_npages, dev->rad_id, 
                                dev->rad_nphysmap, dev->rad_nppphysmap,
                                dev->rad_nvirtmap, dev->rad_nobvirtmap);
                        return -ENOMEM; /* assume insufficient resources */
                }

                dev->rad_nphysmap++;
                dev->rad_nppphysmap += tx->tx_phys_npages;

                tx->tx_buftype = RANAL_BUF_PHYS_MAPPED;
                return 0;

        case RANAL_BUF_VIRT_UNMAPPED:
                rrc = RapkRegisterMemory(dev->rad_handle,
                                         tx->tx_buffer, tx->tx_nob,
                                         &tx->tx_map_key);
                if (rrc != RAP_SUCCESS) {
                        CERROR ("Can't map %d bytes: dev %d "
                                "phys %u pp %u, virt %u nob %lu\n",
                                tx->tx_nob, dev->rad_id, 
                                dev->rad_nphysmap, dev->rad_nppphysmap,
                                dev->rad_nvirtmap, dev->rad_nobvirtmap);
                        return -ENOMEM; /* assume insufficient resources */
                }

                dev->rad_nvirtmap++;
                dev->rad_nobvirtmap += tx->tx_nob;

                tx->tx_buftype = RANAL_BUF_VIRT_MAPPED;
                return 0;
        }
}

void
kranal_unmap_buffer (kra_tx_t *tx)
{
        kra_device_t   *dev;
        RAP_RETURN      rrc;

        switch (tx->tx_buftype) {
        default:
                LBUG();

        case RANAL_BUF_NONE:
        case RANAL_BUF_IMMEDIATE:
        case RANAL_BUF_PHYS_UNMAPPED:
        case RANAL_BUF_VIRT_UNMAPPED:
                break;

        case RANAL_BUF_PHYS_MAPPED:
                LASSERT (tx->tx_conn != NULL);
                dev = tx->tx_conn->rac_device;
                LASSERT (current == dev->rad_scheduler);
                rrc = RapkDeregisterMemory(dev->rad_handle, NULL,
                                           &tx->tx_map_key);
                LASSERT (rrc == RAP_SUCCESS);

                dev->rad_nphysmap--;
                dev->rad_nppphysmap -= tx->tx_phys_npages;

                tx->tx_buftype = RANAL_BUF_PHYS_UNMAPPED;
                break;

        case RANAL_BUF_VIRT_MAPPED:
                LASSERT (tx->tx_conn != NULL);
                dev = tx->tx_conn->rac_device;
                LASSERT (current == dev->rad_scheduler);
                rrc = RapkDeregisterMemory(dev->rad_handle, tx->tx_buffer,
                                           &tx->tx_map_key);
                LASSERT (rrc == RAP_SUCCESS);

                dev->rad_nvirtmap--;
                dev->rad_nobvirtmap -= tx->tx_nob;

                tx->tx_buftype = RANAL_BUF_VIRT_UNMAPPED;
                break;
        }
}

void
kranal_tx_done (kra_tx_t *tx, int completion)
{
	lnet_msg_t      *lnetmsg[2];
	unsigned long    flags;
	int              i;

	LASSERT (!in_interrupt());

	kranal_unmap_buffer(tx);

	lnetmsg[0] = tx->tx_lntmsg[0]; tx->tx_lntmsg[0] = NULL;
	lnetmsg[1] = tx->tx_lntmsg[1]; tx->tx_lntmsg[1] = NULL;

	tx->tx_buftype = RANAL_BUF_NONE;
	tx->tx_msg.ram_type = RANAL_MSG_NONE;
	tx->tx_conn = NULL;

	spin_lock_irqsave(&kranal_data.kra_tx_lock, flags);

	cfs_list_add_tail(&tx->tx_list, &kranal_data.kra_idle_txs);

	spin_unlock_irqrestore(&kranal_data.kra_tx_lock, flags);

	/* finalize AFTER freeing lnet msgs */
	for (i = 0; i < 2; i++) {
		if (lnetmsg[i] == NULL)
			continue;

		lnet_finalize(kranal_data.kra_ni, lnetmsg[i], completion);
	}
}

kra_conn_t *
kranal_find_conn_locked (kra_peer_t *peer)
{
        cfs_list_t *tmp;

        /* just return the first connection */
        cfs_list_for_each (tmp, &peer->rap_conns) {
                return cfs_list_entry(tmp, kra_conn_t, rac_list);
        }

        return NULL;
}

void
kranal_post_fma (kra_conn_t *conn, kra_tx_t *tx)
{
        unsigned long    flags;

        tx->tx_conn = conn;

	spin_lock_irqsave(&conn->rac_lock, flags);
        cfs_list_add_tail(&tx->tx_list, &conn->rac_fmaq);
        tx->tx_qtime = jiffies;
	spin_unlock_irqrestore(&conn->rac_lock, flags);

        kranal_schedule_conn(conn);
}

void
kranal_launch_tx (kra_tx_t *tx, lnet_nid_t nid)
{
        unsigned long    flags;
        kra_peer_t      *peer;
        kra_conn_t      *conn;
        int              rc;
        int              retry;
	rwlock_t    *g_lock = &kranal_data.kra_global_lock;

        /* If I get here, I've committed to send, so I complete the tx with
         * failure on any problems */

        LASSERT (tx->tx_conn == NULL);      /* only set when assigned a conn */

        for (retry = 0; ; retry = 1) {

		read_lock(g_lock);

                peer = kranal_find_peer_locked(nid);
                if (peer != NULL) {
                        conn = kranal_find_conn_locked(peer);
                        if (conn != NULL) {
                                kranal_post_fma(conn, tx);
				read_unlock(g_lock);
                                return;
                        }
                }
                
                /* Making connections; I'll need a write lock... */
		read_unlock(g_lock);
		write_lock_irqsave(g_lock, flags);

                peer = kranal_find_peer_locked(nid);
                if (peer != NULL)
                        break;
                
		write_unlock_irqrestore(g_lock, flags);
                
                if (retry) {
                        CERROR("Can't find peer %s\n", libcfs_nid2str(nid));
                        kranal_tx_done(tx, -EHOSTUNREACH);
                        return;
                }

                rc = kranal_add_persistent_peer(nid, LNET_NIDADDR(nid),
                                                lnet_acceptor_port());
                if (rc != 0) {
                        CERROR("Can't add peer %s: %d\n",
                               libcfs_nid2str(nid), rc);
                        kranal_tx_done(tx, rc);
                        return;
                }
        }
        
        conn = kranal_find_conn_locked(peer);
        if (conn != NULL) {
                /* Connection exists; queue message on it */
                kranal_post_fma(conn, tx);
		write_unlock_irqrestore(g_lock, flags);
                return;
        }
                        
        LASSERT (peer->rap_persistence > 0);

        if (!peer->rap_connecting) {
                LASSERT (cfs_list_empty(&peer->rap_tx_queue));

                if (!(peer->rap_reconnect_interval == 0 || /* first attempt */
                      cfs_time_aftereq(jiffies, peer->rap_reconnect_time))) {
			write_unlock_irqrestore(g_lock, flags);
                        kranal_tx_done(tx, -EHOSTUNREACH);
                        return;
                }

                peer->rap_connecting = 1;
                kranal_peer_addref(peer); /* extra ref for connd */

		spin_lock(&kranal_data.kra_connd_lock);

		cfs_list_add_tail(&peer->rap_connd_list,
			      &kranal_data.kra_connd_peers);
		wake_up(&kranal_data.kra_connd_waitq);

		spin_unlock(&kranal_data.kra_connd_lock);
        }

        /* A connection is being established; queue the message... */
        cfs_list_add_tail(&tx->tx_list, &peer->rap_tx_queue);

	write_unlock_irqrestore(g_lock, flags);
}

void
kranal_rdma(kra_tx_t *tx, int type,
            kra_rdma_desc_t *sink, int nob, __u64 cookie)
{
        kra_conn_t   *conn = tx->tx_conn;
        RAP_RETURN    rrc;
        unsigned long flags;

        LASSERT (kranal_tx_mapped(tx));
        LASSERT (nob <= sink->rard_nob);
        LASSERT (nob <= tx->tx_nob);

        /* No actual race with scheduler sending CLOSE (I'm she!) */
        LASSERT (current == conn->rac_device->rad_scheduler);

        memset(&tx->tx_rdma_desc, 0, sizeof(tx->tx_rdma_desc));
        tx->tx_rdma_desc.SrcPtr.AddressBits = (__u64)((unsigned long)tx->tx_buffer);
        tx->tx_rdma_desc.SrcKey = tx->tx_map_key;
        tx->tx_rdma_desc.DstPtr = sink->rard_addr;
        tx->tx_rdma_desc.DstKey = sink->rard_key;
        tx->tx_rdma_desc.Length = nob;
        tx->tx_rdma_desc.AppPtr = tx;

        /* prep final completion message */
        kranal_init_msg(&tx->tx_msg, type);
        tx->tx_msg.ram_u.completion.racm_cookie = cookie;

        if (nob == 0) { /* Immediate completion */
                kranal_post_fma(conn, tx);
                return;
        }

        LASSERT (!conn->rac_close_sent); /* Don't lie (CLOSE == RDMA idle) */

        rrc = RapkPostRdma(conn->rac_rihandle, &tx->tx_rdma_desc);
        LASSERT (rrc == RAP_SUCCESS);

	spin_lock_irqsave(&conn->rac_lock, flags);
        cfs_list_add_tail(&tx->tx_list, &conn->rac_rdmaq);
        tx->tx_qtime = jiffies;
	spin_unlock_irqrestore(&conn->rac_lock, flags);
}

int
kranal_consume_rxmsg (kra_conn_t *conn, void *buffer, int nob)
{
        __u32      nob_received = nob;
        RAP_RETURN rrc;

        LASSERT (conn->rac_rxmsg != NULL);
        CDEBUG(D_NET, "Consuming %p\n", conn);

        rrc = RapkFmaCopyOut(conn->rac_rihandle, buffer,
                             &nob_received, sizeof(kra_msg_t));
        LASSERT (rrc == RAP_SUCCESS);

        conn->rac_rxmsg = NULL;

        if (nob_received < nob) {
                CWARN("Incomplete immediate msg from %s: expected %d, got %d\n",
                      libcfs_nid2str(conn->rac_peer->rap_nid), 
                      nob, nob_received);
                return -EPROTO;
        }

        return 0;
}

int
kranal_send (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
        lnet_hdr_t       *hdr = &lntmsg->msg_hdr;
        int               type = lntmsg->msg_type;
        lnet_process_id_t target = lntmsg->msg_target;
        int               target_is_router = lntmsg->msg_target_is_router;
        int               routing = lntmsg->msg_routing;
        unsigned int      niov = lntmsg->msg_niov;
        struct iovec     *iov = lntmsg->msg_iov;
        lnet_kiov_t      *kiov = lntmsg->msg_kiov;
        unsigned int      offset = lntmsg->msg_offset;
        unsigned int      nob = lntmsg->msg_len;
        kra_tx_t         *tx;
        int               rc;

        /* NB 'private' is different depending on what we're sending.... */

	CDEBUG(D_NET, "sending %d bytes in %d frags to %s\n",
	       nob, niov, libcfs_id2str(target));

	LASSERT (nob == 0 || niov > 0);
	LASSERT (niov <= LNET_MAX_IOV);

	LASSERT (!in_interrupt());
	/* payload is either all vaddrs or all pages */
	LASSERT (!(kiov != NULL && iov != NULL));

	if (routing) {
		CERROR ("Can't route\n");
		return -EIO;
	}

        switch(type) {
        default:
                LBUG();

        case LNET_MSG_ACK:
                LASSERT (nob == 0);
                break;

        case LNET_MSG_GET:
                LASSERT (niov == 0);
                LASSERT (nob == 0);
                /* We have to consider the eventual sink buffer rather than any
                 * payload passed here (there isn't any, and strictly, looking
                 * inside lntmsg is a layering violation).  We send a simple
                 * IMMEDIATE GET if the sink buffer is mapped already and small
                 * enough for FMA */

                if (routing || target_is_router)
                        break;                  /* send IMMEDIATE */

                if ((lntmsg->msg_md->md_options & LNET_MD_KIOV) == 0 &&
                    lntmsg->msg_md->md_length <= RANAL_FMA_MAX_DATA &&
                    lntmsg->msg_md->md_length <= *kranal_tunables.kra_max_immediate)
                        break;                  /* send IMMEDIATE */

                tx = kranal_new_tx_msg(RANAL_MSG_GET_REQ);
                if (tx == NULL)
                        return -ENOMEM;

                if ((lntmsg->msg_md->md_options & LNET_MD_KIOV) == 0)
                        rc = kranal_setup_virt_buffer(tx, lntmsg->msg_md->md_niov,
                                                      lntmsg->msg_md->md_iov.iov,
                                                      0, lntmsg->msg_md->md_length);
                else
                        rc = kranal_setup_phys_buffer(tx, lntmsg->msg_md->md_niov,
                                                      lntmsg->msg_md->md_iov.kiov,
                                                      0, lntmsg->msg_md->md_length);
                if (rc != 0) {
                        kranal_tx_done(tx, rc);
                        return -EIO;
                }

                tx->tx_lntmsg[1] = lnet_create_reply_msg(ni, lntmsg);
                if (tx->tx_lntmsg[1] == NULL) {
                        CERROR("Can't create reply for GET to %s\n", 
                               libcfs_nid2str(target.nid));
                        kranal_tx_done(tx, rc);
                        return -EIO;
                }

                tx->tx_lntmsg[0] = lntmsg;
                tx->tx_msg.ram_u.get.ragm_hdr = *hdr;
                /* rest of tx_msg is setup just before it is sent */
                kranal_launch_tx(tx, target.nid);
                return 0;

        case LNET_MSG_REPLY:
        case LNET_MSG_PUT:
                if (kiov == NULL &&             /* not paged */
                    nob <= RANAL_FMA_MAX_DATA && /* small enough */
                    nob <= *kranal_tunables.kra_max_immediate)
                        break;                  /* send IMMEDIATE */

                tx = kranal_new_tx_msg(RANAL_MSG_PUT_REQ);
                if (tx == NULL)
                        return -ENOMEM;

                rc = kranal_setup_rdma_buffer(tx, niov, iov, kiov, offset, nob);
                if (rc != 0) {
                        kranal_tx_done(tx, rc);
                        return -EIO;
                }

                tx->tx_lntmsg[0] = lntmsg;
                tx->tx_msg.ram_u.putreq.raprm_hdr = *hdr;
                /* rest of tx_msg is setup just before it is sent */
                kranal_launch_tx(tx, target.nid);
                return 0;
        }

        /* send IMMEDIATE */

        LASSERT (kiov == NULL);
        LASSERT (nob <= RANAL_FMA_MAX_DATA);

        tx = kranal_new_tx_msg(RANAL_MSG_IMMEDIATE);
        if (tx == NULL)
                return -ENOMEM;

        rc = kranal_setup_immediate_buffer(tx, niov, iov, offset, nob);
        if (rc != 0) {
                kranal_tx_done(tx, rc);
                return -EIO;
        }

        tx->tx_msg.ram_u.immediate.raim_hdr = *hdr;
        tx->tx_lntmsg[0] = lntmsg;
        kranal_launch_tx(tx, target.nid);
        return 0;
}

void
kranal_reply(lnet_ni_t *ni, kra_conn_t *conn, lnet_msg_t *lntmsg)
{
        kra_msg_t     *rxmsg = conn->rac_rxmsg;
        unsigned int   niov = lntmsg->msg_niov;
        struct iovec  *iov = lntmsg->msg_iov;
        lnet_kiov_t   *kiov = lntmsg->msg_kiov;
        unsigned int   offset = lntmsg->msg_offset;
        unsigned int   nob = lntmsg->msg_len;
        kra_tx_t      *tx;
        int            rc;

        tx = kranal_get_idle_tx();
        if (tx == NULL)
                goto failed_0;

        rc = kranal_setup_rdma_buffer(tx, niov, iov, kiov, offset, nob);
        if (rc != 0)
                goto failed_1;

        tx->tx_conn = conn;

        rc = kranal_map_buffer(tx);
        if (rc != 0)
                goto failed_1;

        tx->tx_lntmsg[0] = lntmsg;

        kranal_rdma(tx, RANAL_MSG_GET_DONE,
                    &rxmsg->ram_u.get.ragm_desc, nob,
                    rxmsg->ram_u.get.ragm_cookie);
        return;

 failed_1:
        kranal_tx_done(tx, -EIO);
 failed_0:
        lnet_finalize(ni, lntmsg, -EIO);
}

int
kranal_eager_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
                   void **new_private)
{
        kra_conn_t *conn = (kra_conn_t *)private;

        LCONSOLE_ERROR_MSG(0x12b, "Dropping message from %s: no buffers free.\n",
                           libcfs_nid2str(conn->rac_peer->rap_nid));

        return -EDEADLK;
}

int
kranal_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
             int delayed, unsigned int niov, 
             struct iovec *iov, lnet_kiov_t *kiov,
             unsigned int offset, unsigned int mlen, unsigned int rlen)
{
	kra_conn_t  *conn = private;
	kra_msg_t   *rxmsg = conn->rac_rxmsg;
	kra_tx_t    *tx;
	void        *buffer;
	int          rc;

	LASSERT (mlen <= rlen);
	LASSERT (!in_interrupt());
	/* Either all pages or all vaddrs */
	LASSERT (!(kiov != NULL && iov != NULL));

	CDEBUG(D_NET, "conn %p, rxmsg %p, lntmsg %p\n", conn, rxmsg, lntmsg);

        switch(rxmsg->ram_type) {
        default:
                LBUG();

        case RANAL_MSG_IMMEDIATE:
                if (mlen == 0) {
                        buffer = NULL;
                } else if (kiov != NULL) {
                        CERROR("Can't recv immediate into paged buffer\n");
                        return -EIO;
                } else {
                        LASSERT (niov > 0);
                        while (offset >= iov->iov_len) {
                                offset -= iov->iov_len;
                                iov++;
                                niov--;
                                LASSERT (niov > 0);
                        }
                        if (mlen > iov->iov_len - offset) {
                                CERROR("Can't handle immediate frags\n");
                                return -EIO;
                        }
                        buffer = ((char *)iov->iov_base) + offset;
                }
                rc = kranal_consume_rxmsg(conn, buffer, mlen);
                lnet_finalize(ni, lntmsg, (rc == 0) ? 0 : -EIO);
                return 0;

        case RANAL_MSG_PUT_REQ:
                tx = kranal_new_tx_msg(RANAL_MSG_PUT_ACK);
                if (tx == NULL) {
                        kranal_consume_rxmsg(conn, NULL, 0);
                        return -ENOMEM;
                }
                
                rc = kranal_setup_rdma_buffer(tx, niov, iov, kiov, offset, mlen);
                if (rc != 0) {
                        kranal_tx_done(tx, rc);
                        kranal_consume_rxmsg(conn, NULL, 0);
                        return -EIO;
                }

                tx->tx_conn = conn;
                rc = kranal_map_buffer(tx);
                if (rc != 0) {
                        kranal_tx_done(tx, rc);
                        kranal_consume_rxmsg(conn, NULL, 0);
                        return -EIO;
                }

                tx->tx_msg.ram_u.putack.rapam_src_cookie =
                        conn->rac_rxmsg->ram_u.putreq.raprm_cookie;
                tx->tx_msg.ram_u.putack.rapam_dst_cookie = tx->tx_cookie;
                tx->tx_msg.ram_u.putack.rapam_desc.rard_key = tx->tx_map_key;
                tx->tx_msg.ram_u.putack.rapam_desc.rard_addr.AddressBits =
                        (__u64)((unsigned long)tx->tx_buffer);
                tx->tx_msg.ram_u.putack.rapam_desc.rard_nob = mlen;

                tx->tx_lntmsg[0] = lntmsg; /* finalize this on RDMA_DONE */

                kranal_post_fma(conn, tx);
                kranal_consume_rxmsg(conn, NULL, 0);
                return 0;

        case RANAL_MSG_GET_REQ:
                if (lntmsg != NULL) {
                        /* Matched! */
                        kranal_reply(ni, conn, lntmsg);
                } else {
                        /* No match */
                        tx = kranal_new_tx_msg(RANAL_MSG_GET_NAK);
                        if (tx != NULL) {
                                tx->tx_msg.ram_u.completion.racm_cookie =
                                        rxmsg->ram_u.get.ragm_cookie;
                                kranal_post_fma(conn, tx);
                        }
                }
                kranal_consume_rxmsg(conn, NULL, 0);
                return 0;
        }
}

int
kranal_thread_start(int(*fn)(void *arg), void *arg, char *name)
{
	struct task_struct *task = cfs_thread_run(fn, arg, name);

	if (!IS_ERR(task))
		atomic_inc(&kranal_data.kra_nthreads);
	return PTR_ERR(task);
}

void
kranal_thread_fini (void)
{
	atomic_dec(&kranal_data.kra_nthreads);
}

int
kranal_check_conn_timeouts (kra_conn_t *conn)
{
        kra_tx_t          *tx;
        cfs_list_t        *ttmp;
        unsigned long      flags;
        long               timeout;
        unsigned long      now = jiffies;

        LASSERT (conn->rac_state == RANAL_CONN_ESTABLISHED ||
                 conn->rac_state == RANAL_CONN_CLOSING);

	if (!conn->rac_close_sent &&
	    cfs_time_aftereq(now, conn->rac_last_tx +
			     msecs_to_jiffies(conn->rac_keepalive *
					      MSEC_PER_SEC))) {
		/* not sent in a while; schedule conn so scheduler sends a keepalive */
		CDEBUG(D_NET, "Scheduling keepalive %p->%s\n",
		       conn, libcfs_nid2str(conn->rac_peer->rap_nid));
		kranal_schedule_conn(conn);
	}

	timeout = msecs_to_jiffies(conn->rac_timeout * MSEC_PER_SEC);

	if (!conn->rac_close_recvd &&
	    cfs_time_aftereq(now, conn->rac_last_rx + timeout)) {
		CERROR("%s received from %s within %lu seconds\n",
		       (conn->rac_state == RANAL_CONN_ESTABLISHED) ?
		       "Nothing" : "CLOSE not",
		       libcfs_nid2str(conn->rac_peer->rap_nid),
		       jiffies_to_msecs(now - conn->rac_last_rx)/MSEC_PER_SEC);
		return -ETIMEDOUT;
	}

        if (conn->rac_state != RANAL_CONN_ESTABLISHED)
                return 0;

        /* Check the conn's queues are moving.  These are "belt+braces" checks,
         * in case of hardware/software errors that make this conn seem
         * responsive even though it isn't progressing its message queues. */

	spin_lock_irqsave(&conn->rac_lock, flags);

	cfs_list_for_each (ttmp, &conn->rac_fmaq) {
		tx = cfs_list_entry(ttmp, kra_tx_t, tx_list);

		if (cfs_time_aftereq(now, tx->tx_qtime + timeout)) {
			spin_unlock_irqrestore(&conn->rac_lock, flags);
			CERROR("tx on fmaq for %s blocked %lu seconds\n",
			       libcfs_nid2str(conn->rac_peer->rap_nid),
			       jiffies_to_msecs(now-tx->tx_qtime)/MSEC_PER_SEC);
			return -ETIMEDOUT;
		}
	}

	cfs_list_for_each (ttmp, &conn->rac_rdmaq) {
		tx = cfs_list_entry(ttmp, kra_tx_t, tx_list);

		if (cfs_time_aftereq(now, tx->tx_qtime + timeout)) {
			spin_unlock_irqrestore(&conn->rac_lock, flags);
			CERROR("tx on rdmaq for %s blocked %lu seconds\n",
			       libcfs_nid2str(conn->rac_peer->rap_nid),
			       jiffies_to_msecs(now-tx->tx_qtime)/MSEC_PER_SEC);
			return -ETIMEDOUT;
		}
	}

	cfs_list_for_each (ttmp, &conn->rac_replyq) {
		tx = cfs_list_entry(ttmp, kra_tx_t, tx_list);

		if (cfs_time_aftereq(now, tx->tx_qtime + timeout)) {
			spin_unlock_irqrestore(&conn->rac_lock, flags);
			CERROR("tx on replyq for %s blocked %lu seconds\n",
			       libcfs_nid2str(conn->rac_peer->rap_nid),
			       jiffies_to_msecs(now-tx->tx_qtime)/MSEC_PER_SEC);
			return -ETIMEDOUT;
		}
	}

	spin_unlock_irqrestore(&conn->rac_lock, flags);
        return 0;
}

void
kranal_reaper_check (int idx, unsigned long *min_timeoutp)
{
        cfs_list_t        *conns = &kranal_data.kra_conns[idx];
        cfs_list_t        *ctmp;
        kra_conn_t        *conn;
        unsigned long      flags;
        int                rc;

 again:
        /* NB. We expect to check all the conns and not find any problems, so
         * we just use a shared lock while we take a look... */
	read_lock(&kranal_data.kra_global_lock);

        cfs_list_for_each (ctmp, conns) {
                conn = cfs_list_entry(ctmp, kra_conn_t, rac_hashlist);

                if (conn->rac_timeout < *min_timeoutp )
                        *min_timeoutp = conn->rac_timeout;
                if (conn->rac_keepalive < *min_timeoutp )
                        *min_timeoutp = conn->rac_keepalive;

                rc = kranal_check_conn_timeouts(conn);
                if (rc == 0)
                        continue;

                kranal_conn_addref(conn);
		read_unlock(&kranal_data.kra_global_lock);

                CERROR("Conn to %s, cqid %d timed out\n",
                       libcfs_nid2str(conn->rac_peer->rap_nid), 
                       conn->rac_cqid);

		write_lock_irqsave(&kranal_data.kra_global_lock, flags);

                switch (conn->rac_state) {
                default:
                        LBUG();

                case RANAL_CONN_ESTABLISHED:
                        kranal_close_conn_locked(conn, -ETIMEDOUT);
                        break;

                case RANAL_CONN_CLOSING:
                        kranal_terminate_conn_locked(conn);
                        break;
                }

		write_unlock_irqrestore(&kranal_data.kra_global_lock,
                                            flags);

                kranal_conn_decref(conn);

                /* start again now I've dropped the lock */
                goto again;
        }

	read_unlock(&kranal_data.kra_global_lock);
}

int
kranal_connd (void *arg)
{
	long               id = (long)arg;
	wait_queue_t     wait;
	unsigned long      flags;
	kra_peer_t        *peer;
	kra_acceptsock_t  *ras;
	int                did_something;

	cfs_block_allsigs();

	init_waitqueue_entry_current(&wait);

	spin_lock_irqsave(&kranal_data.kra_connd_lock, flags);

	while (!kranal_data.kra_shutdown) {
		did_something = 0;

		if (!cfs_list_empty(&kranal_data.kra_connd_acceptq)) {
			ras = cfs_list_entry(kranal_data.kra_connd_acceptq.next,
					     kra_acceptsock_t, ras_list);
			cfs_list_del(&ras->ras_list);

			spin_unlock_irqrestore(&kranal_data.kra_connd_lock,
						   flags);

			CDEBUG(D_NET,"About to handshake someone\n");

			kranal_conn_handshake(ras->ras_sock, NULL);
			kranal_free_acceptsock(ras);

			CDEBUG(D_NET,"Finished handshaking someone\n");

			spin_lock_irqsave(&kranal_data.kra_connd_lock,
					      flags);
			did_something = 1;
		}

		if (!cfs_list_empty(&kranal_data.kra_connd_peers)) {
			peer = cfs_list_entry(kranal_data.kra_connd_peers.next,
					      kra_peer_t, rap_connd_list);

			cfs_list_del_init(&peer->rap_connd_list);
			spin_unlock_irqrestore(&kranal_data.kra_connd_lock,
						   flags);

			kranal_connect(peer);
			kranal_peer_decref(peer);

			spin_lock_irqsave(&kranal_data.kra_connd_lock,
					      flags);
			did_something = 1;
		}

		if (did_something)
			continue;

		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue_exclusive(&kranal_data.kra_connd_waitq, &wait);

		spin_unlock_irqrestore(&kranal_data.kra_connd_lock, flags);

		waitq_wait(&wait, TASK_INTERRUPTIBLE);

		set_current_state(TASK_RUNNING);
		remove_wait_queue(&kranal_data.kra_connd_waitq, &wait);

		spin_lock_irqsave(&kranal_data.kra_connd_lock, flags);
	}

	spin_unlock_irqrestore(&kranal_data.kra_connd_lock, flags);

	kranal_thread_fini();
	return 0;
}

void
kranal_update_reaper_timeout(long timeout)
{
        unsigned long   flags;

        LASSERT (timeout > 0);

	spin_lock_irqsave(&kranal_data.kra_reaper_lock, flags);

        if (timeout < kranal_data.kra_new_min_timeout)
                kranal_data.kra_new_min_timeout = timeout;

	spin_unlock_irqrestore(&kranal_data.kra_reaper_lock, flags);
}

int
kranal_reaper (void *arg)
{
	wait_queue_t     wait;
	unsigned long      flags;
	long               timeout;
	int                i;
	int                conn_entries = kranal_data.kra_conn_hash_size;
	int                conn_index = 0;
	int                base_index = conn_entries - 1;
	unsigned long      next_check_time = jiffies;
	long               next_min_timeout = MAX_SCHEDULE_TIMEOUT;
	long               current_min_timeout = 1;

	cfs_block_allsigs();

	init_waitqueue_entry_current(&wait);

	spin_lock_irqsave(&kranal_data.kra_reaper_lock, flags);

	while (!kranal_data.kra_shutdown) {
		/* I wake up every 'p' seconds to check for timeouts on some
		 * more peers.  I try to check every connection 'n' times
		 * within the global minimum of all keepalive and timeout
		 * intervals, to ensure I attend to every connection within
		 * (n+1)/n times its timeout intervals. */
		const int     p = 1;
		const int     n = 3;
		unsigned long min_timeout;
		int           chunk;

		/* careful with the jiffy wrap... */
		timeout = (long)(next_check_time - jiffies);
		if (timeout > 0) {
			set_current_state(TASK_INTERRUPTIBLE);
			add_wait_queue(&kranal_data.kra_reaper_waitq, &wait);

			spin_unlock_irqrestore(&kranal_data.kra_reaper_lock,
						   flags);

			waitq_timedwait(&wait, TASK_INTERRUPTIBLE,
					    timeout);

			spin_lock_irqsave(&kranal_data.kra_reaper_lock,
					      flags);

			set_current_state(TASK_RUNNING);
			remove_wait_queue(&kranal_data.kra_reaper_waitq, &wait);
			continue;
		}

		if (kranal_data.kra_new_min_timeout !=
		    MAX_SCHEDULE_TIMEOUT) {
			/* new min timeout set: restart min timeout scan */
			next_min_timeout = MAX_SCHEDULE_TIMEOUT;
			base_index = conn_index - 1;
			if (base_index < 0)
				base_index = conn_entries - 1;

			if (kranal_data.kra_new_min_timeout <
			    current_min_timeout) {
				current_min_timeout =
					kranal_data.kra_new_min_timeout;
				CDEBUG(D_NET, "Set new min timeout %ld\n",
				       current_min_timeout);
			}

			kranal_data.kra_new_min_timeout =
				MAX_SCHEDULE_TIMEOUT;
		}
		min_timeout = current_min_timeout;

		spin_unlock_irqrestore(&kranal_data.kra_reaper_lock, flags);

		LASSERT (min_timeout > 0);

		/* Compute how many table entries to check now so I get round
		 * the whole table fast enough given that I do this at fixed
		 * intervals of 'p' seconds) */
		chunk = conn_entries;
		if (min_timeout > n * p)
			chunk = (chunk * n * p) / min_timeout;
		if (chunk == 0)
			chunk = 1;

		for (i = 0; i < chunk; i++) {
			kranal_reaper_check(conn_index,
					    &next_min_timeout);
			conn_index = (conn_index + 1) % conn_entries;
		}

		next_check_time += msecs_to_jiffies(p * MSEC_PER_SEC);

		spin_lock_irqsave(&kranal_data.kra_reaper_lock, flags);

		if (((conn_index - chunk <= base_index &&
		      base_index < conn_index) ||
		     (conn_index - conn_entries - chunk <= base_index &&
		      base_index < conn_index - conn_entries))) {

			/* Scanned all conns: set current_min_timeout... */
			if (current_min_timeout != next_min_timeout) {
				current_min_timeout = next_min_timeout;
				CDEBUG(D_NET, "Set new min timeout %ld\n",
				       current_min_timeout);
			}

			/* ...and restart min timeout scan */
			next_min_timeout = MAX_SCHEDULE_TIMEOUT;
			base_index = conn_index - 1;
			if (base_index < 0)
				base_index = conn_entries - 1;
		}
	}

	kranal_thread_fini();
	return 0;
}

void
kranal_check_rdma_cq (kra_device_t *dev)
{
        kra_conn_t          *conn;
        kra_tx_t            *tx;
        RAP_RETURN           rrc;
        unsigned long        flags;
        RAP_RDMA_DESCRIPTOR *desc;
        __u32                cqid;
        __u32                event_type;

        for (;;) {
                rrc = RapkCQDone(dev->rad_rdma_cqh, &cqid, &event_type);
                if (rrc == RAP_NOT_DONE) {
                        CDEBUG(D_NET, "RDMA CQ %d empty\n", dev->rad_id);
                        return;
                }

                LASSERT (rrc == RAP_SUCCESS);
                LASSERT ((event_type & RAPK_CQ_EVENT_OVERRUN) == 0);

		read_lock(&kranal_data.kra_global_lock);

                conn = kranal_cqid2conn_locked(cqid);
                if (conn == NULL) {
                        /* Conn was destroyed? */
                        CDEBUG(D_NET, "RDMA CQID lookup %d failed\n", cqid);
			read_unlock(&kranal_data.kra_global_lock);
                        continue;
                }

                rrc = RapkRdmaDone(conn->rac_rihandle, &desc);
                LASSERT (rrc == RAP_SUCCESS);

                CDEBUG(D_NET, "Completed %p\n",
                       cfs_list_entry(conn->rac_rdmaq.next, kra_tx_t, tx_list));

		spin_lock_irqsave(&conn->rac_lock, flags);

                LASSERT (!cfs_list_empty(&conn->rac_rdmaq));
                tx = cfs_list_entry(conn->rac_rdmaq.next, kra_tx_t, tx_list);
                cfs_list_del(&tx->tx_list);

                LASSERT(desc->AppPtr == (void *)tx);
                LASSERT(tx->tx_msg.ram_type == RANAL_MSG_PUT_DONE ||
                        tx->tx_msg.ram_type == RANAL_MSG_GET_DONE);

                cfs_list_add_tail(&tx->tx_list, &conn->rac_fmaq);
                tx->tx_qtime = jiffies;

		spin_unlock_irqrestore(&conn->rac_lock, flags);

                /* Get conn's fmaq processed, now I've just put something
                 * there */
                kranal_schedule_conn(conn);

		read_unlock(&kranal_data.kra_global_lock);
        }
}

void
kranal_check_fma_cq (kra_device_t *dev)
{
        kra_conn_t         *conn;
        RAP_RETURN          rrc;
        __u32               cqid;
        __u32               event_type;
        cfs_list_t         *conns;
        cfs_list_t         *tmp;
        int                 i;

        for (;;) {
                rrc = RapkCQDone(dev->rad_fma_cqh, &cqid, &event_type);
                if (rrc == RAP_NOT_DONE) {
                        CDEBUG(D_NET, "FMA CQ %d empty\n", dev->rad_id);
                        return;
                }

                LASSERT (rrc == RAP_SUCCESS);

                if ((event_type & RAPK_CQ_EVENT_OVERRUN) == 0) {

			read_lock(&kranal_data.kra_global_lock);

                        conn = kranal_cqid2conn_locked(cqid);
                        if (conn == NULL) {
                                CDEBUG(D_NET, "FMA CQID lookup %d failed\n",
                                       cqid);
                        } else {
                                CDEBUG(D_NET, "FMA completed: %p CQID %d\n",
                                       conn, cqid);
                                kranal_schedule_conn(conn);
                        }

			read_unlock(&kranal_data.kra_global_lock);
                        continue;
                }

                /* FMA CQ has overflowed: check ALL conns */
                CWARN("FMA CQ overflow: scheduling ALL conns on device %d\n", 
                      dev->rad_id);

                for (i = 0; i < kranal_data.kra_conn_hash_size; i++) {

			read_lock(&kranal_data.kra_global_lock);

                        conns = &kranal_data.kra_conns[i];

                        cfs_list_for_each (tmp, conns) {
                                conn = cfs_list_entry(tmp, kra_conn_t,
                                                      rac_hashlist);

                                if (conn->rac_device == dev)
                                        kranal_schedule_conn(conn);
                        }

                        /* don't block write lockers for too long... */
			read_unlock(&kranal_data.kra_global_lock);
                }
        }
}

int
kranal_sendmsg(kra_conn_t *conn, kra_msg_t *msg,
               void *immediate, int immediatenob)
{
        int        sync = (msg->ram_type & RANAL_MSG_FENCE) != 0;
        RAP_RETURN rrc;

        CDEBUG(D_NET,"%p sending msg %p %02x%s [%p for %d]\n",
               conn, msg, msg->ram_type, sync ? "(sync)" : "",
               immediate, immediatenob);

        LASSERT (sizeof(*msg) <= RANAL_FMA_MAX_PREFIX);
        LASSERT ((msg->ram_type == RANAL_MSG_IMMEDIATE) ?
                 immediatenob <= RANAL_FMA_MAX_DATA :
                 immediatenob == 0);

        msg->ram_connstamp = conn->rac_my_connstamp;
        msg->ram_seq = conn->rac_tx_seq;

        if (sync)
                rrc = RapkFmaSyncSend(conn->rac_rihandle,
                                      immediate, immediatenob,
                                      msg, sizeof(*msg));
        else
                rrc = RapkFmaSend(conn->rac_rihandle,
                                  immediate, immediatenob,
                                  msg, sizeof(*msg));

        switch (rrc) {
        default:
                LBUG();

        case RAP_SUCCESS:
                conn->rac_last_tx = jiffies;
                conn->rac_tx_seq++;
                return 0;

        case RAP_NOT_DONE:
		if (cfs_time_aftereq(jiffies,
				     conn->rac_last_tx +
				     msecs_to_jiffies(conn->rac_keepalive *
						      MSEC_PER_SEC)))
			CWARN("EAGAIN sending %02x (idle %lu secs)\n",
			      msg->ram_type,
			      jiffies_to_msecs(jiffies - conn->rac_last_tx) /
			      MSEC_PER_SEC);
		return -EAGAIN;
        }
}

void
kranal_process_fmaq (kra_conn_t *conn)
{
        unsigned long flags;
        int           more_to_do;
        kra_tx_t     *tx;
        int           rc;
        int           expect_reply;

        /* NB 1. kranal_sendmsg() may fail if I'm out of credits right now.
         *       However I will be rescheduled by an FMA completion event
         *       when I eventually get some.
         * NB 2. Sampling rac_state here races with setting it elsewhere.
         *       But it doesn't matter if I try to send a "real" message just
         *       as I start closing because I'll get scheduled to send the
         *       close anyway. */

        /* Not racing with incoming message processing! */
        LASSERT (current == conn->rac_device->rad_scheduler);

        if (conn->rac_state != RANAL_CONN_ESTABLISHED) {
                if (!cfs_list_empty(&conn->rac_rdmaq)) {
                        /* RDMAs in progress */
                        LASSERT (!conn->rac_close_sent);

			if (cfs_time_aftereq(jiffies,
					     conn->rac_last_tx +
					     msecs_to_jiffies(conn->rac_keepalive *
							      MSEC_PER_SEC))) {
				CDEBUG(D_NET, "sending NOOP (rdma in progress)\n");
				kranal_init_msg(&conn->rac_msg, RANAL_MSG_NOOP);
				kranal_sendmsg(conn, &conn->rac_msg, NULL, 0);
			}
                        return;
                }

                if (conn->rac_close_sent)
                        return;

                CWARN("sending CLOSE to %s\n", 
                      libcfs_nid2str(conn->rac_peer->rap_nid));
                kranal_init_msg(&conn->rac_msg, RANAL_MSG_CLOSE);
                rc = kranal_sendmsg(conn, &conn->rac_msg, NULL, 0);
                if (rc != 0)
                        return;

                conn->rac_close_sent = 1;
                if (!conn->rac_close_recvd)
                        return;

		write_lock_irqsave(&kranal_data.kra_global_lock, flags);

                if (conn->rac_state == RANAL_CONN_CLOSING)
                        kranal_terminate_conn_locked(conn);

		write_unlock_irqrestore(&kranal_data.kra_global_lock,
                                            flags);
                return;
        }

	spin_lock_irqsave(&conn->rac_lock, flags);

        if (cfs_list_empty(&conn->rac_fmaq)) {

		spin_unlock_irqrestore(&conn->rac_lock, flags);

		if (cfs_time_aftereq(jiffies,
				     conn->rac_last_tx +
				     msecs_to_jiffies(conn->rac_keepalive *
						      MSEC_PER_SEC))) {
			CDEBUG(D_NET, "sending NOOP -> %s (%p idle %lu(%ld))\n",
			       libcfs_nid2str(conn->rac_peer->rap_nid), conn,
			       jiffies_to_msecs(jiffies - conn->rac_last_tx) /
			       MSEC_PER_SEC,
			       conn->rac_keepalive);
			kranal_init_msg(&conn->rac_msg, RANAL_MSG_NOOP);
			kranal_sendmsg(conn, &conn->rac_msg, NULL, 0);
		}
                return;
        }

        tx = cfs_list_entry(conn->rac_fmaq.next, kra_tx_t, tx_list);
        cfs_list_del(&tx->tx_list);
        more_to_do = !cfs_list_empty(&conn->rac_fmaq);

	spin_unlock_irqrestore(&conn->rac_lock, flags);

        expect_reply = 0;
        CDEBUG(D_NET, "sending regular msg: %p, type %02x, cookie "LPX64"\n",
               tx, tx->tx_msg.ram_type, tx->tx_cookie);
        switch (tx->tx_msg.ram_type) {
        default:
                LBUG();

        case RANAL_MSG_IMMEDIATE:
                rc = kranal_sendmsg(conn, &tx->tx_msg,
                                    tx->tx_buffer, tx->tx_nob);
                break;

        case RANAL_MSG_PUT_NAK:
        case RANAL_MSG_PUT_DONE:
        case RANAL_MSG_GET_NAK:
        case RANAL_MSG_GET_DONE:
                rc = kranal_sendmsg(conn, &tx->tx_msg, NULL, 0);
                break;

        case RANAL_MSG_PUT_REQ:
                rc = kranal_map_buffer(tx);
                LASSERT (rc != -EAGAIN);
                if (rc != 0)
                        break;

                tx->tx_msg.ram_u.putreq.raprm_cookie = tx->tx_cookie;
                rc = kranal_sendmsg(conn, &tx->tx_msg, NULL, 0);
                expect_reply = 1;
                break;

        case RANAL_MSG_PUT_ACK:
                rc = kranal_sendmsg(conn, &tx->tx_msg, NULL, 0);
                expect_reply = 1;
                break;

        case RANAL_MSG_GET_REQ:
                rc = kranal_map_buffer(tx);
                LASSERT (rc != -EAGAIN);
                if (rc != 0)
                        break;

                tx->tx_msg.ram_u.get.ragm_cookie = tx->tx_cookie;
                tx->tx_msg.ram_u.get.ragm_desc.rard_key = tx->tx_map_key;
                tx->tx_msg.ram_u.get.ragm_desc.rard_addr.AddressBits =
                        (__u64)((unsigned long)tx->tx_buffer);
                tx->tx_msg.ram_u.get.ragm_desc.rard_nob = tx->tx_nob;
                rc = kranal_sendmsg(conn, &tx->tx_msg, NULL, 0);
                expect_reply = 1;
                break;
        }

        if (rc == -EAGAIN) {
                /* I need credits to send this.  Replace tx at the head of the
                 * fmaq and I'll get rescheduled when credits appear */
                CDEBUG(D_NET, "EAGAIN on %p\n", conn);
		spin_lock_irqsave(&conn->rac_lock, flags);
                cfs_list_add(&tx->tx_list, &conn->rac_fmaq);
		spin_unlock_irqrestore(&conn->rac_lock, flags);
                return;
        }

        if (!expect_reply || rc != 0) {
                kranal_tx_done(tx, rc);
        } else {
                /* LASSERT(current) above ensures this doesn't race with reply
                 * processing */
		spin_lock_irqsave(&conn->rac_lock, flags);
                cfs_list_add_tail(&tx->tx_list, &conn->rac_replyq);
                tx->tx_qtime = jiffies;
		spin_unlock_irqrestore(&conn->rac_lock, flags);
        }

        if (more_to_do) {
                CDEBUG(D_NET, "Rescheduling %p (more to do)\n", conn);
                kranal_schedule_conn(conn);
        }
}

static inline void
kranal_swab_rdma_desc (kra_rdma_desc_t *d)
{
        __swab64s(&d->rard_key.Key);
        __swab16s(&d->rard_key.Cookie);
        __swab16s(&d->rard_key.MdHandle);
        __swab32s(&d->rard_key.Flags);
        __swab64s(&d->rard_addr.AddressBits);
        __swab32s(&d->rard_nob);
}

kra_tx_t *
kranal_match_reply(kra_conn_t *conn, int type, __u64 cookie)
{
        cfs_list_t       *ttmp;
        kra_tx_t         *tx;
        unsigned long     flags;

	spin_lock_irqsave(&conn->rac_lock, flags);

        cfs_list_for_each(ttmp, &conn->rac_replyq) {
                tx = cfs_list_entry(ttmp, kra_tx_t, tx_list);

                CDEBUG(D_NET,"Checking %p %02x/"LPX64"\n",
                       tx, tx->tx_msg.ram_type, tx->tx_cookie);

                if (tx->tx_cookie != cookie)
                        continue;

                if (tx->tx_msg.ram_type != type) {
			spin_unlock_irqrestore(&conn->rac_lock, flags);
                        CWARN("Unexpected type %x (%x expected) "
                              "matched reply from %s\n",
                              tx->tx_msg.ram_type, type,
                              libcfs_nid2str(conn->rac_peer->rap_nid));
                        return NULL;
                }

                cfs_list_del(&tx->tx_list);
		spin_unlock_irqrestore(&conn->rac_lock, flags);
                return tx;
        }

	spin_unlock_irqrestore(&conn->rac_lock, flags);
        CWARN("Unmatched reply %02x/"LPX64" from %s\n",
              type, cookie, libcfs_nid2str(conn->rac_peer->rap_nid));
        return NULL;
}

void
kranal_check_fma_rx (kra_conn_t *conn)
{
        unsigned long flags;
        __u32         seq;
        kra_tx_t     *tx;
        kra_msg_t    *msg;
        void         *prefix;
        RAP_RETURN    rrc = RapkFmaGetPrefix(conn->rac_rihandle, &prefix);
        kra_peer_t   *peer = conn->rac_peer;
        int           rc = 0;
        int           repost = 1;

        if (rrc == RAP_NOT_DONE)
                return;

        CDEBUG(D_NET, "RX on %p\n", conn);

        LASSERT (rrc == RAP_SUCCESS);
        conn->rac_last_rx = jiffies;
        seq = conn->rac_rx_seq++;
        msg = (kra_msg_t *)prefix;

        /* stash message for portals callbacks they'll NULL
         * rac_rxmsg if they consume it */
        LASSERT (conn->rac_rxmsg == NULL);
        conn->rac_rxmsg = msg;

        if (msg->ram_magic != RANAL_MSG_MAGIC) {
                if (__swab32(msg->ram_magic) != RANAL_MSG_MAGIC) {
                        CERROR("Unexpected magic %08x from %s\n",
                               msg->ram_magic, libcfs_nid2str(peer->rap_nid));
                        rc = -EPROTO;
                        goto out;
                }

                __swab32s(&msg->ram_magic);
                __swab16s(&msg->ram_version);
                __swab16s(&msg->ram_type);
                __swab64s(&msg->ram_srcnid);
                __swab64s(&msg->ram_connstamp);
                __swab32s(&msg->ram_seq);

                /* NB message type checked below; NOT here... */
                switch (msg->ram_type) {
                case RANAL_MSG_PUT_ACK:
                        kranal_swab_rdma_desc(&msg->ram_u.putack.rapam_desc);
                        break;

                case RANAL_MSG_GET_REQ:
                        kranal_swab_rdma_desc(&msg->ram_u.get.ragm_desc);
                        break;

                default:
                        break;
                }
        }

        if (msg->ram_version != RANAL_MSG_VERSION) {
                CERROR("Unexpected protocol version %d from %s\n",
                       msg->ram_version, libcfs_nid2str(peer->rap_nid));
                rc = -EPROTO;
                goto out;
        }

        if (msg->ram_srcnid != peer->rap_nid) {
                CERROR("Unexpected peer %s from %s\n",
                       libcfs_nid2str(msg->ram_srcnid), 
                       libcfs_nid2str(peer->rap_nid));
                rc = -EPROTO;
                goto out;
        }

        if (msg->ram_connstamp != conn->rac_peer_connstamp) {
                CERROR("Unexpected connstamp "LPX64"("LPX64
                       " expected) from %s\n",
                       msg->ram_connstamp, conn->rac_peer_connstamp,
                       libcfs_nid2str(peer->rap_nid));
                rc = -EPROTO;
                goto out;
        }

        if (msg->ram_seq != seq) {
                CERROR("Unexpected sequence number %d(%d expected) from %s\n",
                       msg->ram_seq, seq, libcfs_nid2str(peer->rap_nid));
                rc = -EPROTO;
                goto out;
        }

        if ((msg->ram_type & RANAL_MSG_FENCE) != 0) {
                /* This message signals RDMA completion... */
                rrc = RapkFmaSyncWait(conn->rac_rihandle);
                if (rrc != RAP_SUCCESS) {
                        CERROR("RapkFmaSyncWait failed: %d\n", rrc);
                        rc = -ENETDOWN;
                        goto out;
                }
        }

        if (conn->rac_close_recvd) {
                CERROR("Unexpected message %d after CLOSE from %s\n",
                       msg->ram_type, libcfs_nid2str(conn->rac_peer->rap_nid));
                rc = -EPROTO;
                goto out;
        }

        if (msg->ram_type == RANAL_MSG_CLOSE) {
                CWARN("RX CLOSE from %s\n", libcfs_nid2str(conn->rac_peer->rap_nid));
                conn->rac_close_recvd = 1;
		write_lock_irqsave(&kranal_data.kra_global_lock, flags);

                if (conn->rac_state == RANAL_CONN_ESTABLISHED)
                        kranal_close_conn_locked(conn, 0);
                else if (conn->rac_state == RANAL_CONN_CLOSING &&
                         conn->rac_close_sent)
                        kranal_terminate_conn_locked(conn);

		write_unlock_irqrestore(&kranal_data.kra_global_lock,
                                            flags);
                goto out;
        }

        if (conn->rac_state != RANAL_CONN_ESTABLISHED)
                goto out;

        switch (msg->ram_type) {
        case RANAL_MSG_NOOP:
                /* Nothing to do; just a keepalive */
                CDEBUG(D_NET, "RX NOOP on %p\n", conn);
                break;

        case RANAL_MSG_IMMEDIATE:
                CDEBUG(D_NET, "RX IMMEDIATE on %p\n", conn);
                rc = lnet_parse(kranal_data.kra_ni, &msg->ram_u.immediate.raim_hdr, 
                                msg->ram_srcnid, conn, 0);
                repost = rc < 0;
                break;

        case RANAL_MSG_PUT_REQ:
                CDEBUG(D_NET, "RX PUT_REQ on %p\n", conn);
                rc = lnet_parse(kranal_data.kra_ni, &msg->ram_u.putreq.raprm_hdr, 
                                msg->ram_srcnid, conn, 1);
                repost = rc < 0;
                break;

        case RANAL_MSG_PUT_NAK:
                CDEBUG(D_NET, "RX PUT_NAK on %p\n", conn);
                tx = kranal_match_reply(conn, RANAL_MSG_PUT_REQ,
                                        msg->ram_u.completion.racm_cookie);
                if (tx == NULL)
                        break;

                LASSERT (tx->tx_buftype == RANAL_BUF_PHYS_MAPPED ||
                         tx->tx_buftype == RANAL_BUF_VIRT_MAPPED);
                kranal_tx_done(tx, -ENOENT);    /* no match */
                break;

        case RANAL_MSG_PUT_ACK:
                CDEBUG(D_NET, "RX PUT_ACK on %p\n", conn);
                tx = kranal_match_reply(conn, RANAL_MSG_PUT_REQ,
                                        msg->ram_u.putack.rapam_src_cookie);
                if (tx == NULL)
                        break;

                kranal_rdma(tx, RANAL_MSG_PUT_DONE,
                            &msg->ram_u.putack.rapam_desc,
                            msg->ram_u.putack.rapam_desc.rard_nob,
                            msg->ram_u.putack.rapam_dst_cookie);
                break;

        case RANAL_MSG_PUT_DONE:
                CDEBUG(D_NET, "RX PUT_DONE on %p\n", conn);
                tx = kranal_match_reply(conn, RANAL_MSG_PUT_ACK,
                                        msg->ram_u.completion.racm_cookie);
                if (tx == NULL)
                        break;

                LASSERT (tx->tx_buftype == RANAL_BUF_PHYS_MAPPED ||
                         tx->tx_buftype == RANAL_BUF_VIRT_MAPPED);
                kranal_tx_done(tx, 0);
                break;

        case RANAL_MSG_GET_REQ:
                CDEBUG(D_NET, "RX GET_REQ on %p\n", conn);
                rc = lnet_parse(kranal_data.kra_ni, &msg->ram_u.get.ragm_hdr, 
                                msg->ram_srcnid, conn, 1);
                repost = rc < 0;
                break;

        case RANAL_MSG_GET_NAK:
                CDEBUG(D_NET, "RX GET_NAK on %p\n", conn);
                tx = kranal_match_reply(conn, RANAL_MSG_GET_REQ,
                                        msg->ram_u.completion.racm_cookie);
                if (tx == NULL)
                        break;

                LASSERT (tx->tx_buftype == RANAL_BUF_PHYS_MAPPED ||
                         tx->tx_buftype == RANAL_BUF_VIRT_MAPPED);
                kranal_tx_done(tx, -ENOENT);    /* no match */
                break;

        case RANAL_MSG_GET_DONE:
                CDEBUG(D_NET, "RX GET_DONE on %p\n", conn);
                tx = kranal_match_reply(conn, RANAL_MSG_GET_REQ,
                                        msg->ram_u.completion.racm_cookie);
                if (tx == NULL)
                        break;

                LASSERT (tx->tx_buftype == RANAL_BUF_PHYS_MAPPED ||
                         tx->tx_buftype == RANAL_BUF_VIRT_MAPPED);
#if 0
                /* completion message should send rdma length if we ever allow
                 * GET truncation */
                lnet_set_reply_msg_len(kranal_data.kra_ni, tx->tx_lntmsg[1], ???);
#endif
                kranal_tx_done(tx, 0);
                break;
        }

 out:
        if (rc < 0)                             /* protocol/comms error */
                kranal_close_conn (conn, rc);

        if (repost && conn->rac_rxmsg != NULL)
                kranal_consume_rxmsg(conn, NULL, 0);

        /* check again later */
        kranal_schedule_conn(conn);
}

void
kranal_complete_closed_conn (kra_conn_t *conn)
{
        kra_tx_t   *tx;
        int         nfma;
        int         nreplies;

        LASSERT (conn->rac_state == RANAL_CONN_CLOSED);
        LASSERT (cfs_list_empty(&conn->rac_list));
        LASSERT (cfs_list_empty(&conn->rac_hashlist));

        for (nfma = 0; !cfs_list_empty(&conn->rac_fmaq); nfma++) {
                tx = cfs_list_entry(conn->rac_fmaq.next, kra_tx_t, tx_list);

                cfs_list_del(&tx->tx_list);
                kranal_tx_done(tx, -ECONNABORTED);
        }

        LASSERT (cfs_list_empty(&conn->rac_rdmaq));

        for (nreplies = 0; !cfs_list_empty(&conn->rac_replyq); nreplies++) {
                tx = cfs_list_entry(conn->rac_replyq.next, kra_tx_t, tx_list);

                cfs_list_del(&tx->tx_list);
                kranal_tx_done(tx, -ECONNABORTED);
        }

        CWARN("Closed conn %p -> %s: nmsg %d nreplies %d\n",
               conn, libcfs_nid2str(conn->rac_peer->rap_nid), nfma, nreplies);
}

int kranal_process_new_conn (kra_conn_t *conn)
{
	RAP_RETURN   rrc;

	rrc = RapkCompleteSync(conn->rac_rihandle, 1);
	if (rrc == RAP_SUCCESS)
		return 0;

	LASSERT (rrc == RAP_NOT_DONE);
	if (!cfs_time_aftereq(jiffies, conn->rac_last_tx +
			      msecs_to_jiffies(conn->rac_timeout*MSEC_PER_SEC)))
		return -EAGAIN;

	/* Too late */
	rrc = RapkCompleteSync(conn->rac_rihandle, 0);
	LASSERT (rrc == RAP_SUCCESS);
	return -ETIMEDOUT;
}

int
kranal_scheduler (void *arg)
{
	kra_device_t     *dev = (kra_device_t *)arg;
	wait_queue_t    wait;
	kra_conn_t       *conn;
        unsigned long     flags;
        unsigned long     deadline;
        unsigned long     soonest;
        int               nsoonest;
        long              timeout;
        cfs_list_t       *tmp;
        cfs_list_t       *nxt;
        int               rc;
        int               dropped_lock;
        int               busy_loops = 0;

        cfs_block_allsigs();

	dev->rad_scheduler = current;
	init_waitqueue_entry_current(&wait);

	spin_lock_irqsave(&dev->rad_lock, flags);

        while (!kranal_data.kra_shutdown) {
                /* Safe: kra_shutdown only set when quiescent */

                if (busy_loops++ >= RANAL_RESCHED) {
			spin_unlock_irqrestore(&dev->rad_lock, flags);

			cond_resched();
			busy_loops = 0;

			spin_lock_irqsave(&dev->rad_lock, flags);
                }

                dropped_lock = 0;

                if (dev->rad_ready) {
                        /* Device callback fired since I last checked it */
                        dev->rad_ready = 0;
			spin_unlock_irqrestore(&dev->rad_lock, flags);
                        dropped_lock = 1;

                        kranal_check_rdma_cq(dev);
                        kranal_check_fma_cq(dev);

			spin_lock_irqsave(&dev->rad_lock, flags);
                }

                cfs_list_for_each_safe(tmp, nxt, &dev->rad_ready_conns) {
                        conn = cfs_list_entry(tmp, kra_conn_t, rac_schedlist);

                        cfs_list_del_init(&conn->rac_schedlist);
                        LASSERT (conn->rac_scheduled);
                        conn->rac_scheduled = 0;
			spin_unlock_irqrestore(&dev->rad_lock, flags);
                        dropped_lock = 1;

                        kranal_check_fma_rx(conn);
                        kranal_process_fmaq(conn);

                        if (conn->rac_state == RANAL_CONN_CLOSED)
                                kranal_complete_closed_conn(conn);

                        kranal_conn_decref(conn);
			spin_lock_irqsave(&dev->rad_lock, flags);
                }

                nsoonest = 0;
                soonest = jiffies;

                cfs_list_for_each_safe(tmp, nxt, &dev->rad_new_conns) {
                        conn = cfs_list_entry(tmp, kra_conn_t, rac_schedlist);

                        deadline = conn->rac_last_tx + conn->rac_keepalive;
                        if (cfs_time_aftereq(jiffies, deadline)) {
                                /* Time to process this new conn */
				spin_unlock_irqrestore(&dev->rad_lock,
                                                           flags);
                                dropped_lock = 1;

                                rc = kranal_process_new_conn(conn);
                                if (rc != -EAGAIN) {
                                        /* All done with this conn */
					spin_lock_irqsave(&dev->rad_lock,
                                                              flags);
                                        cfs_list_del_init(&conn->rac_schedlist);
					spin_unlock_irqrestore(&dev-> \
                                                                   rad_lock,
                                                                   flags);

                                        kranal_conn_decref(conn);
					spin_lock_irqsave(&dev->rad_lock,
                                                              flags);
                                        continue;
                                }

				/* retry with exponential backoff until HZ */
				if (conn->rac_keepalive == 0)
					conn->rac_keepalive = 1;
				else if (conn->rac_keepalive <=
					 msecs_to_jiffies(MSEC_PER_SEC))
					conn->rac_keepalive *= 2;
				else
					conn->rac_keepalive +=
						msecs_to_jiffies(MSEC_PER_SEC);

				deadline = conn->rac_last_tx + conn->rac_keepalive;
				spin_lock_irqsave(&dev->rad_lock, flags);
                        }

                        /* Does this conn need attention soonest? */
                        if (nsoonest++ == 0 ||
                            !cfs_time_aftereq(deadline, soonest))
                                soonest = deadline;
                }

                if (dropped_lock)               /* may sleep iff I didn't drop the lock */
                        continue;

		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue_exclusive(&dev->rad_waitq, &wait);
		spin_unlock_irqrestore(&dev->rad_lock, flags);

		if (nsoonest == 0) {
			busy_loops = 0;
			waitq_wait(&wait, TASK_INTERRUPTIBLE);
		} else {
			timeout = (long)(soonest - jiffies);
			if (timeout > 0) {
				busy_loops = 0;
				waitq_timedwait(&wait,
						    TASK_INTERRUPTIBLE,
						    timeout);
			}
		}

		remove_wait_queue(&dev->rad_waitq, &wait);
		set_current_state(TASK_RUNNING);
		spin_lock_irqsave(&dev->rad_lock, flags);
	}

	spin_unlock_irqrestore(&dev->rad_lock, flags);

        dev->rad_scheduler = NULL;
        kranal_thread_fini();
        return 0;
}
