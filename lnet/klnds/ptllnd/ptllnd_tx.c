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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/ptllnd/ptllnd_tx.c
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 */

 #include "ptllnd.h"

void
kptllnd_free_tx(kptl_tx_t *tx)
{
        if (tx->tx_msg != NULL)
                LIBCFS_FREE(tx->tx_msg, sizeof(*tx->tx_msg));
                        
        if (tx->tx_frags != NULL)
                LIBCFS_FREE(tx->tx_frags, sizeof(*tx->tx_frags));

        LIBCFS_FREE(tx, sizeof(*tx));

        cfs_atomic_dec(&kptllnd_data.kptl_ntx);

        /* Keep the tunable in step for visibility */
        *kptllnd_tunables.kptl_ntx = cfs_atomic_read(&kptllnd_data.kptl_ntx);
}

kptl_tx_t *
kptllnd_alloc_tx(void)
{
        kptl_tx_t       *tx;

        LIBCFS_ALLOC(tx, sizeof(*tx));
        if (tx == NULL) {
                CERROR("Failed to allocate TX\n");
                return NULL;
        }

        cfs_atomic_inc(&kptllnd_data.kptl_ntx);

        /* Keep the tunable in step for visibility */
        *kptllnd_tunables.kptl_ntx = cfs_atomic_read(&kptllnd_data.kptl_ntx);

        tx->tx_idle = 1;
        tx->tx_rdma_mdh = PTL_INVALID_HANDLE;
        tx->tx_msg_mdh = PTL_INVALID_HANDLE;
        tx->tx_rdma_eventarg.eva_type = PTLLND_EVENTARG_TYPE_RDMA;
        tx->tx_msg_eventarg.eva_type = PTLLND_EVENTARG_TYPE_MSG;
        tx->tx_msg = NULL;
        tx->tx_peer = NULL;
        tx->tx_frags = NULL;
                
        LIBCFS_ALLOC(tx->tx_msg, sizeof(*tx->tx_msg));
        if (tx->tx_msg == NULL) {
                CERROR("Failed to allocate TX payload\n");
                goto failed;
        }

        LIBCFS_ALLOC(tx->tx_frags, sizeof(*tx->tx_frags));
        if (tx->tx_frags == NULL) {
                CERROR("Failed to allocate TX frags\n");
                goto failed;
        }

        return tx;

 failed:
        kptllnd_free_tx(tx);
        return NULL;
}

int
kptllnd_setup_tx_descs()
{
        int       n = *kptllnd_tunables.kptl_ntx;
        int       i;

        for (i = 0; i < n; i++) {
                kptl_tx_t *tx = kptllnd_alloc_tx();
                if (tx == NULL)
                        return -ENOMEM;

		spin_lock(&kptllnd_data.kptl_tx_lock);
                cfs_list_add_tail(&tx->tx_list, &kptllnd_data.kptl_idle_txs);
		spin_unlock(&kptllnd_data.kptl_tx_lock);
        }

        return 0;
}

void
kptllnd_cleanup_tx_descs()
{
        kptl_tx_t       *tx;

        /* No locking; single threaded now */
        LASSERT (kptllnd_data.kptl_shutdown == 2);

        while (!cfs_list_empty(&kptllnd_data.kptl_idle_txs)) {
                tx = cfs_list_entry(kptllnd_data.kptl_idle_txs.next,
                                    kptl_tx_t, tx_list);

                cfs_list_del(&tx->tx_list);
                kptllnd_free_tx(tx);
        }

        LASSERT (cfs_atomic_read(&kptllnd_data.kptl_ntx) == 0);
}

kptl_tx_t *
kptllnd_get_idle_tx(enum kptl_tx_type type)
{
        kptl_tx_t      *tx = NULL;

        if (IS_SIMULATION_ENABLED(FAIL_TX_PUT_ALLOC) &&
            type == TX_TYPE_PUT_REQUEST) {
                CERROR("FAIL_TX_PUT_ALLOC SIMULATION triggered\n");
                return NULL;
        }

        if (IS_SIMULATION_ENABLED(FAIL_TX_GET_ALLOC) &&
            type == TX_TYPE_GET_REQUEST) {
                CERROR ("FAIL_TX_GET_ALLOC SIMULATION triggered\n");
                return NULL;
        }

        if (IS_SIMULATION_ENABLED(FAIL_TX)) {
                CERROR ("FAIL_TX SIMULATION triggered\n");
                return NULL;
        }

	spin_lock(&kptllnd_data.kptl_tx_lock);

        if (cfs_list_empty (&kptllnd_data.kptl_idle_txs)) {
		spin_unlock(&kptllnd_data.kptl_tx_lock);

                tx = kptllnd_alloc_tx();
                if (tx == NULL)
                        return NULL;
        } else {
                tx = cfs_list_entry(kptllnd_data.kptl_idle_txs.next, 
                                    kptl_tx_t, tx_list);
                cfs_list_del(&tx->tx_list);

		spin_unlock(&kptllnd_data.kptl_tx_lock);
        }

        LASSERT (cfs_atomic_read(&tx->tx_refcount)== 0);
        LASSERT (tx->tx_idle);
        LASSERT (!tx->tx_active);
        LASSERT (tx->tx_lnet_msg == NULL);
        LASSERT (tx->tx_lnet_replymsg == NULL);
        LASSERT (tx->tx_peer == NULL);
        LASSERT (PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));
        LASSERT (PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));
        
        tx->tx_type = type;
        cfs_atomic_set(&tx->tx_refcount, 1);
        tx->tx_status = 0;
        tx->tx_idle = 0;
        tx->tx_tposted = 0;
        tx->tx_acked = *kptllnd_tunables.kptl_ack_puts;

        CDEBUG(D_NET, "tx=%p\n", tx);
        return tx;
}

#ifdef LUSTRE_PORTALS_UNLINK_SEMANTICS
int
kptllnd_tx_abort_netio(kptl_tx_t *tx)
{
        kptl_peer_t     *peer = tx->tx_peer;
        ptl_handle_md_t  msg_mdh;
        ptl_handle_md_t  rdma_mdh;
        unsigned long    flags;

        LASSERT (cfs_atomic_read(&tx->tx_refcount) == 0);
        LASSERT (!tx->tx_active);

	spin_lock_irqsave(&peer->peer_lock, flags);

        msg_mdh = tx->tx_msg_mdh;
        rdma_mdh = tx->tx_rdma_mdh;

        if (PtlHandleIsEqual(msg_mdh, PTL_INVALID_HANDLE) &&
            PtlHandleIsEqual(rdma_mdh, PTL_INVALID_HANDLE)) {
		spin_unlock_irqrestore(&peer->peer_lock, flags);
                return 0;
        }
        
        /* Uncompleted comms: there must have been some error and it must be
         * propagated to LNET... */
        LASSERT (tx->tx_status != 0 ||
                 (tx->tx_lnet_msg == NULL && 
                  tx->tx_lnet_replymsg == NULL));

        /* stash the tx on its peer until it completes */
        cfs_atomic_set(&tx->tx_refcount, 1);
        tx->tx_active = 1;
        cfs_list_add_tail(&tx->tx_list, &peer->peer_activeq);
        
	spin_unlock_irqrestore(&peer->peer_lock, flags);

        /* These unlinks will ensure completion events (normal or unlink) will
         * happen ASAP */

        if (!PtlHandleIsEqual(msg_mdh, PTL_INVALID_HANDLE))
                PtlMDUnlink(msg_mdh);
        
        if (!PtlHandleIsEqual(rdma_mdh, PTL_INVALID_HANDLE))
                PtlMDUnlink(rdma_mdh);

        return -EAGAIN;
}
#else
int
kptllnd_tx_abort_netio(kptl_tx_t *tx)
{
        ptl_peer_t      *peer = tx->tx_peer;
        ptl_handle_md_t  msg_mdh;
        ptl_handle_md_t  rdma_mdh;
        unsigned long    flags;
        ptl_err_t        prc;

        LASSERT (cfs_atomic_read(&tx->tx_refcount) == 0);
        LASSERT (!tx->tx_active);

	spin_lock_irqsave(&peer->peer_lock, flags);

        msg_mdh = tx->tx_msg_mdh;
        rdma_mdh = tx->tx_rdma_mdh;

        if (PtlHandleIsEqual(msg_mdh, PTL_INVALID_HANDLE) &&
            PtlHandleIsEqual(rdma_mdh, PTL_INVALID_HANDLE)) {
		spin_unlock_irqrestore(&peer->peer_lock, flags);
                return 0;
        }
        
        /* Uncompleted comms: there must have been some error and it must be
         * propagated to LNET... */
        LASSERT (tx->tx_status != 0 ||
                 (tx->tx_lnet_msg == NULL && 
                  tx->tx_replymsg == NULL));

	spin_unlock_irqrestore(&peer->peer_lock, flags);

        if (!PtlHandleIsEqual(msg_mdh, PTL_INVALID_HANDLE)) {
                prc = PtlMDUnlink(msg_mdh);
                if (prc == PTL_OK)
                        msg_mdh = PTL_INVALID_HANDLE;
        }

        if (!PtlHandleIsEqual(rdma_mdh, PTL_INVALID_HANDLE)) {
                prc = PtlMDUnlink(rdma_mdh);
                if (prc == PTL_OK)
                        rdma_mdh = PTL_INVALID_HANDLE;
        }

	spin_lock_irqsave(&peer->peer_lock, flags);

        /* update tx_???_mdh if callback hasn't fired */
        if (PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE))
                msg_mdh = PTL_INVALID_HANDLE;
        else
                tx->tx_msg_mdh = msg_mdh;
        
        if (PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE))
                rdma_mdh = PTL_INVALID_HANDLE;
        else
                tx->tx_rdma_mdh = rdma_mdh;

        if (PtlHandleIsEqual(msg_mdh, PTL_INVALID_HANDLE) &&
            PtlHandleIsEqual(rdma_mdh, PTL_INVALID_HANDLE)) {
		spin_unlock_irqrestore(&peer->peer_lock, flags);
                return 0;
        }

        /* stash the tx on its peer until it completes */
        cfs_atomic_set(&tx->tx_refcount, 1);
        tx->tx_active = 1;
        cfs_list_add_tail(&tx->tx_list, &peer->peer_activeq);

        kptllnd_peer_addref(peer);              /* extra ref for me... */

	spin_unlock_irqrestore(&peer->peer_lock, flags);

        /* This will get the watchdog thread to try aborting all the peer's
         * comms again.  NB, this deems it fair that 1 failing tx which can't
         * be aborted immediately (i.e. its MDs are still busy) is valid cause
         * to nuke everything to the same peer! */
        kptllnd_peer_close(peer, tx->tx_status);

        kptllnd_peer_decref(peer);

        return -EAGAIN;
}
#endif

void
kptllnd_tx_fini (kptl_tx_t *tx)
{
        lnet_msg_t     *replymsg = tx->tx_lnet_replymsg;
        lnet_msg_t     *msg      = tx->tx_lnet_msg;
        kptl_peer_t    *peer     = tx->tx_peer;
        int             status   = tx->tx_status;
        int             rc;

        LASSERT (!cfs_in_interrupt());
        LASSERT (cfs_atomic_read(&tx->tx_refcount) == 0);
        LASSERT (!tx->tx_idle);
        LASSERT (!tx->tx_active);

        /* TX has completed or failed */

        if (peer != NULL) {
                rc = kptllnd_tx_abort_netio(tx);
                if (rc != 0)
                        return;
        }

        LASSERT (PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));
        LASSERT (PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));

        tx->tx_lnet_msg = tx->tx_lnet_replymsg = NULL;
        tx->tx_peer = NULL;
        tx->tx_idle = 1;

	spin_lock(&kptllnd_data.kptl_tx_lock);
        cfs_list_add_tail(&tx->tx_list, &kptllnd_data.kptl_idle_txs);
	spin_unlock(&kptllnd_data.kptl_tx_lock);

        /* Must finalize AFTER freeing 'tx' */
        if (msg != NULL)
                lnet_finalize(NULL, msg, (replymsg == NULL) ? status : 0);

        if (replymsg != NULL)
                lnet_finalize(NULL, replymsg, status);

        if (peer != NULL)
                kptllnd_peer_decref(peer);
}

const char *
kptllnd_tx_typestr(int type)
{
        switch (type) {
        default:
                return "<TYPE UNKNOWN>";
                
        case TX_TYPE_SMALL_MESSAGE:
                return "msg";

        case TX_TYPE_PUT_REQUEST:
                return "put_req";

        case TX_TYPE_GET_REQUEST:
                return "get_req";
                break;

        case TX_TYPE_PUT_RESPONSE:
                return "put_rsp";
                break;

        case TX_TYPE_GET_RESPONSE:
                return "get_rsp";
        }
}

void
kptllnd_tx_callback(ptl_event_t *ev)
{
        kptl_eventarg_t *eva = ev->md.user_ptr;
        int              ismsg = (eva->eva_type == PTLLND_EVENTARG_TYPE_MSG);
        kptl_tx_t       *tx = kptllnd_eventarg2obj(eva);
        kptl_peer_t     *peer = tx->tx_peer;
        int              ok = (ev->ni_fail_type == PTL_OK);
        int              unlinked;
        unsigned long    flags;

        LASSERT (peer != NULL);
        LASSERT (eva->eva_type == PTLLND_EVENTARG_TYPE_MSG ||
                 eva->eva_type == PTLLND_EVENTARG_TYPE_RDMA);
        LASSERT (!ismsg || !PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));
        LASSERT (ismsg || !PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));

#ifdef LUSTRE_PORTALS_UNLINK_SEMANTICS
        unlinked = ev->unlinked;
#else
        unlinked = (ev->type == PTL_EVENT_UNLINK);
#endif
        CDEBUG(D_NETTRACE, "%s[%d/%d+%d]: %s(%d) tx=%p fail=%s(%d) unlinked=%d\n",
               libcfs_id2str(peer->peer_id), peer->peer_credits,
               peer->peer_outstanding_credits, peer->peer_sent_credits,
               kptllnd_evtype2str(ev->type), ev->type, 
               tx, kptllnd_errtype2str(ev->ni_fail_type),
               ev->ni_fail_type, unlinked);

        switch (tx->tx_type) {
        default:
                LBUG();
                
        case TX_TYPE_SMALL_MESSAGE:
                LASSERT (ismsg);
                LASSERT (ev->type == PTL_EVENT_UNLINK ||
                         ev->type == PTL_EVENT_SEND_END ||
                         (ev->type == PTL_EVENT_ACK && tx->tx_acked));
                break;

        case TX_TYPE_PUT_REQUEST:
                LASSERT (ev->type == PTL_EVENT_UNLINK ||
                         (ismsg && ev->type == PTL_EVENT_SEND_END) ||
                         (ismsg && ev->type == PTL_EVENT_ACK && tx->tx_acked) ||
                         (!ismsg && ev->type == PTL_EVENT_GET_END));
                break;

        case TX_TYPE_GET_REQUEST:
                LASSERT (ev->type == PTL_EVENT_UNLINK ||
                         (ismsg && ev->type == PTL_EVENT_SEND_END) ||
                         (ismsg && ev->type == PTL_EVENT_ACK && tx->tx_acked) ||
                         (!ismsg && ev->type == PTL_EVENT_PUT_END));

                if (!ismsg && ok && ev->type == PTL_EVENT_PUT_END) {
                        if (ev->hdr_data == PTLLND_RDMA_OK) {
                                lnet_set_reply_msg_len(NULL,
                                        tx->tx_lnet_replymsg,
                                        ev->mlength);
                        } else {
                                /* no match at peer */
                                tx->tx_status = -EIO;
                        }
                }
                break;

        case TX_TYPE_PUT_RESPONSE:
                LASSERT (!ismsg);
                LASSERT (ev->type == PTL_EVENT_UNLINK ||
                         ev->type == PTL_EVENT_SEND_END ||
                         ev->type == PTL_EVENT_REPLY_END);
                break;

        case TX_TYPE_GET_RESPONSE:
                LASSERT (!ismsg);
                LASSERT (ev->type == PTL_EVENT_UNLINK ||
                         ev->type == PTL_EVENT_SEND_END ||
                         (ev->type == PTL_EVENT_ACK && tx->tx_acked));
                break;
        }

        if (ok) {
                kptllnd_peer_alive(peer);
        } else {
                CERROR("Portals error to %s: %s(%d) tx=%p fail=%s(%d) unlinked=%d\n",
                       libcfs_id2str(peer->peer_id),
                       kptllnd_evtype2str(ev->type), ev->type, 
                       tx, kptllnd_errtype2str(ev->ni_fail_type),
                       ev->ni_fail_type, unlinked);
                tx->tx_status = -EIO; 
                kptllnd_peer_close(peer, -EIO);
        }

        if (!unlinked)
                return;

	spin_lock_irqsave(&peer->peer_lock, flags);

        if (ismsg)
                tx->tx_msg_mdh = PTL_INVALID_HANDLE;
        else
                tx->tx_rdma_mdh = PTL_INVALID_HANDLE;

        if (!PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE) ||
            !PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE) ||
            !tx->tx_active) {
		spin_unlock_irqrestore(&peer->peer_lock, flags);
                return;
        }

        cfs_list_del(&tx->tx_list);
        tx->tx_active = 0;

	spin_unlock_irqrestore(&peer->peer_lock, flags);

        /* drop peer's ref, but if it was the last one... */
        if (cfs_atomic_dec_and_test(&tx->tx_refcount)) {
                /* ...finalize it in thread context! */
		spin_lock_irqsave(&kptllnd_data.kptl_sched_lock, flags);

                cfs_list_add_tail(&tx->tx_list, &kptllnd_data.kptl_sched_txq);
                cfs_waitq_signal(&kptllnd_data.kptl_sched_waitq);

		spin_unlock_irqrestore(&kptllnd_data.kptl_sched_lock,
                                           flags);
        }
}
