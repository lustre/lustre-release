/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   This file is confidential source code owned by Cluster File Systems.
 *   No viewing, modification, compilation, redistribution, or any other
 *   form of use is permitted except through a signed license agreement.
 *
 *   If you have not signed such an agreement, then you have no rights to
 *   this file.  Please destroy it immediately and contact CFS.
 *
 */

 #include "ptllnd.h"

void
kptllnd_free_tx(kptl_tx_t *tx)
{
        if (tx->tx_msg != NULL)
                LIBCFS_FREE(tx->tx_msg, 
                            *kptllnd_tunables.kptl_max_msg_size);
                        
        if (tx->tx_rdma_frags != NULL)
                LIBCFS_FREE(tx->tx_rdma_frags, 
                            sizeof(*tx->tx_rdma_frags));

        LIBCFS_FREE(tx, sizeof(*tx));

        atomic_dec(&kptllnd_data.kptl_ntx);

        /* Keep the tunable in step for visibility */
        *kptllnd_tunables.kptl_ntx = atomic_read(&kptllnd_data.kptl_ntx);
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

        atomic_inc(&kptllnd_data.kptl_ntx);

        /* Keep the tunable in step for visibility */
        *kptllnd_tunables.kptl_ntx = atomic_read(&kptllnd_data.kptl_ntx);

        tx->tx_idle = 1;
        tx->tx_rdma_mdh = PTL_INVALID_HANDLE;
        tx->tx_msg_mdh = PTL_INVALID_HANDLE;
        tx->tx_rdma_eventarg.eva_type = PTLLND_EVENTARG_TYPE_RDMA;
        tx->tx_msg_eventarg.eva_type = PTLLND_EVENTARG_TYPE_MSG;
        tx->tx_msg = NULL;
        tx->tx_rdma_frags = NULL;
                
        LIBCFS_ALLOC(tx->tx_msg, *kptllnd_tunables.kptl_max_msg_size);
        if (tx->tx_msg == NULL) {
                CERROR("Failed to allocate TX payload\n");
                goto failed;
        }

        LIBCFS_ALLOC(tx->tx_rdma_frags, sizeof(*tx->tx_rdma_frags));
        if (tx->tx_rdma_frags == NULL) {
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
                
                list_add_tail(&tx->tx_list, &kptllnd_data.kptl_idle_txs);
                
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

        while (!list_empty(&kptllnd_data.kptl_idle_txs)) {
                tx = list_entry(kptllnd_data.kptl_idle_txs.next,
                                kptl_tx_t, tx_list);
                
                list_del(&tx->tx_list);
                kptllnd_free_tx(tx);
        }

        LASSERT (atomic_read(&kptllnd_data.kptl_ntx) == 0);
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

        if (list_empty (&kptllnd_data.kptl_idle_txs)) {
                spin_unlock(&kptllnd_data.kptl_tx_lock);

                tx = kptllnd_alloc_tx();
                if (tx == NULL)
                        return NULL;
        } else {
                tx = list_entry(kptllnd_data.kptl_idle_txs.next, 
                                kptl_tx_t, tx_list);
                list_del(&tx->tx_list);

                spin_unlock(&kptllnd_data.kptl_tx_lock);
        }

        LASSERT (atomic_read(&tx->tx_refcount)== 0);
        LASSERT (tx->tx_idle);
        LASSERT (!tx->tx_active);
        LASSERT (tx->tx_lnet_msg == NULL);
        LASSERT (tx->tx_lnet_replymsg == NULL);
        LASSERT (tx->tx_peer == NULL);
        LASSERT (PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));
        LASSERT (PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));
        
        tx->tx_type = type;
        atomic_set(&tx->tx_refcount, 1);
        tx->tx_status = 0;
        tx->tx_idle = 0;

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

        LASSERT (atomic_read(&tx->tx_refcount) == 0);
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
        atomic_set(&tx->tx_refcount, 1);
        tx->tx_active = 1;
        list_add_tail(&tx->tx_list, &peer->peer_activeq);
        
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

        LASSERT (atomic_read(&tx->tx_refcount) == 0);
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
        atomic_set(&tx->tx_refcount, 1);
        tx->tx_active = 1;
        list_add_tail(&tx->tx_list, &peer->peer_activeq);

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

        LASSERT (!in_interrupt());
        LASSERT (atomic_read(&tx->tx_refcount) == 0);
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
        list_add_tail(&tx->tx_list, &kptllnd_data.kptl_idle_txs);
        spin_unlock(&kptllnd_data.kptl_tx_lock);

        /* Must finalize AFTER freeing 'tx' */
        if (msg != NULL)
                lnet_finalize(kptllnd_data.kptl_ni, msg,
                              (replymsg == NULL) ? status : 0);

        if (replymsg != NULL)
                lnet_finalize(kptllnd_data.kptl_ni, replymsg, status);

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
        CDEBUG(D_NETTRACE, "%s[%d/%d]: %s(%d) tx=%p fail=%d unlinked=%d\n",
               libcfs_id2str(peer->peer_id),
               peer->peer_credits, peer->peer_outstanding_credits,
               kptllnd_evtype2str(ev->type), ev->type, 
               tx, ev->ni_fail_type, unlinked);

        switch (tx->tx_type) {
        default:
                LBUG();
                
        case TX_TYPE_SMALL_MESSAGE:
                LASSERT (ismsg);
                LASSERT (ev->type == PTL_EVENT_UNLINK ||
                         ev->type == PTL_EVENT_SEND_END);
                break;

        case TX_TYPE_PUT_REQUEST:
                LASSERT (ev->type == PTL_EVENT_UNLINK ||
                         (ismsg && ev->type == PTL_EVENT_SEND_END) ||
                         (!ismsg && ev->type == PTL_EVENT_GET_END));
                break;

        case TX_TYPE_GET_REQUEST:
                LASSERT (ev->type == PTL_EVENT_UNLINK ||
                         (ismsg && ev->type == PTL_EVENT_SEND_END) ||
                         (!ismsg && ev->type == PTL_EVENT_PUT_END));

                if (!ismsg && ok && ev->type == PTL_EVENT_PUT_END) {
                        if (ev->hdr_data == PTLLND_RDMA_OK) {
                                lnet_set_reply_msg_len(
                                        kptllnd_data.kptl_ni,
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
                         ev->type == PTL_EVENT_SEND_END);
                break;
        }

        if (!ok)
                kptllnd_peer_close(peer, -EIO);
        else
                kptllnd_peer_alive(peer);

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

        list_del(&tx->tx_list);
        tx->tx_active = 0;

        spin_unlock_irqrestore(&peer->peer_lock, flags);

        /* drop peer's ref, but if it was the last one... */
        if (atomic_dec_and_test(&tx->tx_refcount)) {
                /* ...finalize it in thread context! */
                spin_lock_irqsave(&kptllnd_data.kptl_sched_lock, flags);

                list_add_tail(&tx->tx_list, &kptllnd_data.kptl_sched_txq);
                wake_up(&kptllnd_data.kptl_sched_waitq);

                spin_unlock_irqrestore(&kptllnd_data.kptl_sched_lock, flags);
        }
}
