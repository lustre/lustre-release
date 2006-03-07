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
#include <libcfs/list.h>

void
kptllnd_peer_add_peertable_locked (kptl_peer_t *peer)
{
        LASSERT (kptllnd_data.kptl_npeers <
                 *kptllnd_tunables.kptl_concurrent_peers);
        LASSERT(peer->peer_state == PEER_STATE_ALLOCATED);

        peer->peer_state = PEER_STATE_WAITING_HELLO;
        atomic_inc(&peer->peer_refcount);       /* +1 ref for the list */

        list_add_tail(&peer->peer_list,
                      kptllnd_ptlnid2peerlist(peer->peer_ptlid.nid));
}

int
kptllnd_peer_allocate (kptl_peer_t **peerp, ptl_process_id_t ptlid) 
{
        unsigned long    flags;
        kptl_peer_t     *peer;
        int              rc;

        CDEBUG(D_NET, ">>> "FMT_NID"/%d\n", ptlid.nid, ptlid.pid);
        LASSERT (ptlid.nid != PTL_NID_ANY);

        write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        /* Only increase # peers under lock, to guarantee we don't overflow and
         * don't grow it during shutdown */

        if (kptllnd_data.kptl_shutdown ||
            kptllnd_data.kptl_npeers >= 
            *kptllnd_tunables.kptl_concurrent_peers) {
                rc = -EOVERFLOW;
        } else {
                rc = 0;
                kptllnd_data.kptl_npeers++;
        }

        write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        if (rc != 0)
                return rc;

        LIBCFS_ALLOC(peer, sizeof (*peer));
        if (peer == NULL) {
                CERROR("Cannot allocate memory for peer\n");
                rc = -ENOMEM;
                goto failed_0;
        }

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        INIT_LIST_HEAD (&peer->peer_sendq);
        INIT_LIST_HEAD (&peer->peer_activeq);
        spin_lock_init (&peer->peer_lock);

        peer->peer_state = PEER_STATE_ALLOCATED;
        peer->peer_nid = kptllnd_ptl2lnetnid(ptlid.nid);
        peer->peer_ptlid = ptlid;
        peer->peer_credits = 1;                 /* enough for HELLO */
        peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;
        peer->peer_outstanding_credits = *kptllnd_tunables.kptl_peercredits - 1;

        /*
         * Reserve space in the RX buffer pool for this new peer
         */
        rc = kptllnd_rx_buffer_pool_reserve(&kptllnd_data.kptl_rx_buffer_pool,
                                            *kptllnd_tunables.kptl_peercredits);
        if (rc != 0) {
                CERROR("Cannot reserve rx buffer pool space\n");
                goto failed_1;
        }

        atomic_set(&peer->peer_refcount, 1);    /* 1 ref for caller */

        CDEBUG(D_NET, "<<< Peer=%p nid=%s\n", 
               peer, libcfs_nid2str(peer->peer_nid));
        *peerp = peer;
        return 0;

 failed_1:
        LIBCFS_FREE(peer, sizeof (*peer));
 failed_0:
        write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        kptllnd_data.kptl_npeers--;
        write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        LASSERT (rc != 0);
        return rc;
}

void
kptllnd_peer_destroy (kptl_peer_t *peer)
{
        unsigned long flags;
        
        CDEBUG(D_NET, "Peer=%p\n", peer);

        LASSERT (!in_interrupt());
        LASSERT (atomic_read(&peer->peer_refcount) == 0);
        LASSERT (peer->peer_state == PEER_STATE_ALLOCATED ||
                 peer->peer_state == PEER_STATE_ZOMBIE);
        LASSERT (list_empty(&peer->peer_sendq));
        LASSERT (list_empty(&peer->peer_activeq));

        kptllnd_rx_buffer_pool_unreserve(&kptllnd_data.kptl_rx_buffer_pool,
                                         *kptllnd_tunables.kptl_peercredits);

        LIBCFS_FREE (peer, sizeof (*peer));

        write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        kptllnd_data.kptl_npeers--;
        write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);
}

void
kptllnd_peer_cancel_txs(kptl_peer_t *peer)
{
        struct list_head   sendq;
        struct list_head   activeq;
        struct list_head  *tmp;
        struct list_head  *nxt;
        kptl_tx_t         *tx;
        unsigned long      flags;

        /* atomically grab all the peer's tx-es... */

        spin_lock_irqsave(&peer->peer_lock, flags);

        list_add(&sendq, &peer->peer_sendq);
        list_del_init(&peer->peer_sendq);
        list_for_each (tmp, &sendq) {
                tx = list_entry(tmp, kptl_tx_t, tx_list);
                tx->tx_active = 0;
        }

        list_add(&activeq, &peer->peer_activeq);
        list_del_init(&peer->peer_activeq);
        list_for_each (tmp, &activeq) {
                tx = list_entry(tmp, kptl_tx_t, tx_list);
                tx->tx_active = 0;
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);

        /* ...then drop the peer's ref on them at leasure.  This will get
         * kptllnd_tx_fini() to abort outstanding comms if necessary. */

        list_for_each_safe (tmp, nxt, &sendq) {
                tx = list_entry(tmp, kptl_tx_t, tx_list);
                list_del(&tx->tx_list);
                tx->tx_status = -EIO;
                kptllnd_tx_decref(tx);
        }

        list_for_each_safe (tmp, nxt, &activeq) {
                tx = list_entry(tmp, kptl_tx_t, tx_list);
                list_del(&tx->tx_list);
                tx->tx_status = -EIO;
                kptllnd_tx_decref(tx);
        }
}

void
kptllnd_handle_closing_peers ()
{
        unsigned long           flags;
        kptl_peer_t            *peer;
        struct list_head        list;
        struct list_head       *tmp;
        struct list_head       *nxt;
        int                     idle;

        /* Check with a read lock first to prevent blocking anyone */

        read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        idle = list_empty(&kptllnd_data.kptl_closing_peers);
        read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        if (idle)
                return;

        /* Grab all the cancelled peers atomically... */

        write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
        
        list_add(&list, &kptllnd_data.kptl_closing_peers);
        list_del_init(&kptllnd_data.kptl_closing_peers);
        
        write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        /* ...and clear comms at leasure... */
        
        list_for_each_safe (tmp, nxt, &list) {
                peer = list_entry (tmp, kptl_peer_t, peer_list);

                LASSERT (peer->peer_state == PEER_STATE_CLOSING);

                /* Change peer state to allow it to be scheduled to me again
                 * (PtlMDUnlink may have to be retried with non-lustre unlink
                 * semantics) */

                list_del(&peer->peer_list); /* not strictly necessary (think about it) */
                
                write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);
                peer->peer_state = PEER_STATE_ZOMBIE;
                write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

                kptllnd_peer_cancel_txs(peer);
                kptllnd_peer_decref(peer);
        }

        read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);
}

void
kptllnd_peer_close(kptl_peer_t *peer)
{
        unsigned long      flags;

        write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        LASSERT (peer->peer_state == PEER_STATE_WAITING_HELLO ||
                 peer->peer_state == PEER_STATE_ACTIVE ||
                 peer->peer_state == PEER_STATE_CLOSING ||
                 peer->peer_state == PEER_STATE_ZOMBIE);

        if (peer->peer_state != PEER_STATE_CLOSING) {

                if (peer->peer_state != PEER_STATE_ZOMBIE)
                        list_del(&peer->peer_list);

                list_add_tail(&peer->peer_list, 
                              &kptllnd_data.kptl_closing_peers);

                /* Wait for the next timeout if already a zombie */
                if (peer->peer_state != PEER_STATE_ZOMBIE)
                        wake_up(&kptllnd_data.kptl_watchdog_waitq);

                peer->peer_state = PEER_STATE_CLOSING;
        }

        write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);
}

int
kptllnd_peer_del(lnet_nid_t nid)
{
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        kptl_peer_t       *peer;
        int                lo;
        int                hi;
        int                i;
        unsigned long      flags;
        int                rc = -ENOENT;

        CDEBUG(D_NET, ">>> NID="LPX64"\n", nid);

        /*
         * Find the single bucket we are supposed to look at or if nid is a
         * wildcard (LNET_NID_ANY) then look at all of the buckets
         */
        if (nid != LNET_NID_ANY) {
                ptl_nid_t         ptlnid = kptllnd_lnet2ptlnid(nid);
                struct list_head *l = kptllnd_ptlnid2peerlist(ptlnid);
                
                lo = hi =  l - kptllnd_data.kptl_peers;
        } else {
                lo = 0;
                hi = kptllnd_data.kptl_peer_hash_size - 1;
        }

again:
        read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kptllnd_data.kptl_peers[i]) {
                        peer = list_entry (ptmp, kptl_peer_t, peer_list);

                        /*
                         * Is this the right one?
                         */
                        if (!(nid == LNET_NID_ANY || peer->peer_nid == nid))
                                continue;

                        kptllnd_peer_addref(peer); /* 1 ref for me... */

                        read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock,
                                               flags);

                        kptllnd_peer_close(peer);
                        kptllnd_peer_decref(peer); /* ...until here */

                        rc = 0;         /* matched something */

                        /* start again now I've dropped the lock */
                        goto again;
                }
        }

        read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        CDEBUG(D_NET, "<<< rc=%d\n", rc);
        return (rc);
}

void
kptllnd_post_tx(kptl_peer_t *peer, kptl_tx_t *tx)
{
        /* CAVEAT EMPTOR: I take over caller's ref on 'tx' */
        ptl_handle_md_t  rdma_mdh = PTL_INVALID_HANDLE;
        ptl_handle_md_t  msg_mdh = PTL_INVALID_HANDLE;
        ptl_handle_me_t  meh;
        ptl_md_t         md;
        ptl_err_t        prc;
        unsigned long    flags;
        
        LASSERT (!tx->tx_idle);
        LASSERT (!tx->tx_active);
        LASSERT (PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));
        LASSERT (PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));
        LASSERT (tx->tx_type == TX_TYPE_SMALL_MESSAGE ||
                 tx->tx_type == TX_TYPE_PUT_REQUEST ||
                 tx->tx_type == TX_TYPE_GET_REQUEST);

        kptllnd_set_tx_peer(tx, peer);

        if (tx->tx_type == TX_TYPE_PUT_REQUEST ||
            tx->tx_type == TX_TYPE_GET_REQUEST) {

                spin_lock_irqsave(&peer->peer_lock, flags);
        
                if (peer->peer_next_matchbits < PTL_RESERVED_MATCHBITS)
                        peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;

                tx->tx_msg->ptlm_u.rdma.kptlrm_matchbits =
                        peer->peer_next_matchbits++;
                        
                spin_unlock_irqrestore(&peer->peer_lock, flags);

                prc = PtlMEAttach(kptllnd_data.kptl_nih,
                                  *kptllnd_tunables.kptl_portal,
                                  peer->peer_ptlid,
                                  tx->tx_msg->ptlm_u.rdma.kptlrm_matchbits,
                                  0,             /* ignore bits */
                                  PTL_UNLINK,
                                  PTL_INS_BEFORE,
                                  &meh);
                if (prc != PTL_OK) {
                        CERROR("PtlMEAttach(%s) failed: %d\n",
                               libcfs_nid2str(peer->peer_nid), prc);
                        goto failed;
                }

                prc = PtlMDAttach(meh, tx->tx_rdma_md, PTL_UNLINK, &rdma_mdh);
                if (prc != PTL_OK) {
                        CERROR("PtlMDAttach(%s) failed: %d\n",
                               libcfs_nid2str(tx->tx_peer->peer_nid), prc);
                        prc = PtlMEUnlink(meh);
                        LASSERT(prc == PTL_OK);
                        rdma_mdh = PTL_INVALID_HANDLE;
                        goto failed;
                }

                /* I'm not racing with the event callback here.  It's a bug if
                 * there's an event on the MD I just attached before I actually
                 * send the RDMA request message which the event callback
                 * catches by asserting 'rdma_mdh' is valid. */
        }

        memset(&md, 0, sizeof(md));
        
        md.start = tx->tx_msg;
        md.length = tx->tx_msg->ptlm_nob;
        md.threshold = 1;
        md.options = PTL_MD_OP_PUT |
                     PTL_MD_LUSTRE_COMPLETION_SEMANTICS |
                     PTL_MD_EVENT_START_DISABLE;
        md.user_ptr = &tx->tx_msg_eventarg;
        md.eq_handle = kptllnd_data.kptl_eqh;

        prc = PtlMDBind(kptllnd_data.kptl_nih, md, PTL_UNLINK, &msg_mdh);
        if (prc != PTL_OK) {
                msg_mdh = PTL_INVALID_HANDLE;
                goto failed;
        }
        
        spin_lock_irqsave(&peer->peer_lock, flags);

        tx->tx_deadline = jiffies + (*kptllnd_tunables.kptl_timeout * HZ);
        tx->tx_active = 1;
        tx->tx_rdma_mdh = rdma_mdh;
        tx->tx_msg_mdh = msg_mdh;
        
        list_add_tail(&tx->tx_list, &peer->peer_sendq);

        spin_unlock_irqrestore(&peer->peer_lock, flags);
        return;
        
 failed:
        spin_lock_irqsave(&peer->peer_lock, flags);

        tx->tx_status = -EIO;
        tx->tx_rdma_mdh = rdma_mdh;
        tx->tx_msg_mdh = msg_mdh;

        spin_unlock_irqrestore(&peer->peer_lock, flags);

        kptllnd_tx_decref(tx);
}

void
kptllnd_peer_check_sends (kptl_peer_t *peer)
{

        kptl_tx_t       *tx;
        int              rc;
        unsigned long    flags;

        LASSERT(!in_interrupt());

        spin_lock_irqsave(&peer->peer_lock, flags);

        if (list_empty(&peer->peer_sendq) &&
            peer->peer_outstanding_credits >= PTLLND_CREDIT_HIGHWATER) {

                /* post a NOOP to return credits */
                spin_unlock_irqrestore(&peer->peer_lock, flags);

                tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
                if (tx == NULL) {
                        CERROR("Can't return credits to %s: tx descs exhausted\n",
                               libcfs_nid2str(peer->peer_nid));
                } else {
                        kptllnd_init_msg(tx->tx_msg, PTLLND_MSG_TYPE_NOOP, 0);
                        kptllnd_post_tx(peer, tx);
                }

                spin_lock_irqsave(&peer->peer_lock, flags);
        }

        while (!list_empty(&peer->peer_sendq)) {
                tx = list_entry (peer->peer_sendq.next, kptl_tx_t, tx_list);

                LASSERT (tx->tx_active);
                LASSERT (!PtlHandleIsEqual(tx->tx_msg_mdh, PTL_INVALID_HANDLE));
                LASSERT (tx->tx_type == TX_TYPE_SMALL_MESSAGE ||
                         !PtlHandleIsEqual(tx->tx_rdma_mdh, PTL_INVALID_HANDLE));

                LASSERT (peer->peer_outstanding_credits >= 0);
                LASSERT (peer->peer_outstanding_credits <= 
                         *kptllnd_tunables.kptl_peercredits);
                LASSERT (peer->peer_credits >= 0);
                LASSERT (peer->peer_credits <= 
                         *kptllnd_tunables.kptl_peercredits);

                if (peer->peer_credits == 0) {
                        CDEBUG(D_NET, "%s: no credits\n",
                               libcfs_nid2str(peer->peer_nid));
                        break;
                }

                /* Don't use the last credit unless I've got credits to
                 * return */
                if (peer->peer_credits == 1 &&
                    peer->peer_outstanding_credits == 0) {
                        CDEBUG(D_NET, "%s: not using last credit\n",
                               libcfs_nid2str(peer->peer_nid));
                        break;
                }

                list_del(&tx->tx_list);

                /* Discard any NOOP I queued if I'm not at the high-water mark
                 * any more or more messages have been queued */
                if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_NOOP &&
                    (!list_empty(&peer->peer_sendq) ||
                     peer->peer_outstanding_credits < PTLLND_CREDIT_HIGHWATER)) {

                        list_del(&tx->tx_list);
                        tx->tx_active = 0;

                        spin_unlock_irqrestore(&peer->peer_lock, flags);

                        CDEBUG(D_NET, "%s: redundant noop\n", 
                               libcfs_nid2str(peer->peer_nid));
                        kptllnd_tx_decref(tx);

                        spin_lock_irqsave(&peer->peer_lock, flags);
                        continue;
                }

                CDEBUG(D_NET, "tx=%p nob=%d to %s("FMT_NID"/%d)\n",
                       tx, tx->tx_msg->ptlm_nob,
                       libcfs_nid2str(peer->peer_nid), 
                       peer->peer_ptlid.nid, peer->peer_ptlid.pid);

                /* fill last-minute msg header fields */
                kptllnd_msg_pack(tx->tx_msg,
                                 peer->peer_outstanding_credits,
                                 peer->peer_nid,
                                 peer->peer_incarnation,
                                 peer->peer_tx_seqnum++);

                peer->peer_outstanding_credits = 0;
                peer->peer_credits--;

                list_add_tail(&tx->tx_list, &peer->peer_activeq);

                kptllnd_tx_addref(tx);          /* 1 ref for me... */

                spin_unlock_irqrestore(&peer->peer_lock, flags);

                if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_HELLO &&
                    the_lnet.ln_testprotocompat != 0) {
                        /* single-shot proto test */
                        LNET_LOCK();
                        if ((the_lnet.ln_testprotocompat & 1) != 0) {
                                tx->tx_msg->ptlm_version++;
                                the_lnet.ln_testprotocompat &= ~1;
                        }
                        if ((the_lnet.ln_testprotocompat & 2) != 0) {
                                tx->tx_msg->ptlm_magic = LNET_PROTO_MAGIC;
                                the_lnet.ln_testprotocompat &= ~2;
                        }
                        LNET_UNLOCK();
                }

                rc = PtlPut (tx->tx_msg_mdh,
                             PTL_NOACK_REQ,
                             peer->peer_ptlid,
                             *kptllnd_tunables.kptl_portal,
                             0,                 /* acl cookie */
                             LNET_MSG_MATCHBITS,
                             0,                 /* offset */
                             0);                /* header data */
                if (rc != PTL_OK) {
                        CERROR("PtlPut %s error %d\n",
                               libcfs_nid2str(peer->peer_nid), rc);

                        /* Nuke everything (including this tx) */
                        kptllnd_peer_close(peer);
                        return;
                }

                kptllnd_tx_decref(tx);          /* drop my ref */

                spin_lock_irqsave(&peer->peer_lock, flags);
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);
}

int
kptllnd_peer_timedout(kptl_peer_t *peer)
{
        kptl_tx_t         *tx;
        struct list_head  *tmp;
        unsigned long      flags;

        spin_lock_irqsave(&peer->peer_lock, flags);

        list_for_each(tmp, &peer->peer_sendq) {
                tx = list_entry(peer->peer_sendq.next, kptl_tx_t, tx_list);

                if (time_after_eq(jiffies, tx->tx_deadline)) {
                        spin_unlock_irqrestore(&peer->peer_lock, flags);
                        return 1;
                }
        }

        list_for_each(tmp, &peer->peer_activeq) {
                tx = list_entry(peer->peer_activeq.next, kptl_tx_t, tx_list);

                if (time_after_eq(jiffies, tx->tx_deadline)) {
                        spin_unlock_irqrestore(&peer->peer_lock, flags);
                        return 1;
                }
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);
        return 0;
}


void
kptllnd_peer_check_bucket (int idx)
{
        struct list_head  *peers = &kptllnd_data.kptl_peers[idx];
        struct list_head  *ptmp;
        kptl_peer_t       *peer;
        unsigned long      flags;


        CDEBUG(D_NET, "Bucket=%d\n", idx);

 again:
        /* NB. Shared lock while I just look */
        read_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        list_for_each (ptmp, peers) {
                peer = list_entry (ptmp, kptl_peer_t, peer_list);

                CDEBUG(D_NET, "Peer=%s Credits=%d Outstanding=%d\n",
                       libcfs_nid2str(peer->peer_nid),
                       peer->peer_credits, peer->peer_outstanding_credits);

                /* In case we have enough credits to return via a
                 * NOOP, but there were no non-blocking tx descs
                 * free to do it last time... */
                kptllnd_peer_check_sends(peer);

                if (!kptllnd_peer_timedout(peer))
                        continue;

                kptllnd_peer_addref(peer); /* 1 ref for me... */

                read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock,
                                       flags);

                CERROR("Timing out communications with %s: "
                       "cred %d outstanding %d \n",
                       libcfs_nid2str(peer->peer_nid),
                       peer->peer_credits, peer->peer_outstanding_credits);

                kptllnd_peer_close(peer);
                kptllnd_peer_decref(peer); /* ...until here */

                /* start again now I've dropped the lock */
                goto again;
        }

        read_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);
}

kptl_peer_t *
kptllnd_ptlnid2peer_locked (ptl_nid_t nid)
{
        struct list_head *peers = kptllnd_ptlnid2peerlist(nid);
        struct list_head *tmp;
        kptl_peer_t      *peer;

        list_for_each (tmp, peers) {

                peer = list_entry (tmp, kptl_peer_t, peer_list);

                LASSERT(peer->peer_state == PEER_STATE_WAITING_HELLO ||
                        peer->peer_state == PEER_STATE_ACTIVE);
                
                if (peer->peer_ptlid.nid != nid)
                        continue;

                kptllnd_peer_addref(peer);

                CDEBUG(D_NET, "got peer [%p] -> %s (%d)\n",
                       peer, libcfs_nid2str(peer->peer_nid), 
                       atomic_read (&peer->peer_refcount));
                return peer;
        }

        return NULL;
}

kptl_peer_t *
kptllnd_peer_handle_hello (ptl_process_id_t  initiator,
                           kptl_msg_t       *msg)
{
        kptl_peer_t    *peer           = NULL;
        kptl_peer_t    *new_peer       = NULL;
        kptl_peer_t    *peer_to_cancel = NULL;
        unsigned long   flags;
        kptl_tx_t      *hello_tx = NULL;
        int             rc;
        __u64           safe_matchbits_from_peer;
        __u64           safe_matchbits_to_peer = 0;

        safe_matchbits_from_peer = msg->ptlm_u.hello.kptlhm_matchbits +
                        *kptllnd_tunables.kptl_peercredits;

        if (msg->ptlm_u.hello.kptlhm_max_msg_size !=
            *kptllnd_tunables.kptl_max_msg_size) {
                CERROR("max message size MUST be equal for all peers: "
                       "got %d expected %d\n",
                       msg->ptlm_u.hello.kptlhm_max_msg_size,
                       *kptllnd_tunables.kptl_max_msg_size);
                return NULL;
        }

        hello_tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
        if (hello_tx == NULL) {
                CERROR("Unable to allocate HELLO message for "FMT_NID"/%d\n",
                       initiator.nid, initiator.pid);
                return NULL;
        }

        kptllnd_init_msg(hello_tx->tx_msg, PTLLND_MSG_TYPE_HELLO,
                         sizeof(kptl_hello_msg_t));

        rc = kptllnd_peer_allocate(&new_peer, initiator);
        if (rc != 0) {
                kptllnd_tx_decref(hello_tx);
                CERROR("Failed to create peer for "FMT_NID"/%d\n",
                       initiator.nid, initiator.pid);
                return NULL;
        }

        write_lock_irqsave(&kptllnd_data.kptl_peer_rw_lock, flags);

        peer = kptllnd_ptlnid2peer_locked(initiator.nid);
        if (peer != NULL) {
                if (peer->peer_incarnation == 0) {
                        LASSERT(peer->peer_state == PEER_STATE_WAITING_HELLO);

                        peer->peer_state = PEER_STATE_ACTIVE;
                        peer->peer_incarnation = msg->ptlm_srcstamp;
                        peer->peer_next_matchbits = safe_matchbits_from_peer;
                        if (peer->peer_next_matchbits < PTL_RESERVED_MATCHBITS)
                                peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;

                } else {
                        CDEBUG(D_NET, "Peer %s reconnecting:"
                               "pid,stamp %d,"LPX64" (old %d,"LPX64")\n",
                               libcfs_nid2str(peer->peer_nid),
                               initiator.pid, msg->ptlm_srcstamp,
                               peer->peer_ptlid.pid, 
                               peer->peer_incarnation);
                                
                        safe_matchbits_to_peer =
                                peer->peer_last_matchbits_seen + 1 +
                                *kptllnd_tunables.kptl_peercredits;

                        peer_to_cancel = peer;
                        peer = NULL;

                }
        }

        if (peer == NULL) {
                hello_tx->tx_msg->ptlm_u.hello.kptlhm_matchbits =
                        safe_matchbits_to_peer;
                hello_tx->tx_msg->ptlm_u.hello.kptlhm_max_msg_size =
                        *kptllnd_tunables.kptl_max_msg_size;

                kptllnd_peer_add_peertable_locked(new_peer);

                peer = new_peer;
                new_peer = NULL;

                LASSERT(peer->peer_state == PEER_STATE_WAITING_HELLO);
                peer->peer_state = PEER_STATE_ACTIVE;

                /* NB We don't need to hold the peer->peer_lock because we
                 * haven't released the kptl_peer_rw_lock.  This prevents
                 * anyone else from getting a pointer to new_peer */

                peer->peer_incarnation = msg->ptlm_srcstamp;
                peer->peer_next_matchbits = safe_matchbits_from_peer;
                if (peer->peer_next_matchbits < PTL_RESERVED_MATCHBITS)
                        peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;

                peer->peer_last_matchbits_seen = safe_matchbits_to_peer;

                kptllnd_post_tx(peer, hello_tx);
                hello_tx = NULL;
        }

        write_unlock_irqrestore(&kptllnd_data.kptl_peer_rw_lock, flags);

        if (hello_tx != NULL)
                kptllnd_tx_decref(hello_tx);

        if (peer != NULL)
                kptllnd_peer_check_sends(peer);

        if (peer_to_cancel != NULL) {
                kptllnd_peer_close(peer_to_cancel);
                kptllnd_peer_decref(peer_to_cancel);
        }

        if (new_peer != NULL)
                kptllnd_peer_decref(new_peer);

        return peer;
}

void
kptllnd_tx_launch(kptl_tx_t *tx, lnet_process_id_t target)
{
        rwlock_t        *g_lock = &kptllnd_data.kptl_peer_rw_lock;
        kptl_peer_t     *peer;
        kptl_peer_t     *new_peer;
        kptl_tx_t       *hello_tx;
        unsigned long    flags;
        int              rc;
        ptl_process_id_t ptlid;

        LASSERT (tx->tx_lnet_msg != NULL);
        LASSERT (tx->tx_peer == NULL);

        /* I expect to find the peer... */
        peer = kptllnd_nid2peer(target.nid);

        if (peer == NULL) {
                hello_tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
                if (hello_tx == NULL) {
                        CERROR("Unable to allocate connect message for %s\n",
                               libcfs_id2str(target));
                        kptllnd_tx_decref(tx);
                        return;
                }

                hello_tx->tx_msg->ptlm_u.hello.kptlhm_matchbits = 0;
                hello_tx->tx_msg->ptlm_u.hello.kptlhm_max_msg_size =
                        *kptllnd_tunables.kptl_max_msg_size;
                kptllnd_init_msg(hello_tx->tx_msg, PTLLND_MSG_TYPE_HELLO,
                                 sizeof(kptl_hello_msg_t));

                /* Allocate a new peer (it's not active until its on the list) */
                CDEBUG(D_NET, "TX %p creating NEW PEER %s\n", 
                       tx, libcfs_id2str(target));

                ptlid.nid = kptllnd_lnet2ptlnid(target.nid);
                ptlid.pid = kptllnd_data.kptl_portals_id.pid;

                rc = kptllnd_peer_allocate(&new_peer, ptlid);
                if (rc != 0) {
                        CERROR("Failed to create peer %s: %d\n",
                               libcfs_id2str(target), rc);
                        kptllnd_tx_decref(tx);
                        kptllnd_tx_decref(hello_tx);
                }

                write_lock_irqsave(g_lock, flags);

                peer = kptllnd_nid2peer_locked(target.nid);
                if (peer != NULL) {
                        write_unlock_irqrestore(g_lock, flags);

                        kptllnd_peer_decref(new_peer);
                        kptllnd_tx_decref(hello_tx);
                } else {
                        kptllnd_peer_add_peertable_locked(new_peer);

                        write_unlock_irqrestore(g_lock, flags);
                        peer = new_peer;
                
                        /* Queue HELLO first: it will consume the single credit
                         * and the tx, enqueued below will block until I
                         * receive more credits */
                        kptllnd_post_tx(peer, hello_tx);
                }
        }

        kptllnd_post_tx(peer, tx);
        kptllnd_peer_check_sends(peer);
        kptllnd_peer_decref(peer);
}
