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
kptllnd_peer_destroy (
        kptl_peer_t *peer);

int
kptllnd_peer_add_to_list_locked (
        kptl_data_t *kptllnd_data,
        kptl_peer_t *peer)
{
        /* QQQ - this got split out
         * But first check we haven't exceeded or maximum
         * number of peers
         */
        if (atomic_read(&kptllnd_data->kptl_npeers) >=
            *kptllnd_tunables.kptl_concurrent_peers) {
                STAT_UPDATE(kps_too_many_peers);
                CERROR("Can't create peer: too many peers\n");
                return -EOVERFLOW;      /* !! but at least it distinguishes */
        }

        /*
         * Update the state
         */
        LASSERT(peer->peer_state == PEER_STATE_ALLOCATED);
        peer->peer_state = PEER_STATE_WAITING_HELLO;

        /*
         * +1 ref for the list
         */
        atomic_inc(&peer->peer_refcount);

        /* npeers only grows with the global lock held */
        atomic_inc(&kptllnd_data->kptl_npeers);

        /* And add this to the list */
        LASSERT(list_empty(&peer->peer_list));
        list_add_tail (&peer->peer_list,
                       kptllnd_ptlnid2peerlist(kptllnd_data,peer->peer_ptlid.nid));

        STAT_UPDATE(kps_peers_created);

        return 0;
}

int
kptllnd_peer_allocate (kptl_data_t       *kptllnd_data,
                       kptl_peer_t      **peerp,
                       ptl_process_id_t   ptlid) 
{
        kptl_peer_t     *peer;
        int             rc;

        CDEBUG(D_NET, ">>> "FMT_NID"/%d\n", ptlid.nid, ptlid.pid);

        LASSERT (ptlid.nid != PTL_NID_ANY);

        LIBCFS_ALLOC(peer, sizeof (*peer));
        if (peer == NULL) {
                CERROR("Cannot allocate memory for peer\n");
                return -ENOMEM;
        }

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        INIT_LIST_HEAD (&peer->peer_list);       /* not in the peer table yet */
        INIT_LIST_HEAD (&peer->peer_pending_txs);
        INIT_LIST_HEAD (&peer->peer_active_txs);
        spin_lock_init (&peer->peer_lock);


        peer->peer_state = PEER_STATE_ALLOCATED;
        peer->peer_kptllnd_data = kptllnd_data;

        peer->peer_nid = ptl2lnetnid(kptllnd_data, ptlid.nid);
        peer->peer_ptlid = ptlid;

        //peer->peer_incarnation = 0;
        //peer->peer_tx_seqnum = 0;

        /*
         * Just enough to send the connect message
         */
        peer->peer_credits = 1;

        /*
         * We just posted this many buffers ready for the peer
         * to send into, so give back this many credits
         */
        peer->peer_outstanding_credits = *kptllnd_tunables.kptl_peercredits - 1;


        peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;
        //peer->peer_last_matchbits_seen = 0;

        /*
         * Reserve space in the RX buffer pool for this new peer
         */
        rc = kptllnd_rx_buffer_pool_reserve(
                &kptllnd_data->kptl_rx_buffer_pool,
                kptllnd_data,
                *kptllnd_tunables.kptl_peercredits);
        if(rc != 0){
                CERROR("Cannot reserve rx buffer pool space\n");
                LIBCFS_FREE(peer, sizeof (*peer));
                return rc;
        }

        /* QQQ - we're not adding to the list anymore
         * 1 for the caller
         */
        atomic_set (&peer->peer_refcount, 1);

        CDEBUG(D_NET, "<<< Peer=%p nid=%s\n", 
               peer, libcfs_nid2str(peer->peer_nid));
        *peerp = peer;
        return 0;
}


void
kptllnd_peer_destroy (
        kptl_peer_t *peer)
{
        kptl_data_t *kptllnd_data = peer->peer_kptllnd_data;

        CDEBUG(D_NET, "Peer=%p\n",peer);

        LASSERT (atomic_read (&peer->peer_refcount) == 0);
        /* Not on the peer list */
        LASSERT (list_empty (&peer->peer_list));
        /* No pending tx descriptors */
        LASSERT (list_empty (&peer->peer_pending_txs));
        /* No active tx descriptors */
        LASSERT (list_empty (&peer->peer_active_txs));

        LIBCFS_FREE (peer, sizeof (*peer));

        kptllnd_rx_buffer_pool_unreserve(
                &kptllnd_data->kptl_rx_buffer_pool,
                *kptllnd_tunables.kptl_peercredits);

        /*
         * If the peer is only in the ALLOCATED state
         * then it isn't yet trackied in kptl_npeers,
         * so do nothing in that case.  In all other cases
         * we need to decrement the counter.
         */
        if(peer->peer_state != PEER_STATE_ALLOCATED)
                atomic_dec(&kptllnd_data->kptl_npeers);
}


void
kptllnd_peer_addref (
        kptl_peer_t *peer,
        const char *owner)
{
        atomic_inc(&peer->peer_refcount);
}

void
kptllnd_peer_decref (
        kptl_peer_t *peer,
        const char *owner)
{
        unsigned long    flags;
        kptl_data_t     *kptllnd_data = peer->peer_kptllnd_data;

        if (!atomic_dec_and_test(&peer->peer_refcount))
                return;

        CDEBUG(D_NET, "peer=%p owner=%s LAST REF\n",peer,owner);

        write_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);
        list_del_init (&peer->peer_list);
        if (peer->peer_state == PEER_STATE_CANCELED)
                kptllnd_data->kptl_canceled_peers_counter++;
        write_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock, flags);

        kptllnd_peer_destroy(peer);
}


void
kptllnd_peer_cancel_pending_txs(
        kptl_peer_t *peer)
{
        struct list_head   list;
        struct list_head  *tx_temp;
        struct list_head  *tx_next;
        kptl_tx_t         *tx;
        unsigned long      flags;


        INIT_LIST_HEAD (&list);

        /*
         * Tranfer all the PENDING TX's to a temporary list
         * while holding the peer lock
         */
        spin_lock_irqsave(&peer->peer_lock, flags);

        if(!list_empty(&peer->peer_pending_txs))
                CDEBUG(D_NET, "Clearing Pending TXs\n");

        list_for_each_safe (tx_temp, tx_next, &peer->peer_pending_txs) {
                tx = list_entry (tx_temp, kptl_tx_t, tx_list);

                list_del_init(&tx->tx_list);
                list_add(&tx->tx_list,&list);
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);

        /*
         * Now relese the refereces outside of the peer_lock
         */
        list_for_each_safe (tx_temp, tx_next, &list) {
                tx = list_entry (tx_temp, kptl_tx_t, tx_list);
                list_del_init(&tx->tx_list);
                kptllnd_tx_decref(tx);
        }
}

void
kptllnd_peer_cancel_active_txs(
        kptl_peer_t *peer)
{
        struct list_head  *iter;
        kptl_tx_t         *tx;
        ptl_err_t          ptl_rc;
        int                counter;
        unsigned long      flags;

        spin_lock_irqsave(&peer->peer_lock, flags);

        if(!list_empty(&peer->peer_active_txs))
                CDEBUG(D_NET, "Clearing Active TXs\n");

again:

        counter = peer->peer_active_txs_change_counter;

        list_for_each (iter, &peer->peer_active_txs) {
                tx = list_entry (iter, kptl_tx_t, tx_list);

                /*
                 * Hold onto one ref so we can make these
                 * unlink calls even though we have
                 * released the lock
                 */
                kptllnd_tx_addref(tx);

                spin_unlock_irqrestore(&peer->peer_lock, flags);


                /*
                 * Question:  Why is it safe to acces tx_mdh and tx_mdh
                 * outside the peer_lock.  We could be racing with
                 * tx_callback?
                 */

                if(!PtlHandleIsEqual(tx->tx_mdh_msg,PTL_INVALID_HANDLE)){
                        CDEBUG(D_NET, "Unlink mhd_msg\n");
                        LASSERT(atomic_read(&tx->tx_refcount)>1);
                        ptl_rc = PtlMDUnlink(tx->tx_mdh_msg);
#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                        if(ptl_rc == PTL_OK) {
                                tx->tx_mdh_msg = PTL_INVALID_HANDLE;
                                kptllnd_tx_decref(tx);
                        }
#endif
                }

                if(!PtlHandleIsEqual(tx->tx_mdh,PTL_INVALID_HANDLE)){
                        CDEBUG(D_NET, "Unlink mdh\n");
                        LASSERT(atomic_read(&tx->tx_refcount)>1);
                        ptl_rc = PtlMDUnlink(tx->tx_mdh);
#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                        if(ptl_rc == PTL_OK){
                                tx->tx_mdh = PTL_INVALID_HANDLE;
                                kptllnd_tx_decref(tx);
                        }
#endif
                }

                kptllnd_tx_decref(tx);

                spin_lock_irqsave(&peer->peer_lock, flags);

                /*
                 * If a change in the list has be detected
                 * go back to the beginning
                 */
                if( counter != peer->peer_active_txs_change_counter)
                        goto again;
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);
}

void
kptllnd_peer_cancel(
        kptl_peer_t *peer)
{
        kptl_data_t *kptllnd_data = peer->peer_kptllnd_data;
        unsigned long      flags;
        int                list_owns_ref=0;

        CDEBUG(D_NET, ">>> Peer=%p\n",peer);

        write_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);
        if(peer->peer_state != PEER_STATE_CANCELED){
                peer->peer_state = PEER_STATE_CANCELED;
                list_del_init(&peer->peer_list);
                list_add(&peer->peer_list,&kptllnd_data->kptl_canceled_peers);
                kptllnd_data->kptl_canceled_peers_counter++;
                list_owns_ref = 1;
        }
        write_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock, flags);


        /*
         * First cancel the pending and active TXs
         */
        kptllnd_peer_cancel_pending_txs(peer);
        kptllnd_peer_cancel_active_txs(peer);


        /* lose peerlist's ref as long as we haven't done
           this before */
        if(list_owns_ref)
                kptllnd_peer_decref(peer,"list");

        CDEBUG(D_NET, "<<< Peer=%p\n",peer);
}

int
kptllnd_peer_del (kptl_data_t *kptllnd_data, lnet_nid_t nid)
{
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        kptl_peer_t        *peer;
        int                lo;
        int                hi;
        int                i;
        unsigned long      flags;
        int                rc = -ENOENT;

        CDEBUG(D_NET, ">>> NID="LPX64"\n",nid);

        /*
         * Find the single bucket we are supposed to look at or if nid is a
         * wildcard (LNET_NID_ANY) then look at all of the buckets
         */
        if (nid != LNET_NID_ANY) {
                ptl_nid_t         ptlnid = lnet2ptlnid(kptllnd_data, nid);
                struct list_head *l = kptllnd_ptlnid2peerlist(kptllnd_data, ptlnid);
                
                lo = hi =  l - kptllnd_data->kptl_peers;
        } else {
                lo = 0;
                hi = kptllnd_data->kptl_peer_hash_size - 1;
        }

again:
        read_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kptllnd_data->kptl_peers[i]) {
                        peer = list_entry (ptmp, kptl_peer_t, peer_list);

                        /*
                         * Is this the right one?
                         */
                        if (!(nid == LNET_NID_ANY || peer->peer_nid == nid))
                                continue;

                        kptllnd_peer_addref(peer,"temp"); /* 1 ref for me... */

                        read_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock,
                                               flags);

                        kptllnd_peer_cancel(peer);
                        kptllnd_peer_decref(peer,"temp"); /* ...until here */

                        rc = 0;         /* matched something */

                        /* start again now I've dropped the lock */
                        goto again;
                }
        }

        read_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock, flags);

        CDEBUG(D_NET, "<<< rc=%d\n",rc);
        return (rc);
}

void
kptllnd_peer_queue_tx_locked (
        kptl_peer_t *peer,
        kptl_tx_t *tx)
{
        CDEBUG(D_NET, "Peer=%p TX=%p\n",peer,tx);

        LASSERT(peer->peer_state != PEER_STATE_CANCELED);
        LASSERT(tx->tx_state == TX_STATE_ALLOCATED);
        tx->tx_state = TX_STATE_WAITING_CREDITS;
        LASSERT(tx->tx_peer == NULL);

        kptllnd_peer_addref(peer,"tx");
        tx->tx_peer = peer;

        tx->tx_deadline = jiffies + (*kptllnd_tunables.kptl_timeout * HZ);
        list_add_tail(&tx->tx_list, &peer->peer_pending_txs);
}

void
kptllnd_peer_queue_bulk_rdma_tx_locked(
        kptl_peer_t *peer,
        kptl_tx_t *tx)
{
        CDEBUG(D_NET, "Peer=%p TX=%p\n",peer,tx);

        LASSERT(peer->peer_state != PEER_STATE_CANCELED);
        LASSERT(tx->tx_state == TX_STATE_ALLOCATED);
        tx->tx_state = TX_STATE_WAITING_RESPONSE;

        LASSERT(tx->tx_type == TX_TYPE_LARGE_PUT_RESPONSE ||
                tx->tx_type == TX_TYPE_LARGE_GET_RESPONSE);

        LASSERT(tx->tx_peer == NULL);
        kptllnd_peer_addref(peer,"tx");
        tx->tx_peer = peer;
        tx->tx_deadline = jiffies + (*kptllnd_tunables.kptl_timeout * HZ);

        list_add_tail(&tx->tx_list, &peer->peer_active_txs);
        peer->peer_active_txs_change_counter++;
}

void
kptllnd_peer_dequeue_tx_locked(
        kptl_peer_t *peer,
        kptl_tx_t *tx)
{
        list_del_init(&tx->tx_list);
        /*
         * The tx could be on the active list
         * or possibily the passive list.  Either way
         * we'll be safe an update the active txs list counter
         * (this counter only indicates change, and in this
         * case it's possible change, which is an acceptable
         * usage)
         */
        peer->peer_active_txs_change_counter++;
}

void
kptllnd_peer_dequeue_tx(
        kptl_peer_t *peer,
        kptl_tx_t *tx)
{
        unsigned long   flags;
        spin_lock_irqsave(&peer->peer_lock, flags);
        kptllnd_peer_dequeue_tx_locked(peer,tx);
        spin_unlock_irqrestore(&peer->peer_lock, flags);
}

void
kptllnd_peer_check_sends (
        kptl_peer_t *peer)
{

        kptl_tx_t       *tx;
        kptl_data_t     *kptllnd_data = peer->peer_kptllnd_data;
        int              rc,rc2;
        ptl_md_t         md;
        ptl_handle_me_t  meh;
        ptl_handle_md_t  mdh;
        ptl_handle_md_t  mdh_msg;
        unsigned long    flags;

        LASSERT(!in_interrupt());

        /*
         * If there is nothing to send, and we have hit the credit
         * high water mark, then send a no-op message
         */
        spin_lock_irqsave(&peer->peer_lock, flags);

        CDEBUG(D_NET, ">>>Peer=%p Credits=%d Outstanding=%d\n",
                peer,peer->peer_credits,peer->peer_outstanding_credits);

        if(list_empty(&peer->peer_pending_txs) &&
           peer->peer_outstanding_credits >= PTLLND_CREDIT_HIGHWATER) {

                /*
                 * Get an idle tx descriptor
                 */
                tx = kptllnd_get_idle_tx(kptllnd_data,TX_TYPE_SMALL_MESSAGE);
                if( tx == NULL ) {
                        CERROR("Can't return credits to %s: tx descs exhausted\n",
                               libcfs_nid2str(peer->peer_nid));
                }else{
                        kptllnd_init_msg(tx->tx_msg, PTLLND_MSG_TYPE_NOOP,0);
                        kptllnd_peer_queue_tx_locked(peer,tx);
                        STAT_UPDATE(kps_sending_credits_back_noop_msg);
                }
        }
        /*
         * Now go through all the sends to see what we can send
         */
        while(!list_empty(&peer->peer_pending_txs)) {
                tx = list_entry (peer->peer_pending_txs.next, kptl_tx_t, tx_list);

                LASSERT (tx->tx_state == TX_STATE_WAITING_CREDITS);
                LASSERT (peer->peer_outstanding_credits >= 0);
                LASSERT (peer->peer_outstanding_credits <= *kptllnd_tunables.kptl_peercredits);
                LASSERT (peer->peer_credits >= 0);
                LASSERT (peer->peer_credits <= *kptllnd_tunables.kptl_peercredits);

                /*
                 * If there are no credits we're done
                 */
                if (peer->peer_credits == 0) {
                        STAT_UPDATE(kps_no_credits);
                        CDEBUG(D_NET, "%s: no credits\n",
                               libcfs_nid2str(peer->peer_nid));
                        break;
                }


                /*
                 * If there is one credit but we have no credits to give
                 * back then we don't use our one credit and we are done
                 */
                if (peer->peer_credits == 1 &&
                    peer->peer_outstanding_credits == 0) {
                        STAT_UPDATE(kps_saving_last_credit);
                        CDEBUG(D_NET, "%s: not using last credit\n",
                               libcfs_nid2str(peer->peer_nid));
                        break;
                }

                /*
                 * Remove the tx from the list.  We don't decrement the
                 * ref count here.  The reference is simply transferred from
                 * the Peer to this calling function, and it will be this
                 * functions responsibility to dispose of the reference properly
                 */
                list_del_init(&tx->tx_list);

                /*
                 * If there is a NOOP in the queue but there
                 * are pending tx buffers also in the queue
                 *
                 * OR we are not at the high-water mark anymore
                 *
                 * THEN it is safe to simply discard this NOOP
                 * and continue one.
                 *
                 * NOTE: We can't be holding the lock while calling
                 * kptllnd_tx_decref because that will call lnet_finalize()
                 * which can not be called while loding a lock.
                 */
                if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_NOOP &&
                    (!list_empty(&peer->peer_pending_txs) ||
                     peer->peer_outstanding_credits < PTLLND_CREDIT_HIGHWATER)) {
                        spin_unlock_irqrestore(&peer->peer_lock, flags);
                        /* redundant NOOP */
                        kptllnd_tx_decref(tx);
                        CDEBUG(D_NET, "%s: redundant noop\n",
                               libcfs_nid2str(peer->peer_nid));
                        spin_lock_irqsave(&peer->peer_lock, flags);
                        continue;
                }

                CDEBUG(D_NET, "--- TXTXTXTXTXTXTXTXTXTXTXTXTXTX\n");
                CDEBUG(D_NET, "Sending TX=%p Size=%d\n",tx,tx->tx_msg->ptlm_nob);
                CDEBUG(D_NET, "Target nid=%s ptl "FMT_NID"/%d\n",
                       libcfs_nid2str(peer->peer_nid), 
                       peer->peer_ptlid.nid, peer->peer_ptlid.pid);

                mdh = PTL_INVALID_HANDLE;
                mdh_msg =PTL_INVALID_HANDLE;

                /*
                 * Assign matchbits for a put/get
                 */
                if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_PUT ||
                    tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_GET) {

                        CDEBUG(D_NET, "next matchbits="LPX64" (before)\n",
                                peer->peer_next_matchbits);


                        /* Allocate a new match bits value.  It might not be needed,
                         * but we've got a lock right now and we're unlikely to
                         * wrap...
                         *
                         * A set of match bits at the low end are reserved.  So we can
                         * not use them.  Just skip over them.  This check protects us
                         * even in the case of 64-bit rollover.
                         */
                        if (peer->peer_next_matchbits < PTL_RESERVED_MATCHBITS) {
                                CDEBUG(D_INFO,"Match Bits Rollover for %s\n",
                                       libcfs_nid2str(peer->peer_nid));
                                peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;
                        }

                        /*
                         * Set the payload match bits and update the peer's counter
                         */
                        tx->tx_msg->ptlm_u.req.kptlrm_matchbits =
                                peer->peer_next_matchbits ++;

                        CDEBUG(D_NET, "next matchbits="LPX64" (after)\n",
                                peer->peer_next_matchbits);
                }

                /*
                 * Complete the message fill in all the rest
                 * of the header
                 */
                kptllnd_msg_pack(tx->tx_msg,
                                 peer->peer_outstanding_credits,
                                 peer->peer_nid,
                                 peer->peer_incarnation,
                                 peer->peer_tx_seqnum,
                                 kptllnd_data);
                /*
                 * We just sent a packet
                 */
                peer->peer_tx_seqnum++;

                /*
                 * And we've returned all of our credits
                 */
                peer->peer_outstanding_credits = 0;

                /*
                 * And we have one less credit :-(
                 */
                peer->peer_credits--;

                spin_unlock_irqrestore(&peer->peer_lock, flags);


                /*
                 * Set the state before the PtlPut() because
                 * we could get the PUT_END callback before PtlPut()
                 * returns.
                 */
                LASSERT(tx->tx_state == TX_STATE_WAITING_CREDITS);
                tx->tx_state = TX_STATE_WAITING_RESPONSE;

                /*
                 * Construct an address that Portals needs from the NID
                 */

                CDEBUG(D_NET, "Msg NOB = %d\n",tx->tx_msg->ptlm_nob);
                CDEBUG(D_NET, "Giving %d credits back to peer\n",
                       tx->tx_msg->ptlm_credits);
                CDEBUG(D_NET, "Seq # = "LPX64"\n",tx->tx_msg->ptlm_seq);

                CDEBUG(D_NET, "lnet TX %s\n", libcfs_nid2str(peer->peer_nid));
                CDEBUG(D_NET, "ptl  TX "FMT_NID"/%d\n",
                       peer->peer_ptlid.nid, peer->peer_ptlid.pid);

                if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_GET ||
                    tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_PUT) {
                        int       op;
                        
                        if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_PUT)
                                op = PTL_MD_OP_GET;
                        else
                                op = PTL_MD_OP_PUT;

                        CDEBUG(D_NET, "matchibts=" LPX64 "\n",
                                tx->tx_msg->ptlm_u.req.kptlrm_matchbits);

                        rc = PtlMEAttach(kptllnd_data->kptl_nih,
                                         *kptllnd_tunables.kptl_portal,
                                         peer->peer_ptlid,
                                         tx->tx_msg->ptlm_u.req.kptlrm_matchbits,
                                         0, /* ignore none */
                                         PTL_UNLINK,
                                         PTL_INS_BEFORE,
                                         &meh);
                        if (rc != PTL_OK) {
                                CERROR("PtlMeAttach failed %d\n",rc);
                                goto failed_without_lock;
                        }

                        /* Setup the MD */
                        kptllnd_setup_md(kptllnd_data, &md, op, tx,
                                         tx->tx_payload_niov,
                                         tx->tx_payload_iov,
                                         tx->tx_payload_kiov,
                                         tx->tx_payload_offset,
                                         tx->tx_payload_nob);

                        /*
                         * Add a ref for this MD, because unlink
                         * events can happen at any time once
                         * something is posted.
                         */
                        kptllnd_tx_addref(tx);

                        /*
                         * Attach the MD
                         */
                        rc = PtlMDAttach(
                                meh,
                                md,
                                PTL_UNLINK,
                                &mdh);
                        if(rc != 0){
                                CERROR("PtlMDAttach failed %d\n",rc);

                                /*
                                 * Just drop the ref for this MD because it was never
                                 * posted to portals
                                 */
                                kptllnd_tx_decref(tx);

                                rc2 = PtlMEUnlink(meh);
                                LASSERT(rc2 == 0);
                                goto failed_without_lock;
                        }
                        STAT_UPDATE(kps_posted_tx_bulk_mds);
                        
                } else if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_HELLO &&
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
                
                /*
                 * Setup the MD
                 */
                md.start = tx->tx_msg;
                md.length = tx->tx_msg->ptlm_nob;
                md.threshold = 1;
                md.options = PTL_MD_OP_PUT;
                md.options |= PTL_MD_LUSTRE_COMPLETION_SEMANTICS;
                md.options |= PTL_MD_EVENT_START_DISABLE;
                /* we don't need an ACK, we'll get a callback when the get is complete */
                md.options |= PTL_MD_ACK_DISABLE;
                md.user_ptr = tx;
                md.eq_handle = kptllnd_data->kptl_eqh;


                /*
                 * Bind the MD
                 */
                rc = PtlMDBind(kptllnd_data->kptl_nih, md,
                               PTL_UNLINK, &mdh_msg);
                if (rc != PTL_OK) {
                        if (!PtlHandleIsEqual(mdh,PTL_INVALID_HANDLE)) {
                                rc2 = PtlMDUnlink(mdh);
                                /*
                                 * The unlink should succeed
                                 */
                                LASSERT( rc2 == 0);
                         }
                        CERROR("PtlMDBind failed %d\n",rc);
                        goto failed_without_lock;
                }
                STAT_UPDATE(kps_posted_tx_msg_mds);

                spin_lock_irqsave(&peer->peer_lock, flags);

                /*
                 *  Assign the MDH's under lock
                 */
                LASSERT(PtlHandleIsEqual(tx->tx_mdh,PTL_INVALID_HANDLE));
                LASSERT(PtlHandleIsEqual(tx->tx_mdh_msg,PTL_INVALID_HANDLE));
#ifdef _USING_LUSTRE_PORTALS_
                CDEBUG(D_NET, "tx_mdh     = " LPX64 "\n",mdh.cookie);
                CDEBUG(D_NET, "tx_mdh_msg = " LPX64 "\n",mdh_msg.cookie);
#endif
                tx->tx_mdh = mdh;
                tx->tx_mdh_msg = mdh_msg;

                LASSERT (tx->tx_type != TX_TYPE_SMALL_MESSAGE ||
                         PtlHandleIsEqual(tx->tx_mdh,PTL_INVALID_HANDLE));

                list_add_tail(&tx->tx_list, &peer->peer_active_txs);
                peer->peer_active_txs_change_counter++;

                LASSERT (tx->tx_peer == peer);

                /*
                 * Grab a ref so the TX doesn't go away
                 * if we fail.
                 */
                kptllnd_tx_addref(tx);

                spin_unlock_irqrestore(&peer->peer_lock, flags);

                rc = PtlPut (tx->tx_mdh_msg,
                             PTL_NOACK_REQ,     /* we dont need an ack */
                             peer->peer_ptlid,  /* peer "address" */
                             *kptllnd_tunables.kptl_portal,     /* portal */
                             0,                 /* cookie */
                             LNET_MSG_MATCHBITS, /* match bits */
                             0,                 /* offset */
                             0);                /* header data */
                if (rc != PTL_OK) {
                        CERROR("PtlPut error %d\n",rc);
                        /*
                         * Do the unlink which should succeed
                         */
                        LASSERT(atomic_read(&tx->tx_refcount)>1);
                        rc2 = PtlMDUnlink(tx->tx_mdh_msg);
                        LASSERT( rc2 == 0);

#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                        tx->tx_mdh_msg = PTL_INVALID_HANDLE;
                        kptllnd_tx_decref(tx);
#endif
                        goto failed_without_lock;
                }

                /*
                 * Release our temporary reference
                 */
                kptllnd_tx_decref(tx);

                spin_lock_irqsave(&peer->peer_lock, flags);

        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);

        CDEBUG(D_NET, "<<<\n");
        return;

failed_without_lock:

        /*
         * Now unlink the MDs (if they were posted)
         */
        if(!PtlHandleIsEqual(tx->tx_mdh,PTL_INVALID_HANDLE)){
                LASSERT(atomic_read(&tx->tx_refcount)>1);
                rc2 = PtlMDUnlink(tx->tx_mdh);
                /*
                 * The unlink should succeed
                 */
                LASSERT( rc2 == 0);
#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                tx->tx_mdh = PTL_INVALID_HANDLE;
                kptllnd_tx_decref(tx);
#endif
        }

        /*
         * And cleanup this peer
         */
        kptllnd_peer_cancel(peer);

        /*
         * And release the tx reference
         */
        kptllnd_tx_decref(tx);

        CDEBUG(D_NET, "<<< FAILED\n");
}

int
kptllnd_peer_timedout(kptl_peer_t *peer)
{
        kptl_tx_t      *tx;
        int             rc = 0;
        unsigned long   flags;

        spin_lock_irqsave(&peer->peer_lock, flags);

        /*
         * Check the head of the pending list for expiration
         * this is a queue, so if the head isn't expired then nothing
         * else will be expired
         */
        if(!list_empty(&peer->peer_pending_txs)){
                tx = list_entry(peer->peer_pending_txs.next,kptl_tx_t,tx_list);
                if(time_after_eq(jiffies,tx->tx_deadline)){
                        CDEBUG(D_NET, "Peer=%p PENDING tx=%p time=%lu sec\n",
                                peer,tx,(jiffies - tx->tx_deadline)/HZ);
                        rc = 1;
                }
        }

        /*
         * Check the head of the active list
         */
        if(!list_empty(&peer->peer_active_txs)){
                tx = list_entry(peer->peer_active_txs.next,kptl_tx_t,tx_list);
                if(time_after_eq(jiffies,tx->tx_deadline)){
                        CDEBUG(D_NET, "Peer=%p ACTIVE tx=%p time=%lu sec\n",
                                peer,tx,(jiffies - tx->tx_deadline)/HZ);
                        rc = 1;
                }
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);
        return rc;
}


void
kptllnd_peer_check_bucket (int idx, kptl_data_t *kptllnd_data)
{
        struct list_head  *peers = &kptllnd_data->kptl_peers[idx];
        struct list_head  *ptmp;
        kptl_peer_t       *peer;
        unsigned long      flags;


        CDEBUG(D_INFO, "Bucket=%d\n",idx);

 again:
        /* NB. We expect to have a look at all the peers and not find any
         * rdmas to time out, so we just use a shared lock while we
         * take a look... */
        read_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);

        list_for_each (ptmp, peers) {
                peer = list_entry (ptmp, kptl_peer_t, peer_list);

                CDEBUG(D_NET, "Peer=%p Credits=%d Outstanding=%d\n",
                       peer,peer->peer_credits,peer->peer_outstanding_credits);

                /* In case we have enough credits to return via a
                 * NOOP, but there were no non-blocking tx descs
                 * free to do it last time... */
                kptllnd_peer_check_sends(peer);

                if (!kptllnd_peer_timedout(peer))
                        continue;

                kptllnd_peer_addref(peer,"temp"); /* 1 ref for me... */

                read_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock,
                                       flags);

                CERROR("Timed out communications with %s\n",
                       libcfs_nid2str(peer->peer_nid));

                kptllnd_peer_cancel(peer);
                kptllnd_peer_decref(peer,"temp"); /* ...until here */

                /* start again now I've dropped the lock */
                goto again;
        }

        read_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock, flags);
}

kptl_peer_t *
kptllnd_ptlnid2peer_locked (kptl_data_t  *kptllnd_data,
                            ptl_nid_t     nid)
{
        struct list_head *peer_list = kptllnd_ptlnid2peerlist(kptllnd_data, nid);
        struct list_head *tmp;
        kptl_peer_t      *peer;

        CDEBUG(D_NET, ">>> id="FMT_NID"\n", nid);

        list_for_each (tmp, peer_list) {

                peer = list_entry (tmp, kptl_peer_t, peer_list);

                LASSERT(peer->peer_state != PEER_STATE_CANCELED);
                
                if (peer->peer_ptlid.nid != nid)
                        continue;

                kptllnd_peer_addref(peer,"find");

                CDEBUG(D_NET, "got peer [%p] -> %s (%d)\n",
                       peer, libcfs_nid2str(peer->peer_nid), 
                       atomic_read (&peer->peer_refcount));
                return peer;
        }

        CDEBUG(D_NET, "<<< NOTFOUND\n");
        return NULL;
}

kptl_peer_t *
kptllnd_ptlnid2peer (kptl_data_t *kptllnd_data, ptl_nid_t nid)
{
        kptl_peer_t   *peer;
        unsigned long  flags;

        read_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);
        peer = kptllnd_ptlnid2peer_locked(kptllnd_data, nid);
        read_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock, flags);

        return peer;
}

kptl_peer_t *
kptllnd_nid2peer_locked (kptl_data_t  *kptllnd_data,
                         lnet_nid_t    nid)
{
        return kptllnd_ptlnid2peer_locked(kptllnd_data,
                                          lnet2ptlnid(kptllnd_data, nid));
}

kptl_peer_t *
kptllnd_nid2peer (kptl_data_t *kptllnd_data, lnet_nid_t nid)
{
        return kptllnd_ptlnid2peer(kptllnd_data,
                                   lnet2ptlnid(kptllnd_data, nid));
}

kptl_peer_t *
kptllnd_peer_handle_hello (kptl_data_t      *kptllnd_data,
                           ptl_process_id_t  initiator,
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

        CDEBUG(D_NET, ">>> "FMT_NID"/%d\n", initiator.nid, initiator.pid);

        safe_matchbits_from_peer = msg->ptlm_u.hello.kptlhm_matchbits +
                        *kptllnd_tunables.kptl_peercredits;

        /*
         * Immediate message sizes MUST be equal
         */
        if (msg->ptlm_u.hello.kptlhm_max_msg_size !=
            *kptllnd_tunables.kptl_max_msg_size) {
                CERROR("IMMD message size MUST be equal for all peers got %d expected %d\n",
                       msg->ptlm_u.hello.kptlhm_max_msg_size,
                       *kptllnd_tunables.kptl_max_msg_size);
                return 0;
        }

        /*
         * Setup a connect HELLO message.  We ultimately might not
         * use it but likely we will.
         */
        hello_tx = kptllnd_get_idle_tx(kptllnd_data,TX_TYPE_SMALL_MESSAGE);
        if (hello_tx == NULL) {
                CERROR("Unable to allocate connect message for "FMT_NID"/%d\n",
                       initiator.nid, initiator.pid);
                return 0;
        }

        kptllnd_init_msg(hello_tx->tx_msg, PTLLND_MSG_TYPE_HELLO,
                         sizeof(kptl_hello_msg_t));

        /*
         * Allocate a peer, even though we might not ultimately use it
         * however we want to avoid doing this while holding
         * the peer_rw_lock and be forced into atomic context
         */
        rc = kptllnd_peer_allocate(kptllnd_data, &new_peer, initiator);
        if (rc != 0){
                kptllnd_tx_decref(hello_tx);
                CERROR("Failed to create peer for "FMT_NID"/%d\n",
                       initiator.nid, initiator.pid);
                return 0;
        }

        write_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);

        /*
         * Look for peer because it could have been previously here
         */
        peer = kptllnd_ptlnid2peer_locked(kptllnd_data, initiator.nid);

        /*
         * If peer is already here
         */
        if (peer != NULL) {
                if (peer->peer_incarnation == 0) {
                        /*
                         * Update the peer state
                         */
                        LASSERT(peer->peer_state == PEER_STATE_WAITING_HELLO);
                        peer->peer_state = PEER_STATE_ACTIVE;

                        /*
                         * Update the incarnation
                         */
                        peer->peer_incarnation = msg->ptlm_srcstamp;

                        /*
                         * Save the match bits
                         */
                        CDEBUG(D_NET, " **** Updating Matchbits="LPX64" ****\n",
                               safe_matchbits_from_peer);

                        peer->peer_next_matchbits = safe_matchbits_from_peer;
                        if (peer->peer_next_matchbits < PTL_RESERVED_MATCHBITS)
                                peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;

                } else if (peer->peer_incarnation != msg->ptlm_srcstamp ||
                           peer->peer_ptlid.pid != initiator.pid) {

                        CDEBUG(D_NET, "Peer %s reconnecting with pid,stamp: "
                               "%d,"LPX64" (old %d,"LPX64"\n",
                               libcfs_nid2str(peer->peer_nid),
                               initiator.pid, msg->ptlm_srcstamp,
                               peer->peer_ptlid.pid, peer->peer_incarnation);
                        /*
                         * If the incarnation or PID have changed, assume the
                         * peer has rebooted and resend the hello 
                         */
                        safe_matchbits_to_peer =
                                peer->peer_last_matchbits_seen + 1 +
                                *kptllnd_tunables.kptl_peercredits;

                        /*
                         * Save this peer to cancel
                         */
                        peer_to_cancel = peer;
                        peer = NULL;

                } else {
                        CERROR("Receiving HELLO message on already connected peer %s\n",
                               libcfs_nid2str(peer->peer_nid));
                }
        }

        if (peer == NULL) {
                /*
                 * Put the match bits into the hello message
                 */
                hello_tx->tx_msg->ptlm_u.hello.kptlhm_matchbits =
                        safe_matchbits_to_peer;
                hello_tx->tx_msg->ptlm_u.hello.kptlhm_max_msg_size =
                        *kptllnd_tunables.kptl_max_msg_size;

                /*
                 * Try and attach this peer to the list
                 */
                rc = kptllnd_peer_add_to_list_locked(kptllnd_data, new_peer);
                if (rc != 0) {
                        CERROR("Failed to create peer for "FMT_NID"/%d\n",
                               initiator.nid, initiator.pid);
                        goto failed;
                }

                peer = new_peer;
                new_peer = NULL;

                LASSERT(peer->peer_state == PEER_STATE_WAITING_HELLO);
                peer->peer_state = PEER_STATE_ACTIVE;

                /*
                 * NB We don't need to hold the peer->peer_lock
                 * because we haven't released the kptl_peer_rw_lock which
                 * holds prevents anyone else from getting a pointer to
                 * this newly added (to the lost) peer
                 */

                /*
                 * Update the incarnation
                 */
                peer->peer_incarnation = msg->ptlm_srcstamp;

                /*
                 * Save the match bits
                 */
                CDEBUG(D_NET, "**** Setting Matchbits="LPX64" ****\n",
                       safe_matchbits_from_peer);
                peer->peer_next_matchbits = safe_matchbits_from_peer;
                if(peer->peer_next_matchbits < PTL_RESERVED_MATCHBITS)
                        peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;

                /*
                 * And save them from a previous incarnation
                 */
                peer->peer_last_matchbits_seen = safe_matchbits_to_peer;

                /*
                 * Queue the message
                 */
                kptllnd_peer_queue_tx_locked(peer,hello_tx);

                /*
                 * And don't free it because it's queued
                 */
                hello_tx = NULL;
        }

failed:
        write_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock,flags);

        if (hello_tx != NULL)
                kptllnd_tx_decref(hello_tx);

        if (peer != NULL)
                kptllnd_peer_check_sends(peer);

        if (peer_to_cancel != NULL) {
                kptllnd_peer_cancel(peer_to_cancel);
                kptllnd_peer_decref(peer_to_cancel, "find");
        }

        if (new_peer != NULL)
                kptllnd_peer_decref(new_peer, "alloc");

        CDEBUG(D_NET, "<<< Peer=%p\n", peer);
        return peer;
}

void
kptllnd_tx_launch (kptl_tx_t         *tx,
                   lnet_process_id_t  target,
                   lnet_msg_t        *ptlmsg)
{
        kptl_data_t     *kptllnd_data = tx->tx_po.po_kptllnd_data;
        kptl_peer_t     *peer = NULL;
        kptl_peer_t     *new_peer = NULL;
        unsigned long    flags;
        rwlock_t        *g_lock = &kptllnd_data->kptl_peer_rw_lock;
        int              rc;
        ptl_process_id_t ptlid;
        kptl_tx_t       *hello_tx = NULL;


        /* If I get here, I've committed to send, so I complete the tx with
         * failure on any problems */

        CDEBUG(D_NET, ">>> TX=%p target=%s\n",tx,libcfs_id2str(target));

        LASSERT (tx->tx_ptlmsg == NULL);
        tx->tx_ptlmsg = ptlmsg;              /* finalize ptlmsg on completion */

        LASSERT (tx->tx_peer == NULL);       /* only set when assigned a peer */


        /*
         * First try to find the peer (this will grab the
         * read lock
         */
        peer = kptllnd_nid2peer(kptllnd_data, target.nid);

        /*
         * If we find the peer
         * then just queue the tx
         * (which could send it)
         */
        if (peer != NULL) {
                spin_lock_irqsave(&peer->peer_lock, flags);
                kptllnd_peer_queue_tx_locked ( peer, tx );
                spin_unlock_irqrestore(&peer->peer_lock, flags);
                kptllnd_peer_check_sends(peer);
                kptllnd_peer_decref(peer,"find");
                CDEBUG(D_NET, "<<< FOUND\n");
                return;
        }


        /*
         * Since we didn't find the peer
         * Setup a HELLO message.  We ultimately might not use it
         * (in the case that the peer is racing to connect with us)
         * but more than likely we will.
         */
        hello_tx = kptllnd_get_idle_tx(kptllnd_data,TX_TYPE_SMALL_MESSAGE);
        if( hello_tx == NULL) {
                CERROR("Unable to allocate connect message for %s\n",
                       libcfs_id2str(target));
                kptllnd_tx_decref (tx);
                return;
        }

        kptllnd_init_msg(
                hello_tx->tx_msg,
                PTLLND_MSG_TYPE_HELLO,
                sizeof(kptl_hello_msg_t));

        /*
         * We've never seen this peer before.  So setup
         * a default message.
         */
        hello_tx->tx_msg->ptlm_u.hello.kptlhm_matchbits = 0;
        hello_tx->tx_msg->ptlm_u.hello.kptlhm_max_msg_size =
                *kptllnd_tunables.kptl_max_msg_size;

        /*
         * Allocate a new peer
         * (it's not active until its on the list)
         */
        CDEBUG(D_NET, "TX %p creating NEW PEER %s\n", 
               tx, libcfs_id2str(target));
        ptlid.nid = lnet2ptlnid(kptllnd_data, target.nid);
        ptlid.pid = kptllnd_data->kptl_portals_id.pid;

        rc = kptllnd_peer_allocate(kptllnd_data, &new_peer, ptlid);

        if (rc != 0) {
                CERROR("Failed to create peer %s\n", libcfs_id2str(target));
                kptllnd_tx_decref(tx);
                kptllnd_tx_decref(hello_tx);
                return;
        }


        /*
         * Now try again with the exclusive lock
         * so if it's not found we'll add it
         */
        write_lock_irqsave(g_lock, flags);

        peer = kptllnd_nid2peer_locked(kptllnd_data, target.nid);

        /*
         * If we find the peer
         * then just queue the tx
         * (which could send it)
         */
        if (peer != NULL) {
                write_unlock_irqrestore(g_lock, flags);

                CDEBUG(D_TRACE,"HELLO message race occurred for %s\n",
                       libcfs_id2str(target));

                spin_lock_irqsave(&peer->peer_lock, flags);
                kptllnd_peer_queue_tx_locked ( peer, tx );
                spin_unlock_irqrestore(&peer->peer_lock, flags);

                kptllnd_peer_check_sends(peer);
                kptllnd_peer_decref(peer,"find");
                kptllnd_peer_decref(new_peer,"alloc");

                /* and we don't need the connection tx*/
                kptllnd_tx_decref(hello_tx);

                CDEBUG(D_NET, "<<< FOUND2\n");
                return;
        }


        rc = kptllnd_peer_add_to_list_locked ( kptllnd_data, new_peer);
        if(rc != 0){
                write_unlock_irqrestore(g_lock, flags);

                CERROR("Failed to add peer to list for %s\n",
                       libcfs_id2str(target));

                /* Drop these TXs tx*/
                kptllnd_tx_decref(tx);
                kptllnd_tx_decref(hello_tx);
                kptllnd_peer_decref(new_peer,"create");
                return;
        }

        peer = new_peer;
        new_peer = NULL;

        write_unlock_irqrestore(g_lock,flags);


        /*
         * Queue the connection request
         * and the actually tx.  We have one credit so
         * the connection request will go out, and
         * the tx will wait for a reply.
         */
        CDEBUG(D_NET, "TXHello=%p\n", hello_tx);

        spin_lock_irqsave(&peer->peer_lock, flags);
        kptllnd_peer_queue_tx_locked(peer, hello_tx);
        kptllnd_peer_queue_tx_locked(peer, tx);
        spin_unlock_irqrestore(&peer->peer_lock, flags);

        kptllnd_peer_check_sends(peer);
        kptllnd_peer_decref(peer,"find");

        CDEBUG(D_NET, "<<<\n");
}
