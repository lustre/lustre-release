#include "ptllnd.h"
#include <libcfs/list.h>

void
kptllnd_peer_destroy (
        kptl_peer_t *peer);

kptl_peer_t *
kptllnd_peer_find_locked (
        kptl_data_t *kptllnd_data,
        lnet_nid_t nid);



int
kptllnd_peer_create_locked (
        kptl_data_t *kptllnd_data,
        kptl_peer_t **peerp,
        lnet_nid_t nid)
{
        kptl_peer_t     *peer;
        int             rc;

        PJK_UT_MSG(">>> nid="LPX64"\n",nid);

        LASSERT (nid != PTL_NID_ANY);

        /*
         * But first check we haven't exceeded or maximum
         * number of peers
         */
        if (atomic_read(&kptllnd_data->kptl_npeers) >=
            *kptllnd_tunables.kptl_concurrent_peers) {
                STAT_UPDATE(kps_too_many_peers);
                CERROR("Can't create peer: too many peers\n");
                rc = -EOVERFLOW;        /* !! but at least it distinguishes */
        }

        PORTAL_ALLOC(peer, sizeof (*peer));
        if (peer == NULL) {
                CERROR("Cannot allocate memory for peer\n");
                return -ENOMEM;
        }

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        INIT_LIST_HEAD (&peer->peer_list);       /* not in the peer table yet */
        INIT_LIST_HEAD (&peer->peer_pending_txs);
        INIT_LIST_HEAD (&peer->peer_active_txs);
        spin_lock_init (&peer->peer_lock);


        peer->peer_state = PEER_STATE_WAITING_HELLO;
        peer->peer_kptllnd_data = kptllnd_data;
        peer->peer_nid = nid;
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
                PORTAL_FREE(peer, sizeof (*peer));
                return rc;
        }

        /*
         * 1 ref for the list
         * 1 for the caller
         */
        atomic_set (&peer->peer_refcount, 2);

        /* npeers only grows with the global lock held */
        atomic_inc(&kptllnd_data->kptl_npeers);

        /* And add this to the list */
        list_add_tail (&peer->peer_list,
                       kptllnd_nid2peerlist (kptllnd_data,nid));

        STAT_UPDATE(kps_peers_created);

        PJK_UT_MSG("<<< Peer=%p nid="LPX64"\n",peer,nid);
        *peerp = peer;
        return 0;
}


void
kptllnd_peer_destroy (
        kptl_peer_t *peer)
{
        kptl_data_t *kptllnd_data = peer->peer_kptllnd_data;

        PJK_UT_MSG("Peer=%p\n",peer);

        LASSERT (atomic_read (&peer->peer_refcount) == 0);
        /* Not on the peer list */
        LASSERT (list_empty (&peer->peer_list));
        /* No pending tx descriptors */
        LASSERT (list_empty (&peer->peer_pending_txs));
        /* No active tx descriptors */
        LASSERT (list_empty (&peer->peer_active_txs));

        PORTAL_FREE (peer, sizeof (*peer));

        kptllnd_rx_buffer_pool_unreserve(
                &kptllnd_data->kptl_rx_buffer_pool,
                *kptllnd_tunables.kptl_peercredits);


        /* NB a peer's connections keep a reference on their peer until
         * they are destroyed, so we can be assured that _all_ state to do
         * with this peer has been cleaned up when its refcount drops to
         * zero. */
        atomic_dec(&kptllnd_data->kptl_npeers);
}


void
kptllnd_peer_addref (
        kptl_peer_t *peer,
        const char *owner)
{
        atomic_inc(&peer->peer_refcount);

        /*
         * The below message could actually be out of sync
         * with the real ref count, and is for informational purposes
         * only
         */
        PJK_UT_MSG("peer=%p owner=%s count=%d\n",peer,owner,
                atomic_read(&peer->peer_refcount));
}

void
kptllnd_peer_decref (
        kptl_peer_t *peer,
        const char *owner)
{
        unsigned long    flags;
        kptl_data_t     *kptllnd_data = peer->peer_kptllnd_data;

        if( !atomic_dec_and_test(&peer->peer_refcount)){

                /*
                 * The below message could actually be out of sync
                 * with the real ref count, and is for informational purposes
                 * only
                 */
                PJK_UT_MSG("peer=%p owner=%s count=%d\n",peer,owner,
                        atomic_read(&peer->peer_refcount));
                return;
        }

        PJK_UT_MSG("peer=%p owner=%s LAST REF\n",peer,owner);

        write_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);
        list_del_init (&peer->peer_list);
        if(peer->peer_state == PEER_STATE_CANCELED)
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


        INIT_LIST_HEAD (&list);

        /*
         * Tranfer all the PENDING TX's to a temporary list
         * while holding the peer lock
         */
        spin_lock(&peer->peer_lock);

        if(!list_empty(&peer->peer_pending_txs))
                PJK_UT_MSG("Clearing Pending TXs\n");

        list_for_each_safe (tx_temp, tx_next, &peer->peer_pending_txs) {
                tx = list_entry (tx_temp, kptl_tx_t, tx_list);

                list_del_init(&tx->tx_list);
                list_add(&tx->tx_list,&list);
        }

        spin_unlock(&peer->peer_lock);

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

        spin_lock(&peer->peer_lock);

        if(!list_empty(&peer->peer_active_txs))
                PJK_UT_MSG("Clearing Active TXs\n");

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

                spin_unlock(&peer->peer_lock);


                /*
                 * Question:  Why is it safe to acces tx_mdh and tx_mdh
                 * outside the peer_lock.  We could be racing with
                 * tx_callback?
                 */

                if(!PtlHandleIsEqual(tx->tx_mdh_msg,PTL_INVALID_HANDLE)){
                        PJK_UT_MSG("Unlink mhd_msg\n");
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
                        PJK_UT_MSG("Unlink mdh\n");
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

                spin_lock(&peer->peer_lock);

                /*
                 * If a change in the list has be detected
                 * go back to the beginning
                 */
                if( counter != peer->peer_active_txs_change_counter)
                        goto again;
        }

        spin_unlock(&peer->peer_lock);
}

void
kptllnd_peer_cancel(
        kptl_peer_t *peer)
{
        kptl_data_t *kptllnd_data = peer->peer_kptllnd_data;
        unsigned long      flags;
        int                list_owns_ref=0;

        PJK_UT_MSG(">>> Peer=%p\n",peer);

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

        PJK_UT_MSG("<<< Peer=%p\n",peer);
}

int
kptllnd_peer_del (
        kptl_data_t *kptllnd_data,
        lnet_nid_t nid)
{
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        kptl_peer_t        *peer;
        int                lo;
        int                hi;
        int                i;
        unsigned long      flags;
        int                rc = -ENOENT;


        PJK_UT_MSG(">>> NID="LPX64"\n",nid);

        /*
         * Find the single bucket we are supposed to look at
         * or if nid = PTL_NID_ANY then look at all of the buckets
         */
        if (nid != PTL_NID_ANY)
                lo = hi = kptllnd_nid2peerlist(kptllnd_data,nid) - kptllnd_data->kptl_peers;
        else {
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
                        if (!(nid == PTL_NID_ANY || peer->peer_nid == nid))
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

        PJK_UT_MSG("<<< rc=%d\n",rc);
        return (rc);
}

void
kptllnd_peer_queue_tx_locked (
        kptl_peer_t *peer,
        kptl_tx_t *tx)
{
        PJK_UT_MSG("Peer=%p TX=%p\n",peer,tx);

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
kptllnd_peer_queue_tx (
        kptl_peer_t *peer,
        kptl_tx_t *tx)
{
        spin_lock(&peer->peer_lock);
        kptllnd_peer_queue_tx_locked (peer, tx);
        spin_unlock(&peer->peer_lock);

        kptllnd_peer_check_sends(peer);
}


void
kptllnd_peer_queue_bulk_rdma_tx_locked(
        kptl_peer_t *peer,
        kptl_tx_t *tx)
{
        PJK_UT_MSG("Peer=%p TX=%p\n",peer,tx);

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
        spin_lock(&peer->peer_lock);
        kptllnd_peer_dequeue_tx_locked(peer,tx);
        spin_unlock(&peer->peer_lock);
}

void
kptllnd_peer_check_sends (
        kptl_peer_t *peer )
{

        kptl_tx_t      *tx;
        kptl_data_t    *kptllnd_data = peer->peer_kptllnd_data;
        int             rc,rc2;
        ptl_md_t        md;
        ptl_handle_me_t meh;
        ptl_process_id_t target;

        /*
         * If there is nothing to send, and we have hit the credit
         * high water mark, then send a no-op message
         */
        spin_lock(&peer->peer_lock);

        PJK_UT_MSG_DATA(">>>Peer=%p Credits=%d Outstanding=%d\n",
                peer,peer->peer_credits,peer->peer_outstanding_credits);

        if(list_empty(&peer->peer_pending_txs) &&
           peer->peer_outstanding_credits >= PTLLND_CREDIT_HIGHWATER) {

                /*
                 * Get an idle tx descriptor
                 * may NOT block: (That's the "0" param)
                 */
                tx = kptllnd_get_idle_tx(kptllnd_data,0,TX_TYPE_SMALL_MESSAGE);
                if( tx == NULL ) {
                        CERROR ("Can't return credits to "LPX64": tx descs exhausted\n",
                                peer->peer_nid);
                }else{
                        kptllnd_init_msg(tx->tx_msg, PTLLND_MSG_TYPE_NOOP,0);
                        kptllnd_peer_queue_tx_locked(peer,tx);
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
                        CDEBUG(D_NET, LPX64": no credits\n",peer->peer_nid);
                        break;
                }


                /*
                 * If there is one credit but we have no credits to give
                 * back then we don't use our one credit and we are done
                 */
                if (peer->peer_credits == 1 &&
                    peer->peer_outstanding_credits == 0) {
                        STAT_UPDATE(kps_saving_last_credit);
                        CDEBUG(D_NET, LPX64": not using last credit\n",
                               peer->peer_nid);
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
                 */
                if (tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_NOOP &&
                    (!list_empty(&peer->peer_pending_txs) ||
                     peer->peer_outstanding_credits < PTLLND_CREDIT_HIGHWATER)) {
                        /* redundant NOOP */
                        kptllnd_tx_decref(tx);
                        CDEBUG(D_NET, LPX64": redundant noop\n",
                               peer->peer_nid);
                        continue;
                }

                PJK_UT_MSG_DATA("--- TXTXTXTXTXTXTXTXTXTXTXTXTXTX\n");
                PJK_UT_MSG_DATA("Sending TX=%p Size=%d\n",tx,tx->tx_msg->ptlm_nob);
                PJK_UT_MSG_DATA("Target nid="LPX64"\n",peer->peer_nid);


                /*
                 * Assign matchbits for a put/get
                 */
                if(tx->tx_msg->ptlm_type == PLTLND_MSG_TYPE_PUT ||
                   tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_GET){

                        PJK_UT_MSG_DATA("next matchbits="LPX64" (before)\n",
                                peer->peer_next_matchbits);


                        /* Allocate a new match bits value.  It might not be needed,
                         * but we've got a lock right now and we're unlikely to
                         * wrap...
                         *
                         * A set of match bits at the low end are reserved.  So we can
                         * not use them.  Just skip over them.  This check protects us
                         * even in the case of 64-bit rollover.
                         */
                        if(peer->peer_next_matchbits < PTL_RESERVED_MATCHBITS){
                                CDEBUG(D_INFO,"Match Bits Rollover for "LPX64"\n",
                                        peer->peer_nid);
                                peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;

                        }

                        /*
                         * Set the payload match bits and update the peer's counter
                         */
                        tx->tx_msg->ptlm_u.req.kptlrm_matchbits =
                                peer->peer_next_matchbits ++;

                        PJK_UT_MSG_DATA("next matchbits="LPX64" (after)\n",
                                peer->peer_next_matchbits);
                }

                /*
                 * Complete the message fill in all the rest
                 * of the header
                 */
                kptllnd_msg_pack(
                        tx->tx_msg,
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

                target.nid = lnet2ptlnid(kptllnd_data,peer->peer_nid);
                target.pid = 0;

                PJK_UT_MSG_DATA("Msg NOB = %d\n",tx->tx_msg->ptlm_nob);
                PJK_UT_MSG_DATA("Returned Credits=%d\n",tx->tx_msg->ptlm_credits);
                PJK_UT_MSG_DATA("Seq # = "LPX64"\n",tx->tx_msg->ptlm_seq);

                PJK_UT_MSG("lnet TX nid=" LPX64 "\n",peer->peer_nid);
                PJK_UT_MSG("ptl  TX nid=" LPX64 "\n",target.nid);

                if(tx->tx_msg->ptlm_type == PTLLND_MSG_TYPE_GET ||
                   tx->tx_msg->ptlm_type == PLTLND_MSG_TYPE_PUT){
                        tempiov_t tempiov;

#ifdef TESTING_WITH_LOOPBACK
                        /*
                         * When doing loopback testing the data comes back
                         * on the given loopback nid
                         */
                        ptl_process_id_t target;
                        target.nid = PTL_NID_ANY;
                        target.pid = 0;
#endif

                        PJK_UT_MSG_DATA("matchibts=" LPX64 "\n",
                                tx->tx_msg->ptlm_u.req.kptlrm_matchbits);


                        /*
                         * Attach the ME
                         */
                        rc = PtlMEAttach(
                            kptllnd_data->kptl_nih,
                            *kptllnd_tunables.kptl_portal,
                            target,
                            tx->tx_msg->ptlm_u.req.kptlrm_matchbits,
                            0, /* all matchbits are valid - ignore none*/
                            PTL_UNLINK,
                            PTL_INS_BEFORE,
                            &meh);
                        if(rc != 0) {
                                CERROR("PtlMeAttach failed %d\n",rc);
                                goto failed;
                        }

                        /* Setup the MD */
                        kptllnd_setup_md(kptllnd_data,&md,
                                tx->tx_msg->ptlm_type == LNET_MSG_GET ? PTL_MD_OP_PUT :
                                        PTL_MD_OP_GET,
                                tx,
                                tx->tx_payload_niov,
                                tx->tx_payload_iov,
                                tx->tx_payload_kiov,
                                tx->tx_payload_offset,
                                tx->tx_payload_nob,
                                &tempiov);

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
                                &tx->tx_mdh);
                        if(rc != 0){
                                CERROR("PtlMDAttach failed %d\n",rc);

                                /*
                                 * Just drop the ref for this MD because it was never
                                 * posted to portals
                                 */
                                tx->tx_mdh = PTL_INVALID_HANDLE;
                                kptllnd_tx_decref(tx);

                                rc2 = PtlMEUnlink(meh);
                                LASSERT(rc2 == 0);
                                goto failed;
                        }
                }


                /*
                 * Setup the MD
                 */
                md.start = tx->tx_msg;
                md.length = tx->tx_msg->ptlm_nob;
                md.threshold = 1;
                md.options = PTL_MD_OP_PUT;
                md.options |= PTL_MD_EVENT_START_DISABLE;
                /* we don't need an ACK, we'll get a callback when the get is complete */
                md.options |= PTL_MD_ACK_DISABLE;
                md.user_ptr = tx;
                md.eq_handle = kptllnd_data->kptl_eqh;


                /*
                 * Bind the MD
                 */
                rc = PtlMDBind (
                        kptllnd_data->kptl_nih,
                        md,
                        PTL_UNLINK,
                        &tx->tx_mdh_msg);
                if(rc != 0){
                        CERROR("PtlMDBind failed %d\n",rc);
                        tx->tx_mdh_msg = PTL_INVALID_HANDLE;
                        goto failed;
                }

                list_add_tail(&tx->tx_list, &peer->peer_active_txs);
                peer->peer_active_txs_change_counter++;
                LASSERT(tx->tx_peer == peer);

                /*
                 * Grab a ref so the TX doesn't go away
                 * if we fail.
                 */
                kptllnd_tx_addref(tx);

                spin_unlock(&peer->peer_lock);

                rc = PtlPut (
                            tx->tx_mdh_msg,
                            PTL_NOACK_REQ,     /* we dont need an ack */
                            target,            /* peer "address" */
                            *kptllnd_tunables.kptl_portal,     /* portal */
                            0,                 /* cookie */
                            LNET_MSG_MATCHBITS, /* match bits */
                            0,                 /* offset */
                            0);                /* header data */
                if(rc != 0){
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
                        goto failed;
                }

                /*
                 * Release our temporary reference
                 */
                kptllnd_tx_decref(tx);

                spin_lock(&peer->peer_lock);

        }


        spin_unlock(&peer->peer_lock);

        PJK_UT_MSG_DATA("<<<\n");
        return;

failed:

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
         * Get back the credits
         * ??? WHY even do this because we're killing the peer
         */
        peer->peer_outstanding_credits += tx->tx_msg->ptlm_credits;
        peer->peer_credits++;

        spin_unlock(&peer->peer_lock);

        /*
         * And cleanup this peer
         */
        kptllnd_peer_cancel(peer);

        /*
         * And release the tx reference
         */
        kptllnd_tx_decref(tx);

        PJK_UT_MSG("<<< FAILED\n");
}

int
kptllnd_peer_timedout(kptl_peer_t *peer)
{
        kptl_tx_t          *tx;

        spin_lock(&peer->peer_lock);

        /*
         * Check the head of the pending list for expiration
         * this is a queue, so if the head isn't expired then nothing
         * else will be expired
         */
        if(!list_empty(&peer->peer_pending_txs)){
                tx = list_entry(peer->peer_pending_txs.next,kptl_tx_t,tx_list);
                if(time_after_eq(jiffies,tx->tx_deadline)){
                        spin_unlock(&peer->peer_lock);
                        PJK_UT_MSG("Peer=%p PENDING tx=%p time=%lu sec\n",
                                peer,tx,(jiffies - tx->tx_deadline)/HZ);
                        return 1;
                }
        }

        /*
         * Check the head of the active list
         */
        if(!list_empty(&peer->peer_active_txs)){
                tx = list_entry(peer->peer_active_txs.next,kptl_tx_t,tx_list);
                if(time_after_eq(jiffies,tx->tx_deadline)){
                        spin_unlock(&peer->peer_lock);
                        PJK_UT_MSG("Peer=%p ACTIVE tx=%p time=%lu sec\n",
                                peer,tx,(jiffies - tx->tx_deadline)/HZ);
                        return 1;
                }
        }

        spin_unlock(&peer->peer_lock);
        return 0;
}


void
kptllnd_peer_check_bucket (int idx, kptl_data_t *kptllnd_data)
{
        struct list_head  *peers = &kptllnd_data->kptl_peers[idx];
        struct list_head  *ptmp;
        kptl_peer_t       *peer;
        unsigned long      flags;


        /*PJK_UT_MSG("Bucket=%d\n",idx);*/

 again:
        /* NB. We expect to have a look at all the peers and not find any
         * rdmas to time out, so we just use a shared lock while we
         * take a look... */
        read_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);

        list_for_each (ptmp, peers) {
                peer = list_entry (ptmp, kptl_peer_t, peer_list);

                /* In case we have enough credits to return via a
                 * NOOP, but there were no non-blocking tx descs
                 * free to do it last time... */
                kptllnd_peer_check_sends(peer);

                if (!kptllnd_peer_timedout(peer))
                        continue;

                kptllnd_peer_addref(peer,"temp"); /* 1 ref for me... */

                read_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock,
                                       flags);

                CERROR("Timed out RDMA with "LPX64"\n",peer->peer_nid);

                kptllnd_peer_cancel(peer);
                kptllnd_peer_decref(peer,"temp"); /* ...until here */

                /* start again now I've dropped the lock */
                goto again;
        }

        read_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock, flags);
}

kptl_peer_t *
kptllnd_peer_find (
        kptl_data_t *kptllnd_data,
        lnet_nid_t nid)
{
        kptl_peer_t *peer;
        unsigned long flags;
        read_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);
        peer = kptllnd_peer_find_locked(kptllnd_data,nid);
        read_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);
        return peer;
}

kptl_peer_t *
kptllnd_peer_find_locked (
        kptl_data_t *kptllnd_data,
        lnet_nid_t nid)
{
        struct list_head *peer_list = kptllnd_nid2peerlist (kptllnd_data,nid);
        struct list_head *tmp;
        kptl_peer_t      *peer;

        PJK_UT_MSG(">>> nid="LPX64"\n",nid);

        list_for_each (tmp, peer_list) {

                peer = list_entry (tmp, kptl_peer_t, peer_list);

                LASSERT(peer->peer_state != PEER_STATE_CANCELED);

                if (peer->peer_nid != nid)
                        continue;

                CDEBUG(D_NET, "got peer [%p] -> "LPX64" (%d)\n",
                       peer, nid, atomic_read (&peer->peer_refcount));

                kptllnd_peer_addref(peer,"find");
                PJK_UT_MSG("<<< Peer=%p\n",peer);
                return peer;
        }

        PJK_UT_MSG("<<< NOTFOUND\n");
        return NULL;
}

kptl_peer_t *
kptllnd_peer_handle_hello (
        kptl_data_t *kptllnd_data,
        lnet_nid_t nid,
        kptl_msg_t *msg)
{
        kptl_peer_t    *peer;
        kptl_peer_t    *peer_to_cancel = 0;
        unsigned long   flags;
        kptl_tx_t      *tx_hello = 0;
        int             rc;
        __u64           safe_matchbits_from_peer;
        __u64           safe_matchbits_to_peer = 0;


        PJK_UT_MSG(">>>\n");

        safe_matchbits_from_peer = msg->ptlm_u.hello.kptlhm_matchbits +
                        *kptllnd_tunables.kptl_peercredits;

        /*
         * Immediate message sizes MUST be equal
         */
        if(  msg->ptlm_u.hello.kptlhm_max_immd_size !=
                *kptllnd_tunables.kptl_max_immd_size){
                CERROR("IMMD message size MUST be equal for all peers got %d expected %d\n",
                        msg->ptlm_u.hello.kptlhm_max_immd_size,
                        *kptllnd_tunables.kptl_max_immd_size);

                return 0;
        }

        write_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);

        /*
         * Look for peer because it could have been previously here
         */
        peer = kptllnd_peer_find_locked(kptllnd_data,nid);

        /*
         * If peer is already here
         */
        if(peer != NULL){

                if(peer->peer_incarnation == 0) {
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
                        PJK_UT_MSG_DATA(" **** Updating Matchbits="LPX64" ****\n",
                                safe_matchbits_from_peer);

                        peer->peer_next_matchbits = safe_matchbits_from_peer;
                        if(peer->peer_next_matchbits < PTL_RESERVED_MATCHBITS)
                                peer->peer_next_matchbits = PTL_RESERVED_MATCHBITS;
                }

                /*
                 * If the incarnation has changed then we need to
                 * resend the hello.
                 */
                else if( peer->peer_incarnation != msg->ptlm_srcnid ) {

                        /*
                         * Put the match bits into the hello message
                         */
                        safe_matchbits_to_peer =
                                peer->peer_last_matchbits_seen + 1 +
                                *kptllnd_tunables.kptl_peercredits;

                        /*
                         * Save this peer to cancel
                         */
                        peer_to_cancel = peer;
                        peer = NULL;

                }else{
                        CERROR("Receiving HELLO message on already connected peer " LPX64"\n",nid);
                }
        }

        if( peer == NULL) {

                /*
                 * Setup a connect HELLO message.  We ultimately might not
                 * use it but likely we will.
                 */
                tx_hello = kptllnd_get_idle_tx(kptllnd_data,0,TX_TYPE_SMALL_MESSAGE);
                if( tx_hello == NULL) {
                        CERROR("Unable to allocate connect message for "LPX64"\n",nid);
                        goto failed;
                }

                kptllnd_init_msg(
                        tx_hello->tx_msg,
                        PTLLND_MSG_TYPE_HELLO,
                        sizeof(kptl_hello_msg_t));
                /*
                 * Put the match bits into the hello message
                 */
                tx_hello->tx_msg->ptlm_u.hello.kptlhm_matchbits =
                        safe_matchbits_to_peer;
                tx_hello->tx_msg->ptlm_u.hello.kptlhm_max_immd_size =
                        *kptllnd_tunables.kptl_max_immd_size;

                rc = kptllnd_peer_create_locked ( kptllnd_data, &peer, nid);
                if(rc != 0){
                        CERROR("Failed to create peer (nid="LPX64")\n",nid);
                        write_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock, flags);
                        peer = NULL;
                        goto failed;
                }

                LASSERT(peer->peer_state == PEER_STATE_WAITING_HELLO);
                peer->peer_state = PEER_STATE_ACTIVE;

                /*
                 * NB We don't need to hold the peer->peer_lock
                 * because we haven't released the kptl_peer_rw_lock which
                 * holds prevents anyone else from getting a pointer to
                 * this newly created peer
                 */

                /*
                 * Update the incarnation
                 */
                peer->peer_incarnation = msg->ptlm_srcstamp;

                /*
                 * Save the match bits
                 */
                PJK_UT_MSG_DATA("**** Setting Matchbits="LPX64" ****\n",
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
                kptllnd_peer_queue_tx_locked(peer,tx_hello);

                /*
                 * And don't free it because it's queued
                 */
                tx_hello = 0;

        }

failed:
        write_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock,flags);

        if(tx_hello)
                kptllnd_tx_decref(tx_hello);

        /*
         *
         */
        if(peer){
                kptllnd_peer_check_sends(peer);
        }

        if(peer_to_cancel) {
                kptllnd_peer_cancel(peer_to_cancel);
                kptllnd_peer_decref(peer_to_cancel,"find");
        }

        PJK_UT_MSG("<<< Peer=%p\n",peer);

        return peer;
}

void
kptllnd_tx_launch (
        kptl_tx_t *tx,
        lnet_nid_t target_nid,
        lnet_msg_t *ptlmsg )
{
        kptl_data_t     *kptllnd_data = tx->tx_po.po_kptllnd_data;
        kptl_peer_t     *peer;
        unsigned long    flags;
        rwlock_t        *g_lock = &kptllnd_data->kptl_peer_rw_lock;
        int              rc;
        kptl_tx_t       *tx_hello;

        /* If I get here, I've committed to send, so I complete the tx with
         * failure on any problems */

        PJK_UT_MSG(">>> TX=%p nid="LPX64"\n",tx,target_nid);

        LASSERT (tx->tx_ptlmsg == NULL);
        tx->tx_ptlmsg = ptlmsg;              /* finalize ptlmsg on completion */

        LASSERT (tx->tx_peer == NULL);       /* only set when assigned a peer */


        /*
         * First try to find the peer (this will grab the
         * read lock
         */
        peer = kptllnd_peer_find (kptllnd_data,target_nid);

        /*
         * If we find the peer
         * then just queue the tx
         * (which could send it)
         */
        if (peer != NULL) {
                kptllnd_peer_queue_tx ( peer, tx );
                kptllnd_peer_decref(peer,"find");
                PJK_UT_MSG("<<< FOUND\n");
                return;
        }


        /*
         * Since we didn't find the peer
         * Setup a HELLO message.  We ultimately might not use it
         * (in the case that the peer is racing to connect with us)
         * but more than likely we will.
         */
        tx_hello = kptllnd_get_idle_tx(kptllnd_data,0,TX_TYPE_SMALL_MESSAGE);
        if( tx_hello == NULL) {
                CERROR("Unable to allocate connect message for "LPX64"\n",target_nid);
                kptllnd_tx_decref (tx);
                kptllnd_peer_decref(peer,"find");
                return;
        }

        kptllnd_init_msg(
                tx_hello->tx_msg,
                PTLLND_MSG_TYPE_HELLO,
                sizeof(kptl_hello_msg_t));


        /*
         * Now try again with the exclusive lock
         * so if it's not found we'll add it
         */
        write_lock_irqsave(g_lock, flags);

        peer = kptllnd_peer_find_locked (kptllnd_data,target_nid);

        /*
         * If we find the peer
         * then just queue the tx
         * (which could send it)
         */
        if (peer != NULL) {
                write_unlock_irqrestore(g_lock, flags);

                CDEBUG(D_TRACE,"HELLO message race occurred (nid="LPX64")\n",target_nid);

                kptllnd_peer_queue_tx ( peer, tx );
                kptllnd_peer_decref(peer,"find");

                /* and we don't need the connection tx*/
                kptllnd_tx_decref(tx_hello);

                PJK_UT_MSG("<<< FOUND2\n");
                return;
        }

        PJK_UT_MSG("TX %p creating NEW PEER nid="LPX64"\n",tx,target_nid);
        rc = kptllnd_peer_create_locked ( kptllnd_data, &peer, target_nid);
        if(rc != 0){
                CERROR("Failed to create peer (nid="LPX64")\n",target_nid);
                write_unlock_irqrestore(g_lock, flags);
                kptllnd_tx_decref (tx);
                kptllnd_tx_decref (tx_hello);
                kptllnd_peer_decref(peer,"find");
                return;
        }


        /*
         * We've never seen this peer before.  So setup
         * a default message.
         */
        tx_hello->tx_msg->ptlm_u.hello.kptlhm_matchbits = 0;
        tx_hello->tx_msg->ptlm_u.hello.kptlhm_max_immd_size =
                *kptllnd_tunables.kptl_max_immd_size;

        /*
         * Queue the connection request
         * and the actually tx.  We have one credit so
         * the connection request will go out, and
         * the tx will wait for a reply.
         */
        PJK_UT_MSG("TXHello=%p\n",tx_hello);
        kptllnd_peer_queue_tx_locked(peer,tx_hello);
        kptllnd_peer_queue_tx_locked(peer,tx);

        write_unlock_irqrestore(g_lock,flags);

        kptllnd_peer_check_sends(peer);
        kptllnd_peer_decref(peer,"find");

        PJK_UT_MSG("<<<\n");
}
