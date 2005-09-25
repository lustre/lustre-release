#include "ptllnd.h"

kptl_rx_t*
kptllnd_rx_alloc(
        kptl_data_t *kptllnd_data );

void
kptllnd_rx_schedule (kptl_rx_t *rx);

void
kptllnd_rx_buffer_destroy(
        kptl_rx_buffer_t *rxb);
int
kptllnd_rx_buffer_post(
        kptl_rx_buffer_t *rxb);

void
kptllnd_rx_buffer_addref(
        kptl_rx_buffer_t *rxb,
        const char *owner);

void
kptllnd_rx_buffer_pool_init(
        kptl_rx_buffer_pool_t *rxbp)
{
        PJK_UT_MSG("kptllnd_rx_buffer_pool_init\n");
        memset(rxbp,0,sizeof(*rxbp));

        spin_lock_init (&rxbp->rxbp_lock);
        INIT_LIST_HEAD (&rxbp->rxbp_list);

}

void
kptllnd_rx_buffer_pool_fini(
        kptl_rx_buffer_pool_t *rxbp)
{
        kptl_rx_buffer_t       *rxb;
        int                     rc;
        int                     i;

        PJK_UT_MSG("kptllnd_rx_buffer_pool_fini\n");

        spin_lock(&rxbp->rxbp_lock);

        /*
         * Set the shutdown flag under the lock
         */
        rxbp->rxbp_shutdown = 1;

        i = 2;
        while(!list_empty(&rxbp->rxbp_list))
        {
                struct list_head* iter;
                int count = 0;

                /*
                 * Count how many items are on the list right now
                 */
                list_for_each(iter,&rxbp->rxbp_list)
                        ++count;

                CDEBUG(D_TRACE,"|rxbp_list|=%d\n",count);

                /*
                 * Loop while we still have items on the list
                 * ore we've going through the list once
                 */
                while(!list_empty(&rxbp->rxbp_list) && count!=0)
                {
                        --count;
                        rxb = list_entry (rxbp->rxbp_list.next,
                                                 kptl_rx_buffer_t, rxb_list);

                        LASSERT(rxb->rxb_state == RXB_STATE_POSTED);


                        list_del_init(&rxb->rxb_list);

                        /*
                         * We have hit the one race where the MD has been put
                         * on the list, but the MD is not created.
                         */
                        if(PtlHandleIsEqual(rxb->rxb_mdh,PTL_INVALID_HANDLE)){
                                list_add_tail(&rxb->rxb_list,&rxbp->rxbp_list);
                                continue;
                        }


                        /*
                         * Keep the RXB from being deleted
                         */
                        kptllnd_rx_buffer_addref(rxb,"temp");

                        spin_unlock(&rxbp->rxbp_lock);

                        /*
                         * Unlinked the MD
                         */
                        LASSERT(atomic_read(&rxb->rxb_refcount)>1);
                        rc = PtlMDUnlink(rxb->rxb_mdh);
                        if(rc == 0){
#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                                rxb->rxb_mdh = PTL_INVALID_HANDLE;
                                kptllnd_rx_buffer_decref(rxb,"portals");
#endif
                                /*
                                 * Drop the reference we took above
                                 */
                                kptllnd_rx_buffer_decref(rxb,"temp");

                                spin_lock(&rxbp->rxbp_lock);
                        }else{
                                PJK_UT_MSG("PtlMDUnlink(%p) rc=%d\n",rxb,rc);
                                /*
                                 * The unlinked failed so put this back
                                 * on the list for later
                                 */
                                spin_lock(&rxbp->rxbp_lock);

                                list_add_tail(&rxb->rxb_list,&rxbp->rxbp_list);

                                /*
                                 * Drop the reference we took above
                                 */
                                kptllnd_rx_buffer_decref(rxb,"temp");
                        }
                }

                /*
                 * If there are still items on the list we
                 * need to take a break, and let the Busy RX's
                 * finish up.
                 */
                if(!list_empty(&rxbp->rxbp_list)){
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "Waiting for %d Busy RX Buffers\n",
                               rxbp->rxbp_count);
                        spin_unlock(&rxbp->rxbp_lock);
                        cfs_pause(cfs_time_seconds(1));
                        spin_lock(&rxbp->rxbp_lock);
                }
        }

        CDEBUG(D_TRACE,"|rxbp_list|=EMPTY\n");

        if(rxbp->rxbp_count != 0){
                PJK_UT_MSG("Waiting for %d RX Buffers to unlink\n",rxbp->rxbp_count);

                i = 2;
                while (rxbp->rxbp_count != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "Waiting for %d RX Buffers to unlink\n",
                               rxbp->rxbp_count);
                        spin_unlock(&rxbp->rxbp_lock);
                        cfs_pause(cfs_time_seconds(1));
                        spin_lock(&rxbp->rxbp_lock);
                }
        }

        CDEBUG(D_TRACE,"|rxbp_count|=0\n");

        spin_unlock(&rxbp->rxbp_lock);
}


int
kptllnd_rx_buffer_pool_reserve(
        kptl_rx_buffer_pool_t *rxbp,
        kptl_data_t *kptllnd_data,
        int count)
{
        int                     add = 0;
        int                     i;
        int                     rc;
        kptl_rx_buffer_t       *rxb;
        int                     nbuffers;

        spin_lock(&rxbp->rxbp_lock);

        PJK_UT_MSG("kptllnd_rx_buffer_pool_reserve(%d)\n",count);

        /*
         * Prevent reservation of anymore while we are shutting down
         */
        if(rxbp->rxbp_shutdown){
                spin_unlock(&rxbp->rxbp_lock);
                return -ESHUTDOWN;
        }

        /*
         * Make the reservation
         */
        rxbp->rxbp_reserved += count;

        /*
         * Calcuate the number or buffers we need
         * +1 to handle any rounding error
         */
        nbuffers = (rxbp->rxbp_reserved) *
                (*kptllnd_tunables.kptl_max_immd_size) /
                (PAGE_SIZE * (*kptllnd_tunables.kptl_rxb_npages));
        ++nbuffers ;

        PJK_UT_MSG("nbuffers=%d rxbp_count=%d\n",nbuffers,rxbp->rxbp_count);

        if(rxbp->rxbp_count < nbuffers)
                add = nbuffers - rxbp->rxbp_count;

        PJK_UT_MSG("adding=%d\n",add);

        /*
         * Under the same lock assume they are added
         * we'll subtract if we hit an error.
         */
        rxbp->rxbp_count += add;
        spin_unlock(&rxbp->rxbp_lock);

        for(i=0;i<add;i++){
                PORTAL_ALLOC( rxb,sizeof(*rxb));
                if(rxb == NULL){
                        CERROR("Failed to allocate data rxb%d\n",i);
                        rc = -ENOMEM;
                        goto failed;
                }

                memset(rxb,0,sizeof(*rxb));

                kptllnd_posted_object_setup(&rxb->rxb_po,
                          kptllnd_data,
                          POSTED_OBJECT_TYPE_RXB);

                rxb->rxb_pool = rxbp;
                rxb->rxb_state = RXB_STATE_IDLE;
                rxb->rxb_mdh = PTL_INVALID_HANDLE;
                INIT_LIST_HEAD (&rxb->rxb_list);
                INIT_LIST_HEAD (&rxb->rxb_repost_list);

                PORTAL_ALLOC( rxb->rxb_buffer,
                        PAGE_SIZE * *kptllnd_tunables.kptl_rxb_npages);
                if(rxb->rxb_buffer == NULL) {
                        CERROR("Failed to allocate data buffer or size %d pages for rx%d\n",
                                *kptllnd_tunables.kptl_rxb_npages,i);
                        rc = -ENOMEM;
                        goto failed;
                }

                rc = kptllnd_rx_buffer_post(rxb);
                if(rc != 0)
                        goto failed;
        }
        return 0;

failed:
        spin_lock(&rxbp->rxbp_lock);

        /*
         * We really didn't add as many
         * as we were planning to.
         */
        rxbp->rxbp_count -= add - i;

        /*
         * Cancel this reservation
         */
        rxbp->rxbp_reserved -= count;
        spin_unlock(&rxbp->rxbp_lock);


        if(rxb){
                if(rxb->rxb_buffer)
                        PORTAL_FREE( rxb->rxb_buffer,PAGE_SIZE * *kptllnd_tunables.kptl_rxb_npages);
                PORTAL_FREE( rxb,sizeof(*rxb));
        }

        return rc;
}

void
kptllnd_rx_buffer_pool_unreserve(
        kptl_rx_buffer_pool_t *rxbp,
        int count)
{
        spin_lock(&rxbp->rxbp_lock);
        PJK_UT_MSG("kptllnd_rx_buffer_pool_unreserve(%d)\n",count);
        rxbp->rxbp_reserved -= count;
        spin_unlock(&rxbp->rxbp_lock);
}

void
kptllnd_rx_buffer_scheduled_post(
        kptl_rx_buffer_t *rxb)
{
        kptl_data_t     *kptllnd_data = rxb->rxb_po.po_kptllnd_data;
        unsigned long    flags;

        PJK_UT_MSG("rxb=%p\n",rxb);

        spin_lock_irqsave(&kptllnd_data->kptl_sched_lock, flags);
        LASSERT(list_empty(&rxb->rxb_repost_list));
        list_add_tail(&rxb->rxb_repost_list,&kptllnd_data->kptl_sched_rxbq);
        wake_up(&kptllnd_data->kptl_sched_waitq);
        spin_unlock_irqrestore(&kptllnd_data->kptl_sched_lock, flags);
}


int
kptllnd_rx_buffer_post(
        kptl_rx_buffer_t *rxb)
{
        int                     rc;
        ptl_md_t                md;
        ptl_handle_me_t         meh;
        ptl_handle_md_t         mdh;
        ptl_process_id_t        any;
        kptl_data_t            *kptllnd_data = rxb->rxb_po.po_kptllnd_data;
        kptl_rx_buffer_pool_t  *rxbp = rxb->rxb_pool;

        any.nid = PTL_NID_ANY;
        any.pid = PTL_PID_ANY;

        /*PJK_UT_MSG("rxb=%p\n",rxb);*/

        spin_lock(&rxbp->rxbp_lock);

        /*
         * No new RXB's can enter the POSTED state
         */
        if(rxbp->rxbp_shutdown){
                spin_unlock(&rxbp->rxbp_lock);
                return -ESHUTDOWN;
        }

        LASSERT(!in_interrupt());

        LASSERT(rxb->rxb_state == RXB_STATE_IDLE);
        LASSERT(atomic_read(&rxb->rxb_refcount)==0);
        LASSERT(PtlHandleIsEqual(rxb->rxb_mdh,PTL_INVALID_HANDLE));

        list_add_tail(&rxb->rxb_list,&rxbp->rxbp_list);
        atomic_set(&rxb->rxb_refcount,1);
        rxb->rxb_state = RXB_STATE_POSTED;

        spin_unlock(&rxbp->rxbp_lock);

        /*
         * Attach the ME
         */
        rc = PtlMEAttach(
            kptllnd_data->kptl_nih,
            *kptllnd_tunables.kptl_portal,
            any,
            LNET_MSG_MATCHBITS,
            0, /* all matchbits are valid - ignore none*/
            PTL_UNLINK,
            PTL_INS_AFTER,
            &meh);
        if(rc != 0) {
                CERROR("PtlMeAttach rxb failed %d\n",rc);
                goto failure;
        }

        /*
         * Setup MD
         */
        md.start = rxb->rxb_buffer;
        md.length = PAGE_SIZE * *kptllnd_tunables.kptl_rxb_npages;
        md.threshold = PTL_MD_THRESH_INF;
        md.options = PTL_MD_OP_PUT;
        md.options |= PTL_MD_LUSTRE_COMPLETION_SEMANTICS;
        md.options |= PTL_MD_EVENT_START_DISABLE;
        md.options |= PTL_MD_MAX_SIZE;
        md.user_ptr = rxb;
        md.max_size = *kptllnd_tunables.kptl_max_immd_size;
        md.eq_handle = kptllnd_data->kptl_eqh;


        /*
         * Attach the MD
         */
        rc = PtlMDAttach(
                meh,
                md,
                PTL_UNLINK,
                &mdh);
        if(rc != 0){
                int rc2;
                CERROR("PtlMDAttach rxb failed %d\n",rc);
                rc2 = PtlMEUnlink(meh);
                LASSERT(rc2 == 0);
                goto failure;
        }

        /*
         * Assign the MDH under the lock
         * to deal with shutdown race, of
         * a partially constructed rbx
         */
        spin_lock(&rxbp->rxbp_lock);
        rxb->rxb_mdh = mdh;
        spin_unlock(&rxbp->rxbp_lock);

        return 0;


failure:
        /*
         * Cleanup on error
         */
        spin_lock(&rxbp->rxbp_lock);
        list_del_init(&rxb->rxb_list);
        atomic_set(&rxb->rxb_refcount,0);
        rxb->rxb_state = RXB_STATE_IDLE;
        spin_unlock(&rxbp->rxbp_lock);

        return rc;
}

void
kptllnd_rx_buffer_post_handle_error(
        kptl_rx_buffer_t *rxb)
{
        int rc;
        rc = kptllnd_rx_buffer_post(rxb);
        if(rc!=0){
                /* Don't log on shutdown */
                if(rc != -ESHUTDOWN)
                        CERROR("Failing to Repost buffer rc=%d\n",rc);

                kptllnd_rx_buffer_destroy(rxb);
                /* Should I destroy the peer?
                 * I don't think so.  But this now
                 * now means there is some chance
                 * under very heavy load that we will drop a packet.
                 * On the other hand, if there is more buffers in
                 * the pool that are reserved this won't happen.
                 * And secondly under heavly load it is liklye a
                 * a new peer will be added added, the reservation
                 * for the ones that were lost will
                 * get new backing buffers at that time.
                 *
                 * So things are starting to get bad, but
                 * in all likelihood things will be fine,
                 * and even better they might correct themselves
                 * in time.
                 */
        }
}

void
kptllnd_rx_buffer_destroy(
        kptl_rx_buffer_t *rxb)
{
        kptl_rx_buffer_pool_t *rxbp = rxb->rxb_pool;

        LASSERT(atomic_read(&rxb->rxb_refcount) == 0);
        LASSERT(rxb->rxb_state == RXB_STATE_IDLE);
        LASSERT(PtlHandleIsEqual(rxb->rxb_mdh,PTL_INVALID_HANDLE));

        spin_lock(&rxbp->rxbp_lock);
        list_del(&rxb->rxb_list);
        rxbp->rxbp_count--;
        spin_unlock(&rxbp->rxbp_lock);

        PORTAL_FREE( rxb->rxb_buffer,PAGE_SIZE * *kptllnd_tunables.kptl_rxb_npages);
        PORTAL_FREE(rxb,sizeof(*rxb));
}



void
kptllnd_rx_buffer_callback(ptl_event_t *ev)
{
        kptl_rx_buffer_t *rxb = ev->md.user_ptr;
        kptl_rx_buffer_pool_t *rxbp = rxb->rxb_pool;
        /*kptl_data_t  *kptllnd_data = rxb->rxb_po.po_kptllnd_data;*/
        kptl_rx_t *rx;
        int nob;
        int unlinked;

        /*
         * Set the local unlinked flag
         */
        unlinked = ev->type == PTL_EVENT_UNLINK;
#ifdef LUSTRE_PORTALS_UNLINK_SEMANTICS
        if( ev->unlinked )
                unlinked = 1;
#endif

        if(!rxbp->rxbp_shutdown){
                PJK_UT_MSG("RXB Callback %s(%d) rxb=%p nid="FMT_NID" unlink=%d\n",
                        get_ev_type_string(ev->type),ev->type,
                        rxb,ev->initiator.nid,unlinked);
        }

        LASSERT( ev->md.start == rxb->rxb_buffer);
        LASSERT( ev->offset + ev->mlength <= PAGE_SIZE * *kptllnd_tunables.kptl_rxb_npages);
        LASSERT( ev->type == PTL_EVENT_PUT_END || ev->type == PTL_EVENT_UNLINK);
        LASSERT( ev->match_bits == LNET_MSG_MATCHBITS);

        CDEBUG((ev->ni_fail_type == PTL_OK) ? D_NET : D_ERROR,
               "event type %d, status %d from "FMT_NID"\n",
               ev->type, ev->ni_fail_type,ev->initiator.nid);

        nob = ev->mlength;

        if(unlinked){
                spin_lock(&rxbp->rxbp_lock);

                /*
                 * Remove this from the list
                 */
                list_del_init(&rxb->rxb_list);

                LASSERT(rxb->rxb_state == RXB_STATE_POSTED);
                rxb->rxb_state = RXB_STATE_IDLE;
                rxb->rxb_mdh = PTL_INVALID_HANDLE;

                if( rxbp->rxbp_shutdown){
                        spin_unlock(&rxbp->rxbp_lock);
                        kptllnd_rx_buffer_decref(rxb,"portals");
                        return;
                }

                spin_unlock(&rxbp->rxbp_lock);


        }

        /*
         * Handle failure by just dropping the path
         */
        if(ev->ni_fail_type != PTL_NI_OK){
                CERROR("Message Dropped: ev status %d",ev->ni_fail_type);
                if(unlinked)
                        kptllnd_rx_buffer_scheduled_post(rxb);
                return;
        }

        /*
         * Allocate an RX
         */
        rx = kptllnd_rx_alloc(rxb->rxb_po.po_kptllnd_data);
        if(rx == 0){
                CERROR("Message Dropped: Memory allocation failure");
                if(unlinked)
                        kptllnd_rx_buffer_scheduled_post(rxb);
                return;
        }

        PJK_UT_MSG_DATA("New RX=%p\n",rx);

        /*
         * If we are unlinked we can just transfer the ref
         * that portals owned to the ref that this RX owns
         * otherwise we need to add a ref specifically for this RX
         */
        if(!unlinked)
                kptllnd_rx_buffer_addref(rxb,"rx");

        rx->rx_msg = rxb->rxb_buffer + ev->offset;
        rx->rx_rxb = rxb;
        rx->rx_nob = nob;
        rx->rx_initiator = ev->initiator;

        kptllnd_rx_schedule(rx);

        if(!rxbp->rxbp_shutdown){
                PJK_UT_MSG("<<< rx=%p rxb=%p\n",rx,rxb);
        }
}


void
kptllnd_rx_schedule (kptl_rx_t *rx)
{
        unsigned long    flags;
        kptl_data_t  *kptllnd_data = rx->rx_rxb->rxb_po.po_kptllnd_data;

        CDEBUG(D_NET, "rx\n");

        PJK_UT_MSG("RX Schedule %p\n",rx);

        spin_lock_irqsave(&kptllnd_data->kptl_sched_lock, flags);
        list_add_tail(&rx->rx_list,&kptllnd_data->kptl_sched_rxq);
        wake_up(&kptllnd_data->kptl_sched_waitq);
        spin_unlock_irqrestore(&kptllnd_data->kptl_sched_lock, flags);
}


void
kptllnd_rx_scheduler_handler(kptl_rx_t *rx)
{
        int                     rc;
        kptl_rx_buffer_t       *rxb = rx->rx_rxb;
        kptl_msg_t             *msg = rx->rx_msg;
        kptl_data_t            *kptllnd_data = rxb->rxb_po.po_kptllnd_data;
        kptl_peer_t            *peer = NULL;
        int                     returned_credits = 0;
        int                     type = msg->ptlm_type;
        lnet_nid_t              lnet_initiator_nid = ptl2lnetnid(kptllnd_data,rx->rx_initiator.nid);


        PJK_UT_MSG_DATA(">>> RXRXRXRXRXRXRXRXRXRXRXRX\n");
        PJK_UT_MSG_DATA("rx=%p nob=%d\n",rx,rx->rx_nob);

        /*
         * If the nob==0 then silently discard this message
         */
        if(rx->rx_nob == 0)
                goto exit;

        rc = kptllnd_msg_unpack(msg, rx->rx_nob, kptllnd_data);
        if (rc != 0) {
                CERROR ("Error %d unpacking rx from "FMT_NID"\n",
                        rc, rx->rx_initiator.nid);
                goto exit;
        }

        PJK_UT_MSG_DATA("RX=%p Type=%s(%d)\n",rx,
                get_msg_type_string(type),type);
        PJK_UT_MSG_DATA("Msg NOB = %d\n",msg->ptlm_nob);
        PJK_UT_MSG_DATA("Returned Credits=%d\n",msg->ptlm_credits);
        PJK_UT_MSG_DATA("Seq # ="LPX64"\n",msg->ptlm_seq);
        PJK_UT_MSG_DATA("lnet RX nid=" LPX64 "\n",lnet_initiator_nid);
        PJK_UT_MSG("ptl  RX nid=" FMT_NID "\n",rx->rx_initiator.nid);

        if(type == PTLLND_MSG_TYPE_HELLO)
        {
                peer = kptllnd_peer_handle_hello(
                        kptllnd_data,
                        lnet_initiator_nid,
                        msg);
                if( peer == NULL){
                        CERROR ("Failed to create peer for "LPX64"\n",
                                lnet_initiator_nid);
                        goto exit;
                }

                if (!( msg->ptlm_dststamp == kptllnd_data->kptl_incarnation ||
                       msg->ptlm_dststamp == 0)) {
                        CERROR ("Stale rx from "LPX64" dststamp "LPX64" expected "LPX64"\n",
                                peer->peer_nid,
                                msg->ptlm_dststamp,
                                kptllnd_data->kptl_incarnation );
                        goto exit;
                }
        }
        else
        {
                peer = kptllnd_peer_find(kptllnd_data,lnet_initiator_nid);
                if( peer == NULL){
                        CERROR ("No connection with "LPX64"\n",
                                lnet_initiator_nid);
                        goto exit;
                }

                if (msg->ptlm_dststamp != kptllnd_data->kptl_incarnation) {
                        CERROR ("Stale rx from "LPX64" dststamp "LPX64" expected "LPX64"\n",
                                peer->peer_nid,
                                msg->ptlm_dststamp,
                                kptllnd_data->kptl_incarnation );
                        goto exit;
                }
        }

        if( msg->ptlm_srcnid != peer->peer_nid){
                CERROR ("Stale rx srcnid "LPX64" expected "LPX64"\n",
                        msg->ptlm_srcnid,
                        peer->peer_nid );
                goto exit;
        }
        if( msg->ptlm_srcstamp != peer->peer_incarnation){
                CERROR ("Stale rx from "LPX64" srcstamp"LPX64" expected "LPX64"\n",
                        peer->peer_nid,
                        msg->ptlm_srcstamp,
                        peer->peer_incarnation );
                goto exit;
        }
        if( msg->ptlm_dstnid != kptllnd_data->kptl_ni->ni_nid){
                CERROR ("Stale rx from "LPX64" dststamp "LPX64" expected "LPX64"\n",
                        peer->peer_nid,
                        msg->ptlm_dstnid,
                        kptllnd_data->kptl_ni->ni_nid );
                goto exit;
        }

        /*
         * Save the number of credits
         */
        returned_credits = msg->ptlm_credits;

        /*
         * Attach the peer to the RX
         * it now is responsibly for releaseing the refrence
         */
        rx->rx_peer = peer;
        peer = 0;

        /*
         * Note: We are explicitly ignore sequence #
         * It is informational only
         */
        switch (msg->ptlm_type) {
        default:
                CERROR("Bad PTL message type %x from "LPX64"\n",
                       msg->ptlm_type, rx->rx_peer->peer_nid);
                break;

        case PTLLND_MSG_TYPE_HELLO:
                PJK_UT_MSG("PTLLND_MSG_TYPE_HELLO\n");
                break;

        case PTLLND_MSG_TYPE_NOOP:
                PJK_UT_MSG("PTLLND_MSG_TYPE_NOOP\n");
                break;

        case PTLLND_MSG_TYPE_IMMEDIATE:
                PJK_UT_MSG("PTLLND_MSG_TYPE_IMMEDIATE\n");
                rc = lnet_parse(kptllnd_data->kptl_ni,
                        &msg->ptlm_u.immediate.kptlim_hdr,
                        msg->ptlm_srcnid,
                        rx);
                /* RX Completing asynchronously */
                if( rc >= 0)
                        rx = 0;
                break;

        case PTLLND_MSG_TYPE_PUT:
        case PTLLND_MSG_TYPE_GET:
                PJK_UT_MSG("PTLLND_MSG_TYPE_%s\n",
                        msg->ptlm_type == PTLLND_MSG_TYPE_PUT ?
                        "PUT" : "GET");

                /*
                 * Save the last match bits used
                 */
                spin_lock(&rx->rx_peer->peer_lock);
                if(msg->ptlm_u.req.kptlrm_matchbits > rx->rx_peer->peer_last_matchbits_seen)
                        rx->rx_peer->peer_last_matchbits_seen = msg->ptlm_u.req.kptlrm_matchbits;
                spin_unlock(&rx->rx_peer->peer_lock);

                rc = lnet_parse(kptllnd_data->kptl_ni,
                        &msg->ptlm_u.req.kptlrm_hdr,
                        msg->ptlm_srcnid,
                        rx);

                /* RX Completing asynchronously */
                if( rc >= 0)
                        rx = 0;
                break;
         }


        CDEBUG (D_NET, "Received %x[%d] from "LPX64"\n",
                type, returned_credits, peer->peer_nid);

exit:
        /* PEER == NULL if it is not yet assigned or already
         * been attached to RX */
        if(peer)
                kptllnd_peer_decref(peer,"lookup");

        /* RX == NULL if it is completing asynchronously */
        if(rx)
                kptllnd_rx_decref(rx,"sched",kptllnd_data);

        PJK_UT_MSG_DATA("<<< RXRXRXRXRXRXRXRXRXRXRXRX rx=%p\n",rx);
        return;
}

void
kptllnd_rx_buffer_addref(
        kptl_rx_buffer_t *rxb,
        const char *owner)
{
        atomic_inc(&rxb->rxb_refcount);

#if 0
        /*
         * The below message could actually be out of sync
         * with the real ref count, and is for informational purposes
         * only
         */
        PJK_UT_MSG("rxb=%p owner=%s count=%d\n",rxb,owner,
                atomic_read(&rxb->rxb_refcount));
#endif
}

void
kptllnd_rx_buffer_decref(
        kptl_rx_buffer_t *rxb,
        const char *owner)
{
        if( !atomic_dec_and_test (&rxb->rxb_refcount)){

#if 0
                /*
                 * The below message could actually be out of sync
                 * with the real ref count, and is for informational purposes
                 * only
                 */
                PJK_UT_MSG("rxb=%p owner=%s count=%d\n",rxb,owner,
                        atomic_read(&rxb->rxb_refcount));
#endif
                return;
        }

#if 0
        PJK_UT_MSG("rxb=%p owner=%s LAST REF reposting\n",rxb,owner);
#endif

        kptllnd_rx_buffer_post_handle_error(rxb);
}

kptl_rx_t*
kptllnd_rx_alloc(
        kptl_data_t *kptllnd_data )
{
        kptl_rx_t* rx;

        if(IS_SIMULATION_ENABLED( FAIL_BLOCKING_RX_ALLOC )){
                PJK_UT_MSG_SIMULATION("FAIL_BLOCKING_RX_ALLOC SIMULATION triggered\n");
                CERROR ("FAIL_BLOCKING_RX_ALLOC SIMULATION triggered\n");
                STAT_UPDATE(kps_rx_allocation_failed);
                return 0;
        }

        rx = cfs_mem_cache_alloc ( kptllnd_data->kptl_rx_cache , CFS_SLAB_ATOMIC);
        if(rx == 0 ){
                CERROR("Failed to allocate rx\n");
                STAT_UPDATE(kps_rx_allocation_failed);

        }else{

                STAT_UPDATE(kps_rx_allocated);

                memset(rx,0,sizeof(rx));

                CFS_INIT_LIST_HEAD(&rx->rx_list);
                atomic_set(&rx->rx_refcount,1);
        }

        return rx;
}

void
kptllnd_rx_destroy(kptl_rx_t *rx,kptl_data_t *kptllnd_data)
{
        kptl_peer_t  *peer = rx->rx_peer;
        kptl_msg_t   *msg = rx->rx_msg;
        int returned_credits = msg->ptlm_credits;
        
        PJK_UT_MSG(">>> rx=%p\n",rx);

        STAT_UPDATE(kps_rx_released);

        LASSERT(atomic_read(&rx->rx_refcount)==0);

        if(rx->rx_rxb){
                PJK_UT_MSG("Release rxb=%p\n",rx->rx_rxb);
                kptllnd_rx_buffer_decref(rx->rx_rxb,"rx");
                rx->rx_rxb = 0;
        }else{
                PJK_UT_MSG("rxb already released\n");
        }

        if(peer){

                /*
                 * Update credits
                 * (Only after I've reposted the buffer)
                 */
                spin_lock(&peer->peer_lock);
                peer->peer_credits += returned_credits;
                LASSERT( peer->peer_credits <=
                        *kptllnd_tunables.kptl_peercredits);
                peer->peer_outstanding_credits++;
                LASSERT( peer->peer_outstanding_credits <=
                        *kptllnd_tunables.kptl_peercredits);
                spin_unlock(&peer->peer_lock);

                PJK_UT_MSG_DATA("Giving Back %d credits rx=%p\n",returned_credits,rx);

                /* Have I received credits that will let me send? */
                if (returned_credits != 0)
                        kptllnd_peer_check_sends(peer);

                kptllnd_peer_decref(peer,"lookup");
        }

        cfs_mem_cache_free(kptllnd_data->kptl_rx_cache,rx);

        PJK_UT_MSG("<<< rx=%p\n",rx);
}

void
kptllnd_rx_addref(kptl_rx_t *rx,const char *owner)
{
        atomic_inc(&rx->rx_refcount);

        /*
         * The below message could actually be out of sync
         * with the real ref count, and is for informational purposes
         * only
         */
        PJK_UT_MSG("rx=%p owner=%s count=%d\n",rx,owner,
                atomic_read(&rx->rx_refcount));
}

void
kptllnd_rx_decref(kptl_rx_t *rx,const char *owner,kptl_data_t *kptllnd_data)
{
        if( !atomic_dec_and_test (&rx->rx_refcount)){
                /*
                 * The below message could actually be out of sync
                 * with the real ref count, and is for informational purposes
                 * only
                 */
                PJK_UT_MSG("rx=%p owner=%s count=%d\n",rx,owner,
                        atomic_read(&rx->rx_refcount));
                return;
        }

        PJK_UT_MSG("rx=%p owner=%s LAST REF destroying\n",rx,owner);

        kptllnd_rx_destroy(rx,kptllnd_data);
}

