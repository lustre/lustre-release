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
kptllnd_tx_schedule (kptl_tx_t *tx);



int
kptllnd_setup_tx_descs (kptl_data_t *kptllnd_data)
{
        kptl_tx_t       *tx;
        int             i;

        CDEBUG(D_NET, "\n");

        /*
         * First initialize the tx descriptors
         */
        memset(kptllnd_data->kptl_tx_descs, 0,
               (*kptllnd_tunables.kptl_ntx) * sizeof(kptl_tx_t));

        for (i = 0; i < (*kptllnd_tunables.kptl_ntx); i++) {
                tx = &kptllnd_data->kptl_tx_descs[i];


                kptllnd_posted_object_setup(&tx->tx_po,
                                          kptllnd_data,
                                          POSTED_OBJECT_TYPE_TX);

                CFS_INIT_LIST_HEAD(&tx->tx_list);
                CFS_INIT_LIST_HEAD(&tx->tx_schedlist);

                /*
                 * Set the state
                 */
                tx->tx_state = TX_STATE_ON_IDLE_QUEUE;

                LIBCFS_ALLOC(tx->tx_msg, *kptllnd_tunables.kptl_max_msg_size);
                if (tx->tx_msg == NULL) {
                        CERROR("Failed to allocate TX payload\n");
                        goto failed;
                }

                LIBCFS_ALLOC(tx->tx_frags, sizeof(*tx->tx_frags));
                if (tx->tx_frags == NULL) {
                        CERROR("Failed to allocate TX frags\n");
                        goto failed;
                }
                
                /*
                 * Add this to the queue
                 */
                list_add (&tx->tx_list,&kptllnd_data->kptl_idle_txs);
        }

        return 0;

 failed:
        kptllnd_cleanup_tx_descs(kptllnd_data);
        return -ENOMEM;
}

void
kptllnd_cleanup_tx_descs(kptl_data_t *kptllnd_data)
{
        kptl_tx_t       *tx;
        int             i;

        CDEBUG(D_NET, "\n");

        for (i = 0; i < (*kptllnd_tunables.kptl_ntx); i++) {
                tx = &kptllnd_data->kptl_tx_descs[i];

                if (tx->tx_msg != NULL)
                        LIBCFS_FREE(tx->tx_msg, 
                                    *kptllnd_tunables.kptl_max_msg_size);
                        
                if (tx->tx_frags != NULL)
                        LIBCFS_FREE(tx->tx_frags, sizeof(*tx->tx_frags));

                LASSERT( tx->tx_state == TX_STATE_ON_IDLE_QUEUE );
        }
}

kptl_tx_t *
kptllnd_get_idle_tx(kptl_data_t *kptllnd_data,
                    enum kptl_tx_type purpose)
{
        kptl_tx_t      *tx = NULL;

        CDEBUG(D_NET, ">>> purpose=%d\n",purpose);

        if(IS_SIMULATION_ENABLED( FAIL_BLOCKING_TX_PUT_ALLOC ) && purpose == TX_TYPE_LARGE_PUT){
                CERROR ("FAIL_BLOCKING_TX_PUT_ALLOC SIMULATION triggered\n");
                tx = NULL;
                STAT_UPDATE(kps_tx_allocation_failed);
                goto exit;
        }
        if(IS_SIMULATION_ENABLED( FAIL_BLOCKING_TX_GET_ALLOC ) && purpose == TX_TYPE_LARGE_GET){
                CERROR ("FAIL_BLOCKING_TX_GET_ALLOC SIMULATION triggered\n");
                tx = NULL;
                STAT_UPDATE(kps_tx_allocation_failed);
                goto exit;
        }
        if(IS_SIMULATION_ENABLED( FAIL_BLOCKING_TX )){
                CERROR ("FAIL_BLOCKING_TX SIMULATION triggered\n");
                tx = NULL;
                STAT_UPDATE(kps_tx_allocation_failed);
                goto exit;
        }

        spin_lock(&kptllnd_data->kptl_tx_lock);

        if (!list_empty (&kptllnd_data->kptl_idle_txs)) {
                tx = list_entry (kptllnd_data->kptl_idle_txs.next,
                                 kptl_tx_t, tx_list);
                /*
                 * Remove it from the idle queue
                 */
                list_del_init (&tx->tx_list);
        }

        spin_unlock(&kptllnd_data->kptl_tx_lock);

        if (tx != NULL) {

                /*
                 * Check the state
                 */
                LASSERT(tx->tx_state == TX_STATE_ON_IDLE_QUEUE);

                /*
                 * Reference is now owned by caller
                 */
                LASSERT(atomic_read(&tx->tx_refcount)== 0);
                atomic_set(&tx->tx_refcount,1);



                /*
                 * Set the state and type
                 */
                tx->tx_state = TX_STATE_ALLOCATED;
                tx->tx_type = purpose;

                /*
                 * Initialize the TX descriptor so that cleanup can be
                 * handled easily even with a partially initialized descriptor
                 */
                tx->tx_mdh              = PTL_INVALID_HANDLE;
                tx->tx_mdh_msg          = PTL_INVALID_HANDLE;
                tx->tx_ptlmsg           = NULL;
                tx->tx_ptlmsg_reply     = NULL;
                tx->tx_peer             = NULL;
                tx->tx_associated_rx    = NULL;

                /*
                 * These must be re-initialized
                 */
                tx->tx_status           = -EINVAL;
                tx->tx_seen_send_end    = 0;
                tx->tx_seen_reply_end   = 0;
                tx->tx_payload_niov     = 0;
                tx->tx_payload_iov      = NULL;
                tx->tx_payload_kiov     = NULL;
                tx->tx_payload_offset   = 0;
                tx->tx_payload_nob      = 0;

                STAT_UPDATE(kps_tx_allocated);
        }else{
                STAT_UPDATE(kps_tx_allocation_failed);
        }


exit:
        CDEBUG(D_NET, "<<< tx=%p\n",tx);
        return tx;
}

void
kptllnd_tx_done (kptl_tx_t *tx)
{
        lnet_msg_t  *lnetmsg[2];
        int          status = tx->tx_status;
        kptl_data_t *kptllnd_data = tx->tx_po.po_kptllnd_data;

        LASSERT (!in_interrupt());

        CDEBUG(D_NET, ">>> tx=%p\n",tx);

        LASSERT(tx->tx_state != TX_STATE_ON_IDLE_QUEUE);
        LASSERT(PtlHandleIsEqual(tx->tx_mdh,PTL_INVALID_HANDLE));
        LASSERT(PtlHandleIsEqual(tx->tx_mdh_msg,PTL_INVALID_HANDLE));
        LASSERT(atomic_read(&tx->tx_refcount) == 0);
        LASSERT(list_empty(&tx->tx_schedlist)); /*not any the scheduler list*/

        /* stash lnet msgs for finalize AFTER I free this tx desc */
        lnetmsg[0] = tx->tx_ptlmsg; tx->tx_ptlmsg = NULL;
        lnetmsg[1] = tx->tx_ptlmsg_reply; tx->tx_ptlmsg_reply = NULL;

        /*
         * Release the associated RX if there is one
         */
        if(tx->tx_associated_rx){
                CDEBUG(D_NET, "tx=%p destroy associated rx %p\n",tx,tx->tx_associated_rx);
                kptllnd_rx_decref(tx->tx_associated_rx,"tx",kptllnd_data);
                tx->tx_associated_rx = NULL;
        }

        /*
         * Cleanup resources associate with the peer
         */
        if(tx->tx_peer){
                CDEBUG(D_NET, "tx=%p detach from peer=%p\n",tx,tx->tx_peer);
                kptllnd_peer_dequeue_tx(tx->tx_peer,tx);
                kptllnd_peer_decref(tx->tx_peer,"tx");
                tx->tx_peer = NULL;
        }

        LASSERT(list_empty(&tx->tx_list)); /* removed from any peer list*/

        /*
         * state = back on idle queue
         */
        tx->tx_state = TX_STATE_ON_IDLE_QUEUE;

        /*
         * Put this tx descriptor back on the idle queue
         */
        spin_lock(&kptllnd_data->kptl_tx_lock);
        list_add (&tx->tx_list, &kptllnd_data->kptl_idle_txs);
        STAT_UPDATE(kps_tx_released);
        spin_unlock(&kptllnd_data->kptl_tx_lock);
        
        if (lnetmsg[0] != NULL)
                lnet_finalize(kptllnd_data->kptl_ni, lnetmsg[0], status);

        if (lnetmsg[1] != NULL)
                lnet_finalize(kptllnd_data->kptl_ni, lnetmsg[1], status);

        CDEBUG(D_NET, "<<< tx=%p\n",tx);
}

void
kptllnd_tx_schedule (kptl_tx_t *tx)
{
        kptl_data_t *kptllnd_data = tx->tx_po.po_kptllnd_data;
        unsigned long    flags;

        CDEBUG(D_NET, "tx=%p\n",tx);

        spin_lock_irqsave(&kptllnd_data->kptl_sched_lock, flags);
        LASSERT(list_empty(&tx->tx_schedlist));
        list_add_tail(&tx->tx_schedlist,&kptllnd_data->kptl_sched_txq);
        wake_up(&kptllnd_data->kptl_sched_waitq);
        spin_unlock_irqrestore(&kptllnd_data->kptl_sched_lock, flags);
}

void
kptllnd_tx_callback(ptl_event_t *ev)
{
        kptl_tx_t       *tx = ev->md.user_ptr;
        kptl_peer_t     *peer;
        int              rc;
        int              do_decref = 0;
        unsigned long    flags;

        CDEBUG(D_NET, ">>> %s(%d) tx=%p fail=%d\n",
                get_ev_type_string(ev->type),ev->type,tx,ev->ni_fail_type);

        STAT_UPDATE(kps_tx_event);

#ifdef LUSTRE_PORTALS_UNLINK_SEMANTICS
        CDEBUG(D_NET, "ev->unlinked=%d\n",ev->unlinked);
        if(ev->unlinked)
                STAT_UPDATE(kps_tx_unlink_event);
#endif

        if(ev->type == PTL_EVENT_UNLINK ){
#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                STAT_UPDATE(kps_tx_unlink_event);
                /*
                 * Ignore unlink events if we don't
                 * have lustre semantics as these only occur
                 * in one-to-one correspondence with OPXXX_END
                 * event's and we've already cleaned up in
                 * those cases.
                 */
                CDEBUG(D_NET, "<<<\n");
                return;
#else
                /*
                 * Clear the handles
                 */
                if(PtlHandleIsEqual(ev->md_handle,tx->tx_mdh))
                        tx->tx_mdh = PTL_INVALID_HANDLE;
                else if (PtlHandleIsEqual(ev->md_handle,tx->tx_mdh_msg))
                        tx->tx_mdh_msg = PTL_INVALID_HANDLE;

                tx->tx_status = -EINVAL;
                kptllnd_tx_scheduled_decref(tx);
                CDEBUG(D_NET, "<<<\n");
                return;
#endif
        }

        LASSERT(tx->tx_peer != NULL);
        peer = tx->tx_peer;

        spin_lock_irqsave(&peer->peer_lock, flags);

        /*
         * Save the status flag
         */
        tx->tx_status = ev->ni_fail_type == PTL_NI_OK ? 0 : -EINVAL;

        switch(ev->type)
        {
        case PTL_EVENT_SEND_END:

                /*
                 * Mark that we've seen an SEND END
                 */
                tx->tx_seen_send_end = 1;

                switch(tx->tx_type)
                {
                default:
                        LBUG();
                        break;

                case TX_TYPE_SMALL_MESSAGE:
                        CDEBUG(D_NET, "TX_TYPE_SMALL_MESSAGE\n");
                        LASSERT(PtlHandleIsEqual(tx->tx_mdh,PTL_INVALID_HANDLE));

                        /*
                         * Success or failure we are done with the Message MD
                         */
                        tx->tx_mdh_msg = PTL_INVALID_HANDLE;
                        do_decref = 1;
                        break;

                case TX_TYPE_LARGE_PUT:
                case TX_TYPE_LARGE_GET:
                        CDEBUG(D_NET, "TX_TYPE_LARGE_%s\n",
                                tx->tx_type == TX_TYPE_LARGE_PUT ?
                                "PUT" : "GET");
                        /*
                         * Success or failure we are done with the Message MD
                         */
                        tx->tx_mdh_msg = PTL_INVALID_HANDLE;

                        /*
                         * There was an error, and we're not going to make any more
                         *    progress (obviously) and the
                         *    PUT_END or GET_END is never going to come.
                         */
                        if(ev->ni_fail_type != PTL_NI_OK ){

                                /*
                                 * There was a error in the message
                                 * we can safely unlink the MD
                                 *
                                 */
                                if(!PtlHandleIsEqual(tx->tx_mdh,PTL_INVALID_HANDLE)){
                                        LASSERT(atomic_read(&tx->tx_refcount)>1);
                                        rc = PtlMDUnlink(tx->tx_mdh);
                                        LASSERT(rc == 0);
#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                                        tx->tx_mdh = PTL_INVALID_HANDLE;
                                        /*
                                         * We are holding another reference
                                         * so this is not going to do anything
                                         * but decrement the tx->ref_count
                                         */
                                        kptllnd_tx_decref(tx);
#endif
                                }
                        }

                        do_decref = 1;
                        break;

                case TX_TYPE_LARGE_PUT_RESPONSE:
                        CDEBUG(D_NET, "TX_TYPE_LARGE_PUT_RESPONSE\n");
                        LASSERT(PtlHandleIsEqual(tx->tx_mdh_msg,PTL_INVALID_HANDLE));

                        /*
                         * If'we've already seen the reply end
                         * or if this is a failure and we're NEVER going
                         * to see the reply end, release our reference here
                         */
                        if(tx->tx_seen_reply_end || ev->ni_fail_type != PTL_NI_OK){
                                tx->tx_mdh = PTL_INVALID_HANDLE;
                                do_decref = 1;
                        }
                        break;

                case TX_TYPE_LARGE_GET_RESPONSE:
                        CDEBUG(D_NET, "TX_TYPE_LARGE_GET_RESPONSE\n");
                        LASSERT(PtlHandleIsEqual(tx->tx_mdh_msg,PTL_INVALID_HANDLE));

                        /*
                         * Success or failure we are done with the MD
                         */
                        tx->tx_mdh = PTL_INVALID_HANDLE;
                        do_decref = 1;
                        break;
                }
                break;

        case PTL_EVENT_GET_END:
                LASSERT(tx->tx_type == TX_TYPE_LARGE_PUT);
                tx->tx_mdh = PTL_INVALID_HANDLE;
                do_decref = 1;
                break;
        case PTL_EVENT_PUT_END:
                LASSERT(tx->tx_type == TX_TYPE_LARGE_GET);
                tx->tx_mdh = PTL_INVALID_HANDLE;
                do_decref = 1;
                break;
        case PTL_EVENT_REPLY_END:
                LASSERT(tx->tx_type == TX_TYPE_LARGE_PUT_RESPONSE);
                tx->tx_seen_reply_end = 1;
                if(tx->tx_seen_send_end){
                        tx->tx_mdh = PTL_INVALID_HANDLE;
                        do_decref = 1;
                }
                break;
        default:
                LBUG();
        }

        spin_unlock_irqrestore(&peer->peer_lock, flags);

        if(do_decref)
                kptllnd_tx_scheduled_decref(tx);
        CDEBUG(D_NET, "<<< decref=%d\n",do_decref);
}

void
kptllnd_tx_addref(
        kptl_tx_t *tx)
{
        atomic_inc(&tx->tx_refcount);
}

void
kptllnd_tx_decref(
        kptl_tx_t *tx)
{
        if( !atomic_dec_and_test(&tx->tx_refcount)){
                return;
        }

        CDEBUG(D_NET, "tx=%p LAST REF\n",tx);
        kptllnd_tx_done(tx);
}

void
kptllnd_tx_scheduled_decref(
        kptl_tx_t *tx)
{
        if( !atomic_dec_and_test(&tx->tx_refcount)){
                /*
                 * The below message could actually be out of sync
                 * with the real ref count, and is for informational purposes
                 * only
                 */
                CDEBUG(D_NET, "tx=%p count=%d\n",tx,
                        atomic_read(&tx->tx_refcount));
                return;
        }

        CDEBUG(D_NET, "tx=%p LAST REF\n",tx);
        kptllnd_tx_schedule(tx);
}
