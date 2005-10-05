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

void kptllnd_clean_canceled_peers(kptl_data_t *kptllnd_data);

void
kptllnd_setup_md(
        kptl_data_t     *kptllnd_data,
        ptl_md_t        *md,
        unsigned int     op,
        kptl_tx_t       *tx,
        unsigned int     payload_niov,
        struct iovec    *payload_iov,
        lnet_kiov_t     *payload_kiov,
        unsigned int     payload_offset,
        int              payload_nob,
        tempiov_t       *tempiov)
{
        unsigned int niov = 0;

        PJK_UT_MSG_DATA("%s nob=%d offset=%d niov=%d\n",
                op == PTL_MD_OP_GET ? "GET" : "PUT",
                payload_nob,payload_offset,payload_niov);

        /* One but not both of iov or kiov must be NULL (XOR) */
        LASSERT( (payload_iov != NULL && payload_kiov == NULL) ||
                 (payload_iov == NULL && payload_kiov != NULL ) );

        /* We have a put or get operation*/
        LASSERT( op == PTL_MD_OP_GET || op == PTL_MD_OP_PUT);


        /* Only one operation then unlink */
        md->threshold = 1;

        /*
         * Get operations need threshold +1 to handle the
         * reply operation.  But only on the receiver side.
         */
        if( op == PTL_MD_OP_GET && tx->tx_associated_rx != NULL)
                md->threshold++;

        /* setup the options*/
        md->options = op;
        md->options |= PTL_MD_LUSTRE_COMPLETION_SEMANTICS;
        /* we don't care about the start event */
        md->options |= PTL_MD_EVENT_START_DISABLE;

        /* If this is a PUT then we need to disable ACK */
        /* we don't need an ACK, we'll get a callback when it is complete */
        if( op == PTL_MD_OP_PUT)
                md->options |= PTL_MD_ACK_DISABLE;

        /* point back to this TX descriptor so we know what to complete
         * when the event is triggered */
        md->user_ptr = tx;

        md->eq_handle = kptllnd_data->kptl_eqh;
        if (payload_iov != NULL){

                while (payload_offset >= payload_iov->iov_len) {
                        payload_offset -= payload_iov->iov_len;
                        payload_iov++;
                        payload_niov--;
                        LASSERT (payload_niov > 0);
                }

                while(payload_nob){
                        LASSERT( payload_offset < payload_iov->iov_len);
                        LASSERT (payload_niov > 0);
                        LASSERT (niov < sizeof(tempiov->iov)/sizeof(tempiov->iov[0]));

                        tempiov->iov[niov].iov_base = payload_iov->iov_base + payload_offset;
                        tempiov->iov[niov].iov_len  = min((int)(payload_iov->iov_len - payload_offset),
                                                (int)payload_nob);

                        PJK_UT_MSG("iov_base[%d]=%p\n",niov,tempiov->iov[niov].iov_base);
                        PJK_UT_MSG("iov_len[%d] =%d\n",niov,tempiov->iov[niov].iov_len);

                        payload_offset = 0;
                        payload_nob -= tempiov->iov[niov].iov_len;
                        payload_iov++;
                        payload_niov--;
                        niov++;
                }

                md->start = tempiov->iov;
                md->options |= PTL_MD_IOVEC;
        }else{

#ifdef _USING_LUSTRE_PORTALS_

                while (payload_offset >= payload_kiov->kiov_len) {
                        payload_offset -= payload_kiov->kiov_len;
                        payload_kiov++;
                        payload_niov--;
                        LASSERT (payload_niov > 0);
                }

                while(payload_nob){
                        LASSERT( payload_offset < payload_kiov->kiov_len);
                        LASSERT (payload_niov > 0);
                        LASSERT (niov < sizeof(tempiov->kiov)/sizeof(tempiov->kiov[0]));

                        tempiov->kiov[niov].kiov_page   = payload_kiov->kiov_page;
                        tempiov->kiov[niov].kiov_offset = payload_kiov->kiov_offset + payload_offset;
                        tempiov->kiov[niov].kiov_len    = min((int)(payload_kiov->kiov_len - payload_offset),
                                                        (int)payload_nob);

                        payload_offset = 0;
                        payload_nob -=  tempiov->kiov[niov].kiov_len;
                        payload_kiov++;
                        payload_niov--;
                        niov++;
                }

                md->start = tempiov->kiov;
                md->options |= PTL_MD_KIOV;

#else /* _USING_CRAY_PORTALS_ */

/*
 * If we're using CRAY PORTALS
 * it is not supposed to support PTL_MD_KIOV
 */
#ifdef PTL_MD_KIOV
#error "Conflicting compilation directives"
#endif

                PJK_UT_MSG("payload_offset %d\n",payload_offset);
                PJK_UT_MSG("payload_niov   %d\n",payload_niov);
                PJK_UT_MSG("payload_nob    %d\n",payload_nob);

                while (payload_offset >= payload_kiov->kiov_len) {
                        payload_offset -= payload_kiov->kiov_len;
                        payload_kiov++;
                        payload_niov--;
                        LASSERT (payload_niov > 0);
                }

                while(payload_nob){

                        LASSERT( payload_offset < payload_kiov->kiov_len);
                        LASSERT (payload_niov > 0);
                        LASSERT (niov < sizeof(tempiov->iov)/sizeof(tempiov->iov[0]));

                        PJK_UT_MSG("kiov_page  [%d]=%p (phys)\n",niov,(void*)page_to_phys(payload_kiov->kiov_page));
                        PJK_UT_MSG("kiov_offset[%d]=%d (phys)\n",niov,payload_kiov->kiov_offset);
                        PJK_UT_MSG("kiov_len   [%d]=%d (phys)\n",niov,payload_kiov->kiov_len);

                        tempiov->iov[niov].iov_base = (void *)(
                                page_to_phys(payload_kiov->kiov_page) +
                                payload_kiov->kiov_offset +
                                payload_offset);
                        tempiov->iov[niov].iov_len = min(
                                (int)(payload_kiov->kiov_len - payload_offset),
                                (int)payload_nob);

                        PJK_UT_MSG("iov_base[%d]=%p\n",niov,tempiov->iov[niov].iov_base);
                        PJK_UT_MSG("iov_len [%d]=%d\n",niov,tempiov->iov[niov].iov_len);

                        payload_offset = 0;
                        payload_nob -= tempiov->iov[niov].iov_len;
                        payload_kiov++;
                        payload_niov--;
                        niov++;
                }

                md->start = tempiov->iov;
                md->options |= PTL_MD_IOVEC | PTL_MD_PHYS;
#endif

        }

        /*
         * When using PTL_MD_IOVEC or PTL_MD_KIOV this is not
         * length, rather it is # iovs
         */
        md->length = niov;

        PJK_UT_MSG("md->options=%x\n",md->options);
        PJK_UT_MSG("md->length=%d\n",md->length);
}

int
kptllnd_start_bulk_rdma(
        kptl_data_t     *kptllnd_data,
        kptl_rx_t       *rx,
        lnet_msg_t      *lntmsg,
        unsigned int     op,
        unsigned int     payload_niov,
        struct iovec    *payload_iov,
        lnet_kiov_t     *payload_kiov,
        unsigned int     payload_offset,
        int              payload_nob)
{
        kptl_tx_t       *tx;
        ptl_md_t         md;
        ptl_err_t        ptl_rc;
        ptl_err_t        ptl_rc2;
        int              rc;
        tempiov_t        tempiov;
        kptl_msg_t      *rxmsg = rx->rx_msg;
        kptl_peer_t     *peer = rx->rx_peer;
        unsigned long    flags;
        ptl_handle_md_t  mdh;


        /*
         * Get an idle tx descriptor
         */
        LASSERT(op ==  PTL_MD_OP_GET || op == PTL_MD_OP_PUT);
        tx = kptllnd_get_idle_tx(kptllnd_data,
                op == PTL_MD_OP_GET ? TX_TYPE_LARGE_PUT_RESPONSE :
                                      TX_TYPE_LARGE_GET_RESPONSE);
        if(tx == NULL){
                CERROR ("Can't start bulk rdma %d to "FMT_NID": tx descs exhausted\n",
                        op, rx->rx_initiator.nid);
                return -ENOMEM;
        }

        /*
         * Attach the RX to the TX and take a refrence
         */
        tx->tx_associated_rx = rx;
        kptllnd_rx_addref(rx,"tx");

        PJK_UT_MSG_DATA(">>> %s rx=%p associated with tx=%p\n",
                op == PTL_MD_OP_GET ? "GET" : "PUT",
                rx,tx);
        PJK_UT_MSG_DATA("matchibts=" LPX64 "\n",
                rxmsg->ptlm_u.req.kptlrm_matchbits);

        /*
         * Setup the MD
         */
        kptllnd_setup_md(kptllnd_data,&md,op,tx,
                payload_niov,payload_iov,payload_kiov,
                payload_offset,payload_nob,&tempiov);

        /*
         * Attach the MD
         */
        ptl_rc = PtlMDBind(
                kptllnd_data->kptl_nih,
                md,
                PTL_UNLINK,
                &mdh);
        if(ptl_rc != PTL_OK){
                CERROR("PtlMDBind failed %d\n",ptl_rc);
                rc = -ENOMEM;
                goto end;
        }

        spin_lock_irqsave(&peer->peer_lock, flags);

        tx->tx_mdh = mdh;

        STAT_UPDATE(kps_posted_tx_bulk_mds);

        /*
         * And save the portals message
         */
        tx->tx_ptlmsg = lntmsg;

        /*
         * Queue the request on the peer
         */
        kptllnd_peer_queue_bulk_rdma_tx_locked(peer,tx);

        /*
         * Grab a ref so the TX doesn't dissappear
         */
        kptllnd_tx_addref(tx);

        spin_unlock_irqrestore(&peer->peer_lock, flags);


        /*
         * Do the Put
         */
        if( op == PTL_MD_OP_PUT)
        {
                ptl_rc = PtlPut (
                            tx->tx_mdh,
                            PTL_NOACK_REQ,         /* we dont need an ack */
                            rx->rx_initiator,      /* peer "address" */
                            *kptllnd_tunables.kptl_portal,         /* portal */
                            0,                     /* cookie */
                            rxmsg->ptlm_u.req.kptlrm_matchbits, /* match bits */
                            0,                     /* offset - unused */
                            0);                    /* header data */
        }else{
                ptl_rc = PtlGet (
                            tx->tx_mdh,
                            rx->rx_initiator,      /* peer "address" */
                            *kptllnd_tunables.kptl_portal,         /* portal */
                            0,                     /* cookie */
                            rxmsg->ptlm_u.req.kptlrm_matchbits, /* match bits */
                            0);                    /* offset - unused*/
        }

        if(ptl_rc != PTL_OK){
                CERROR("Ptl%s failed: %d\n",
                        op == PTL_MD_OP_GET ? "Get" : "Put",ptl_rc);


                /*
                 * Unlink the MD because it's not yet in use
                 * this should happen immediately
                 */
                LASSERT(atomic_read(&tx->tx_refcount)>1);
                ptl_rc2 = PtlMDUnlink(tx->tx_mdh);
                LASSERT(ptl_rc2 == PTL_OK);

#ifndef LUSTRE_PORTALS_UNLINK_SEMANTICS
                /* If we have LUSTRE Portals UNLINK semantics
                 * we'll get an unlink event.  If we have standard
                 * Portals semantics we decref the TX explicitly here
                 */
                tx->tx_mdh = PTL_INVALID_HANDLE;
                kptllnd_tx_decref(tx);
#endif

                spin_lock_irqsave(&peer->peer_lock, flags);

                /*
                 * We are returning failure so we don't
                 * want tx_done to finalize the message
                 * so we set it to zero
                 */
                tx->tx_ptlmsg = NULL;

                kptllnd_peer_dequeue_tx_locked(peer,tx);
                tx->tx_peer = NULL;

                spin_unlock_irqrestore(&peer->peer_lock, flags);

                rc = -ENOMEM;
                goto end;
        }

        rc = 0;

end:
        /*
         * Release our temporary reference
         * (this one could be the last)
         */
        kptllnd_tx_decref(tx);

        PJK_UT_MSG("<<< rc=%d\n",rc);
        return rc;
}


void
kptllnd_do_put(
        kptl_tx_t       *tx,
        lnet_msg_t      *lntmsg,
        kptl_data_t     *kptllnd_data)
{
        LASSERT(tx != NULL);

        tx->tx_payload_niov     = lntmsg->msg_niov;
        tx->tx_payload_iov      = lntmsg->msg_iov;
        tx->tx_payload_kiov     = lntmsg->msg_kiov;
        tx->tx_payload_offset   = lntmsg->msg_offset;
        tx->tx_payload_nob      = lntmsg->msg_len;

        tx->tx_msg->ptlm_u.req.kptlrm_hdr = lntmsg->msg_hdr;
        kptllnd_init_msg (tx->tx_msg,
                          PTLLND_MSG_TYPE_PUT,
                          sizeof(kptl_request_msg_t));
        kptllnd_tx_launch(tx, lntmsg->msg_target.nid,lntmsg);
}

int
kptllnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
        lnet_hdr_t       *hdr = &lntmsg->msg_hdr;
        int               type = lntmsg->msg_type;
        lnet_process_id_t target = lntmsg->msg_target;
        int               target_is_router = lntmsg->msg_target_is_router;
        int               routing = lntmsg->msg_routing;
        unsigned int      payload_niov = lntmsg->msg_niov;
        struct iovec     *payload_iov = lntmsg->msg_iov;
        lnet_kiov_t      *payload_kiov = lntmsg->msg_kiov;
        unsigned int      payload_offset = lntmsg->msg_offset;
        unsigned int      payload_nob = lntmsg->msg_len;
        kptl_tx_t        *tx = NULL;
        kptl_data_t      *kptllnd_data = ni->ni_data;
        int               nob;
        int               rc;

        PJK_UT_MSG_DATA(">>> SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");
        PJK_UT_MSG_DATA("nob=%d nov=%d offset=%d to %s\n",
               payload_nob, payload_niov, payload_offset,
               libcfs_id2str(target));
        PJK_UT_MSG_DATA("routing=%d target_is_router=%d\n",
                routing,target_is_router);

        if(routing)
                STAT_UPDATE(kps_send_routing);
        if(target_is_router)
                STAT_UPDATE(kps_send_target_is_router);

        /* NB 'private' is different depending on what we're sending.... */

        CDEBUG(D_NET, "sending %d bytes in %d frags to %s\n",
               payload_nob, payload_niov, libcfs_id2str(target));

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= LNET_MAX_IOV);

        LASSERT (payload_niov <= PTL_MD_MAX_IOV); /* !!! */

        /* Thread context */
        LASSERT (!in_interrupt());
        /* payload is either all vaddrs or all pages */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));

        /*
         * we rely on this being true, as we only store hdr
         * in the tx descriptor, and just ignore type
         */
        LASSERT(hdr->type == type);

        switch (type) {
        default:
                LBUG();
                return -EINVAL;

        case LNET_MSG_PUT:
                PJK_UT_MSG_DATA("LNET_MSG_PUT\n");

                /*
                 * Get an idle tx descriptor
                 */
                tx = kptllnd_get_idle_tx(kptllnd_data,TX_TYPE_LARGE_PUT);
                if(tx == NULL){
                        CERROR ("Can't send %d to "LPX64": tx descs exhausted\n",
                                type, target.nid);
                        return -ENOMEM;
                }

                /* Is the payload small enough not to need RDMA? */
                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[payload_nob]);
                if (nob <= *kptllnd_tunables.kptl_max_immd_size)
                        break;


                STAT_UPDATE(kps_send_put);

                kptllnd_do_put(tx,lntmsg,kptllnd_data);

                PJK_UT_MSG_DATA("<<< SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");
                return 0;

        case LNET_MSG_GET:

                PJK_UT_MSG_DATA("LNET_MSG_GET\n");

                /*
                 * Get an idle tx descriptor
                 */
                tx = kptllnd_get_idle_tx(kptllnd_data,TX_TYPE_LARGE_GET);
                if(tx == NULL){
                        CERROR ("Can't send %d to "LPX64": tx descs exhausted\n",
                                type, target.nid);
                        return -ENOMEM;
                }

                /*
                 * If routing go immediate
                 */
                if(target_is_router || routing)
                        break;

                PJK_UT_MSG_DATA("nob=%d\n",lntmsg->msg_md->md_length);

                /* Is the payload small enough not to need RDMA? */
                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[lntmsg->msg_md->md_length]);
                if (nob <= *kptllnd_tunables.kptl_max_immd_size)
                        break;

                STAT_UPDATE(kps_send_get);

                tx->tx_payload_offset = 0;
                tx->tx_payload_niov = lntmsg->msg_md->md_niov;
                tx->tx_payload_nob  = lntmsg->msg_md->md_length;

                if((lntmsg->msg_md->md_options & LNET_MD_KIOV) != 0){
                        tx->tx_payload_iov = NULL;
                        tx->tx_payload_kiov = lntmsg->msg_md->md_iov.kiov;
                }else{
                        LASSERT((lntmsg->msg_md->md_options & LNET_MD_IOVEC) != 0);
                        tx->tx_payload_iov = lntmsg->msg_md->md_iov.iov;
                        tx->tx_payload_kiov = NULL;
                }

                tx->tx_msg->ptlm_u.req.kptlrm_hdr = *hdr;
                kptllnd_init_msg (tx->tx_msg,
                                  PTLLND_MSG_TYPE_GET,
                                  sizeof(kptl_request_msg_t));

                tx->tx_ptlmsg_reply =
                        lnet_create_reply_msg(kptllnd_data->kptl_ni,lntmsg);

                goto launch;

        case LNET_MSG_ACK:
                PJK_UT_MSG_DATA("LNET_MSG_ACK\n");
                LASSERT (payload_nob == 0);
                break;

        case LNET_MSG_REPLY:
                PJK_UT_MSG_DATA("LNET_MSG_REPLY\n");

                STAT_UPDATE(kps_send_reply);

                if(routing!=0 || target_is_router!=0)
                {
                        /*
                         * Get an idle tx descriptor
                         */
                        tx = kptllnd_get_idle_tx(kptllnd_data,TX_TYPE_LARGE_PUT);
                        if(tx == NULL){
                                CERROR ("Can't send %d to "LPX64": tx descs exhausted\n",
                                        type, target.nid);
                                return -ENOMEM;
                        }

                        /* Is the payload small enough not to need RDMA? */
                        nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[payload_nob]);
                        if (nob <= *kptllnd_tunables.kptl_max_immd_size)
                                break;

                        kptllnd_do_put(tx,lntmsg,kptllnd_data);

                        PJK_UT_MSG_DATA("<<< SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");
                        return 0;
                }else{
                        /*
                         * Reply's private is the incoming rx descriptor
                         */
                        kptl_rx_t *rx = private;
                        LASSERT(rx != NULL);

                        /*
                         * If the request was to NOT do RDMA
                         * break out and just send back an IMMEDIATE message
                         */
                        if (rx->rx_msg->ptlm_type == PTLLND_MSG_TYPE_IMMEDIATE) {
                                /* RDMA not expected */
                                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[payload_nob]);
                                if (nob > *kptllnd_tunables.kptl_max_immd_size) {
                                        CERROR("REPLY for "LPX64" too big but RDMA not requested:"
                                               "%d (max for message is %d)\n",
                                               target.nid, payload_nob,
                                               *kptllnd_tunables.kptl_max_immd_size);
                                        CERROR("Can't REPLY IMMEDIATE %d to "LPX64"\n",
                                               nob, target.nid);
                                        return -EINVAL;
                                }
                                break;
                        }


                        /* Incoming message consistent with RDMA? */
                        if (rx->rx_msg->ptlm_type != PTLLND_MSG_TYPE_GET) {
                                CERROR("REPLY to "LPX64" bad msg type %x!!!\n",
                                       target.nid, rx->rx_msg->ptlm_type);
                                return -EINVAL;
                        }

                        rc = kptllnd_start_bulk_rdma(
                                kptllnd_data,
                                rx,
                                lntmsg,
                                PTL_MD_OP_PUT,
                                payload_niov,
                                payload_iov,
                                payload_kiov,
                                payload_offset,
                                payload_nob);
                        PJK_UT_MSG_DATA("<<< SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS rc=%d\n",rc);
                        return rc;
                }
        }


        if(tx == NULL){
                PJK_UT_MSG_DATA("PTLLND_MSG_TYPE_IMMEDIATE\n");

                /*
                 * Get an idle tx descriptor
                 */
                tx = kptllnd_get_idle_tx(kptllnd_data,TX_TYPE_SMALL_MESSAGE);
                if(tx == NULL){
                        CERROR ("Can't send %d to "LPX64": tx descs exhausted\n",
                                type, target.nid);
                        return -ENOMEM;
                }
        }else{
                PJK_UT_MSG_DATA("Using PTLLND_MSG_TYPE_IMMEDIATE\n");
                /*
                 * Repurpose this TX
                 */
                tx->tx_type = TX_TYPE_SMALL_MESSAGE;

        }

        STAT_UPDATE(kps_send_immd);

        LASSERT (offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[payload_nob])
                 <= *kptllnd_tunables.kptl_max_immd_size);

        /*
         * Setup the header
         */
        tx->tx_msg->ptlm_u.immediate.kptlim_hdr = *hdr;

        if (payload_nob > 0) {
                if (payload_kiov != NULL)
                        lnet_copy_kiov2flat(
                                *kptllnd_tunables.kptl_max_immd_size,
                                tx->tx_msg->ptlm_u.immediate.kptlim_payload,
                                0,
                                payload_niov, payload_kiov,
                                payload_offset, payload_nob);
                else
                        lnet_copy_iov2flat(
                                *kptllnd_tunables.kptl_max_immd_size,
                                tx->tx_msg->ptlm_u.immediate.kptlim_payload,
                                0,
                                payload_niov, payload_iov,
                                payload_offset, payload_nob);
        }

        nob = offsetof(kptl_immediate_msg_t, kptlim_payload[payload_nob]);
        kptllnd_init_msg (tx->tx_msg, PTLLND_MSG_TYPE_IMMEDIATE,nob);


launch:
        kptllnd_tx_launch(tx, target.nid,lntmsg);
        PJK_UT_MSG_DATA("<<< SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");
        return 0;
}

int kptllnd_eager_recv(
        struct lnet_ni *ni,
        void *private,
        lnet_msg_t *msg,
        void **new_privatep)
{
        //kptl_data_t    *kptllnd_data = ni->ni_data;
        kptl_rx_t    *rx = private;

        PJK_UT_MSG_DATA("Eager RX=%p RXB=%p\n",rx,rx->rx_rxb);

        LASSERT(rx->rx_nob < *kptllnd_tunables.kptl_max_immd_size);

        /*
         * Copy the data directly into the RX
         */
        memcpy(rx->rx_payload,rx->rx_msg,rx->rx_nob);

        *new_privatep = rx;

        /*
         * Free the request buffer
         * will repost of we are the last ones using it
         */
        LASSERT(rx->rx_rxb != NULL);
        kptllnd_rx_buffer_decref(rx->rx_rxb,"rx-eager");
        rx->rx_rxb = NULL;

        /*
         * Now point the msg buffer at the RX descriptor payload
         * rather than the RXB (because that is now freed!
         */
        rx->rx_msg = (kptl_msg_t*)rx->rx_payload;

        return 0;
}


int kptllnd_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, int delayed,
                  unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
                  unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        kptl_rx_t    *rx = private;
        kptl_msg_t   *rxmsg = rx->rx_msg;
        kptl_data_t  *kptllnd_data = ni->ni_data;
        int           nob;
        int           rc;

        PJK_UT_MSG_DATA(">>> RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR\n");
        PJK_UT_MSG_DATA("niov=%d offset=%d mlen=%d rlen=%d\n",
                niov,offset,mlen,rlen);

        LASSERT (mlen <= rlen);
        LASSERT (mlen >= 0);
        LASSERT (!in_interrupt());
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));

        LASSERT (niov <= PTL_MD_MAX_IOV);       /* !!! */

        if(delayed)
                STAT_UPDATE(kps_recv_delayed);

        switch(rxmsg->ptlm_type)
        {
        default:
                LBUG();
                rc = -EINVAL;
                break;

        case PTLLND_MSG_TYPE_IMMEDIATE:
                PJK_UT_MSG_DATA("PTLLND_MSG_TYPE_IMMEDIATE\n");

                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[rlen]);
                if (nob > *kptllnd_tunables.kptl_max_immd_size) {
                        CERROR ("Immediate message from "LPX64" too big: %d\n",
                                rxmsg->ptlm_u.immediate.kptlim_hdr.src_nid, rlen);
                        rc = -EINVAL;
                        break;
                }

                if (kiov != NULL)
                        lnet_copy_flat2kiov(
                                niov, kiov, offset,
                                *kptllnd_tunables.kptl_max_immd_size,
                                rxmsg->ptlm_u.immediate.kptlim_payload,
                                0,
                                mlen);
                else
                        lnet_copy_flat2iov(
                                niov, iov, offset,
                                *kptllnd_tunables.kptl_max_immd_size,
                                rxmsg->ptlm_u.immediate.kptlim_payload,
                                0,
                                mlen);

                lnet_finalize (ni, lntmsg, 0);
                rc = 0;
                break;

        case PTLLND_MSG_TYPE_GET:
                PJK_UT_MSG_DATA("PTLLND_MSG_TYPE_GET\n");
                /* We get called here just to discard any junk after the
                 * GET hdr. */
                LASSERT (lntmsg == NULL); /* What is this all about ???*/

                lnet_finalize (ni, lntmsg, 0);

                rc = 0;
                break;

        case PTLLND_MSG_TYPE_PUT:
                PJK_UT_MSG_DATA("PTLLND_MSG_TYPE_PUT\n");

                if (mlen == 0) { /* No payload */
                        lnet_finalize(ni, lntmsg, 0);
                        rc = 0;
                }else{
                        rc = kptllnd_start_bulk_rdma(
                                kptllnd_data,
                                rx,
                                lntmsg,
                                PTL_MD_OP_GET,
                                niov,
                                iov,
                                kiov,
                                offset,
                                mlen);
                }
                break;
        }

        /*
         * We're done with the RX
         */
        kptllnd_rx_decref(rx,"lnet_parse",kptllnd_data);

        PJK_UT_MSG_DATA("<<< RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR rc=%d\n",rc);
        return rc;
}


void
kptllnd_eq_callback(ptl_event_t *ev)
{
        kptl_posted_object_t *po = ev->md.user_ptr;

        /*
         * Just delegate to the correct callback
         * based on object type
         */
        if(po->po_flags.pof_type == POSTED_OBJECT_TYPE_TX)
                kptllnd_tx_callback(ev);
        else
                kptllnd_rx_buffer_callback(ev);
}

typedef struct
{
        int id;                         /* The unique ID */
        kptl_data_t *kptllnd_data;     /* pointer to the NAL instance */

}kptllnd_thread_data_t;

void
kptllnd_thread_fini (kptllnd_thread_data_t *thread_data)
{
        atomic_dec (&thread_data->kptllnd_data->kptl_nthreads);
        LIBCFS_FREE(thread_data,sizeof(*thread_data));
}

int
kptllnd_thread_start (int (*fn)(void *arg), int id,kptl_data_t *kptllnd_data)
{
        long pid;
        kptllnd_thread_data_t *thread_data;

        /*
         * Allocate the tread data so we can pass more that
         * one param to the thread function
         */
        LIBCFS_ALLOC (thread_data,sizeof(*thread_data));
        if(thread_data == 0){
                CERROR("No memory to allocated thread data structure\n");
                return 0;
        }

        atomic_inc (&kptllnd_data->kptl_nthreads);

        /*
         * Initialize thread data structure
         */
        thread_data->id = id;
        thread_data->kptllnd_data = kptllnd_data;

        pid = kernel_thread (fn, thread_data, 0);

        /*
         * On error cleanup the context explicitly
         */
        if (pid < 0){
                CERROR("Failed to start kernel_thread id=%d\n",id);
                kptllnd_thread_fini(thread_data);
                return (int)pid;
        }else{
                return 0;
        }
}

int
kptllnd_watchdog(void *arg)
{
        kptllnd_thread_data_t *thread_data = arg;
        int                id = thread_data->id;
        kptl_data_t       *kptllnd_data = thread_data->kptllnd_data;
        char               name[16];
        cfs_waitlink_t     waitlink;
        int                peer_index = 0;
        unsigned long      deadline = jiffies;
        int                timeout;
        int                i;

        PJK_UT_MSG(">>>\n");

        /*
         * Daemonize
         */
        snprintf(name, sizeof(name), "kptllnd_wd_%02d", id);
        libcfs_daemonize(name);

        cfs_waitlink_init(&waitlink);

        /*
         * Keep going around
         */
        while(!kptllnd_data->kptl_shutdown) {

                /*
                 * Wait on the scheduler waitq
                 */

                set_current_state (TASK_INTERRUPTIBLE);
                cfs_waitq_add(&kptllnd_data->kptl_sched_waitq, &waitlink);
                cfs_waitq_timedwait(&waitlink,cfs_time_seconds(PTLLND_TIMEOUT_SEC));
                set_current_state (TASK_RUNNING);
                cfs_waitq_del (&kptllnd_data->kptl_sched_waitq, &waitlink);


                timeout = (int)(deadline - jiffies);
                if (timeout <= 0) {
                        const int n = 4;
                        const int p = 1;
                        int       chunk = kptllnd_data->kptl_peer_hash_size;


                        /* Time to check for RDMA timeouts on a few more
                         * peers: I do checks every 'p' seconds on a
                         * proportion of the peer table and I need to check
                         * every connection 'n' times within a timeout
                         * interval, to ensure I detect a timeout on any
                         * connection within (n+1)/n times the timeout
                         * interval. */

                        if ((*kptllnd_tunables.kptl_timeout) > n * p)
                                chunk = (chunk * n * p) /
                                        (*kptllnd_tunables.kptl_timeout);
                        if (chunk == 0)
                                chunk = 1;

                        for (i = 0; i < chunk; i++) {
                                STAT_UPDATE(kps_checking_buckets);
                                kptllnd_peer_check_bucket(peer_index,kptllnd_data);
                                peer_index = (peer_index + 1) %
                                     kptllnd_data->kptl_peer_hash_size;
                        }

                        deadline += p * HZ;
                }

                kptllnd_clean_canceled_peers(kptllnd_data);
        }

        kptllnd_thread_fini(thread_data);
        PJK_UT_MSG("<<<\n");
        return (0);
};

int
kptllnd_scheduler(void *arg)
{
        kptllnd_thread_data_t *thread_data = arg;
        int             id = thread_data->id;
        kptl_data_t    *kptllnd_data = thread_data->kptllnd_data;
        char            name[16];
        cfs_waitlink_t  waitlink;
        unsigned long           flags;
        kptl_rx_t               *rx = NULL;
        kptl_rx_buffer_t        *rxb = NULL;
        kptl_tx_t               *tx = NULL;

        PJK_UT_MSG(">>>\n");

        /*
         * Daemonize
         */
        snprintf(name, sizeof(name), "kptllnd_sd_%02d", id);
        libcfs_daemonize(name);

        cfs_waitlink_init(&waitlink);

        /*
         * Keep going around
         */
        while(!kptllnd_data->kptl_shutdown) {

                /*
                 * Wait on the scheduler waitq
                 */

                set_current_state (TASK_INTERRUPTIBLE);
                cfs_waitq_add(&kptllnd_data->kptl_sched_waitq, &waitlink);
                cfs_waitq_timedwait(&waitlink,cfs_time_seconds(PTLLND_TIMEOUT_SEC));
                set_current_state (TASK_RUNNING);
                cfs_waitq_del (&kptllnd_data->kptl_sched_waitq, &waitlink);

                /*
                 * Now service the queuse
                 */
                do{
                        spin_lock_irqsave(&kptllnd_data->kptl_sched_lock, flags);

                        /*
                         * Drain the RX queue
                         */
                        rx = NULL;
                        if(!list_empty(&kptllnd_data->kptl_sched_rxq)){
                                rx = list_entry (kptllnd_data->kptl_sched_rxq.next,
                                                 kptl_rx_t, rx_list);
                                list_del_init(&rx->rx_list);
                        }

                        /*
                         * IDrain the RXB Repost queue
                         */
                        rxb = NULL;
                        if(!list_empty(&kptllnd_data->kptl_sched_rxbq)){
                                rxb = list_entry (kptllnd_data->kptl_sched_rxbq.next,
                                                 kptl_rx_buffer_t, rxb_repost_list);
                                list_del_init(&rxb->rxb_repost_list);
                        }
                        /*
                         * Drain the TX queue.  Note RX's can cause new TX's
                         * to be added to the queue.
                         */
                        tx = NULL;
                        if(!list_empty(&kptllnd_data->kptl_sched_txq)){
                                tx = list_entry (kptllnd_data->kptl_sched_txq.next,
                                                 kptl_tx_t, tx_schedlist);
                                list_del_init(&tx->tx_schedlist);
                        }

                        spin_unlock_irqrestore(&kptllnd_data->kptl_sched_lock, flags);


                        /*
                         * Process anything that came off the list
                         */
                        if(rx)
                                kptllnd_rx_scheduler_handler(rx);
                        if(rxb)
                                kptllnd_rx_buffer_post_handle_error(rxb);
                        if(tx){
                                PJK_UT_MSG(">>> tx=%p\n",tx);
                                kptllnd_tx_done(tx);
                                PJK_UT_MSG("<<<\n");
                        }

                        /*
                         * As long as we did something this time around
                         * try again.
                         */
                }while(rx != NULL || rxb != NULL || tx != NULL);
        }

        kptllnd_thread_fini(thread_data);
        PJK_UT_MSG("<<<\n");
        return (0);
}

void kptllnd_clean_canceled_peers(kptl_data_t *kptllnd_data)
{
        unsigned long           flags;
        kptl_peer_t            *peer;
        struct list_head       *iter;
        int                     counter;

        read_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);


        if(!list_empty(&kptllnd_data->kptl_canceled_peers)){
                PJK_UT_MSG("Cleaning Canceled Peers\n");
                STAT_UPDATE(kps_cleaning_caneled_peers);
        }

again:
        counter = kptllnd_data->kptl_canceled_peers_counter;

        list_for_each(iter, &kptllnd_data->kptl_canceled_peers) {
                peer = list_entry (iter, kptl_peer_t, peer_list);


                /*
                 * Take reference so we can manipulate it
                 * outside the lock
                 * */
                kptllnd_peer_addref(peer,"temp");

                read_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock, flags);

                kptllnd_peer_cancel(peer);
                kptllnd_peer_decref(peer,"temp");

                read_lock_irqsave(&kptllnd_data->kptl_peer_rw_lock, flags);

                /*
                 * if the list has changed then we need to start again
                 */
                if(counter != kptllnd_data->kptl_canceled_peers_counter)
                        goto again;
        }

        read_unlock_irqrestore(&kptllnd_data->kptl_peer_rw_lock, flags);
}
