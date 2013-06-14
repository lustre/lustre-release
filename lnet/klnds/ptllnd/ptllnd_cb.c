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
 * lnet/klnds/ptllnd/ptllnd_cb.c
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 */

#include "ptllnd.h"

#ifndef _USING_LUSTRE_PORTALS_
int
kptllnd_extract_iov (int dst_niov, ptl_md_iovec_t *dst,
                     int src_niov, struct iovec *src,
                     unsigned int offset, unsigned int len)
{
        /* Initialise 'dst' to the subset of 'src' starting at 'offset',
         * for exactly 'len' bytes, and return the number of entries.
         * NB not destructive to 'src' */
        unsigned int    frag_len;
        unsigned int    niov;

        if (len == 0)                           /* no data => */
                return (0);                     /* no frags */

        LASSERT (src_niov > 0);
        while (offset >= src->iov_len) {      /* skip initial frags */
                offset -= src->iov_len;
                src_niov--;
                src++;
                LASSERT (src_niov > 0);
        }

        niov = 1;
        for (;;) {
                LASSERT (src_niov > 0);
                LASSERT (niov <= dst_niov);

                frag_len = src->iov_len - offset;
                dst->iov_base = ((char *)src->iov_base) + offset;

                if (len <= frag_len) {
                        dst->iov_len = len;
                        return (niov);
                }

                dst->iov_len = frag_len;

                len -= frag_len;
                dst++;
                src++;
                niov++;
                src_niov--;
                offset = 0;
        }
}

int
kptllnd_extract_phys (int dst_niov, ptl_md_iovec_t *dst,
                      int src_niov, lnet_kiov_t *src,
                      unsigned int offset, unsigned int len)
{
        /* Initialise 'dst' to the physical addresses of the subset of 'src'
         * starting at 'offset', for exactly 'len' bytes, and return the number
         * of entries.  NB not destructive to 'src' */
        unsigned int    frag_len;
        unsigned int    niov;
        __u64           phys_page;
        __u64           phys;

        if (len == 0)                           /* no data => */
                return (0);                     /* no frags */

        LASSERT (src_niov > 0);
        while (offset >= src->kiov_len) {      /* skip initial frags */
                offset -= src->kiov_len;
                src_niov--;
                src++;
                LASSERT (src_niov > 0);
        }

        niov = 1;
        for (;;) {
                LASSERT (src_niov > 0);
                LASSERT (niov <= dst_niov);

                frag_len = min(src->kiov_len - offset, len);
                phys_page = lnet_page2phys(src->kiov_page);
                phys = phys_page + src->kiov_offset + offset;

                LASSERT (sizeof(void *) > 4 || 
                         (phys <= 0xffffffffULL &&
                          phys + (frag_len - 1) <= 0xffffffffULL));

                dst->iov_base = (void *)((unsigned long)phys);
                dst->iov_len = frag_len;
                
                if (frag_len == len)
                        return niov;

                len -= frag_len;
                dst++;
                src++;
                niov++;
                src_niov--;
                offset = 0;
        }
}
#endif

void
kptllnd_init_rdma_md(kptl_tx_t *tx, unsigned int niov,
                     struct iovec *iov, lnet_kiov_t *kiov,
                     unsigned int offset, unsigned int nob)
{
        LASSERT (iov == NULL || kiov == NULL);
        
        memset(&tx->tx_rdma_md, 0, sizeof(tx->tx_rdma_md));

        tx->tx_rdma_md.start     = tx->tx_frags;
        tx->tx_rdma_md.user_ptr  = &tx->tx_rdma_eventarg;
        tx->tx_rdma_md.eq_handle = kptllnd_data.kptl_eqh;
        tx->tx_rdma_md.options   = PTL_MD_LUSTRE_COMPLETION_SEMANTICS |
                                   PTL_MD_EVENT_START_DISABLE;
        switch (tx->tx_type) {
        default:
                LBUG();
                
        case TX_TYPE_PUT_REQUEST:               /* passive: peer gets */
                tx->tx_rdma_md.threshold = 1;   /* GET event */
                tx->tx_rdma_md.options |= PTL_MD_OP_GET;
                break;

        case TX_TYPE_GET_REQUEST:               /* passive: peer puts */
                tx->tx_rdma_md.threshold = 1;   /* PUT event */
                tx->tx_rdma_md.options |= PTL_MD_OP_PUT;
                break;
                
        case TX_TYPE_PUT_RESPONSE:              /* active: I get */
                tx->tx_rdma_md.threshold = 2;   /* SEND + REPLY */
                break;
                
        case TX_TYPE_GET_RESPONSE:              /* active: I put */
                tx->tx_rdma_md.threshold = tx->tx_acked ? 2 : 1;   /* SEND + ACK? */
                break;
        }

        if (nob == 0) {
                tx->tx_rdma_md.length = 0;
                return;
        }

#ifdef _USING_LUSTRE_PORTALS_
        if (iov != NULL) {
                tx->tx_rdma_md.options |= PTL_MD_IOVEC;
                tx->tx_rdma_md.length = 
                        lnet_extract_iov(PTL_MD_MAX_IOV, tx->tx_frags->iov,
                                         niov, iov, offset, nob);
                return;
        }

        /* Cheating OK since ptl_kiov_t == lnet_kiov_t */
        CLASSERT(sizeof(ptl_kiov_t) == sizeof(lnet_kiov_t));
        CLASSERT(offsetof(ptl_kiov_t, kiov_offset) ==
                 offsetof(lnet_kiov_t, kiov_offset));
        CLASSERT(offsetof(ptl_kiov_t, kiov_page) ==
                 offsetof(lnet_kiov_t, kiov_page));
        CLASSERT(offsetof(ptl_kiov_t, kiov_len) ==
                 offsetof(lnet_kiov_t, kiov_len));
        
        tx->tx_rdma_md.options |= PTL_MD_KIOV;
        tx->tx_rdma_md.length = 
                lnet_extract_kiov(PTL_MD_MAX_IOV, tx->tx_frags->kiov,
                                  niov, kiov, offset, nob);
#else
        if (iov != NULL) {
                tx->tx_rdma_md.options |= PTL_MD_IOVEC;
                tx->tx_rdma_md.length = 
                        kptllnd_extract_iov(PTL_MD_MAX_IOV, tx->tx_frags->iov,
                                            niov, iov, offset, nob);
                return;
        }

        tx->tx_rdma_md.options |= PTL_MD_IOVEC | PTL_MD_PHYS;
        tx->tx_rdma_md.length =
                kptllnd_extract_phys(PTL_MD_MAX_IOV, tx->tx_frags->iov,
                                     niov, kiov, offset, nob);
#endif
}

int
kptllnd_active_rdma(kptl_rx_t *rx, lnet_msg_t *lntmsg, int type,
                    unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
                    unsigned int offset, int nob)
{
        kptl_tx_t       *tx;
        ptl_err_t        ptlrc;
        kptl_msg_t      *rxmsg = rx->rx_msg;
        kptl_peer_t     *peer = rx->rx_peer;
        unsigned long    flags;
        ptl_handle_md_t  mdh;

        LASSERT (type == TX_TYPE_PUT_RESPONSE || 
                 type == TX_TYPE_GET_RESPONSE);

        tx = kptllnd_get_idle_tx(type);
        if (tx == NULL) {
                CERROR ("Can't do %s rdma to %s: can't allocate descriptor\n",
                        type == TX_TYPE_PUT_RESPONSE ? "GET" : "PUT",
                        libcfs_id2str(peer->peer_id));
                return -ENOMEM;
        }

        kptllnd_set_tx_peer(tx, peer);
        kptllnd_init_rdma_md(tx, niov, iov, kiov, offset, nob);

        ptlrc = PtlMDBind(kptllnd_data.kptl_nih, tx->tx_rdma_md, 
                          PTL_UNLINK, &mdh);
        if (ptlrc != PTL_OK) {
                CERROR("PtlMDBind(%s) failed: %s(%d)\n",
                       libcfs_id2str(peer->peer_id),
                       kptllnd_errtype2str(ptlrc), ptlrc);
                tx->tx_status = -EIO;
                kptllnd_tx_decref(tx);
                return -EIO;
        }

	spin_lock_irqsave(&peer->peer_lock, flags);

        tx->tx_lnet_msg = lntmsg;
        /* lnet_finalize() will be called when tx is torn down, so I must
         * return success from here on... */

        tx->tx_deadline = jiffies + (*kptllnd_tunables.kptl_timeout * CFS_HZ);
        tx->tx_rdma_mdh = mdh;
        tx->tx_active = 1;
        cfs_list_add_tail(&tx->tx_list, &peer->peer_activeq);

        /* peer has now got my ref on 'tx' */

	spin_unlock_irqrestore(&peer->peer_lock, flags);

        tx->tx_tposted = jiffies;

        if (type == TX_TYPE_GET_RESPONSE)
                ptlrc = PtlPut(mdh,
                               tx->tx_acked ? PTL_ACK_REQ : PTL_NOACK_REQ,
                               rx->rx_initiator,
                               *kptllnd_tunables.kptl_portal,
                               0,                     /* acl cookie */
                               rxmsg->ptlm_u.rdma.kptlrm_matchbits,
                               0,                     /* offset */
                               (lntmsg != NULL) ?     /* header data */
                               PTLLND_RDMA_OK :
                               PTLLND_RDMA_FAIL);
        else
                ptlrc = PtlGet(mdh,
                               rx->rx_initiator,
                               *kptllnd_tunables.kptl_portal,
                               0,                     /* acl cookie */
                               rxmsg->ptlm_u.rdma.kptlrm_matchbits,
                               0);                    /* offset */

        if (ptlrc != PTL_OK) {
                CERROR("Ptl%s failed: %s(%d)\n", 
                       (type == TX_TYPE_GET_RESPONSE) ? "Put" : "Get",
                       kptllnd_errtype2str(ptlrc), ptlrc);
                
                kptllnd_peer_close(peer, -EIO);
                /* Everything (including this RDMA) queued on the peer will
                 * be completed with failure */
        }

        return 0;
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
        kptl_net_t       *net = ni->ni_data;
        kptl_peer_t      *peer = NULL;
        int               mpflag = 0;
        kptl_tx_t        *tx;
        int               nob;
        int               nfrag;
        int               rc;

        LASSERT (net->net_ni == ni);
        LASSERT (!net->net_shutdown);
        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= LNET_MAX_IOV);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV); /* !!! */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));
        LASSERT (!cfs_in_interrupt());

        if (lntmsg->msg_vmflush)
                mpflag = cfs_memory_pressure_get_and_set();

        rc = kptllnd_find_target(net, target, &peer);
        if (rc != 0)
                goto out;

        /* NB peer->peer_id does NOT always equal target, be careful with
         * which one to use */
        switch (type) {
        default:
                LBUG();
                return -EINVAL;

        case LNET_MSG_REPLY:
        case LNET_MSG_PUT:
                /* Should the payload avoid RDMA? */
                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[payload_nob]);
                if (payload_kiov == NULL && 
                    nob <= peer->peer_max_msg_size)
                        break;

                tx = kptllnd_get_idle_tx(TX_TYPE_PUT_REQUEST);
                if (tx == NULL) {
                        CERROR("Can't send %s to %s: can't allocate descriptor\n",
                               lnet_msgtyp2str(type),
                               libcfs_id2str(target));
                        rc = -ENOMEM;
                        goto out;
                }

                kptllnd_init_rdma_md(tx, payload_niov, 
                                     payload_iov, payload_kiov,
                                     payload_offset, payload_nob);

                tx->tx_lnet_msg = lntmsg;
                tx->tx_msg->ptlm_u.rdma.kptlrm_hdr = *hdr;
                kptllnd_init_msg (tx->tx_msg, PTLLND_MSG_TYPE_PUT,
                                 target, sizeof(kptl_rdma_msg_t));

                CDEBUG(D_NETTRACE, "%s: passive PUT p %d %p\n",
                       libcfs_id2str(target),
                       le32_to_cpu(lntmsg->msg_hdr.msg.put.ptl_index), tx);

                kptllnd_tx_launch(peer, tx, 0);
                goto out;

        case LNET_MSG_GET:
                /* routed gets don't RDMA */
                if (target_is_router || routing)
                        break;

                /* Is the payload small enough not to need RDMA? */
                nob = lntmsg->msg_md->md_length;
                nob = offsetof(kptl_msg_t, 
                               ptlm_u.immediate.kptlim_payload[nob]);
                if (nob <= peer->peer_max_msg_size)
                        break;

                tx = kptllnd_get_idle_tx(TX_TYPE_GET_REQUEST);
                if (tx == NULL) {
                        CERROR("Can't send GET to %s: can't allocate descriptor\n",
                               libcfs_id2str(target));
                        rc = -ENOMEM;
                        goto out;
                }

                tx->tx_lnet_replymsg = lnet_create_reply_msg(ni, lntmsg);
                if (tx->tx_lnet_replymsg == NULL) {
                        CERROR("Failed to allocate LNET reply for %s\n",
                               libcfs_id2str(target));
                        kptllnd_tx_decref(tx);
                        rc = -ENOMEM;
                        goto out;
                }

                if ((lntmsg->msg_md->md_options & LNET_MD_KIOV) == 0)
                        kptllnd_init_rdma_md(tx, lntmsg->msg_md->md_niov,
                                             lntmsg->msg_md->md_iov.iov, NULL,
                                             0, lntmsg->msg_md->md_length);
                else
                        kptllnd_init_rdma_md(tx, lntmsg->msg_md->md_niov,
                                             NULL, lntmsg->msg_md->md_iov.kiov,
                                             0, lntmsg->msg_md->md_length);

                tx->tx_lnet_msg = lntmsg;
                tx->tx_msg->ptlm_u.rdma.kptlrm_hdr = *hdr;
                kptllnd_init_msg (tx->tx_msg, PTLLND_MSG_TYPE_GET,
                                 target, sizeof(kptl_rdma_msg_t));

                CDEBUG(D_NETTRACE, "%s: passive GET p %d %p\n",
                       libcfs_id2str(target),
                       le32_to_cpu(lntmsg->msg_hdr.msg.put.ptl_index), tx);

                kptllnd_tx_launch(peer, tx, 0);
                goto out;

        case LNET_MSG_ACK:
                CDEBUG(D_NET, "LNET_MSG_ACK\n");
                LASSERT (payload_nob == 0);
                break;
        }

        /* I don't have to handle kiovs */
        LASSERT (payload_nob == 0 || payload_iov != NULL);

        tx = kptllnd_get_idle_tx(TX_TYPE_SMALL_MESSAGE);
        if (tx == NULL) {
                CERROR("Can't send %s to %s: can't allocate descriptor\n",
                       lnet_msgtyp2str(type), libcfs_id2str(target));
                rc = -ENOMEM;
                goto out;
        }

        tx->tx_lnet_msg = lntmsg;
        tx->tx_msg->ptlm_u.immediate.kptlim_hdr = *hdr;

        if (payload_nob == 0) {
                nfrag = 0;
        } else {
                tx->tx_frags->iov[0].iov_base = tx->tx_msg;
                tx->tx_frags->iov[0].iov_len = offsetof(kptl_msg_t,
                                                        ptlm_u.immediate.kptlim_payload);

                /* NB relying on lustre not asking for PTL_MD_MAX_IOV
                 * fragments!! */
#ifdef _USING_LUSTRE_PORTALS_
                nfrag = 1 + lnet_extract_iov(PTL_MD_MAX_IOV - 1, 
                                             &tx->tx_frags->iov[1],
                                             payload_niov, payload_iov,
                                             payload_offset, payload_nob);
#else
                nfrag = 1 + kptllnd_extract_iov(PTL_MD_MAX_IOV - 1,
                                                &tx->tx_frags->iov[1],
                                                payload_niov, payload_iov,
                                                payload_offset, payload_nob);
#endif
        }

        nob = offsetof(kptl_immediate_msg_t, kptlim_payload[payload_nob]);
        kptllnd_init_msg(tx->tx_msg, PTLLND_MSG_TYPE_IMMEDIATE, target, nob);

        CDEBUG(D_NETTRACE, "%s: immediate %s p %d %p\n",
               libcfs_id2str(target),
               lnet_msgtyp2str(lntmsg->msg_type),
               (le32_to_cpu(lntmsg->msg_type) == LNET_MSG_PUT) ? 
               le32_to_cpu(lntmsg->msg_hdr.msg.put.ptl_index) :
               (le32_to_cpu(lntmsg->msg_type) == LNET_MSG_GET) ? 
               le32_to_cpu(lntmsg->msg_hdr.msg.get.ptl_index) : -1,
               tx);

        kptllnd_tx_launch(peer, tx, nfrag);

 out:
        if (lntmsg->msg_vmflush)
                cfs_memory_pressure_restore(mpflag);
        if (peer)
                kptllnd_peer_decref(peer);
        return rc;
}

int 
kptllnd_eager_recv(struct lnet_ni *ni, void *private,
                   lnet_msg_t *msg, void **new_privatep)
{
        kptl_rx_t        *rx = private;

        CDEBUG(D_NET, "Eager RX=%p RXB=%p\n", rx, rx->rx_rxb);

        /* I have to release my ref on rxb (if I have one) to ensure I'm an
         * eager receiver, so I copy the incoming request from the buffer it
         * landed in, into space reserved in the descriptor... */

#if (PTL_MD_LOCAL_ALIGN8 == 0)
        if (rx->rx_rxb == NULL)                 /* already copied */
                return 0;                       /* to fix alignment */
#else
        LASSERT(rx->rx_rxb != NULL);
#endif
        LASSERT(rx->rx_nob <= *kptllnd_tunables.kptl_max_msg_size);

        memcpy(rx->rx_space, rx->rx_msg, rx->rx_nob);
        rx->rx_msg = (kptl_msg_t *)rx->rx_space;

        kptllnd_rx_buffer_decref(rx->rx_rxb);
        rx->rx_rxb = NULL;

        return 0;
}


int 
kptllnd_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, int delayed,
              unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
              unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        kptl_rx_t    *rx = private;
        kptl_msg_t   *rxmsg = rx->rx_msg;
        int           nob;
        int           rc;

        CDEBUG(D_NET, "%s niov=%d offset=%d mlen=%d rlen=%d\n",
               kptllnd_msgtype2str(rxmsg->ptlm_type),
               niov, offset, mlen, rlen);

        LASSERT (mlen <= rlen);
        LASSERT (mlen >= 0);
        LASSERT (!cfs_in_interrupt());
        LASSERT (!(kiov != NULL && iov != NULL)); /* never both */
        LASSERT (niov <= PTL_MD_MAX_IOV);       /* !!! */

        switch(rxmsg->ptlm_type)
        {
        default:
                LBUG();
                rc = -EINVAL;
                break;

        case PTLLND_MSG_TYPE_IMMEDIATE:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_IMMEDIATE %d,%d\n", mlen, rlen);

                nob = offsetof(kptl_msg_t, ptlm_u.immediate.kptlim_payload[rlen]);
                if (nob > rx->rx_nob) {
                        CERROR ("Immediate message from %s too big: %d(%d)\n",
                                libcfs_id2str(rx->rx_peer->peer_id), nob,
                                rx->rx_nob);
                        rc = -EINVAL;
                        break;
                }

                if (kiov != NULL)
                        lnet_copy_flat2kiov(
                                niov, kiov, offset,
                                *kptllnd_tunables.kptl_max_msg_size,
                                rxmsg->ptlm_u.immediate.kptlim_payload,
                                0,
                                mlen);
                else
                        lnet_copy_flat2iov(
                                niov, iov, offset,
                                *kptllnd_tunables.kptl_max_msg_size,
                                rxmsg->ptlm_u.immediate.kptlim_payload,
                                0,
                                mlen);

                lnet_finalize (ni, lntmsg, 0);
                rc = 0;
                break;

        case PTLLND_MSG_TYPE_GET:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_GET %d,%d\n", mlen, rlen);

                /* NB always send RDMA so the peer can complete.  I send
                 * success/failure in the portals 'hdr_data' */

                if (lntmsg == NULL)
                        rc = kptllnd_active_rdma(rx, NULL,
                                                 TX_TYPE_GET_RESPONSE,
                                                 0, NULL, NULL, 0, 0);
                else
                        rc = kptllnd_active_rdma(rx, lntmsg, 
                                                 TX_TYPE_GET_RESPONSE,
                                                 lntmsg->msg_niov,
                                                 lntmsg->msg_iov, 
                                                 lntmsg->msg_kiov,
                                                 lntmsg->msg_offset, 
                                                 lntmsg->msg_len);
                break;

        case PTLLND_MSG_TYPE_PUT:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_PUT %d,%d\n", mlen, rlen);

                /* NB always send RDMA so the peer can complete; it'll be 0
                 * bytes if there was no match (lntmsg == NULL). I have no way
                 * to let my peer know this, but she's only interested in when
                 * the net has stopped accessing her buffer in any case. */

                rc = kptllnd_active_rdma(rx, lntmsg, TX_TYPE_PUT_RESPONSE,
                                         niov, iov, kiov, offset, mlen);
                break;
        }

        /*
         * We're done with the RX
         */
        kptllnd_rx_done(rx, PTLLND_POSTRX_PEER_CREDIT);
        return rc;
}

void
kptllnd_eq_callback(ptl_event_t *ev)
{
        kptl_eventarg_t *eva = ev->md.user_ptr;

        switch (eva->eva_type) {
        default:
                LBUG();

        case PTLLND_EVENTARG_TYPE_MSG:
        case PTLLND_EVENTARG_TYPE_RDMA:
                kptllnd_tx_callback(ev);
                break;

        case PTLLND_EVENTARG_TYPE_BUF:
                kptllnd_rx_buffer_callback(ev);
                break;
        }
}

void
kptllnd_thread_fini (void)
{
        cfs_atomic_dec(&kptllnd_data.kptl_nthreads);
}

int
kptllnd_thread_start(int (*fn)(void *arg), void *arg, char *name)
{
	cfs_task_t *task;

	cfs_atomic_inc(&kptllnd_data.kptl_nthreads);

	task = kthread_run(fn, arg, name);
	if (IS_ERR(task)) {
		CERROR("Failed to start thread: error %ld\n", PTR_ERR(task));
		kptllnd_thread_fini();
	}
	return PTR_ERR(task);
}

int
kptllnd_watchdog(void *arg)
{
        int                 id = (long)arg;
        cfs_waitlink_t      waitlink;
        int                 stamp = 0;
        int                 peer_index = 0;
        unsigned long       deadline = jiffies;
        int                 timeout;
        int                 i;

        cfs_block_allsigs();

        cfs_waitlink_init(&waitlink);

        /* threads shut down in phase 2 after all peers have been destroyed */
        while (kptllnd_data.kptl_shutdown < 2) {

                timeout = (int)(deadline - jiffies);
                if (timeout <= 0) {
                        const int n = 4;
                        const int p = 1;
                        int       chunk = kptllnd_data.kptl_peer_hash_size;


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
                                kptllnd_peer_check_bucket(peer_index, stamp);
                                peer_index = (peer_index + 1) %
                                     kptllnd_data.kptl_peer_hash_size;
                        }

                        deadline += p * CFS_HZ;
                        stamp++;
                        continue;
                }

                kptllnd_handle_closing_peers();

                cfs_set_current_state(CFS_TASK_INTERRUPTIBLE);
                cfs_waitq_add_exclusive(&kptllnd_data.kptl_watchdog_waitq,
                                        &waitlink);

                cfs_waitq_timedwait(&waitlink, CFS_TASK_INTERRUPTIBLE, timeout);

                cfs_set_current_state (CFS_TASK_RUNNING);
                cfs_waitq_del(&kptllnd_data.kptl_watchdog_waitq, &waitlink);
        }

        kptllnd_thread_fini();
        CDEBUG(D_NET, "<<<\n");
        return (0);
};

int
kptllnd_scheduler (void *arg)
{
        int                 id = (long)arg;
        cfs_waitlink_t      waitlink;
        unsigned long       flags;
        int                 did_something;
        int                 counter = 0;
        kptl_rx_t          *rx;
        kptl_rx_buffer_t   *rxb;
        kptl_tx_t          *tx;

        cfs_block_allsigs();

        cfs_waitlink_init(&waitlink);

	spin_lock_irqsave(&kptllnd_data.kptl_sched_lock, flags);

        /* threads shut down in phase 2 after all peers have been destroyed */
        while (kptllnd_data.kptl_shutdown < 2) {

                did_something = 0;

                if (!cfs_list_empty(&kptllnd_data.kptl_sched_rxq)) {
                        rx = cfs_list_entry (kptllnd_data.kptl_sched_rxq.next,
                                             kptl_rx_t, rx_list);
                        cfs_list_del(&rx->rx_list);

			spin_unlock_irqrestore(&kptllnd_data. \
                                                   kptl_sched_lock,
                                                   flags);

                        kptllnd_rx_parse(rx);
                        did_something = 1;

			spin_lock_irqsave(&kptllnd_data.kptl_sched_lock,
                                              flags);
                }

                if (!cfs_list_empty(&kptllnd_data.kptl_sched_rxbq)) {
                        rxb = cfs_list_entry (kptllnd_data.kptl_sched_rxbq.next,
                                              kptl_rx_buffer_t,
                                              rxb_repost_list);
                        cfs_list_del(&rxb->rxb_repost_list);

			spin_unlock_irqrestore(&kptllnd_data. \
                                                   kptl_sched_lock,
                                                   flags);

                        kptllnd_rx_buffer_post(rxb);
                        did_something = 1;

			spin_lock_irqsave(&kptllnd_data.kptl_sched_lock,
                                              flags);
                }

                if (!cfs_list_empty(&kptllnd_data.kptl_sched_txq)) {
                        tx = cfs_list_entry (kptllnd_data.kptl_sched_txq.next,
                                             kptl_tx_t, tx_list);
                        cfs_list_del_init(&tx->tx_list);

			spin_unlock_irqrestore(&kptllnd_data. \
                                                   kptl_sched_lock, flags);

                        kptllnd_tx_fini(tx);
                        did_something = 1;

			spin_lock_irqsave(&kptllnd_data.kptl_sched_lock,
                                              flags);
                }

                if (did_something) {
                        if (++counter != *kptllnd_tunables.kptl_reschedule_loops)
                                continue;
                }

                cfs_set_current_state(CFS_TASK_INTERRUPTIBLE);
                cfs_waitq_add_exclusive(&kptllnd_data.kptl_sched_waitq,
                                        &waitlink);
		spin_unlock_irqrestore(&kptllnd_data.kptl_sched_lock,
                                           flags);

                if (!did_something)
                        cfs_waitq_wait(&waitlink, CFS_TASK_INTERRUPTIBLE);
                else
                        cfs_cond_resched();

                cfs_set_current_state(CFS_TASK_RUNNING);
                cfs_waitq_del(&kptllnd_data.kptl_sched_waitq, &waitlink);

		spin_lock_irqsave(&kptllnd_data.kptl_sched_lock, flags);

                counter = 0;
        }

	spin_unlock_irqrestore(&kptllnd_data.kptl_sched_lock, flags);

        kptllnd_thread_fini();
        return 0;
}
