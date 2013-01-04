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
 * lnet/klnds/ptllnd/ptllnd_rx_buf.c
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 */

 #include "ptllnd.h"

void
kptllnd_rx_buffer_pool_init(kptl_rx_buffer_pool_t *rxbp)
{
        memset(rxbp, 0, sizeof(*rxbp));
	spin_lock_init(&rxbp->rxbp_lock);
        CFS_INIT_LIST_HEAD(&rxbp->rxbp_list);
}

void
kptllnd_rx_buffer_destroy(kptl_rx_buffer_t *rxb)
{
        kptl_rx_buffer_pool_t *rxbp = rxb->rxb_pool;

        LASSERT(rxb->rxb_refcount == 0);
        LASSERT(PtlHandleIsEqual(rxb->rxb_mdh, PTL_INVALID_HANDLE));
        LASSERT(!rxb->rxb_posted);
        LASSERT(rxb->rxb_idle);

        cfs_list_del(&rxb->rxb_list);
        rxbp->rxbp_count--;

        LIBCFS_FREE(rxb->rxb_buffer, kptllnd_rx_buffer_size());
        LIBCFS_FREE(rxb, sizeof(*rxb));
}

int
kptllnd_rx_buffer_pool_reserve(kptl_rx_buffer_pool_t *rxbp, int count)
{
        int               bufsize;
        int               msgs_per_buffer;
        int               rc;
        kptl_rx_buffer_t *rxb;
        char             *buffer;
        unsigned long     flags;

        bufsize = kptllnd_rx_buffer_size();
        msgs_per_buffer = bufsize / (*kptllnd_tunables.kptl_max_msg_size);

        CDEBUG(D_NET, "kptllnd_rx_buffer_pool_reserve(%d)\n", count);

	spin_lock_irqsave(&rxbp->rxbp_lock, flags);

        for (;;) {
                if (rxbp->rxbp_shutdown) {
                        rc = -ESHUTDOWN;
                        break;
                }
                
                if (rxbp->rxbp_reserved + count <= 
                    rxbp->rxbp_count * msgs_per_buffer) {
                        rc = 0;
                        break;
                }
                
		spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);
                
                LIBCFS_ALLOC(rxb, sizeof(*rxb));
                LIBCFS_ALLOC(buffer, bufsize);

                if (rxb == NULL || buffer == NULL) {
                        CERROR("Failed to allocate rx buffer\n");

                        if (rxb != NULL)
                                LIBCFS_FREE(rxb, sizeof(*rxb));
                        if (buffer != NULL)
                                LIBCFS_FREE(buffer, bufsize);
                        
			spin_lock_irqsave(&rxbp->rxbp_lock, flags);
                        rc = -ENOMEM;
                        break;
                }

                memset(rxb, 0, sizeof(*rxb));

                rxb->rxb_eventarg.eva_type = PTLLND_EVENTARG_TYPE_BUF;
                rxb->rxb_refcount = 0;
                rxb->rxb_pool = rxbp;
                rxb->rxb_idle = 0;
                rxb->rxb_posted = 0;
                rxb->rxb_buffer = buffer;
                rxb->rxb_mdh = PTL_INVALID_HANDLE;

		spin_lock_irqsave(&rxbp->rxbp_lock, flags);
                
                if (rxbp->rxbp_shutdown) {
			spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);
                        
                        LIBCFS_FREE(rxb, sizeof(*rxb));
                        LIBCFS_FREE(buffer, bufsize);

			spin_lock_irqsave(&rxbp->rxbp_lock, flags);
                        rc = -ESHUTDOWN;
                        break;
                }
                
                cfs_list_add_tail(&rxb->rxb_list, &rxbp->rxbp_list);
                rxbp->rxbp_count++;

		spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);
                
                kptllnd_rx_buffer_post(rxb);

		spin_lock_irqsave(&rxbp->rxbp_lock, flags);
        }

        if (rc == 0)
                rxbp->rxbp_reserved += count;

	spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);

        return rc;
}

void
kptllnd_rx_buffer_pool_unreserve(kptl_rx_buffer_pool_t *rxbp,
                                 int count)
{
        unsigned long flags;

	spin_lock_irqsave(&rxbp->rxbp_lock, flags);

        CDEBUG(D_NET, "kptllnd_rx_buffer_pool_unreserve(%d)\n", count);
        rxbp->rxbp_reserved -= count;

	spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);
}

void
kptllnd_rx_buffer_pool_fini(kptl_rx_buffer_pool_t *rxbp)
{
        kptl_rx_buffer_t       *rxb;
        int                     rc;
        int                     i;
        unsigned long           flags;
        cfs_list_t             *tmp;
        cfs_list_t             *nxt;
        ptl_handle_md_t         mdh;

        /* CAVEAT EMPTOR: I'm racing with everything here!!!
         *
         * Buffers can still be posted after I set rxbp_shutdown because I
         * can't hold rxbp_lock while I'm posting them.
         *
         * Calling PtlMDUnlink() here races with auto-unlinks; i.e. a buffer's
         * MD handle could become invalid under me.  I am vulnerable to portals
         * re-using handles (i.e. make the same handle valid again, but for a
         * different MD) from when the MD is actually unlinked, to when the
         * event callback tells me it has been unlinked. */

	spin_lock_irqsave(&rxbp->rxbp_lock, flags);

        rxbp->rxbp_shutdown = 1;

        for (i = 9;; i++) {
                cfs_list_for_each_safe(tmp, nxt, &rxbp->rxbp_list) {
                        rxb = cfs_list_entry (tmp, kptl_rx_buffer_t, rxb_list);

                        if (rxb->rxb_idle) {
				spin_unlock_irqrestore(&rxbp->rxbp_lock,
                                                           flags);
                                kptllnd_rx_buffer_destroy(rxb);
				spin_lock_irqsave(&rxbp->rxbp_lock,
                                                      flags);
                                continue;
                        }

                        mdh = rxb->rxb_mdh;
                        if (PtlHandleIsEqual(mdh, PTL_INVALID_HANDLE))
                                continue;
                        
			spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);

                        rc = PtlMDUnlink(mdh);

			spin_lock_irqsave(&rxbp->rxbp_lock, flags);
                        
#ifdef LUSTRE_PORTALS_UNLINK_SEMANTICS
                        /* callback clears rxb_mdh and drops net's ref
                         * (which causes repost, but since I set
                         * shutdown, it will just set the buffer
                         * idle) */
#else
                        if (rc == PTL_OK) {
                                rxb->rxb_posted = 0;
                                rxb->rxb_mdh = PTL_INVALID_HANDLE;
                                kptllnd_rx_buffer_decref_locked(rxb);
                        }
#endif
                }

                if (cfs_list_empty(&rxbp->rxbp_list))
                        break;

		spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);

                /* Wait a bit for references to be dropped */
                CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                       "Waiting for %d Busy RX Buffers\n",
                       rxbp->rxbp_count);

                cfs_pause(cfs_time_seconds(1));

		spin_lock_irqsave(&rxbp->rxbp_lock, flags);
        }

	spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);
}

void
kptllnd_rx_buffer_post(kptl_rx_buffer_t *rxb)
{
        int                     rc;
        ptl_md_t                md;
        ptl_handle_me_t         meh;
        ptl_handle_md_t         mdh;
        ptl_process_id_t        any;
        kptl_rx_buffer_pool_t  *rxbp = rxb->rxb_pool;
        unsigned long           flags;

        LASSERT (!cfs_in_interrupt());
        LASSERT (rxb->rxb_refcount == 0);
        LASSERT (!rxb->rxb_idle);
        LASSERT (!rxb->rxb_posted);
        LASSERT (PtlHandleIsEqual(rxb->rxb_mdh, PTL_INVALID_HANDLE));

        any.nid = PTL_NID_ANY;
        any.pid = PTL_PID_ANY;

	spin_lock_irqsave(&rxbp->rxbp_lock, flags);

        if (rxbp->rxbp_shutdown) {
                rxb->rxb_idle = 1;
		spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);
                return;
        }

        rxb->rxb_refcount = 1;                  /* net's ref */
        rxb->rxb_posted = 1;                    /* I'm posting */
        
	spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);

        rc = PtlMEAttach(kptllnd_data.kptl_nih,
                         *kptllnd_tunables.kptl_portal,
                         any,
                         LNET_MSG_MATCHBITS,
                         0, /* all matchbits are valid - ignore none */
                         PTL_UNLINK,
                         PTL_INS_AFTER,
                         &meh);
        if (rc != PTL_OK) {
                CERROR("PtlMeAttach rxb failed %s(%d)\n",
                       kptllnd_errtype2str(rc), rc);
                goto failed;
        }

        /*
         * Setup MD
         */
        md.start = rxb->rxb_buffer;
        md.length = kptllnd_rx_buffer_size();
        md.threshold = PTL_MD_THRESH_INF;
        md.options = PTL_MD_OP_PUT |
                     PTL_MD_LUSTRE_COMPLETION_SEMANTICS |
                     PTL_MD_EVENT_START_DISABLE |
                     PTL_MD_MAX_SIZE |
                     PTL_MD_LOCAL_ALIGN8;
        md.user_ptr = &rxb->rxb_eventarg;
        md.max_size = *kptllnd_tunables.kptl_max_msg_size;
        md.eq_handle = kptllnd_data.kptl_eqh;

        rc = PtlMDAttach(meh, md, PTL_UNLINK, &mdh);
        if (rc == PTL_OK) {
		spin_lock_irqsave(&rxbp->rxbp_lock, flags);
                if (rxb->rxb_posted)            /* Not auto-unlinked yet!!! */
                        rxb->rxb_mdh = mdh;
		spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);
                return;
        }
        
        CERROR("PtlMDAttach rxb failed %s(%d)\n",
               kptllnd_errtype2str(rc), rc);
        rc = PtlMEUnlink(meh);
        LASSERT(rc == PTL_OK);

 failed:
	spin_lock_irqsave(&rxbp->rxbp_lock, flags);
        rxb->rxb_posted = 0;
        /* XXX this will just try again immediately */
        kptllnd_rx_buffer_decref_locked(rxb);
	spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);
}

kptl_rx_t *
kptllnd_rx_alloc(void)
{
        kptl_rx_t* rx;

        if (IS_SIMULATION_ENABLED(FAIL_RX_ALLOC)) {
                CERROR ("FAIL_RX_ALLOC SIMULATION triggered\n");
                return NULL;
        }

        rx = cfs_mem_cache_alloc(kptllnd_data.kptl_rx_cache, CFS_ALLOC_ATOMIC);
        if (rx == NULL) {
                CERROR("Failed to allocate rx\n");
                return NULL;
        }

        memset(rx, 0, sizeof(*rx));
        return rx;
}

void
kptllnd_rx_done(kptl_rx_t *rx, int post_credit)
{
        kptl_rx_buffer_t *rxb = rx->rx_rxb;
        kptl_peer_t      *peer = rx->rx_peer;
        unsigned long     flags;

        LASSERT (post_credit == PTLLND_POSTRX_NO_CREDIT ||
                 post_credit == PTLLND_POSTRX_PEER_CREDIT);

        CDEBUG(D_NET, "rx=%p rxb %p peer %p\n", rx, rxb, peer);

        if (rxb != NULL)
                kptllnd_rx_buffer_decref(rxb);

        if (peer != NULL) {
                /* Update credits (after I've decref-ed the buffer) */
		spin_lock_irqsave(&peer->peer_lock, flags);

                if (post_credit == PTLLND_POSTRX_PEER_CREDIT)
                        peer->peer_outstanding_credits++;

                LASSERT (peer->peer_outstanding_credits +
                         peer->peer_sent_credits <=
                         *kptllnd_tunables.kptl_peertxcredits);

                CDEBUG(D_NETTRACE, "%s[%d/%d+%d]: rx %p done\n",
                       libcfs_id2str(peer->peer_id), peer->peer_credits,
                       peer->peer_outstanding_credits, peer->peer_sent_credits,
                       rx);

		spin_unlock_irqrestore(&peer->peer_lock, flags);

                /* I might have to send back credits */
                kptllnd_peer_check_sends(peer);
                kptllnd_peer_decref(peer);
        }

        cfs_mem_cache_free(kptllnd_data.kptl_rx_cache, rx);
}

void
kptllnd_rx_buffer_callback (ptl_event_t *ev)
{
        kptl_eventarg_t        *eva = ev->md.user_ptr;
        kptl_rx_buffer_t       *rxb = kptllnd_eventarg2obj(eva);
        kptl_rx_buffer_pool_t  *rxbp = rxb->rxb_pool;
        kptl_rx_t              *rx;
        int                     unlinked;
        unsigned long           flags;

#ifdef LUSTRE_PORTALS_UNLINK_SEMANTICS
        unlinked = ev->unlinked;
#else
        unlinked = ev->type == PTL_EVENT_UNLINK;
#endif

        CDEBUG(D_NET, "%s: %s(%d) rxb=%p fail=%s(%d) unlink=%d\n",
               kptllnd_ptlid2str(ev->initiator),
               kptllnd_evtype2str(ev->type), ev->type, rxb,
               kptllnd_errtype2str(ev->ni_fail_type), ev->ni_fail_type,
               unlinked);

        LASSERT (!rxb->rxb_idle);
        LASSERT (ev->md.start == rxb->rxb_buffer);
        LASSERT (ev->offset + ev->mlength <=
                 PAGE_SIZE * *kptllnd_tunables.kptl_rxb_npages);
        LASSERT (ev->type == PTL_EVENT_PUT_END ||
                 ev->type == PTL_EVENT_UNLINK);
        LASSERT (ev->type == PTL_EVENT_UNLINK ||
                 ev->match_bits == LNET_MSG_MATCHBITS);

        if (ev->ni_fail_type != PTL_NI_OK) {
                CERROR("Portals error from %s: %s(%d) rxb=%p fail=%s(%d) unlink=%dn",
                       kptllnd_ptlid2str(ev->initiator),
                       kptllnd_evtype2str(ev->type), ev->type, rxb,
                       kptllnd_errtype2str(ev->ni_fail_type),
                       ev->ni_fail_type, unlinked);
        } else if (ev->type == PTL_EVENT_PUT_END &&
                   !rxbp->rxbp_shutdown) {

                /* rxbp_shutdown sampled without locking!  I only treat it as a
                 * hint since shutdown can start while rx's are queued on
                 * kptl_sched_rxq. */
#if (PTL_MD_LOCAL_ALIGN8 == 0)
                /* Portals can't force message alignment - someone sending an
                 * odd-length message will misalign subsequent messages and
                 * force the fixup below...  */
                if ((ev->mlength & 7) != 0)
                        CWARN("Message from %s has odd length "LPU64": "
                              "probable version incompatibility\n",
                              kptllnd_ptlid2str(ev->initiator),
                              (__u64)ev->mlength);
#endif
                rx = kptllnd_rx_alloc();
                if (rx == NULL) {
                        CERROR("Message from %s dropped: ENOMEM",
                               kptllnd_ptlid2str(ev->initiator));
                } else {
                        if ((ev->offset & 7) == 0) {
                                kptllnd_rx_buffer_addref(rxb);
                                rx->rx_rxb = rxb;
                                rx->rx_nob = ev->mlength;
                                rx->rx_msg = (kptl_msg_t *)
                                             (rxb->rxb_buffer + ev->offset);
                        } else {
#if (PTL_MD_LOCAL_ALIGN8 == 0)
                                /* Portals can't force alignment - copy into
                                 * rx_space (avoiding overflow) to fix */
                                int maxlen = *kptllnd_tunables.kptl_max_msg_size;

                                rx->rx_rxb = NULL;
                                rx->rx_nob = MIN(maxlen, ev->mlength);
                                rx->rx_msg = (kptl_msg_t *)rx->rx_space;
                                memcpy(rx->rx_msg, rxb->rxb_buffer + ev->offset,
                                       rx->rx_nob);
#else
                                /* Portals should have forced the alignment */
                                LBUG();
#endif
                        }

                        rx->rx_initiator = ev->initiator;
                        rx->rx_treceived = jiffies;
                        /* Queue for attention */
			spin_lock_irqsave(&kptllnd_data.kptl_sched_lock,
                                              flags);

                        cfs_list_add_tail(&rx->rx_list,
                                          &kptllnd_data.kptl_sched_rxq);
                        cfs_waitq_signal(&kptllnd_data.kptl_sched_waitq);

			spin_unlock_irqrestore(&kptllnd_data. \
                                                   kptl_sched_lock, flags);
                }
        }

        if (unlinked) {
		spin_lock_irqsave(&rxbp->rxbp_lock, flags);

                rxb->rxb_posted = 0;
                rxb->rxb_mdh = PTL_INVALID_HANDLE;
                kptllnd_rx_buffer_decref_locked(rxb);

		spin_unlock_irqrestore(&rxbp->rxbp_lock, flags);
        }
}

void
kptllnd_nak (ptl_process_id_t dest)
{
        /* Fire-and-forget a stub message that will let the peer know my
         * protocol magic/version and make her drop/refresh any peer state she
         * might have with me. */
        ptl_md_t md = {
                .start        = kptllnd_data.kptl_nak_msg,
                .length       = kptllnd_data.kptl_nak_msg->ptlm_nob,
                .threshold    = 1,
                .options      = 0,
                .user_ptr     = NULL,
                .eq_handle    = PTL_EQ_NONE};
        ptl_handle_md_t   mdh;
        int               rc;

        rc = PtlMDBind(kptllnd_data.kptl_nih, md, PTL_UNLINK, &mdh);
        if (rc != PTL_OK) {
                CWARN("Can't NAK %s: bind failed %s(%d)\n",
                      kptllnd_ptlid2str(dest), kptllnd_errtype2str(rc), rc);
                return;
        }

        rc = PtlPut(mdh, PTL_NOACK_REQ, dest,
                    *kptllnd_tunables.kptl_portal, 0,
                    LNET_MSG_MATCHBITS, 0, 0);
        if (rc != PTL_OK) {
                CWARN("Can't NAK %s: put failed %s(%d)\n",
                      kptllnd_ptlid2str(dest), kptllnd_errtype2str(rc), rc);
        }
}

kptl_net_t *
kptllnd_find_net (lnet_nid_t nid)
{
        kptl_net_t *net;

	read_lock(&kptllnd_data.kptl_net_rw_lock);
        cfs_list_for_each_entry (net, &kptllnd_data.kptl_nets, net_list) {
                LASSERT (!net->net_shutdown);

                if (net->net_ni->ni_nid == nid) {
                        kptllnd_net_addref(net);
			read_unlock(&kptllnd_data.kptl_net_rw_lock);
                        return net;
                }
        }
	read_unlock(&kptllnd_data.kptl_net_rw_lock);

        return NULL;
}

void
kptllnd_rx_parse(kptl_rx_t *rx)
{
        kptl_msg_t             *msg = rx->rx_msg;
        int                     rc = 0;
        int                     post_credit = PTLLND_POSTRX_PEER_CREDIT;
        kptl_net_t             *net = NULL;
        kptl_peer_t            *peer;
        cfs_list_t              txs;
        unsigned long           flags;
        lnet_process_id_t       srcid;

        LASSERT (!cfs_in_interrupt());
        LASSERT (rx->rx_peer == NULL);

        CFS_INIT_LIST_HEAD(&txs);

        if ((rx->rx_nob >= 4 &&
             (msg->ptlm_magic == LNET_PROTO_MAGIC ||
              msg->ptlm_magic == __swab32(LNET_PROTO_MAGIC))) ||
            (rx->rx_nob >= 6 &&
             ((msg->ptlm_magic == PTLLND_MSG_MAGIC &&
               msg->ptlm_version != PTLLND_MSG_VERSION) ||
              (msg->ptlm_magic == __swab32(PTLLND_MSG_MAGIC) &&
               msg->ptlm_version != __swab16(PTLLND_MSG_VERSION))))) {
                /* NAK incompatible versions
                 * See other LNDs for how to handle this if/when ptllnd begins
                 * to allow different versions to co-exist */
                CERROR("Bad version: got %04x expected %04x from %s\n",
                       (__u32)(msg->ptlm_magic == PTLLND_MSG_MAGIC ?
                               msg->ptlm_version : __swab16(msg->ptlm_version)),
                        PTLLND_MSG_VERSION, kptllnd_ptlid2str(rx->rx_initiator));
                /* NB backward compatibility */
                kptllnd_nak(rx->rx_initiator);
                goto rx_done;
        }
        
        rc = kptllnd_msg_unpack(msg, rx->rx_nob);
        if (rc != 0) {
                CERROR ("Error %d unpacking rx from %s\n",
                        rc, kptllnd_ptlid2str(rx->rx_initiator));
                goto rx_done;
        }

        srcid.nid = msg->ptlm_srcnid;
        srcid.pid = msg->ptlm_srcpid;

        CDEBUG(D_NETTRACE, "%s: RX %s c %d %p rxb %p queued %lu ticks (%ld s)\n",
               libcfs_id2str(srcid), kptllnd_msgtype2str(msg->ptlm_type),
               msg->ptlm_credits, rx, rx->rx_rxb, 
               jiffies - rx->rx_treceived,
               cfs_duration_sec(jiffies - rx->rx_treceived));

        if (kptllnd_lnet2ptlnid(srcid.nid) != rx->rx_initiator.nid) {
                CERROR("Bad source nid %s from %s\n",
                       libcfs_id2str(srcid),
                       kptllnd_ptlid2str(rx->rx_initiator));
                goto rx_done;
        }

        if (msg->ptlm_type == PTLLND_MSG_TYPE_NAK) {
                peer = kptllnd_id2peer(srcid);
                if (peer == NULL)
                        goto rx_done;
                
                CWARN("NAK from %s (%d:%s)\n",
                      libcfs_id2str(srcid), peer->peer_state,
                      kptllnd_ptlid2str(rx->rx_initiator));

                /* NB can't nuke new peer - bug 17546 comment 31 */
                if (peer->peer_state == PEER_STATE_WAITING_HELLO) {
                        CDEBUG(D_NET, "Stale NAK from %s(%s): WAITING_HELLO\n",
                               libcfs_id2str(srcid),
                               kptllnd_ptlid2str(rx->rx_initiator));
                        kptllnd_peer_decref(peer);
                        goto rx_done;
                }

                rc = -EPROTO;
                goto failed;
        }

        net = kptllnd_find_net(msg->ptlm_dstnid);
        if (net == NULL || msg->ptlm_dstpid != the_lnet.ln_pid) {
                CERROR("Bad dstid %s from %s\n",
                       libcfs_id2str((lnet_process_id_t) {
                               .nid = msg->ptlm_dstnid,
                               .pid = msg->ptlm_dstpid}),
                       kptllnd_ptlid2str(rx->rx_initiator));
                goto rx_done;
        }

        if (LNET_NIDNET(srcid.nid) != LNET_NIDNET(net->net_ni->ni_nid)) {
                lnet_nid_t nid = LNET_MKNID(LNET_NIDNET(net->net_ni->ni_nid),
                                            LNET_NIDADDR(srcid.nid));
                CERROR("Bad source nid %s from %s, %s expected.\n",
                       libcfs_id2str(srcid),
                       kptllnd_ptlid2str(rx->rx_initiator),
                       libcfs_nid2str(nid));
                goto rx_done;
        }

        if (msg->ptlm_type == PTLLND_MSG_TYPE_HELLO) {
                peer = kptllnd_peer_handle_hello(net, rx->rx_initiator, msg);
                if (peer == NULL)
                        goto rx_done;
        } else {
                peer = kptllnd_id2peer(srcid);
                if (peer == NULL) {
                        CWARN("NAK %s: no connection, %s must reconnect\n",
                              kptllnd_msgtype2str(msg->ptlm_type),
                              libcfs_id2str(srcid));
                        /* NAK to make the peer reconnect */
                        kptllnd_nak(rx->rx_initiator);
                        goto rx_done;
                }

                /* Ignore any messages for a previous incarnation of me */
                if (msg->ptlm_dststamp < peer->peer_myincarnation) {
                        kptllnd_peer_decref(peer);
                        goto rx_done;
                }

                if (msg->ptlm_dststamp != peer->peer_myincarnation) {
                        CERROR("%s: Unexpected dststamp "LPX64" "
                               "("LPX64" expected)\n",
                               libcfs_id2str(peer->peer_id), msg->ptlm_dststamp,
                               peer->peer_myincarnation);
                        rc = -EPROTO;
                        goto failed;
                }

                if (peer->peer_state == PEER_STATE_WAITING_HELLO) {
                        /* recoverable error - restart txs */
			spin_lock_irqsave(&peer->peer_lock, flags);
                        kptllnd_cancel_txlist(&peer->peer_sendq, &txs);
			spin_unlock_irqrestore(&peer->peer_lock, flags);

                        CWARN("NAK %s: Unexpected %s message\n",
                              libcfs_id2str(srcid),
                              kptllnd_msgtype2str(msg->ptlm_type));
                        kptllnd_nak(rx->rx_initiator);
                        rc = -EPROTO;
                        goto failed;
                }

                if (msg->ptlm_srcstamp != peer->peer_incarnation) {
                        CERROR("%s: Unexpected srcstamp "LPX64" "
                               "("LPX64" expected)\n",
                               libcfs_id2str(srcid),
                               msg->ptlm_srcstamp,
                               peer->peer_incarnation);
                        rc = -EPROTO;
                        goto failed;
                }
        }

        LASSERTF (LNET_NIDADDR(msg->ptlm_srcnid) ==
                         LNET_NIDADDR(peer->peer_id.nid), "m %s p %s\n",
                  libcfs_nid2str(msg->ptlm_srcnid),
                  libcfs_nid2str(peer->peer_id.nid));
        LASSERTF (msg->ptlm_srcpid == peer->peer_id.pid, "m %u p %u\n",
                  msg->ptlm_srcpid, peer->peer_id.pid);

	spin_lock_irqsave(&peer->peer_lock, flags);

        /* Check peer only sends when I've sent her credits */
        if (peer->peer_sent_credits == 0) {
                int  c = peer->peer_credits;
                int oc = peer->peer_outstanding_credits;
                int sc = peer->peer_sent_credits;

		spin_unlock_irqrestore(&peer->peer_lock, flags);

                CERROR("%s: buffer overrun [%d/%d+%d]\n",
                       libcfs_id2str(peer->peer_id), c, sc, oc);
                rc = -EPROTO;
                goto failed;
        }
        peer->peer_sent_credits--;

        /* No check for credit overflow - the peer may post new
         * buffers after the startup handshake. */
        peer->peer_credits += msg->ptlm_credits;

        /* This ensures the credit taken by NOOP can be returned */
        if (msg->ptlm_type == PTLLND_MSG_TYPE_NOOP) {
                peer->peer_outstanding_credits++;
                post_credit = PTLLND_POSTRX_NO_CREDIT;
        }

	spin_unlock_irqrestore(&peer->peer_lock, flags);

        /* See if something can go out now that credits have come in */
        if (msg->ptlm_credits != 0)
                kptllnd_peer_check_sends(peer);

        /* ptllnd-level protocol correct - rx takes my ref on peer and increments
         * peer_outstanding_credits when it completes */
        rx->rx_peer = peer;
        kptllnd_peer_alive(peer);

        switch (msg->ptlm_type) {
        default:
                /* already checked by kptllnd_msg_unpack() */
                LBUG();

        case PTLLND_MSG_TYPE_HELLO:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_HELLO\n");
                goto rx_done;

        case PTLLND_MSG_TYPE_NOOP:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_NOOP\n");
                goto rx_done;

        case PTLLND_MSG_TYPE_IMMEDIATE:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_IMMEDIATE\n");
                rc = lnet_parse(net->net_ni,
                                &msg->ptlm_u.immediate.kptlim_hdr,
                                msg->ptlm_srcnid,
                                rx, 0);
                if (rc >= 0) {                  /* kptllnd_recv owns 'rx' now */
                        kptllnd_net_decref(net);
                        return;
                }
                goto failed;
                
        case PTLLND_MSG_TYPE_PUT:
        case PTLLND_MSG_TYPE_GET:
                CDEBUG(D_NET, "PTLLND_MSG_TYPE_%s\n",
                        msg->ptlm_type == PTLLND_MSG_TYPE_PUT ?
                        "PUT" : "GET");

                /* checked in kptllnd_msg_unpack() */
                LASSERT (msg->ptlm_u.rdma.kptlrm_matchbits >= 
                         PTL_RESERVED_MATCHBITS);

                /* Update last match bits seen */
		spin_lock_irqsave(&peer->peer_lock, flags);

                if (msg->ptlm_u.rdma.kptlrm_matchbits >
                    rx->rx_peer->peer_last_matchbits_seen)
                        rx->rx_peer->peer_last_matchbits_seen =
                                msg->ptlm_u.rdma.kptlrm_matchbits;

		spin_unlock_irqrestore(&rx->rx_peer->peer_lock, flags);

                rc = lnet_parse(net->net_ni,
                                &msg->ptlm_u.rdma.kptlrm_hdr,
                                msg->ptlm_srcnid,
                                rx, 1);
                if (rc >= 0) {                  /* kptllnd_recv owns 'rx' now */
                        kptllnd_net_decref(net);
                        return;
                }
                goto failed;
        }

 failed:
        LASSERT (rc != 0);
        kptllnd_peer_close(peer, rc);
        if (rx->rx_peer == NULL)                /* drop ref on peer */
                kptllnd_peer_decref(peer);      /* unless rx_done will */
        if (!cfs_list_empty(&txs)) {
                LASSERT (net != NULL);
                kptllnd_restart_txs(net, srcid, &txs);
        }
 rx_done:
        if (net != NULL)
                kptllnd_net_decref(net);
        kptllnd_rx_done(rx, post_credit);
}
