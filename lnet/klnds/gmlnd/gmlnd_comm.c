/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 *
 * Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

/*
 *	This file contains all gmnal send and receive functions
 */

#include "gmlnd.h"

void
gmnal_notify_peer_down(gmnal_tx_t *tx)
{
        time_t             then;

        then = cfs_time_current_sec() -
                cfs_duration_sec(cfs_time_current() -
                                 tx->tx_launchtime);

        lnet_notify(tx->tx_gmni->gmni_ni, tx->tx_nid, 0, then);
}

void
gmnal_pack_msg(gmnal_ni_t *gmni, gmnal_msg_t *msg,
               lnet_nid_t dstnid, int type)
{
        /* CAVEAT EMPTOR! this only sets the common message fields. */
        msg->gmm_magic    = GMNAL_MSG_MAGIC;
        msg->gmm_version  = GMNAL_MSG_VERSION;
        msg->gmm_type     = type;
        msg->gmm_srcnid   = lnet_ptlcompat_srcnid(gmni->gmni_ni->ni_nid,
                                                  dstnid);
        msg->gmm_dstnid   = dstnid;
}

int
gmnal_unpack_msg(gmnal_ni_t *gmni, gmnal_rx_t *rx)
{
        gmnal_msg_t *msg = GMNAL_NETBUF_MSG(&rx->rx_buf);
        const int    hdr_size = offsetof(gmnal_msg_t, gmm_u);
        int          buffnob = rx->rx_islarge ? gmni->gmni_large_msgsize :
                                                gmni->gmni_small_msgsize;
        int          flip;

        /* rc = 0:SUCCESS -ve:failure +ve:version mismatch */

        /* GM may not overflow our buffer */
        LASSERT (rx->rx_recv_nob <= buffnob);

        /* 6 bytes are enough to have received magic + version */
        if (rx->rx_recv_nob < 6) {
                CERROR("Short message from gmid %u: %d\n",
                       rx->rx_recv_gmid, rx->rx_recv_nob);
                return -EPROTO;
        }

        if (msg->gmm_magic == GMNAL_MSG_MAGIC) {
                flip = 0;
        } else if (msg->gmm_magic == __swab32(GMNAL_MSG_MAGIC)) {
                flip = 1;
        } else if (msg->gmm_magic == LNET_PROTO_MAGIC ||
                   msg->gmm_magic == __swab32(LNET_PROTO_MAGIC)) {
                return EPROTO;
        } else {
                CERROR("Bad magic from gmid %u: %08x\n",
                       rx->rx_recv_gmid, msg->gmm_magic);
                return -EPROTO;
        }

        if (msg->gmm_version !=
            (flip ? __swab16(GMNAL_MSG_VERSION) : GMNAL_MSG_VERSION)) {
                return EPROTO;
        }

        if (rx->rx_recv_nob < hdr_size) {
                CERROR("Short message from %u: %d\n",
                       rx->rx_recv_gmid, rx->rx_recv_nob);
                return -EPROTO;
        }

        if (flip) {
                /* leave magic unflipped as a clue to peer endianness */
                __swab16s(&msg->gmm_version);
                __swab16s(&msg->gmm_type);
                __swab64s(&msg->gmm_srcnid);
                __swab64s(&msg->gmm_dstnid);
        }

        if (msg->gmm_srcnid == LNET_NID_ANY) {
                CERROR("Bad src nid from %u: %s\n",
                       rx->rx_recv_gmid, libcfs_nid2str(msg->gmm_srcnid));
                return -EPROTO;
        }

        if (!lnet_ptlcompat_matchnid(gmni->gmni_ni->ni_nid,
                                     msg->gmm_dstnid)) {
                CERROR("Bad dst nid from %u: %s\n",
                       rx->rx_recv_gmid, libcfs_nid2str(msg->gmm_dstnid));
                return -EPROTO;
        }

        switch (msg->gmm_type) {
        default:
                CERROR("Unknown message type from %u: %x\n",
                       rx->rx_recv_gmid, msg->gmm_type);
                return -EPROTO;

        case GMNAL_MSG_IMMEDIATE:
                if (rx->rx_recv_nob < offsetof(gmnal_msg_t, gmm_u.immediate.gmim_payload[0])) {
                        CERROR("Short IMMEDIATE from %u: %d(%lu)\n",
                               rx->rx_recv_gmid, rx->rx_recv_nob,
                               offsetof(gmnal_msg_t, gmm_u.immediate.gmim_payload[0]));
                        return -EPROTO;
                }
                break;
        }
        return 0;
}

gmnal_tx_t *
gmnal_get_tx(gmnal_ni_t *gmni)
{
        gmnal_tx_t *tx = NULL;

        spin_lock(&gmni->gmni_tx_lock);

        if (gmni->gmni_shutdown ||
            list_empty(&gmni->gmni_idle_txs)) {
                spin_unlock(&gmni->gmni_tx_lock);
                return NULL;
        }

        tx = list_entry(gmni->gmni_idle_txs.next, gmnal_tx_t, tx_list);
        list_del(&tx->tx_list);

        spin_unlock(&gmni->gmni_tx_lock);

        LASSERT (tx->tx_lntmsg == NULL);
        LASSERT (tx->tx_ltxb == NULL);
        LASSERT (!tx->tx_credit);

        return tx;
}

void
gmnal_tx_done(gmnal_tx_t *tx, int rc)
{
        gmnal_ni_t *gmni = tx->tx_gmni;
        int         wake_sched = 0;
        lnet_msg_t *lnetmsg = tx->tx_lntmsg;

        tx->tx_lntmsg = NULL;

        spin_lock(&gmni->gmni_tx_lock);

        if (tx->tx_ltxb != NULL) {
                wake_sched = 1;
                list_add_tail(&tx->tx_ltxb->txb_list, &gmni->gmni_idle_ltxbs);
                tx->tx_ltxb = NULL;
        }

        if (tx->tx_credit) {
                wake_sched = 1;
                gmni->gmni_tx_credits++;
                tx->tx_credit = 0;
        }

        list_add_tail(&tx->tx_list, &gmni->gmni_idle_txs);

        if (wake_sched)
                gmnal_check_txqueues_locked(gmni);

        spin_unlock(&gmni->gmni_tx_lock);

        /* Delay finalize until tx is free */
        if (lnetmsg != NULL)
                lnet_finalize(gmni->gmni_ni, lnetmsg, rc);
}

void
gmnal_drop_sends_callback(struct gm_port *gm_port, void *context,
                          gm_status_t status)
{
        gmnal_tx_t *tx = (gmnal_tx_t*)context;

        LASSERT(!in_interrupt());

        CDEBUG(D_NET, "status for tx [%p] is [%d][%s], nid %s\n",
               tx, status, gmnal_gmstatus2str(status),
               libcfs_nid2str(tx->tx_nid));

        gmnal_tx_done(tx, -EIO);
}

void
gmnal_tx_callback(gm_port_t *gm_port, void *context, gm_status_t status)
{
        gmnal_tx_t *tx = (gmnal_tx_t*)context;
        gmnal_ni_t *gmni = tx->tx_gmni;

        LASSERT(!in_interrupt());

        switch(status) {
        case GM_SUCCESS:
                gmnal_tx_done(tx, 0);
                return;

        case GM_SEND_DROPPED:
                CNETERR("Dropped tx %p to %s\n",
                        tx, libcfs_nid2str(tx->tx_nid));
                /* Another tx failed and called gm_drop_sends() which made this
                 * one complete immediately */
                gmnal_tx_done(tx, -EIO);
                return;

        default:
                /* Some error; NB don't complete tx yet; we need its credit for
                 * gm_drop_sends() */
                CNETERR("tx %p error %d(%s), nid %s\n",
                        tx, status, gmnal_gmstatus2str(status),
                        libcfs_nid2str(tx->tx_nid));

                gmnal_notify_peer_down(tx);

                spin_lock(&gmni->gmni_gm_lock);
                gm_drop_sends(gmni->gmni_port,
                              tx->tx_ltxb != NULL ?
                              GMNAL_LARGE_PRIORITY : GMNAL_SMALL_PRIORITY,
                              tx->tx_gmlid, *gmnal_tunables.gm_port,
                              gmnal_drop_sends_callback, tx);
                spin_unlock(&gmni->gmni_gm_lock);
                return;
        }

        /* not reached */
        LBUG();
}

void
gmnal_check_txqueues_locked (gmnal_ni_t *gmni)
{
        gmnal_tx_t    *tx;
        gmnal_txbuf_t *ltxb;
        int            gmsize;
        int            pri;
        void          *netaddr;

        tx = list_empty(&gmni->gmni_buf_txq) ? NULL :
             list_entry(gmni->gmni_buf_txq.next, gmnal_tx_t, tx_list);

        if (tx != NULL &&
            (tx->tx_large_nob == 0 ||
             !list_empty(&gmni->gmni_idle_ltxbs))) {

                /* consume tx */
                list_del(&tx->tx_list);

                LASSERT (tx->tx_ltxb == NULL);

                if (tx->tx_large_nob != 0) {
                        ltxb = list_entry(gmni->gmni_idle_ltxbs.next,
                                          gmnal_txbuf_t, txb_list);

                        /* consume large buffer */
                        list_del(&ltxb->txb_list);

                        spin_unlock(&gmni->gmni_tx_lock);

                        /* Unlocking here allows sends to get re-ordered,
                         * but we want to allow other CPUs to progress... */

                        tx->tx_ltxb = ltxb;

                        /* marshall message in tx_ltxb...
                         * 1. Copy what was marshalled so far (in tx_buf) */
                        memcpy(GMNAL_NETBUF_MSG(&ltxb->txb_buf),
                               GMNAL_NETBUF_MSG(&tx->tx_buf), tx->tx_msgnob);

                        /* 2. Copy the payload */
                        if (tx->tx_large_iskiov)
                                lnet_copy_kiov2kiov(
                                        gmni->gmni_large_pages,
                                        ltxb->txb_buf.nb_kiov,
                                        tx->tx_msgnob,
                                        tx->tx_large_niov,
                                        tx->tx_large_frags.kiov,
                                        tx->tx_large_offset,
                                        tx->tx_large_nob);
                        else
                                lnet_copy_iov2kiov(
                                        gmni->gmni_large_pages,
                                        ltxb->txb_buf.nb_kiov,
                                        tx->tx_msgnob,
                                        tx->tx_large_niov,
                                        tx->tx_large_frags.iov,
                                        tx->tx_large_offset,
                                        tx->tx_large_nob);

                        tx->tx_msgnob += tx->tx_large_nob;

                        spin_lock(&gmni->gmni_tx_lock);
                }

                list_add_tail(&tx->tx_list, &gmni->gmni_cred_txq);
        }

        if (!list_empty(&gmni->gmni_cred_txq) &&
            gmni->gmni_tx_credits != 0) {

                tx = list_entry(gmni->gmni_cred_txq.next, gmnal_tx_t, tx_list);

                /* consume tx and 1 credit */
                list_del(&tx->tx_list);
                gmni->gmni_tx_credits--;

                spin_unlock(&gmni->gmni_tx_lock);

                /* Unlocking here allows sends to get re-ordered, but we want
                 * to allow other CPUs to progress... */

                LASSERT(!tx->tx_credit);
                tx->tx_credit = 1;

                tx->tx_launchtime = cfs_time_current();

                if (tx->tx_msgnob <= gmni->gmni_small_msgsize) {
                        LASSERT (tx->tx_ltxb == NULL);
                        netaddr = GMNAL_NETBUF_LOCAL_NETADDR(&tx->tx_buf);
                        gmsize = gmni->gmni_small_gmsize;
                        pri = GMNAL_SMALL_PRIORITY;
                } else {
                        LASSERT (tx->tx_ltxb != NULL);
                        netaddr = GMNAL_NETBUF_LOCAL_NETADDR(&tx->tx_ltxb->txb_buf);
                        gmsize = gmni->gmni_large_gmsize;
                        pri = GMNAL_LARGE_PRIORITY;
                }

                spin_lock(&gmni->gmni_gm_lock);

                gm_send_to_peer_with_callback(gmni->gmni_port,
                                              netaddr, gmsize,
                                              tx->tx_msgnob,
                                              pri,
                                              tx->tx_gmlid,
                                              gmnal_tx_callback,
                                              (void*)tx);

                spin_unlock(&gmni->gmni_gm_lock);
                spin_lock(&gmni->gmni_tx_lock);
        }
}

void
gmnal_post_rx(gmnal_ni_t *gmni, gmnal_rx_t *rx)
{
        int   gmsize = rx->rx_islarge ? gmni->gmni_large_gmsize :
                                        gmni->gmni_small_gmsize;
        int   pri    = rx->rx_islarge ? GMNAL_LARGE_PRIORITY :
                                        GMNAL_SMALL_PRIORITY;
        void *buffer = GMNAL_NETBUF_LOCAL_NETADDR(&rx->rx_buf);

        CDEBUG(D_NET, "posting rx %p buf %p\n", rx, buffer);

        spin_lock(&gmni->gmni_gm_lock);
        gm_provide_receive_buffer_with_tag(gmni->gmni_port,
                                           buffer, gmsize, pri, 0);
        spin_unlock(&gmni->gmni_gm_lock);
}

void
gmnal_version_reply (gmnal_ni_t *gmni, gmnal_rx_t *rx)
{
        /* Future protocol version compatibility support!
         * The next gmlnd-specific protocol rev will first send a message to
         * check version; I reply with a stub message containing my current
         * magic+version... */
        gmnal_msg_t *msg;
        gmnal_tx_t  *tx = gmnal_get_tx(gmni);

        if (tx == NULL) {
                CERROR("Can't allocate tx to send version info to %u\n",
                       rx->rx_recv_gmid);
                return;
        }

        LASSERT (tx->tx_lntmsg == NULL);        /* no finalize */

        tx->tx_nid = LNET_NID_ANY;
        tx->tx_gmlid = rx->rx_recv_gmid;

        msg = GMNAL_NETBUF_MSG(&tx->tx_buf);
        msg->gmm_magic   = GMNAL_MSG_MAGIC;
        msg->gmm_version = GMNAL_MSG_VERSION;

        /* just send magic + version */
        tx->tx_msgnob = offsetof(gmnal_msg_t, gmm_type);
        tx->tx_large_nob = 0;

        spin_lock(&gmni->gmni_tx_lock);

        list_add_tail(&tx->tx_list, &gmni->gmni_buf_txq);
        gmnal_check_txqueues_locked(gmni);

        spin_unlock(&gmni->gmni_tx_lock);
}

int
gmnal_rx_thread(void *arg)
{
        gmnal_ni_t      *gmni = arg;
        gm_recv_event_t *rxevent = NULL;
        gm_recv_t       *recv = NULL;
        gmnal_rx_t      *rx;
        int              rc;

        cfs_daemonize("gmnal_rxd");

        while (!gmni->gmni_shutdown) {
                rc = down_interruptible(&gmni->gmni_rx_mutex);
                LASSERT (rc == 0 || rc == -EINTR);
                if (rc != 0)
                        continue;

                spin_lock(&gmni->gmni_gm_lock);
                rxevent = gm_blocking_receive_no_spin(gmni->gmni_port);
                spin_unlock(&gmni->gmni_gm_lock);

                switch (GM_RECV_EVENT_TYPE(rxevent)) {
                default:
                        gm_unknown(gmni->gmni_port, rxevent);
                        up(&gmni->gmni_rx_mutex);
                        continue;

                case GM_FAST_RECV_EVENT:
                case GM_FAST_PEER_RECV_EVENT:
                case GM_PEER_RECV_EVENT:
                case GM_FAST_HIGH_RECV_EVENT:
                case GM_FAST_HIGH_PEER_RECV_EVENT:
                case GM_HIGH_PEER_RECV_EVENT:
                case GM_RECV_EVENT:
                case GM_HIGH_RECV_EVENT:
                        break;
                }

                recv = &rxevent->recv;
                rx = gm_hash_find(gmni->gmni_rx_hash,
                                  gm_ntohp(recv->buffer));
                LASSERT (rx != NULL);

                rx->rx_recv_nob  = gm_ntoh_u32(recv->length);
                rx->rx_recv_gmid = gm_ntoh_u16(recv->sender_node_id);
                rx->rx_recv_port = gm_ntoh_u8(recv->sender_port_id);
                rx->rx_recv_type = gm_ntoh_u8(recv->type);

                switch (GM_RECV_EVENT_TYPE(rxevent)) {
                case GM_FAST_RECV_EVENT:
                case GM_FAST_PEER_RECV_EVENT:
                case GM_FAST_HIGH_RECV_EVENT:
                case GM_FAST_HIGH_PEER_RECV_EVENT:
                        LASSERT (rx->rx_recv_nob <= PAGE_SIZE);

                        memcpy(GMNAL_NETBUF_MSG(&rx->rx_buf),
                               gm_ntohp(recv->message), rx->rx_recv_nob);
                        break;
                }

                up(&gmni->gmni_rx_mutex);

                CDEBUG (D_NET, "rx %p: buf %p(%p) nob %d\n", rx,
                        GMNAL_NETBUF_LOCAL_NETADDR(&rx->rx_buf),
                        gm_ntohp(recv->buffer), rx->rx_recv_nob);

                /* We're connectionless: simply drop packets with
                 * errors */
                rc = gmnal_unpack_msg(gmni, rx);

                if (rc == 0) {
                        gmnal_msg_t *msg = GMNAL_NETBUF_MSG(&rx->rx_buf);

                        LASSERT (msg->gmm_type == GMNAL_MSG_IMMEDIATE);
                        rc = lnet_parse(gmni->gmni_ni,
                                        &msg->gmm_u.immediate.gmim_hdr,
                                        msg->gmm_srcnid, rx, 0);
                } else if (rc > 0) {
                        gmnal_version_reply(gmni, rx);
                        rc = -EPROTO;           /* repost rx */
                }

                if (rc < 0)                     /* parse failure */
                        gmnal_post_rx(gmni, rx);
        }

        CDEBUG(D_NET, "exiting\n");
        atomic_dec(&gmni->gmni_nthreads);
        return 0;
}

void
gmnal_stop_threads(gmnal_ni_t *gmni)
{
        int count = 2;

        gmni->gmni_shutdown = 1;
        mb();

        /* wake rxthread owning gmni_rx_mutex with an alarm. */
        spin_lock(&gmni->gmni_gm_lock);
        gm_set_alarm(gmni->gmni_port, &gmni->gmni_alarm, 0, NULL, NULL);
        spin_unlock(&gmni->gmni_gm_lock);

        while (atomic_read(&gmni->gmni_nthreads) != 0) {
                count++;
                if ((count & (count - 1)) == 0)
                        CWARN("Waiting for %d threads to stop\n",
                              atomic_read(&gmni->gmni_nthreads));
                gmnal_yield(1);
        }
}

int
gmnal_start_threads(gmnal_ni_t *gmni)
{
        int     i;
        int     pid;

        LASSERT (!gmni->gmni_shutdown);
        LASSERT (atomic_read(&gmni->gmni_nthreads) == 0);

        gm_initialize_alarm(&gmni->gmni_alarm);

        for (i = 0; i < num_online_cpus(); i++) {

                pid = kernel_thread(gmnal_rx_thread, (void*)gmni, 0);
                if (pid < 0) {
                        CERROR("rx thread failed to start: %d\n", pid);
                        gmnal_stop_threads(gmni);
                        return pid;
                }

                atomic_inc(&gmni->gmni_nthreads);
        }

        return 0;
}
