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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/o2iblnd/o2iblnd.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "o2iblnd.h"

lnd_t the_kiblnd = {
        .lnd_type       = O2IBLND,
        .lnd_startup    = kiblnd_startup,
        .lnd_shutdown   = kiblnd_shutdown,
        .lnd_ctl        = kiblnd_ctl,
        .lnd_send       = kiblnd_send,
        .lnd_recv       = kiblnd_recv,
};

kib_data_t              kiblnd_data;

__u32
kiblnd_cksum (void *ptr, int nob)
{
        char  *c  = ptr;
        __u32  sum = 0;

        while (nob-- > 0)
                sum = ((sum << 1) | (sum >> 31)) + *c++;

        /* ensure I don't return 0 (== no checksum) */
        return (sum == 0) ? 1 : sum;
}

void
kiblnd_init_msg (kib_msg_t *msg, int type, int body_nob)
{
        msg->ibm_type = type;
        msg->ibm_nob  = offsetof(kib_msg_t, ibm_u) + body_nob;
}

void
kiblnd_pack_msg (lnet_ni_t *ni, kib_msg_t *msg,
                 int credits, lnet_nid_t dstnid, __u64 dststamp)
{
        kib_net_t *net = ni->ni_data;

        /* CAVEAT EMPTOR! all message fields not set here should have been
         * initialised previously. */
        msg->ibm_magic    = IBLND_MSG_MAGIC;
        msg->ibm_version  = IBLND_MSG_VERSION;
        /*   ibm_type */
        msg->ibm_credits  = credits;
        /*   ibm_nob */
        msg->ibm_cksum    = 0;
        msg->ibm_srcnid   = lnet_ptlcompat_srcnid(ni->ni_nid, dstnid);
        msg->ibm_srcstamp = net->ibn_incarnation;
        msg->ibm_dstnid   = dstnid;
        msg->ibm_dststamp = dststamp;

        if (*kiblnd_tunables.kib_cksum) {
                /* NB ibm_cksum zero while computing cksum */
                msg->ibm_cksum = kiblnd_cksum(msg, msg->ibm_nob);
        }
}

int
kiblnd_unpack_msg(kib_msg_t *msg, int nob)
{
        const int hdr_size = offsetof(kib_msg_t, ibm_u);
        __u32     msg_cksum;
        int       flip;
        int       msg_nob;
#if !IBLND_MAP_ON_DEMAND
        int       i;
        int       n;
#endif
        /* 6 bytes are enough to have received magic + version */
        if (nob < 6) {
                CERROR("Short message: %d\n", nob);
                return -EPROTO;
        }

        if (msg->ibm_magic == IBLND_MSG_MAGIC) {
                flip = 0;
        } else if (msg->ibm_magic == __swab32(IBLND_MSG_MAGIC)) {
                flip = 1;
        } else {
                CERROR("Bad magic: %08x\n", msg->ibm_magic);
                return -EPROTO;
        }

        if (msg->ibm_version !=
            (flip ? __swab16(IBLND_MSG_VERSION) : IBLND_MSG_VERSION)) {
                CERROR("Bad version: %d\n", msg->ibm_version);
                return -EPROTO;
        }

        if (nob < hdr_size) {
                CERROR("Short message: %d\n", nob);
                return -EPROTO;
        }

        msg_nob = flip ? __swab32(msg->ibm_nob) : msg->ibm_nob;
        if (msg_nob > nob) {
                CERROR("Short message: got %d, wanted %d\n", nob, msg_nob);
                return -EPROTO;
        }

        /* checksum must be computed with ibm_cksum zero and BEFORE anything
         * gets flipped */
        msg_cksum = flip ? __swab32(msg->ibm_cksum) : msg->ibm_cksum;
        msg->ibm_cksum = 0;
        if (msg_cksum != 0 &&
            msg_cksum != kiblnd_cksum(msg, msg_nob)) {
                CERROR("Bad checksum\n");
                return -EPROTO;
        }
        msg->ibm_cksum = msg_cksum;

        if (flip) {
                /* leave magic unflipped as a clue to peer endianness */
                __swab16s(&msg->ibm_version);
                CLASSERT (sizeof(msg->ibm_type) == 1);
                CLASSERT (sizeof(msg->ibm_credits) == 1);
                msg->ibm_nob = msg_nob;
                __swab64s(&msg->ibm_srcnid);
                __swab64s(&msg->ibm_srcstamp);
                __swab64s(&msg->ibm_dstnid);
                __swab64s(&msg->ibm_dststamp);
        }

        if (msg->ibm_srcnid == LNET_NID_ANY) {
                CERROR("Bad src nid: %s\n", libcfs_nid2str(msg->ibm_srcnid));
                return -EPROTO;
        }

        switch (msg->ibm_type) {
        default:
                CERROR("Unknown message type %x\n", msg->ibm_type);
                return -EPROTO;

        case IBLND_MSG_NOOP:
                break;

        case IBLND_MSG_IMMEDIATE:
                if (msg_nob < offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[0])) {
                        CERROR("Short IMMEDIATE: %d(%d)\n", msg_nob,
                               (int)offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[0]));
                        return -EPROTO;
                }
                break;

        case IBLND_MSG_PUT_REQ:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.putreq)) {
                        CERROR("Short PUT_REQ: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.putreq)));
                        return -EPROTO;
                }
                break;

        case IBLND_MSG_PUT_ACK:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.putack)) {
                        CERROR("Short PUT_ACK: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.putack)));
                        return -EPROTO;
                }
#if IBLND_MAP_ON_DEMAND
                if (flip) {
                        __swab64s(&msg->ibm_u.putack.ibpam_rd.rd_addr);
                        __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_nob);
                        __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_key);
                }
#else
                if (flip) {
                        __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_key);
                        __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_nfrags);
                }

                n = msg->ibm_u.putack.ibpam_rd.rd_nfrags;
                if (n <= 0 || n > IBLND_MAX_RDMA_FRAGS) {
                        CERROR("Bad PUT_ACK nfrags: %d, should be 0 < n <= %d\n", 
                               n, IBLND_MAX_RDMA_FRAGS);
                        return -EPROTO;
                }

                if (msg_nob < offsetof(kib_msg_t, ibm_u.putack.ibpam_rd.rd_frags[n])) {
                        CERROR("Short PUT_ACK: %d(%d)\n", msg_nob,
                               (int)offsetof(kib_msg_t, ibm_u.putack.ibpam_rd.rd_frags[n]));
                        return -EPROTO;
                }

                if (flip) {
                        for (i = 0; i < n; i++) {
                                __swab32s(&msg->ibm_u.putack.ibpam_rd.rd_frags[i].rf_nob);
                                __swab64s(&msg->ibm_u.putack.ibpam_rd.rd_frags[i].rf_addr);
                        }
                }
#endif
                break;

        case IBLND_MSG_GET_REQ:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.get)) {
                        CERROR("Short GET_REQ: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.get)));
                        return -EPROTO;
                }
#if IBLND_MAP_ON_DEMAND
                if (flip) {
                        __swab64s(&msg->ibm_u.get.ibgm_rd.rd_addr);
                        __swab32s(&msg->ibm_u.get.ibgm_rd.rd_nob);
                        __swab32s(&msg->ibm_u.get.ibgm_rd.rd_key);
                }
#else
                if (flip) {
                        __swab32s(&msg->ibm_u.get.ibgm_rd.rd_key);
                        __swab32s(&msg->ibm_u.get.ibgm_rd.rd_nfrags);
                }

                n = msg->ibm_u.get.ibgm_rd.rd_nfrags;
                if (n <= 0 || n > IBLND_MAX_RDMA_FRAGS) {
                        CERROR("Bad GET_REQ nfrags: %d, should be 0 < n <= %d\n", 
                               n, IBLND_MAX_RDMA_FRAGS);
                        return -EPROTO;
                }
                
                if (msg_nob < offsetof(kib_msg_t, ibm_u.get.ibgm_rd.rd_frags[n])) {
                        CERROR("Short GET_REQ: %d(%d)\n", msg_nob,
                               (int)offsetof(kib_msg_t, ibm_u.get.ibgm_rd.rd_frags[n]));
                        return -EPROTO;
                }
                
                if (flip)
                        for (i = 0; i < msg->ibm_u.get.ibgm_rd.rd_nfrags; i++) {
                                __swab32s(&msg->ibm_u.get.ibgm_rd.rd_frags[i].rf_nob);
                                __swab64s(&msg->ibm_u.get.ibgm_rd.rd_frags[i].rf_addr);
                        }
#endif
                break;

        case IBLND_MSG_PUT_NAK:
        case IBLND_MSG_PUT_DONE:
        case IBLND_MSG_GET_DONE:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.completion)) {
                        CERROR("Short RDMA completion: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.completion)));
                        return -EPROTO;
                }
                if (flip)
                        __swab32s(&msg->ibm_u.completion.ibcm_status);
                break;

        case IBLND_MSG_CONNREQ:
        case IBLND_MSG_CONNACK:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.connparams)) {
                        CERROR("Short connreq/ack: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.connparams)));
                        return -EPROTO;
                }
                if (flip) {
                        __swab16s(&msg->ibm_u.connparams.ibcp_queue_depth);
                        __swab16s(&msg->ibm_u.connparams.ibcp_max_frags);
                        __swab32s(&msg->ibm_u.connparams.ibcp_max_msg_size);
                }
                break;
        }
        return 0;
}

int
kiblnd_create_peer (lnet_ni_t *ni, kib_peer_t **peerp, lnet_nid_t nid)
{
        kib_peer_t     *peer;
        kib_net_t      *net = ni->ni_data;
        unsigned long   flags;

        LASSERT (net != NULL);
        LASSERT (nid != LNET_NID_ANY);

        LIBCFS_ALLOC(peer, sizeof(*peer));
        if (peer == NULL) {
                CERROR("Cannot allocate peer\n");
                return -ENOMEM;
        }

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        peer->ibp_ni = ni;
        peer->ibp_nid = nid;
        peer->ibp_error = 0;
        peer->ibp_last_alive = cfs_time_current();
        atomic_set(&peer->ibp_refcount, 1);     /* 1 ref for caller */

        INIT_LIST_HEAD(&peer->ibp_list);       /* not in the peer table yet */
        INIT_LIST_HEAD(&peer->ibp_conns);
        INIT_LIST_HEAD(&peer->ibp_tx_queue);

        write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        /* always called with a ref on ni, which prevents ni being shutdown */
        LASSERT (net->ibn_shutdown == 0);

        /* npeers only grows with the global lock held */
        atomic_inc(&net->ibn_npeers);

        write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

        *peerp = peer;
        return 0;
}

void
kiblnd_destroy_peer (kib_peer_t *peer)
{
        kib_net_t *net = peer->ibp_ni->ni_data;

        LASSERT (net != NULL);
        LASSERT (atomic_read(&peer->ibp_refcount) == 0);
        LASSERT (!kiblnd_peer_active(peer));
        LASSERT (peer->ibp_connecting == 0);
        LASSERT (peer->ibp_accepting == 0);
        LASSERT (list_empty(&peer->ibp_conns));
        LASSERT (list_empty(&peer->ibp_tx_queue));

        LIBCFS_FREE(peer, sizeof(*peer));

        /* NB a peer's connections keep a reference on their peer until
         * they are destroyed, so we can be assured that _all_ state to do
         * with this peer has been cleaned up when its refcount drops to
         * zero. */
        atomic_dec(&net->ibn_npeers);
}

void
kiblnd_destroy_dev (kib_dev_t *dev)
{
        LASSERT (dev->ibd_nnets == 0);

        if (!list_empty(&dev->ibd_list)) /* on kib_devs? */
                list_del_init(&dev->ibd_list);

        if (dev->ibd_mr != NULL)
                ib_dereg_mr(dev->ibd_mr);

        if (dev->ibd_pd != NULL)
                ib_dealloc_pd(dev->ibd_pd);

        if (dev->ibd_cmid != NULL)
                rdma_destroy_id(dev->ibd_cmid);

        LIBCFS_FREE(dev, sizeof(*dev));
}

kib_peer_t *
kiblnd_find_peer_locked (lnet_nid_t nid)
{
        /* the caller is responsible for accounting the additional reference
         * that this creates */
        struct list_head *peer_list = kiblnd_nid2peerlist(nid);
        struct list_head *tmp;
        kib_peer_t       *peer;

        list_for_each (tmp, peer_list) {

                peer = list_entry(tmp, kib_peer_t, ibp_list);

                LASSERT (peer->ibp_connecting > 0 || /* creating conns */
                         peer->ibp_accepting > 0 ||
                         !list_empty(&peer->ibp_conns));  /* active conn */

                if (peer->ibp_nid != nid)
                        continue;

                CDEBUG(D_NET, "got peer [%p] -> %s (%d)\n",
                       peer, libcfs_nid2str(nid),
                       atomic_read(&peer->ibp_refcount));
                return peer;
        }
        return NULL;
}

void
kiblnd_unlink_peer_locked (kib_peer_t *peer)
{
        LASSERT (list_empty(&peer->ibp_conns));

        LASSERT (kiblnd_peer_active(peer));
        list_del_init(&peer->ibp_list);
        /* lose peerlist's ref */
        kiblnd_peer_decref(peer);
}

int
kiblnd_get_peer_info (lnet_ni_t *ni, int index, 
                      lnet_nid_t *nidp, int *count)
{
        kib_peer_t        *peer;
        struct list_head  *ptmp;
        int                i;
        unsigned long      flags;

        read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {

                list_for_each (ptmp, &kiblnd_data.kib_peers[i]) {

                        peer = list_entry(ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_connecting > 0 ||
                                 peer->ibp_accepting > 0 ||
                                 !list_empty(&peer->ibp_conns));

                        if (peer->ibp_ni != ni)
                                continue;

                        if (index-- > 0)
                                continue;

                        *nidp = peer->ibp_nid;
                        *count = atomic_read(&peer->ibp_refcount);

                        read_unlock_irqrestore(&kiblnd_data.kib_global_lock,
                                               flags);
                        return 0;
                }
        }

        read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
        return -ENOENT;
}

void
kiblnd_del_peer_locked (kib_peer_t *peer)
{
        struct list_head *ctmp;
        struct list_head *cnxt;
        kib_conn_t       *conn;

        if (list_empty(&peer->ibp_conns)) {
                kiblnd_unlink_peer_locked(peer);
        } else {
                list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                        conn = list_entry(ctmp, kib_conn_t, ibc_list);

                        kiblnd_close_conn_locked(conn, 0);
                }
                /* NB closing peer's last conn unlinked it. */
        }
        /* NB peer now unlinked; might even be freed if the peer table had the
         * last ref on it. */
}

int
kiblnd_del_peer (lnet_ni_t *ni, lnet_nid_t nid)
{
        CFS_LIST_HEAD     (zombies);
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        kib_peer_t        *peer;
        int                lo;
        int                hi;
        int                i;
        unsigned long      flags;
        int                rc = -ENOENT;

        write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        if (nid != LNET_NID_ANY) {
                lo = hi = kiblnd_nid2peerlist(nid) - kiblnd_data.kib_peers;
        } else {
                lo = 0;
                hi = kiblnd_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kiblnd_data.kib_peers[i]) {
                        peer = list_entry(ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_connecting > 0 ||
                                 peer->ibp_accepting > 0 ||
                                 !list_empty(&peer->ibp_conns));

                        if (peer->ibp_ni != ni)
                                continue;

                        if (!(nid == LNET_NID_ANY || peer->ibp_nid == nid))
                                continue;

                        if (!list_empty(&peer->ibp_tx_queue)) {
                                LASSERT (list_empty(&peer->ibp_conns));

                                list_splice_init(&peer->ibp_tx_queue, &zombies);
                        }

                        kiblnd_del_peer_locked(peer);
                        rc = 0;         /* matched something */
                }
        }

        write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

        kiblnd_txlist_done(ni, &zombies, -EIO);

        return rc;
}

kib_conn_t *
kiblnd_get_conn_by_idx (lnet_ni_t *ni, int index)
{
        kib_peer_t        *peer;
        struct list_head  *ptmp;
        kib_conn_t        *conn;
        struct list_head  *ctmp;
        int                i;
        unsigned long      flags;

        read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {
                list_for_each (ptmp, &kiblnd_data.kib_peers[i]) {

                        peer = list_entry(ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_connecting > 0 ||
                                 peer->ibp_accepting > 0 ||
                                 !list_empty(&peer->ibp_conns));

                        if (peer->ibp_ni != ni)
                                continue;

                        list_for_each (ctmp, &peer->ibp_conns) {
                                if (index-- > 0)
                                        continue;

                                conn = list_entry(ctmp, kib_conn_t, ibc_list);
                                kiblnd_conn_addref(conn);
                                read_unlock_irqrestore(&kiblnd_data.kib_global_lock,
                                                       flags);
                                return conn;
                        }
                }
        }

        read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
        return NULL;
}

void
kiblnd_debug_rx (kib_rx_t *rx)
{
        CDEBUG(D_CONSOLE, "      %p status %d msg_type %x cred %d\n",
               rx, rx->rx_status, rx->rx_msg->ibm_type,
               rx->rx_msg->ibm_credits);
}

void
kiblnd_debug_tx (kib_tx_t *tx)
{
        CDEBUG(D_CONSOLE, "      %p snd %d q %d w %d rc %d dl %lx "
               "cookie "LPX64" msg %s%s type %x cred %d\n",
               tx, tx->tx_sending, tx->tx_queued, tx->tx_waiting,
               tx->tx_status, tx->tx_deadline, tx->tx_cookie,
               tx->tx_lntmsg[0] == NULL ? "-" : "!",
               tx->tx_lntmsg[1] == NULL ? "-" : "!",
               tx->tx_msg->ibm_type, tx->tx_msg->ibm_credits);
}

void
kiblnd_debug_conn (kib_conn_t *conn)
{
        struct list_head *tmp;
        int               i;

        spin_lock(&conn->ibc_lock);

        CDEBUG(D_CONSOLE, "conn[%d] %p -> %s: \n",
               atomic_read(&conn->ibc_refcount), conn,
               libcfs_nid2str(conn->ibc_peer->ibp_nid));
        CDEBUG(D_CONSOLE, "   state %d nposted %d cred %d o_cred %d r_cred %d\n",
               conn->ibc_state, conn->ibc_nsends_posted, conn->ibc_credits, 
               conn->ibc_outstanding_credits, conn->ibc_reserved_credits);
        CDEBUG(D_CONSOLE, "   comms_err %d\n", conn->ibc_comms_error);

        CDEBUG(D_CONSOLE, "   early_rxs:\n");
        list_for_each(tmp, &conn->ibc_early_rxs)
                kiblnd_debug_rx(list_entry(tmp, kib_rx_t, rx_list));

        CDEBUG(D_CONSOLE, "   tx_noops:\n");
        list_for_each(tmp, &conn->ibc_tx_noops)
                kiblnd_debug_tx(list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   tx_queue_nocred:\n");
        list_for_each(tmp, &conn->ibc_tx_queue_nocred)
                kiblnd_debug_tx(list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   tx_queue_rsrvd:\n");
        list_for_each(tmp, &conn->ibc_tx_queue_rsrvd)
                kiblnd_debug_tx(list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   tx_queue:\n");
        list_for_each(tmp, &conn->ibc_tx_queue)
                kiblnd_debug_tx(list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   active_txs:\n");
        list_for_each(tmp, &conn->ibc_active_txs)
                kiblnd_debug_tx(list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   rxs:\n");
        for (i = 0; i < IBLND_RX_MSGS; i++)
                kiblnd_debug_rx(&conn->ibc_rxs[i]);

        spin_unlock(&conn->ibc_lock);
}

kib_conn_t *
kiblnd_create_conn (kib_peer_t *peer, struct rdma_cm_id *cmid, int state)
{
        /* CAVEAT EMPTOR:
         * If the new conn is created successfully it takes over the caller's
         * ref on 'peer'.  It also "owns" 'cmid' and destroys it when it itself
         * is destroyed.  On failure, the caller's ref on 'peer' remains and
         * she must dispose of 'cmid'.  (Actually I'd block forever if I tried
         * to destroy 'cmid' here since I'm called from the CM which still has
         * its ref on 'cmid'). */
        kib_conn_t             *conn;
        kib_net_t              *net = peer->ibp_ni->ni_data;
        int                     i;
        int                     page_offset;
        int                     ipage;
        int                     rc;
        struct ib_cq           *cq;
        struct ib_qp_init_attr *init_qp_attr;
        unsigned long           flags;

        LASSERT (net != NULL);
        LASSERT (!in_interrupt());

        LIBCFS_ALLOC(init_qp_attr, sizeof(*init_qp_attr));
        if (init_qp_attr == NULL) {
                CERROR("Can't allocate qp_attr for %s\n",
                       libcfs_nid2str(peer->ibp_nid));
                goto failed_0;
        }

        LIBCFS_ALLOC(conn, sizeof(*conn));
        if (conn == NULL) {
                CERROR("Can't allocate connection for %s\n",
                       libcfs_nid2str(peer->ibp_nid));
                goto failed_1;
        }

        memset(conn, 0, sizeof(*conn)); /* zero flags, NULL pointers etc... */

        conn->ibc_state = IBLND_CONN_INIT;
        conn->ibc_peer = peer;                  /* I take the caller's ref */
        cmid->context = conn;                   /* for future CM callbacks */
        conn->ibc_cmid = cmid;

        INIT_LIST_HEAD(&conn->ibc_early_rxs);
        INIT_LIST_HEAD(&conn->ibc_tx_noops);
        INIT_LIST_HEAD(&conn->ibc_tx_queue);
        INIT_LIST_HEAD(&conn->ibc_tx_queue_rsrvd);
        INIT_LIST_HEAD(&conn->ibc_tx_queue_nocred);
        INIT_LIST_HEAD(&conn->ibc_active_txs);
        spin_lock_init(&conn->ibc_lock);

        LIBCFS_ALLOC(conn->ibc_connvars, sizeof(*conn->ibc_connvars));
        if (conn->ibc_connvars == NULL) {
                CERROR("Can't allocate in-progress connection state\n");
                goto failed_2;
        }
        memset(conn->ibc_connvars, 0, sizeof(*conn->ibc_connvars));

        LIBCFS_ALLOC(conn->ibc_rxs, IBLND_RX_MSGS * sizeof(kib_rx_t));
        if (conn->ibc_rxs == NULL) {
                CERROR("Cannot allocate RX buffers\n");
                goto failed_2;
        }
        memset(conn->ibc_rxs, 0, IBLND_RX_MSGS * sizeof(kib_rx_t));

        rc = kiblnd_alloc_pages(&conn->ibc_rx_pages, IBLND_RX_MSG_PAGES);
        if (rc != 0)
                goto failed_2;

        for (i = ipage = page_offset = 0; i < IBLND_RX_MSGS; i++) {
                struct page *page = conn->ibc_rx_pages->ibp_pages[ipage];
                kib_rx_t    *rx = &conn->ibc_rxs[i];

                rx->rx_conn = conn;
                rx->rx_msg = (kib_msg_t *)(((char *)page_address(page)) +
                                           page_offset);
                rx->rx_msgaddr = kiblnd_dma_map_single(cmid->device,
                                                       rx->rx_msg, IBLND_MSG_SIZE,
                                                       DMA_FROM_DEVICE);
                KIBLND_UNMAP_ADDR_SET(rx, rx_msgunmap, rx->rx_msgaddr);

                CDEBUG(D_NET,"rx %d: %p "LPX64"("LPX64")\n",
                       i, rx->rx_msg, rx->rx_msgaddr,
                       lnet_page2phys(page) + page_offset);

                page_offset += IBLND_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= IBLND_RX_MSG_PAGES);
                }
        }

#ifdef HAVE_OFED_IB_COMP_VECTOR
        cq = ib_create_cq(cmid->device,
                          kiblnd_cq_completion, kiblnd_cq_event, conn,
                          IBLND_CQ_ENTRIES(), 0);
#else
        cq = ib_create_cq(cmid->device,
                          kiblnd_cq_completion, kiblnd_cq_event, conn,
                          IBLND_CQ_ENTRIES());
#endif
        if (!IS_ERR(cq)) {
                conn->ibc_cq = cq;
        } else {
                CERROR("Can't create CQ: %ld\n", PTR_ERR(cq));
                goto failed_2;
        }

        rc = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
        if (rc != 0) {
                CERROR("Can't request completion notificiation: %d\n", rc);
                goto failed_2;
        }

        memset(init_qp_attr, 0, sizeof(*init_qp_attr));
        init_qp_attr->event_handler = kiblnd_qp_event;
        init_qp_attr->qp_context = conn;
        init_qp_attr->cap.max_send_wr = IBLND_SEND_WRS;
        init_qp_attr->cap.max_recv_wr = IBLND_RECV_WRS;
        init_qp_attr->cap.max_send_sge = 1;
        init_qp_attr->cap.max_recv_sge = 1;
        init_qp_attr->sq_sig_type = IB_SIGNAL_REQ_WR;
        init_qp_attr->qp_type = IB_QPT_RC;
        init_qp_attr->send_cq = cq;
        init_qp_attr->recv_cq = cq;

        rc = 0;
        write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
        switch (*kiblnd_tunables.kib_ib_mtu) {
        default:
                rc = *kiblnd_tunables.kib_ib_mtu;
                /* fall through to... */
        case 0: /* set tunable to the default
                 * CAVEAT EMPTOR! this assumes the default is one of the MTUs
                 * below, otherwise we'll WARN on the next QP create */
                *kiblnd_tunables.kib_ib_mtu =
                        ib_mtu_enum_to_int(cmid->route.path_rec->mtu);
                break;
        case 256:
                cmid->route.path_rec->mtu = IB_MTU_256;
                break;
        case 512:
                cmid->route.path_rec->mtu = IB_MTU_512;
                break;
        case 1024:
                cmid->route.path_rec->mtu = IB_MTU_1024;
                break;
        case 2048:
                cmid->route.path_rec->mtu = IB_MTU_2048;
                break;
        case 4096:
                cmid->route.path_rec->mtu = IB_MTU_4096;
                break;
        }
        write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

        if (rc != 0)
                CWARN("Invalid IB MTU value %d, using default value %d\n",
                      rc, *kiblnd_tunables.kib_ib_mtu);
                                
        rc = rdma_create_qp(cmid, net->ibn_dev->ibd_pd, init_qp_attr);
        if (rc != 0) {
                CERROR("Can't create QP: %d\n", rc);
                goto failed_2;
        }

        LIBCFS_FREE(init_qp_attr, sizeof(*init_qp_attr));

        /* 1 ref for caller and each rxmsg */
        atomic_set(&conn->ibc_refcount, 1 + IBLND_RX_MSGS);
        conn->ibc_nrx = IBLND_RX_MSGS;

        /* post receives */
        for (i = 0; i < IBLND_RX_MSGS; i++) {
                rc = kiblnd_post_rx(&conn->ibc_rxs[i],
                                    IBLND_POSTRX_NO_CREDIT);
                if (rc != 0) {
                        CERROR("Can't post rxmsg: %d\n", rc);

                        /* Make posted receives complete */
                        kiblnd_abort_receives(conn);

                        /* correct # of posted buffers 
                         * NB locking needed now I'm racing with completion */
                        spin_lock_irqsave(&kiblnd_data.kib_sched_lock, flags);
                        conn->ibc_nrx -= IBLND_RX_MSGS - i;
                        spin_unlock_irqrestore(&kiblnd_data.kib_sched_lock,
                                               flags);

                        /* Drop my own and unused rxbuffer refcounts */
                        while (i++ <= IBLND_RX_MSGS)
                                kiblnd_conn_decref(conn);

                        return NULL;
                }
        }
        
        /* Init successful! */
        LASSERT (state == IBLND_CONN_ACTIVE_CONNECT ||
                 state == IBLND_CONN_PASSIVE_WAIT);
        conn->ibc_state = state;

        /* 1 more conn */
        atomic_inc(&net->ibn_nconns);
        return conn;

 failed_2:
        kiblnd_destroy_conn(conn);
 failed_1:
        LIBCFS_FREE(init_qp_attr, sizeof(*init_qp_attr));
 failed_0:
        return NULL;
}

void
kiblnd_destroy_conn (kib_conn_t *conn)
{
        struct rdma_cm_id *cmid = conn->ibc_cmid;
        kib_peer_t        *peer = conn->ibc_peer;
        int                rc;
        int                i;

        LASSERT (!in_interrupt());
        LASSERT (atomic_read(&conn->ibc_refcount) == 0);
        LASSERT (list_empty(&conn->ibc_early_rxs));
        LASSERT (list_empty(&conn->ibc_tx_noops));
        LASSERT (list_empty(&conn->ibc_tx_queue));
        LASSERT (list_empty(&conn->ibc_tx_queue_rsrvd));
        LASSERT (list_empty(&conn->ibc_tx_queue_nocred));
        LASSERT (list_empty(&conn->ibc_active_txs));
        LASSERT (conn->ibc_nsends_posted == 0);

        switch (conn->ibc_state) {
        default:
                /* conn must be completely disengaged from the network */
                LBUG();

        case IBLND_CONN_DISCONNECTED:
                /* connvars should have been freed already */
                LASSERT (conn->ibc_connvars == NULL);
                break;

        case IBLND_CONN_INIT:
                break;
        }

        if (conn->ibc_cmid->qp != NULL)
                rdma_destroy_qp(conn->ibc_cmid);

        if (conn->ibc_cq != NULL) {
                rc = ib_destroy_cq(conn->ibc_cq);
                if (rc != 0)
                        CWARN("Error destroying CQ: %d\n", rc);
        }

        if (conn->ibc_rx_pages != NULL) {
                LASSERT (conn->ibc_rxs != NULL);

                for (i = 0; i < IBLND_RX_MSGS; i++) {
                        kib_rx_t *rx = &conn->ibc_rxs[i];

                        LASSERT (rx->rx_nob >= 0); /* not posted */

                        kiblnd_dma_unmap_single(conn->ibc_cmid->device,
                                                KIBLND_UNMAP_ADDR(rx, rx_msgunmap,
                                                                  rx->rx_msgaddr),
                                                IBLND_MSG_SIZE, DMA_FROM_DEVICE);
                }

                kiblnd_free_pages(conn->ibc_rx_pages);
        }

        if (conn->ibc_rxs != NULL) {
                LIBCFS_FREE(conn->ibc_rxs,
                            IBLND_RX_MSGS * sizeof(kib_rx_t));
        }

        if (conn->ibc_connvars != NULL)
                LIBCFS_FREE(conn->ibc_connvars, sizeof(*conn->ibc_connvars));

        /* See CAVEAT EMPTOR above in kiblnd_create_conn */
        if (conn->ibc_state != IBLND_CONN_INIT) {
                kib_net_t *net = peer->ibp_ni->ni_data;

                kiblnd_peer_decref(peer);
                rdma_destroy_id(cmid);
                atomic_dec(&net->ibn_nconns);
        }

        LIBCFS_FREE(conn, sizeof(*conn));
}

int
kiblnd_close_peer_conns_locked (kib_peer_t *peer, int why)
{
        kib_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry(ctmp, kib_conn_t, ibc_list);

                count++;
                kiblnd_close_conn_locked(conn, why);
        }

        return count;
}

int
kiblnd_close_stale_conns_locked (kib_peer_t *peer, __u64 incarnation)
{
        kib_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry(ctmp, kib_conn_t, ibc_list);

                if (conn->ibc_incarnation == incarnation)
                        continue;

                CDEBUG(D_NET, "Closing stale conn -> %s incarnation:"LPX64"("LPX64")\n",
                       libcfs_nid2str(peer->ibp_nid),
                       conn->ibc_incarnation, incarnation);

                count++;
                kiblnd_close_conn_locked(conn, -ESTALE);
        }

        return count;
}

int
kiblnd_close_matching_conns (lnet_ni_t *ni, lnet_nid_t nid)
{
        kib_peer_t         *peer;
        struct list_head   *ptmp;
        struct list_head   *pnxt;
        int                 lo;
        int                 hi;
        int                 i;
        unsigned long       flags;
        int                 count = 0;

        write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        if (nid != LNET_NID_ANY)
                lo = hi = kiblnd_nid2peerlist(nid) - kiblnd_data.kib_peers;
        else {
                lo = 0;
                hi = kiblnd_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kiblnd_data.kib_peers[i]) {

                        peer = list_entry(ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_connecting > 0 ||
                                 peer->ibp_accepting > 0 ||
                                 !list_empty(&peer->ibp_conns));

                        if (peer->ibp_ni != ni)
                                continue;

                        if (!(nid == LNET_NID_ANY || nid == peer->ibp_nid))
                                continue;

                        count += kiblnd_close_peer_conns_locked(peer, 0);
                }
        }

        write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

        /* wildcards always succeed */
        if (nid == LNET_NID_ANY)
                return 0;

        return (count == 0) ? -ENOENT : 0;
}

int
kiblnd_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg)
{
        struct libcfs_ioctl_data *data = arg;
        int                       rc = -EINVAL;

        switch(cmd) {
        case IOC_LIBCFS_GET_PEER: {
                lnet_nid_t   nid = 0;
                int          count = 0;

                rc = kiblnd_get_peer_info(ni, data->ioc_count,
                                          &nid, &count);
                data->ioc_nid    = nid;
                data->ioc_count  = count;
                break;
        }

        case IOC_LIBCFS_DEL_PEER: {
                rc = kiblnd_del_peer(ni, data->ioc_nid);
                break;
        }
        case IOC_LIBCFS_GET_CONN: {
                kib_conn_t *conn = kiblnd_get_conn_by_idx(ni, data->ioc_count);

                if (conn == NULL) {
                        rc = -ENOENT;
                } else {
                        // kiblnd_debug_conn(conn);
                        rc = 0;
                        data->ioc_nid = conn->ibc_peer->ibp_nid;
                        kiblnd_conn_decref(conn);
                }
                break;
        }
        case IOC_LIBCFS_CLOSE_CONNECTION: {
                rc = kiblnd_close_matching_conns(ni, data->ioc_nid);
                break;
        }

        default:
                break;
        }

        return rc;
}

void
kiblnd_free_pages (kib_pages_t *p)
{
        int         npages = p->ibp_npages;
        int         i;

        for (i = 0; i < npages; i++)
                if (p->ibp_pages[i] != NULL)
                        __free_page(p->ibp_pages[i]);

        LIBCFS_FREE (p, offsetof(kib_pages_t, ibp_pages[npages]));
}

int
kiblnd_alloc_pages (kib_pages_t **pp, int npages)
{
        kib_pages_t   *p;
        int            i;

        LIBCFS_ALLOC(p, offsetof(kib_pages_t, ibp_pages[npages]));
        if (p == NULL) {
                CERROR("Can't allocate descriptor for %d pages\n", npages);
                return -ENOMEM;
        }

        memset(p, 0, offsetof(kib_pages_t, ibp_pages[npages]));
        p->ibp_npages = npages;

        for (i = 0; i < npages; i++) {
                p->ibp_pages[i] = alloc_page(GFP_KERNEL);
                if (p->ibp_pages[i] == NULL) {
                        CERROR("Can't allocate page %d of %d\n", i, npages);
                        kiblnd_free_pages(p);
                        return -ENOMEM;
                }
        }

        *pp = p;
        return 0;
}

void
kiblnd_free_tx_descs (lnet_ni_t *ni)
{
        int        i;
        kib_net_t *net = ni->ni_data;

        LASSERT (net != NULL);

        if (net->ibn_tx_descs != NULL) {
                for (i = 0; i < IBLND_TX_MSGS(); i++) {
                        kib_tx_t *tx = &net->ibn_tx_descs[i];

#if IBLND_MAP_ON_DEMAND
                        if (tx->tx_pages != NULL)
                                LIBCFS_FREE(tx->tx_pages, LNET_MAX_IOV *
                                            sizeof(*tx->tx_pages));
#else
                        if (tx->tx_wrq != NULL)
                                LIBCFS_FREE(tx->tx_wrq, 
                                            (1 + IBLND_MAX_RDMA_FRAGS) * 
                                            sizeof(*tx->tx_wrq));

                        if (tx->tx_sge != NULL)
                                LIBCFS_FREE(tx->tx_sge, 
                                            (1 + IBLND_MAX_RDMA_FRAGS) * 
                                            sizeof(*tx->tx_sge));

                        if (tx->tx_rd != NULL)
                                LIBCFS_FREE(tx->tx_rd, 
                                            offsetof(kib_rdma_desc_t, 
                                               rd_frags[IBLND_MAX_RDMA_FRAGS]));

                        if (tx->tx_frags != NULL)
                                LIBCFS_FREE(tx->tx_frags, 
                                            IBLND_MAX_RDMA_FRAGS *
                                            sizeof(*tx->tx_frags));
#endif
                }

                LIBCFS_FREE(net->ibn_tx_descs,
                            IBLND_TX_MSGS() * sizeof(kib_tx_t));
        }

        if (net->ibn_tx_pages != NULL)
                kiblnd_free_pages(net->ibn_tx_pages);
}

int
kiblnd_alloc_tx_descs (lnet_ni_t *ni)
{
        int        i;
        int        rc;
        kib_net_t *net = ni->ni_data;

        LASSERT (net != NULL);

        rc = kiblnd_alloc_pages(&net->ibn_tx_pages, IBLND_TX_MSG_PAGES());

        if (rc != 0) {
                CERROR("Can't allocate tx pages\n");
                return rc;
        }

        LIBCFS_ALLOC (net->ibn_tx_descs,
                      IBLND_TX_MSGS() * sizeof(kib_tx_t));
        if (net->ibn_tx_descs == NULL) {
                CERROR("Can't allocate %d tx descriptors\n", IBLND_TX_MSGS());
                return -ENOMEM;
        }

        memset(net->ibn_tx_descs, 0,
               IBLND_TX_MSGS() * sizeof(kib_tx_t));

        for (i = 0; i < IBLND_TX_MSGS(); i++) {
                kib_tx_t *tx = &net->ibn_tx_descs[i];

#if IBLND_MAP_ON_DEMAND
                LIBCFS_ALLOC(tx->tx_pages, LNET_MAX_IOV *
                             sizeof(*tx->tx_pages));
                if (tx->tx_pages == NULL) {
                        CERROR("Can't allocate phys page vector[%d]\n",
                               LNET_MAX_IOV);
                        return -ENOMEM;
                }
#else
                LIBCFS_ALLOC(tx->tx_wrq,
                             (1 + IBLND_MAX_RDMA_FRAGS) *
                             sizeof(*tx->tx_wrq));
                if (tx->tx_wrq == NULL)
                        return -ENOMEM;

                LIBCFS_ALLOC(tx->tx_sge,
                             (1 + IBLND_MAX_RDMA_FRAGS) *
                             sizeof(*tx->tx_sge));
                if (tx->tx_sge == NULL)
                        return -ENOMEM;

                LIBCFS_ALLOC(tx->tx_rd,
                             offsetof(kib_rdma_desc_t,
                                      rd_frags[IBLND_MAX_RDMA_FRAGS]));
                if (tx->tx_rd == NULL)
                        return -ENOMEM;

                LIBCFS_ALLOC(tx->tx_frags,
                             IBLND_MAX_RDMA_FRAGS * 
                             sizeof(*tx->tx_frags));
                if (tx->tx_frags == NULL)
                        return -ENOMEM;
#endif
        }

        return 0;
}

void
kiblnd_unmap_tx_descs (lnet_ni_t *ni)
{
        int             i;
        kib_tx_t       *tx;
        kib_net_t      *net = ni->ni_data;

        LASSERT (net != NULL);

        for (i = 0; i < IBLND_TX_MSGS(); i++) {
                tx = &net->ibn_tx_descs[i];

                kiblnd_dma_unmap_single(net->ibn_dev->ibd_cmid->device,
                                        KIBLND_UNMAP_ADDR(tx, tx_msgunmap,
                                                          tx->tx_msgaddr),
                                        IBLND_MSG_SIZE, DMA_TO_DEVICE);
        }
}

void
kiblnd_map_tx_descs (lnet_ni_t *ni)
{
        int             ipage = 0;
        int             page_offset = 0;
        int             i;
        struct page    *page;
        kib_tx_t       *tx;
        kib_net_t      *net = ni->ni_data;

        LASSERT (net != NULL);

        /* pre-mapped messages are not bigger than 1 page */
        CLASSERT (IBLND_MSG_SIZE <= PAGE_SIZE);

        /* No fancy arithmetic when we do the buffer calculations */
        CLASSERT (PAGE_SIZE % IBLND_MSG_SIZE == 0);

        for (i = 0; i < IBLND_TX_MSGS(); i++) {
                page = net->ibn_tx_pages->ibp_pages[ipage];
                tx = &net->ibn_tx_descs[i];

                tx->tx_msg = (kib_msg_t *)(((char *)page_address(page)) +
                                           page_offset);

                tx->tx_msgaddr = kiblnd_dma_map_single(
                        net->ibn_dev->ibd_cmid->device,
                        tx->tx_msg, IBLND_MSG_SIZE, DMA_TO_DEVICE);
                KIBLND_UNMAP_ADDR_SET(tx, tx_msgunmap, tx->tx_msgaddr);

                list_add(&tx->tx_list, &net->ibn_idle_txs);

                page_offset += IBLND_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= IBLND_TX_MSG_PAGES());
                }
        }
}

void
kiblnd_base_shutdown (void)
{
        int i;

        LASSERT (list_empty(&kiblnd_data.kib_devs));

        CDEBUG(D_MALLOC, "before LND base cleanup: kmem %d\n",
               atomic_read(&libcfs_kmemory));

        switch (kiblnd_data.kib_init) {
        default:
                LBUG();

        case IBLND_INIT_ALL:
        case IBLND_INIT_DATA:
                LASSERT (kiblnd_data.kib_peers != NULL);
                for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {
                        LASSERT (list_empty(&kiblnd_data.kib_peers[i]));
                }
                LASSERT (list_empty(&kiblnd_data.kib_connd_zombies));
                LASSERT (list_empty(&kiblnd_data.kib_connd_conns));

                /* flag threads to terminate; wake and wait for them to die */
                kiblnd_data.kib_shutdown = 1;
                wake_up_all(&kiblnd_data.kib_sched_waitq);
                wake_up_all(&kiblnd_data.kib_connd_waitq);

                i = 2;
                while (atomic_read(&kiblnd_data.kib_nthreads) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "Waiting for %d threads to terminate\n",
                               atomic_read(&kiblnd_data.kib_nthreads));
                        cfs_pause(cfs_time_seconds(1));
                }

                /* fall through */

        case IBLND_INIT_NOTHING:
                break;
        }

        if (kiblnd_data.kib_peers != NULL)
                LIBCFS_FREE(kiblnd_data.kib_peers,
                            sizeof(struct list_head) *
                            kiblnd_data.kib_peer_hash_size);

        CDEBUG(D_MALLOC, "after LND base cleanup: kmem %d\n",
               atomic_read(&libcfs_kmemory));

        kiblnd_data.kib_init = IBLND_INIT_NOTHING;
        PORTAL_MODULE_UNUSE;
}

void
kiblnd_shutdown (lnet_ni_t *ni)
{
        kib_net_t        *net = ni->ni_data;
        rwlock_t         *g_lock = &kiblnd_data.kib_global_lock;
        int               i;
        unsigned long     flags;

        LASSERT(kiblnd_data.kib_init == IBLND_INIT_ALL);

        if (net == NULL)
                goto out;

        CDEBUG(D_MALLOC, "before LND net cleanup: kmem %d\n",
               atomic_read(&libcfs_kmemory));

        write_lock_irqsave(g_lock, flags);
        net->ibn_shutdown = 1;
        write_unlock_irqrestore(g_lock, flags);

        switch (net->ibn_init) {
        default:
                LBUG();

        case IBLND_INIT_ALL:
                /* nuke all existing peers within this net */
                kiblnd_del_peer(ni, LNET_NID_ANY);

                /* Wait for all peer state to clean up */
                i = 2;
                while (atomic_read(&net->ibn_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* 2**n? */
                               "%s: waiting for %d peers to disconnect\n",
                               libcfs_nid2str(ni->ni_nid),
                               atomic_read(&net->ibn_npeers));
                        cfs_pause(cfs_time_seconds(1));
                }

                kiblnd_unmap_tx_descs(ni);

                LASSERT (net->ibn_dev->ibd_nnets > 0);
                net->ibn_dev->ibd_nnets--;

                /* fall through */

        case IBLND_INIT_NOTHING:
                LASSERT (atomic_read(&net->ibn_nconns) == 0);

#if IBLND_MAP_ON_DEMAND
                if (net->ibn_fmrpool != NULL)
                        ib_destroy_fmr_pool(net->ibn_fmrpool);
#endif
                if (net->ibn_dev != NULL &&
                    net->ibn_dev->ibd_nnets == 0)
                        kiblnd_destroy_dev(net->ibn_dev);

                break;
        }

        kiblnd_free_tx_descs(ni);

        CDEBUG(D_MALLOC, "after LND net cleanup: kmem %d\n",
               atomic_read(&libcfs_kmemory));

        net->ibn_init = IBLND_INIT_NOTHING;
        ni->ni_data = NULL;
        
        LIBCFS_FREE(net, sizeof(*net));

out:
        if (list_empty(&kiblnd_data.kib_devs))
                kiblnd_base_shutdown();
        return;
}

int
kiblnd_base_startup (void)
{
        int               rc;
        int               i;

        LASSERT (kiblnd_data.kib_init == IBLND_INIT_NOTHING);

        if (*kiblnd_tunables.kib_credits > *kiblnd_tunables.kib_ntx) {
                CERROR("Can't set credits(%d) > ntx(%d)\n",
                       *kiblnd_tunables.kib_credits,
                       *kiblnd_tunables.kib_ntx);
                return -EINVAL;
        }

        PORTAL_MODULE_USE;
        memset(&kiblnd_data, 0, sizeof(kiblnd_data)); /* zero pointers, flags etc */

        rwlock_init(&kiblnd_data.kib_global_lock);

        INIT_LIST_HEAD(&kiblnd_data.kib_devs);

        kiblnd_data.kib_peer_hash_size = IBLND_PEER_HASH_SIZE;
        LIBCFS_ALLOC(kiblnd_data.kib_peers,
                     sizeof(struct list_head) * kiblnd_data.kib_peer_hash_size);
        if (kiblnd_data.kib_peers == NULL) {
                goto failed;
        }
        for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++)
                INIT_LIST_HEAD(&kiblnd_data.kib_peers[i]);

        spin_lock_init(&kiblnd_data.kib_connd_lock);
        INIT_LIST_HEAD(&kiblnd_data.kib_connd_conns);
        INIT_LIST_HEAD(&kiblnd_data.kib_connd_zombies);
        init_waitqueue_head(&kiblnd_data.kib_connd_waitq);

        spin_lock_init(&kiblnd_data.kib_sched_lock);
        INIT_LIST_HEAD(&kiblnd_data.kib_sched_conns);
        init_waitqueue_head(&kiblnd_data.kib_sched_waitq);

        kiblnd_data.kib_error_qpa.qp_state = IB_QPS_ERR;

        /* lists/ptrs/locks initialised */
        kiblnd_data.kib_init = IBLND_INIT_DATA;
        /*****************************************************/

        for (i = 0; i < IBLND_N_SCHED; i++) {
                rc = kiblnd_thread_start(kiblnd_scheduler, (void *)((long)i));
                if (rc != 0) {
                        CERROR("Can't spawn o2iblnd scheduler[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        rc = kiblnd_thread_start(kiblnd_connd, NULL);
        if (rc != 0) {
                CERROR("Can't spawn o2iblnd connd: %d\n", rc);
                goto failed;
        }

        /* flag everything initialised */
        kiblnd_data.kib_init = IBLND_INIT_ALL;
        /*****************************************************/

        return 0;

 failed:
        kiblnd_base_shutdown();
        return -ENETDOWN;
}

int
kiblnd_startup (lnet_ni_t *ni)
{
        char                     *ifname;
        kib_net_t                *net;
        kib_dev_t                *ibdev;
        struct list_head         *tmp;
        struct timeval            tv;
        int                       rc;

        LASSERT (ni->ni_lnd == &the_kiblnd);

        if (kiblnd_data.kib_init == IBLND_INIT_NOTHING) {
                rc = kiblnd_base_startup();
                if (rc != 0)
                        return rc;
        }

        LIBCFS_ALLOC(net, sizeof(*net));
        ni->ni_data = net;
        if (net == NULL)
                goto failed;

        memset(net, 0, sizeof(*net));

        do_gettimeofday(&tv);
        net->ibn_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

        ni->ni_maxtxcredits = *kiblnd_tunables.kib_credits;
        ni->ni_peertxcredits = *kiblnd_tunables.kib_peercredits;

        spin_lock_init(&net->ibn_tx_lock);
        INIT_LIST_HEAD(&net->ibn_idle_txs);

        rc = kiblnd_alloc_tx_descs(ni);
        if (rc != 0) {
                CERROR("Can't allocate tx descs\n");
                goto failed;
        }

        if (ni->ni_interfaces[0] != NULL) {
                /* Use the IPoIB interface specified in 'networks=' */

                CLASSERT (LNET_MAX_INTERFACES > 1);
                if (ni->ni_interfaces[1] != NULL) {
                        CERROR("Multiple interfaces not supported\n");
                        goto failed;
                }

                ifname = ni->ni_interfaces[0];
        } else {
                ifname = *kiblnd_tunables.kib_default_ipif;
        }

        if (strlen(ifname) >= sizeof(ibdev->ibd_ifname)) {
                CERROR("IPoIB interface name too long: %s\n", ifname);
                goto failed;
        }

        ibdev = NULL;
        list_for_each (tmp, &kiblnd_data.kib_devs) {
                ibdev = list_entry(tmp, kib_dev_t, ibd_list);

                if (!strcmp(&ibdev->ibd_ifname[0], ifname))
                        break;

                ibdev = NULL;
        }

        if (ibdev == NULL) {
                __u32                     ip;
                __u32                     netmask;
                int                       up;
                struct rdma_cm_id        *id;
                struct ib_pd             *pd;
                struct ib_mr             *mr;
                struct sockaddr_in	  addr;

                rc = libcfs_ipif_query(ifname, &up, &ip, &netmask);
                if (rc != 0) {
                        CERROR("Can't query IPoIB interface %s: %d\n",
                               ifname, rc);
                        goto failed;
                }

                if (!up) {
                        CERROR("Can't query IPoIB interface %s: it's down\n",
                               ifname);
                        goto failed;
                }

                LIBCFS_ALLOC(ibdev, sizeof(*ibdev));
                if (ibdev == NULL)
                        goto failed;

                memset(ibdev, 0, sizeof(*ibdev));

                INIT_LIST_HEAD(&ibdev->ibd_list); /* not yet in kib_devs */
                ibdev->ibd_ifip = ip;
                strcpy(&ibdev->ibd_ifname[0], ifname);

                id = rdma_create_id(kiblnd_cm_callback, ibdev, RDMA_PS_TCP);
                if (!IS_ERR(id)) {
                        ibdev->ibd_cmid = id;
                } else {
                        CERROR("Can't create listen ID: %ld\n", PTR_ERR(id));
                        goto failed;
                }

                memset(&addr, 0, sizeof(addr));
                addr.sin_family      = AF_INET;
                addr.sin_port        = htons(*kiblnd_tunables.kib_service);
                addr.sin_addr.s_addr = htonl(ip);

                rc = rdma_bind_addr(id, (struct sockaddr *)&addr);
                if (rc != 0) {
                        CERROR("Can't bind to %s: %d\n", ifname, rc);
                        goto failed;
                }

                /* Binding should have assigned me an IB device */
                LASSERT (id->device != NULL);

                pd = ib_alloc_pd(id->device);
                if (!IS_ERR(pd)) {
                        ibdev->ibd_pd = pd;
                } else {
                        CERROR("Can't allocate PD: %ld\n", PTR_ERR(pd));
                        goto failed;
                }

#if IBLND_MAP_ON_DEMAND
                /* MR for sends and receives */
                mr = ib_get_dma_mr(pd, IB_ACCESS_LOCAL_WRITE);
#else
                /* MR for sends, recieves _and_ RDMA...........v */
                mr = ib_get_dma_mr(pd, IB_ACCESS_LOCAL_WRITE |
                                       IB_ACCESS_REMOTE_WRITE);
#endif
                if (!IS_ERR(mr)) {
                        ibdev->ibd_mr = mr;
                } else {
                        CERROR("Can't get MR: %ld\n", PTR_ERR(mr));
                        goto failed;
                }

                rc = rdma_listen(id, 0);
                if (rc != 0) {
                        CERROR("Can't start listener: %d\n", rc);
                        goto failed;
                }

                list_add_tail(&ibdev->ibd_list, 
                              &kiblnd_data.kib_devs);
        }

        ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), ibdev->ibd_ifip);
        net->ibn_dev = ibdev;

#if IBLND_MAP_ON_DEMAND
        /* FMR pool for RDMA */
        {
                struct ib_fmr_pool      *fmrpool;
                struct ib_fmr_pool_param param = {
                        .max_pages_per_fmr = LNET_MAX_PAYLOAD/PAGE_SIZE,
                        .page_shift        = PAGE_SHIFT,
                        .access            = (IB_ACCESS_LOCAL_WRITE |
                                              IB_ACCESS_REMOTE_WRITE),
                        .pool_size         = *kiblnd_tunables.kib_fmr_pool_size,
                        .dirty_watermark   = *kiblnd_tunables.kib_fmr_flush_trigger,
                        .flush_function    = NULL,
                        .flush_arg         = NULL,
                        .cache             = *kiblnd_tunables.kib_fmr_cache};

                if (*kiblnd_tunables.kib_fmr_pool_size < 
                    *kiblnd_tunables.kib_ntx) {
                        CERROR("Can't set fmr pool size (%d) < ntx(%d)\n",
                               *kiblnd_tunables.kib_fmr_pool_size,
                               *kiblnd_tunables.kib_ntx);
                        goto failed;
                }

                fmrpool = ib_create_fmr_pool(ibdev->ibd_pd, &param);
                if (!IS_ERR(fmrpool)) {
                        net->ibn_fmrpool = fmrpool;
                } else {
                        CERROR("Can't create FMR pool: %ld\n", 
                               PTR_ERR(fmrpool));
                        goto failed;
                }
        }
#endif

        kiblnd_map_tx_descs(ni);

        ibdev->ibd_nnets++;
        net->ibn_init = IBLND_INIT_ALL;

        return 0;

failed:
        kiblnd_shutdown(ni);

        CDEBUG(D_NET, "kiblnd_startup failed\n");
        return -ENETDOWN;
}

void __exit
kiblnd_module_fini (void)
{
        lnet_unregister_lnd(&the_kiblnd);
        kiblnd_tunables_fini();
}

int __init
kiblnd_module_init (void)
{
        int    rc;

        CLASSERT (sizeof(kib_msg_t) <= IBLND_MSG_SIZE);
#if !IBLND_MAP_ON_DEMAND
        CLASSERT (offsetof(kib_msg_t, ibm_u.get.ibgm_rd.rd_frags[IBLND_MAX_RDMA_FRAGS])
                  <= IBLND_MSG_SIZE);
        CLASSERT (offsetof(kib_msg_t, ibm_u.putack.ibpam_rd.rd_frags[IBLND_MAX_RDMA_FRAGS])
                  <= IBLND_MSG_SIZE);
#endif
        rc = kiblnd_tunables_init();
        if (rc != 0)
                return rc;

        lnet_register_lnd(&the_kiblnd);

        return 0;
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Kernel OpenIB gen2 LND v1.00");
MODULE_LICENSE("GPL");

module_init(kiblnd_module_init);
module_exit(kiblnd_module_fini);
