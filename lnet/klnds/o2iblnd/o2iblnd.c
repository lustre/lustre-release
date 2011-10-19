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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
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

lnd_t the_o2iblnd = {
        .lnd_type       = O2IBLND,
        .lnd_startup    = kiblnd_startup,
        .lnd_shutdown   = kiblnd_shutdown,
        .lnd_ctl        = kiblnd_ctl,
        .lnd_query      = kiblnd_query,
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

static char *
kiblnd_msgtype2str(int type)
{
        switch (type) {
        case IBLND_MSG_CONNREQ:
                return "CONNREQ";

        case IBLND_MSG_CONNACK:
                return "CONNACK";

        case IBLND_MSG_NOOP:
                return "NOOP";

        case IBLND_MSG_IMMEDIATE:
                return "IMMEDIATE";

        case IBLND_MSG_PUT_REQ:
                return "PUT_REQ";

        case IBLND_MSG_PUT_NAK:
                return "PUT_NAK";

        case IBLND_MSG_PUT_ACK:
                return "PUT_ACK";

        case IBLND_MSG_PUT_DONE:
                return "PUT_DONE";

        case IBLND_MSG_GET_REQ:
                return "GET_REQ";

        case IBLND_MSG_GET_DONE:
                return "GET_DONE";

        default:
                return "???";
        }
}

static int
kiblnd_msgtype2size(int type)
{
        const int hdr_size = offsetof(kib_msg_t, ibm_u);

        switch (type) {
        case IBLND_MSG_CONNREQ:
        case IBLND_MSG_CONNACK:
                return hdr_size + sizeof(kib_connparams_t);

        case IBLND_MSG_NOOP:
                return hdr_size;

        case IBLND_MSG_IMMEDIATE:
                return offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[0]);

        case IBLND_MSG_PUT_REQ:
                return hdr_size + sizeof(kib_putreq_msg_t);

        case IBLND_MSG_PUT_ACK:
                return hdr_size + sizeof(kib_putack_msg_t);

        case IBLND_MSG_GET_REQ:
                return hdr_size + sizeof(kib_get_msg_t);

        case IBLND_MSG_PUT_NAK:
        case IBLND_MSG_PUT_DONE:
        case IBLND_MSG_GET_DONE:
                return hdr_size + sizeof(kib_completion_msg_t);
        default:
                return -1;
        }
}

static int
kiblnd_unpack_rd(kib_msg_t *msg, int flip)
{
        kib_rdma_desc_t   *rd;
        int                nob;
        int                n;
        int                i;

        LASSERT (msg->ibm_type == IBLND_MSG_GET_REQ ||
                 msg->ibm_type == IBLND_MSG_PUT_ACK);

        rd = msg->ibm_type == IBLND_MSG_GET_REQ ?
                              &msg->ibm_u.get.ibgm_rd :
                              &msg->ibm_u.putack.ibpam_rd;

        if (flip) {
                __swab32s(&rd->rd_key);
                __swab32s(&rd->rd_nfrags);
        }

        n = rd->rd_nfrags;

        if (n <= 0 || n > IBLND_MAX_RDMA_FRAGS) {
                CERROR("Bad nfrags: %d, should be 0 < n <= %d\n",
                       n, IBLND_MAX_RDMA_FRAGS);
                return 1;
        }

        nob = offsetof (kib_msg_t, ibm_u) +
              kiblnd_rd_msg_size(rd, msg->ibm_type, n);

        if (msg->ibm_nob < nob) {
                CERROR("Short %s: %d(%d)\n",
                       kiblnd_msgtype2str(msg->ibm_type), msg->ibm_nob, nob);
                return 1;
        }

        if (!flip)
                return 0;

        for (i = 0; i < n; i++) {
                __swab32s(&rd->rd_frags[i].rf_nob);
                __swab64s(&rd->rd_frags[i].rf_addr);
        }

        return 0;
}

void
kiblnd_pack_msg (lnet_ni_t *ni, kib_msg_t *msg, int version,
                 int credits, lnet_nid_t dstnid, __u64 dststamp)
{
        kib_net_t *net = ni->ni_data;

        /* CAVEAT EMPTOR! all message fields not set here should have been
         * initialised previously. */
        msg->ibm_magic    = IBLND_MSG_MAGIC;
        msg->ibm_version  = version;
        /*   ibm_type */
        msg->ibm_credits  = credits;
        /*   ibm_nob */
        msg->ibm_cksum    = 0;
        msg->ibm_srcnid   = ni->ni_nid;
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
        __u16     version;
        int       msg_nob;
        int       flip;

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

        version = flip ? __swab16(msg->ibm_version) : msg->ibm_version;
        if (version != IBLND_MSG_VERSION &&
            version != IBLND_MSG_VERSION_1) {
                CERROR("Bad version: %x\n", version);
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
                msg->ibm_version = version;
                CLASSERT (sizeof(msg->ibm_type) == 1);
                CLASSERT (sizeof(msg->ibm_credits) == 1);
                msg->ibm_nob     = msg_nob;
                __swab64s(&msg->ibm_srcnid);
                __swab64s(&msg->ibm_srcstamp);
                __swab64s(&msg->ibm_dstnid);
                __swab64s(&msg->ibm_dststamp);
        }

        if (msg->ibm_srcnid == LNET_NID_ANY) {
                CERROR("Bad src nid: %s\n", libcfs_nid2str(msg->ibm_srcnid));
                return -EPROTO;
        }

        if (msg_nob < kiblnd_msgtype2size(msg->ibm_type)) {
                CERROR("Short %s: %d(%d)\n", kiblnd_msgtype2str(msg->ibm_type),
                       msg_nob, kiblnd_msgtype2size(msg->ibm_type));
                return -EPROTO;
        }

        switch (msg->ibm_type) {
        default:
                CERROR("Unknown message type %x\n", msg->ibm_type);
                return -EPROTO;

        case IBLND_MSG_NOOP:
        case IBLND_MSG_IMMEDIATE:
        case IBLND_MSG_PUT_REQ:
                break;

        case IBLND_MSG_PUT_ACK:
        case IBLND_MSG_GET_REQ:
                if (kiblnd_unpack_rd(msg, flip))
                        return -EPROTO;
                break;

        case IBLND_MSG_PUT_NAK:
        case IBLND_MSG_PUT_DONE:
        case IBLND_MSG_GET_DONE:
                if (flip)
                        __swab32s(&msg->ibm_u.completion.ibcm_status);
                break;

        case IBLND_MSG_CONNREQ:
        case IBLND_MSG_CONNACK:
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
        peer->ibp_last_alive = 0;
        cfs_atomic_set(&peer->ibp_refcount, 1);  /* 1 ref for caller */

        CFS_INIT_LIST_HEAD(&peer->ibp_list);     /* not in the peer table yet */
        CFS_INIT_LIST_HEAD(&peer->ibp_conns);
        CFS_INIT_LIST_HEAD(&peer->ibp_tx_queue);

        cfs_write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        /* always called with a ref on ni, which prevents ni being shutdown */
        LASSERT (net->ibn_shutdown == 0);

        /* npeers only grows with the global lock held */
        cfs_atomic_inc(&net->ibn_npeers);

        cfs_write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

        *peerp = peer;
        return 0;
}

void
kiblnd_destroy_peer (kib_peer_t *peer)
{
        kib_net_t *net = peer->ibp_ni->ni_data;

        LASSERT (net != NULL);
        LASSERT (cfs_atomic_read(&peer->ibp_refcount) == 0);
        LASSERT (!kiblnd_peer_active(peer));
        LASSERT (peer->ibp_connecting == 0);
        LASSERT (peer->ibp_accepting == 0);
        LASSERT (cfs_list_empty(&peer->ibp_conns));
        LASSERT (cfs_list_empty(&peer->ibp_tx_queue));

        LIBCFS_FREE(peer, sizeof(*peer));

        /* NB a peer's connections keep a reference on their peer until
         * they are destroyed, so we can be assured that _all_ state to do
         * with this peer has been cleaned up when its refcount drops to
         * zero. */
        cfs_atomic_dec(&net->ibn_npeers);
}

kib_peer_t *
kiblnd_find_peer_locked (lnet_nid_t nid)
{
        /* the caller is responsible for accounting the additional reference
         * that this creates */
        cfs_list_t       *peer_list = kiblnd_nid2peerlist(nid);
        cfs_list_t       *tmp;
        kib_peer_t       *peer;

        cfs_list_for_each (tmp, peer_list) {

                peer = cfs_list_entry(tmp, kib_peer_t, ibp_list);

                LASSERT (peer->ibp_connecting > 0 || /* creating conns */
                         peer->ibp_accepting > 0 ||
                         !cfs_list_empty(&peer->ibp_conns));  /* active conn */

                if (peer->ibp_nid != nid)
                        continue;

                CDEBUG(D_NET, "got peer [%p] -> %s (%d) version: %x\n",
                       peer, libcfs_nid2str(nid),
                       cfs_atomic_read(&peer->ibp_refcount),
                       peer->ibp_version);
                return peer;
        }
        return NULL;
}

void
kiblnd_unlink_peer_locked (kib_peer_t *peer)
{
        LASSERT (cfs_list_empty(&peer->ibp_conns));

        LASSERT (kiblnd_peer_active(peer));
        cfs_list_del_init(&peer->ibp_list);
        /* lose peerlist's ref */
        kiblnd_peer_decref(peer);
}

int
kiblnd_get_peer_info (lnet_ni_t *ni, int index, 
                      lnet_nid_t *nidp, int *count)
{
        kib_peer_t            *peer;
        cfs_list_t            *ptmp;
        int                    i;
        unsigned long          flags;

        cfs_read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {

                cfs_list_for_each (ptmp, &kiblnd_data.kib_peers[i]) {

                        peer = cfs_list_entry(ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_connecting > 0 ||
                                 peer->ibp_accepting > 0 ||
                                 !cfs_list_empty(&peer->ibp_conns));

                        if (peer->ibp_ni != ni)
                                continue;

                        if (index-- > 0)
                                continue;

                        *nidp = peer->ibp_nid;
                        *count = cfs_atomic_read(&peer->ibp_refcount);

                        cfs_read_unlock_irqrestore(&kiblnd_data.kib_global_lock,
                                                   flags);
                        return 0;
                }
        }

        cfs_read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
        return -ENOENT;
}

void
kiblnd_del_peer_locked (kib_peer_t *peer)
{
        cfs_list_t           *ctmp;
        cfs_list_t           *cnxt;
        kib_conn_t           *conn;

        if (cfs_list_empty(&peer->ibp_conns)) {
                kiblnd_unlink_peer_locked(peer);
        } else {
                cfs_list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                        conn = cfs_list_entry(ctmp, kib_conn_t, ibc_list);

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
        CFS_LIST_HEAD         (zombies);
        cfs_list_t            *ptmp;
        cfs_list_t            *pnxt;
        kib_peer_t            *peer;
        int                    lo;
        int                    hi;
        int                    i;
        unsigned long          flags;
        int                    rc = -ENOENT;

        cfs_write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        if (nid != LNET_NID_ANY) {
                lo = hi = kiblnd_nid2peerlist(nid) - kiblnd_data.kib_peers;
        } else {
                lo = 0;
                hi = kiblnd_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                cfs_list_for_each_safe (ptmp, pnxt, &kiblnd_data.kib_peers[i]) {
                        peer = cfs_list_entry(ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_connecting > 0 ||
                                 peer->ibp_accepting > 0 ||
                                 !cfs_list_empty(&peer->ibp_conns));

                        if (peer->ibp_ni != ni)
                                continue;

                        if (!(nid == LNET_NID_ANY || peer->ibp_nid == nid))
                                continue;

                        if (!cfs_list_empty(&peer->ibp_tx_queue)) {
                                LASSERT (cfs_list_empty(&peer->ibp_conns));

                                cfs_list_splice_init(&peer->ibp_tx_queue,
                                                     &zombies);
                        }

                        kiblnd_del_peer_locked(peer);
                        rc = 0;         /* matched something */
                }
        }

        cfs_write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

        kiblnd_txlist_done(ni, &zombies, -EIO);

        return rc;
}

kib_conn_t *
kiblnd_get_conn_by_idx (lnet_ni_t *ni, int index)
{
        kib_peer_t            *peer;
        cfs_list_t            *ptmp;
        kib_conn_t            *conn;
        cfs_list_t            *ctmp;
        int                    i;
        unsigned long          flags;

        cfs_read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {
                cfs_list_for_each (ptmp, &kiblnd_data.kib_peers[i]) {

                        peer = cfs_list_entry(ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_connecting > 0 ||
                                 peer->ibp_accepting > 0 ||
                                 !cfs_list_empty(&peer->ibp_conns));

                        if (peer->ibp_ni != ni)
                                continue;

                        cfs_list_for_each (ctmp, &peer->ibp_conns) {
                                if (index-- > 0)
                                        continue;

                                conn = cfs_list_entry(ctmp, kib_conn_t,
                                                      ibc_list);
                                kiblnd_conn_addref(conn);
                                cfs_read_unlock_irqrestore(&kiblnd_data.kib_global_lock,
                                                           flags);
                                return conn;
                        }
                }
        }

        cfs_read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
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
        cfs_list_t           *tmp;
        int                   i;

        cfs_spin_lock(&conn->ibc_lock);

        CDEBUG(D_CONSOLE, "conn[%d] %p [version %x] -> %s: \n",
               cfs_atomic_read(&conn->ibc_refcount), conn,
               conn->ibc_version, libcfs_nid2str(conn->ibc_peer->ibp_nid));
        CDEBUG(D_CONSOLE, "   state %d nposted %d/%d cred %d o_cred %d r_cred %d\n",
               conn->ibc_state, conn->ibc_noops_posted,
               conn->ibc_nsends_posted, conn->ibc_credits,
               conn->ibc_outstanding_credits, conn->ibc_reserved_credits);
        CDEBUG(D_CONSOLE, "   comms_err %d\n", conn->ibc_comms_error);

        CDEBUG(D_CONSOLE, "   early_rxs:\n");
        cfs_list_for_each(tmp, &conn->ibc_early_rxs)
                kiblnd_debug_rx(cfs_list_entry(tmp, kib_rx_t, rx_list));

        CDEBUG(D_CONSOLE, "   tx_noops:\n");
        cfs_list_for_each(tmp, &conn->ibc_tx_noops)
                kiblnd_debug_tx(cfs_list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   tx_queue_nocred:\n");
        cfs_list_for_each(tmp, &conn->ibc_tx_queue_nocred)
                kiblnd_debug_tx(cfs_list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   tx_queue_rsrvd:\n");
        cfs_list_for_each(tmp, &conn->ibc_tx_queue_rsrvd)
                kiblnd_debug_tx(cfs_list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   tx_queue:\n");
        cfs_list_for_each(tmp, &conn->ibc_tx_queue)
                kiblnd_debug_tx(cfs_list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   active_txs:\n");
        cfs_list_for_each(tmp, &conn->ibc_active_txs)
                kiblnd_debug_tx(cfs_list_entry(tmp, kib_tx_t, tx_list));

        CDEBUG(D_CONSOLE, "   rxs:\n");
        for (i = 0; i < IBLND_RX_MSGS(conn->ibc_version); i++)
                kiblnd_debug_rx(&conn->ibc_rxs[i]);

        cfs_spin_unlock(&conn->ibc_lock);
}

int
kiblnd_translate_mtu(int value)
{
        switch (value) {
        default:
                return -1;
        case 0:
                return 0;
        case 256:
                return IB_MTU_256;
        case 512:
                return IB_MTU_512;
        case 1024:
                return IB_MTU_1024;
        case 2048:
                return IB_MTU_2048;
        case 4096:
                return IB_MTU_4096;
        }
}

static void
kiblnd_setup_mtu_locked(struct rdma_cm_id *cmid)
{
        int           mtu;

        /* XXX There is no path record for iWARP, set by netdev->change_mtu? */
        if (cmid->route.path_rec == NULL)
                return;

        mtu = kiblnd_translate_mtu(*kiblnd_tunables.kib_ib_mtu);
        LASSERT (mtu >= 0);
        if (mtu != 0)
                cmid->route.path_rec->mtu = mtu;
}

kib_conn_t *
kiblnd_create_conn(kib_peer_t *peer, struct rdma_cm_id *cmid,
                   int state, int version)
{
        /* CAVEAT EMPTOR:
         * If the new conn is created successfully it takes over the caller's
         * ref on 'peer'.  It also "owns" 'cmid' and destroys it when it itself
         * is destroyed.  On failure, the caller's ref on 'peer' remains and
         * she must dispose of 'cmid'.  (Actually I'd block forever if I tried
         * to destroy 'cmid' here since I'm called from the CM which still has
         * its ref on 'cmid'). */
        cfs_rwlock_t           *glock = &kiblnd_data.kib_global_lock;
        kib_net_t              *net = peer->ibp_ni->ni_data;
        kib_dev_t              *dev = net->ibn_dev;
        struct ib_qp_init_attr *init_qp_attr;
        kib_conn_t             *conn;
        struct ib_cq           *cq;
        unsigned long           flags;
        int                     rc;
        int                     i;

        LASSERT (net != NULL);
        LASSERT (!cfs_in_interrupt());

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
        conn->ibc_version = version;
        conn->ibc_peer = peer;                  /* I take the caller's ref */
        cmid->context = conn;                   /* for future CM callbacks */
        conn->ibc_cmid = cmid;

        CFS_INIT_LIST_HEAD(&conn->ibc_early_rxs);
        CFS_INIT_LIST_HEAD(&conn->ibc_tx_noops);
        CFS_INIT_LIST_HEAD(&conn->ibc_tx_queue);
        CFS_INIT_LIST_HEAD(&conn->ibc_tx_queue_rsrvd);
        CFS_INIT_LIST_HEAD(&conn->ibc_tx_queue_nocred);
        CFS_INIT_LIST_HEAD(&conn->ibc_active_txs);
        cfs_spin_lock_init(&conn->ibc_lock);

        LIBCFS_ALLOC(conn->ibc_connvars, sizeof(*conn->ibc_connvars));
        if (conn->ibc_connvars == NULL) {
                CERROR("Can't allocate in-progress connection state\n");
                goto failed_2;
        }
        memset(conn->ibc_connvars, 0, sizeof(*conn->ibc_connvars));

        cfs_write_lock_irqsave(glock, flags);
        if (dev->ibd_failover) {
                cfs_write_unlock_irqrestore(glock, flags);
                CERROR("%s: failover in progress\n", dev->ibd_ifname);
                goto failed_2;
        }

        if (dev->ibd_hdev->ibh_ibdev != cmid->device) {
                /* wakeup failover thread and teardown connection */
                if (kiblnd_dev_can_failover(dev)) {
                        cfs_list_add_tail(&dev->ibd_fail_list,
                                      &kiblnd_data.kib_failed_devs);
                        cfs_waitq_signal(&kiblnd_data.kib_failover_waitq);
                }

                cfs_write_unlock_irqrestore(glock, flags);
                CERROR("cmid HCA(%s), kib_dev(%s) need failover\n",
                       cmid->device->name, dev->ibd_ifname);
                goto failed_2;
        }

        kiblnd_hdev_addref_locked(dev->ibd_hdev);
        conn->ibc_hdev = dev->ibd_hdev;

        kiblnd_setup_mtu_locked(cmid);

        cfs_write_unlock_irqrestore(glock, flags);

        LIBCFS_ALLOC(conn->ibc_rxs, IBLND_RX_MSGS(version) * sizeof(kib_rx_t));
        if (conn->ibc_rxs == NULL) {
                CERROR("Cannot allocate RX buffers\n");
                goto failed_2;
        }
        memset(conn->ibc_rxs, 0, IBLND_RX_MSGS(version) * sizeof(kib_rx_t));

        rc = kiblnd_alloc_pages(&conn->ibc_rx_pages,
                                IBLND_RX_MSG_PAGES(version));
        if (rc != 0)
                goto failed_2;

        kiblnd_map_rx_descs(conn);

#ifdef HAVE_OFED_IB_COMP_VECTOR
        cq = ib_create_cq(cmid->device,
                          kiblnd_cq_completion, kiblnd_cq_event, conn,
                          IBLND_CQ_ENTRIES(version), 0);
#else
        cq = ib_create_cq(cmid->device,
                          kiblnd_cq_completion, kiblnd_cq_event, conn,
                          IBLND_CQ_ENTRIES(version));
#endif
        if (IS_ERR(cq)) {
                CERROR("Can't create CQ: %ld, cqe: %d\n",
                       PTR_ERR(cq), IBLND_CQ_ENTRIES(version));
                goto failed_2;
        }

        conn->ibc_cq = cq;

        rc = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
        if (rc != 0) {
                CERROR("Can't request completion notificiation: %d\n", rc);
                goto failed_2;
        }

        memset(init_qp_attr, 0, sizeof(*init_qp_attr));
        init_qp_attr->event_handler = kiblnd_qp_event;
        init_qp_attr->qp_context = conn;
        init_qp_attr->cap.max_send_wr = IBLND_SEND_WRS(version);
        init_qp_attr->cap.max_recv_wr = IBLND_RECV_WRS(version);
        init_qp_attr->cap.max_send_sge = 1;
        init_qp_attr->cap.max_recv_sge = 1;
        init_qp_attr->sq_sig_type = IB_SIGNAL_REQ_WR;
        init_qp_attr->qp_type = IB_QPT_RC;
        init_qp_attr->send_cq = cq;
        init_qp_attr->recv_cq = cq;

        rc = rdma_create_qp(cmid, conn->ibc_hdev->ibh_pd, init_qp_attr);
        if (rc != 0) {
                CERROR("Can't create QP: %d, send_wr: %d, recv_wr: %d\n",
                       rc, init_qp_attr->cap.max_send_wr,
                       init_qp_attr->cap.max_recv_wr);
                goto failed_2;
        }

        LIBCFS_FREE(init_qp_attr, sizeof(*init_qp_attr));

        /* 1 ref for caller and each rxmsg */
        cfs_atomic_set(&conn->ibc_refcount, 1 + IBLND_RX_MSGS(version));
        conn->ibc_nrx = IBLND_RX_MSGS(version);

        /* post receives */
        for (i = 0; i < IBLND_RX_MSGS(version); i++) {
                rc = kiblnd_post_rx(&conn->ibc_rxs[i],
                                    IBLND_POSTRX_NO_CREDIT);
                if (rc != 0) {
                        CERROR("Can't post rxmsg: %d\n", rc);

                        /* Make posted receives complete */
                        kiblnd_abort_receives(conn);

                        /* correct # of posted buffers
                         * NB locking needed now I'm racing with completion */
                        cfs_spin_lock_irqsave(&kiblnd_data.kib_sched_lock,
                                              flags);
                        conn->ibc_nrx -= IBLND_RX_MSGS(version) - i;
                        cfs_spin_unlock_irqrestore(&kiblnd_data.kib_sched_lock,
                                                   flags);

                        /* cmid will be destroyed by CM(ofed) after cm_callback
                         * returned, so we can't refer it anymore
                         * (by kiblnd_connd()->kiblnd_destroy_conn) */
                        rdma_destroy_qp(conn->ibc_cmid);
                        conn->ibc_cmid = NULL;

                        /* Drop my own and unused rxbuffer refcounts */
                        while (i++ <= IBLND_RX_MSGS(version))
                                kiblnd_conn_decref(conn);

                        return NULL;
                }
        }

        /* Init successful! */
        LASSERT (state == IBLND_CONN_ACTIVE_CONNECT ||
                 state == IBLND_CONN_PASSIVE_WAIT);
        conn->ibc_state = state;

        /* 1 more conn */
        cfs_atomic_inc(&net->ibn_nconns);
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

        LASSERT (!cfs_in_interrupt());
        LASSERT (cfs_atomic_read(&conn->ibc_refcount) == 0);
        LASSERT (cfs_list_empty(&conn->ibc_early_rxs));
        LASSERT (cfs_list_empty(&conn->ibc_tx_noops));
        LASSERT (cfs_list_empty(&conn->ibc_tx_queue));
        LASSERT (cfs_list_empty(&conn->ibc_tx_queue_rsrvd));
        LASSERT (cfs_list_empty(&conn->ibc_tx_queue_nocred));
        LASSERT (cfs_list_empty(&conn->ibc_active_txs));
        LASSERT (conn->ibc_noops_posted == 0);
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

        /* conn->ibc_cmid might be destroyed by CM already */
        if (cmid != NULL && cmid->qp != NULL)
                rdma_destroy_qp(cmid);

        if (conn->ibc_cq != NULL) {
                rc = ib_destroy_cq(conn->ibc_cq);
                if (rc != 0)
                        CWARN("Error destroying CQ: %d\n", rc);
        }

        if (conn->ibc_rx_pages != NULL)
                kiblnd_unmap_rx_descs(conn);

        if (conn->ibc_rxs != NULL) {
                LIBCFS_FREE(conn->ibc_rxs,
                            IBLND_RX_MSGS(conn->ibc_version) * sizeof(kib_rx_t));
        }

        if (conn->ibc_connvars != NULL)
                LIBCFS_FREE(conn->ibc_connvars, sizeof(*conn->ibc_connvars));

        if (conn->ibc_hdev != NULL)
                kiblnd_hdev_decref(conn->ibc_hdev);

        /* See CAVEAT EMPTOR above in kiblnd_create_conn */
        if (conn->ibc_state != IBLND_CONN_INIT) {
                kib_net_t *net = peer->ibp_ni->ni_data;

                kiblnd_peer_decref(peer);
                rdma_destroy_id(cmid);
                cfs_atomic_dec(&net->ibn_nconns);
        }

        LIBCFS_FREE(conn, sizeof(*conn));
}

int
kiblnd_close_peer_conns_locked (kib_peer_t *peer, int why)
{
        kib_conn_t             *conn;
        cfs_list_t             *ctmp;
        cfs_list_t             *cnxt;
        int                     count = 0;

        cfs_list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = cfs_list_entry(ctmp, kib_conn_t, ibc_list);

                CDEBUG(D_NET, "Closing conn -> %s, "
                              "version: %x, reason: %d\n",
                       libcfs_nid2str(peer->ibp_nid),
                       conn->ibc_version, why);

                kiblnd_close_conn_locked(conn, why);
                count++;
        }

        return count;
}

int
kiblnd_close_stale_conns_locked (kib_peer_t *peer,
                                 int version, __u64 incarnation)
{
        kib_conn_t             *conn;
        cfs_list_t             *ctmp;
        cfs_list_t             *cnxt;
        int                     count = 0;

        cfs_list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = cfs_list_entry(ctmp, kib_conn_t, ibc_list);

                if (conn->ibc_version     == version &&
                    conn->ibc_incarnation == incarnation)
                        continue;

                CDEBUG(D_NET, "Closing stale conn -> %s version: %x, "
                              "incarnation:"LPX64"(%x, "LPX64")\n",
                       libcfs_nid2str(peer->ibp_nid),
                       conn->ibc_version, conn->ibc_incarnation,
                       version, incarnation);

                kiblnd_close_conn_locked(conn, -ESTALE);
                count++;
        }

        return count;
}

int
kiblnd_close_matching_conns (lnet_ni_t *ni, lnet_nid_t nid)
{
        kib_peer_t             *peer;
        cfs_list_t             *ptmp;
        cfs_list_t             *pnxt;
        int                     lo;
        int                     hi;
        int                     i;
        unsigned long           flags;
        int                     count = 0;

        cfs_write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        if (nid != LNET_NID_ANY)
                lo = hi = kiblnd_nid2peerlist(nid) - kiblnd_data.kib_peers;
        else {
                lo = 0;
                hi = kiblnd_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                cfs_list_for_each_safe (ptmp, pnxt, &kiblnd_data.kib_peers[i]) {

                        peer = cfs_list_entry(ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_connecting > 0 ||
                                 peer->ibp_accepting > 0 ||
                                 !cfs_list_empty(&peer->ibp_conns));

                        if (peer->ibp_ni != ni)
                                continue;

                        if (!(nid == LNET_NID_ANY || nid == peer->ibp_nid))
                                continue;

                        count += kiblnd_close_peer_conns_locked(peer, 0);
                }
        }

        cfs_write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

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
                kib_conn_t *conn;

                rc = 0;
                conn = kiblnd_get_conn_by_idx(ni, data->ioc_count);
                if (conn == NULL) {
                        rc = -ENOENT;
                        break;
                }

                LASSERT (conn->ibc_cmid != NULL);
                data->ioc_nid = conn->ibc_peer->ibp_nid;
                if (conn->ibc_cmid->route.path_rec == NULL)
                        data->ioc_u32[0] = 0; /* iWarp has no path MTU */
                else
                        data->ioc_u32[0] =
                        ib_mtu_enum_to_int(conn->ibc_cmid->route.path_rec->mtu);
                kiblnd_conn_decref(conn);
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
kiblnd_query (lnet_ni_t *ni, lnet_nid_t nid, cfs_time_t *when)
{
        cfs_time_t         last_alive = 0;
        cfs_time_t         now = cfs_time_current();
        cfs_rwlock_t      *glock = &kiblnd_data.kib_global_lock;
        kib_peer_t        *peer;
        unsigned long      flags;

        cfs_read_lock_irqsave(glock, flags);

        peer = kiblnd_find_peer_locked(nid);
        if (peer != NULL) {
                LASSERT (peer->ibp_connecting > 0 || /* creating conns */
                         peer->ibp_accepting > 0 ||
                         !cfs_list_empty(&peer->ibp_conns));  /* active conn */
                last_alive = peer->ibp_last_alive;
        }

        cfs_read_unlock_irqrestore(glock, flags);

        if (last_alive != 0)
                *when = last_alive;

        /* peer is not persistent in hash, trigger peer creation
         * and connection establishment with a NULL tx */
        if (peer == NULL)
                kiblnd_launch_tx(ni, NULL, nid);

        CDEBUG(D_NET, "Peer %s %p, alive %ld secs ago\n",
               libcfs_nid2str(nid), peer,
               last_alive ? cfs_duration_sec(now - last_alive) : -1);
        return;
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
kiblnd_unmap_rx_descs(kib_conn_t *conn)
{
        kib_rx_t *rx;
        int       i;

        LASSERT (conn->ibc_rxs != NULL);
        LASSERT (conn->ibc_hdev != NULL);

        for (i = 0; i < IBLND_RX_MSGS(conn->ibc_version); i++) {
                rx = &conn->ibc_rxs[i];

                LASSERT (rx->rx_nob >= 0); /* not posted */

                kiblnd_dma_unmap_single(conn->ibc_hdev->ibh_ibdev,
                                        KIBLND_UNMAP_ADDR(rx, rx_msgunmap,
                                                          rx->rx_msgaddr),
                                        IBLND_MSG_SIZE, DMA_FROM_DEVICE);
        }

        kiblnd_free_pages(conn->ibc_rx_pages);

        conn->ibc_rx_pages = NULL;
}

void
kiblnd_map_rx_descs(kib_conn_t *conn)
{
        kib_rx_t       *rx;
        struct page    *pg;
        int             pg_off;
        int             ipg;
        int             i;

        for (pg_off = ipg = i = 0;
             i < IBLND_RX_MSGS(conn->ibc_version); i++) {
                pg = conn->ibc_rx_pages->ibp_pages[ipg];
                rx = &conn->ibc_rxs[i];

                rx->rx_conn = conn;
                rx->rx_msg = (kib_msg_t *)(((char *)page_address(pg)) + pg_off);

                rx->rx_msgaddr = kiblnd_dma_map_single(conn->ibc_hdev->ibh_ibdev,
                                                       rx->rx_msg, IBLND_MSG_SIZE,
                                                       DMA_FROM_DEVICE);
                LASSERT (!kiblnd_dma_mapping_error(conn->ibc_hdev->ibh_ibdev,
                                                   rx->rx_msgaddr));
                KIBLND_UNMAP_ADDR_SET(rx, rx_msgunmap, rx->rx_msgaddr);

                CDEBUG(D_NET,"rx %d: %p "LPX64"("LPX64")\n",
                       i, rx->rx_msg, rx->rx_msgaddr,
                       lnet_page2phys(pg) + pg_off);

                pg_off += IBLND_MSG_SIZE;
                LASSERT (pg_off <= PAGE_SIZE);

                if (pg_off == PAGE_SIZE) {
                        pg_off = 0;
                        ipg++;
                        LASSERT (ipg <= IBLND_RX_MSG_PAGES(conn->ibc_version));
                }
        }
}

static void
kiblnd_unmap_tx_pool(kib_tx_pool_t *tpo)
{
        kib_hca_dev_t  *hdev = tpo->tpo_hdev;
        kib_tx_t       *tx;
        int             i;

        LASSERT (tpo->tpo_pool.po_allocated == 0);

        if (hdev == NULL)
                return;

        for (i = 0; i < tpo->tpo_pool.po_size; i++) {
                tx = &tpo->tpo_tx_descs[i];
                kiblnd_dma_unmap_single(hdev->ibh_ibdev,
                                        KIBLND_UNMAP_ADDR(tx, tx_msgunmap,
                                                          tx->tx_msgaddr),
                                        IBLND_MSG_SIZE, DMA_TO_DEVICE);
        }

        kiblnd_hdev_decref(hdev);
        tpo->tpo_hdev = NULL;
}

static kib_hca_dev_t *
kiblnd_current_hdev(kib_dev_t *dev)
{
        kib_hca_dev_t *hdev;
        unsigned long  flags;
        int            i = 0;

        cfs_read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
        while (dev->ibd_failover) {
                cfs_read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
                if (i++ % 50 == 0)
                        CDEBUG(D_NET, "Wait for dev(%s) failover\n", dev->ibd_ifname);
                cfs_schedule_timeout(cfs_time_seconds(1) / 100);

                cfs_read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
        }

        kiblnd_hdev_addref_locked(dev->ibd_hdev);
        hdev = dev->ibd_hdev;

        cfs_read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

        return hdev;
}

static void
kiblnd_map_tx_pool(kib_tx_pool_t *tpo)
{
        kib_pages_t    *txpgs = tpo->tpo_tx_pages;
        kib_pool_t     *pool  = &tpo->tpo_pool;
        kib_net_t      *net   = pool->po_owner->ps_net;
        kib_dev_t      *dev   = net->ibn_dev;
        struct page    *page;
        kib_tx_t       *tx;
        int             page_offset;
        int             ipage;
        int             i;

        LASSERT (net != NULL);

        /* pre-mapped messages are not bigger than 1 page */
        CLASSERT (IBLND_MSG_SIZE <= PAGE_SIZE);

        /* No fancy arithmetic when we do the buffer calculations */
        CLASSERT (PAGE_SIZE % IBLND_MSG_SIZE == 0);

        tpo->tpo_hdev = kiblnd_current_hdev(dev);

        for (ipage = page_offset = i = 0; i < pool->po_size; i++) {
                page = txpgs->ibp_pages[ipage];
                tx = &tpo->tpo_tx_descs[i];

                tx->tx_msg = (kib_msg_t *)(((char *)page_address(page)) +
                                           page_offset);

                tx->tx_msgaddr = kiblnd_dma_map_single(
                        tpo->tpo_hdev->ibh_ibdev, tx->tx_msg,
                        IBLND_MSG_SIZE, DMA_TO_DEVICE);
                LASSERT (!kiblnd_dma_mapping_error(tpo->tpo_hdev->ibh_ibdev,
                                                   tx->tx_msgaddr));
                KIBLND_UNMAP_ADDR_SET(tx, tx_msgunmap, tx->tx_msgaddr);

                cfs_list_add(&tx->tx_list, &pool->po_free_list);

                page_offset += IBLND_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= txpgs->ibp_npages);
                }
        }
}

struct ib_mr *
kiblnd_find_dma_mr(kib_hca_dev_t *hdev, __u64 addr, __u64 size)
{
        __u64   index;

        LASSERT (hdev->ibh_mrs[0] != NULL);

        if (hdev->ibh_nmrs == 1)
                return hdev->ibh_mrs[0];

        index = addr >> hdev->ibh_mr_shift;

        if (index <  hdev->ibh_nmrs &&
            index == ((addr + size - 1) >> hdev->ibh_mr_shift))
                return hdev->ibh_mrs[index];

        return NULL;
}

struct ib_mr *
kiblnd_find_rd_dma_mr(kib_hca_dev_t *hdev, kib_rdma_desc_t *rd)
{
        struct ib_mr *prev_mr;
        struct ib_mr *mr;
        int           i;

        LASSERT (hdev->ibh_mrs[0] != NULL);

        if (*kiblnd_tunables.kib_map_on_demand > 0 &&
            *kiblnd_tunables.kib_map_on_demand <= rd->rd_nfrags)
                return NULL;

        if (hdev->ibh_nmrs == 1)
                return hdev->ibh_mrs[0];

        for (i = 0, mr = prev_mr = NULL;
             i < rd->rd_nfrags; i++) {
                mr = kiblnd_find_dma_mr(hdev,
                                        rd->rd_frags[i].rf_addr,
                                        rd->rd_frags[i].rf_nob);
                if (prev_mr == NULL)
                        prev_mr = mr;

                if (mr == NULL || prev_mr != mr) {
                        /* Can't covered by one single MR */
                        mr = NULL;
                        break;
                }
        }

        return mr;
}

void
kiblnd_destroy_fmr_pool(kib_fmr_pool_t *pool)
{
        LASSERT (pool->fpo_map_count == 0);

        if (pool->fpo_fmr_pool != NULL)
                ib_destroy_fmr_pool(pool->fpo_fmr_pool);

        if (pool->fpo_hdev != NULL)
                kiblnd_hdev_decref(pool->fpo_hdev);

        LIBCFS_FREE(pool, sizeof(kib_fmr_pool_t));
}

void
kiblnd_destroy_fmr_pool_list(cfs_list_t *head)
{
        kib_fmr_pool_t *pool;

        while (!cfs_list_empty(head)) {
                pool = cfs_list_entry(head->next, kib_fmr_pool_t, fpo_list);
                cfs_list_del(&pool->fpo_list);
                kiblnd_destroy_fmr_pool(pool);
        }
}

int
kiblnd_create_fmr_pool(kib_fmr_poolset_t *fps, kib_fmr_pool_t **pp_fpo)
{
        /* FMR pool for RDMA */
        kib_dev_t               *dev = fps->fps_net->ibn_dev;
        kib_fmr_pool_t          *fpo;
        struct ib_fmr_pool_param param = {
                .max_pages_per_fmr = LNET_MAX_PAYLOAD/PAGE_SIZE,
                .page_shift        = PAGE_SHIFT,
                .access            = (IB_ACCESS_LOCAL_WRITE |
                                      IB_ACCESS_REMOTE_WRITE),
                .pool_size         = *kiblnd_tunables.kib_fmr_pool_size,
                .dirty_watermark   = *kiblnd_tunables.kib_fmr_flush_trigger,
                .flush_function    = NULL,
                .flush_arg         = NULL,
                .cache             = !!*kiblnd_tunables.kib_fmr_cache};
        int rc;

        LIBCFS_ALLOC(fpo, sizeof(kib_fmr_pool_t));
        if (fpo == NULL)
                return -ENOMEM;

        memset(fpo, 0, sizeof(kib_fmr_pool_t));
        fpo->fpo_hdev = kiblnd_current_hdev(dev);
        fpo->fpo_fmr_pool = ib_create_fmr_pool(fpo->fpo_hdev->ibh_pd, &param);
        if (IS_ERR(fpo->fpo_fmr_pool)) {
                CERROR("Failed to create FMR pool: %ld\n",
                       PTR_ERR(fpo->fpo_fmr_pool));
                rc = PTR_ERR(fpo->fpo_fmr_pool);
                kiblnd_hdev_decref(fpo->fpo_hdev);
                LIBCFS_FREE(fpo, sizeof(kib_fmr_pool_t));
                return rc;
        }

        fpo->fpo_deadline = cfs_time_shift(IBLND_POOL_DEADLINE);
        fpo->fpo_owner    = fps;
        *pp_fpo = fpo;

        return 0;
}

static void
kiblnd_fail_fmr_pool_set(kib_fmr_poolset_t *fps, cfs_list_t *zombies)
{
        cfs_spin_lock(&fps->fps_lock);

        while (!cfs_list_empty(&fps->fps_pool_list)) {
                kib_fmr_pool_t *fpo = cfs_list_entry(fps->fps_pool_list.next,
                                                 kib_fmr_pool_t, fpo_list);
                fpo->fpo_failed = 1;
                cfs_list_del(&fpo->fpo_list);
                if (fpo->fpo_map_count == 0)
                        cfs_list_add(&fpo->fpo_list, zombies);
                else
                        cfs_list_add(&fpo->fpo_list, &fps->fps_failed_pool_list);
        }

        cfs_spin_unlock(&fps->fps_lock);
}

static void
kiblnd_fini_fmr_pool_set(kib_fmr_poolset_t *fps)
{
        kiblnd_destroy_fmr_pool_list(&fps->fps_failed_pool_list);
        kiblnd_destroy_fmr_pool_list(&fps->fps_pool_list);
}

static int
kiblnd_init_fmr_pool_set(kib_fmr_poolset_t *fps, kib_net_t *net)
{
        kib_fmr_pool_t *fpo;
        int             rc;

        memset(fps, 0, sizeof(kib_fmr_poolset_t));

        fps->fps_net = net;
        cfs_spin_lock_init(&fps->fps_lock);
        CFS_INIT_LIST_HEAD(&fps->fps_pool_list);
        CFS_INIT_LIST_HEAD(&fps->fps_failed_pool_list);
        rc = kiblnd_create_fmr_pool(fps, &fpo);
        if (rc == 0)
                cfs_list_add_tail(&fpo->fpo_list, &fps->fps_pool_list);

        return rc;
}

static int
kiblnd_fmr_pool_is_idle(kib_fmr_pool_t *fpo, cfs_time_t now)
{
        if (fpo->fpo_map_count != 0) /* still in use */
                return 0;
        if (fpo->fpo_failed)
                return 1;
        return cfs_time_aftereq(now, fpo->fpo_deadline);
}

void
kiblnd_fmr_pool_unmap(kib_fmr_t *fmr, int status)
{
        CFS_LIST_HEAD     (zombies);
        kib_fmr_pool_t    *fpo = fmr->fmr_pool;
        kib_fmr_poolset_t *fps = fpo->fpo_owner;
        cfs_time_t         now = cfs_time_current();
        kib_fmr_pool_t    *tmp;
        int                rc;

        rc = ib_fmr_pool_unmap(fmr->fmr_pfmr);
        LASSERT (rc == 0);

        if (status != 0) {
                rc = ib_flush_fmr_pool(fpo->fpo_fmr_pool);
                LASSERT (rc == 0);
        }

        fmr->fmr_pool = NULL;
        fmr->fmr_pfmr = NULL;

        cfs_spin_lock(&fps->fps_lock);
        fpo->fpo_map_count --;  /* decref the pool */

        cfs_list_for_each_entry_safe(fpo, tmp, &fps->fps_pool_list, fpo_list) {
                /* the first pool is persistent */
                if (fps->fps_pool_list.next == &fpo->fpo_list)
                        continue;

                if (kiblnd_fmr_pool_is_idle(fpo, now)) {
                        cfs_list_move(&fpo->fpo_list, &zombies);
                        fps->fps_version ++;
                }
        }
        cfs_spin_unlock(&fps->fps_lock);

        if (!cfs_list_empty(&zombies))
                kiblnd_destroy_fmr_pool_list(&zombies);
}

int
kiblnd_fmr_pool_map(kib_fmr_poolset_t *fps, __u64 *pages, int npages,
                    __u64 iov, kib_fmr_t *fmr)
{
        struct ib_pool_fmr *pfmr;
        kib_fmr_pool_t     *fpo;
        __u64               version;
        int                 rc;

        LASSERT (fps->fps_net->ibn_with_fmr);
 again:
        cfs_spin_lock(&fps->fps_lock);
        version = fps->fps_version;
        cfs_list_for_each_entry(fpo, &fps->fps_pool_list, fpo_list) {
                fpo->fpo_deadline = cfs_time_shift(IBLND_POOL_DEADLINE);
                fpo->fpo_map_count ++;
                cfs_spin_unlock(&fps->fps_lock);

                pfmr = ib_fmr_pool_map_phys(fpo->fpo_fmr_pool,
                                            pages, npages, iov);
                if (likely(!IS_ERR(pfmr))) {
                        fmr->fmr_pool = fpo;
                        fmr->fmr_pfmr = pfmr;
                        return 0;
                }

                cfs_spin_lock(&fps->fps_lock);
                fpo->fpo_map_count --;
                if (PTR_ERR(pfmr) != -EAGAIN) {
                        cfs_spin_unlock(&fps->fps_lock);
                        return PTR_ERR(pfmr);
                }

                /* EAGAIN and ... */
                if (version != fps->fps_version) {
                        cfs_spin_unlock(&fps->fps_lock);
                        goto again;
                }
        }

        if (fps->fps_increasing) {
                cfs_spin_unlock(&fps->fps_lock);
                CDEBUG(D_NET, "Another thread is allocating new "
                              "FMR pool, waiting for her to complete\n");
                cfs_schedule();
                goto again;

        }

        if (cfs_time_before(cfs_time_current(), fps->fps_next_retry)) {
                /* someone failed recently */
                cfs_spin_unlock(&fps->fps_lock);
                return -EAGAIN;
        }

        fps->fps_increasing = 1;
        cfs_spin_unlock(&fps->fps_lock);

        CDEBUG(D_NET, "Allocate new FMR pool\n");
        rc = kiblnd_create_fmr_pool(fps, &fpo);
        cfs_spin_lock(&fps->fps_lock);
        fps->fps_increasing = 0;
        if (rc == 0) {
                fps->fps_version ++;
                cfs_list_add_tail(&fpo->fpo_list, &fps->fps_pool_list);
        } else {
                fps->fps_next_retry = cfs_time_shift(10);
        }
        cfs_spin_unlock(&fps->fps_lock);

        goto again;
}

static void
kiblnd_fini_pool(kib_pool_t *pool)
{
        LASSERT (cfs_list_empty(&pool->po_free_list));
        LASSERT (pool->po_allocated == 0);

        CDEBUG(D_NET, "Finalize %s pool\n", pool->po_owner->ps_name);
}

static void
kiblnd_init_pool(kib_poolset_t *ps, kib_pool_t *pool, int size)
{
        CDEBUG(D_NET, "Initialize %s pool\n", ps->ps_name);

        memset(pool, 0, sizeof(kib_pool_t));
        CFS_INIT_LIST_HEAD(&pool->po_free_list);
        pool->po_deadline = cfs_time_shift(IBLND_POOL_DEADLINE);
        pool->po_owner    = ps;
        pool->po_size     = size;
}

void
kiblnd_destroy_pool_list(cfs_list_t *head)
{
        kib_pool_t *pool;

        while (!cfs_list_empty(head)) {
                pool = cfs_list_entry(head->next, kib_pool_t, po_list);
                cfs_list_del(&pool->po_list);

                LASSERT (pool->po_owner != NULL);
                pool->po_owner->ps_pool_destroy(pool);
        }
}

static void
kiblnd_fail_pool_set(kib_poolset_t *ps, cfs_list_t *zombies)
{
        cfs_spin_lock(&ps->ps_lock);
        while (!cfs_list_empty(&ps->ps_pool_list)) {
                kib_pool_t *po = cfs_list_entry(ps->ps_pool_list.next,
                                            kib_pool_t, po_list);
                po->po_failed = 1;
                cfs_list_del(&po->po_list);
                if (po->po_allocated == 0)
                        cfs_list_add(&po->po_list, zombies);
                else
                        cfs_list_add(&po->po_list, &ps->ps_failed_pool_list);
        }
        cfs_spin_unlock(&ps->ps_lock);
}

static void
kiblnd_fini_pool_set(kib_poolset_t *ps)
{
        kiblnd_destroy_pool_list(&ps->ps_failed_pool_list);
        kiblnd_destroy_pool_list(&ps->ps_pool_list);
}

static int
kiblnd_init_pool_set(kib_poolset_t *ps, kib_net_t *net,
                     char *name, int size,
                     kib_ps_pool_create_t po_create,
                     kib_ps_pool_destroy_t po_destroy,
                     kib_ps_node_init_t nd_init,
                     kib_ps_node_fini_t nd_fini)
{
        kib_pool_t    *pool;
        int            rc;

        memset(ps, 0, sizeof(kib_poolset_t));

        ps->ps_net          = net;
        ps->ps_pool_create  = po_create;
        ps->ps_pool_destroy = po_destroy;
        ps->ps_node_init    = nd_init;
        ps->ps_node_fini    = nd_fini;
        ps->ps_pool_size    = size;
        strncpy(ps->ps_name, name, IBLND_POOL_NAME_LEN);
        cfs_spin_lock_init(&ps->ps_lock);
        CFS_INIT_LIST_HEAD(&ps->ps_pool_list);
        CFS_INIT_LIST_HEAD(&ps->ps_failed_pool_list);

        rc = ps->ps_pool_create(ps, size, &pool);
        if (rc == 0)
                cfs_list_add(&pool->po_list, &ps->ps_pool_list);
        else
                CERROR("Failed to create the first pool for %s\n", ps->ps_name);

        return rc;
}

static int
kiblnd_pool_is_idle(kib_pool_t *pool, cfs_time_t now)
{
        if (pool->po_allocated != 0) /* still in use */
                return 0;
        if (pool->po_failed)
                return 1;
        return cfs_time_aftereq(now, pool->po_deadline);
}

void
kiblnd_pool_free_node(kib_pool_t *pool, cfs_list_t *node)
{
        CFS_LIST_HEAD  (zombies);
        kib_poolset_t  *ps = pool->po_owner;
        kib_pool_t     *tmp;
        cfs_time_t      now = cfs_time_current();

        cfs_spin_lock(&ps->ps_lock);

        if (ps->ps_node_fini != NULL)
                ps->ps_node_fini(pool, node);

        LASSERT (pool->po_allocated > 0);
        cfs_list_add(node, &pool->po_free_list);
        pool->po_allocated --;

        cfs_list_for_each_entry_safe(pool, tmp, &ps->ps_pool_list, po_list) {
                /* the first pool is persistent */
                if (ps->ps_pool_list.next == &pool->po_list)
                        continue;

                if (kiblnd_pool_is_idle(pool, now))
                        cfs_list_move(&pool->po_list, &zombies);
        }
        cfs_spin_unlock(&ps->ps_lock);

        if (!cfs_list_empty(&zombies))
                kiblnd_destroy_pool_list(&zombies);
}

cfs_list_t *
kiblnd_pool_alloc_node(kib_poolset_t *ps)
{
        cfs_list_t            *node;
        kib_pool_t            *pool;
        int                    rc;

 again:
        cfs_spin_lock(&ps->ps_lock);
        cfs_list_for_each_entry(pool, &ps->ps_pool_list, po_list) {
                if (cfs_list_empty(&pool->po_free_list))
                        continue;

                pool->po_allocated ++;
                pool->po_deadline = cfs_time_shift(IBLND_POOL_DEADLINE);
                node = pool->po_free_list.next;
                cfs_list_del(node);

                if (ps->ps_node_init != NULL) {
                        /* still hold the lock */
                        ps->ps_node_init(pool, node);
                }
                cfs_spin_unlock(&ps->ps_lock);
                return node;
        }

        /* no available tx pool and ... */
        if (ps->ps_increasing) {
                /* another thread is allocating a new pool */
                cfs_spin_unlock(&ps->ps_lock);
                CDEBUG(D_NET, "Another thread is allocating new "
                       "%s pool, waiting for her to complete\n",
                       ps->ps_name);
                cfs_schedule();
                goto again;
        }

        if (cfs_time_before(cfs_time_current(), ps->ps_next_retry)) {
                /* someone failed recently */
                cfs_spin_unlock(&ps->ps_lock);
                return NULL;
        }

        ps->ps_increasing = 1;
        cfs_spin_unlock(&ps->ps_lock);

        CDEBUG(D_NET, "%s pool exhausted, allocate new pool\n", ps->ps_name);

        rc = ps->ps_pool_create(ps, ps->ps_pool_size, &pool);

        cfs_spin_lock(&ps->ps_lock);
        ps->ps_increasing = 0;
        if (rc == 0) {
                cfs_list_add_tail(&pool->po_list, &ps->ps_pool_list);
        } else {
                /* retry 10 seconds later */
                ps->ps_next_retry = cfs_time_shift(10);
                CERROR("Can't allocate new %s pool because out of memory\n",
                       ps->ps_name);
        }
        cfs_spin_unlock(&ps->ps_lock);

        goto again;
}

void
kiblnd_pmr_pool_unmap(kib_phys_mr_t *pmr)
{
        kib_pmr_pool_t      *ppo = pmr->pmr_pool;
        struct ib_mr        *mr  = pmr->pmr_mr;

        pmr->pmr_mr = NULL;
        kiblnd_pool_free_node(&ppo->ppo_pool, &pmr->pmr_list);
        if (mr != NULL)
                ib_dereg_mr(mr);
}

int
kiblnd_pmr_pool_map(kib_pmr_poolset_t *pps, kib_hca_dev_t *hdev,
                    kib_rdma_desc_t *rd, __u64 *iova, kib_phys_mr_t **pp_pmr)
{
        kib_phys_mr_t *pmr;
        cfs_list_t    *node;
        int            rc;
        int            i;

        node = kiblnd_pool_alloc_node(&pps->pps_poolset);
        if (node == NULL) {
                CERROR("Failed to allocate PMR descriptor\n");
                return -ENOMEM;
        }

        pmr = container_of(node, kib_phys_mr_t, pmr_list);
        if (pmr->pmr_pool->ppo_hdev != hdev) {
                kiblnd_pool_free_node(&pmr->pmr_pool->ppo_pool, node);
                return -EAGAIN;
        }

        for (i = 0; i < rd->rd_nfrags; i ++) {
                pmr->pmr_ipb[i].addr = rd->rd_frags[i].rf_addr;
                pmr->pmr_ipb[i].size = rd->rd_frags[i].rf_nob;
        }

        pmr->pmr_mr = ib_reg_phys_mr(hdev->ibh_pd,
                                     pmr->pmr_ipb, rd->rd_nfrags,
                                     IB_ACCESS_LOCAL_WRITE |
                                     IB_ACCESS_REMOTE_WRITE,
                                     iova);
        if (!IS_ERR(pmr->pmr_mr)) {
                pmr->pmr_iova = *iova;
                *pp_pmr = pmr;
                return 0;
        }

        rc = PTR_ERR(pmr->pmr_mr);
        CERROR("Failed ib_reg_phys_mr: %d\n", rc);

        pmr->pmr_mr = NULL;
        kiblnd_pool_free_node(&pmr->pmr_pool->ppo_pool, node);

        return rc;
}

static void
kiblnd_destroy_pmr_pool(kib_pool_t *pool)
{
        kib_pmr_pool_t *ppo = container_of(pool, kib_pmr_pool_t, ppo_pool);
        kib_phys_mr_t  *pmr;

        LASSERT (pool->po_allocated == 0);

        while (!cfs_list_empty(&pool->po_free_list)) {
                pmr = cfs_list_entry(pool->po_free_list.next,
                                     kib_phys_mr_t, pmr_list);

                LASSERT (pmr->pmr_mr == NULL);
                cfs_list_del(&pmr->pmr_list);

                if (pmr->pmr_ipb != NULL) {
                        LIBCFS_FREE(pmr->pmr_ipb,
                                    IBLND_MAX_RDMA_FRAGS *
                                    sizeof(struct ib_phys_buf));
                }

                LIBCFS_FREE(pmr, sizeof(kib_phys_mr_t));
        }

        kiblnd_fini_pool(pool);
        if (ppo->ppo_hdev != NULL)
                kiblnd_hdev_decref(ppo->ppo_hdev);

        LIBCFS_FREE(ppo, sizeof(kib_pmr_pool_t));
}

static int
kiblnd_create_pmr_pool(kib_poolset_t *ps, int size, kib_pool_t **pp_po)
{
        kib_pmr_pool_t      *ppo;
        kib_pool_t          *pool;
        kib_phys_mr_t       *pmr;
        int                  i;

        LIBCFS_ALLOC(ppo, sizeof(kib_pmr_pool_t));
        if (ppo == NULL) {
                CERROR("Failed to allocate PMR pool\n");
                return -ENOMEM;
        }

        pool = &ppo->ppo_pool;
        kiblnd_init_pool(ps, pool, size);

        for (i = 0; i < size; i++) {
                LIBCFS_ALLOC(pmr, sizeof(kib_phys_mr_t));
                if (pmr == NULL)
                        break;

                memset(pmr, 0, sizeof(kib_phys_mr_t));
                pmr->pmr_pool = ppo;
                LIBCFS_ALLOC(pmr->pmr_ipb,
                             IBLND_MAX_RDMA_FRAGS *
                             sizeof(struct ib_phys_buf));
                if (pmr->pmr_ipb == NULL)
                        break;

                cfs_list_add(&pmr->pmr_list, &pool->po_free_list);
        }

        if (i < size) {
                ps->ps_pool_destroy(pool);
                return -ENOMEM;
        }

        ppo->ppo_hdev = kiblnd_current_hdev(ps->ps_net->ibn_dev);
        *pp_po = pool;
        return 0;
}

static void
kiblnd_destroy_tx_pool(kib_pool_t *pool)
{
        kib_tx_pool_t  *tpo = container_of(pool, kib_tx_pool_t, tpo_pool);
        int             i;

        LASSERT (pool->po_allocated == 0);

        if (tpo->tpo_tx_pages != NULL) {
                kiblnd_unmap_tx_pool(tpo);
                kiblnd_free_pages(tpo->tpo_tx_pages);
        }

        if (tpo->tpo_tx_descs == NULL)
                goto out;

        for (i = 0; i < pool->po_size; i++) {
                kib_tx_t *tx = &tpo->tpo_tx_descs[i];

                cfs_list_del(&tx->tx_list);
                if (tx->tx_pages != NULL)
                        LIBCFS_FREE(tx->tx_pages,
                                    LNET_MAX_IOV *
                                    sizeof(*tx->tx_pages));
                if (tx->tx_frags != NULL)
                        LIBCFS_FREE(tx->tx_frags,
                                    IBLND_MAX_RDMA_FRAGS *
                                            sizeof(*tx->tx_frags));
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
        }

        LIBCFS_FREE(tpo->tpo_tx_descs,
                    pool->po_size * sizeof(kib_tx_t));
out:
        kiblnd_fini_pool(pool);
        LIBCFS_FREE(tpo, sizeof(kib_tx_pool_t));
}

static int
kiblnd_create_tx_pool(kib_poolset_t *ps, int size, kib_pool_t **pp_po)
{
        int            i;
        int            npg;
        kib_pool_t    *pool;
        kib_tx_pool_t *tpo;

        LIBCFS_ALLOC(tpo, sizeof(kib_tx_pool_t));
        if (tpo == NULL) {
                CERROR("Failed to allocate TX pool\n");
                return -ENOMEM;
        }

        pool = &tpo->tpo_pool;
        kiblnd_init_pool(ps, pool, size);
        tpo->tpo_tx_descs = NULL;
        tpo->tpo_tx_pages = NULL;

        npg = (size * IBLND_MSG_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;
        if (kiblnd_alloc_pages(&tpo->tpo_tx_pages, npg) != 0) {
                CERROR("Can't allocate tx pages: %d\n", npg);
                LIBCFS_FREE(tpo, sizeof(kib_tx_pool_t));
                return -ENOMEM;
        }

        LIBCFS_ALLOC (tpo->tpo_tx_descs, size * sizeof(kib_tx_t));
        if (tpo->tpo_tx_descs == NULL) {
                CERROR("Can't allocate %d tx descriptors\n", size);
                ps->ps_pool_destroy(pool);
                return -ENOMEM;
        }

        memset(tpo->tpo_tx_descs, 0, size * sizeof(kib_tx_t));

        for (i = 0; i < size; i++) {
                kib_tx_t *tx = &tpo->tpo_tx_descs[i];

                tx->tx_pool = tpo;
                if (ps->ps_net->ibn_with_fmr){
                        LIBCFS_ALLOC(tx->tx_pages, LNET_MAX_IOV *
                                     sizeof(*tx->tx_pages));
                        if (tx->tx_pages == NULL)
                                break;
                }

                LIBCFS_ALLOC(tx->tx_frags,
                             IBLND_MAX_RDMA_FRAGS *
                             sizeof(*tx->tx_frags));
                if (tx->tx_frags == NULL)
                        break;

                LIBCFS_ALLOC(tx->tx_wrq,
                             (1 + IBLND_MAX_RDMA_FRAGS) *
                             sizeof(*tx->tx_wrq));
                if (tx->tx_wrq == NULL)
                        break;

                LIBCFS_ALLOC(tx->tx_sge,
                             (1 + IBLND_MAX_RDMA_FRAGS) *
                             sizeof(*tx->tx_sge));
                if (tx->tx_sge == NULL)
                        break;

                LIBCFS_ALLOC(tx->tx_rd,
                             offsetof(kib_rdma_desc_t,
                                      rd_frags[IBLND_MAX_RDMA_FRAGS]));
                if (tx->tx_rd == NULL)
                        break;
        }

        if (i == size) {
                kiblnd_map_tx_pool(tpo);
                *pp_po = pool;
                return 0;
        }

        ps->ps_pool_destroy(pool);
        return -ENOMEM;
}

static void
kiblnd_tx_init(kib_pool_t *pool, cfs_list_t *node)
{
        kib_tx_poolset_t *tps = container_of(pool->po_owner, kib_tx_poolset_t,
                                             tps_poolset);
        kib_tx_t         *tx  = cfs_list_entry(node, kib_tx_t, tx_list);

        tx->tx_cookie = tps->tps_next_tx_cookie ++;
}

void
kiblnd_ni_fini_pools(kib_net_t *net)
{
        kiblnd_fini_pool_set(&net->ibn_tx_ps.tps_poolset);
        if (net->ibn_with_fmr)
                kiblnd_fini_fmr_pool_set(&net->ibn_fmr_ps);
        else if (net->ibn_with_pmr)
                kiblnd_fini_pool_set(&net->ibn_pmr_ps.pps_poolset);
}

int
kiblnd_net_init_pools(kib_net_t *net)
{
        kib_fmr_poolset_t *fps = &net->ibn_fmr_ps;
        kib_pmr_poolset_t *pps = &net->ibn_pmr_ps;
        kib_tx_poolset_t  *tps = &net->ibn_tx_ps;
        unsigned long      flags;
        int                rc;

        if (*kiblnd_tunables.kib_fmr_pool_size <
            *kiblnd_tunables.kib_ntx / 4) {
                CERROR("Can't set fmr pool size (%d) < ntx / 4(%d)\n",
                       *kiblnd_tunables.kib_fmr_pool_size,
                       *kiblnd_tunables.kib_ntx / 4);
                return -EINVAL;
        }

        if (*kiblnd_tunables.kib_pmr_pool_size <
            *kiblnd_tunables.kib_ntx / 4) {
                CERROR("Can't set pmr pool size (%d) < ntx / 4(%d)\n",
                       *kiblnd_tunables.kib_pmr_pool_size,
                       *kiblnd_tunables.kib_ntx / 4);
                return -EINVAL;
        }

        cfs_read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
        if (*kiblnd_tunables.kib_map_on_demand > 0 ||
            net->ibn_dev->ibd_hdev->ibh_nmrs > 1) {
                /* premapping can fail if ibd_nmr > 1, so we always create
                 * FMR/PMR pool and map-on-demand if premapping failed */
                cfs_read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
                rc = kiblnd_init_fmr_pool_set(fps, net);
                if (rc == 0) {
                        net->ibn_with_fmr = 1;
                } else if (rc == -ENOSYS) {
                        rc = kiblnd_init_pool_set(&pps->pps_poolset, net, "PMR",
                                                  *kiblnd_tunables.kib_pmr_pool_size,
                                                  kiblnd_create_pmr_pool,
                                                  kiblnd_destroy_pmr_pool,
                                                  NULL, NULL);
                        if (rc == 0)
                                net->ibn_with_pmr = 1;
                }
                if (rc != 0)
                        return rc;
        } else {
                cfs_read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
        }

        rc = kiblnd_init_pool_set(&tps->tps_poolset, net, "TX", IBLND_TX_MSGS(),
                                  kiblnd_create_tx_pool, kiblnd_destroy_tx_pool,
                                  kiblnd_tx_init, NULL);
        if (rc == 0)
                return 0;

        if (net->ibn_with_fmr)
                kiblnd_fini_fmr_pool_set(fps);
        else if (net->ibn_with_pmr)
                kiblnd_fini_pool_set(&pps->pps_poolset);

        return rc;
}

static int
kiblnd_hdev_get_attr(kib_hca_dev_t *hdev)
{
        struct ib_device_attr *attr;
        int                    rc;

        /* It's safe to assume a HCA can handle a page size
         * matching that of the native system */
        hdev->ibh_page_shift = PAGE_SHIFT;
        hdev->ibh_page_size  = 1 << PAGE_SHIFT;
        hdev->ibh_page_mask  = ~((__u64)hdev->ibh_page_size - 1);

        LIBCFS_ALLOC(attr, sizeof(*attr));
        if (attr == NULL) {
                CERROR("Out of memory\n");
                return -ENOMEM;
        }

        rc = ib_query_device(hdev->ibh_ibdev, attr);
        if (rc == 0)
                hdev->ibh_mr_size = attr->max_mr_size;

        LIBCFS_FREE(attr, sizeof(*attr));

        if (rc != 0) {
                CERROR("Failed to query IB device: %d\n", rc);
                return rc;
        }

#ifdef HAVE_OFED_TRANSPORT_IWARP
        /* XXX We can't trust this value returned by Chelsio driver, it's wrong
         * and we have reported the bug, remove these in the future when Chelsio
         * bug got fixed. */
        if (rdma_node_get_transport(hdev->ibh_ibdev->node_type) ==
            RDMA_TRANSPORT_IWARP)
                hdev->ibh_mr_size = (1ULL << 32) - 1;
#endif

        if (hdev->ibh_mr_size == ~0ULL) {
                hdev->ibh_mr_shift = 64;
                return 0;
        }

        for (hdev->ibh_mr_shift = 0;
             hdev->ibh_mr_shift < 64; hdev->ibh_mr_shift ++) {
                if (hdev->ibh_mr_size == (1ULL << hdev->ibh_mr_shift) ||
                    hdev->ibh_mr_size == (1ULL << hdev->ibh_mr_shift) - 1)
                        return 0;
        }

        CERROR("Invalid mr size: "LPX64"\n", hdev->ibh_mr_size);
        return -EINVAL;
}

void
kiblnd_hdev_cleanup_mrs(kib_hca_dev_t *hdev)
{
        int     i;

        if (hdev->ibh_nmrs == 0 || hdev->ibh_mrs == NULL)
                return;

        for (i = 0; i < hdev->ibh_nmrs; i++) {
                if (hdev->ibh_mrs[i] == NULL)
                        break;

                ib_dereg_mr(hdev->ibh_mrs[i]);
        }

        LIBCFS_FREE(hdev->ibh_mrs, sizeof(*hdev->ibh_mrs) * hdev->ibh_nmrs);
        hdev->ibh_mrs  = NULL;
        hdev->ibh_nmrs = 0;
}

void
kiblnd_hdev_destroy(kib_hca_dev_t *hdev)
{
        kiblnd_hdev_cleanup_mrs(hdev);

        if (hdev->ibh_pd != NULL)
                ib_dealloc_pd(hdev->ibh_pd);

        if (hdev->ibh_cmid != NULL)
                rdma_destroy_id(hdev->ibh_cmid);

        LIBCFS_FREE(hdev, sizeof(*hdev));
}

int
kiblnd_hdev_setup_mrs(kib_hca_dev_t *hdev)
{
        struct ib_mr *mr;
        int           i;
        int           rc;
        __u64         mm_size;
        __u64         mr_size;
        int           acflags = IB_ACCESS_LOCAL_WRITE |
                                IB_ACCESS_REMOTE_WRITE;

        rc = kiblnd_hdev_get_attr(hdev);
        if (rc != 0)
                return rc;

        if (hdev->ibh_mr_shift == 64) {
                LIBCFS_ALLOC(hdev->ibh_mrs, 1 * sizeof(*hdev->ibh_mrs));
                if (hdev->ibh_mrs == NULL) {
                        CERROR("Failed to allocate MRs table\n");
                        return -ENOMEM;
                }

                hdev->ibh_mrs[0] = NULL;
                hdev->ibh_nmrs   = 1;

                mr = ib_get_dma_mr(hdev->ibh_pd, acflags);
                if (IS_ERR(mr)) {
                        CERROR("Failed ib_get_dma_mr : %ld\n", PTR_ERR(mr));
                        kiblnd_hdev_cleanup_mrs(hdev);
                        return PTR_ERR(mr);
                }

                hdev->ibh_mrs[0] = mr;

                goto out;
        }

        mr_size = (1ULL << hdev->ibh_mr_shift);
        mm_size = (unsigned long)high_memory - PAGE_OFFSET;

        hdev->ibh_nmrs = (int)((mm_size + mr_size - 1) >> hdev->ibh_mr_shift);

        if (hdev->ibh_mr_shift < 32 || hdev->ibh_nmrs > 1024) {
                /* it's 4T..., assume we will re-code at that time */
                CERROR("Can't support memory size: x"LPX64
                       " with MR size: x"LPX64"\n", mm_size, mr_size);
                return -EINVAL;
        }

        /* create an array of MRs to cover all memory */
        LIBCFS_ALLOC(hdev->ibh_mrs, sizeof(*hdev->ibh_mrs) * hdev->ibh_nmrs);
        if (hdev->ibh_mrs == NULL) {
                CERROR("Failed to allocate MRs' table\n");
                return -ENOMEM;
        }

        memset(hdev->ibh_mrs, 0, sizeof(*hdev->ibh_mrs) * hdev->ibh_nmrs);

        for (i = 0; i < hdev->ibh_nmrs; i++) {
                struct ib_phys_buf ipb;
                __u64              iova;

                ipb.size = hdev->ibh_mr_size;
                ipb.addr = i * mr_size;
                iova     = ipb.addr;

                mr = ib_reg_phys_mr(hdev->ibh_pd, &ipb, 1, acflags, &iova);
                if (IS_ERR(mr)) {
                        CERROR("Failed ib_reg_phys_mr addr "LPX64
                               " size "LPX64" : %ld\n",
                               ipb.addr, ipb.size, PTR_ERR(mr));
                        kiblnd_hdev_cleanup_mrs(hdev);
                        return PTR_ERR(mr);
                }

                LASSERT (iova == ipb.addr);

                hdev->ibh_mrs[i] = mr;
        }

out:
        CDEBUG(D_CONSOLE, "Register global MR array, MR size: "
                          LPX64", array size: %d\n",
                          hdev->ibh_mr_size, hdev->ibh_nmrs);
        return 0;
}

static int
kiblnd_dummy_callback(struct rdma_cm_id *cmid, struct rdma_cm_event *event)
{       /* DUMMY */
        return 0;
}

static int
kiblnd_dev_need_failover(kib_dev_t *dev)
{
        struct rdma_cm_id  *cmid;
        struct sockaddr_in  srcaddr;
        struct sockaddr_in  dstaddr;
        int                 rc;

        if (dev->ibd_hdev == NULL || /* initializing */
            dev->ibd_hdev->ibh_cmid == NULL || /* listener is dead */
            *kiblnd_tunables.kib_dev_failover > 1) /* debugging */
                return 1;

        /* XXX: it's UGLY, but I don't have better way to find
         * ib-bonding HCA failover because:
         *
         * a. no reliable CM event for HCA failover...
         * b. no OFED API to get ib_device for current net_device...
         *
         * We have only two choices at this point:
         *
         * a. rdma_bind_addr(), it will conflict with listener cmid
         * b. rdma_resolve_addr() to zero addr */
        cmid = kiblnd_rdma_create_id(kiblnd_dummy_callback, dev, RDMA_PS_TCP,
                                     IB_QPT_RC);
        if (IS_ERR(cmid)) {
                rc = PTR_ERR(cmid);
                CERROR("Failed to create cmid for failover: %d\n", rc);
                return rc;
        }

        memset(&srcaddr, 0, sizeof(srcaddr));
        srcaddr.sin_family      = AF_INET;
        srcaddr.sin_addr.s_addr = (__force u32)htonl(dev->ibd_ifip);

        memset(&dstaddr, 0, sizeof(dstaddr));
        dstaddr.sin_family = AF_INET;
        rc = rdma_resolve_addr(cmid, (struct sockaddr *)&srcaddr,
                               (struct sockaddr *)&dstaddr, 1);
        if (rc != 0) {
                CERROR("Failed to bind %s to device: %d\n",
                       dev->ibd_ifname, rc);
                rdma_destroy_id(cmid);
                return rc;
        }

        LASSERT (cmid->device != NULL);
        if (dev->ibd_hdev->ibh_ibdev == cmid->device) {
                /* don't need device failover */
                rdma_destroy_id(cmid);
                return 0;
        }

        return 1;
}

int
kiblnd_dev_failover(kib_dev_t *dev)
{
        CFS_LIST_HEAD      (zombie_tpo);
        CFS_LIST_HEAD      (zombie_ppo);
        CFS_LIST_HEAD      (zombie_fpo);
        struct rdma_cm_id  *cmid  = NULL;
        kib_hca_dev_t      *hdev  = NULL;
        kib_hca_dev_t      *old;
        struct ib_pd       *pd;
        kib_net_t          *net;
        struct sockaddr_in  addr;
        unsigned long       flags;
        int                 rc = 0;

        LASSERT (*kiblnd_tunables.kib_dev_failover > 1 ||
                 dev->ibd_can_failover ||
                 dev->ibd_hdev == NULL);

        rc = kiblnd_dev_need_failover(dev);
        if (rc <= 0)
                goto out;

        if (dev->ibd_hdev != NULL &&
            dev->ibd_hdev->ibh_cmid != NULL) {
                /* XXX it's not good to close old listener at here,
                 * because we can fail to create new listener.
                 * But we have to close it now, otherwise rdma_bind_addr
                 * will return EADDRINUSE... How crap! */
                cfs_write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

                cmid = dev->ibd_hdev->ibh_cmid;
                /* make next schedule of kiblnd_dev_need_failover
                 * will return 1 for me */
                dev->ibd_hdev->ibh_cmid  = NULL;
                cfs_write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

                rdma_destroy_id(cmid);
        }

        cmid = kiblnd_rdma_create_id(kiblnd_cm_callback, dev, RDMA_PS_TCP,
                                     IB_QPT_RC);
        if (IS_ERR(cmid)) {
                rc = PTR_ERR(cmid);
                CERROR("Failed to create cmid for failover: %d\n", rc);
                goto out;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = (__force u32)htonl(dev->ibd_ifip);
        addr.sin_port        = htons(*kiblnd_tunables.kib_service);

        /* Bind to failover device or port */
        rc = rdma_bind_addr(cmid, (struct sockaddr *)&addr);
        if (rc != 0) {
                CERROR("Failed to bind %s to device: %d\n",
                       dev->ibd_ifname, rc);
                rdma_destroy_id(cmid);
                goto out;
        }

        LIBCFS_ALLOC(hdev, sizeof(*hdev));
        if (hdev == NULL) {
                CERROR("Failed to allocate kib_hca_dev\n");
                rdma_destroy_id(cmid);
                rc = -ENOMEM;
                goto out;
        }
        memset(hdev, 0, sizeof(*hdev));
        atomic_set(&hdev->ibh_ref, 1);
        hdev->ibh_dev   = dev;
        hdev->ibh_cmid  = cmid;
        hdev->ibh_ibdev = cmid->device;

        pd = ib_alloc_pd(cmid->device);
        if (IS_ERR(pd)) {
                rc = PTR_ERR(pd);
                CERROR("Can't allocate PD: %d\n", rc);
                goto out;
        }

        hdev->ibh_pd = pd;

        rc = rdma_listen(cmid, 0);
        if (rc != 0) {
                CERROR("Can't start new listener: %d\n", rc);
                goto out;
        }

        rc = kiblnd_hdev_setup_mrs(hdev);
        if (rc != 0) {
                CERROR("Can't setup device: %d\n", rc);
                goto out;
        }

        cfs_write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        old = dev->ibd_hdev;
        dev->ibd_hdev = hdev; /* take over the refcount */
        hdev = old;

        cfs_list_for_each_entry(net, &dev->ibd_nets, ibn_list) {
                kiblnd_fail_pool_set(&net->ibn_tx_ps.tps_poolset, &zombie_tpo);
                if (net->ibn_with_pmr)
                        kiblnd_fail_pool_set(&net->ibn_pmr_ps.pps_poolset, &zombie_ppo);
                if (net->ibn_with_fmr)
                        kiblnd_fail_fmr_pool_set(&net->ibn_fmr_ps, &zombie_fpo);
        }

        cfs_write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
 out:
        if (!cfs_list_empty(&zombie_tpo))
                kiblnd_destroy_pool_list(&zombie_tpo);
        if (!cfs_list_empty(&zombie_ppo))
                kiblnd_destroy_pool_list(&zombie_ppo);
        if (!cfs_list_empty(&zombie_fpo))
                kiblnd_destroy_fmr_pool_list(&zombie_fpo);
        if (hdev != NULL)
                kiblnd_hdev_decref(hdev);

        if (rc != 0)
                dev->ibd_failed_failover++;
        else
                dev->ibd_failed_failover = 0;

        return rc;
}

void
kiblnd_destroy_dev (kib_dev_t *dev)
{
        LASSERT (dev->ibd_nnets == 0);
        LASSERT (cfs_list_empty(&dev->ibd_nets));

        cfs_list_del(&dev->ibd_fail_list);
        cfs_list_del(&dev->ibd_list);

        if (dev->ibd_hdev != NULL)
                kiblnd_hdev_decref(dev->ibd_hdev);

        LIBCFS_FREE(dev, sizeof(*dev));
}

kib_dev_t *
kiblnd_create_dev(char *ifname)
{
        struct net_device *netdev;
        kib_dev_t         *dev;
        __u32              netmask;
        __u32              ip;
        int                up;
        int                rc;

        rc = libcfs_ipif_query(ifname, &up, &ip, &netmask);
        if (rc != 0) {
                CERROR("Can't query IPoIB interface %s: %d\n",
                       ifname, rc);
                return NULL;
        }

        if (!up) {
                CERROR("Can't query IPoIB interface %s: it's down\n", ifname);
                return NULL;
        }

        LIBCFS_ALLOC(dev, sizeof(*dev));
        if (dev == NULL)
                return NULL;

        memset(dev, 0, sizeof(*dev));
#ifdef HAVE_DEV_GET_BY_NAME_2ARG
        if ((netdev = dev_get_by_name(&init_net, ifname)) == NULL) {
#else
        if ((netdev = dev_get_by_name(ifname)) == NULL) {
#endif
                CERROR("Can't find netdev of IF: %s\n", ifname);
                LIBCFS_FREE(dev, sizeof(*dev));
                return NULL;
        }

        dev->ibd_can_failover = !!(netdev->flags & IFF_MASTER);
        dev_put(netdev);

        CFS_INIT_LIST_HEAD(&dev->ibd_nets);
        CFS_INIT_LIST_HEAD(&dev->ibd_list); /* not yet in kib_devs */
        CFS_INIT_LIST_HEAD(&dev->ibd_fail_list);
        dev->ibd_ifip = ip;
        strcpy(&dev->ibd_ifname[0], ifname);

        /* initialize the device */
        rc = kiblnd_dev_failover(dev);
        if (rc != 0) {
                CERROR("Can't initialize device: %d\n", rc);
                LIBCFS_FREE(dev, sizeof(*dev));
                return NULL;
        }

        cfs_list_add_tail(&dev->ibd_list,
                          &kiblnd_data.kib_devs);
        return dev;
}

void
kiblnd_base_shutdown (void)
{
        int i;

        LASSERT (cfs_list_empty(&kiblnd_data.kib_devs));

        CDEBUG(D_MALLOC, "before LND base cleanup: kmem %d\n",
               cfs_atomic_read(&libcfs_kmemory));

        switch (kiblnd_data.kib_init) {
        default:
                LBUG();

        case IBLND_INIT_ALL:
        case IBLND_INIT_DATA:
                LASSERT (kiblnd_data.kib_peers != NULL);
                for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {
                        LASSERT (cfs_list_empty(&kiblnd_data.kib_peers[i]));
                }
                LASSERT (cfs_list_empty(&kiblnd_data.kib_connd_zombies));
                LASSERT (cfs_list_empty(&kiblnd_data.kib_connd_conns));

                /* flag threads to terminate; wake and wait for them to die */
                kiblnd_data.kib_shutdown = 1;
                cfs_waitq_broadcast(&kiblnd_data.kib_sched_waitq);
                cfs_waitq_broadcast(&kiblnd_data.kib_connd_waitq);
                cfs_waitq_broadcast(&kiblnd_data.kib_failover_waitq);

                i = 2;
                while (cfs_atomic_read(&kiblnd_data.kib_nthreads) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "Waiting for %d threads to terminate\n",
                               cfs_atomic_read(&kiblnd_data.kib_nthreads));
                        cfs_pause(cfs_time_seconds(1));
                }

                /* fall through */

        case IBLND_INIT_NOTHING:
                break;
        }

        if (kiblnd_data.kib_peers != NULL)
                LIBCFS_FREE(kiblnd_data.kib_peers,
                            sizeof(cfs_list_t) *
                            kiblnd_data.kib_peer_hash_size);

        CDEBUG(D_MALLOC, "after LND base cleanup: kmem %d\n",
               cfs_atomic_read(&libcfs_kmemory));

        kiblnd_data.kib_init = IBLND_INIT_NOTHING;
        PORTAL_MODULE_UNUSE;
}

void
kiblnd_shutdown (lnet_ni_t *ni)
{
        kib_net_t        *net = ni->ni_data;
        cfs_rwlock_t     *g_lock = &kiblnd_data.kib_global_lock;
        int               i;
        unsigned long     flags;

        LASSERT(kiblnd_data.kib_init == IBLND_INIT_ALL);

        if (net == NULL)
                goto out;

        CDEBUG(D_MALLOC, "before LND net cleanup: kmem %d\n",
               cfs_atomic_read(&libcfs_kmemory));

        cfs_write_lock_irqsave(g_lock, flags);
        net->ibn_shutdown = 1;
        cfs_write_unlock_irqrestore(g_lock, flags);

        switch (net->ibn_init) {
        default:
                LBUG();

        case IBLND_INIT_ALL:
                /* nuke all existing peers within this net */
                kiblnd_del_peer(ni, LNET_NID_ANY);

                /* Wait for all peer state to clean up */
                i = 2;
                while (cfs_atomic_read(&net->ibn_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* 2**n? */
                               "%s: waiting for %d peers to disconnect\n",
                               libcfs_nid2str(ni->ni_nid),
                               cfs_atomic_read(&net->ibn_npeers));
                        cfs_pause(cfs_time_seconds(1));
                }

                kiblnd_ni_fini_pools(net);

                cfs_write_lock_irqsave(g_lock, flags);
                LASSERT (net->ibn_dev->ibd_nnets > 0);
                net->ibn_dev->ibd_nnets--;
                cfs_list_del(&net->ibn_list);
                cfs_write_unlock_irqrestore(g_lock, flags);

                /* fall through */

        case IBLND_INIT_NOTHING:
                LASSERT (cfs_atomic_read(&net->ibn_nconns) == 0);

                if (net->ibn_dev != NULL &&
                    net->ibn_dev->ibd_nnets == 0)
                        kiblnd_destroy_dev(net->ibn_dev);

                break;
        }

        CDEBUG(D_MALLOC, "after LND net cleanup: kmem %d\n",
               cfs_atomic_read(&libcfs_kmemory));

        net->ibn_init = IBLND_INIT_NOTHING;
        ni->ni_data = NULL;

        LIBCFS_FREE(net, sizeof(*net));

out:
        if (cfs_list_empty(&kiblnd_data.kib_devs))
                kiblnd_base_shutdown();
        return;
}

int
kiblnd_base_startup (void)
{
        int i;
        int rc;

        LASSERT (kiblnd_data.kib_init == IBLND_INIT_NOTHING);

        PORTAL_MODULE_USE;
        memset(&kiblnd_data, 0, sizeof(kiblnd_data)); /* zero pointers, flags etc */

        cfs_rwlock_init(&kiblnd_data.kib_global_lock);

        CFS_INIT_LIST_HEAD(&kiblnd_data.kib_devs);
        CFS_INIT_LIST_HEAD(&kiblnd_data.kib_failed_devs);

        kiblnd_data.kib_peer_hash_size = IBLND_PEER_HASH_SIZE;
        LIBCFS_ALLOC(kiblnd_data.kib_peers,
                     sizeof(cfs_list_t) *
                            kiblnd_data.kib_peer_hash_size);
        if (kiblnd_data.kib_peers == NULL) {
                goto failed;
        }
        for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++)
                CFS_INIT_LIST_HEAD(&kiblnd_data.kib_peers[i]);

        cfs_spin_lock_init(&kiblnd_data.kib_connd_lock);
        CFS_INIT_LIST_HEAD(&kiblnd_data.kib_connd_conns);
        CFS_INIT_LIST_HEAD(&kiblnd_data.kib_connd_zombies);
        cfs_waitq_init(&kiblnd_data.kib_connd_waitq);

        cfs_spin_lock_init(&kiblnd_data.kib_sched_lock);
        CFS_INIT_LIST_HEAD(&kiblnd_data.kib_sched_conns);
        cfs_waitq_init(&kiblnd_data.kib_sched_waitq);
        cfs_waitq_init(&kiblnd_data.kib_failover_waitq);

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

        if (*kiblnd_tunables.kib_dev_failover != 0)
                rc = kiblnd_thread_start(kiblnd_failover_thread, NULL);

        if (rc != 0) {
                CERROR("Can't spawn o2iblnd failover thread: %d\n", rc);
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
        kib_dev_t                *ibdev = NULL;
        kib_net_t                *net;
        cfs_list_t               *tmp;
        struct timeval            tv;
        unsigned long             flags;
        int                       rc;

        LASSERT (ni->ni_lnd == &the_o2iblnd);

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

        cfs_gettimeofday(&tv);
        net->ibn_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

        ni->ni_peertimeout    = *kiblnd_tunables.kib_peertimeout;
        ni->ni_maxtxcredits   = *kiblnd_tunables.kib_credits;
        ni->ni_peertxcredits  = *kiblnd_tunables.kib_peertxcredits;
        ni->ni_peerrtrcredits = *kiblnd_tunables.kib_peerrtrcredits;

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

        cfs_list_for_each (tmp, &kiblnd_data.kib_devs) {
                ibdev = cfs_list_entry(tmp, kib_dev_t, ibd_list);

                if (!strcmp(&ibdev->ibd_ifname[0], ifname))
                        break;

                ibdev = NULL;
        }

        if (ibdev == NULL)
                ibdev = kiblnd_create_dev(ifname);

        if (ibdev == NULL)
                goto failed;

        net->ibn_dev = ibdev;
        ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), ibdev->ibd_ifip);

        rc = kiblnd_net_init_pools(net);
        if (rc != 0) {
                CERROR("Failed to initialize NI pools: %d\n", rc);
                goto failed;
        }

        cfs_write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
        ibdev->ibd_nnets++;
        cfs_list_add_tail(&net->ibn_list, &ibdev->ibd_nets);
        cfs_write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

        net->ibn_init = IBLND_INIT_ALL;

        return 0;

failed:
        if (net->ibn_dev == NULL && ibdev != NULL)
                kiblnd_destroy_dev(ibdev);

        kiblnd_shutdown(ni);

        CDEBUG(D_NET, "kiblnd_startup failed\n");
        return -ENETDOWN;
}

void __exit
kiblnd_module_fini (void)
{
        lnet_unregister_lnd(&the_o2iblnd);
        kiblnd_tunables_fini();
}

int __init
kiblnd_module_init (void)
{
        int    rc;

        CLASSERT (sizeof(kib_msg_t) <= IBLND_MSG_SIZE);
        CLASSERT (offsetof(kib_msg_t, ibm_u.get.ibgm_rd.rd_frags[IBLND_MAX_RDMA_FRAGS])
                  <= IBLND_MSG_SIZE);
        CLASSERT (offsetof(kib_msg_t, ibm_u.putack.ibpam_rd.rd_frags[IBLND_MAX_RDMA_FRAGS])
                  <= IBLND_MSG_SIZE);

        rc = kiblnd_tunables_init();
        if (rc != 0)
                return rc;

        lnet_register_lnd(&the_o2iblnd);

        return 0;
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Kernel OpenIB gen2 LND v2.00");
MODULE_LICENSE("GPL");

module_init(kiblnd_module_init);
module_exit(kiblnd_module_fini);
