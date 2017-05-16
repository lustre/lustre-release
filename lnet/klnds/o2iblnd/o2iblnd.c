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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/o2iblnd/o2iblnd.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include <asm/page.h>
#include "o2iblnd.h"

static struct lnet_lnd the_o2iblnd;

kib_data_t              kiblnd_data;

static __u32
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
kiblnd_pack_msg(struct lnet_ni *ni, kib_msg_t *msg, int version,
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
                /* leave magic unflipped as a clue to peer_ni endianness */
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
kiblnd_create_peer(struct lnet_ni *ni, kib_peer_ni_t **peerp, lnet_nid_t nid)
{
	kib_peer_ni_t	*peer_ni;
	kib_net_t	*net = ni->ni_data;
	int		cpt = lnet_cpt_of_nid(nid, ni);
	unsigned long   flags;

	LASSERT(net != NULL);
	LASSERT(nid != LNET_NID_ANY);

	LIBCFS_CPT_ALLOC(peer_ni, lnet_cpt_table(), cpt, sizeof(*peer_ni));
        if (peer_ni == NULL) {
                CERROR("Cannot allocate peer_ni\n");
                return -ENOMEM;
        }

	peer_ni->ibp_ni = ni;
	peer_ni->ibp_nid = nid;
	peer_ni->ibp_error = 0;
	peer_ni->ibp_last_alive = 0;
	peer_ni->ibp_max_frags = kiblnd_cfg_rdma_frags(peer_ni->ibp_ni);
	peer_ni->ibp_queue_depth = ni->ni_net->net_tunables.lct_peer_tx_credits;
	atomic_set(&peer_ni->ibp_refcount, 1);	/* 1 ref for caller */

	INIT_LIST_HEAD(&peer_ni->ibp_list);	/* not in the peer_ni table yet */
	INIT_LIST_HEAD(&peer_ni->ibp_conns);
	INIT_LIST_HEAD(&peer_ni->ibp_tx_queue);

	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	/* always called with a ref on ni, which prevents ni being shutdown */
	LASSERT(net->ibn_shutdown == 0);

	/* npeers only grows with the global lock held */
	atomic_inc(&net->ibn_npeers);

	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	*peerp = peer_ni;
	return 0;
}

void
kiblnd_destroy_peer (kib_peer_ni_t *peer_ni)
{
	kib_net_t *net = peer_ni->ibp_ni->ni_data;

	LASSERT(net != NULL);
	LASSERT (atomic_read(&peer_ni->ibp_refcount) == 0);
	LASSERT(!kiblnd_peer_active(peer_ni));
	LASSERT(kiblnd_peer_idle(peer_ni));
	LASSERT(list_empty(&peer_ni->ibp_tx_queue));

	LIBCFS_FREE(peer_ni, sizeof(*peer_ni));

	/* NB a peer_ni's connections keep a reference on their peer_ni until
	 * they are destroyed, so we can be assured that _all_ state to do
	 * with this peer_ni has been cleaned up when its refcount drops to
	 * zero. */
	atomic_dec(&net->ibn_npeers);
}

kib_peer_ni_t *
kiblnd_find_peer_locked(struct lnet_ni *ni, lnet_nid_t nid)
{
	/* the caller is responsible for accounting the additional reference
	 * that this creates */
	struct list_head	*peer_list = kiblnd_nid2peerlist(nid);
	struct list_head	*tmp;
	kib_peer_ni_t		*peer_ni;

	list_for_each(tmp, peer_list) {

		peer_ni = list_entry(tmp, kib_peer_ni_t, ibp_list);
		LASSERT(!kiblnd_peer_idle(peer_ni));

		/*
		 * Match a peer if its NID and the NID of the local NI it
		 * communicates over are the same. Otherwise don't match
		 * the peer, which will result in a new lnd peer being
		 * created.
		 */
		if (peer_ni->ibp_nid != nid ||
		    peer_ni->ibp_ni->ni_nid != ni->ni_nid)
			continue;

		CDEBUG(D_NET, "got peer_ni [%p] -> %s (%d) version: %x\n",
		       peer_ni, libcfs_nid2str(nid),
		       atomic_read(&peer_ni->ibp_refcount),
		       peer_ni->ibp_version);
		return peer_ni;
	}
	return NULL;
}

void
kiblnd_unlink_peer_locked (kib_peer_ni_t *peer_ni)
{
	LASSERT(list_empty(&peer_ni->ibp_conns));

        LASSERT (kiblnd_peer_active(peer_ni));
	list_del_init(&peer_ni->ibp_list);
        /* lose peerlist's ref */
        kiblnd_peer_decref(peer_ni);
}

static int
kiblnd_get_peer_info(struct lnet_ni *ni, int index,
		     lnet_nid_t *nidp, int *count)
{
	kib_peer_ni_t		*peer_ni;
	struct list_head	*ptmp;
	int			 i;
	unsigned long		 flags;

	read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {

		list_for_each(ptmp, &kiblnd_data.kib_peers[i]) {

			peer_ni = list_entry(ptmp, kib_peer_ni_t, ibp_list);
			LASSERT(!kiblnd_peer_idle(peer_ni));

			if (peer_ni->ibp_ni != ni)
				continue;

			if (index-- > 0)
				continue;

			*nidp = peer_ni->ibp_nid;
			*count = atomic_read(&peer_ni->ibp_refcount);

			read_unlock_irqrestore(&kiblnd_data.kib_global_lock,
					       flags);
			return 0;
		}
	}

	read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
	return -ENOENT;
}

static void
kiblnd_del_peer_locked (kib_peer_ni_t *peer_ni)
{
	struct list_head	*ctmp;
	struct list_head	*cnxt;
	kib_conn_t		*conn;

	if (list_empty(&peer_ni->ibp_conns)) {
		kiblnd_unlink_peer_locked(peer_ni);
	} else {
		list_for_each_safe(ctmp, cnxt, &peer_ni->ibp_conns) {
			conn = list_entry(ctmp, kib_conn_t, ibc_list);

			kiblnd_close_conn_locked(conn, 0);
		}
		/* NB closing peer_ni's last conn unlinked it. */
	}
	/* NB peer_ni now unlinked; might even be freed if the peer_ni table had the
	 * last ref on it. */
}

static int
kiblnd_del_peer(struct lnet_ni *ni, lnet_nid_t nid)
{
	struct list_head	zombies = LIST_HEAD_INIT(zombies);
	struct list_head	*ptmp;
	struct list_head	*pnxt;
	kib_peer_ni_t		*peer_ni;
	int			lo;
	int			hi;
	int			i;
	unsigned long		flags;
	int			rc = -ENOENT;

	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        if (nid != LNET_NID_ANY) {
                lo = hi = kiblnd_nid2peerlist(nid) - kiblnd_data.kib_peers;
        } else {
                lo = 0;
                hi = kiblnd_data.kib_peer_hash_size - 1;
        }

	for (i = lo; i <= hi; i++) {
		list_for_each_safe(ptmp, pnxt, &kiblnd_data.kib_peers[i]) {
			peer_ni = list_entry(ptmp, kib_peer_ni_t, ibp_list);
			LASSERT(!kiblnd_peer_idle(peer_ni));

			if (peer_ni->ibp_ni != ni)
				continue;

			if (!(nid == LNET_NID_ANY || peer_ni->ibp_nid == nid))
				continue;

			if (!list_empty(&peer_ni->ibp_tx_queue)) {
				LASSERT(list_empty(&peer_ni->ibp_conns));

				list_splice_init(&peer_ni->ibp_tx_queue,
						 &zombies);
			}

			kiblnd_del_peer_locked(peer_ni);
			rc = 0;		/* matched something */
		}
	}

	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	kiblnd_txlist_done(&zombies, -EIO);

	return rc;
}

static kib_conn_t *
kiblnd_get_conn_by_idx(struct lnet_ni *ni, int index)
{
	kib_peer_ni_t		*peer_ni;
	struct list_head	*ptmp;
	kib_conn_t		*conn;
	struct list_head	*ctmp;
	int			i;
	unsigned long		flags;

	read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {
		list_for_each(ptmp, &kiblnd_data.kib_peers[i]) {

			peer_ni = list_entry(ptmp, kib_peer_ni_t, ibp_list);
			LASSERT(!kiblnd_peer_idle(peer_ni));

			if (peer_ni->ibp_ni != ni)
				continue;

			list_for_each(ctmp, &peer_ni->ibp_conns) {
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

static void
kiblnd_debug_rx (kib_rx_t *rx)
{
        CDEBUG(D_CONSOLE, "      %p status %d msg_type %x cred %d\n",
               rx, rx->rx_status, rx->rx_msg->ibm_type,
               rx->rx_msg->ibm_credits);
}

static void
kiblnd_debug_tx (kib_tx_t *tx)
{
        CDEBUG(D_CONSOLE, "      %p snd %d q %d w %d rc %d dl %lx "
	       "cookie %#llx msg %s%s type %x cred %d\n",
               tx, tx->tx_sending, tx->tx_queued, tx->tx_waiting,
               tx->tx_status, tx->tx_deadline, tx->tx_cookie,
               tx->tx_lntmsg[0] == NULL ? "-" : "!",
               tx->tx_lntmsg[1] == NULL ? "-" : "!",
               tx->tx_msg->ibm_type, tx->tx_msg->ibm_credits);
}

void
kiblnd_debug_conn (kib_conn_t *conn)
{
	struct list_head	*tmp;
	int			i;

	spin_lock(&conn->ibc_lock);

	CDEBUG(D_CONSOLE, "conn[%d] %p [version %x] -> %s:\n",
	       atomic_read(&conn->ibc_refcount), conn,
	       conn->ibc_version, libcfs_nid2str(conn->ibc_peer->ibp_nid));
	CDEBUG(D_CONSOLE, "   state %d nposted %d/%d cred %d o_cred %d "
	       " r_cred %d\n", conn->ibc_state, conn->ibc_noops_posted,
	       conn->ibc_nsends_posted, conn->ibc_credits,
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
	for (i = 0; i < IBLND_RX_MSGS(conn); i++)
		kiblnd_debug_rx(&conn->ibc_rxs[i]);

	spin_unlock(&conn->ibc_lock);
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

static int
kiblnd_get_completion_vector(kib_conn_t *conn, int cpt)
{
	cpumask_t	*mask;
	int		vectors;
	int		off;
	int		i;
	lnet_nid_t	ibp_nid;

	vectors = conn->ibc_cmid->device->num_comp_vectors;
	if (vectors <= 1)
		return 0;

	mask = cfs_cpt_cpumask(lnet_cpt_table(), cpt);

	/* hash NID to CPU id in this partition... */
	ibp_nid = conn->ibc_peer->ibp_nid;
	off = do_div(ibp_nid, cpumask_weight(mask));
	for_each_cpu(i, mask) {
		if (off-- == 0)
			return i % vectors;
	}

	LBUG();
	return 1;
}

/*
 * Get the scheduler bound to this CPT. If the scheduler has no
 * threads, which means that the CPT has no CPUs, then grab the
 * next scheduler that we can use.
 *
 * This case would be triggered if a NUMA node is configured with
 * no associated CPUs.
 */
static struct kib_sched_info *
kiblnd_get_scheduler(int cpt)
{
	struct kib_sched_info *sched;
	int i;

	sched = kiblnd_data.kib_scheds[cpt];

	if (sched->ibs_nthreads > 0)
		return sched;

	cfs_percpt_for_each(sched, i, kiblnd_data.kib_scheds) {
		if (sched->ibs_nthreads > 0) {
			CDEBUG(D_NET, "scheduler[%d] has no threads. selected scheduler[%d]\n",
					cpt, sched->ibs_cpt);
			return sched;
		}
	}

	return NULL;
}

kib_conn_t *
kiblnd_create_conn(kib_peer_ni_t *peer_ni, struct rdma_cm_id *cmid,
		   int state, int version)
{
	/* CAVEAT EMPTOR:
	 * If the new conn is created successfully it takes over the caller's
	 * ref on 'peer_ni'.  It also "owns" 'cmid' and destroys it when it itself
	 * is destroyed.  On failure, the caller's ref on 'peer_ni' remains and
	 * she must dispose of 'cmid'.  (Actually I'd block forever if I tried
	 * to destroy 'cmid' here since I'm called from the CM which still has
	 * its ref on 'cmid'). */
	rwlock_t	       *glock = &kiblnd_data.kib_global_lock;
	kib_net_t              *net = peer_ni->ibp_ni->ni_data;
	kib_dev_t              *dev;
	struct ib_qp_init_attr *init_qp_attr;
	struct kib_sched_info	*sched;
#ifdef HAVE_IB_CQ_INIT_ATTR
	struct ib_cq_init_attr  cq_attr = {};
#endif
	kib_conn_t		*conn;
	struct ib_cq		*cq;
	unsigned long		flags;
	int			cpt;
	int			rc;
	int			i;

	LASSERT(net != NULL);
	LASSERT(!in_interrupt());

	dev = net->ibn_dev;

	cpt = lnet_cpt_of_nid(peer_ni->ibp_nid, peer_ni->ibp_ni);
	sched = kiblnd_get_scheduler(cpt);

	if (sched == NULL) {
		CERROR("no schedulers available. node is unhealthy\n");
		goto failed_0;
	}

	/*
	 * The cpt might have changed if we ended up selecting a non cpt
	 * native scheduler. So use the scheduler's cpt instead.
	 */
	cpt = sched->ibs_cpt;

	LIBCFS_CPT_ALLOC(init_qp_attr, lnet_cpt_table(), cpt,
			 sizeof(*init_qp_attr));
	if (init_qp_attr == NULL) {
		CERROR("Can't allocate qp_attr for %s\n",
		       libcfs_nid2str(peer_ni->ibp_nid));
		goto failed_0;
	}

	LIBCFS_CPT_ALLOC(conn, lnet_cpt_table(), cpt, sizeof(*conn));
	if (conn == NULL) {
		CERROR("Can't allocate connection for %s\n",
		       libcfs_nid2str(peer_ni->ibp_nid));
		goto failed_1;
	}

	conn->ibc_state = IBLND_CONN_INIT;
	conn->ibc_version = version;
	conn->ibc_peer = peer_ni;			/* I take the caller's ref */
	cmid->context = conn;			/* for future CM callbacks */
	conn->ibc_cmid = cmid;
	conn->ibc_max_frags = peer_ni->ibp_max_frags;
	conn->ibc_queue_depth = peer_ni->ibp_queue_depth;

	INIT_LIST_HEAD(&conn->ibc_early_rxs);
	INIT_LIST_HEAD(&conn->ibc_tx_noops);
	INIT_LIST_HEAD(&conn->ibc_tx_queue);
	INIT_LIST_HEAD(&conn->ibc_tx_queue_rsrvd);
	INIT_LIST_HEAD(&conn->ibc_tx_queue_nocred);
	INIT_LIST_HEAD(&conn->ibc_active_txs);
	spin_lock_init(&conn->ibc_lock);

	LIBCFS_CPT_ALLOC(conn->ibc_connvars, lnet_cpt_table(), cpt,
			 sizeof(*conn->ibc_connvars));
	if (conn->ibc_connvars == NULL) {
		CERROR("Can't allocate in-progress connection state\n");
		goto failed_2;
	}

	write_lock_irqsave(glock, flags);
	if (dev->ibd_failover) {
		write_unlock_irqrestore(glock, flags);
		CERROR("%s: failover in progress\n", dev->ibd_ifname);
		goto failed_2;
	}

	if (dev->ibd_hdev->ibh_ibdev != cmid->device) {
		/* wakeup failover thread and teardown connection */
		if (kiblnd_dev_can_failover(dev)) {
			list_add_tail(&dev->ibd_fail_list,
				      &kiblnd_data.kib_failed_devs);
			wake_up(&kiblnd_data.kib_failover_waitq);
		}

		write_unlock_irqrestore(glock, flags);
		CERROR("cmid HCA(%s), kib_dev(%s) need failover\n",
		       cmid->device->name, dev->ibd_ifname);
		goto failed_2;
	}

        kiblnd_hdev_addref_locked(dev->ibd_hdev);
        conn->ibc_hdev = dev->ibd_hdev;

        kiblnd_setup_mtu_locked(cmid);

	write_unlock_irqrestore(glock, flags);

	LIBCFS_CPT_ALLOC(conn->ibc_rxs, lnet_cpt_table(), cpt,
			 IBLND_RX_MSGS(conn) * sizeof(kib_rx_t));
	if (conn->ibc_rxs == NULL) {
		CERROR("Cannot allocate RX buffers\n");
		goto failed_2;
	}

	rc = kiblnd_alloc_pages(&conn->ibc_rx_pages, cpt,
				IBLND_RX_MSG_PAGES(conn));
	if (rc != 0)
		goto failed_2;

	kiblnd_map_rx_descs(conn);

#ifdef HAVE_IB_CQ_INIT_ATTR
	cq_attr.cqe = IBLND_CQ_ENTRIES(conn);
	cq_attr.comp_vector = kiblnd_get_completion_vector(conn, cpt);
	cq = ib_create_cq(cmid->device,
			  kiblnd_cq_completion, kiblnd_cq_event, conn,
			  &cq_attr);
#else
	cq = ib_create_cq(cmid->device,
			  kiblnd_cq_completion, kiblnd_cq_event, conn,
			  IBLND_CQ_ENTRIES(conn),
			  kiblnd_get_completion_vector(conn, cpt));
#endif
	if (IS_ERR(cq)) {
		CERROR("Failed to create CQ with %d CQEs: %ld\n",
			IBLND_CQ_ENTRIES(conn), PTR_ERR(cq));
		goto failed_2;
	}

        conn->ibc_cq = cq;

	rc = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (rc != 0) {
		CERROR("Can't request completion notification: %d\n", rc);
		goto failed_2;
	}

	init_qp_attr->event_handler = kiblnd_qp_event;
	init_qp_attr->qp_context = conn;
	init_qp_attr->cap.max_send_wr = IBLND_SEND_WRS(conn);
	init_qp_attr->cap.max_recv_wr = IBLND_RECV_WRS(conn);
	init_qp_attr->cap.max_send_sge = *kiblnd_tunables.kib_wrq_sge;
	init_qp_attr->cap.max_recv_sge = 1;
	init_qp_attr->sq_sig_type = IB_SIGNAL_REQ_WR;
	init_qp_attr->qp_type = IB_QPT_RC;
	init_qp_attr->send_cq = cq;
	init_qp_attr->recv_cq = cq;

	conn->ibc_sched = sched;

	do {
		rc = rdma_create_qp(cmid, conn->ibc_hdev->ibh_pd, init_qp_attr);
		if (!rc || init_qp_attr->cap.max_send_wr < 16)
			break;

		init_qp_attr->cap.max_send_wr -= init_qp_attr->cap.max_send_wr / 4;
	} while (rc);

	if (rc) {
		CERROR("Can't create QP: %d, send_wr: %d, recv_wr: %d, "
		       "send_sge: %d, recv_sge: %d\n",
		       rc, init_qp_attr->cap.max_send_wr,
		       init_qp_attr->cap.max_recv_wr,
		       init_qp_attr->cap.max_send_sge,
		       init_qp_attr->cap.max_recv_sge);
		goto failed_2;
	}

	if (init_qp_attr->cap.max_send_wr != IBLND_SEND_WRS(conn))
		CDEBUG(D_NET, "original send wr %d, created with %d\n",
			IBLND_SEND_WRS(conn), init_qp_attr->cap.max_send_wr);

	LIBCFS_FREE(init_qp_attr, sizeof(*init_qp_attr));

	/* 1 ref for caller and each rxmsg */
	atomic_set(&conn->ibc_refcount, 1 + IBLND_RX_MSGS(conn));
	conn->ibc_nrx = IBLND_RX_MSGS(conn);

	/* post receives */
	for (i = 0; i < IBLND_RX_MSGS(conn); i++) {
		rc = kiblnd_post_rx(&conn->ibc_rxs[i], IBLND_POSTRX_NO_CREDIT);
		if (rc != 0) {
			CERROR("Can't post rxmsg: %d\n", rc);

			/* Make posted receives complete */
			kiblnd_abort_receives(conn);

			/* correct # of posted buffers
			 * NB locking needed now I'm racing with completion */
			spin_lock_irqsave(&sched->ibs_lock, flags);
			conn->ibc_nrx -= IBLND_RX_MSGS(conn) - i;
			spin_unlock_irqrestore(&sched->ibs_lock, flags);

                        /* cmid will be destroyed by CM(ofed) after cm_callback
                         * returned, so we can't refer it anymore
                         * (by kiblnd_connd()->kiblnd_destroy_conn) */
                        rdma_destroy_qp(conn->ibc_cmid);
                        conn->ibc_cmid = NULL;

			/* Drop my own and unused rxbuffer refcounts */
			while (i++ <= IBLND_RX_MSGS(conn))
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
	kiblnd_destroy_conn(conn, true);
 failed_1:
        LIBCFS_FREE(init_qp_attr, sizeof(*init_qp_attr));
 failed_0:
        return NULL;
}

void
kiblnd_destroy_conn(kib_conn_t *conn, bool free_conn)
{
	struct rdma_cm_id *cmid = conn->ibc_cmid;
	kib_peer_ni_t        *peer_ni = conn->ibc_peer;
	int                rc;

	LASSERT (!in_interrupt());
	LASSERT (atomic_read(&conn->ibc_refcount) == 0);
	LASSERT(list_empty(&conn->ibc_early_rxs));
	LASSERT(list_empty(&conn->ibc_tx_noops));
	LASSERT(list_empty(&conn->ibc_tx_queue));
	LASSERT(list_empty(&conn->ibc_tx_queue_rsrvd));
	LASSERT(list_empty(&conn->ibc_tx_queue_nocred));
	LASSERT(list_empty(&conn->ibc_active_txs));
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
			    IBLND_RX_MSGS(conn) * sizeof(kib_rx_t));
	}

	if (conn->ibc_connvars != NULL)
		LIBCFS_FREE(conn->ibc_connvars, sizeof(*conn->ibc_connvars));

	if (conn->ibc_hdev != NULL)
		kiblnd_hdev_decref(conn->ibc_hdev);

	/* See CAVEAT EMPTOR above in kiblnd_create_conn */
	if (conn->ibc_state != IBLND_CONN_INIT) {
		kib_net_t *net = peer_ni->ibp_ni->ni_data;

		kiblnd_peer_decref(peer_ni);
		rdma_destroy_id(cmid);
		atomic_dec(&net->ibn_nconns);
	}

	if (free_conn)
		LIBCFS_FREE(conn, sizeof(*conn));
}

int
kiblnd_close_peer_conns_locked(kib_peer_ni_t *peer_ni, int why)
{
	kib_conn_t		*conn;
	struct list_head	*ctmp;
	struct list_head	*cnxt;
	int			count = 0;

	list_for_each_safe(ctmp, cnxt, &peer_ni->ibp_conns) {
		conn = list_entry(ctmp, kib_conn_t, ibc_list);

		CDEBUG(D_NET, "Closing conn -> %s, "
			      "version: %x, reason: %d\n",
		       libcfs_nid2str(peer_ni->ibp_nid),
		       conn->ibc_version, why);

		kiblnd_close_conn_locked(conn, why);
		count++;
	}

	return count;
}

int
kiblnd_close_stale_conns_locked(kib_peer_ni_t *peer_ni,
				int version, __u64 incarnation)
{
	kib_conn_t		*conn;
	struct list_head	*ctmp;
	struct list_head	*cnxt;
	int			count = 0;

	list_for_each_safe(ctmp, cnxt, &peer_ni->ibp_conns) {
		conn = list_entry(ctmp, kib_conn_t, ibc_list);

		if (conn->ibc_version     == version &&
		    conn->ibc_incarnation == incarnation)
			continue;

		CDEBUG(D_NET, "Closing stale conn -> %s version: %x, "
			      "incarnation:%#llx(%x, %#llx)\n",
		       libcfs_nid2str(peer_ni->ibp_nid),
		       conn->ibc_version, conn->ibc_incarnation,
		       version, incarnation);

		kiblnd_close_conn_locked(conn, -ESTALE);
		count++;
	}

	return count;
}

static int
kiblnd_close_matching_conns(struct lnet_ni *ni, lnet_nid_t nid)
{
	kib_peer_ni_t		*peer_ni;
	struct list_head	*ptmp;
	struct list_head	*pnxt;
	int			lo;
	int			hi;
	int			i;
	unsigned long		flags;
	int			count = 0;

	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	if (nid != LNET_NID_ANY)
		lo = hi = kiblnd_nid2peerlist(nid) - kiblnd_data.kib_peers;
	else {
		lo = 0;
		hi = kiblnd_data.kib_peer_hash_size - 1;
	}

	for (i = lo; i <= hi; i++) {
		list_for_each_safe(ptmp, pnxt, &kiblnd_data.kib_peers[i]) {

			peer_ni = list_entry(ptmp, kib_peer_ni_t, ibp_list);
			LASSERT(!kiblnd_peer_idle(peer_ni));

			if (peer_ni->ibp_ni != ni)
				continue;

			if (!(nid == LNET_NID_ANY || nid == peer_ni->ibp_nid))
				continue;

			count += kiblnd_close_peer_conns_locked(peer_ni, 0);
		}
	}

	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	/* wildcards always succeed */
	if (nid == LNET_NID_ANY)
		return 0;

	return (count == 0) ? -ENOENT : 0;
}

static int
kiblnd_ctl(struct lnet_ni *ni, unsigned int cmd, void *arg)
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

		LASSERT(conn->ibc_cmid != NULL);
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

static void
kiblnd_query(struct lnet_ni *ni, lnet_nid_t nid, cfs_time_t *when)
{
	cfs_time_t	last_alive = 0;
	cfs_time_t	now = cfs_time_current();
	rwlock_t	*glock = &kiblnd_data.kib_global_lock;
	kib_peer_ni_t	*peer_ni;
	unsigned long	flags;

	read_lock_irqsave(glock, flags);

	peer_ni = kiblnd_find_peer_locked(ni, nid);
	if (peer_ni != NULL)
		last_alive = peer_ni->ibp_last_alive;

	read_unlock_irqrestore(glock, flags);

	if (last_alive != 0)
		*when = last_alive;

	/* peer_ni is not persistent in hash, trigger peer_ni creation
	 * and connection establishment with a NULL tx */
	if (peer_ni == NULL)
		kiblnd_launch_tx(ni, NULL, nid);

	CDEBUG(D_NET, "peer_ni %s %p, alive %ld secs ago\n",
	       libcfs_nid2str(nid), peer_ni,
	       last_alive ? cfs_duration_sec(now - last_alive) : -1);
	return;
}

static void
kiblnd_free_pages(kib_pages_t *p)
{
	int	npages = p->ibp_npages;
	int	i;

	for (i = 0; i < npages; i++) {
		if (p->ibp_pages[i] != NULL)
			__free_page(p->ibp_pages[i]);
	}

	LIBCFS_FREE(p, offsetof(kib_pages_t, ibp_pages[npages]));
}

int
kiblnd_alloc_pages(kib_pages_t **pp, int cpt, int npages)
{
	kib_pages_t	*p;
	int		i;

	LIBCFS_CPT_ALLOC(p, lnet_cpt_table(), cpt,
			 offsetof(kib_pages_t, ibp_pages[npages]));
        if (p == NULL) {
                CERROR("Can't allocate descriptor for %d pages\n", npages);
                return -ENOMEM;
        }

        memset(p, 0, offsetof(kib_pages_t, ibp_pages[npages]));
        p->ibp_npages = npages;

        for (i = 0; i < npages; i++) {
		p->ibp_pages[i] = cfs_page_cpt_alloc(lnet_cpt_table(), cpt,
						     GFP_NOFS);
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

	for (i = 0; i < IBLND_RX_MSGS(conn); i++) {
		rx = &conn->ibc_rxs[i];

		LASSERT(rx->rx_nob >= 0); /* not posted */

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

	for (pg_off = ipg = i = 0; i < IBLND_RX_MSGS(conn); i++) {
		pg = conn->ibc_rx_pages->ibp_pages[ipg];
		rx = &conn->ibc_rxs[i];

		rx->rx_conn = conn;
		rx->rx_msg = (kib_msg_t *)(((char *)page_address(pg)) + pg_off);

		rx->rx_msgaddr =
			kiblnd_dma_map_single(conn->ibc_hdev->ibh_ibdev,
					      rx->rx_msg, IBLND_MSG_SIZE,
					      DMA_FROM_DEVICE);
		LASSERT(!kiblnd_dma_mapping_error(conn->ibc_hdev->ibh_ibdev,
						  rx->rx_msgaddr));
		KIBLND_UNMAP_ADDR_SET(rx, rx_msgunmap, rx->rx_msgaddr);

		CDEBUG(D_NET, "rx %d: %p %#llx(%#llx)\n",
		       i, rx->rx_msg, rx->rx_msgaddr,
		       (__u64)(page_to_phys(pg) + pg_off));

		pg_off += IBLND_MSG_SIZE;
		LASSERT(pg_off <= PAGE_SIZE);

		if (pg_off == PAGE_SIZE) {
			pg_off = 0;
			ipg++;
			LASSERT(ipg <= IBLND_RX_MSG_PAGES(conn));
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

	read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
	while (dev->ibd_failover) {
		read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
		if (i++ % 50 == 0)
			CDEBUG(D_NET, "%s: Wait for failover\n",
			       dev->ibd_ifname);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1) / 100);

		read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
	}

	kiblnd_hdev_addref_locked(dev->ibd_hdev);
	hdev = dev->ibd_hdev;

	read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	return hdev;
}

static void
kiblnd_map_tx_pool(kib_tx_pool_t *tpo)
{
        kib_pages_t    *txpgs = tpo->tpo_tx_pages;
        kib_pool_t     *pool  = &tpo->tpo_pool;
        kib_net_t      *net   = pool->po_owner->ps_net;
	kib_dev_t      *dev;
        struct page    *page;
        kib_tx_t       *tx;
        int             page_offset;
        int             ipage;
        int             i;

        LASSERT (net != NULL);

	dev = net->ibn_dev;

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

		tx->tx_msgaddr = kiblnd_dma_map_single(tpo->tpo_hdev->ibh_ibdev,
						       tx->tx_msg,
						       IBLND_MSG_SIZE,
						       DMA_TO_DEVICE);
		LASSERT(!kiblnd_dma_mapping_error(tpo->tpo_hdev->ibh_ibdev,
						  tx->tx_msgaddr));
		KIBLND_UNMAP_ADDR_SET(tx, tx_msgunmap, tx->tx_msgaddr);

		list_add(&tx->tx_list, &pool->po_free_list);

		page_offset += IBLND_MSG_SIZE;
		LASSERT(page_offset <= PAGE_SIZE);

		if (page_offset == PAGE_SIZE) {
			page_offset = 0;
			ipage++;
			LASSERT(ipage <= txpgs->ibp_npages);
		}
	}
}

#ifdef HAVE_IB_GET_DMA_MR
struct ib_mr *
kiblnd_find_rd_dma_mr(struct lnet_ni *ni, kib_rdma_desc_t *rd,
		      int negotiated_nfrags)
{
	kib_net_t     *net   = ni->ni_data;
	kib_hca_dev_t *hdev  = net->ibn_dev->ibd_hdev;
	struct lnet_ioctl_config_o2iblnd_tunables *tunables;
	int	mod;
	__u16	nfrags;

	tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib;
	mod = tunables->lnd_map_on_demand;
	nfrags = (negotiated_nfrags != -1) ? negotiated_nfrags : mod;

	LASSERT(hdev->ibh_mrs != NULL);

	if (mod > 0 && nfrags <= rd->rd_nfrags)
		return NULL;

	return hdev->ibh_mrs;
}
#endif

static void
kiblnd_destroy_fmr_pool(kib_fmr_pool_t *fpo)
{
	LASSERT(fpo->fpo_map_count == 0);

	if (fpo->fpo_is_fmr) {
		if (fpo->fmr.fpo_fmr_pool)
			ib_destroy_fmr_pool(fpo->fmr.fpo_fmr_pool);
	} else {
		struct kib_fast_reg_descriptor *frd, *tmp;
		int i = 0;

		list_for_each_entry_safe(frd, tmp, &fpo->fast_reg.fpo_pool_list,
					 frd_list) {
			list_del(&frd->frd_list);
#ifndef HAVE_IB_MAP_MR_SG
			ib_free_fast_reg_page_list(frd->frd_frpl);
#endif
			ib_dereg_mr(frd->frd_mr);
			LIBCFS_FREE(frd, sizeof(*frd));
			i++;
		}
		if (i < fpo->fast_reg.fpo_pool_size)
			CERROR("FastReg pool still has %d regions registered\n",
				fpo->fast_reg.fpo_pool_size - i);
	}

	if (fpo->fpo_hdev)
		kiblnd_hdev_decref(fpo->fpo_hdev);

	LIBCFS_FREE(fpo, sizeof(*fpo));
}

static void
kiblnd_destroy_fmr_pool_list(struct list_head *head)
{
	kib_fmr_pool_t *fpo, *tmp;

	list_for_each_entry_safe(fpo, tmp, head, fpo_list) {
		list_del(&fpo->fpo_list);
		kiblnd_destroy_fmr_pool(fpo);
	}
}

static int
kiblnd_fmr_pool_size(struct lnet_ioctl_config_o2iblnd_tunables *tunables,
		     int ncpts)
{
	int size = tunables->lnd_fmr_pool_size / ncpts;

	return max(IBLND_FMR_POOL, size);
}

static int
kiblnd_fmr_flush_trigger(struct lnet_ioctl_config_o2iblnd_tunables *tunables,
			 int ncpts)
{
	int size = tunables->lnd_fmr_flush_trigger / ncpts;

	return max(IBLND_FMR_POOL_FLUSH, size);
}

static int kiblnd_alloc_fmr_pool(kib_fmr_poolset_t *fps, kib_fmr_pool_t *fpo)
{
	struct ib_fmr_pool_param param = {
		.max_pages_per_fmr = LNET_MAX_PAYLOAD/PAGE_SIZE,
		.page_shift        = PAGE_SHIFT,
		.access            = (IB_ACCESS_LOCAL_WRITE |
				      IB_ACCESS_REMOTE_WRITE),
		.pool_size	   = fps->fps_pool_size,
		.dirty_watermark   = fps->fps_flush_trigger,
		.flush_function    = NULL,
		.flush_arg         = NULL,
		.cache             = !!fps->fps_cache };
	int rc = 0;

	fpo->fmr.fpo_fmr_pool = ib_create_fmr_pool(fpo->fpo_hdev->ibh_pd,
						   &param);
	if (IS_ERR(fpo->fmr.fpo_fmr_pool)) {
		rc = PTR_ERR(fpo->fmr.fpo_fmr_pool);
		if (rc != -ENOSYS)
			CERROR("Failed to create FMR pool: %d\n", rc);
		else
			CERROR("FMRs are not supported\n");
	}

	return rc;
}

static int kiblnd_alloc_freg_pool(kib_fmr_poolset_t *fps, kib_fmr_pool_t *fpo)
{
	struct kib_fast_reg_descriptor *frd, *tmp;
	int i, rc;

	INIT_LIST_HEAD(&fpo->fast_reg.fpo_pool_list);
	fpo->fast_reg.fpo_pool_size = 0;
	for (i = 0; i < fps->fps_pool_size; i++) {
		LIBCFS_CPT_ALLOC(frd, lnet_cpt_table(), fps->fps_cpt,
				 sizeof(*frd));
		if (!frd) {
			CERROR("Failed to allocate a new fast_reg descriptor\n");
			rc = -ENOMEM;
			goto out;
		}
		frd->frd_mr = NULL;

#ifndef HAVE_IB_MAP_MR_SG
		frd->frd_frpl = ib_alloc_fast_reg_page_list(fpo->fpo_hdev->ibh_ibdev,
							    LNET_MAX_PAYLOAD/PAGE_SIZE);
		if (IS_ERR(frd->frd_frpl)) {
			rc = PTR_ERR(frd->frd_frpl);
			CERROR("Failed to allocate ib_fast_reg_page_list: %d\n",
				rc);
			frd->frd_frpl = NULL;
			goto out_middle;
		}
#endif

#ifdef HAVE_IB_ALLOC_FAST_REG_MR
		frd->frd_mr = ib_alloc_fast_reg_mr(fpo->fpo_hdev->ibh_pd,
						   LNET_MAX_PAYLOAD/PAGE_SIZE);
#else
		frd->frd_mr = ib_alloc_mr(fpo->fpo_hdev->ibh_pd,
					  IB_MR_TYPE_MEM_REG,
					  LNET_MAX_PAYLOAD/PAGE_SIZE);
#endif
		if (IS_ERR(frd->frd_mr)) {
			rc = PTR_ERR(frd->frd_mr);
			CERROR("Failed to allocate ib_fast_reg_mr: %d\n", rc);
			frd->frd_mr = NULL;
			goto out_middle;
		}

		/* There appears to be a bug in MLX5 code where you must
		 * invalidate the rkey of a new FastReg pool before first
		 * using it. Thus, I am marking the FRD invalid here. */
		frd->frd_valid = false;

		list_add_tail(&frd->frd_list, &fpo->fast_reg.fpo_pool_list);
		fpo->fast_reg.fpo_pool_size++;
	}

	return 0;

out_middle:
	if (frd->frd_mr)
		ib_dereg_mr(frd->frd_mr);
#ifndef HAVE_IB_MAP_MR_SG
	if (frd->frd_frpl)
		ib_free_fast_reg_page_list(frd->frd_frpl);
#endif
	LIBCFS_FREE(frd, sizeof(*frd));

out:
	list_for_each_entry_safe(frd, tmp, &fpo->fast_reg.fpo_pool_list,
				 frd_list) {
		list_del(&frd->frd_list);
#ifndef HAVE_IB_MAP_MR_SG
		ib_free_fast_reg_page_list(frd->frd_frpl);
#endif
		ib_dereg_mr(frd->frd_mr);
		LIBCFS_FREE(frd, sizeof(*frd));
	}

	return rc;
}

static int
kiblnd_create_fmr_pool(kib_fmr_poolset_t *fps, kib_fmr_pool_t **pp_fpo)
{
	struct ib_device_attr *dev_attr;
	kib_dev_t *dev = fps->fps_net->ibn_dev;
	kib_fmr_pool_t *fpo;
	int rc;

#ifndef HAVE_IB_DEVICE_ATTRS
	dev_attr = kmalloc(sizeof(*dev_attr), GFP_KERNEL);
	if (!dev_attr)
		return -ENOMEM;
#endif

	LIBCFS_CPT_ALLOC(fpo, lnet_cpt_table(), fps->fps_cpt, sizeof(*fpo));
	if (!fpo) {
		rc = -ENOMEM;
		goto out_dev_attr;
	}

	fpo->fpo_hdev = kiblnd_current_hdev(dev);

#ifdef HAVE_IB_DEVICE_ATTRS
	dev_attr = &fpo->fpo_hdev->ibh_ibdev->attrs;
#else
	rc = ib_query_device(fpo->fpo_hdev->ibh_ibdev, dev_attr);
	if (rc) {
		CERROR("Query device failed for %s: %d\n",
			fpo->fpo_hdev->ibh_ibdev->name, rc);
		goto out_dev_attr;
	}
#endif

	/* Check for FMR or FastReg support */
	fpo->fpo_is_fmr = 0;
	if (fpo->fpo_hdev->ibh_ibdev->alloc_fmr &&
	    fpo->fpo_hdev->ibh_ibdev->dealloc_fmr &&
	    fpo->fpo_hdev->ibh_ibdev->map_phys_fmr &&
	    fpo->fpo_hdev->ibh_ibdev->unmap_fmr) {
		LCONSOLE_INFO("Using FMR for registration\n");
		fpo->fpo_is_fmr = 1;
	} else if (dev_attr->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS) {
		LCONSOLE_INFO("Using FastReg for registration\n");
	} else {
		rc = -ENOSYS;
		LCONSOLE_ERROR_MSG(rc, "IB device does not support FMRs nor FastRegs, can't register memory\n");
		goto out_dev_attr;
	}

	if (fpo->fpo_is_fmr)
		rc = kiblnd_alloc_fmr_pool(fps, fpo);
	else
		rc = kiblnd_alloc_freg_pool(fps, fpo);
	if (rc)
		goto out_fpo;

#ifndef HAVE_IB_DEVICE_ATTRS
	kfree(dev_attr);
#endif
	fpo->fpo_deadline = cfs_time_shift(IBLND_POOL_DEADLINE);
	fpo->fpo_owner    = fps;
	*pp_fpo = fpo;

	return 0;

out_fpo:
	kiblnd_hdev_decref(fpo->fpo_hdev);
	LIBCFS_FREE(fpo, sizeof(*fpo));

out_dev_attr:
#ifndef HAVE_IB_DEVICE_ATTRS
	kfree(dev_attr);
#endif

	return rc;
}

static void
kiblnd_fail_fmr_poolset(kib_fmr_poolset_t *fps, struct list_head *zombies)
{
	if (fps->fps_net == NULL) /* intialized? */
		return;

	spin_lock(&fps->fps_lock);

	while (!list_empty(&fps->fps_pool_list)) {
		kib_fmr_pool_t *fpo = list_entry(fps->fps_pool_list.next,
                                                 kib_fmr_pool_t, fpo_list);
		fpo->fpo_failed = 1;
		list_del(&fpo->fpo_list);
		if (fpo->fpo_map_count == 0)
			list_add(&fpo->fpo_list, zombies);
		else
			list_add(&fpo->fpo_list, &fps->fps_failed_pool_list);
	}

	spin_unlock(&fps->fps_lock);
}

static void
kiblnd_fini_fmr_poolset(kib_fmr_poolset_t *fps)
{
	if (fps->fps_net != NULL) { /* initialized? */
		kiblnd_destroy_fmr_pool_list(&fps->fps_failed_pool_list);
		kiblnd_destroy_fmr_pool_list(&fps->fps_pool_list);
	}
}

static int
kiblnd_init_fmr_poolset(kib_fmr_poolset_t *fps, int cpt, int ncpts,
			kib_net_t *net,
			struct lnet_ioctl_config_o2iblnd_tunables *tunables)
{
	kib_fmr_pool_t *fpo;
	int		rc;

	memset(fps, 0, sizeof(kib_fmr_poolset_t));

	fps->fps_net = net;
	fps->fps_cpt = cpt;

	fps->fps_pool_size = kiblnd_fmr_pool_size(tunables, ncpts);
	fps->fps_flush_trigger = kiblnd_fmr_flush_trigger(tunables, ncpts);
	fps->fps_cache = tunables->lnd_fmr_cache;

	spin_lock_init(&fps->fps_lock);
	INIT_LIST_HEAD(&fps->fps_pool_list);
	INIT_LIST_HEAD(&fps->fps_failed_pool_list);

	rc = kiblnd_create_fmr_pool(fps, &fpo);
	if (rc == 0)
		list_add_tail(&fpo->fpo_list, &fps->fps_pool_list);

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

static int
kiblnd_map_tx_pages(kib_tx_t *tx, kib_rdma_desc_t *rd)
{
	kib_hca_dev_t	*hdev;
	__u64		*pages = tx->tx_pages;
	int		npages;
	int		size;
	int		i;

	hdev = tx->tx_pool->tpo_hdev;

	for (i = 0, npages = 0; i < rd->rd_nfrags; i++) {
		for (size = 0; size <  rd->rd_frags[i].rf_nob;
			size += hdev->ibh_page_size) {
			pages[npages++] = (rd->rd_frags[i].rf_addr &
					   hdev->ibh_page_mask) + size;
		}
	}

	return npages;
}

void
kiblnd_fmr_pool_unmap(kib_fmr_t *fmr, int status)
{
	struct list_head   zombies = LIST_HEAD_INIT(zombies);
	kib_fmr_pool_t    *fpo = fmr->fmr_pool;
	kib_fmr_poolset_t *fps;
	cfs_time_t         now = cfs_time_current();
	kib_fmr_pool_t    *tmp;
	int                rc;

	if (!fpo)
		return;

	fps = fpo->fpo_owner;
	if (fpo->fpo_is_fmr) {
		if (fmr->fmr_pfmr) {
			rc = ib_fmr_pool_unmap(fmr->fmr_pfmr);
			LASSERT(!rc);
			fmr->fmr_pfmr = NULL;
		}

		if (status) {
			rc = ib_flush_fmr_pool(fpo->fmr.fpo_fmr_pool);
			LASSERT(!rc);
		}
	} else {
		struct kib_fast_reg_descriptor *frd = fmr->fmr_frd;

		if (frd) {
			frd->frd_valid = false;
			spin_lock(&fps->fps_lock);
			list_add_tail(&frd->frd_list, &fpo->fast_reg.fpo_pool_list);
			spin_unlock(&fps->fps_lock);
			fmr->fmr_frd = NULL;
		}
	}
	fmr->fmr_pool = NULL;

	spin_lock(&fps->fps_lock);
	fpo->fpo_map_count--;	/* decref the pool */

	list_for_each_entry_safe(fpo, tmp, &fps->fps_pool_list, fpo_list) {
		/* the first pool is persistent */
		if (fps->fps_pool_list.next == &fpo->fpo_list)
			continue;

		if (kiblnd_fmr_pool_is_idle(fpo, now)) {
			list_move(&fpo->fpo_list, &zombies);
			fps->fps_version++;
		}
	}
	spin_unlock(&fps->fps_lock);

	if (!list_empty(&zombies))
		kiblnd_destroy_fmr_pool_list(&zombies);
}

int
kiblnd_fmr_pool_map(kib_fmr_poolset_t *fps, kib_tx_t *tx, kib_rdma_desc_t *rd,
		    __u32 nob, __u64 iov, kib_fmr_t *fmr, bool *is_fastreg)
{
	kib_fmr_pool_t *fpo;
	__u64 *pages = tx->tx_pages;
	__u64 version;
	bool is_rx = (rd != tx->tx_rd);
	bool tx_pages_mapped = 0;
	int npages = 0;
	int rc;

again:
	spin_lock(&fps->fps_lock);
	version = fps->fps_version;
	list_for_each_entry(fpo, &fps->fps_pool_list, fpo_list) {
		fpo->fpo_deadline = cfs_time_shift(IBLND_POOL_DEADLINE);
		fpo->fpo_map_count++;

		if (fpo->fpo_is_fmr) {
			struct ib_pool_fmr *pfmr;

			*is_fastreg = 0;
			spin_unlock(&fps->fps_lock);

			if (!tx_pages_mapped) {
				npages = kiblnd_map_tx_pages(tx, rd);
				tx_pages_mapped = 1;
			}

			pfmr = ib_fmr_pool_map_phys(fpo->fmr.fpo_fmr_pool,
						    pages, npages, iov);
			if (likely(!IS_ERR(pfmr))) {
				fmr->fmr_key  = is_rx ? pfmr->fmr->rkey
						      : pfmr->fmr->lkey;
				fmr->fmr_frd  = NULL;
				fmr->fmr_pfmr = pfmr;
				fmr->fmr_pool = fpo;
				return 0;
			}
			rc = PTR_ERR(pfmr);
		} else {
			*is_fastreg = 1;
			if (!list_empty(&fpo->fast_reg.fpo_pool_list)) {
				struct kib_fast_reg_descriptor *frd;
#ifdef HAVE_IB_MAP_MR_SG
				struct ib_reg_wr *wr;
				int n;
#else
				struct ib_rdma_wr *wr;
				struct ib_fast_reg_page_list *frpl;
#endif
				struct ib_mr *mr;

				frd = list_first_entry(&fpo->fast_reg.fpo_pool_list,
							struct kib_fast_reg_descriptor,
							frd_list);
				list_del(&frd->frd_list);
				spin_unlock(&fps->fps_lock);

#ifndef HAVE_IB_MAP_MR_SG
				frpl = frd->frd_frpl;
#endif
				mr   = frd->frd_mr;

				if (!frd->frd_valid) {
					struct ib_rdma_wr *inv_wr;
					__u32 key = is_rx ? mr->rkey : mr->lkey;

					inv_wr = &frd->frd_inv_wr;
					memset(inv_wr, 0, sizeof(*inv_wr));

					inv_wr->wr.opcode = IB_WR_LOCAL_INV;
					inv_wr->wr.wr_id  = IBLND_WID_MR;
					inv_wr->wr.ex.invalidate_rkey = key;

					/* Bump the key */
					key = ib_inc_rkey(key);
					ib_update_fast_reg_key(mr, key);
				}

#ifdef HAVE_IB_MAP_MR_SG
#ifdef HAVE_IB_MAP_MR_SG_5ARGS
				n = ib_map_mr_sg(mr, tx->tx_frags,
						 tx->tx_nfrags, NULL, PAGE_SIZE);
#else
				n = ib_map_mr_sg(mr, tx->tx_frags,
						 tx->tx_nfrags, PAGE_SIZE);
#endif
				if (unlikely(n != tx->tx_nfrags)) {
					CERROR("Failed to map mr %d/%d "
					       "elements\n", n, tx->tx_nfrags);
					return n < 0 ? n : -EINVAL;
				}

				wr = &frd->frd_fastreg_wr;
				memset(wr, 0, sizeof(*wr));

				wr->wr.opcode = IB_WR_REG_MR;
				wr->wr.wr_id  = IBLND_WID_MR;
				wr->wr.num_sge = 0;
				wr->wr.send_flags = 0;
				wr->mr = mr;
				wr->key = is_rx ? mr->rkey : mr->lkey;
				wr->access = (IB_ACCESS_LOCAL_WRITE |
					      IB_ACCESS_REMOTE_WRITE);
#else
				if (!tx_pages_mapped) {
					npages = kiblnd_map_tx_pages(tx, rd);
					tx_pages_mapped = 1;
				}

				LASSERT(npages <= frpl->max_page_list_len);
				memcpy(frpl->page_list, pages,
					sizeof(*pages) * npages);

				/* Prepare FastReg WR */
				wr = &frd->frd_fastreg_wr;
				memset(wr, 0, sizeof(*wr));

				wr->wr.opcode = IB_WR_FAST_REG_MR;
				wr->wr.wr_id  = IBLND_WID_MR;

				wr->wr.wr.fast_reg.iova_start = iov;
				wr->wr.wr.fast_reg.page_list  = frpl;
				wr->wr.wr.fast_reg.page_list_len = npages;
				wr->wr.wr.fast_reg.page_shift = PAGE_SHIFT;
				wr->wr.wr.fast_reg.length = nob;
				wr->wr.wr.fast_reg.rkey =
						is_rx ? mr->rkey : mr->lkey;
				wr->wr.wr.fast_reg.access_flags =
						(IB_ACCESS_LOCAL_WRITE |
						 IB_ACCESS_REMOTE_WRITE);
#endif

				fmr->fmr_key  = is_rx ? mr->rkey : mr->lkey;
				fmr->fmr_frd  = frd;
				fmr->fmr_pfmr = NULL;
				fmr->fmr_pool = fpo;
				return 0;
			}
			spin_unlock(&fps->fps_lock);
			rc = -EAGAIN;
		}

		spin_lock(&fps->fps_lock);
		fpo->fpo_map_count--;
		if (rc != -EAGAIN) {
			spin_unlock(&fps->fps_lock);
			return rc;
		}

		/* EAGAIN and ... */
		if (version != fps->fps_version) {
			spin_unlock(&fps->fps_lock);
			goto again;
		}
	}

	if (fps->fps_increasing) {
		spin_unlock(&fps->fps_lock);
		CDEBUG(D_NET, "Another thread is allocating new "
		       "FMR pool, waiting for her to complete\n");
		schedule();
		goto again;

	}

	if (cfs_time_before(cfs_time_current(), fps->fps_next_retry)) {
		/* someone failed recently */
		spin_unlock(&fps->fps_lock);
		return -EAGAIN;
	}

	fps->fps_increasing = 1;
	spin_unlock(&fps->fps_lock);

	CDEBUG(D_NET, "Allocate new FMR pool\n");
	rc = kiblnd_create_fmr_pool(fps, &fpo);
	spin_lock(&fps->fps_lock);
	fps->fps_increasing = 0;
	if (rc == 0) {
		fps->fps_version++;
		list_add_tail(&fpo->fpo_list, &fps->fps_pool_list);
	} else {
		fps->fps_next_retry = cfs_time_shift(IBLND_POOL_RETRY);
	}
	spin_unlock(&fps->fps_lock);

	goto again;
}

static void
kiblnd_fini_pool(kib_pool_t *pool)
{
	LASSERT(list_empty(&pool->po_free_list));
	LASSERT(pool->po_allocated == 0);

	CDEBUG(D_NET, "Finalize %s pool\n", pool->po_owner->ps_name);
}

static void
kiblnd_init_pool(kib_poolset_t *ps, kib_pool_t *pool, int size)
{
	CDEBUG(D_NET, "Initialize %s pool\n", ps->ps_name);

	memset(pool, 0, sizeof(kib_pool_t));
	INIT_LIST_HEAD(&pool->po_free_list);
	pool->po_deadline = cfs_time_shift(IBLND_POOL_DEADLINE);
	pool->po_owner	  = ps;
	pool->po_size	  = size;
}

static void
kiblnd_destroy_pool_list(struct list_head *head)
{
	kib_pool_t *pool;

	while (!list_empty(head)) {
		pool = list_entry(head->next, kib_pool_t, po_list);
		list_del(&pool->po_list);

		LASSERT(pool->po_owner != NULL);
		pool->po_owner->ps_pool_destroy(pool);
	}
}

static void
kiblnd_fail_poolset(kib_poolset_t *ps, struct list_head *zombies)
{
	if (ps->ps_net == NULL) /* intialized? */
		return;

	spin_lock(&ps->ps_lock);
	while (!list_empty(&ps->ps_pool_list)) {
		kib_pool_t *po = list_entry(ps->ps_pool_list.next,
                                            kib_pool_t, po_list);
		po->po_failed = 1;
		list_del(&po->po_list);
		if (po->po_allocated == 0)
			list_add(&po->po_list, zombies);
		else
			list_add(&po->po_list, &ps->ps_failed_pool_list);
	}
	spin_unlock(&ps->ps_lock);
}

static void
kiblnd_fini_poolset(kib_poolset_t *ps)
{
	if (ps->ps_net != NULL) { /* initialized? */
		kiblnd_destroy_pool_list(&ps->ps_failed_pool_list);
		kiblnd_destroy_pool_list(&ps->ps_pool_list);
	}
}

static int
kiblnd_init_poolset(kib_poolset_t *ps, int cpt,
		    kib_net_t *net, char *name, int size,
		    kib_ps_pool_create_t po_create,
		    kib_ps_pool_destroy_t po_destroy,
		    kib_ps_node_init_t nd_init,
		    kib_ps_node_fini_t nd_fini)
{
	kib_pool_t	*pool;
	int		rc;

	memset(ps, 0, sizeof(kib_poolset_t));

	ps->ps_cpt	    = cpt;
        ps->ps_net          = net;
        ps->ps_pool_create  = po_create;
        ps->ps_pool_destroy = po_destroy;
        ps->ps_node_init    = nd_init;
        ps->ps_node_fini    = nd_fini;
        ps->ps_pool_size    = size;
	if (strlcpy(ps->ps_name, name, sizeof(ps->ps_name))
	    >= sizeof(ps->ps_name))
		return -E2BIG;
	spin_lock_init(&ps->ps_lock);
	INIT_LIST_HEAD(&ps->ps_pool_list);
	INIT_LIST_HEAD(&ps->ps_failed_pool_list);

	rc = ps->ps_pool_create(ps, size, &pool);
	if (rc == 0)
		list_add(&pool->po_list, &ps->ps_pool_list);
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
kiblnd_pool_free_node(kib_pool_t *pool, struct list_head *node)
{
	struct list_head zombies = LIST_HEAD_INIT(zombies);
	kib_poolset_t	*ps = pool->po_owner;
	kib_pool_t	*tmp;
	cfs_time_t	 now = cfs_time_current();

	spin_lock(&ps->ps_lock);

	if (ps->ps_node_fini != NULL)
		ps->ps_node_fini(pool, node);

	LASSERT(pool->po_allocated > 0);
	list_add(node, &pool->po_free_list);
	pool->po_allocated--;

	list_for_each_entry_safe(pool, tmp, &ps->ps_pool_list, po_list) {
		/* the first pool is persistent */
		if (ps->ps_pool_list.next == &pool->po_list)
			continue;

		if (kiblnd_pool_is_idle(pool, now))
			list_move(&pool->po_list, &zombies);
	}
	spin_unlock(&ps->ps_lock);

	if (!list_empty(&zombies))
		kiblnd_destroy_pool_list(&zombies);
}

struct list_head *
kiblnd_pool_alloc_node(kib_poolset_t *ps)
{
	struct list_head	*node;
	kib_pool_t		*pool;
	int			rc;
	unsigned int		interval = 1;
	cfs_time_t		time_before;
	unsigned int		trips = 0;

again:
	spin_lock(&ps->ps_lock);
	list_for_each_entry(pool, &ps->ps_pool_list, po_list) {
		if (list_empty(&pool->po_free_list))
			continue;

		pool->po_allocated++;
		pool->po_deadline = cfs_time_shift(IBLND_POOL_DEADLINE);
		node = pool->po_free_list.next;
		list_del(node);

		if (ps->ps_node_init != NULL) {
			/* still hold the lock */
			ps->ps_node_init(pool, node);
		}
		spin_unlock(&ps->ps_lock);
		return node;
	}

	/* no available tx pool and ... */
	if (ps->ps_increasing) {
		/* another thread is allocating a new pool */
		spin_unlock(&ps->ps_lock);
		trips++;
                CDEBUG(D_NET, "Another thread is allocating new "
		       "%s pool, waiting %d HZs for her to complete."
		       "trips = %d\n",
		       ps->ps_name, interval, trips);

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(interval);
		if (interval < cfs_time_seconds(1))
			interval *= 2;

                goto again;
        }

	if (cfs_time_before(cfs_time_current(), ps->ps_next_retry)) {
		/* someone failed recently */
		spin_unlock(&ps->ps_lock);
		return NULL;
	}

	ps->ps_increasing = 1;
	spin_unlock(&ps->ps_lock);

	CDEBUG(D_NET, "%s pool exhausted, allocate new pool\n", ps->ps_name);
	time_before = cfs_time_current();
	rc = ps->ps_pool_create(ps, ps->ps_pool_size, &pool);
	CDEBUG(D_NET, "ps_pool_create took %lu HZ to complete",
	       cfs_time_current() - time_before);

	spin_lock(&ps->ps_lock);
	ps->ps_increasing = 0;
	if (rc == 0) {
		list_add_tail(&pool->po_list, &ps->ps_pool_list);
	} else {
		ps->ps_next_retry = cfs_time_shift(IBLND_POOL_RETRY);
		CERROR("Can't allocate new %s pool because out of memory\n",
		       ps->ps_name);
	}
	spin_unlock(&ps->ps_lock);

	goto again;
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
		int	  wrq_sge = *kiblnd_tunables.kib_wrq_sge;

		list_del(&tx->tx_list);
                if (tx->tx_pages != NULL)
                        LIBCFS_FREE(tx->tx_pages,
                                    LNET_MAX_IOV *
                                    sizeof(*tx->tx_pages));
                if (tx->tx_frags != NULL)
                        LIBCFS_FREE(tx->tx_frags,
				    (1 + IBLND_MAX_RDMA_FRAGS) *
				    sizeof(*tx->tx_frags));
                if (tx->tx_wrq != NULL)
                        LIBCFS_FREE(tx->tx_wrq,
                                    (1 + IBLND_MAX_RDMA_FRAGS) *
                                    sizeof(*tx->tx_wrq));
		if (tx->tx_sge != NULL)
			LIBCFS_FREE(tx->tx_sge,
				    (1 + IBLND_MAX_RDMA_FRAGS) * wrq_sge *
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

static int kiblnd_tx_pool_size(struct lnet_ni *ni, int ncpts)
{
	struct lnet_ioctl_config_o2iblnd_tunables *tunables;
	int ntx;

	tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib;
	ntx = tunables->lnd_ntx / ncpts;

	return max(IBLND_TX_POOL, ntx);
}

static int
kiblnd_create_tx_pool(kib_poolset_t *ps, int size, kib_pool_t **pp_po)
{
        int            i;
        int            npg;
        kib_pool_t    *pool;
        kib_tx_pool_t *tpo;

	LIBCFS_CPT_ALLOC(tpo, lnet_cpt_table(), ps->ps_cpt, sizeof(*tpo));
        if (tpo == NULL) {
                CERROR("Failed to allocate TX pool\n");
                return -ENOMEM;
        }

        pool = &tpo->tpo_pool;
        kiblnd_init_pool(ps, pool, size);
        tpo->tpo_tx_descs = NULL;
        tpo->tpo_tx_pages = NULL;

        npg = (size * IBLND_MSG_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;
	if (kiblnd_alloc_pages(&tpo->tpo_tx_pages, ps->ps_cpt, npg) != 0) {
		CERROR("Can't allocate tx pages: %d\n", npg);
		LIBCFS_FREE(tpo, sizeof(kib_tx_pool_t));
		return -ENOMEM;
	}

	LIBCFS_CPT_ALLOC(tpo->tpo_tx_descs, lnet_cpt_table(), ps->ps_cpt,
			 size * sizeof(kib_tx_t));
        if (tpo->tpo_tx_descs == NULL) {
                CERROR("Can't allocate %d tx descriptors\n", size);
                ps->ps_pool_destroy(pool);
                return -ENOMEM;
        }

        memset(tpo->tpo_tx_descs, 0, size * sizeof(kib_tx_t));

        for (i = 0; i < size; i++) {
		kib_tx_t *tx = &tpo->tpo_tx_descs[i];
		int	  wrq_sge = *kiblnd_tunables.kib_wrq_sge;

                tx->tx_pool = tpo;
		if (ps->ps_net->ibn_fmr_ps != NULL) {
			LIBCFS_CPT_ALLOC(tx->tx_pages,
					 lnet_cpt_table(), ps->ps_cpt,
					 LNET_MAX_IOV * sizeof(*tx->tx_pages));
			if (tx->tx_pages == NULL)
				break;
		}

		LIBCFS_CPT_ALLOC(tx->tx_frags, lnet_cpt_table(), ps->ps_cpt,
				 (1 + IBLND_MAX_RDMA_FRAGS) *
				 sizeof(*tx->tx_frags));
		if (tx->tx_frags == NULL)
			break;

		sg_init_table(tx->tx_frags, IBLND_MAX_RDMA_FRAGS + 1);

		LIBCFS_CPT_ALLOC(tx->tx_wrq, lnet_cpt_table(), ps->ps_cpt,
				 (1 + IBLND_MAX_RDMA_FRAGS) *
				 sizeof(*tx->tx_wrq));
		if (tx->tx_wrq == NULL)
			break;

		LIBCFS_CPT_ALLOC(tx->tx_sge, lnet_cpt_table(), ps->ps_cpt,
				 (1 + IBLND_MAX_RDMA_FRAGS) * wrq_sge *
				 sizeof(*tx->tx_sge));
		if (tx->tx_sge == NULL)
			break;

		LIBCFS_CPT_ALLOC(tx->tx_rd, lnet_cpt_table(), ps->ps_cpt,
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
kiblnd_tx_init(kib_pool_t *pool, struct list_head *node)
{
	kib_tx_poolset_t *tps = container_of(pool->po_owner, kib_tx_poolset_t,
					     tps_poolset);
	kib_tx_t	 *tx  = list_entry(node, kib_tx_t, tx_list);

	tx->tx_cookie = tps->tps_next_tx_cookie++;
}

static void
kiblnd_net_fini_pools(kib_net_t *net)
{
	int	i;

	cfs_cpt_for_each(i, lnet_cpt_table()) {
		kib_tx_poolset_t	*tps;
		kib_fmr_poolset_t	*fps;

		if (net->ibn_tx_ps != NULL) {
			tps = net->ibn_tx_ps[i];
			kiblnd_fini_poolset(&tps->tps_poolset);
		}

		if (net->ibn_fmr_ps != NULL) {
			fps = net->ibn_fmr_ps[i];
			kiblnd_fini_fmr_poolset(fps);
		}
	}

	if (net->ibn_tx_ps != NULL) {
		cfs_percpt_free(net->ibn_tx_ps);
		net->ibn_tx_ps = NULL;
	}

	if (net->ibn_fmr_ps != NULL) {
		cfs_percpt_free(net->ibn_fmr_ps);
		net->ibn_fmr_ps = NULL;
	}
}

static int
kiblnd_net_init_pools(kib_net_t *net, struct lnet_ni *ni, __u32 *cpts,
		      int ncpts)
{
	struct lnet_ioctl_config_o2iblnd_tunables *tunables;
#ifdef HAVE_IB_GET_DMA_MR
	unsigned long	flags;
#endif
	int		cpt;
	int		rc;
	int		i;

	tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib;

#ifdef HAVE_IB_GET_DMA_MR
	read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
	if (tunables->lnd_map_on_demand == 0) {
		read_unlock_irqrestore(&kiblnd_data.kib_global_lock,
					   flags);
		goto create_tx_pool;
	}

	read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
#endif

	if (tunables->lnd_fmr_pool_size < tunables->lnd_ntx / 4) {
		CERROR("Can't set fmr pool size (%d) < ntx / 4(%d)\n",
		       tunables->lnd_fmr_pool_size,
		       tunables->lnd_ntx / 4);
		rc = -EINVAL;
		goto failed;
	}

	/* TX pool must be created later than FMR, see LU-2268
	 * for details */
	LASSERT(net->ibn_tx_ps == NULL);

	/* premapping can fail if ibd_nmr > 1, so we always create
	 * FMR pool and map-on-demand if premapping failed */

	net->ibn_fmr_ps = cfs_percpt_alloc(lnet_cpt_table(),
					   sizeof(kib_fmr_poolset_t));
	if (net->ibn_fmr_ps == NULL) {
		CERROR("Failed to allocate FMR pool array\n");
		rc = -ENOMEM;
		goto failed;
	}

	for (i = 0; i < ncpts; i++) {
		cpt = (cpts == NULL) ? i : cpts[i];
		rc = kiblnd_init_fmr_poolset(net->ibn_fmr_ps[cpt], cpt, ncpts,
					     net, tunables);
		if (rc != 0) {
			CERROR("Can't initialize FMR pool for CPT %d: %d\n",
			       cpt, rc);
			goto failed;
		}
	}

	if (i > 0)
		LASSERT(i == ncpts);

#ifdef HAVE_IB_GET_DMA_MR
 create_tx_pool:
#endif
	net->ibn_tx_ps = cfs_percpt_alloc(lnet_cpt_table(),
					  sizeof(kib_tx_poolset_t));
	if (net->ibn_tx_ps == NULL) {
		CERROR("Failed to allocate tx pool array\n");
		rc = -ENOMEM;
		goto failed;
	}

	for (i = 0; i < ncpts; i++) {
		cpt = (cpts == NULL) ? i : cpts[i];
		rc = kiblnd_init_poolset(&net->ibn_tx_ps[cpt]->tps_poolset,
					 cpt, net, "TX",
					 kiblnd_tx_pool_size(ni, ncpts),
					 kiblnd_create_tx_pool,
					 kiblnd_destroy_tx_pool,
					 kiblnd_tx_init, NULL);
		if (rc != 0) {
			CERROR("Can't initialize TX pool for CPT %d: %d\n",
			       cpt, rc);
			goto failed;
		}
	}

	return 0;
 failed:
	kiblnd_net_fini_pools(net);
	LASSERT(rc != 0);
	return rc;
}

static int
kiblnd_hdev_get_attr(kib_hca_dev_t *hdev)
{
#ifndef HAVE_IB_DEVICE_ATTRS
	struct ib_device_attr *attr;
	int                    rc;
#endif

        /* It's safe to assume a HCA can handle a page size
         * matching that of the native system */
        hdev->ibh_page_shift = PAGE_SHIFT;
        hdev->ibh_page_size  = 1 << PAGE_SHIFT;
        hdev->ibh_page_mask  = ~((__u64)hdev->ibh_page_size - 1);

#ifdef HAVE_IB_DEVICE_ATTRS
	hdev->ibh_mr_size = hdev->ibh_ibdev->attrs.max_mr_size;
#else
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
#endif

        if (hdev->ibh_mr_size == ~0ULL) {
                hdev->ibh_mr_shift = 64;
                return 0;
        }

	CERROR("Invalid mr size: %#llx\n", hdev->ibh_mr_size);
        return -EINVAL;
}

#ifdef HAVE_IB_GET_DMA_MR
static void
kiblnd_hdev_cleanup_mrs(kib_hca_dev_t *hdev)
{
	if (hdev->ibh_mrs == NULL)
		return;

	ib_dereg_mr(hdev->ibh_mrs);

	hdev->ibh_mrs = NULL;
}
#endif

void
kiblnd_hdev_destroy(kib_hca_dev_t *hdev)
{
#ifdef HAVE_IB_GET_DMA_MR
        kiblnd_hdev_cleanup_mrs(hdev);
#endif

        if (hdev->ibh_pd != NULL)
                ib_dealloc_pd(hdev->ibh_pd);

        if (hdev->ibh_cmid != NULL)
                rdma_destroy_id(hdev->ibh_cmid);

        LIBCFS_FREE(hdev, sizeof(*hdev));
}

#ifdef HAVE_IB_GET_DMA_MR
static int
kiblnd_hdev_setup_mrs(kib_hca_dev_t *hdev)
{
	struct ib_mr *mr;
	int           rc;
	int           acflags = IB_ACCESS_LOCAL_WRITE |
				IB_ACCESS_REMOTE_WRITE;

	rc = kiblnd_hdev_get_attr(hdev);
	if (rc != 0)
		return rc;

	mr = ib_get_dma_mr(hdev->ibh_pd, acflags);
	if (IS_ERR(mr)) {
		CERROR("Failed ib_get_dma_mr: %ld\n", PTR_ERR(mr));
		kiblnd_hdev_cleanup_mrs(hdev);
		return PTR_ERR(mr);
	}

	hdev->ibh_mrs = mr;

	return 0;
}
#endif

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
	if (rc != 0 || cmid->device == NULL) {
		CERROR("Failed to bind %s:%pI4h to device(%p): %d\n",
		       dev->ibd_ifname, &dev->ibd_ifip,
		       cmid->device, rc);
                rdma_destroy_id(cmid);
                return rc;
        }

	rc = dev->ibd_hdev->ibh_ibdev != cmid->device; /* true for failover */
	rdma_destroy_id(cmid);
	return rc;
}

int
kiblnd_dev_failover(kib_dev_t *dev)
{
	struct list_head    zombie_tpo = LIST_HEAD_INIT(zombie_tpo);
	struct list_head    zombie_ppo = LIST_HEAD_INIT(zombie_ppo);
	struct list_head    zombie_fpo = LIST_HEAD_INIT(zombie_fpo);
        struct rdma_cm_id  *cmid  = NULL;
        kib_hca_dev_t      *hdev  = NULL;
        kib_hca_dev_t      *old;
        struct ib_pd       *pd;
        kib_net_t          *net;
        struct sockaddr_in  addr;
        unsigned long       flags;
        int                 rc = 0;
	int		    i;

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
		write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

		cmid = dev->ibd_hdev->ibh_cmid;
		/* make next schedule of kiblnd_dev_need_failover()
		 * return 1 for me */
		dev->ibd_hdev->ibh_cmid  = NULL;
		write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

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
	if (rc != 0 || cmid->device == NULL) {
		CERROR("Failed to bind %s:%pI4h to device(%p): %d\n",
		       dev->ibd_ifname, &dev->ibd_ifip,
		       cmid->device, rc);
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

        atomic_set(&hdev->ibh_ref, 1);
        hdev->ibh_dev   = dev;
        hdev->ibh_cmid  = cmid;
        hdev->ibh_ibdev = cmid->device;

#ifdef HAVE_IB_ALLOC_PD_2ARGS
	pd = ib_alloc_pd(cmid->device, 0);
#else
	pd = ib_alloc_pd(cmid->device);
#endif
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

#ifdef HAVE_IB_GET_DMA_MR
	rc = kiblnd_hdev_setup_mrs(hdev);
	if (rc != 0) {
		CERROR("Can't setup device: %d\n", rc);
		goto out;
	}
#else
	rc = kiblnd_hdev_get_attr(hdev);
	if (rc != 0) {
		CERROR("Can't get device attributes: %d\n", rc);
		goto out;
	}
#endif

	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	old = dev->ibd_hdev;
	dev->ibd_hdev = hdev;	/* take over the refcount */
	hdev = old;

	list_for_each_entry(net, &dev->ibd_nets, ibn_list) {
		cfs_cpt_for_each(i, lnet_cpt_table()) {
			kiblnd_fail_poolset(&net->ibn_tx_ps[i]->tps_poolset,
					    &zombie_tpo);

			if (net->ibn_fmr_ps != NULL)
				kiblnd_fail_fmr_poolset(net->ibn_fmr_ps[i],
							&zombie_fpo);
		}
	}

	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
 out:
	if (!list_empty(&zombie_tpo))
		kiblnd_destroy_pool_list(&zombie_tpo);
	if (!list_empty(&zombie_ppo))
		kiblnd_destroy_pool_list(&zombie_ppo);
	if (!list_empty(&zombie_fpo))
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
	LASSERT(list_empty(&dev->ibd_nets));

	list_del(&dev->ibd_fail_list);
	list_del(&dev->ibd_list);

        if (dev->ibd_hdev != NULL)
                kiblnd_hdev_decref(dev->ibd_hdev);

        LIBCFS_FREE(dev, sizeof(*dev));
}

static kib_dev_t *
kiblnd_create_dev(char *ifname)
{
        struct net_device *netdev;
        kib_dev_t         *dev;
        __u32              netmask;
        __u32              ip;
        int                up;
        int                rc;

	rc = lnet_ipif_query(ifname, &up, &ip, &netmask);
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

        netdev = dev_get_by_name(&init_net, ifname);
        if (netdev == NULL) {
                dev->ibd_can_failover = 0;
        } else {
                dev->ibd_can_failover = !!(netdev->flags & IFF_MASTER);
                dev_put(netdev);
        }

	INIT_LIST_HEAD(&dev->ibd_nets);
	INIT_LIST_HEAD(&dev->ibd_list); /* not yet in kib_devs */
	INIT_LIST_HEAD(&dev->ibd_fail_list);
        dev->ibd_ifip = ip;
        strcpy(&dev->ibd_ifname[0], ifname);

        /* initialize the device */
        rc = kiblnd_dev_failover(dev);
        if (rc != 0) {
                CERROR("Can't initialize device: %d\n", rc);
                LIBCFS_FREE(dev, sizeof(*dev));
                return NULL;
        }

	list_add_tail(&dev->ibd_list,
                          &kiblnd_data.kib_devs);
        return dev;
}

static void
kiblnd_base_shutdown(void)
{
	struct kib_sched_info	*sched;
	int			i;

	LASSERT(list_empty(&kiblnd_data.kib_devs));

        CDEBUG(D_MALLOC, "before LND base cleanup: kmem %d\n",
	       atomic_read(&libcfs_kmemory));

        switch (kiblnd_data.kib_init) {
        default:
                LBUG();

        case IBLND_INIT_ALL:
        case IBLND_INIT_DATA:
                LASSERT (kiblnd_data.kib_peers != NULL);
                for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {
			LASSERT(list_empty(&kiblnd_data.kib_peers[i]));
                }
		LASSERT(list_empty(&kiblnd_data.kib_connd_zombies));
		LASSERT(list_empty(&kiblnd_data.kib_connd_conns));
		LASSERT(list_empty(&kiblnd_data.kib_reconn_list));
		LASSERT(list_empty(&kiblnd_data.kib_reconn_wait));

		/* flag threads to terminate; wake and wait for them to die */
		kiblnd_data.kib_shutdown = 1;

		/* NB: we really want to stop scheduler threads net by net
		 * instead of the whole module, this should be improved
		 * with dynamic configuration LNet */
		cfs_percpt_for_each(sched, i, kiblnd_data.kib_scheds)
			wake_up_all(&sched->ibs_waitq);

		wake_up_all(&kiblnd_data.kib_connd_waitq);
		wake_up_all(&kiblnd_data.kib_failover_waitq);

		i = 2;
		while (atomic_read(&kiblnd_data.kib_nthreads) != 0) {
			i++;
			/* power of 2? */
			CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET,
			       "Waiting for %d threads to terminate\n",
			       atomic_read(&kiblnd_data.kib_nthreads));
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(cfs_time_seconds(1));
		}

                /* fall through */

        case IBLND_INIT_NOTHING:
                break;
        }

	if (kiblnd_data.kib_peers != NULL) {
		LIBCFS_FREE(kiblnd_data.kib_peers,
			    sizeof(struct list_head) *
			    kiblnd_data.kib_peer_hash_size);
	}

	if (kiblnd_data.kib_scheds != NULL)
		cfs_percpt_free(kiblnd_data.kib_scheds);

        CDEBUG(D_MALLOC, "after LND base cleanup: kmem %d\n",
	       atomic_read(&libcfs_kmemory));

	kiblnd_data.kib_init = IBLND_INIT_NOTHING;
	module_put(THIS_MODULE);
}

static void
kiblnd_shutdown(struct lnet_ni *ni)
{
        kib_net_t        *net = ni->ni_data;
	rwlock_t     *g_lock = &kiblnd_data.kib_global_lock;
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

		/* Wait for all peer_ni state to clean up */
		i = 2;
		while (atomic_read(&net->ibn_npeers) != 0) {
			i++;
			/* power of 2? */
			CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET,
			       "%s: waiting for %d peers to disconnect\n",
			       libcfs_nid2str(ni->ni_nid),
			       atomic_read(&net->ibn_npeers));
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(cfs_time_seconds(1));
		}

		kiblnd_net_fini_pools(net);

		write_lock_irqsave(g_lock, flags);
		LASSERT(net->ibn_dev->ibd_nnets > 0);
		net->ibn_dev->ibd_nnets--;
		list_del(&net->ibn_list);
		write_unlock_irqrestore(g_lock, flags);

                /* fall through */

        case IBLND_INIT_NOTHING:
		LASSERT (atomic_read(&net->ibn_nconns) == 0);

                if (net->ibn_dev != NULL &&
                    net->ibn_dev->ibd_nnets == 0)
                        kiblnd_destroy_dev(net->ibn_dev);

                break;
        }

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

static int
kiblnd_base_startup(void)
{
	struct kib_sched_info	*sched;
	int			rc;
	int			i;

	LASSERT(kiblnd_data.kib_init == IBLND_INIT_NOTHING);

	try_module_get(THIS_MODULE);
	memset(&kiblnd_data, 0, sizeof(kiblnd_data)); /* zero pointers, flags etc */

	rwlock_init(&kiblnd_data.kib_global_lock);

	INIT_LIST_HEAD(&kiblnd_data.kib_devs);
	INIT_LIST_HEAD(&kiblnd_data.kib_failed_devs);

	kiblnd_data.kib_peer_hash_size = IBLND_PEER_HASH_SIZE;
	LIBCFS_ALLOC(kiblnd_data.kib_peers,
		     sizeof(struct list_head) *
		     kiblnd_data.kib_peer_hash_size);
	if (kiblnd_data.kib_peers == NULL)
		goto failed;

	for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++)
		INIT_LIST_HEAD(&kiblnd_data.kib_peers[i]);

	spin_lock_init(&kiblnd_data.kib_connd_lock);
	INIT_LIST_HEAD(&kiblnd_data.kib_connd_conns);
	INIT_LIST_HEAD(&kiblnd_data.kib_connd_zombies);
	INIT_LIST_HEAD(&kiblnd_data.kib_reconn_list);
	INIT_LIST_HEAD(&kiblnd_data.kib_reconn_wait);

	init_waitqueue_head(&kiblnd_data.kib_connd_waitq);
	init_waitqueue_head(&kiblnd_data.kib_failover_waitq);

	kiblnd_data.kib_scheds = cfs_percpt_alloc(lnet_cpt_table(),
						  sizeof(*sched));
	if (kiblnd_data.kib_scheds == NULL)
		goto failed;

	cfs_percpt_for_each(sched, i, kiblnd_data.kib_scheds) {
		int	nthrs;

		spin_lock_init(&sched->ibs_lock);
		INIT_LIST_HEAD(&sched->ibs_conns);
		init_waitqueue_head(&sched->ibs_waitq);

		nthrs = cfs_cpt_weight(lnet_cpt_table(), i);
		if (*kiblnd_tunables.kib_nscheds > 0) {
			nthrs = min(nthrs, *kiblnd_tunables.kib_nscheds);
		} else {
			/* max to half of CPUs, another half is reserved for
			 * upper layer modules */
			nthrs = min(max(IBLND_N_SCHED, nthrs >> 1), nthrs);
		}

		sched->ibs_nthreads_max = nthrs;
		sched->ibs_cpt = i;
	}

        kiblnd_data.kib_error_qpa.qp_state = IB_QPS_ERR;

        /* lists/ptrs/locks initialised */
        kiblnd_data.kib_init = IBLND_INIT_DATA;
        /*****************************************************/

	rc = kiblnd_thread_start(kiblnd_connd, NULL, "kiblnd_connd");
        if (rc != 0) {
                CERROR("Can't spawn o2iblnd connd: %d\n", rc);
                goto failed;
        }

	if (*kiblnd_tunables.kib_dev_failover != 0)
		rc = kiblnd_thread_start(kiblnd_failover_thread, NULL,
					 "kiblnd_failover");

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

static int
kiblnd_start_schedulers(struct kib_sched_info *sched)
{
	int	rc = 0;
	int	nthrs;
	int	i;

	if (sched->ibs_nthreads == 0) {
		if (*kiblnd_tunables.kib_nscheds > 0) {
			nthrs = sched->ibs_nthreads_max;
		} else {
			nthrs = cfs_cpt_weight(lnet_cpt_table(),
					       sched->ibs_cpt);
			nthrs = min(max(IBLND_N_SCHED, nthrs >> 1), nthrs);
			nthrs = min(IBLND_N_SCHED_HIGH, nthrs);
		}
	} else {
		LASSERT(sched->ibs_nthreads <= sched->ibs_nthreads_max);
		/* increase one thread if there is new interface */
		nthrs = (sched->ibs_nthreads < sched->ibs_nthreads_max);
	}

	for (i = 0; i < nthrs; i++) {
		long	id;
		char	name[20];
		id = KIB_THREAD_ID(sched->ibs_cpt, sched->ibs_nthreads + i);
		snprintf(name, sizeof(name), "kiblnd_sd_%02ld_%02ld",
			 KIB_THREAD_CPT(id), KIB_THREAD_TID(id));
		rc = kiblnd_thread_start(kiblnd_scheduler, (void *)id, name);
		if (rc == 0)
			continue;

		CERROR("Can't spawn thread %d for scheduler[%d]: %d\n",
		       sched->ibs_cpt, sched->ibs_nthreads + i, rc);
		break;
	}

	sched->ibs_nthreads += i;
	return rc;
}

static int
kiblnd_dev_start_threads(kib_dev_t *dev, int newdev, __u32 *cpts, int ncpts)
{
	int	cpt;
	int	rc;
	int	i;

	for (i = 0; i < ncpts; i++) {
		struct kib_sched_info *sched;

		cpt = (cpts == NULL) ? i : cpts[i];
		sched = kiblnd_data.kib_scheds[cpt];

		if (!newdev && sched->ibs_nthreads > 0)
			continue;

		rc = kiblnd_start_schedulers(kiblnd_data.kib_scheds[cpt]);
		if (rc != 0) {
			CERROR("Failed to start scheduler threads for %s\n",
			       dev->ibd_ifname);
			return rc;
		}
	}
	return 0;
}

static kib_dev_t *
kiblnd_dev_search(char *ifname)
{
	kib_dev_t	*alias = NULL;
	kib_dev_t	*dev;
	char		*colon;
	char		*colon2;

	colon = strchr(ifname, ':');
	list_for_each_entry(dev, &kiblnd_data.kib_devs, ibd_list) {
		if (strcmp(&dev->ibd_ifname[0], ifname) == 0)
			return dev;

		if (alias != NULL)
			continue;

		colon2 = strchr(dev->ibd_ifname, ':');
		if (colon != NULL)
			*colon = 0;
		if (colon2 != NULL)
			*colon2 = 0;

		if (strcmp(&dev->ibd_ifname[0], ifname) == 0)
			alias = dev;

		if (colon != NULL)
			*colon = ':';
		if (colon2 != NULL)
			*colon2 = ':';
	}
	return alias;
}

static int
kiblnd_startup(struct lnet_ni *ni)
{
        char                     *ifname;
        kib_dev_t                *ibdev = NULL;
        kib_net_t                *net;
        unsigned long             flags;
        int                       rc;
	int			  newdev;
	int			  node_id;

        LASSERT (ni->ni_net->net_lnd == &the_o2iblnd);

        if (kiblnd_data.kib_init == IBLND_INIT_NOTHING) {
                rc = kiblnd_base_startup();
                if (rc != 0)
                        return rc;
        }

        LIBCFS_ALLOC(net, sizeof(*net));
        ni->ni_data = net;
        if (net == NULL)
                goto failed;

	net->ibn_incarnation = ktime_get_real_ns() / NSEC_PER_USEC;

	kiblnd_tunables_setup(ni);

	if (ni->ni_interfaces[0] != NULL) {
		/* Use the IPoIB interface specified in 'networks=' */

		CLASSERT(LNET_NUM_INTERFACES > 1);
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

	ibdev = kiblnd_dev_search(ifname);

	newdev = ibdev == NULL;
	/* hmm...create kib_dev even for alias */
	if (ibdev == NULL || strcmp(&ibdev->ibd_ifname[0], ifname) != 0)
		ibdev = kiblnd_create_dev(ifname);

	if (ibdev == NULL)
		goto failed;

	node_id = dev_to_node(ibdev->ibd_hdev->ibh_ibdev->dma_device);
	ni->ni_dev_cpt = cfs_cpt_of_node(lnet_cpt_table(), node_id);

	net->ibn_dev = ibdev;
	ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), ibdev->ibd_ifip);

	rc = kiblnd_dev_start_threads(ibdev, newdev,
				      ni->ni_cpts, ni->ni_ncpts);
	if (rc != 0)
		goto failed;

	rc = kiblnd_net_init_pools(net, ni, ni->ni_cpts, ni->ni_ncpts);
        if (rc != 0) {
                CERROR("Failed to initialize NI pools: %d\n", rc);
                goto failed;
        }

	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
	ibdev->ibd_nnets++;
	list_add_tail(&net->ibn_list, &ibdev->ibd_nets);
	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

        net->ibn_init = IBLND_INIT_ALL;

        return 0;

failed:
	if (net != NULL && net->ibn_dev == NULL && ibdev != NULL)
                kiblnd_destroy_dev(ibdev);

        kiblnd_shutdown(ni);

        CDEBUG(D_NET, "kiblnd_startup failed\n");
        return -ENETDOWN;
}

static struct lnet_lnd the_o2iblnd = {
	.lnd_type	= O2IBLND,
	.lnd_startup	= kiblnd_startup,
	.lnd_shutdown	= kiblnd_shutdown,
	.lnd_ctl	= kiblnd_ctl,
	.lnd_query	= kiblnd_query,
	.lnd_send	= kiblnd_send,
	.lnd_recv	= kiblnd_recv,
};

static void __exit ko2iblnd_exit(void)
{
	lnet_unregister_lnd(&the_o2iblnd);
}

static int __init ko2iblnd_init(void)
{
	int rc;

	CLASSERT(sizeof(kib_msg_t) <= IBLND_MSG_SIZE);
	CLASSERT(offsetof(kib_msg_t,
			  ibm_u.get.ibgm_rd.rd_frags[IBLND_MAX_RDMA_FRAGS]) <=
		 IBLND_MSG_SIZE);
	CLASSERT(offsetof(kib_msg_t,
			  ibm_u.putack.ibpam_rd.rd_frags[IBLND_MAX_RDMA_FRAGS])
		 <= IBLND_MSG_SIZE);

	rc = kiblnd_tunables_init();
	if (rc != 0)
		return rc;

	lnet_register_lnd(&the_o2iblnd);

	return 0;
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("OpenIB gen2 LNet Network Driver");
MODULE_VERSION("2.8.0");
MODULE_LICENSE("GPL");

module_init(ko2iblnd_init);
module_exit(ko2iblnd_exit);
