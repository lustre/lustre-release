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
 * Copyright (c) 2011, 2017, Intel Corporation.
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
#include <linux/inetdevice.h>

#include "o2iblnd.h"

static struct lnet_lnd the_o2iblnd;

struct kib_data kiblnd_data;

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
	const int hdr_size = offsetof(struct kib_msg, ibm_u);

        switch (type) {
        case IBLND_MSG_CONNREQ:
        case IBLND_MSG_CONNACK:
		return hdr_size + sizeof(struct kib_connparams);

        case IBLND_MSG_NOOP:
                return hdr_size;

        case IBLND_MSG_IMMEDIATE:
		return offsetof(struct kib_msg, ibm_u.immediate.ibim_payload[0]);

        case IBLND_MSG_PUT_REQ:
		return hdr_size + sizeof(struct kib_putreq_msg);

        case IBLND_MSG_PUT_ACK:
		return hdr_size + sizeof(struct kib_putack_msg);

        case IBLND_MSG_GET_REQ:
		return hdr_size + sizeof(struct kib_get_msg);

        case IBLND_MSG_PUT_NAK:
        case IBLND_MSG_PUT_DONE:
        case IBLND_MSG_GET_DONE:
		return hdr_size + sizeof(struct kib_completion_msg);
        default:
                return -1;
        }
}

static int kiblnd_unpack_rd(struct kib_msg *msg, int flip)
{
	struct kib_rdma_desc *rd;
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

	nob = offsetof(struct kib_msg, ibm_u) +
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

void kiblnd_pack_msg(struct lnet_ni *ni, struct kib_msg *msg, int version,
		     int credits, lnet_nid_t dstnid, __u64 dststamp)
{
	struct kib_net *net = ni->ni_data;

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

int kiblnd_unpack_msg(struct kib_msg *msg, int nob)
{
	const int hdr_size = offsetof(struct kib_msg, ibm_u);
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
kiblnd_create_peer(struct lnet_ni *ni, struct kib_peer_ni **peerp,
		   lnet_nid_t nid)
{
	struct kib_peer_ni *peer_ni;
	struct kib_net *net = ni->ni_data;
	int cpt = lnet_cpt_of_nid(nid, ni);
	unsigned long flags;

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
	peer_ni->ibp_max_frags = IBLND_MAX_RDMA_FRAGS;
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
kiblnd_destroy_peer(struct kib_peer_ni *peer_ni)
{
	struct kib_net *net = peer_ni->ibp_ni->ni_data;

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

struct kib_peer_ni *
kiblnd_find_peer_locked(struct lnet_ni *ni, lnet_nid_t nid)
{
	/* the caller is responsible for accounting the additional reference
	 * that this creates */
	struct list_head	*peer_list = kiblnd_nid2peerlist(nid);
	struct list_head	*tmp;
	struct kib_peer_ni		*peer_ni;

	list_for_each(tmp, peer_list) {

		peer_ni = list_entry(tmp, struct kib_peer_ni, ibp_list);
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
kiblnd_unlink_peer_locked(struct kib_peer_ni *peer_ni)
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
	struct kib_peer_ni		*peer_ni;
	struct list_head	*ptmp;
	int			 i;
	unsigned long		 flags;

	read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

        for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {

		list_for_each(ptmp, &kiblnd_data.kib_peers[i]) {

			peer_ni = list_entry(ptmp, struct kib_peer_ni, ibp_list);
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
kiblnd_del_peer_locked(struct kib_peer_ni *peer_ni)
{
	struct list_head *ctmp;
	struct list_head *cnxt;
	struct kib_conn	*conn;

	if (list_empty(&peer_ni->ibp_conns)) {
		kiblnd_unlink_peer_locked(peer_ni);
	} else {
		list_for_each_safe(ctmp, cnxt, &peer_ni->ibp_conns) {
			conn = list_entry(ctmp, struct kib_conn, ibc_list);

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
	struct kib_peer_ni		*peer_ni;
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
			peer_ni = list_entry(ptmp, struct kib_peer_ni, ibp_list);
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

	kiblnd_txlist_done(&zombies, -EIO, LNET_MSG_STATUS_LOCAL_ERROR);

	return rc;
}

static struct kib_conn *
kiblnd_get_conn_by_idx(struct lnet_ni *ni, int index)
{
	struct kib_peer_ni		*peer_ni;
	struct list_head	*ptmp;
	struct kib_conn	*conn;
	struct list_head	*ctmp;
	int			i;
	unsigned long		flags;

	read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	for (i = 0; i < kiblnd_data.kib_peer_hash_size; i++) {
		list_for_each(ptmp, &kiblnd_data.kib_peers[i]) {

			peer_ni = list_entry(ptmp, struct kib_peer_ni, ibp_list);
			LASSERT(!kiblnd_peer_idle(peer_ni));

			if (peer_ni->ibp_ni != ni)
				continue;

			list_for_each(ctmp, &peer_ni->ibp_conns) {
				if (index-- > 0)
					continue;

				conn = list_entry(ctmp, struct kib_conn, ibc_list);
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
kiblnd_debug_rx(struct kib_rx *rx)
{
        CDEBUG(D_CONSOLE, "      %p status %d msg_type %x cred %d\n",
               rx, rx->rx_status, rx->rx_msg->ibm_type,
               rx->rx_msg->ibm_credits);
}

static void
kiblnd_debug_tx(struct kib_tx *tx)
{
	CDEBUG(D_CONSOLE, "      %p snd %d q %d w %d rc %d dl %lld "
	       "cookie %#llx msg %s%s type %x cred %d\n",
               tx, tx->tx_sending, tx->tx_queued, tx->tx_waiting,
	       tx->tx_status, ktime_to_ns(tx->tx_deadline), tx->tx_cookie,
               tx->tx_lntmsg[0] == NULL ? "-" : "!",
               tx->tx_lntmsg[1] == NULL ? "-" : "!",
               tx->tx_msg->ibm_type, tx->tx_msg->ibm_credits);
}

void
kiblnd_debug_conn(struct kib_conn *conn)
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
		kiblnd_debug_rx(list_entry(tmp, struct kib_rx, rx_list));

	CDEBUG(D_CONSOLE, "   tx_noops:\n");
	list_for_each(tmp, &conn->ibc_tx_noops)
		kiblnd_debug_tx(list_entry(tmp, struct kib_tx, tx_list));

	CDEBUG(D_CONSOLE, "   tx_queue_nocred:\n");
	list_for_each(tmp, &conn->ibc_tx_queue_nocred)
		kiblnd_debug_tx(list_entry(tmp, struct kib_tx, tx_list));

	CDEBUG(D_CONSOLE, "   tx_queue_rsrvd:\n");
	list_for_each(tmp, &conn->ibc_tx_queue_rsrvd)
		kiblnd_debug_tx(list_entry(tmp, struct kib_tx, tx_list));

	CDEBUG(D_CONSOLE, "   tx_queue:\n");
	list_for_each(tmp, &conn->ibc_tx_queue)
		kiblnd_debug_tx(list_entry(tmp, struct kib_tx, tx_list));

	CDEBUG(D_CONSOLE, "   active_txs:\n");
	list_for_each(tmp, &conn->ibc_active_txs)
		kiblnd_debug_tx(list_entry(tmp, struct kib_tx, tx_list));

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
kiblnd_get_completion_vector(struct kib_conn *conn, int cpt)
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

static unsigned int kiblnd_send_wrs(struct kib_conn *conn)
{
	/*
	 * One WR for the LNet message
	 * And ibc_max_frags for the transfer WRs
	 */
	int ret;
	int multiplier = 1 + conn->ibc_max_frags;
	enum kib_dev_caps dev_caps = conn->ibc_hdev->ibh_dev->ibd_dev_caps;

	/* FastReg needs two extra WRs for map and invalidate */
	if (dev_caps & IBLND_DEV_CAPS_FASTREG_ENABLED)
		multiplier += 2;

	/* account for a maximum of ibc_queue_depth in-flight transfers */
	ret = multiplier * conn->ibc_queue_depth;

	if (ret > conn->ibc_hdev->ibh_max_qp_wr) {
		CDEBUG(D_NET, "peer_credits %u will result in send work "
		       "request size %d larger than maximum %d device "
		       "can handle\n", conn->ibc_queue_depth, ret,
		       conn->ibc_hdev->ibh_max_qp_wr);
		conn->ibc_queue_depth =
			conn->ibc_hdev->ibh_max_qp_wr / multiplier;
	}

	/* don't go beyond the maximum the device can handle */
	return min(ret, conn->ibc_hdev->ibh_max_qp_wr);
}

struct kib_conn *
kiblnd_create_conn(struct kib_peer_ni *peer_ni, struct rdma_cm_id *cmid,
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
	struct kib_net              *net = peer_ni->ibp_ni->ni_data;
	struct kib_dev *dev;
	struct ib_qp_init_attr *init_qp_attr;
	struct kib_sched_info	*sched;
#ifdef HAVE_IB_CQ_INIT_ATTR
	struct ib_cq_init_attr  cq_attr = {};
#endif
	struct kib_conn	*conn;
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
	INIT_LIST_HEAD(&conn->ibc_zombie_txs);
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
			 IBLND_RX_MSGS(conn) * sizeof(struct kib_rx));
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
		/*
		 * on MLX-5 (possibly MLX-4 as well) this error could be
		 * hit if the concurrent_sends and/or peer_tx_credits is set
		 * too high. Or due to an MLX-5 bug which tries to
		 * allocate 256kb via kmalloc for WR cookie array
		 */
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
	init_qp_attr->cap.max_send_sge = *kiblnd_tunables.kib_wrq_sge;
	init_qp_attr->cap.max_recv_sge = 1;
	init_qp_attr->sq_sig_type = IB_SIGNAL_REQ_WR;
	init_qp_attr->qp_type = IB_QPT_RC;
	init_qp_attr->send_cq = cq;
	init_qp_attr->recv_cq = cq;
	/*
	 * kiblnd_send_wrs() can change the connection's queue depth if
	 * the maximum work requests for the device is maxed out
	 */
	init_qp_attr->cap.max_send_wr = kiblnd_send_wrs(conn);
	init_qp_attr->cap.max_recv_wr = IBLND_RECV_WRS(conn);

	rc = rdma_create_qp(cmid, conn->ibc_hdev->ibh_pd, init_qp_attr);
	if (rc) {
		CERROR("Can't create QP: %d, send_wr: %d, recv_wr: %d, "
		       "send_sge: %d, recv_sge: %d\n",
		       rc, init_qp_attr->cap.max_send_wr,
		       init_qp_attr->cap.max_recv_wr,
		       init_qp_attr->cap.max_send_sge,
		       init_qp_attr->cap.max_recv_sge);
		goto failed_2;
	}

	conn->ibc_sched = sched;

	if (conn->ibc_queue_depth != peer_ni->ibp_queue_depth)
		CWARN("peer %s - queue depth reduced from %u to %u"
		      "  to allow for qp creation\n",
		      libcfs_nid2str(peer_ni->ibp_nid),
		      peer_ni->ibp_queue_depth,
		      conn->ibc_queue_depth);

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
	kiblnd_destroy_conn(conn);
	LIBCFS_FREE(conn, sizeof(*conn));
 failed_1:
        LIBCFS_FREE(init_qp_attr, sizeof(*init_qp_attr));
 failed_0:
        return NULL;
}

void
kiblnd_destroy_conn(struct kib_conn *conn)
{
	struct rdma_cm_id *cmid = conn->ibc_cmid;
	struct kib_peer_ni *peer_ni = conn->ibc_peer;

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

	if (conn->ibc_cq)
		ib_destroy_cq(conn->ibc_cq);

	kiblnd_txlist_done(&conn->ibc_zombie_txs, -ECONNABORTED,
			   LNET_MSG_STATUS_OK);

	if (conn->ibc_rx_pages != NULL)
		kiblnd_unmap_rx_descs(conn);

	if (conn->ibc_rxs != NULL) {
		LIBCFS_FREE(conn->ibc_rxs,
			    IBLND_RX_MSGS(conn) * sizeof(struct kib_rx));
	}

	if (conn->ibc_connvars != NULL)
		LIBCFS_FREE(conn->ibc_connvars, sizeof(*conn->ibc_connvars));

	if (conn->ibc_hdev != NULL)
		kiblnd_hdev_decref(conn->ibc_hdev);

	/* See CAVEAT EMPTOR above in kiblnd_create_conn */
	if (conn->ibc_state != IBLND_CONN_INIT) {
		struct kib_net *net = peer_ni->ibp_ni->ni_data;

		kiblnd_peer_decref(peer_ni);
		rdma_destroy_id(cmid);
		atomic_dec(&net->ibn_nconns);
	}
}

int
kiblnd_close_peer_conns_locked(struct kib_peer_ni *peer_ni, int why)
{
	struct kib_conn	*conn;
	struct list_head	*ctmp;
	struct list_head	*cnxt;
	int			count = 0;

	list_for_each_safe(ctmp, cnxt, &peer_ni->ibp_conns) {
		conn = list_entry(ctmp, struct kib_conn, ibc_list);

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
kiblnd_close_stale_conns_locked(struct kib_peer_ni *peer_ni,
				int version, __u64 incarnation)
{
	struct kib_conn	*conn;
	struct list_head	*ctmp;
	struct list_head	*cnxt;
	int			count = 0;

	list_for_each_safe(ctmp, cnxt, &peer_ni->ibp_conns) {
		conn = list_entry(ctmp, struct kib_conn, ibc_list);

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
	struct kib_peer_ni		*peer_ni;
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

			peer_ni = list_entry(ptmp, struct kib_peer_ni, ibp_list);
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
		struct kib_conn *conn;

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
kiblnd_query(struct lnet_ni *ni, lnet_nid_t nid, time64_t *when)
{
	time64_t last_alive = 0;
	time64_t now = ktime_get_seconds();
	rwlock_t *glock = &kiblnd_data.kib_global_lock;
	struct kib_peer_ni *peer_ni;
	unsigned long flags;

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

	CDEBUG(D_NET, "peer_ni %s %p, alive %lld secs ago\n",
	       libcfs_nid2str(nid), peer_ni,
	       last_alive ? now - last_alive : -1);
	return;
}

static void
kiblnd_free_pages(struct kib_pages *p)
{
	int	npages = p->ibp_npages;
	int	i;

	for (i = 0; i < npages; i++) {
		if (p->ibp_pages[i] != NULL)
			__free_page(p->ibp_pages[i]);
	}

	LIBCFS_FREE(p, offsetof(struct kib_pages, ibp_pages[npages]));
}

int
kiblnd_alloc_pages(struct kib_pages **pp, int cpt, int npages)
{
	struct kib_pages *p;
	int i;

	LIBCFS_CPT_ALLOC(p, lnet_cpt_table(), cpt,
			 offsetof(struct kib_pages, ibp_pages[npages]));
        if (p == NULL) {
                CERROR("Can't allocate descriptor for %d pages\n", npages);
                return -ENOMEM;
        }

	memset(p, 0, offsetof(struct kib_pages, ibp_pages[npages]));
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
kiblnd_unmap_rx_descs(struct kib_conn *conn)
{
	struct kib_rx *rx;
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
kiblnd_map_rx_descs(struct kib_conn *conn)
{
	struct kib_rx *rx;
        struct page    *pg;
        int             pg_off;
        int             ipg;
        int             i;

	for (pg_off = ipg = i = 0; i < IBLND_RX_MSGS(conn); i++) {
		pg = conn->ibc_rx_pages->ibp_pages[ipg];
		rx = &conn->ibc_rxs[i];

		rx->rx_conn = conn;
		rx->rx_msg = (struct kib_msg *)(((char *)page_address(pg)) + pg_off);

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
kiblnd_unmap_tx_pool(struct kib_tx_pool *tpo)
{
	struct kib_hca_dev *hdev = tpo->tpo_hdev;
	struct kib_tx *tx;
	int i;

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

static struct kib_hca_dev *
kiblnd_current_hdev(struct kib_dev *dev)
{
	struct kib_hca_dev *hdev;
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
kiblnd_map_tx_pool(struct kib_tx_pool *tpo)
{
	struct kib_pages *txpgs = tpo->tpo_tx_pages;
	struct kib_pool *pool = &tpo->tpo_pool;
	struct kib_net      *net   = pool->po_owner->ps_net;
	struct kib_dev *dev;
	struct page *page;
	struct kib_tx *tx;
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

		tx->tx_msg = (struct kib_msg *)(((char *)page_address(page)) +
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

static void
kiblnd_destroy_fmr_pool(struct kib_fmr_pool *fpo)
{
	LASSERT(fpo->fpo_map_count == 0);

#ifdef HAVE_FMR_POOL_API
	if (fpo->fpo_is_fmr && fpo->fmr.fpo_fmr_pool) {
		ib_destroy_fmr_pool(fpo->fmr.fpo_fmr_pool);
	} else
#endif /* HAVE_FMR_POOL_API */
	{
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
	struct kib_fmr_pool *fpo, *tmp;

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

#ifdef HAVE_FMR_POOL_API
static int kiblnd_alloc_fmr_pool(struct kib_fmr_poolset *fps,
				 struct kib_fmr_pool *fpo)
{
	struct ib_fmr_pool_param param = {
		.max_pages_per_fmr = LNET_MAX_IOV,
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
	fpo->fpo_is_fmr = true;

	return rc;
}
#endif /* HAVE_FMR_POOL_API */

static int kiblnd_alloc_freg_pool(struct kib_fmr_poolset *fps,
				  struct kib_fmr_pool *fpo,
				  enum kib_dev_caps dev_caps)
{
	struct kib_fast_reg_descriptor *frd, *tmp;
	int i, rc;

#ifdef HAVE_FMR_POOL_API
	fpo->fpo_is_fmr = false;
#endif

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
							    LNET_MAX_IOV);
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
						   LNET_MAX_IOV);
#else
		/*
		 * it is expected to get here if this is an MLX-5 card.
		 * MLX-4 cards will always use FMR and MLX-5 cards will
		 * always use fast_reg. It turns out that some MLX-5 cards
		 * (possibly due to older FW versions) do not natively support
		 * gaps. So we will need to track them here.
		 */
		frd->frd_mr = ib_alloc_mr(fpo->fpo_hdev->ibh_pd,
#ifdef IB_MR_TYPE_SG_GAPS
					  ((*kiblnd_tunables.kib_use_fastreg_gaps == 1) &&
					   (dev_caps & IBLND_DEV_CAPS_FASTREG_GAPS_SUPPORT)) ?
						IB_MR_TYPE_SG_GAPS :
						IB_MR_TYPE_MEM_REG,
#else
						IB_MR_TYPE_MEM_REG,
#endif
					  LNET_MAX_IOV);
		if ((*kiblnd_tunables.kib_use_fastreg_gaps == 1) &&
		    (dev_caps & IBLND_DEV_CAPS_FASTREG_GAPS_SUPPORT))
			CWARN("using IB_MR_TYPE_SG_GAPS, expect a performance drop\n");
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

static int kiblnd_create_fmr_pool(struct kib_fmr_poolset *fps,
				  struct kib_fmr_pool **pp_fpo)
{
	struct kib_dev *dev = fps->fps_net->ibn_dev;
	struct kib_fmr_pool *fpo;
	int rc;

	LIBCFS_CPT_ALLOC(fpo, lnet_cpt_table(), fps->fps_cpt, sizeof(*fpo));
	if (!fpo) {
		return -ENOMEM;
	}
	memset(fpo, 0, sizeof(*fpo));

	fpo->fpo_hdev = kiblnd_current_hdev(dev);

#ifdef HAVE_FMR_POOL_API
	if (dev->ibd_dev_caps & IBLND_DEV_CAPS_FMR_ENABLED)
		rc = kiblnd_alloc_fmr_pool(fps, fpo);
	else
#endif /* HAVE_FMR_POOL_API */
		rc = kiblnd_alloc_freg_pool(fps, fpo, dev->ibd_dev_caps);
	if (rc)
		goto out_fpo;

	fpo->fpo_deadline = ktime_get_seconds() + IBLND_POOL_DEADLINE;
	fpo->fpo_owner = fps;
	*pp_fpo = fpo;

	return 0;

out_fpo:
	kiblnd_hdev_decref(fpo->fpo_hdev);
	LIBCFS_FREE(fpo, sizeof(*fpo));
	return rc;
}

static void
kiblnd_fail_fmr_poolset(struct kib_fmr_poolset *fps, struct list_head *zombies)
{
	if (fps->fps_net == NULL) /* intialized? */
		return;

	spin_lock(&fps->fps_lock);

	while (!list_empty(&fps->fps_pool_list)) {
		struct kib_fmr_pool *fpo = list_entry(fps->fps_pool_list.next,
						      struct kib_fmr_pool,
						      fpo_list);

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
kiblnd_fini_fmr_poolset(struct kib_fmr_poolset *fps)
{
	if (fps->fps_net != NULL) { /* initialized? */
		kiblnd_destroy_fmr_pool_list(&fps->fps_failed_pool_list);
		kiblnd_destroy_fmr_pool_list(&fps->fps_pool_list);
	}
}

static int
kiblnd_init_fmr_poolset(struct kib_fmr_poolset *fps, int cpt, int ncpts,
			struct kib_net *net,
			struct lnet_ioctl_config_o2iblnd_tunables *tunables)
{
	struct kib_fmr_pool *fpo;
	int rc;

	memset(fps, 0, sizeof(struct kib_fmr_poolset));

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
kiblnd_fmr_pool_is_idle(struct kib_fmr_pool *fpo, time64_t now)
{
        if (fpo->fpo_map_count != 0) /* still in use */
                return 0;
        if (fpo->fpo_failed)
                return 1;
	return now >= fpo->fpo_deadline;
}

#if defined(HAVE_FMR_POOL_API) || !defined(HAVE_IB_MAP_MR_SG)
static int
kiblnd_map_tx_pages(struct kib_tx *tx, struct kib_rdma_desc *rd)
{
	struct kib_hca_dev *hdev;
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
#endif

void
kiblnd_fmr_pool_unmap(struct kib_fmr *fmr, int status)
{
	struct list_head zombies = LIST_HEAD_INIT(zombies);
	struct kib_fmr_pool *fpo = fmr->fmr_pool;
	struct kib_fmr_poolset *fps;
	time64_t now = ktime_get_seconds();
	struct kib_fmr_pool *tmp;

	if (!fpo)
		return;

	fps = fpo->fpo_owner;

#ifdef HAVE_FMR_POOL_API
	if (fpo->fpo_is_fmr) {
		if (fmr->fmr_pfmr) {
			ib_fmr_pool_unmap(fmr->fmr_pfmr);
			fmr->fmr_pfmr = NULL;
		}

		if (status) {
			int rc = ib_flush_fmr_pool(fpo->fmr.fpo_fmr_pool);
			LASSERT(!rc);
		}
	} else
#endif /* HAVE_FMR_POOL_API */
	{
		struct kib_fast_reg_descriptor *frd = fmr->fmr_frd;

		if (frd) {
			frd->frd_valid = false;
			frd->frd_posted = false;
			fmr->fmr_frd = NULL;
			spin_lock(&fps->fps_lock);
			list_add_tail(&frd->frd_list, &fpo->fast_reg.fpo_pool_list);
			spin_unlock(&fps->fps_lock);
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

int kiblnd_fmr_pool_map(struct kib_fmr_poolset *fps, struct kib_tx *tx,
			struct kib_rdma_desc *rd, u32 nob, u64 iov,
			struct kib_fmr *fmr)
{
	struct kib_fmr_pool *fpo;
	__u64 version;
	bool is_rx = (rd != tx->tx_rd);
#ifdef HAVE_FMR_POOL_API
	__u64 *pages = tx->tx_pages;
	bool tx_pages_mapped = 0;
	int npages = 0;
#endif
	int rc;

again:
	spin_lock(&fps->fps_lock);
	version = fps->fps_version;
	list_for_each_entry(fpo, &fps->fps_pool_list, fpo_list) {
		fpo->fpo_deadline = ktime_get_seconds() + IBLND_POOL_DEADLINE;
		fpo->fpo_map_count++;

#ifdef HAVE_FMR_POOL_API
		fmr->fmr_pfmr = NULL;
		if (fpo->fpo_is_fmr) {
			struct ib_pool_fmr *pfmr;

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
		} else
#endif /* HAVE_FMR_POOL_API */
		{
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
						 rd->rd_nfrags, NULL, PAGE_SIZE);
#else
				n = ib_map_mr_sg(mr, tx->tx_frags,
						 rd->rd_nfrags, PAGE_SIZE);
#endif /* HAVE_IB_MAP_MR_SG_5ARGS */
				if (unlikely(n != rd->rd_nfrags)) {
					CERROR("Failed to map mr %d/%d "
					       "elements\n", n, rd->rd_nfrags);
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
#else /* HAVE_IB_MAP_MR_SG */
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
#endif /* HAVE_IB_MAP_MR_SG */

				fmr->fmr_key  = is_rx ? mr->rkey : mr->lkey;
				fmr->fmr_frd  = frd;
				fmr->fmr_pool = fpo;
				frd->frd_posted = false;
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

	if (ktime_get_seconds() < fps->fps_next_retry) {
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
		fps->fps_next_retry = ktime_get_seconds() + IBLND_POOL_RETRY;
	}
	spin_unlock(&fps->fps_lock);

	goto again;
}

static void
kiblnd_fini_pool(struct kib_pool *pool)
{
	LASSERT(list_empty(&pool->po_free_list));
	LASSERT(pool->po_allocated == 0);

	CDEBUG(D_NET, "Finalize %s pool\n", pool->po_owner->ps_name);
}

static void
kiblnd_init_pool(struct kib_poolset *ps, struct kib_pool *pool, int size)
{
	CDEBUG(D_NET, "Initialize %s pool\n", ps->ps_name);

	memset(pool, 0, sizeof(struct kib_pool));
	INIT_LIST_HEAD(&pool->po_free_list);
	pool->po_deadline = ktime_get_seconds() + IBLND_POOL_DEADLINE;
	pool->po_owner = ps;
	pool->po_size = size;
}

static void
kiblnd_destroy_pool_list(struct list_head *head)
{
	struct kib_pool *pool;

	while (!list_empty(head)) {
		pool = list_entry(head->next, struct kib_pool, po_list);
		list_del(&pool->po_list);

		LASSERT(pool->po_owner != NULL);
		pool->po_owner->ps_pool_destroy(pool);
	}
}

static void
kiblnd_fail_poolset(struct kib_poolset *ps, struct list_head *zombies)
{
	if (ps->ps_net == NULL) /* intialized? */
		return;

	spin_lock(&ps->ps_lock);
	while (!list_empty(&ps->ps_pool_list)) {
		struct kib_pool *po = list_entry(ps->ps_pool_list.next,
						 struct kib_pool, po_list);

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
kiblnd_fini_poolset(struct kib_poolset *ps)
{
	if (ps->ps_net != NULL) { /* initialized? */
		kiblnd_destroy_pool_list(&ps->ps_failed_pool_list);
		kiblnd_destroy_pool_list(&ps->ps_pool_list);
	}
}

static int
kiblnd_init_poolset(struct kib_poolset *ps, int cpt,
		    struct kib_net *net, char *name, int size,
		    kib_ps_pool_create_t po_create,
		    kib_ps_pool_destroy_t po_destroy,
		    kib_ps_node_init_t nd_init,
		    kib_ps_node_fini_t nd_fini)
{
	struct kib_pool	*pool;
	int rc;

	memset(ps, 0, sizeof(struct kib_poolset));

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
kiblnd_pool_is_idle(struct kib_pool *pool, time64_t now)
{
        if (pool->po_allocated != 0) /* still in use */
                return 0;
        if (pool->po_failed)
                return 1;
	return now >= pool->po_deadline;
}

void
kiblnd_pool_free_node(struct kib_pool *pool, struct list_head *node)
{
	struct list_head zombies = LIST_HEAD_INIT(zombies);
	struct kib_poolset *ps = pool->po_owner;
	struct kib_pool *tmp;
	time64_t now = ktime_get_seconds();

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
kiblnd_pool_alloc_node(struct kib_poolset *ps)
{
	struct list_head	*node;
	struct kib_pool	*pool;
	int			rc;
	unsigned int		interval = 1;
	ktime_t time_before;
	unsigned int trips = 0;

again:
	spin_lock(&ps->ps_lock);
	list_for_each_entry(pool, &ps->ps_pool_list, po_list) {
		if (list_empty(&pool->po_free_list))
			continue;

		pool->po_allocated++;
		pool->po_deadline = ktime_get_seconds() +
				    IBLND_POOL_DEADLINE;
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

	if (ktime_get_seconds() < ps->ps_next_retry) {
		/* someone failed recently */
		spin_unlock(&ps->ps_lock);
		return NULL;
	}

	ps->ps_increasing = 1;
	spin_unlock(&ps->ps_lock);

	CDEBUG(D_NET, "%s pool exhausted, allocate new pool\n", ps->ps_name);
	time_before = ktime_get();
	rc = ps->ps_pool_create(ps, ps->ps_pool_size, &pool);
	CDEBUG(D_NET, "ps_pool_create took %lld ms to complete",
	       ktime_ms_delta(ktime_get(), time_before));

	spin_lock(&ps->ps_lock);
	ps->ps_increasing = 0;
	if (rc == 0) {
		list_add_tail(&pool->po_list, &ps->ps_pool_list);
	} else {
		ps->ps_next_retry = ktime_get_seconds() + IBLND_POOL_RETRY;
		CERROR("Can't allocate new %s pool because out of memory\n",
		       ps->ps_name);
	}
	spin_unlock(&ps->ps_lock);

	goto again;
}

static void
kiblnd_destroy_tx_pool(struct kib_pool *pool)
{
	struct kib_tx_pool *tpo = container_of(pool, struct kib_tx_pool,
					       tpo_pool);
	int i;

        LASSERT (pool->po_allocated == 0);

        if (tpo->tpo_tx_pages != NULL) {
                kiblnd_unmap_tx_pool(tpo);
                kiblnd_free_pages(tpo->tpo_tx_pages);
        }

        if (tpo->tpo_tx_descs == NULL)
                goto out;

        for (i = 0; i < pool->po_size; i++) {
		struct kib_tx *tx = &tpo->tpo_tx_descs[i];
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
				    offsetof(struct kib_rdma_desc,
                                             rd_frags[IBLND_MAX_RDMA_FRAGS]));
        }

        LIBCFS_FREE(tpo->tpo_tx_descs,
		    pool->po_size * sizeof(struct kib_tx));
out:
        kiblnd_fini_pool(pool);
	LIBCFS_FREE(tpo, sizeof(struct kib_tx_pool));
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
kiblnd_create_tx_pool(struct kib_poolset *ps, int size, struct kib_pool **pp_po)
{
        int            i;
        int            npg;
	struct kib_pool *pool;
	struct kib_tx_pool *tpo;

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
		LIBCFS_FREE(tpo, sizeof(struct kib_tx_pool));
		return -ENOMEM;
	}

	LIBCFS_CPT_ALLOC(tpo->tpo_tx_descs, lnet_cpt_table(), ps->ps_cpt,
			 size * sizeof(struct kib_tx));
        if (tpo->tpo_tx_descs == NULL) {
                CERROR("Can't allocate %d tx descriptors\n", size);
                ps->ps_pool_destroy(pool);
                return -ENOMEM;
        }

	memset(tpo->tpo_tx_descs, 0, size * sizeof(struct kib_tx));

        for (i = 0; i < size; i++) {
		struct kib_tx *tx = &tpo->tpo_tx_descs[i];
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
				 offsetof(struct kib_rdma_desc,
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
kiblnd_tx_init(struct kib_pool *pool, struct list_head *node)
{
	struct kib_tx_poolset *tps = container_of(pool->po_owner,
						  struct kib_tx_poolset,
						  tps_poolset);
	struct kib_tx *tx  = list_entry(node, struct kib_tx, tx_list);

	tx->tx_cookie = tps->tps_next_tx_cookie++;
}

static void
kiblnd_net_fini_pools(struct kib_net *net)
{
	int	i;

	cfs_cpt_for_each(i, lnet_cpt_table()) {
		struct kib_tx_poolset *tps;
		struct kib_fmr_poolset *fps;

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
kiblnd_net_init_pools(struct kib_net *net, struct lnet_ni *ni, __u32 *cpts,
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
	/*
	 * if lnd_map_on_demand is zero then we have effectively disabled
	 * FMR or FastReg and we're using global memory regions
	 * exclusively.
	 */
	if (!tunables->lnd_map_on_demand) {
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
					   sizeof(struct kib_fmr_poolset));
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
					  sizeof(struct kib_tx_poolset));
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
kiblnd_hdev_get_attr(struct kib_hca_dev *hdev)
{
	struct ib_device_attr *dev_attr;
	int rc = 0;

	/* It's safe to assume a HCA can handle a page size
	 * matching that of the native system */
	hdev->ibh_page_shift = PAGE_SHIFT;
	hdev->ibh_page_size  = 1 << PAGE_SHIFT;
	hdev->ibh_page_mask  = ~((__u64)hdev->ibh_page_size - 1);

#ifndef HAVE_IB_DEVICE_ATTRS
	LIBCFS_ALLOC(dev_attr, sizeof(*dev_attr));
	if (dev_attr == NULL) {
		CERROR("Out of memory\n");
		return -ENOMEM;
	}

	rc = ib_query_device(hdev->ibh_ibdev, dev_attr);
	if (rc != 0) {
		CERROR("Failed to query IB device: %d\n", rc);
		goto out_clean_attr;
	}
#else
	dev_attr = &hdev->ibh_ibdev->attrs;
#endif

	hdev->ibh_mr_size = dev_attr->max_mr_size;
	hdev->ibh_max_qp_wr = dev_attr->max_qp_wr;

	/* Setup device Memory Registration capabilities */
#ifdef HAVE_FMR_POOL_API
#ifdef HAVE_IB_DEVICE_OPS
	if (hdev->ibh_ibdev->ops.alloc_fmr &&
	    hdev->ibh_ibdev->ops.dealloc_fmr &&
	    hdev->ibh_ibdev->ops.map_phys_fmr &&
	    hdev->ibh_ibdev->ops.unmap_fmr) {
#else
	if (hdev->ibh_ibdev->alloc_fmr &&
	    hdev->ibh_ibdev->dealloc_fmr &&
	    hdev->ibh_ibdev->map_phys_fmr &&
	    hdev->ibh_ibdev->unmap_fmr) {
#endif
		LCONSOLE_INFO("Using FMR for registration\n");
		hdev->ibh_dev->ibd_dev_caps |= IBLND_DEV_CAPS_FMR_ENABLED;
	} else
#endif /* HAVE_FMR_POOL_API */
	if (dev_attr->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS) {
		LCONSOLE_INFO("Using FastReg for registration\n");
		hdev->ibh_dev->ibd_dev_caps |= IBLND_DEV_CAPS_FASTREG_ENABLED;
#ifndef HAVE_IB_ALLOC_FAST_REG_MR
#ifdef IB_DEVICE_SG_GAPS_REG
		if (dev_attr->device_cap_flags & IB_DEVICE_SG_GAPS_REG)
			hdev->ibh_dev->ibd_dev_caps |= IBLND_DEV_CAPS_FASTREG_GAPS_SUPPORT;
#endif
#endif
	} else {
		rc = -ENOSYS;
	}

	if (rc == 0 && hdev->ibh_mr_size == ~0ULL)
		hdev->ibh_mr_shift = 64;
	else if (rc != 0)
		rc = -EINVAL;

#ifndef HAVE_IB_DEVICE_ATTRS
out_clean_attr:
	LIBCFS_FREE(dev_attr, sizeof(*dev_attr));
#endif

	if (rc == -ENOSYS)
		CERROR("IB device does not support FMRs nor FastRegs, can't "
		       "register memory: %d\n", rc);
	else if (rc == -EINVAL)
		CERROR("Invalid mr size: %#llx\n", hdev->ibh_mr_size);
	return rc;
}

#ifdef HAVE_IB_GET_DMA_MR
static void
kiblnd_hdev_cleanup_mrs(struct kib_hca_dev *hdev)
{
	if (hdev->ibh_mrs == NULL)
		return;

	ib_dereg_mr(hdev->ibh_mrs);

	hdev->ibh_mrs = NULL;
}
#endif

void
kiblnd_hdev_destroy(struct kib_hca_dev *hdev)
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
kiblnd_hdev_setup_mrs(struct kib_hca_dev *hdev)
{
	struct ib_mr *mr;
	int           acflags = IB_ACCESS_LOCAL_WRITE |
				IB_ACCESS_REMOTE_WRITE;

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
kiblnd_dev_need_failover(struct kib_dev *dev, struct net *ns)
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
	cmid = kiblnd_rdma_create_id(ns, kiblnd_dummy_callback, dev,
				     RDMA_PS_TCP, IB_QPT_RC);
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
kiblnd_dev_failover(struct kib_dev *dev, struct net *ns)
{
	struct list_head    zombie_tpo = LIST_HEAD_INIT(zombie_tpo);
	struct list_head    zombie_ppo = LIST_HEAD_INIT(zombie_ppo);
	struct list_head    zombie_fpo = LIST_HEAD_INIT(zombie_fpo);
        struct rdma_cm_id  *cmid  = NULL;
	struct kib_hca_dev *hdev  = NULL;
	struct kib_hca_dev *old;
        struct ib_pd       *pd;
	struct kib_net *net;
        struct sockaddr_in  addr;
        unsigned long       flags;
        int                 rc = 0;
	int		    i;

        LASSERT (*kiblnd_tunables.kib_dev_failover > 1 ||
                 dev->ibd_can_failover ||
                 dev->ibd_hdev == NULL);

	rc = kiblnd_dev_need_failover(dev, ns);
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

	cmid = kiblnd_rdma_create_id(ns, kiblnd_cm_callback, dev, RDMA_PS_TCP,
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

	rc = kiblnd_hdev_get_attr(hdev);
	if (rc != 0) {
		CERROR("Can't get device attributes: %d\n", rc);
		goto out;
	}

#ifdef HAVE_IB_GET_DMA_MR
	rc = kiblnd_hdev_setup_mrs(hdev);
	if (rc != 0) {
		CERROR("Can't setup device: %d\n", rc);
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
kiblnd_destroy_dev(struct kib_dev *dev)
{
	LASSERT(dev->ibd_nnets == 0);
	LASSERT(list_empty(&dev->ibd_nets));

	list_del(&dev->ibd_fail_list);
	list_del(&dev->ibd_list);

        if (dev->ibd_hdev != NULL)
                kiblnd_hdev_decref(dev->ibd_hdev);

        LIBCFS_FREE(dev, sizeof(*dev));
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
	struct kib_net *net = ni->ni_data;
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
kiblnd_base_startup(struct net *ns)
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
		rc = kiblnd_thread_start(kiblnd_failover_thread, ns,
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

static int kiblnd_dev_start_threads(struct kib_dev *dev, bool newdev, u32 *cpts,
				    int ncpts)
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

static struct kib_dev *
kiblnd_dev_search(char *ifname)
{
	struct kib_dev *alias = NULL;
	struct kib_dev *dev;
	char            *colon;
	char            *colon2;

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
	char *ifname = NULL;
	struct lnet_inetdev *ifaces = NULL;
	struct kib_dev *ibdev = NULL;
	struct kib_net *net = NULL;
	unsigned long flags;
	int rc;
	int i;
	bool newdev;

	LASSERT(ni->ni_net->net_lnd == &the_o2iblnd);

	if (kiblnd_data.kib_init == IBLND_INIT_NOTHING) {
		rc = kiblnd_base_startup(ni->ni_net_ns);
		if (rc != 0)
			return rc;
	}

	LIBCFS_ALLOC(net, sizeof(*net));
	ni->ni_data = net;
	if (net == NULL) {
		rc = -ENOMEM;
		goto failed;
	}

	net->ibn_incarnation = ktime_get_real_ns() / NSEC_PER_USEC;

	kiblnd_tunables_setup(ni);

	/*
	 * ni_interfaces is only to support legacy pre Multi-Rail
	 * tcp bonding for ksocklnd. Multi-Rail wants each secondary
	 * IP to be treated as an unique 'struct ni' interfaces instead.
	 */
	if (ni->ni_interfaces[0] != NULL) {
		/* Use the IPoIB interface specified in 'networks=' */
		if (ni->ni_interfaces[1] != NULL) {
			CERROR("ko2iblnd: Multiple interfaces not supported\n");
			rc = -EINVAL;
			goto failed;
		}

		ifname = ni->ni_interfaces[0];
	} else {
		ifname = *kiblnd_tunables.kib_default_ipif;
	}

	if (strlen(ifname) >= sizeof(ibdev->ibd_ifname)) {
		CERROR("IPoIB interface name too long: %s\n", ifname);
		rc = -E2BIG;
		goto failed;
	}

	rc = lnet_inet_enumerate(&ifaces, ni->ni_net_ns);
	if (rc < 0)
		goto failed;

	for (i = 0; i < rc; i++) {
		if (strcmp(ifname, ifaces[i].li_name) == 0)
			break;
	}

	if (i == rc) {
		CERROR("ko2iblnd: No matching interfaces\n");
		rc = -ENOENT;
		goto failed;
	}

	ibdev = kiblnd_dev_search(ifname);
	newdev = ibdev == NULL;
	/* hmm...create kib_dev even for alias */
	if (ibdev == NULL || strcmp(&ibdev->ibd_ifname[0], ifname) != 0) {
		LIBCFS_ALLOC(ibdev, sizeof(*ibdev));
		if (!ibdev) {
			rc = -ENOMEM;
			goto failed;
		}

		ibdev->ibd_ifip = ifaces[i].li_ipaddr;
		strlcpy(ibdev->ibd_ifname, ifaces[i].li_name,
			sizeof(ibdev->ibd_ifname));
		ibdev->ibd_can_failover = !!(ifaces[i].li_flags & IFF_MASTER);

		INIT_LIST_HEAD(&ibdev->ibd_nets);
		INIT_LIST_HEAD(&ibdev->ibd_list); /* not yet in kib_devs */
		INIT_LIST_HEAD(&ibdev->ibd_fail_list);

		/* initialize the device */
		rc = kiblnd_dev_failover(ibdev, ni->ni_net_ns);
		if (rc) {
			CERROR("ko2iblnd: Can't initialize device: rc = %d\n", rc);
			goto failed;
		}

		list_add_tail(&ibdev->ibd_list, &kiblnd_data.kib_devs);
	}

	net->ibn_dev = ibdev;
	ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), ibdev->ibd_ifip);

	ni->ni_dev_cpt = ifaces[i].li_cpt;

	rc = kiblnd_dev_start_threads(ibdev, newdev, ni->ni_cpts, ni->ni_ncpts);
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

	kfree(ifaces);
	kiblnd_shutdown(ni);

	CDEBUG(D_NET, "Configuration of device %s failed: rc = %d\n",
	       ifname ? ifname : "", rc);

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

	CLASSERT(sizeof(struct kib_msg) <= IBLND_MSG_SIZE);
	CLASSERT(offsetof(struct kib_msg,
			  ibm_u.get.ibgm_rd.rd_frags[IBLND_MAX_RDMA_FRAGS]) <=
		 IBLND_MSG_SIZE);
	CLASSERT(offsetof(struct kib_msg,
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
