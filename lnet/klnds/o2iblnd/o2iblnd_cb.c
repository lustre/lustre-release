// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "o2iblnd.h"

#define MAX_CONN_RACES_BEFORE_ABORT 20

static void kiblnd_peer_alive(struct kib_peer_ni *peer_ni);
static void kiblnd_peer_connect_failed(struct kib_peer_ni *peer_ni, int active,
				       int error);
static struct ib_rdma_wr *
kiblnd_init_tx_msg_payload(struct lnet_ni *ni, struct kib_tx *tx,
			       int type, int body_nob, int payload_nob);
#define kiblnd_init_tx_msg(ni, tx, type, body) \
	kiblnd_init_tx_msg_payload(ni, tx, type, body, 0)
static int kiblnd_init_rdma(struct kib_conn *conn, struct kib_tx *tx, int type,
			    int resid, struct kib_rdma_desc *dstrd, u64 dstcookie);
static void kiblnd_queue_tx_locked(struct kib_tx *tx, struct kib_conn *conn);
static void kiblnd_queue_tx(struct kib_tx *tx, struct kib_conn *conn);

static void kiblnd_unmap_tx(struct kib_tx *tx);
static void kiblnd_check_sends_locked(struct kib_conn *conn);

static void
kiblnd_tx_done(struct kib_tx *tx)
{
	struct lnet_msg *lntmsg[2];
	int rc;
	int i;

	LASSERT(!in_interrupt());
	LASSERT(!tx->tx_queued);      /* mustn't be queued for sending */
	LASSERT(tx->tx_sending == 0); /* mustn't be awaiting sent callback */
	LASSERT(!tx->tx_waiting);     /* mustn't be awaiting peer_ni response */
	LASSERT(tx->tx_pool != NULL);

	kiblnd_unmap_tx(tx);

	/* tx may have up to 2 lnet msgs to finalise */
	lntmsg[0] = tx->tx_lntmsg[0]; tx->tx_lntmsg[0] = NULL;
	lntmsg[1] = tx->tx_lntmsg[1]; tx->tx_lntmsg[1] = NULL;
	rc = tx->tx_status;

	if (tx->tx_conn != NULL) {
		kiblnd_conn_decref(tx->tx_conn);
		tx->tx_conn = NULL;
	}

	tx->tx_nwrq = tx->tx_nsge = 0;
	tx->tx_status = 0;

	kiblnd_pool_free_node(&tx->tx_pool->tpo_pool, &tx->tx_list);

	/* delay finalize until my descs have been freed */
	for (i = 0; i < 2; i++) {
		if (lntmsg[i] == NULL)
			continue;

		/* propagate health status to LNet for requests */
		if (i == 0 && lntmsg[i])
			lntmsg[i]->msg_health_status = tx->tx_hstatus;

		lnet_finalize(lntmsg[i], rc);
	}
}

void
kiblnd_txlist_done(struct list_head *txlist, int status,
		   enum lnet_msg_hstatus hstatus)
{
	struct kib_tx *tx;

	while ((tx = list_first_entry_or_null(txlist,
					      struct kib_tx,
					      tx_list)) != NULL) {
		list_del(&tx->tx_list);
		/* complete now */
		tx->tx_waiting = 0;
		tx->tx_status = status;
		if (hstatus != LNET_MSG_STATUS_OK)
			tx->tx_hstatus = hstatus;
		kiblnd_tx_done(tx);
	}
}

static struct kib_tx *
kiblnd_get_idle_tx(struct lnet_ni *ni, struct lnet_nid *target)
{
	struct kib_net *net = ni->ni_data;
	struct list_head *node;
	struct kib_tx *tx;
	struct kib_tx_poolset *tps;

	tps = net->ibn_tx_ps[lnet_nid2cpt(target, ni)];
	node = kiblnd_pool_alloc_node(&tps->tps_poolset);
	if (node == NULL)
		return NULL;
	tx = container_of(node, struct kib_tx, tx_list);

	LASSERT(tx->tx_nwrq == 0);
	LASSERT(!tx->tx_queued);
	LASSERT(tx->tx_sending == 0);
	LASSERT(!tx->tx_waiting);
	LASSERT(tx->tx_status == 0);
	LASSERT(tx->tx_conn == NULL);
	LASSERT(tx->tx_lntmsg[0] == NULL);
	LASSERT(tx->tx_lntmsg[1] == NULL);
	LASSERT(tx->tx_nfrags == 0);

	tx->tx_gpu = 0;
	tx->tx_gaps = false;
	tx->tx_hstatus = LNET_MSG_STATUS_OK;

	return tx;
}

static void
kiblnd_drop_rx(struct kib_rx *rx)
{
	struct kib_conn *conn = rx->rx_conn;
	struct kib_sched_info *sched = conn->ibc_sched;
	unsigned long flags;

	spin_lock_irqsave(&sched->ibs_lock, flags);
	LASSERT(conn->ibc_nrx > 0);
	conn->ibc_nrx--;
	spin_unlock_irqrestore(&sched->ibs_lock, flags);

	kiblnd_conn_decref(conn);
}

int
kiblnd_post_rx(struct kib_rx *rx, int credit)
{
	struct kib_conn *conn = rx->rx_conn;
	struct kib_net *net = conn->ibc_peer->ibp_ni->ni_data;
	struct ib_recv_wr wrq = {0};
	struct ib_sge rx_sge = {0};
#ifdef HAVE_OFED_IB_GET_DMA_MR
	struct ib_mr *mr = conn->ibc_hdev->ibh_mrs;
#endif
	int rc;

	LASSERT(net != NULL);
	LASSERT(!in_interrupt());
	LASSERT(credit == IBLND_POSTRX_NO_CREDIT ||
		 credit == IBLND_POSTRX_PEER_CREDIT ||
		 credit == IBLND_POSTRX_RSRVD_CREDIT);
#ifdef HAVE_OFED_IB_GET_DMA_MR
	LASSERT(mr != NULL);

	rx_sge.lkey   = mr->lkey;
#else
	rx_sge.lkey   = conn->ibc_hdev->ibh_pd->local_dma_lkey;
#endif
	rx_sge.addr   = rx->rx_msgaddr;
	rx_sge.length = IBLND_MSG_SIZE;

	wrq.next = NULL;
	wrq.sg_list = &rx_sge;
	wrq.num_sge = 1;
	wrq.wr_id = kiblnd_ptr2wreqid(rx, IBLND_WID_RX);

	LASSERT(conn->ibc_state >= IBLND_CONN_INIT);
	LASSERT(rx->rx_nob >= 0);              /* not posted */

	if (conn->ibc_state > IBLND_CONN_ESTABLISHED) {
		kiblnd_drop_rx(rx);             /* No more posts for this rx */
		return 0;
	}

	rx->rx_nob = -1;                        /* flag posted */

	/* NB: need an extra reference after ib_post_recv because we don't
	 * own this rx (and rx::rx_conn) anymore, LU-5678.
	 */
	kiblnd_conn_addref(conn);
	rc = ib_post_recv(conn->ibc_cmid->qp, &wrq, NULL);
	if (unlikely(rc != 0)) {
		CERROR("Can't post rx for %s: rc = %d\n",
		       libcfs_nidstr(&conn->ibc_peer->ibp_nid), rc);
		rx->rx_nob = 0;
	}

	if (conn->ibc_state < IBLND_CONN_ESTABLISHED) /* Initial post */
		goto out;

	if (unlikely(rc != 0)) {
		kiblnd_close_conn(conn, rc);
		kiblnd_drop_rx(rx);	/* No more posts for this rx */
		goto out;
	}

	if (credit == IBLND_POSTRX_NO_CREDIT)
		goto out;

	spin_lock(&conn->ibc_lock);
	if (credit == IBLND_POSTRX_PEER_CREDIT)
		conn->ibc_outstanding_credits++;
	else
		conn->ibc_reserved_credits++;
	kiblnd_check_sends_locked(conn);
	spin_unlock(&conn->ibc_lock);

out:
	kiblnd_conn_decref(conn);
	return rc;
}

static struct kib_tx *
kiblnd_find_waiting_tx_locked(struct kib_conn *conn, int txtype, u64 cookie)
{
	struct kib_tx *tx;

	list_for_each_entry(tx, &conn->ibc_active_txs, tx_list) {
		LASSERT(!tx->tx_queued);
		LASSERT(tx->tx_sending != 0 || tx->tx_waiting);

		if (tx->tx_cookie != cookie)
			continue;

		if (tx->tx_waiting &&
		    tx->tx_msg->ibm_type == txtype)
			return tx;

		CWARN("Bad completion: %swaiting, type %x (wanted %x)\n",
		      tx->tx_waiting ? "" : "NOT ",
		      tx->tx_msg->ibm_type, txtype);
	}
	return NULL;
}

static void
kiblnd_handle_completion(struct kib_conn *conn, int txtype, int status, u64 cookie)
{
	struct kib_tx *tx;
	struct lnet_ni *ni = conn->ibc_peer->ibp_ni;
	int idle;

	spin_lock(&conn->ibc_lock);

	tx = kiblnd_find_waiting_tx_locked(conn, txtype, cookie);
	if (tx == NULL) {
		spin_unlock(&conn->ibc_lock);

		CWARN("Unmatched completion type %x cookie %#llx from %s\n",
		      txtype, cookie, libcfs_nidstr(&conn->ibc_peer->ibp_nid));
		kiblnd_close_conn(conn, -EPROTO);
		return;
	}

	if (tx->tx_status == 0) {               /* success so far */
		if (status < 0) {               /* failed? */
			if (status == -ECONNABORTED) {
				CDEBUG(D_NET,
				       "bad status for connection to %s with completion type %x\n",
				       libcfs_nidstr(&conn->ibc_peer->ibp_nid),
				       txtype);
			}

			tx->tx_status = status;
			tx->tx_hstatus = LNET_MSG_STATUS_REMOTE_ERROR;
		} else if (txtype == IBLND_MSG_GET_REQ) {
			lnet_set_reply_msg_len(ni, tx->tx_lntmsg[1], status);
		}
	}

	tx->tx_waiting = 0;

	idle = !tx->tx_queued && (tx->tx_sending == 0);
	if (idle)
		list_del(&tx->tx_list);

	spin_unlock(&conn->ibc_lock);

	if (idle)
		kiblnd_tx_done(tx);
}

static void
kiblnd_send_completion(struct kib_conn *conn, int type, int status, u64 cookie)
{
	struct lnet_ni *ni = conn->ibc_peer->ibp_ni;
	struct kib_tx *tx = kiblnd_get_idle_tx(ni, &conn->ibc_peer->ibp_nid);

	if (tx == NULL) {
		CERROR("Can't get tx for completion %x for %s\n",
		       type, libcfs_nidstr(&conn->ibc_peer->ibp_nid));
		return;
	}

	tx->tx_msg->ibm_u.completion.ibcm_status = status;
	tx->tx_msg->ibm_u.completion.ibcm_cookie = cookie;
	kiblnd_init_tx_msg(ni, tx, type, sizeof(struct kib_completion_msg));

	kiblnd_queue_tx(tx, conn);
}

static void
kiblnd_handle_rx(struct kib_rx *rx)
{
	struct kib_msg *msg = rx->rx_msg;
	struct kib_conn *conn = rx->rx_conn;
	struct lnet_ni *ni = conn->ibc_peer->ibp_ni;
	int credits = msg->ibm_credits;
	struct kib_tx *tx;
	int rc = 0;
	int rc2;
	int post_credit;
	struct lnet_hdr hdr;
	struct lnet_nid srcnid;

	LASSERT(conn->ibc_state >= IBLND_CONN_ESTABLISHED);

	CDEBUG(D_NET, "Received %x[%d] nob %u cm_id %p qp_num 0x%x\n",
		msg->ibm_type, credits,
		msg->ibm_nob,
		conn->ibc_cmid,
		conn->ibc_cmid->qp ? conn->ibc_cmid->qp->qp_num : 0);
	kiblnd_dump_conn_dbg(conn);

	if (credits != 0) {
		/* Have I received credits that will let me send? */
		spin_lock(&conn->ibc_lock);

		if (conn->ibc_credits + credits >
		    conn->ibc_queue_depth) {
			rc2 = conn->ibc_credits;
			spin_unlock(&conn->ibc_lock);

			CERROR("Bad credits from %s: %d + %d > %d\n",
			       libcfs_nidstr(&conn->ibc_peer->ibp_nid),
			       rc2, credits, conn->ibc_queue_depth);

			kiblnd_close_conn(conn, -EPROTO);
			kiblnd_post_rx(rx, IBLND_POSTRX_NO_CREDIT);
			return;
		}

		conn->ibc_credits += credits;

		/* This ensures the credit taken by NOOP can be returned */
		if (msg->ibm_type == IBLND_MSG_NOOP &&
		    !IBLND_OOB_CAPABLE(conn->ibc_version)) /* v1 only */
			conn->ibc_outstanding_credits++;

		kiblnd_check_sends_locked(conn);
		spin_unlock(&conn->ibc_lock);
	}

	switch (msg->ibm_type) {
	default:
		rc = -EPROTO;
                CERROR("Bad IBLND message type %x from %s: rc = %d\n",
		       msg->ibm_type, libcfs_nidstr(&conn->ibc_peer->ibp_nid),
		       rc);
		post_credit = IBLND_POSTRX_NO_CREDIT;
		break;

	case IBLND_MSG_NOOP:
		if (IBLND_OOB_CAPABLE(conn->ibc_version)) {
			post_credit = IBLND_POSTRX_NO_CREDIT;
			break;
		}

		if (credits != 0) /* credit already posted */
			post_credit = IBLND_POSTRX_NO_CREDIT;
		else              /* a keepalive NOOP */
			post_credit = IBLND_POSTRX_PEER_CREDIT;
		break;

	case IBLND_MSG_IMMEDIATE:
		post_credit = IBLND_POSTRX_DONT_POST;
		lnet_hdr_from_nid4(&hdr, &msg->ibm_u.immediate.ibim_hdr);
		lnet_nid4_to_nid(msg->ibm_srcnid, &srcnid);
		rc = lnet_parse(ni, &hdr, &srcnid, rx, 0);
		if (rc < 0)                     /* repost on error */
			post_credit = IBLND_POSTRX_PEER_CREDIT;
		break;

	case IBLND_MSG_PUT_REQ:
		post_credit = IBLND_POSTRX_DONT_POST;
		lnet_hdr_from_nid4(&hdr, &msg->ibm_u.putreq.ibprm_hdr);
		lnet_nid4_to_nid(msg->ibm_srcnid, &srcnid);
		rc = lnet_parse(ni, &hdr, &srcnid, rx, 1);
		if (rc < 0)                     /* repost on error */
			post_credit = IBLND_POSTRX_PEER_CREDIT;
		break;

	case IBLND_MSG_PUT_NAK:
		CWARN("PUT_NACK from %s\n",
		      libcfs_nidstr(&conn->ibc_peer->ibp_nid));
		post_credit = IBLND_POSTRX_RSRVD_CREDIT;
		kiblnd_handle_completion(conn, IBLND_MSG_PUT_REQ,
					 msg->ibm_u.completion.ibcm_status,
					 msg->ibm_u.completion.ibcm_cookie);
		break;

	case IBLND_MSG_PUT_ACK:
		post_credit = IBLND_POSTRX_RSRVD_CREDIT;

		spin_lock(&conn->ibc_lock);
		tx = kiblnd_find_waiting_tx_locked(conn, IBLND_MSG_PUT_REQ,
					msg->ibm_u.putack.ibpam_src_cookie);
		if (tx != NULL)
			list_del(&tx->tx_list);
		spin_unlock(&conn->ibc_lock);

		if (tx == NULL) {
			rc = -EPROTO;
			CERROR("Unmatched PUT_ACK from %s: rc = %d\n",
			       libcfs_nidstr(&conn->ibc_peer->ibp_nid), rc);
			break;
		}

		if (!tx->tx_waiting) {
			rc = -EPROTO;
			CERROR("Matching PUT_ACK from %s is not waiting: rc = %d\n",
			       libcfs_nidstr(&conn->ibc_peer->ibp_nid), rc);
			break;
		}

		/* CAVEAT EMPTOR: I could be racing with tx_complete, but...
		 * (a) I can overwrite tx_msg since my peer_ni has received it!
		 * (b) tx_waiting set tells tx_complete() it's not done.
		 */

		tx->tx_nwrq = tx->tx_nsge = 0; /* overwrite PUT_REQ */

		rc2 = kiblnd_init_rdma(conn, tx, IBLND_MSG_PUT_DONE,
				       kiblnd_rd_size(&msg->ibm_u.putack.ibpam_rd),
				       &msg->ibm_u.putack.ibpam_rd,
				       msg->ibm_u.putack.ibpam_dst_cookie);
		if (rc2 < 0)
			CERROR("Can't setup rdma for PUT to %s: rc = %d\n",
			       libcfs_nidstr(&conn->ibc_peer->ibp_nid), rc2);

		spin_lock(&conn->ibc_lock);
		tx->tx_waiting = 0;	/* clear waiting and queue atomically */
		kiblnd_queue_tx_locked(tx, conn);
		spin_unlock(&conn->ibc_lock);
		break;

	case IBLND_MSG_PUT_DONE:
		post_credit = IBLND_POSTRX_PEER_CREDIT;
		kiblnd_handle_completion(conn, IBLND_MSG_PUT_ACK,
					 msg->ibm_u.completion.ibcm_status,
					 msg->ibm_u.completion.ibcm_cookie);
		break;

	case IBLND_MSG_GET_REQ:
		post_credit = IBLND_POSTRX_DONT_POST;
		lnet_hdr_from_nid4(&hdr, &msg->ibm_u.get.ibgm_hdr);
		lnet_nid4_to_nid(msg->ibm_srcnid, &srcnid);
		rc = lnet_parse(ni, &hdr, &srcnid, rx, 1);
		if (rc < 0)			/* repost on error */
			post_credit = IBLND_POSTRX_PEER_CREDIT;
		break;

	case IBLND_MSG_GET_DONE:
		post_credit = IBLND_POSTRX_RSRVD_CREDIT;
		kiblnd_handle_completion(conn, IBLND_MSG_GET_REQ,
					 msg->ibm_u.completion.ibcm_status,
					 msg->ibm_u.completion.ibcm_cookie);
		break;
	}

	if (rc < 0)                             /* protocol error */
		kiblnd_close_conn(conn, rc);

	if (post_credit != IBLND_POSTRX_DONT_POST)
		kiblnd_post_rx(rx, post_credit);
}

static void
kiblnd_rx_complete(struct kib_rx *rx, int status, int nob)
{
	struct kib_msg *msg = rx->rx_msg;
	struct kib_conn   *conn = rx->rx_conn;
	struct lnet_ni *ni = conn->ibc_peer->ibp_ni;
	struct kib_net *net = ni->ni_data;
	struct lnet_nid srcnid, destnid;
	int err = -EIO;
	int rc;

	LASSERT(net);
	LASSERT(rx->rx_nob < 0);	/* was posted */
	rx->rx_nob = 0;			/* isn't now */

	if (conn->ibc_state > IBLND_CONN_ESTABLISHED)
		goto ignore;

	if (status != IB_WC_SUCCESS) {
		CNETERR("Rx from %s failed: %d\n",
			libcfs_nidstr(&conn->ibc_peer->ibp_nid), status);
		goto failed;
	}

	LASSERT(nob >= 0);
	rx->rx_nob = nob;

	rc = kiblnd_unpack_msg(msg, rx->rx_nob);
	if (rc != 0) {
		CERROR("Error unpacking rx from %s: rc = %d\n",
		       libcfs_nidstr(&conn->ibc_peer->ibp_nid), rc);
		goto failed;
	}

	lnet_nid4_to_nid(msg->ibm_srcnid, &srcnid);
	lnet_nid4_to_nid(msg->ibm_dstnid, &destnid);
	if (!nid_same(&srcnid, &conn->ibc_peer->ibp_nid) ||
	    !nid_same(&destnid, &ni->ni_nid) ||
	    msg->ibm_srcstamp != conn->ibc_incarnation ||
	    msg->ibm_dststamp != net->ibn_incarnation) {
		err = -ESTALE;
		CERROR("Stale rx from %s: rc = %d\n",
		       libcfs_nidstr(&conn->ibc_peer->ibp_nid), err);
		GOTO(failed, err);
	}

	/* set time last known alive */
	kiblnd_peer_alive(conn->ibc_peer);

	/* racing with connection establishment/teardown! */

	if (conn->ibc_state < IBLND_CONN_ESTABLISHED) {
		rwlock_t  *g_lock = &kiblnd_data.kib_global_lock;
		unsigned long  flags;

		write_lock_irqsave(g_lock, flags);
		/* must check holding global lock to eliminate race */
		if (conn->ibc_state < IBLND_CONN_ESTABLISHED) {
			list_add_tail(&rx->rx_list, &conn->ibc_early_rxs);
			write_unlock_irqrestore(g_lock, flags);
			return;
		}
		write_unlock_irqrestore(g_lock, flags);
	}
	kiblnd_handle_rx(rx);
	return;

failed:
	CDEBUG(D_NET, "rx %p conn %p\n", rx, conn);
	kiblnd_close_conn(conn, err);
ignore:
	kiblnd_drop_rx(rx);                     /* Don't re-post rx. */
}

static int
kiblnd_fmr_map_tx(struct kib_net *net, struct kib_tx *tx,
		  struct kib_rdma_desc *rd, u32 nob)
{
	struct kib_hca_dev *hdev;
	struct kib_dev *dev;
	struct kib_fmr_poolset *fps;
	int cpt;
	int rc;
	int i;

	LASSERT(tx->tx_pool != NULL);
	LASSERT(tx->tx_pool->tpo_pool.po_owner != NULL);

	dev = net->ibn_dev;
	hdev = tx->tx_pool->tpo_hdev;
	cpt = tx->tx_pool->tpo_pool.po_owner->ps_cpt;

	/* If we're dealing with FastReg, but the device doesn't
	 * support GAPS and the tx has GAPS, then there is no real point
	 * in trying to map the memory, because it'll just fail. So
	 * preemptively fail with an appropriate message
	 */
	if (IS_FAST_REG_DEV(dev) &&
	    !(dev->ibd_dev_caps & IBLND_DEV_CAPS_FASTREG_GAPS_SUPPORT) &&
	    tx->tx_gaps) {
		rc = -EPROTONOSUPPORT;
		CERROR("Using FastReg with no GAPS support, but tx has gaps. Try setting use_fastreg_gaps to 1: rc = %d\n",
		       rc);
		return rc;
	}

#ifdef HAVE_OFED_FMR_POOL_API
	/* FMR does not support gaps but the tx has gaps then
	 * we should make sure that the number of fragments we'll be sending
	 * over fits within the number of fragments negotiated on the
	 * connection, otherwise, we won't be able to RDMA the data.
	 * We need to maintain the number of fragments negotiation on the
	 * connection for backwards compatibility.
	 */
	if (tx->tx_gaps && (dev->ibd_dev_caps & IBLND_DEV_CAPS_FMR_ENABLED)) {
		if (tx->tx_conn &&
		    tx->tx_conn->ibc_max_frags <= rd->rd_nfrags) {
			rc = -EFBIG;
			CERROR("TX number of frags (%d) is <= than connection number of frags (%d). Consider setting peer's map_on_demand to 256: rc = %d\n",
			       tx->tx_nfrags, tx->tx_conn->ibc_max_frags, rc);
			return rc;
		}
	}
#endif

	fps = net->ibn_fmr_ps[cpt];
	rc = kiblnd_fmr_pool_map(fps, tx, rd, nob, 0, &tx->tx_fmr);
	if (rc != 0) {
		CERROR("Can't map %u bytes (%u/%u)s: rc = %d\n", nob,
		       tx->tx_nfrags, rd->rd_nfrags, rc);
		return rc;
	}

	/*
	 * If rd is not tx_rd, it's going to get sent to a peer_ni, who will
	 * need the rkey
	 */
	rd->rd_key = tx->tx_fmr.fmr_key;
	/*
	 * for FastReg or FMR with no gaps we can accumulate all
	 * the fragments in one FastReg or FMR fragment.
	 */
	if (
#ifdef HAVE_OFED_FMR_POOL_API
	    ((dev->ibd_dev_caps & IBLND_DEV_CAPS_FMR_ENABLED)
	     && !tx->tx_gaps) ||
#endif
	    IS_FAST_REG_DEV(dev)) {
		/* FMR requires zero based address */
#ifdef HAVE_OFED_FMR_POOL_API
		if (dev->ibd_dev_caps & IBLND_DEV_CAPS_FMR_ENABLED)
			rd->rd_frags[0].rf_addr &= ~hdev->ibh_page_mask;
#endif
		rd->rd_frags[0].rf_nob = nob;
		rd->rd_nfrags = 1;
	} else {
		/*
		 * We're transmitting with gaps using FMR.
		 * We'll need to use multiple fragments and identify the
		 * zero based address of each fragment.
		 */
		for (i = 0; i < rd->rd_nfrags; i++) {
			rd->rd_frags[i].rf_addr &= ~hdev->ibh_page_mask;
			rd->rd_frags[i].rf_addr += i << hdev->ibh_page_shift;
		}
	}

	return 0;
}

static void
kiblnd_unmap_tx(struct kib_tx *tx)
{
	if (
#ifdef HAVE_OFED_FMR_POOL_API
		tx->tx_fmr.fmr_pfmr ||
#endif
		tx->tx_fmr.fmr_frd)
		kiblnd_fmr_pool_unmap(&tx->tx_fmr, tx->tx_status);

	if (tx->tx_nfrags != 0) {
		kiblnd_dma_unmap_sg(tx->tx_pool->tpo_hdev, tx);
		tx->tx_nfrags = 0;
	}
}

#ifdef HAVE_OFED_IB_GET_DMA_MR
static struct ib_mr *
kiblnd_find_rd_dma_mr(struct lnet_ni *ni, struct kib_rdma_desc *rd)
{
	struct kib_net *net = ni->ni_data;
	struct kib_hca_dev *hdev = net->ibn_dev->ibd_hdev;
	struct lnet_ioctl_config_o2iblnd_tunables *tunables;

	tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib;

	/*
	 * if map-on-demand is turned on and the device supports
	 * either FMR or FastReg then use that. Otherwise use global
	 * memory regions. If that's not available either, then you're
	 * dead in the water and fail the operation.
	 */
	if (tunables->lnd_map_on_demand && (IS_FAST_REG_DEV(net->ibn_dev)
#ifdef HAVE_OFED_FMR_POOL_API
	     || net->ibn_dev->ibd_dev_caps & IBLND_DEV_CAPS_FMR_ENABLED
#endif
	))
		return NULL;

	/*
	 * hdev->ibh_mrs can be NULL. This case is dealt with gracefully
	 * in the call chain. The mapping will fail with appropriate error
	 * message.
	 */
	return hdev->ibh_mrs;
}
#endif

static int kiblnd_map_tx(struct lnet_ni *ni, struct kib_tx *tx,
			 struct kib_rdma_desc *rd, int nfrags)
{
	struct kib_net *net = ni->ni_data;
	struct kib_hca_dev *hdev = net->ibn_dev->ibd_hdev;
#ifdef HAVE_OFED_IB_GET_DMA_MR
	struct ib_mr *mr = NULL;
#endif
	__u32 nob;
	int i;

	/* If rd is not tx_rd, it's going to get sent to a peer_ni and I'm the
	 * RDMA sink
	 */
	tx->tx_dmadir = (rd != tx->tx_rd) ? DMA_FROM_DEVICE : DMA_TO_DEVICE;
	tx->tx_nfrags = nfrags;

	rd->rd_nfrags = kiblnd_dma_map_sg(hdev, tx);
	for (i = 0, nob = 0; i < rd->rd_nfrags; i++) {
		rd->rd_frags[i].rf_nob  = kiblnd_sg_dma_len(
			hdev->ibh_ibdev, &tx->tx_frags[i]);
		rd->rd_frags[i].rf_addr = kiblnd_sg_dma_address(
			hdev->ibh_ibdev, &tx->tx_frags[i]);
		nob += rd->rd_frags[i].rf_nob;
	}

#ifdef HAVE_OFED_IB_GET_DMA_MR
	mr = kiblnd_find_rd_dma_mr(ni, rd);
	if (mr != NULL) {
		/* found pre-mapping MR */
		rd->rd_key = (rd != tx->tx_rd) ? mr->rkey : mr->lkey;
		return 0;
	}
#endif

	if (net->ibn_fmr_ps != NULL)
		return kiblnd_fmr_map_tx(net, tx, rd, nob);

	return -EINVAL;
}

static int kiblnd_setup_rd_kiov(struct lnet_ni *ni, struct kib_tx *tx,
				struct kib_rdma_desc *rd, int nkiov,
				struct bio_vec *kiov, int offset, int nob)
{
	struct kib_net *net = ni->ni_data;
	struct scatterlist *sg;
	int fragnob;
	int max_nkiov;
	int sg_count = 0;

	CDEBUG(D_NET, "niov %d offset %d nob %d gpu %d\n",
	       nkiov, offset, nob, tx->tx_gpu);

	LASSERT(nob > 0);
	LASSERT(nkiov > 0);
	LASSERT(net != NULL);

	while (offset >= kiov->bv_len) {
		offset -= kiov->bv_len;
		nkiov--;
		kiov++;
		LASSERT(nkiov > 0);
	}

	max_nkiov = nkiov;

	sg = tx->tx_frags;
	do {
		LASSERT(nkiov > 0);

		if (!sg) {
			CERROR("lacking enough sg entries to map tx: rc = %d\n",
			       -EFAULT);
			return -EFAULT;
		}
		sg_count++;

		fragnob = min((int)(kiov->bv_len - offset), nob);

		/*
		 * We're allowed to start at a non-aligned page offset in
		 * the first fragment and end at a non-aligned page offset
		 * in the last fragment.
		 */
		if ((fragnob < (int)(kiov->bv_len - offset)) &&
		    nkiov < max_nkiov && nob > fragnob) {
			CDEBUG(D_NET, "fragnob %d < available page %d: with remaining %d kiovs with %d nob left\n",
			       fragnob, (int)(kiov->bv_len - offset), nkiov,
			       nob);
			tx->tx_gaps = true;
		}

		sg_set_page(sg, kiov->bv_page, fragnob,
			    kiov->bv_offset + offset);
		sg = sg_next(sg);

		offset = 0;
		kiov++;
		nkiov--;
		nob -= fragnob;
	} while (nob > 0);

	return kiblnd_map_tx(ni, tx, rd, sg_count);
}

static int
kiblnd_post_tx_locked(struct kib_conn *conn, struct kib_tx *tx, int credit)
__must_hold(&conn->ibc_lock)
{
	struct kib_msg *msg = tx->tx_msg;
	struct kib_peer_ni *peer_ni = conn->ibc_peer;
	struct lnet_ni *ni = peer_ni->ibp_ni;
	struct kib_fast_reg_descriptor *frd = tx->tx_fmr.fmr_frd;
	int ver = conn->ibc_version;
	int rc;
	int done;

	LASSERT(tx->tx_queued);
	/* We rely on this for QP sizing */
	LASSERT(tx->tx_nwrq > 0 && tx->tx_nsge >= 0);
	LASSERT(tx->tx_nwrq <= 1 + conn->ibc_max_frags);

	LASSERT(credit == 0 || credit == 1);
	LASSERT(conn->ibc_outstanding_credits >= 0);
	LASSERT(conn->ibc_outstanding_credits <= conn->ibc_queue_depth);
	LASSERT(conn->ibc_credits >= 0);
	LASSERT(conn->ibc_credits <= conn->ibc_queue_depth);

	if (conn->ibc_nsends_posted ==
	    kiblnd_concurrent_sends(ver, ni)) {
		/* tx completions outstanding... */
		CDEBUG(D_NET, "%s: posted enough\n",
		       libcfs_nidstr(&peer_ni->ibp_nid));
		return -EAGAIN;
	}

	if (credit != 0 && conn->ibc_credits == 0) {   /* no credits */
		CDEBUG(D_NET, "%s: no credits cm_id %p qp_num 0x%x\n",
			libcfs_nidstr(&peer_ni->ibp_nid),
			conn->ibc_cmid,
			conn->ibc_cmid->qp ? conn->ibc_cmid->qp->qp_num : 0);
		kiblnd_dump_conn_dbg(conn);
		return -EAGAIN;
	}

	if (credit != 0 && !IBLND_OOB_CAPABLE(ver) &&
	    conn->ibc_credits == 1 &&   /* last credit reserved */
	    msg->ibm_type != IBLND_MSG_NOOP) {      /* for NOOP */
		CDEBUG(D_NET, "%s: not using last credit\n",
		       libcfs_nidstr(&peer_ni->ibp_nid));
		return -EAGAIN;
	}

	/* NB don't drop ibc_lock before bumping tx_sending */
	list_del(&tx->tx_list);
	tx->tx_queued = 0;

	if (msg->ibm_type == IBLND_MSG_NOOP &&
	    (!kiblnd_need_noop(conn) ||     /* redundant NOOP */
	    (IBLND_OOB_CAPABLE(ver) && /* posted enough NOOP */
	     conn->ibc_noops_posted == IBLND_OOB_MSGS(ver)))) {
		/* OK to drop when posted enough NOOPs, since
		 * kiblnd_check_sends_locked will queue NOOP again when
		 * posted NOOPs complete
		 */
		spin_unlock(&conn->ibc_lock);
		tx->tx_hstatus = LNET_MSG_STATUS_LOCAL_ERROR;
		kiblnd_tx_done(tx);
		spin_lock(&conn->ibc_lock);
		CDEBUG(D_NET, "%s(%d): redundant or enough NOOP cm_id %p qp_num 0x%x\n",
			libcfs_nidstr(&peer_ni->ibp_nid),
			conn->ibc_noops_posted,
			conn->ibc_cmid,
			conn->ibc_cmid->qp ? conn->ibc_cmid->qp->qp_num : 0);
		kiblnd_dump_conn_dbg(conn);
		return 0;
	}

	CDEBUG(D_NET, "Transmit %x[%d] nob %u cm_id %p qp_num 0x%x\n",
		msg->ibm_type, credit,
		msg->ibm_nob,
		conn->ibc_cmid,
		conn->ibc_cmid->qp ? conn->ibc_cmid->qp->qp_num : 0);
	kiblnd_dump_conn_dbg(conn);

	kiblnd_pack_msg(peer_ni->ibp_ni, msg, ver,
			conn->ibc_outstanding_credits, &peer_ni->ibp_nid,
			conn->ibc_incarnation);

	conn->ibc_credits -= credit;
	conn->ibc_outstanding_credits = 0;
	conn->ibc_nsends_posted++;
	if (msg->ibm_type == IBLND_MSG_NOOP)
		conn->ibc_noops_posted++;

	/* CAVEAT EMPTOR!  This tx could be the PUT_DONE of an RDMA
	 * PUT.  If so, it was first queued here as a PUT_REQ, sent and
	 * stashed on ibc_active_txs, matched by an incoming PUT_ACK,
	 * and then re-queued here.  It's (just) possible that
	 * tx_sending is non-zero if we've not done the tx_complete()
	 * from the first send; hence the ++ rather than = below.
	 */
	tx->tx_sending++;
	list_add(&tx->tx_list, &conn->ibc_active_txs);

	/* I'm still holding ibc_lock! */
	if (conn->ibc_state != IBLND_CONN_ESTABLISHED) {
		CDEBUG(D_NET, "connection to %s is not established\n",
		       conn->ibc_peer ?
		       libcfs_nidstr(&conn->ibc_peer->ibp_nid) : "NULL");
		rc = -ECONNABORTED;
	} else if (tx->tx_pool->tpo_pool.po_failed ||
		conn->ibc_hdev != tx->tx_pool->tpo_hdev) {
		/* close_conn will launch failover */
		rc = -ENETDOWN;
	} else {
		struct ib_send_wr *bad = &tx->tx_wrq[tx->tx_nwrq - 1].wr;
		struct ib_send_wr *wr  = &tx->tx_wrq[0].wr;

		if (frd != NULL && !frd->frd_posted) {
			wr = &frd->frd_inv_wr.wr;
			wr->next = &frd->frd_fastreg_wr.wr;
			frd->frd_fastreg_wr.wr.next = &tx->tx_wrq[0].wr;
		}

		LASSERTF(bad->wr_id == kiblnd_ptr2wreqid(tx, IBLND_WID_TX),
			 "bad wr_id %#llx, opc %d, flags %d, peer_ni: %s\n",
			 bad->wr_id, bad->opcode, bad->send_flags,
			 libcfs_nidstr(&conn->ibc_peer->ibp_nid));

		bad = NULL;
		if (lnet_send_error_simulation(tx->tx_lntmsg[0], &tx->tx_hstatus))
			rc = -EINVAL;
		else
#ifdef HAVE_OFED_IB_POST_SEND_RECV_CONST
			rc = ib_post_send(conn->ibc_cmid->qp, wr,
					  (const struct ib_send_wr **)&bad);
#else
			rc = ib_post_send(conn->ibc_cmid->qp, wr, &bad);
#endif
		if (frd && !frd->frd_posted) {
			/* The local invalidate becomes invalid (has been
			 * successfully used) if the post succeeds or the
			 * failing wr was not the invalidate.
			 */
			frd->frd_valid =
				!(rc == 0 || (bad != &frd->frd_inv_wr.wr));
		}
	}

	conn->ibc_last_send = ktime_get();

	if (rc == 0) {
		if (frd != NULL)
			frd->frd_posted = true;
		return 0;
	}

	/* NB credits are transferred in the actual
	 * message, which can only be the last work item
	 */
	conn->ibc_credits += credit;
	conn->ibc_outstanding_credits += msg->ibm_credits;
	conn->ibc_nsends_posted--;
	if (msg->ibm_type == IBLND_MSG_NOOP)
		conn->ibc_noops_posted--;

	tx->tx_status = rc;
	tx->tx_waiting = 0;
	tx->tx_sending--;

	done = (tx->tx_sending == 0);
	if (done)
		list_del(&tx->tx_list);

	spin_unlock(&conn->ibc_lock);

	if (conn->ibc_state == IBLND_CONN_ESTABLISHED)
		CERROR("posting transmit to %s: rc = %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid), rc);
	else
		CDEBUG(D_NET, "posting transmit to %s: rc = %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid), rc);

	kiblnd_close_conn(conn, rc);

	if (done)
		kiblnd_tx_done(tx);

	spin_lock(&conn->ibc_lock);

	return -EIO;
}

static void
kiblnd_check_sends_locked(struct kib_conn *conn)
{
	int ver = conn->ibc_version;
	struct lnet_ni *ni = conn->ibc_peer->ibp_ni;
	struct kib_tx *tx;

	/* Don't send anything until after the connection is established */
	if (conn->ibc_state < IBLND_CONN_ESTABLISHED) {
		CDEBUG(D_NET, "%s too soon\n",
		       libcfs_nidstr(&conn->ibc_peer->ibp_nid));
		return;
	}

	LASSERT(conn->ibc_nsends_posted <=
		kiblnd_concurrent_sends(ver, ni));
	LASSERT(!IBLND_OOB_CAPABLE(ver) ||
		conn->ibc_noops_posted <= IBLND_OOB_MSGS(ver));
	LASSERT(conn->ibc_reserved_credits >= 0);

	while (conn->ibc_reserved_credits > 0 &&
	       (tx = list_first_entry_or_null(&conn->ibc_tx_queue_rsrvd,
					      struct kib_tx, tx_list)) != NULL) {
		list_move_tail(&tx->tx_list, &conn->ibc_tx_queue);
		conn->ibc_reserved_credits--;
	}

	if (kiblnd_need_noop(conn)) {
		spin_unlock(&conn->ibc_lock);

		tx = kiblnd_get_idle_tx(ni, &conn->ibc_peer->ibp_nid);
		if (tx != NULL)
			kiblnd_init_tx_msg(ni, tx, IBLND_MSG_NOOP, 0);

		spin_lock(&conn->ibc_lock);
		if (tx != NULL)
			kiblnd_queue_tx_locked(tx, conn);
	}

	for (;;) {
		int credit;

		if (!list_empty(&conn->ibc_tx_queue_nocred)) {
			credit = 0;
			tx = list_first_entry(&conn->ibc_tx_queue_nocred,
					      struct kib_tx, tx_list);
		} else if (!list_empty(&conn->ibc_tx_noops)) {
			LASSERT(!IBLND_OOB_CAPABLE(ver));
			credit = 1;
			tx = list_first_entry(&conn->ibc_tx_noops,
					      struct kib_tx, tx_list);
		} else if (!list_empty(&conn->ibc_tx_queue)) {
			credit = 1;
			tx = list_first_entry(&conn->ibc_tx_queue,
					      struct kib_tx, tx_list);
		} else
			break;

		if (kiblnd_post_tx_locked(conn, tx, credit) != 0)
			break;
	}
}

static void
kiblnd_tx_complete(struct kib_tx *tx, int status)
{
	int failed = (status != IB_WC_SUCCESS);
	struct kib_conn *conn = tx->tx_conn;
	int idle;

	if (tx->tx_sending <= 0) {
		CERROR("Received an event on a freed tx: %p status %d\n",
		       tx, tx->tx_status);
		return;
	}

	if (failed) {
		if (conn->ibc_state == IBLND_CONN_ESTABLISHED)
			CNETERR("Tx -> %s cookie %#llx sending %d waiting %d: failed %d\n",
				libcfs_nidstr(&conn->ibc_peer->ibp_nid),
				tx->tx_cookie, tx->tx_sending, tx->tx_waiting,
				status);

		kiblnd_close_conn(conn, -EIO);
	} else {
		kiblnd_peer_alive(conn->ibc_peer);
	}

	spin_lock(&conn->ibc_lock);

	/* I could be racing with rdma completion.  Whoever makes 'tx' idle
	 * gets to free it, which also drops its ref on onn'.
	 */

	tx->tx_sending--;
	conn->ibc_nsends_posted--;
	if (tx->tx_msg->ibm_type == IBLND_MSG_NOOP)
		conn->ibc_noops_posted--;

	if (failed) {
		tx->tx_hstatus = LNET_MSG_STATUS_REMOTE_DROPPED;
		tx->tx_waiting = 0;             /* don't wait for peer_ni */
		tx->tx_status = -EIO;
#ifdef O2IBLND_CONN_STATE_DEBUG
		kiblnd_dump_conn_dbg(conn);
#endif
	}

	idle = (tx->tx_sending == 0) &&         /* This is the final callback */
		!tx->tx_waiting &&              /* Not waiting for peer_ni */
		!tx->tx_queued;                 /* Not re-queued (PUT_DONE) */
	if (idle)
		list_del(&tx->tx_list);

	kiblnd_check_sends_locked(conn);
	spin_unlock(&conn->ibc_lock);

	if (idle)
		kiblnd_tx_done(tx);
}


static void
kiblnd_init_tx_sge(struct kib_tx *tx, u64 addr, unsigned int len)
{
	struct ib_sge *sge = &tx->tx_sge[tx->tx_nsge];
	struct kib_hca_dev *hdev = tx->tx_pool->tpo_hdev;
#ifdef HAVE_OFED_IB_GET_DMA_MR
	struct ib_mr *mr = hdev->ibh_mrs;
#endif

	*sge = (struct ib_sge) {
#ifdef HAVE_OFED_IB_GET_DMA_MR
		.lkey   = mr->lkey,
#else
		.lkey   = hdev->ibh_pd->local_dma_lkey,
#endif
		.addr   = addr,
		.length = len,
	};

	tx->tx_nsge++;
}

static struct ib_rdma_wr *
kiblnd_init_tx_msg_payload(struct lnet_ni *ni, struct kib_tx *tx, int type,
		   int body_nob, int payload)
{
	struct ib_rdma_wr *wrq;
	int nob = offsetof(struct kib_msg, ibm_u) + body_nob;

	LASSERT(tx->tx_nwrq >= 0);
	LASSERT(tx->tx_nwrq < IBLND_MAX_RDMA_FRAGS + 1);
	LASSERT(nob <= IBLND_MSG_SIZE);

	kiblnd_init_msg(tx->tx_msg, type, body_nob + payload);

	wrq = &tx->tx_wrq[tx->tx_nwrq];

	*wrq = (struct ib_rdma_wr) {
		.wr = {
			.wr_id		= kiblnd_ptr2wreqid(tx, IBLND_WID_TX),
			.num_sge	= 1,
			.sg_list	= &tx->tx_sge[tx->tx_nsge],
			.opcode		= IB_WR_SEND,
			.send_flags	= IB_SEND_SIGNALED,
		},
	};

	kiblnd_init_tx_sge(tx, tx->tx_msgaddr, nob);

	tx->tx_nwrq++;
	return wrq;
}

static int
kiblnd_init_rdma(struct kib_conn *conn, struct kib_tx *tx, int type,
		 int resid, struct kib_rdma_desc *dstrd, u64 dstcookie)
{
	struct kib_msg *ibmsg = tx->tx_msg;
	struct kib_rdma_desc *srcrd = tx->tx_rd;
	struct ib_rdma_wr *wrq = NULL;
	struct ib_sge	  *sge;
	int		   rc  = resid;
	int		   srcidx;
	int		   dstidx;
	int		   sge_nob;
	int		   wrq_sge;

	LASSERT(!in_interrupt());
	LASSERT(tx->tx_nwrq == 0 && tx->tx_nsge == 0);
	LASSERT(type == IBLND_MSG_GET_DONE || type == IBLND_MSG_PUT_DONE);

	for (srcidx = dstidx = wrq_sge = sge_nob = 0;
	     resid > 0; resid -= sge_nob) {
		int prev = dstidx;

		if (srcidx >= srcrd->rd_nfrags) {
			rc = -EPROTO;
			CERROR("Src buffer exhausted: %d frags %px: rc = %d\n",
				srcidx, tx, rc);
			break;
		}

		if (dstidx >= dstrd->rd_nfrags) {
			rc = -EPROTO;
			CERROR("Dst buffer exhausted: %d frags: rc = %d\n",
			       dstidx, rc);
			break;
		}

		if (tx->tx_nwrq >= conn->ibc_max_frags) {
			rc = -EMSGSIZE;
			CERROR("RDMA has too many fragments for peer_ni %s (%d), src idx/frags: %d/%d dst idx/frags: %d/%d: rc = %d\n",
			       libcfs_nidstr(&conn->ibc_peer->ibp_nid),
			       conn->ibc_max_frags,
			       srcidx, srcrd->rd_nfrags,
			       dstidx, dstrd->rd_nfrags, rc);
			break;
		}

		sge_nob = min3(kiblnd_rd_frag_size(srcrd, srcidx),
			       kiblnd_rd_frag_size(dstrd, dstidx),
			       resid);

		sge = &tx->tx_sge[tx->tx_nsge];
		sge->addr   = kiblnd_rd_frag_addr(srcrd, srcidx);
		sge->lkey   = kiblnd_rd_frag_key(srcrd, srcidx);
		sge->length = sge_nob;

		if (wrq_sge == 0) {
			wrq = &tx->tx_wrq[tx->tx_nwrq];

			wrq->wr.next	= &(wrq + 1)->wr;
			wrq->wr.wr_id	= kiblnd_ptr2wreqid(tx, IBLND_WID_RDMA);
			wrq->wr.sg_list	= sge;
			wrq->wr.opcode	= IB_WR_RDMA_WRITE;
			wrq->wr.send_flags = 0;

#ifdef HAVE_OFED_IB_RDMA_WR
			wrq->remote_addr	= kiblnd_rd_frag_addr(dstrd,
								      dstidx);
			wrq->rkey		= kiblnd_rd_frag_key(dstrd,
								     dstidx);
#else
			wrq->wr.wr.rdma.remote_addr = kiblnd_rd_frag_addr(dstrd,
									dstidx);
			wrq->wr.wr.rdma.rkey	= kiblnd_rd_frag_key(dstrd,
								     dstidx);
#endif
		}

		srcidx = kiblnd_rd_consume_frag(srcrd, srcidx, sge_nob);
		dstidx = kiblnd_rd_consume_frag(dstrd, dstidx, sge_nob);

		wrq_sge++;
		if (wrq_sge == *kiblnd_tunables.kib_wrq_sge || dstidx != prev) {
			tx->tx_nwrq++;
			wrq->wr.num_sge = wrq_sge;
			wrq_sge = 0;
		}
		tx->tx_nsge++;
	}

	if (rc < 0)	/* no RDMA if completing with failure */
		tx->tx_nwrq = tx->tx_nsge = 0;

	ibmsg->ibm_u.completion.ibcm_status = rc;
	ibmsg->ibm_u.completion.ibcm_cookie = dstcookie;
	kiblnd_init_tx_msg(conn->ibc_peer->ibp_ni, tx,
			   type, sizeof(struct kib_completion_msg));

	return rc;
}

static void
kiblnd_queue_tx_locked(struct kib_tx *tx, struct kib_conn *conn)
{
	struct list_head *q;
	s64 timeout_ns;

	LASSERT(tx->tx_nwrq > 0);	/* work items set up */
	LASSERT(!tx->tx_queued);	/* not queued for sending already */
	LASSERT(conn->ibc_state >= IBLND_CONN_ESTABLISHED);

	if (conn->ibc_state >= IBLND_CONN_DISCONNECTED) {
		CDEBUG(D_NET, "connection with %s is disconnected\n",
		       conn->ibc_peer ?
		       libcfs_nidstr(&conn->ibc_peer->ibp_nid) : "NULL");

		tx->tx_status = -ECONNABORTED;
		tx->tx_waiting = 0;
		if (tx->tx_conn != NULL) {
			/* PUT_DONE first attached to conn as a PUT_REQ */
			LASSERT(tx->tx_conn == conn);
			LASSERT(tx->tx_msg->ibm_type == IBLND_MSG_PUT_DONE);
			tx->tx_conn = NULL;
			kiblnd_conn_decref(conn);
		}
		list_add(&tx->tx_list, &conn->ibc_zombie_txs);

		return;
	}

	timeout_ns = kiblnd_timeout() * NSEC_PER_SEC;
	tx->tx_queued = 1;
	tx->tx_deadline = ktime_add_ns(ktime_get(), timeout_ns);

	if (tx->tx_conn == NULL) {
		kiblnd_conn_addref(conn);
		tx->tx_conn = conn;
		LASSERT(tx->tx_msg->ibm_type != IBLND_MSG_PUT_DONE);
	} else {
		/* PUT_DONE first attached to conn as a PUT_REQ */
		LASSERT(tx->tx_conn == conn);
		LASSERT(tx->tx_msg->ibm_type == IBLND_MSG_PUT_DONE);
	}

	switch (tx->tx_msg->ibm_type) {
	default:
		LBUG();

	case IBLND_MSG_PUT_REQ:
	case IBLND_MSG_GET_REQ:
		q = &conn->ibc_tx_queue_rsrvd;
		break;

	case IBLND_MSG_PUT_NAK:
	case IBLND_MSG_PUT_ACK:
	case IBLND_MSG_PUT_DONE:
	case IBLND_MSG_GET_DONE:
		q = &conn->ibc_tx_queue_nocred;
		break;

	case IBLND_MSG_NOOP:
		if (IBLND_OOB_CAPABLE(conn->ibc_version))
			q = &conn->ibc_tx_queue_nocred;
		else
			q = &conn->ibc_tx_noops;
		break;

	case IBLND_MSG_IMMEDIATE:
		q = &conn->ibc_tx_queue;
		break;
	}

	list_add_tail(&tx->tx_list, q);
}

static void
kiblnd_queue_tx(struct kib_tx *tx, struct kib_conn *conn)
{
	spin_lock(&conn->ibc_lock);
	kiblnd_queue_tx_locked(tx, conn);
	kiblnd_check_sends_locked(conn);
	spin_unlock(&conn->ibc_lock);
}

static int
kiblnd_resolve_addr_cap(struct rdma_cm_id *cmid,
			struct sockaddr *srcaddr,
			struct sockaddr *dstaddr,
			int timeout_ms)
{
	unsigned short port;
	int rc;

	/* allow the port to be reused */
	rc = rdma_set_reuseaddr(cmid, 1);
	if (rc != 0) {
		CERROR("Unable to set reuse on cmid: rc = %d\n", rc);
		return rc;
	}

	/* look for a free privileged port */
	for (port = PROT_SOCK-1; port > 0; port--) {
		rc = 0;

		switch (srcaddr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sa = (void *)srcaddr;

			sa->sin_port = htons(port);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sa = (void *)srcaddr;

			sa->sin6_port = htons(port);
			break;
		}
		default:
			rc = -EOPNOTSUPP;
			break;
		}
		if (rc < 0)
			return rc;

		rc = rdma_resolve_addr(cmid, srcaddr, dstaddr, timeout_ms);
		if (rc == 0) {
			CDEBUG(D_NET, "bound to port %hu\n", port);
			return 0;
		} else if (rc == -EADDRINUSE || rc == -EADDRNOTAVAIL) {
			CDEBUG(D_NET, "bind to port %hu failed: %d\n",
			       port, rc);
		} else {
			return rc;
		}
	}

	CERROR("cannot bind to a free privileged port: rc = %d\n", rc);

	return rc;
}

static int
kiblnd_resolve_addr(struct rdma_cm_id *cmid,
		    struct sockaddr *srcaddr,
		    struct sockaddr *dstaddr,
		    int timeout_ms)
{
	const struct cred *old_creds = NULL;
	struct cred *new_creds;
	int rc;

	if (!capable(CAP_NET_BIND_SERVICE)) {
		new_creds = prepare_kernel_cred(&init_task);
		if (!new_creds)
			return -ENOMEM;

		cap_raise(new_creds->cap_effective, CAP_NET_BIND_SERVICE);
		old_creds = override_creds(new_creds);
	}

	rc = kiblnd_resolve_addr_cap(cmid, srcaddr, dstaddr, timeout_ms);

	if (old_creds)
		revert_creds(old_creds);

	return rc;
}

static void
kiblnd_connect_peer(struct kib_peer_ni *peer_ni)
{
	struct rdma_cm_id *cmid;
	struct kib_net *net = peer_ni->ibp_ni->ni_data;
	struct sockaddr_storage srcaddr;
	struct sockaddr_storage dstaddr;
	int rc;

	LASSERT(net != NULL);
	LASSERT(peer_ni->ibp_connecting > 0);

	cmid = kiblnd_rdma_create_id(peer_ni->ibp_ni->ni_net_ns,
				     kiblnd_cm_callback, peer_ni,
				     RDMA_PS_TCP, IB_QPT_RC);

	if (IS_ERR(cmid)) {
		rc = PTR_ERR(cmid);
		CERROR("Can't create CMID for %s: rc = %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid), rc);
		GOTO(failed, rc);
	}

	memset(&srcaddr, 0, sizeof(srcaddr));
	if (nid_is_nid4(&net->ibn_ni->ni_nid)) {
		struct sockaddr_in *sa = (void *)&srcaddr;

		sa->sin_family = AF_INET;
		sa->sin_addr.s_addr = net->ibn_ni->ni_nid.nid_addr[0];
	} else {
		struct sockaddr_in6 *sa = (void *)&srcaddr;

		sa->sin6_family = AF_INET6;
		memcpy(&sa->sin6_addr, &net->ibn_ni->ni_nid.nid_addr,
		       NID_ADDR_BYTES(&net->ibn_ni->ni_nid));
	}

	memset(&dstaddr, 0, sizeof(dstaddr));
	if (nid_is_nid4(&peer_ni->ibp_nid)) {
		struct sockaddr_in *sa = (void *)&dstaddr;

		sa->sin_family = AF_INET;
		sa->sin_port = htons(*kiblnd_tunables.kib_service);
		sa->sin_addr.s_addr = peer_ni->ibp_nid.nid_addr[0];
	} else {
		struct sockaddr_in6 *sa = (void *)&dstaddr;

		sa->sin6_family = AF_INET6;
		sa->sin6_port = htons(*kiblnd_tunables.kib_service);
		memcpy(&sa->sin6_addr, &peer_ni->ibp_nid.nid_addr,
		       NID_ADDR_BYTES(&peer_ni->ibp_nid));
	}

	kiblnd_peer_addref(peer_ni);               /* cmid's ref */

	if (*kiblnd_tunables.kib_use_priv_port) {
		rc = kiblnd_resolve_addr(cmid, (struct sockaddr *)&srcaddr,
					 (struct sockaddr *)&dstaddr,
					 RDMA_RESOLVE_TIMEOUT);
	} else {
		rc = rdma_resolve_addr(cmid, (struct sockaddr *)&srcaddr,
				       (struct sockaddr *)&dstaddr,
				       RDMA_RESOLVE_TIMEOUT);
	}
	if (rc != 0) {
		/* Can't initiate address resolution:  */
		CERROR("Can't resolve addr for %s: rc = %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid), rc);
		goto failed2;
	}

	return;

 failed2:
	kiblnd_peer_connect_failed(peer_ni, 1, rc);
	kiblnd_peer_decref(peer_ni);               /* cmid's ref */
	rdma_destroy_id(cmid);
	return;
 failed:
	kiblnd_peer_connect_failed(peer_ni, 1, rc);
}

bool
kiblnd_reconnect_peer(struct kib_peer_ni *peer_ni)
{
	rwlock_t *glock = &kiblnd_data.kib_global_lock;
	char *reason = NULL;
	LIST_HEAD(txs);
	unsigned long flags;

	write_lock_irqsave(glock, flags);
	if (peer_ni->ibp_reconnecting == 0) {
		if (peer_ni->ibp_accepting)
			reason = "accepting";
		else if (peer_ni->ibp_connecting)
			reason = "connecting";
		else if (!list_empty(&peer_ni->ibp_conns))
			reason = "connected";
		else /* connected then closed */
			reason = "closed";

		goto no_reconnect;
	}

	if (peer_ni->ibp_accepting)
		CNETERR("Detecting race between accepting and reconnecting\n");
	peer_ni->ibp_reconnecting--;

	if (!kiblnd_peer_active(peer_ni)) {
		list_splice_init(&peer_ni->ibp_tx_queue, &txs);
		reason = "unlinked";
		goto no_reconnect;
	}

	peer_ni->ibp_connecting++;
	peer_ni->ibp_reconnected++;

	write_unlock_irqrestore(glock, flags);

	kiblnd_connect_peer(peer_ni);
	return true;

 no_reconnect:
	write_unlock_irqrestore(glock, flags);

	CWARN("Abort reconnection of %s: %s\n",
	      libcfs_nidstr(&peer_ni->ibp_nid), reason);
	kiblnd_txlist_done(&txs, -ECONNABORTED,
			   LNET_MSG_STATUS_LOCAL_ABORTED);
	return false;
}


/**
 * Enqueue a tx waiting for a connection and set the deadline to the maximum
 * connection delay: max_d = d_resolve_addr + d_resolve_route + d_rdma_connect
 */
static inline void
kiblnd_queue_waiting_tx_locked(struct kib_tx *tx, struct kib_peer_ni *peer_ni)
{
	int d = kiblnd_connreq_timeout_ms() + 2 * RDMA_RESOLVE_TIMEOUT;

	tx->tx_deadline = ktime_add_ms(ktime_get(), d);
	list_add_tail(&tx->tx_list, &peer_ni->ibp_tx_queue);
}

void
kiblnd_launch_tx(struct lnet_ni *ni, struct kib_tx *tx, struct lnet_nid *nid)
{
	struct kib_peer_ni *peer_ni;
	struct kib_peer_ni *peer2;
	struct kib_conn *conn;
	rwlock_t *g_lock = &kiblnd_data.kib_global_lock;
	unsigned long flags;
	int rc;
	int i;
	struct lnet_ioctl_config_o2iblnd_tunables *tunables;

	/* If I get here, I've committed to send, so I complete the tx with
	 * failure on any problems
	 */

	LASSERT(!tx || !tx->tx_conn);	  /* only set when assigned a conn */
	LASSERT(!tx || tx->tx_nwrq > 0);  /* work items have been set up */

	/* First time, just use a read lock since I expect to find my peer_ni
	 * connected
	 */
	read_lock_irqsave(g_lock, flags);

	peer_ni = kiblnd_find_peer_locked(ni, nid);
	if (peer_ni != NULL && !list_empty(&peer_ni->ibp_conns)) {
		/* Found a peer_ni with an established connection */
		conn = kiblnd_get_conn_locked(peer_ni);
		kiblnd_conn_addref(conn); /* 1 ref for me... */

		read_unlock_irqrestore(g_lock, flags);

		if (tx != NULL)
			kiblnd_queue_tx(tx, conn);
		kiblnd_conn_decref(conn); /* ...to here */
		return;
	}

	read_unlock(g_lock);
	/* Re-try with a write lock */
	write_lock(g_lock);

	peer_ni = kiblnd_find_peer_locked(ni, nid);
	if (peer_ni != NULL) {
		if (list_empty(&peer_ni->ibp_conns)) {
			/* found a peer_ni, but it's still connecting... */
			LASSERT(kiblnd_peer_connecting(peer_ni));
			if (tx)
				kiblnd_queue_waiting_tx_locked(tx, peer_ni);
			write_unlock_irqrestore(g_lock, flags);
		} else {
			conn = kiblnd_get_conn_locked(peer_ni);
			kiblnd_conn_addref(conn); /* 1 ref for me... */

			write_unlock_irqrestore(g_lock, flags);

			if (tx != NULL)
				kiblnd_queue_tx(tx, conn);
			kiblnd_conn_decref(conn); /* ...to here */
		}
		return;
	}

	write_unlock_irqrestore(g_lock, flags);

	/* Allocate a peer_ni ready to add to the peer_ni table and retry */
	rc = kiblnd_create_peer(ni, &peer_ni, nid);
	if (rc != 0) {
		CERROR("Can't create peer_ni %s: rc = %d\n",
		       libcfs_nidstr(nid), rc);
		if (tx != NULL) {
			tx->tx_status = -EHOSTUNREACH;
			tx->tx_waiting = 0;
			tx->tx_hstatus = LNET_MSG_STATUS_LOCAL_ERROR;
			kiblnd_tx_done(tx);
		}
		return;
	}

	write_lock_irqsave(g_lock, flags);

	peer2 = kiblnd_find_peer_locked(ni, nid);
	if (peer2 != NULL) {
		if (list_empty(&peer2->ibp_conns)) {
			/* found a peer_ni, but it's still connecting... */
			LASSERT(kiblnd_peer_connecting(peer2));
			if (tx)
				kiblnd_queue_waiting_tx_locked(tx, peer2);
			write_unlock_irqrestore(g_lock, flags);
		} else {
			conn = kiblnd_get_conn_locked(peer2);
			kiblnd_conn_addref(conn); /* 1 ref for me... */

			write_unlock_irqrestore(g_lock, flags);

			if (tx != NULL)
				kiblnd_queue_tx(tx, conn);
			kiblnd_conn_decref(conn); /* ...to here */
		}

		kiblnd_peer_decref(peer_ni);
		return;
	}

	/* Brand new peer_ni */
	LASSERT(peer_ni->ibp_connecting == 0);
	tunables = &peer_ni->ibp_ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib;
	peer_ni->ibp_connecting = tunables->lnd_conns_per_peer;

	/* always called with a ref on ni, which prevents ni being shutdown */
	LASSERT(((struct kib_net *)ni->ni_data)->ibn_shutdown == 0);

	if (tx)
		kiblnd_queue_waiting_tx_locked(tx, peer_ni);

	kiblnd_peer_addref(peer_ni);
	hash_add(kiblnd_data.kib_peers, &peer_ni->ibp_list, nidhash(nid));

	write_unlock_irqrestore(g_lock, flags);

	for (i = 0; i < tunables->lnd_conns_per_peer; i++)
		kiblnd_connect_peer(peer_ni);
	kiblnd_peer_decref(peer_ni);
}

int
kiblnd_send(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg)
{
	struct kib_dev *dev = ((struct kib_net *)ni->ni_data)->ibn_dev;
	struct lnet_hdr *hdr = &lntmsg->msg_hdr;
	int type = lntmsg->msg_type;
	struct lnet_processid *target = &lntmsg->msg_target;
	int target_is_router = lntmsg->msg_target_is_router;
	int routing = lntmsg->msg_routing;
	unsigned int payload_niov = lntmsg->msg_niov;
	struct bio_vec *payload_kiov = lntmsg->msg_kiov;
	unsigned int payload_offset = lntmsg->msg_offset;
	unsigned int payload_nob = lntmsg->msg_len;
	struct lnet_libmd *msg_md = lntmsg->msg_md;
	bool gpu;
	struct kib_msg *ibmsg;
	struct kib_rdma_desc *rd;
	struct kib_tx *tx;
	int nob;
	int rc;

	/* NB 'private' is different depending on what we're sending.... */

	CDEBUG(D_NET, "sending %d bytes in %d frags to %s\n",
	       payload_nob, payload_niov, libcfs_idstr(target));

	LASSERT(payload_nob == 0 || payload_niov > 0);

	/* Thread context */
	LASSERT(!in_interrupt());

	tx = kiblnd_get_idle_tx(ni, &target->nid);
	if (tx == NULL) {
		CERROR("Can't allocate %s txd for %s\n",
			lnet_msgtyp2str(type),
			libcfs_nidstr(&target->nid));
		return -ENOMEM;
	}
	ibmsg = tx->tx_msg;
	gpu = lnet_md_is_gpu(msg_md);

	switch (type) {
	default:
		LBUG();
		return (-EIO);

	case LNET_MSG_ACK:
		LASSERT(payload_nob == 0);
		break;

	case LNET_MSG_GET:
		if (routing || target_is_router)
			break;                  /* send IMMEDIATE */

		/* is the REPLY message too small for RDMA? */
		nob = offsetof(struct kib_msg,
			       ibm_u.immediate.ibim_payload[msg_md->md_length]);
		if (nob <= IBLND_MSG_SIZE && !gpu)
			break;                  /* send IMMEDIATE */

		rd = &ibmsg->ibm_u.get.ibgm_rd;
		tx->tx_gpu = gpu;
		rc = kiblnd_setup_rd_kiov(ni, tx, rd,
					  msg_md->md_niov,
					  msg_md->md_kiov,
					  0, msg_md->md_length);
		if (rc != 0) {
			CERROR("Can't setup GET sink %s: rc = %d\n",
			       libcfs_nidstr(&target->nid), rc);
			tx->tx_hstatus = LNET_MSG_STATUS_LOCAL_ERROR;
			kiblnd_tx_done(tx);
			return -EIO;
		}

		nob = offsetof(struct kib_get_msg, ibgm_rd.rd_frags[rd->rd_nfrags]);
		ibmsg->ibm_u.get.ibgm_cookie = tx->tx_cookie;
		lnet_hdr_to_nid4(hdr, &ibmsg->ibm_u.get.ibgm_hdr);

		kiblnd_init_tx_msg(ni, tx, IBLND_MSG_GET_REQ, nob);

		tx->tx_lntmsg[1] = lnet_create_reply_msg(ni, lntmsg);
		if (tx->tx_lntmsg[1] == NULL) {
			CERROR("Can't create reply for GET -> %s: rc = %d\n",
			       libcfs_nidstr(&target->nid), -EIO);
			kiblnd_tx_done(tx);
			return -EIO;
		}

		/* finalise lntmsg[0,1] on completion */
		tx->tx_lntmsg[0] = lntmsg;
		tx->tx_waiting = 1;             /* waiting for GET_DONE */
		kiblnd_launch_tx(ni, tx, &target->nid);
		return 0;

	case LNET_MSG_REPLY:
	case LNET_MSG_PUT:
		/* Is the payload small enough not to need RDMA? */
		nob = offsetof(struct kib_msg,
				ibm_u.immediate.ibim_payload[payload_nob]);
		if (nob <= IBLND_MSG_SIZE && !gpu)
			break;			/* send IMMEDIATE */

		tx->tx_gpu = gpu;

		rc = kiblnd_setup_rd_kiov(ni, tx, tx->tx_rd,
					  payload_niov, payload_kiov,
					  payload_offset, payload_nob);
		if (rc != 0) {
			CERROR("Can't setup PUT src for %s: rc = %d\n",
			       libcfs_nidstr(&target->nid), rc);
			kiblnd_tx_done(tx);
			return -EIO;
		}

		lnet_hdr_to_nid4(hdr, &ibmsg->ibm_u.putreq.ibprm_hdr);
		ibmsg->ibm_u.putreq.ibprm_cookie = tx->tx_cookie;
		kiblnd_init_tx_msg(ni, tx, IBLND_MSG_PUT_REQ,
				   sizeof(struct kib_putreq_msg));

		/* finalise lntmsg[0,1] on completion */
		tx->tx_lntmsg[0] = lntmsg;
		tx->tx_waiting = 1;             /* waiting for PUT_{ACK,NAK} */
		kiblnd_launch_tx(ni, tx, &target->nid);
		return 0;
	}

	/* send IMMEDIATE */
	LASSERT(offsetof(struct kib_msg,
			 ibm_u.immediate.ibim_payload[payload_nob]) <=
			 IBLND_MSG_SIZE);

	ibmsg = tx->tx_msg;
	lnet_hdr_to_nid4(hdr, &ibmsg->ibm_u.immediate.ibim_hdr);

	if (IS_FAST_REG_DEV(dev) && payload_nob)  {
		struct ib_rdma_wr *wrq;
		int i;

		nob = offsetof(struct kib_immediate_msg, ibim_payload[0]);
		wrq = kiblnd_init_tx_msg_payload(ni, tx, IBLND_MSG_IMMEDIATE,
						 nob, payload_nob);

		rd = tx->tx_rd;
		rc = kiblnd_setup_rd_kiov(ni, tx, rd,
					  payload_niov, payload_kiov,
					  payload_offset, payload_nob);
		if (rc != 0) {
			CERROR("Can't setup IMMEDIATE src %s: rc = %d\n",
			       libcfs_nidstr(&target->nid), rc);
			kiblnd_tx_done(tx);
			return -EIO;
		}

		/* lets generate a SGE chain */
		for (i = 0; i < rd->rd_nfrags; i++) {
			kiblnd_init_tx_sge(tx, rd->rd_frags[i].rf_addr,
					   rd->rd_frags[i].rf_nob);
			wrq->wr.num_sge++;
		}
	} else {
		lnet_copy_kiov2flat(IBLND_MSG_SIZE, ibmsg,
				    offsetof(struct kib_msg,
					     ibm_u.immediate.ibim_payload),
				    payload_niov, payload_kiov,
				    payload_offset, payload_nob);

		nob = offsetof(struct kib_immediate_msg,
			       ibim_payload[payload_nob]);

		kiblnd_init_tx_msg(ni, tx, IBLND_MSG_IMMEDIATE, nob);
	}

	/* finalise lntmsg on completion */
	tx->tx_lntmsg[0] = lntmsg;

	kiblnd_launch_tx(ni, tx, &target->nid);
	return 0;
}

static void
kiblnd_reply(struct lnet_ni *ni, struct kib_rx *rx, struct lnet_msg *lntmsg)
{
	struct lnet_processid *target = &lntmsg->msg_target;
	unsigned int niov = lntmsg->msg_niov;
	struct bio_vec *kiov = lntmsg->msg_kiov;
	unsigned int offset = lntmsg->msg_offset;
	unsigned int nob = lntmsg->msg_len;
	struct lnet_libmd *msg_md = lntmsg->msg_md;
	struct kib_tx *tx;
	int rc;

	tx = kiblnd_get_idle_tx(ni, &rx->rx_conn->ibc_peer->ibp_nid);
	if (tx == NULL) {
		CERROR("Can't get tx for REPLY to %s\n",
		       libcfs_nidstr(&target->nid));
		goto failed_0;
	}

	tx->tx_gpu = lnet_md_is_gpu(msg_md);

	if (nob == 0)
		rc = 0;
	else
		rc = kiblnd_setup_rd_kiov(ni, tx, tx->tx_rd,
					  niov, kiov, offset, nob);

	if (rc != 0) {
		CERROR("Can't setup GET src for %s: rc = %d\n",
		       libcfs_nidstr(&target->nid), rc);
		goto failed_1;
	}

	rc = kiblnd_init_rdma(rx->rx_conn, tx,
			      IBLND_MSG_GET_DONE, nob,
			      &rx->rx_msg->ibm_u.get.ibgm_rd,
			      rx->rx_msg->ibm_u.get.ibgm_cookie);
	if (rc < 0) {
		CERROR("Can't setup rdma for GET from %s: rc = %d\n",
		       libcfs_nidstr(&target->nid), rc);
		goto failed_1;
	}

	if (nob == 0) {
		/* No RDMA: local completion may happen now! */
		lnet_finalize(lntmsg, 0);
	} else {
		/* RDMA: lnet_finalize(lntmsg) when it completes */
		tx->tx_lntmsg[0] = lntmsg;
	}

	kiblnd_queue_tx(tx, rx->rx_conn);
	return;


failed_1:
	tx->tx_hstatus = LNET_MSG_STATUS_LOCAL_ERROR;
	kiblnd_tx_done(tx);
failed_0:
	lnet_finalize(lntmsg, -EIO);
}

unsigned int
kiblnd_get_dev_prio(struct lnet_ni *ni, unsigned int dev_idx)
{
	struct kib_net *net = ni->ni_data;
	struct device *dev = NULL;

	if (net)
		dev = net->ibn_dev->ibd_hdev->ibh_ibdev->dma_device;

	return lnet_get_dev_prio(dev, dev_idx);

}

int
kiblnd_recv(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg,
	    int delayed, unsigned int niov, struct bio_vec *kiov,
	    unsigned int offset, unsigned int mlen, unsigned int rlen)
{
	struct kib_rx *rx = private;
	struct kib_msg *rxmsg = rx->rx_msg;
	struct kib_conn *conn = rx->rx_conn;
	struct kib_tx *tx;
	__u64 ibprm_cookie;
	int nob;
	int post_credit = IBLND_POSTRX_PEER_CREDIT;
	int rc = 0;

	LASSERT(mlen <= rlen);
	LASSERT(!in_interrupt());

	switch (rxmsg->ibm_type) {
	default:
		LBUG();
		/* fallthrough */
	case IBLND_MSG_IMMEDIATE:
		nob = offsetof(struct kib_msg,
			       ibm_u.immediate.ibim_payload[rlen]);
		if (nob > rx->rx_nob) {
			char *nid = "unknown";

			if (lntmsg)
				nid = libcfs_nidstr(&lntmsg->msg_hdr.src_nid);
			rc = -EPROTO;
			CERROR("Immediate message from %s too big: %d(%d): rc = %d\n",
			       nid, nob, rx->rx_nob, rc);
			break;
		}

		lnet_copy_flat2kiov(niov, kiov, offset,
				    IBLND_MSG_SIZE, rxmsg,
				    offsetof(struct kib_msg,
					     ibm_u.immediate.ibim_payload),
				    mlen);
		lnet_finalize(lntmsg, 0);
		break;

	case IBLND_MSG_PUT_REQ: {
		struct kib_msg	*txmsg;
		struct kib_rdma_desc *rd;
		struct lnet_libmd *msg_md = NULL;

		if (lntmsg)
			msg_md = lntmsg->msg_md;

		ibprm_cookie = rxmsg->ibm_u.putreq.ibprm_cookie;
		if (mlen == 0) {
			lnet_finalize(lntmsg, 0);
			kiblnd_send_completion(rx->rx_conn, IBLND_MSG_PUT_NAK,
					       0, ibprm_cookie);
			break;
		}

		tx = kiblnd_get_idle_tx(ni, &conn->ibc_peer->ibp_nid);
		if (tx == NULL) {
			rc = -ENOMEM;
			CERROR("Can't allocate tx for %s: rc = %d\n",
				libcfs_nidstr(&conn->ibc_peer->ibp_nid), rc);
			/* Not replying will break the connection */
			break;
		}

		tx->tx_gpu = lnet_md_is_gpu(msg_md);

		txmsg = tx->tx_msg;
		rd = &txmsg->ibm_u.putack.ibpam_rd;
		rc = kiblnd_setup_rd_kiov(ni, tx, rd,
					  niov, kiov, offset, mlen);
		if (rc != 0) {
			CERROR("Can't setup PUT sink for %s: rc = %d\n",
			       libcfs_nidstr(&conn->ibc_peer->ibp_nid), rc);
			tx->tx_hstatus = LNET_MSG_STATUS_LOCAL_ERROR;
			kiblnd_tx_done(tx);
			/* tell peer_ni it's over */
			kiblnd_send_completion(rx->rx_conn, IBLND_MSG_PUT_NAK,
					       rc, ibprm_cookie);
			break;
		}

		nob = offsetof(struct kib_putack_msg,
			       ibpam_rd.rd_frags[rd->rd_nfrags]);
		txmsg->ibm_u.putack.ibpam_src_cookie = ibprm_cookie;
		txmsg->ibm_u.putack.ibpam_dst_cookie = tx->tx_cookie;

		kiblnd_init_tx_msg(ni, tx, IBLND_MSG_PUT_ACK, nob);

		tx->tx_lntmsg[0] = lntmsg;   /* finalise lntmsg on completion */
		tx->tx_waiting = 1;          /* waiting for PUT_DONE */
		kiblnd_queue_tx(tx, conn);

		/* reposted buffer reserved for PUT_DONE */
		post_credit = IBLND_POSTRX_NO_CREDIT;
		break;
		}

	case IBLND_MSG_GET_REQ:
		if (lntmsg != NULL) {
			/* Optimized GET; RDMA lntmsg's payload */
			kiblnd_reply(ni, rx, lntmsg);
		} else {
			/* GET didn't match anything */
			kiblnd_send_completion(rx->rx_conn, IBLND_MSG_GET_DONE,
					       -ENODATA,
					       rxmsg->ibm_u.get.ibgm_cookie);
		}
		break;
	}

	kiblnd_post_rx(rx, post_credit);
	return rc;
}

static void
kiblnd_thread_fini(void)
{
	atomic_dec(&kiblnd_data.kib_nthreads);
}

static void
kiblnd_peer_alive(struct kib_peer_ni *peer_ni)
{
	/* This is racy, but everyone's only writing ktime_get_seconds() */
	peer_ni->ibp_last_alive = ktime_get_seconds();
	smp_mb();
}

static void
kiblnd_peer_notify(struct kib_peer_ni *peer_ni)
{
	int error = 0;
	time64_t last_alive = 0;
	unsigned long flags;

	read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	if (kiblnd_peer_idle(peer_ni) && peer_ni->ibp_error != 0) {
		error = peer_ni->ibp_error;
		peer_ni->ibp_error = 0;

		last_alive = peer_ni->ibp_last_alive;
	}

	read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	if (error != 0)
		lnet_notify(peer_ni->ibp_ni, &peer_ni->ibp_nid,
			    false, false, last_alive);
}

void
kiblnd_close_conn_locked(struct kib_conn *conn, int error)
{
	/* This just does the immediate housekeeping.  'error' is zero for a
	 * normal shutdown which can happen only after the connection has been
	 * established.  If the connection is established, schedule the
	 * connection to be finished off by the connd.  Otherwise the connd is
	 * already dealing with it (either to set it up or tear it down).
	 * Caller holds kib_global_lock exclusively in irq context
	 */
	struct kib_peer_ni *peer_ni = conn->ibc_peer;
	struct kib_dev *dev;
	unsigned long flags;

	LASSERT(error != 0 || conn->ibc_state >= IBLND_CONN_ESTABLISHED);

	if (error != 0 && conn->ibc_comms_error == 0)
		conn->ibc_comms_error = error;

	if (conn->ibc_state != IBLND_CONN_ESTABLISHED)
		return; /* already being handled  */

	if (error == 0 &&
	    list_empty(&conn->ibc_tx_noops) &&
	    list_empty(&conn->ibc_tx_queue) &&
	    list_empty(&conn->ibc_tx_queue_rsrvd) &&
	    list_empty(&conn->ibc_tx_queue_nocred) &&
	    list_empty(&conn->ibc_active_txs))
		CDEBUG(D_NET, "closing conn %p to %s\n",
		       conn, libcfs_nidstr(&peer_ni->ibp_nid));
	else
		CNETERR("Closing conn %p to %s: error %d%s%s%s%s%s\n",
			conn,
			libcfs_nidstr(&peer_ni->ibp_nid), error,
			list_empty(&conn->ibc_tx_queue) ? "" : "(sending)",
			list_empty(&conn->ibc_tx_noops) ?
						"" : "(sending_noops)",
			list_empty(&conn->ibc_tx_queue_rsrvd) ?
						"" : "(sending_rsrvd)",
			list_empty(&conn->ibc_tx_queue_nocred) ?
						"" : "(sending_nocred)",
			list_empty(&conn->ibc_active_txs) ? "" : "(waiting)");

	dev = ((struct kib_net *)peer_ni->ibp_ni->ni_data)->ibn_dev;
	if (peer_ni->ibp_next_conn == conn)
		/* clear next_conn so it won't be used */
		peer_ni->ibp_next_conn = NULL;
	list_del(&conn->ibc_list);
	/* connd (see below) takes over ibc_list's ref */

	if (list_empty(&peer_ni->ibp_conns) &&    /* no more conns */
		kiblnd_peer_active(peer_ni)) {    /* still in peer_ni table */
		kiblnd_unlink_peer_locked(peer_ni);

		/* set/clear error on last conn */
		peer_ni->ibp_error = conn->ibc_comms_error;
	}

	kiblnd_set_conn_state(conn, IBLND_CONN_CLOSING);

	if (error != 0 &&
	    kiblnd_dev_can_failover(dev)) {
		list_add_tail(&dev->ibd_fail_list,
			      &kiblnd_data.kib_failed_devs);
		wake_up(&kiblnd_data.kib_failover_waitq);
	}

	spin_lock_irqsave(&kiblnd_data.kib_connd_lock, flags);

	list_add_tail(&conn->ibc_list, &kiblnd_data.kib_connd_conns);
	wake_up(&kiblnd_data.kib_connd_waitq);

	spin_unlock_irqrestore(&kiblnd_data.kib_connd_lock, flags);
}

void
kiblnd_close_conn(struct kib_conn *conn, int error)
{
	unsigned long flags;

	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	kiblnd_close_conn_locked(conn, error);

	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
}

static void
kiblnd_handle_early_rxs(struct kib_conn *conn)
{
	unsigned long flags;
	struct kib_rx *rx;

	LASSERT(!in_interrupt());
	if (conn->ibc_state < IBLND_CONN_ESTABLISHED) {
		CERROR("conn %p: bad state %d\n", conn, conn->ibc_state);
		return;
	}

	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
	while ((rx = list_first_entry_or_null(&conn->ibc_early_rxs,
					      struct kib_rx,
					      rx_list)) != NULL) {
		list_del(&rx->rx_list);
		write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

		kiblnd_handle_rx(rx);

		write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
	}
	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
}

void
kiblnd_abort_txs(struct kib_conn *conn, struct list_head *txs)
{
	LIST_HEAD(zombies);
	struct kib_tx *nxt;
	struct kib_tx *tx;

	spin_lock(&conn->ibc_lock);

	list_for_each_entry_safe(tx, nxt, txs, tx_list) {
		if (txs == &conn->ibc_active_txs) {
			LASSERT(!tx->tx_queued);
			LASSERT(tx->tx_waiting ||
				tx->tx_sending != 0);
			if (conn->ibc_comms_error == -ETIMEDOUT) {
				if (tx->tx_waiting && !tx->tx_sending)
					tx->tx_hstatus =
					  LNET_MSG_STATUS_REMOTE_TIMEOUT;
				else if (tx->tx_sending)
					tx->tx_hstatus =
					  LNET_MSG_STATUS_NETWORK_TIMEOUT;
			}
		} else {
			LASSERT(tx->tx_queued);
			if (conn->ibc_comms_error == -ETIMEDOUT)
				tx->tx_hstatus = LNET_MSG_STATUS_LOCAL_TIMEOUT;
			else
				tx->tx_hstatus = LNET_MSG_STATUS_LOCAL_ERROR;
		}

		tx->tx_status = -ECONNABORTED;
		tx->tx_waiting = 0;

		/*
		 * TODO: This makes an assumption that
		 * kiblnd_tx_complete() will be called for each tx. If
		 * that event is dropped we could end up with stale
		 * connections floating around. We'd like to deal with
		 * that in a better way.
		 *
		 * Also that means we can exceed the timeout by many
		 * seconds.
		 */
		if (tx->tx_sending == 0) {
			tx->tx_queued = 0;
			list_move(&tx->tx_list, &zombies);
		}
	}

	spin_unlock(&conn->ibc_lock);

	/*
	 * aborting transmits occurs when finalizing the connection.
	 * The connection is finalized on error.
	 * Passing LNET_MSG_STATUS_OK to txlist_done() will not
	 * override the value already set in tx->tx_hstatus above.
	 */
	kiblnd_txlist_done(&zombies, -ECONNABORTED, LNET_MSG_STATUS_OK);
}

static void
kiblnd_finalise_conn(struct kib_conn *conn)
{
	LASSERT(!in_interrupt());
	LASSERT(conn->ibc_state > IBLND_CONN_INIT);

	/* abort_receives moves QP state to IB_QPS_ERR.  This is only required
	 * for connections that didn't get as far as being connected, because
	 * rdma_disconnect() does this for free.
	 */
	kiblnd_abort_receives(conn);

	kiblnd_set_conn_state(conn, IBLND_CONN_DISCONNECTED);

	/* Complete all tx descs not waiting for sends to complete.
	 * NB we should be safe from RDMA now that the QP has changed state
	 */

	CDEBUG(D_NET, "abort connection with %s\n",
	       libcfs_nidstr(&conn->ibc_peer->ibp_nid));

	kiblnd_abort_txs(conn, &conn->ibc_tx_noops);
	kiblnd_abort_txs(conn, &conn->ibc_tx_queue);
	kiblnd_abort_txs(conn, &conn->ibc_tx_queue_rsrvd);
	kiblnd_abort_txs(conn, &conn->ibc_tx_queue_nocred);
	kiblnd_abort_txs(conn, &conn->ibc_active_txs);

	kiblnd_handle_early_rxs(conn);
}

static void
kiblnd_peer_connect_failed(struct kib_peer_ni *peer_ni, int active,
			   int error)
{
	LIST_HEAD(zombies);
	unsigned long flags;
	enum lnet_msg_hstatus hstatus;

	LASSERT(error != 0);
	LASSERT(!in_interrupt());

	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	if (active) {
		LASSERT(peer_ni->ibp_connecting > 0);
		peer_ni->ibp_connecting--;
	} else {
		LASSERT(peer_ni->ibp_accepting > 0);
		peer_ni->ibp_accepting--;
	}

	if (kiblnd_peer_connecting(peer_ni)) {
		/* another connection attempt under way... */
		write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);
		return;
	}

	peer_ni->ibp_reconnected = 0;
	if (list_empty(&peer_ni->ibp_conns)) {
		/* Take peer_ni's blocked transmits to complete with error */
		list_splice_init(&peer_ni->ibp_tx_queue, &zombies);

		if (kiblnd_peer_active(peer_ni))
			kiblnd_unlink_peer_locked(peer_ni);

		peer_ni->ibp_error = error;
	} else {
		/* Can't have blocked transmits if there are connections */
		LASSERT(list_empty(&peer_ni->ibp_tx_queue));
	}

	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	kiblnd_peer_notify(peer_ni);

	if (list_empty(&zombies))
		return;

	CNETERR("Deleting messages for %s: connection failed\n",
		libcfs_nidstr(&peer_ni->ibp_nid));

	switch (error) {
	case -EHOSTUNREACH:
	case -ETIMEDOUT:
		hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		break;
	case -ECONNREFUSED:
		hstatus = LNET_MSG_STATUS_REMOTE_DROPPED;
		break;
	default:
		hstatus = LNET_MSG_STATUS_LOCAL_DROPPED;
		break;
	}

	kiblnd_txlist_done(&zombies, error, hstatus);
}

static void
kiblnd_connreq_done(struct kib_conn *conn, int status)
{
	struct kib_peer_ni *peer_ni = conn->ibc_peer;
	struct kib_tx *tx;
	LIST_HEAD(txs);
	unsigned long flags;
	int active;

	active = (conn->ibc_state == IBLND_CONN_ACTIVE_CONNECT);

	CDEBUG(D_NET, "%s: active(%d), version(%x), status(%d)\n",
	       libcfs_nidstr(&peer_ni->ibp_nid), active,
	       conn->ibc_version, status);

	LASSERT(!in_interrupt());
	LASSERT((conn->ibc_state == IBLND_CONN_ACTIVE_CONNECT &&
		  peer_ni->ibp_connecting > 0) ||
		 (conn->ibc_state == IBLND_CONN_PASSIVE_WAIT &&
		  peer_ni->ibp_accepting > 0));

	LIBCFS_FREE(conn->ibc_connvars, sizeof(*conn->ibc_connvars));
	conn->ibc_connvars = NULL;

	if (status != 0) {
		/* failed to establish connection */
		kiblnd_peer_connect_failed(peer_ni, active, status);
		kiblnd_finalise_conn(conn);
		return;
	}

	/* connection established */
	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	conn->ibc_last_send = ktime_get();
	kiblnd_set_conn_state(conn, IBLND_CONN_ESTABLISHED);
	kiblnd_peer_alive(peer_ni);

	/* Add conn to peer_ni's list and nuke any dangling conns from a
	 * different peer_ni instance...
	 */
	kiblnd_conn_addref(conn); /* +1 ref for ibc_list */
	list_add(&conn->ibc_list, &peer_ni->ibp_conns);
	peer_ni->ibp_reconnected = 0;
	if (active)
		peer_ni->ibp_connecting--;
	else
		peer_ni->ibp_accepting--;

	if (peer_ni->ibp_version == 0) {
		peer_ni->ibp_version     = conn->ibc_version;
		peer_ni->ibp_incarnation = conn->ibc_incarnation;
	}

	if (peer_ni->ibp_version != conn->ibc_version ||
	    peer_ni->ibp_incarnation != conn->ibc_incarnation) {
		kiblnd_close_stale_conns_locked(peer_ni, conn->ibc_version,
						conn->ibc_incarnation);
		peer_ni->ibp_version     = conn->ibc_version;
		peer_ni->ibp_incarnation = conn->ibc_incarnation;
	}

	/* grab pending txs while I have the lock */
	list_splice_init(&peer_ni->ibp_tx_queue, &txs);

	if (!kiblnd_peer_active(peer_ni) ||     /* peer_ni has been deleted */
	    conn->ibc_comms_error != 0) {       /* error has happened already */

		/* start to shut down connection */
		kiblnd_close_conn_locked(conn, -ECONNABORTED);
		write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

		kiblnd_txlist_done(&txs, -ECONNABORTED,
				   LNET_MSG_STATUS_LOCAL_ERROR);

		return;
	}

	/* +1 ref for myself, this connection is visible to other threads
	 * now, refcount of peer:ibp_conns can be released by connection
	 * close from either a different thread, or the calling of
	 * kiblnd_check_sends_locked() below. See bz21911 for details.
	 */
	kiblnd_conn_addref(conn);
	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	/* Schedule blocked txs
	 * Note: if we are running with conns_per_peer > 1, these blocked
	 * txs will all get scheduled to the first connection which gets
	 * scheduled.  We won't be using round robin on this first batch.
	 */
	spin_lock(&conn->ibc_lock);
	while ((tx = list_first_entry_or_null(&txs, struct kib_tx,
					      tx_list)) != NULL) {
		list_del(&tx->tx_list);

		kiblnd_queue_tx_locked(tx, conn);
	}
	kiblnd_check_sends_locked(conn);
	spin_unlock(&conn->ibc_lock);

	/* schedule blocked rxs */
	kiblnd_handle_early_rxs(conn);
	kiblnd_conn_decref(conn);
}

static int
kiblnd_deregister_connreq(struct kib_conn *conn)
{
	unsigned long flags;
	int rc = 0;

	/* check race conditions */
	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	if (conn->ibc_state == IBLND_CONN_ACTIVE_CONNECT &&
	    !list_empty(&conn->ibc_list))
		list_del_init(&conn->ibc_list);
	else if (conn->ibc_state != IBLND_CONN_PASSIVE_WAIT)
		rc = -EALREADY;

	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	return rc;
}

static inline void
kiblnd_abort_connreq(struct kib_conn *conn)
{
	/* ignore, if already handled by the CM */
	if (kiblnd_deregister_connreq(conn))
		return;

	kiblnd_connreq_done(conn, -ENETDOWN);
	kiblnd_conn_decref(conn);
}

static void
kiblnd_reject(struct rdma_cm_id *cmid, struct kib_rej *rej)
{
	int rc;

#ifdef HAVE_OFED_RDMA_REJECT_4ARGS
	rc = rdma_reject(cmid, rej, sizeof(*rej), IB_CM_REJ_CONSUMER_DEFINED);
#else
	rc = rdma_reject(cmid, rej, sizeof(*rej));
#endif

	if (rc != 0)
		CWARN("Error sending reject: rc = %d\n", rc);
}

static int
kiblnd_passive_connect(struct rdma_cm_id *cmid, void *priv, int priv_nob)
{
	rwlock_t *g_lock = &kiblnd_data.kib_global_lock;
	struct kib_msg *reqmsg = priv;
	struct kib_msg *ackmsg;
	struct kib_dev *ibdev;
	struct kib_peer_ni *peer_ni;
	struct kib_peer_ni *peer2;
	struct kib_conn *conn;
	struct lnet_ni *ni = NULL;
	struct kib_net *net = NULL;
	struct lnet_nid destnid;
	struct lnet_nid srcnid;
	struct rdma_conn_param cp;
	struct kib_rej rej;
	int version = IBLND_MSG_VERSION;
	unsigned long flags;
	int port = PROT_SOCK, rc;

	LASSERT(!in_interrupt());
	/* cmid inherits 'context' from the corresponding listener id */
	ibdev = cmid->context;
	LASSERT(ibdev);

	memset(&rej, 0, sizeof(rej));
	rej.ibr_magic                = IBLND_MSG_MAGIC;
	rej.ibr_why                  = IBLND_REJECT_FATAL;
	rej.ibr_cp.ibcp_max_msg_size = IBLND_MSG_SIZE;

	if (*kiblnd_tunables.kib_require_priv_port) {
		switch (cmid->route.addr.dst_addr.ss_family) {
		case AF_INET6: {
			struct sockaddr_in6 *sa;

			sa = (struct sockaddr_in6 *)&(cmid->route.addr.dst_addr);
			port = ntohs(sa->sin6_port);
			break;
		}
		case AF_INET: {
			struct sockaddr_in *sa;

			sa = (struct sockaddr_in *)&(cmid->route.addr.dst_addr);
			port = ntohs(sa->sin_port);
			break;
		}
		default:
			break;
		}

		if (port >= PROT_SOCK) {
			CERROR("peer_ni's port (%pISc:%hu) is not privileged\n",
			       &cmid->route.addr.dst_addr, port);
			goto failed;
		}
	}

	if (priv_nob < offsetof(struct kib_msg, ibm_type)) {
		CERROR("Short connection request\n");
		goto failed;
	}

	/* Future protocol version compatibility support!  If the
	 * o2iblnd-specific protocol changes, or when LNET unifies
	 * protocols over all LNDs, the initial connection will
	 * negotiate a protocol version.  I trap this here to avoid
	 * console errors; the reject tells the peer_ni which protocol I
	 * speak.
	 */
	if (reqmsg->ibm_magic == LNET_PROTO_MAGIC ||
	    reqmsg->ibm_magic == __swab32(LNET_PROTO_MAGIC))
		goto failed;
	if (reqmsg->ibm_magic == IBLND_MSG_MAGIC &&
	    reqmsg->ibm_version != IBLND_MSG_VERSION &&
	    reqmsg->ibm_version != IBLND_MSG_VERSION_1)
		goto failed;
	if (reqmsg->ibm_magic == __swab32(IBLND_MSG_MAGIC) &&
	    reqmsg->ibm_version != __swab16(IBLND_MSG_VERSION) &&
	    reqmsg->ibm_version != __swab16(IBLND_MSG_VERSION_1))
		goto failed;

	rc = kiblnd_unpack_msg(reqmsg, priv_nob);
	if (rc != 0) {
		CERROR("Can't parse connection request: rc = %d\n", rc);
		goto failed;
	}

	lnet_nid4_to_nid(reqmsg->ibm_srcnid, &srcnid);
	lnet_nid4_to_nid(reqmsg->ibm_dstnid, &destnid);
	ni  = lnet_nid_to_ni_addref(&destnid);

	if (ni != NULL) {
		net = (struct kib_net *)ni->ni_data;
		rej.ibr_incarnation = net->ibn_incarnation;
	} else {
		if (ibdev->ibd_nnets == 0) {
			rej.ibr_why = IBLND_REJECT_EARLY;
			CNETERR("Can't accept conn from %s (%s:%d:%pISc): net for nid %s not added yet\n",
				libcfs_nidstr(&srcnid),
				ibdev->ibd_ifname, ibdev->ibd_nnets,
				&ibdev->ibd_addr,
				libcfs_nidstr(&destnid));
			goto failed;
		}
		list_for_each_entry(net, &ibdev->ibd_nets, ibn_list) {
			if ((net->ibn_dev == ibdev) &&
			    (net->ibn_ni != NULL) &&
			    (net->ibn_ni->ni_state != LNET_NI_STATE_ACTIVE)) {
				rej.ibr_why = IBLND_REJECT_EARLY;
				CNETERR("Can't accept conn from %s on %s (%s:%d:%pISc): nid %s not ready\n",
				       libcfs_nidstr(&srcnid),
				       libcfs_nidstr(&net->ibn_ni->ni_nid),
				       ibdev->ibd_ifname, ibdev->ibd_nnets,
				       &ibdev->ibd_addr,
				       libcfs_nidstr(&destnid));
				goto failed;
			}
		}
	}

	if (ni == NULL ||			/* no matching net */
	    !nid_same(&ni->ni_nid, &destnid) ||	/* right NET, wrong NID! */
	    net->ibn_dev != ibdev) {		/* wrong device */
		CERROR("Can't accept conn from %s on %s (%s:%d:%pISc): bad dst nid %s\n",
		       libcfs_nidstr(&srcnid),
		       ni ? libcfs_nidstr(&ni->ni_nid) : "NA",
		       ibdev->ibd_ifname, ibdev->ibd_nnets,
		       &ibdev->ibd_addr,
		       libcfs_nidstr(&destnid));
		goto failed;
	}

	/* check time stamp as soon as possible */
	if (reqmsg->ibm_dststamp != 0 &&
	    reqmsg->ibm_dststamp != net->ibn_incarnation) {
		CWARN("Stale connection request\n");
		rej.ibr_why = IBLND_REJECT_CONN_STALE;
		goto failed;
	}

	/* I can accept peer_ni's version */
	version = reqmsg->ibm_version;

	if (reqmsg->ibm_type != IBLND_MSG_CONNREQ) {
		CERROR("Unexpected connreq msg type: %x from %s\n",
		       reqmsg->ibm_type, libcfs_nidstr(&srcnid));
		goto failed;
	}

	if (reqmsg->ibm_u.connparams.ibcp_queue_depth >
	    kiblnd_msg_queue_size(version, ni)) {
		CERROR("Can't accept conn from %s, queue depth too large:  %d (<=%d wanted)\n",
		       libcfs_nidstr(&srcnid),
		       reqmsg->ibm_u.connparams.ibcp_queue_depth,
		       kiblnd_msg_queue_size(version, ni));

		if (version == IBLND_MSG_VERSION)
			rej.ibr_why = IBLND_REJECT_MSG_QUEUE_SIZE;

		goto failed;
	}

	if (reqmsg->ibm_u.connparams.ibcp_max_frags >
	    IBLND_MAX_RDMA_FRAGS) {
		CWARN("Can't accept conn from %s (version %x): max_frags %d too large (%d wanted)\n",
		      libcfs_nidstr(&srcnid), version,
		      reqmsg->ibm_u.connparams.ibcp_max_frags,
		      IBLND_MAX_RDMA_FRAGS);

		if (version >= IBLND_MSG_VERSION)
			rej.ibr_why = IBLND_REJECT_RDMA_FRAGS;

		goto failed;
	} else if (reqmsg->ibm_u.connparams.ibcp_max_frags <
		   IBLND_MAX_RDMA_FRAGS &&
		   net->ibn_fmr_ps == NULL) {
		CWARN("Can't accept conn from %s (version %x): max_frags %d incompatible without FMR pool (%d wanted)\n",
		      libcfs_nidstr(&srcnid), version,
		      reqmsg->ibm_u.connparams.ibcp_max_frags,
		      IBLND_MAX_RDMA_FRAGS);

		if (version == IBLND_MSG_VERSION)
			rej.ibr_why = IBLND_REJECT_RDMA_FRAGS;

		goto failed;
	}

	if (reqmsg->ibm_u.connparams.ibcp_max_msg_size > IBLND_MSG_SIZE) {
		CERROR("Can't accept %s: message size %d too big (%d max)\n",
		       libcfs_nidstr(&srcnid),
		       reqmsg->ibm_u.connparams.ibcp_max_msg_size,
		       IBLND_MSG_SIZE);
		goto failed;
	}

	/* assume 'nid' is a new peer_ni; create  */
	rc = kiblnd_create_peer(ni, &peer_ni, &srcnid);
	if (rc != 0) {
		CERROR("Can't create peer_ni for %s\n", libcfs_nidstr(&srcnid));
		rej.ibr_why = IBLND_REJECT_NO_RESOURCES;
		goto failed;
	}

	/* We have validated the peer's parameters so use those */
	peer_ni->ibp_max_frags = reqmsg->ibm_u.connparams.ibcp_max_frags;
	peer_ni->ibp_queue_depth = reqmsg->ibm_u.connparams.ibcp_queue_depth;

	write_lock_irqsave(g_lock, flags);

	peer2 = kiblnd_find_peer_locked(ni, &srcnid);
	if (peer2 != NULL) {
		if (peer2->ibp_version == 0) {
			peer2->ibp_version     = version;
			peer2->ibp_incarnation = reqmsg->ibm_srcstamp;
		}

		/* not the guy I've talked with */
		if (peer2->ibp_incarnation != reqmsg->ibm_srcstamp ||
		    peer2->ibp_version     != version) {
			kiblnd_close_peer_conns_locked(peer2, -ESTALE);

			if (kiblnd_peer_active(peer2)) {
				peer2->ibp_incarnation = reqmsg->ibm_srcstamp;
				peer2->ibp_version = version;
			}
			write_unlock_irqrestore(g_lock, flags);

			CWARN("Conn stale %s version %x/%x incarnation %llu/%llu\n",
			      libcfs_nidstr(&srcnid), peer2->ibp_version, version,
			      peer2->ibp_incarnation, reqmsg->ibm_srcstamp);

			kiblnd_peer_decref(peer_ni);
			rej.ibr_why = IBLND_REJECT_CONN_STALE;
			goto failed;
		}

		/* Tie-break connection race in favour of the higher NID.
		 * If we keep running into a race condition multiple times,
		 * we have to assume that the connection attempt with the
		 * higher NID is stuck in a connecting state and will never
		 * recover.  As such, we pass through this if-block and let
		 * the lower NID connection win so we can move forward.
		 */
		if (peer2->ibp_connecting != 0 &&
		    nidhash(&srcnid) < nidhash(&ni->ni_nid) &&
		    peer2->ibp_races < MAX_CONN_RACES_BEFORE_ABORT) {
			peer2->ibp_races++;
			write_unlock_irqrestore(g_lock, flags);

			CDEBUG(D_NET, "Conn race %s\n",
			       libcfs_nidstr(&peer2->ibp_nid));

			kiblnd_peer_decref(peer_ni);
			rej.ibr_why = IBLND_REJECT_CONN_RACE;
			goto failed;
		}
		if (peer2->ibp_races >= MAX_CONN_RACES_BEFORE_ABORT)
			CNETERR("Conn race %s: unresolved after %d attempts, letting lower NID win\n",
				libcfs_nidstr(&peer2->ibp_nid),
				MAX_CONN_RACES_BEFORE_ABORT);
		/* passive connection is allowed even this peer_ni is waiting
		 * for reconnection.
		 */
		peer2->ibp_reconnecting = 0;
		peer2->ibp_races = 0;
		peer2->ibp_accepting++;
		kiblnd_peer_addref(peer2);

		/* Race with kiblnd_launch_tx (active connect) to create peer_ni
		 * so copy validated parameters since we now know what the
		 * peer_ni's limits are
		 */
		peer2->ibp_max_frags = peer_ni->ibp_max_frags;
		peer2->ibp_queue_depth = peer_ni->ibp_queue_depth;

		write_unlock_irqrestore(g_lock, flags);
		kiblnd_peer_decref(peer_ni);
		peer_ni = peer2;
	} else {
		/* Brand new peer_ni */
		LASSERT(peer_ni->ibp_accepting == 0);
		LASSERT(peer_ni->ibp_version == 0 &&
			peer_ni->ibp_incarnation == 0);

		peer_ni->ibp_accepting   = 1;
		peer_ni->ibp_version     = version;
		peer_ni->ibp_incarnation = reqmsg->ibm_srcstamp;

		/* I have a ref on ni that prevents it being shutdown */
		LASSERT(net->ibn_shutdown == 0);

		kiblnd_peer_addref(peer_ni);
		hash_add(kiblnd_data.kib_peers, &peer_ni->ibp_list,
			 nidhash(&srcnid));

		write_unlock_irqrestore(g_lock, flags);
	}

	conn = kiblnd_create_conn(peer_ni, cmid, IBLND_CONN_PASSIVE_WAIT,
				  version);
	if (!conn) {
		kiblnd_peer_connect_failed(peer_ni, 0, -ENOMEM);
		kiblnd_peer_decref(peer_ni);
		rej.ibr_why = IBLND_REJECT_NO_RESOURCES;
		goto failed;
	}

	/* conn now "owns" cmid, so I return success from here on to ensure the
	 * CM callback doesn't destroy cmid.
	 */
	conn->ibc_incarnation      = reqmsg->ibm_srcstamp;
	conn->ibc_credits          = conn->ibc_queue_depth;
	conn->ibc_reserved_credits = conn->ibc_queue_depth;
	LASSERT(conn->ibc_credits + conn->ibc_reserved_credits +
		IBLND_OOB_MSGS(version) <= IBLND_RX_MSGS(conn));

	ackmsg = &conn->ibc_connvars->cv_msg;
	memset(ackmsg, 0, sizeof(*ackmsg));

	kiblnd_init_msg(ackmsg, IBLND_MSG_CONNACK,
			sizeof(ackmsg->ibm_u.connparams));
	ackmsg->ibm_u.connparams.ibcp_queue_depth  = conn->ibc_queue_depth;
	ackmsg->ibm_u.connparams.ibcp_max_frags    = conn->ibc_max_frags;
	ackmsg->ibm_u.connparams.ibcp_max_msg_size = IBLND_MSG_SIZE;

	kiblnd_pack_msg(ni, ackmsg, version, 0, &srcnid, reqmsg->ibm_srcstamp);

	memset(&cp, 0, sizeof(cp));
	cp.private_data        = ackmsg;
	cp.private_data_len    = ackmsg->ibm_nob;
	cp.responder_resources = 0;            /* No atomic ops or RDMA reads */
	cp.initiator_depth     = 0;
	cp.flow_control        = 1;
	cp.retry_count         = *kiblnd_tunables.kib_retry_count;
	cp.rnr_retry_count     = *kiblnd_tunables.kib_rnr_retry_count;

	CDEBUG(D_NET, "Accept %s conn %p\n", libcfs_nidstr(&srcnid), conn);

	rc = rdma_accept(cmid, &cp);
	if (rc != 0) {
		CNETERR("%s: Can't accept: cm_id %p: rc = %d\n",
			libcfs_nidstr(&srcnid), cmid, rc);
		rej.ibr_version = version;
		rej.ibr_why     = IBLND_REJECT_FATAL;

		kiblnd_reject(cmid, &rej);
		kiblnd_connreq_done(conn, rc);
		kiblnd_conn_decref(conn);
	}

	lnet_ni_decref(ni);
	return 0;

 failed:
	if (ni != NULL) {
		rej.ibr_cp.ibcp_queue_depth =
			kiblnd_msg_queue_size(version, ni);
		rej.ibr_cp.ibcp_max_frags   = IBLND_MAX_RDMA_FRAGS;
		lnet_ni_decref(ni);
	}

	rej.ibr_version = version;
	kiblnd_reject(cmid, &rej);

	return -ECONNREFUSED;
}

static void
kiblnd_check_reconnect(struct kib_conn *conn, int version,
		       u64 incarnation, int why, struct kib_connparams *cp)
{
	rwlock_t *glock = &kiblnd_data.kib_global_lock;
	struct kib_peer_ni *peer_ni = conn->ibc_peer;
	char *reason;
	int msg_size = IBLND_MSG_SIZE;
	int frag_num = -1;
	int queue_dep = -1;
	bool reconnect;
	unsigned long flags;

	LASSERT(conn->ibc_state == IBLND_CONN_ACTIVE_CONNECT);
	LASSERT(peer_ni->ibp_connecting > 0);	/* 'conn' at least */

	if (cp) {
		msg_size	= cp->ibcp_max_msg_size;
		frag_num	= cp->ibcp_max_frags;
		queue_dep	= cp->ibcp_queue_depth;
	}

	write_lock_irqsave(glock, flags);
	/* retry connection if it's still needed and no other connection
	 * attempts (active or passive) are in progress
	 * NB: reconnect is still needed even when ibp_tx_queue is
	 * empty if ibp_version != version because reconnect may be
	 * initiated.
	 */
	reconnect = (!list_empty(&peer_ni->ibp_tx_queue) ||
		     peer_ni->ibp_version != version) &&
		    peer_ni->ibp_connecting &&
		    peer_ni->ibp_accepting == 0;
	if (!reconnect) {
		reason = "no need";
		goto out;
	}

	switch (why) {
	default:
		reason = "Unknown";
		break;

	case IBLND_REJECT_RDMA_FRAGS: {
		if (!cp) {
			reason = "can't negotiate max frags";
			goto out;
		}

		if (conn->ibc_max_frags <= frag_num) {
			reason = "unsupported max frags";
			goto out;
		}

		peer_ni->ibp_max_frags = frag_num;
		reason = "rdma fragments";
		break;
	}
	case IBLND_REJECT_MSG_QUEUE_SIZE:
		if (!cp) {
			reason = "can't negotiate queue depth";
			goto out;
		}
		if (conn->ibc_queue_depth <= queue_dep) {
			reason = "unsupported queue depth";
			goto out;
		}

		peer_ni->ibp_queue_depth = queue_dep;
		reason = "queue depth";
		break;

	case IBLND_REJECT_CONN_STALE:
		reason = "stale";
		break;

	case IBLND_REJECT_CONN_RACE:
		reason = "conn race";
		break;

	case IBLND_REJECT_CONN_UNCOMPAT:
		reason = "version negotiation";
		break;
	}

	conn->ibc_reconnect = 1;
	peer_ni->ibp_reconnecting++;
	peer_ni->ibp_version = version;
	if (incarnation != 0)
		peer_ni->ibp_incarnation = incarnation;
 out:
	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	CNETERR("%s: %s (%s), %x, %x, msg_size: %d, queue_depth: %d/%d, max_frags: %d/%d\n",
		libcfs_nidstr(&peer_ni->ibp_nid),
		reconnect ? "reconnect" : "don't reconnect",
		reason, IBLND_MSG_VERSION, version, msg_size,
		conn->ibc_queue_depth, queue_dep,
		conn->ibc_max_frags, frag_num);
	/*
	 * if conn::ibc_reconnect is TRUE, connd will reconnect to the peer_ni
	 * while destroying the zombie
	 */
}

static void
kiblnd_rejected(struct kib_conn *conn, int reason, void *priv, int priv_nob)
{
	struct kib_peer_ni *peer_ni = conn->ibc_peer;
	int status = -ECONNREFUSED;

	LASSERT(!in_interrupt());
	LASSERT(conn->ibc_state == IBLND_CONN_ACTIVE_CONNECT);

	switch (reason) {
	case IB_CM_REJ_STALE_CONN:
		kiblnd_check_reconnect(conn, IBLND_MSG_VERSION, 0,
				       IBLND_REJECT_CONN_STALE, NULL);
		break;

	case IB_CM_REJ_INVALID_SERVICE_ID:
		status = -EHOSTUNREACH;
		CNETERR("%s rejected: no listener at %d\n",
			libcfs_nidstr(&peer_ni->ibp_nid),
			*kiblnd_tunables.kib_service);
		break;

	case IB_CM_REJ_CONSUMER_DEFINED:
		if (priv_nob >= offsetof(struct kib_rej, ibr_padding)) {
			struct kib_rej *rej = priv;
			struct kib_connparams *cp = NULL;
			bool flip = false;
			__u64 incarnation = -1;

			/* NB. default incarnation is -1 because:
			 * a) V1 will ignore dst incarnation in connreq.
			 * b) V2 will provide incarnation while rejecting me,
			 *    -1 will be overwrote.
			 *
			 * if I try to connect to a V1 peer_ni with V2 protocol,
			 * it rejected me then upgrade to V2, I have no idea
			 * about the upgrading and try to reconnect with V1,
			 * in this case upgraded V2 can find out I'm trying to
			 * talk to the old guy and reject me(incarnation is -1).
			 */

			if (rej->ibr_magic == __swab32(IBLND_MSG_MAGIC) ||
			    rej->ibr_magic == __swab32(LNET_PROTO_MAGIC)) {
				__swab32s(&rej->ibr_magic);
				__swab16s(&rej->ibr_version);
				flip = true;
			}

			if (priv_nob >= sizeof(struct kib_rej) &&
			    rej->ibr_version > IBLND_MSG_VERSION_1) {
				/* priv_nob is always 148 in current version
				 * of OFED, so we still need to check version.
				 * (define of IB_CM_REJ_PRIVATE_DATA_SIZE)
				 */
				cp = &rej->ibr_cp;

				if (flip) {
					__swab64s(&rej->ibr_incarnation);
					__swab16s(&cp->ibcp_queue_depth);
					__swab16s(&cp->ibcp_max_frags);
					__swab32s(&cp->ibcp_max_msg_size);
				}

				incarnation = rej->ibr_incarnation;
			}

			if (rej->ibr_magic != IBLND_MSG_MAGIC &&
			    rej->ibr_magic != LNET_PROTO_MAGIC) {
				CERROR("%s rejected: consumer defined fatal error\n",
				       libcfs_nidstr(&peer_ni->ibp_nid));
				break;
			}

			if (rej->ibr_version != IBLND_MSG_VERSION &&
			    rej->ibr_version != IBLND_MSG_VERSION_1) {
				CERROR("%s rejected: o2iblnd version %x error\n",
				       libcfs_nidstr(&peer_ni->ibp_nid),
				       rej->ibr_version);
				break;
			}

			if (rej->ibr_why     == IBLND_REJECT_FATAL &&
			    rej->ibr_version == IBLND_MSG_VERSION_1) {
				CDEBUG(D_NET, "rejected by old version peer_ni %s: %x\n",
				       libcfs_nidstr(&peer_ni->ibp_nid),
				       rej->ibr_version);

				if (conn->ibc_version != IBLND_MSG_VERSION_1)
					rej->ibr_why = IBLND_REJECT_CONN_UNCOMPAT;
			}

			switch (rej->ibr_why) {
			case IBLND_REJECT_CONN_RACE:
			case IBLND_REJECT_CONN_STALE:
			case IBLND_REJECT_CONN_UNCOMPAT:
			case IBLND_REJECT_MSG_QUEUE_SIZE:
			case IBLND_REJECT_RDMA_FRAGS:
				kiblnd_check_reconnect(conn, rej->ibr_version,
						       incarnation,
						       rej->ibr_why, cp);
				break;

			case IBLND_REJECT_NO_RESOURCES:
				CERROR("%s rejected: o2iblnd no resources\n",
				       libcfs_nidstr(&peer_ni->ibp_nid));
				break;

			case IBLND_REJECT_FATAL:
				CERROR("%s rejected: o2iblnd fatal error\n",
				       libcfs_nidstr(&peer_ni->ibp_nid));
				break;

			case IBLND_REJECT_EARLY:
				CNETERR("%s rejected: tried too early\n",
				       libcfs_nidstr(&peer_ni->ibp_nid));
				break;

			default:
				CERROR("%s rejected: o2iblnd reason %d\n",
				       libcfs_nidstr(&peer_ni->ibp_nid),
				       rej->ibr_why);
				break;
			}
			break;
		}
		fallthrough;
	default:
		CNETERR("%s rejected: reason %d, size %d\n",
			libcfs_nidstr(&peer_ni->ibp_nid), reason, priv_nob);
		break;
	}

	kiblnd_connreq_done(conn, status);
}

static void
kiblnd_check_connreply(struct kib_conn *conn, void *priv, int priv_nob)
{
	struct kib_peer_ni *peer_ni = conn->ibc_peer;
	struct lnet_ni *ni = peer_ni->ibp_ni;
	struct kib_net *net = ni->ni_data;
	struct kib_msg *msg = priv;
	int ver = conn->ibc_version;
	int rc = kiblnd_unpack_msg(msg, priv_nob);
	unsigned long flags;

	LASSERT(net != NULL);

	if (rc != 0) {
		CERROR("Can't unpack connack from %s: %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid), rc);
		goto failed;
	}

	if (msg->ibm_type != IBLND_MSG_CONNACK) {
		CERROR("Unexpected message %d from %s\n",
		       msg->ibm_type, libcfs_nidstr(&peer_ni->ibp_nid));
		rc = -EPROTO;
		goto failed;
	}

	if (ver != msg->ibm_version) {
		rc = -EPROTO;
		CERROR("%s replied version %x is different with requested version %x: rc = %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid), msg->ibm_version, ver,
		       rc);
		goto failed;
	}

	if (msg->ibm_u.connparams.ibcp_queue_depth >
	    conn->ibc_queue_depth) {
		rc = -EPROTO;
		CERROR("%s has incompatible queue depth %d (<=%d wanted): rc = %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid),
		       msg->ibm_u.connparams.ibcp_queue_depth,
		       conn->ibc_queue_depth, rc);
		goto failed;
	}

	if (msg->ibm_u.connparams.ibcp_max_frags >
	    conn->ibc_max_frags) {
		rc = -EPROTO;
		CERROR("%s has incompatible max_frags %d (<=%d wanted): rc = %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid),
		       msg->ibm_u.connparams.ibcp_max_frags,
		       conn->ibc_max_frags, rc);

		goto failed;
	}

	if (msg->ibm_u.connparams.ibcp_max_msg_size > IBLND_MSG_SIZE) {
		rc = -EPROTO;
		CERROR("%s max message size %d too big (%d max): rc = %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid),
		       msg->ibm_u.connparams.ibcp_max_msg_size, IBLND_MSG_SIZE,
		       rc);
		goto failed;
	}

	read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
	if (msg->ibm_dstnid == lnet_nid_to_nid4(&ni->ni_nid) &&
	    msg->ibm_dststamp == net->ibn_incarnation)
		rc = 0;
	else
		rc = -ESTALE;
	read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	if (rc != 0) {
		CERROR("Bad connection reply from %s: version: %x max_frags: %d: rc = %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid), msg->ibm_version,
		       msg->ibm_u.connparams.ibcp_max_frags, rc);
		goto failed;
	}

	conn->ibc_incarnation      = msg->ibm_srcstamp;
	conn->ibc_credits          = msg->ibm_u.connparams.ibcp_queue_depth;
	conn->ibc_reserved_credits = msg->ibm_u.connparams.ibcp_queue_depth;
	conn->ibc_queue_depth      = msg->ibm_u.connparams.ibcp_queue_depth;
	conn->ibc_max_frags        = msg->ibm_u.connparams.ibcp_max_frags;
	LASSERT(conn->ibc_credits + conn->ibc_reserved_credits +
		IBLND_OOB_MSGS(ver) <= IBLND_RX_MSGS(conn));

	kiblnd_connreq_done(conn, 0);
	return;

failed:
	/* NB My QP has already established itself, so I handle anything going
	 * wrong here by setting ibc_comms_error.
	 * kiblnd_connreq_done(0) moves the conn state to ESTABLISHED, but then
	 * immediately tears it down.
	 */

	LASSERT(rc != 0);
	conn->ibc_comms_error = rc;
	kiblnd_connreq_done(conn, 0);
}

static int
kiblnd_active_connect(struct rdma_cm_id *cmid)
{
	struct kib_peer_ni *peer_ni = cmid->context;
	struct kib_conn *conn;
	struct kib_msg *msg;
	struct rdma_conn_param cp;
	int version;
	__u64 incarnation;
	unsigned long flags;
	int rc;

	read_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	incarnation = peer_ni->ibp_incarnation;
	version     = (peer_ni->ibp_version == 0) ? IBLND_MSG_VERSION :
						 peer_ni->ibp_version;

	read_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	conn = kiblnd_create_conn(peer_ni, cmid, IBLND_CONN_ACTIVE_CONNECT,
				  version);
	if (conn == NULL) {
		kiblnd_peer_connect_failed(peer_ni, 1, -ENOMEM);
		kiblnd_peer_decref(peer_ni); /* lose cmid's ref */
		return -ENOMEM;
	}

	/* conn "owns" cmid now, so I return success from here on to ensure the
	 * CM callback doesn't destroy cmid. conn also takes over cmid's ref
	 * on peer_ni
	 */

	msg = &conn->ibc_connvars->cv_msg;

	memset(msg, 0, sizeof(*msg));
	kiblnd_init_msg(msg, IBLND_MSG_CONNREQ, sizeof(msg->ibm_u.connparams));
	msg->ibm_u.connparams.ibcp_queue_depth  = conn->ibc_queue_depth;
	msg->ibm_u.connparams.ibcp_max_frags    = conn->ibc_max_frags;
	msg->ibm_u.connparams.ibcp_max_msg_size = IBLND_MSG_SIZE;

	kiblnd_pack_msg(peer_ni->ibp_ni, msg, version,
			0, &peer_ni->ibp_nid, incarnation);

	memset(&cp, 0, sizeof(cp));
	cp.private_data        = msg;
	cp.private_data_len    = msg->ibm_nob;
	cp.responder_resources = 0; /* No atomic ops or RDMA reads */
	cp.initiator_depth     = 0;
	cp.flow_control        = 1;
	cp.retry_count         = *kiblnd_tunables.kib_retry_count;
	cp.rnr_retry_count     = *kiblnd_tunables.kib_rnr_retry_count;

	LASSERT(cmid->context == (void *)conn);
	LASSERT(conn->ibc_cmid == cmid);
	rc = rdma_connect_locked(cmid, &cp);
	if (rc != 0) {
		CNETERR("Can't connect to %s: cm_id %p: rc = %d\n",
			libcfs_nidstr(&peer_ni->ibp_nid), cmid, rc);
		kiblnd_connreq_done(conn, rc);
		kiblnd_conn_decref(conn);
		return 0;
	}

	CDEBUG(D_NET, "Connecting to %s: cm_id %p\n",
	       libcfs_nidstr(&peer_ni->ibp_nid), cmid);

	/* to track connect request timeouts */
	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);
	conn->ibc_last_send = ktime_get();
	list_add(&conn->ibc_list, &peer_ni->ibp_connreqs);
	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	return 0;
}

/* set the IP ToS ("Type of Service") used by the RoCE QoS */
static void
kiblnd_set_tos(struct rdma_cm_id *cmid)
{
	struct kib_peer_ni *peer_ni = cmid->context;
	struct lnet_ioctl_config_o2iblnd_tunables *t;

	t = &peer_ni->ibp_ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib;
	if (t->lnd_tos < 0)
		return;

	rdma_set_service_type(cmid, t->lnd_tos);
}

int
kiblnd_cm_callback(struct rdma_cm_id *cmid, struct rdma_cm_event *event)
{
	struct kib_peer_ni *peer_ni;
	struct kib_conn *conn;
	int rc;

	switch (event->event) {
	default:
		CERROR("Unexpected event: %d, status: %d\n",
		       event->event, event->status);
		LBUG();

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		/* destroy cmid on failure */
		rc = kiblnd_passive_connect(cmid,
					    (void *)KIBLND_CONN_PARAM(event),
					    KIBLND_CONN_PARAM_LEN(event));
		CDEBUG(D_NET, "connreq: %d cm_id %p\n", rc, cmid);
		return rc;

	case RDMA_CM_EVENT_ADDR_ERROR:
		peer_ni = cmid->context;
		CNETERR("%s: ADDR ERROR %d cm_id %p\n",
			libcfs_nidstr(&peer_ni->ibp_nid), event->status, cmid);
		kiblnd_peer_connect_failed(peer_ni, 1, -EHOSTUNREACH);
		kiblnd_peer_decref(peer_ni);
		return -EHOSTUNREACH;      /* rc != 0 destroys cmid */

	case RDMA_CM_EVENT_ADDR_RESOLVED:
		peer_ni = cmid->context;

		CDEBUG(D_NET, "%s Addr resolved: %d cm_id %p\n",
			libcfs_nidstr(&peer_ni->ibp_nid), event->status, cmid);

		if (event->status != 0) {
			CNETERR("Can't resolve address for %s: %d cm_id %p\n",
				libcfs_nidstr(&peer_ni->ibp_nid),
				event->status, cmid);
			rc = event->status;
		} else {
			kiblnd_set_tos(cmid);
			rc = rdma_resolve_route(cmid, RDMA_RESOLVE_TIMEOUT);
			if (rc == 0) {
				struct kib_net *net = peer_ni->ibp_ni->ni_data;
				struct kib_dev *dev = net->ibn_dev;

				CDEBUG(D_NET,
				       "%s: connection bound to %s:%pISc:%s\n",
				       libcfs_nidstr(&peer_ni->ibp_nid),
				       dev->ibd_ifname, &dev->ibd_addr,
				       cmid->device->name);

				return 0;
			}

			/* Can't initiate route resolution */
			CNETERR("Can't resolve route for %s: %d cm_id %p\n",
				libcfs_nidstr(&peer_ni->ibp_nid), rc, cmid);
		}
		kiblnd_peer_connect_failed(peer_ni, 1, rc);
		kiblnd_peer_decref(peer_ni);
		return rc;                      /* rc != 0 destroys cmid */

	case RDMA_CM_EVENT_ROUTE_ERROR:
		peer_ni = cmid->context;
		CNETERR("%s: ROUTE ERROR %d cm_id %p\n",
			libcfs_nidstr(&peer_ni->ibp_nid), event->status, cmid);
		kiblnd_peer_connect_failed(peer_ni, 1, -EHOSTUNREACH);
		kiblnd_peer_decref(peer_ni);
		return -EHOSTUNREACH;           /* rc != 0 destroys cmid */

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		peer_ni = cmid->context;
		CDEBUG(D_NET, "%s Route resolved: %d\n",
		       libcfs_nidstr(&peer_ni->ibp_nid), event->status);

		if (event->status == 0)
			return kiblnd_active_connect(cmid);

		CNETERR("Can't resolve route for %s: %d cm_id %p\n",
			libcfs_nidstr(&peer_ni->ibp_nid), event->status, cmid);
		kiblnd_peer_connect_failed(peer_ni, 1, event->status);
		kiblnd_peer_decref(peer_ni);
		return event->status;           /* rc != 0 destroys cmid */

	case RDMA_CM_EVENT_UNREACHABLE:
		conn = cmid->context;

		/* In case we have a flapping network, we can get this event
		 * before conn is created */
		if (conn == NULL)
			return -ENETDOWN;

		CNETERR("%s: UNREACHABLE %d cm_id %p conn %p ibc_state: %d\n",
			libcfs_nidstr(&conn->ibc_peer->ibp_nid),
			event->status, cmid, conn, conn->ibc_state);

		if (conn->ibc_state != IBLND_CONN_ACTIVE_CONNECT &&
		    conn->ibc_state != IBLND_CONN_PASSIVE_WAIT)
			return 0;

		/* ignore, if aborted by the lnd */
		if (kiblnd_deregister_connreq(conn) == -EALREADY)
			return 0;

		kiblnd_connreq_done(conn, -ENETDOWN);
		kiblnd_conn_decref(conn);
		return 0;

	case RDMA_CM_EVENT_CONNECT_ERROR:
		conn = cmid->context;
		CNETERR("%s: CONNECT ERROR %d cm_id %p conn %p state: %d\n",
			libcfs_nidstr(&conn->ibc_peer->ibp_nid),
			event->status, cmid, conn, conn->ibc_state);

		if (conn->ibc_state != IBLND_CONN_ACTIVE_CONNECT &&
		    conn->ibc_state != IBLND_CONN_PASSIVE_WAIT)
			return 0;

		/* ignore, if aborted by the lnd */
		if (kiblnd_deregister_connreq(conn) == -EALREADY)
			return 0;

		kiblnd_connreq_done(conn, -ENOTCONN);
		kiblnd_conn_decref(conn);

		return 0;

	case RDMA_CM_EVENT_REJECTED:
		conn = cmid->context;
		CNETERR("%s: REJECTED %d cm_id %p conn %p ibc_state: %d\n",
			libcfs_nidstr(&conn->ibc_peer->ibp_nid),
			event->status, cmid, conn, conn->ibc_state);

		/* ignore, if aborted by the lnd */
		if (kiblnd_deregister_connreq(conn) == -EALREADY)
			return 0;

		switch (conn->ibc_state) {
		case IBLND_CONN_PASSIVE_WAIT:
			CERROR("%s: REJECTED %d cm_id %p\n",
				libcfs_nidstr(&conn->ibc_peer->ibp_nid),
				event->status, cmid);
			kiblnd_connreq_done(conn, -ECONNRESET);
			break;

		case IBLND_CONN_ACTIVE_CONNECT:
			kiblnd_rejected(conn, event->status,
					(void *)KIBLND_CONN_PARAM(event),
					KIBLND_CONN_PARAM_LEN(event));
			break;

		default:
			return 0;
		}
		kiblnd_conn_decref(conn);
		return 0;

	case RDMA_CM_EVENT_ESTABLISHED:
		conn = cmid->context;
		switch (conn->ibc_state) {
		default:
			CERROR("%s: ESTABLISHED (ignored): %d cm_id %p conn %p ibc_state: %d\n",
				libcfs_nidstr(&conn->ibc_peer->ibp_nid),
				event->status, cmid, conn, conn->ibc_state);
			return 0;

		case IBLND_CONN_PASSIVE_WAIT:
			CDEBUG(D_NET, "ESTABLISHED (passive): %s cm_id %p conn %p\n",
				libcfs_nidstr(&conn->ibc_peer->ibp_nid), cmid, conn);
			kiblnd_connreq_done(conn, 0);
			break;

		case IBLND_CONN_ACTIVE_CONNECT:
			CDEBUG(D_NET, "ESTABLISHED(active): %s cm_id %p conn %p\n",
				libcfs_nidstr(&conn->ibc_peer->ibp_nid), cmid, conn);

			/* ignore, if aborted by the lnd */
			if (kiblnd_deregister_connreq(conn) == -EALREADY)
				return 0;

			kiblnd_check_connreply(conn,
					       (void *)KIBLND_CONN_PARAM(event),
					       KIBLND_CONN_PARAM_LEN(event));
			break;
		}
		/* net keeps its ref on conn! */
		return 0;

	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		CDEBUG(D_NET, "Ignore TIMEWAIT_EXIT event\n");
		return 0;

	case RDMA_CM_EVENT_DISCONNECTED:
		conn = cmid->context;
		if (conn->ibc_state < IBLND_CONN_ESTABLISHED) {
			CERROR("%s DISCONNECTED cm_id %p conn %p\n",
				libcfs_nidstr(&conn->ibc_peer->ibp_nid), cmid,
				conn);
			kiblnd_connreq_done(conn, -ECONNRESET);
		} else {
			kiblnd_close_conn(conn, 0);
		}
		kiblnd_conn_decref(conn);
		cmid->context = NULL;
		return 0;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		LCONSOLE_ERROR("Received notification of device removal - Please shutdown LNET to allow this to proceed\n");
		/* Can't remove network from underneath LNET for now, so I have
		 * to ignore this
		 */
		return 0;

	case RDMA_CM_EVENT_ADDR_CHANGE:
		LCONSOLE_INFO("Physical link changed (eg hca/port)\n");
		return 0;
	}
}

static int
kiblnd_check_txs_locked(struct kib_conn *conn, struct list_head *txs)
{
	struct kib_tx *tx;

	list_for_each_entry(tx, txs, tx_list) {
		if (txs != &conn->ibc_active_txs) {
			LASSERT(tx->tx_queued);
		} else {
			LASSERT(!tx->tx_queued);
			LASSERT(tx->tx_waiting || tx->tx_sending != 0);
		}

		if (ktime_compare(ktime_get(), tx->tx_deadline) >= 0) {
			CERROR("Timed out tx: %s, %lld seconds\n",
			       kiblnd_queue2str(conn, txs),
			       kiblnd_timeout() +
			       ktime_ms_delta(ktime_get(),
					      tx->tx_deadline) / MSEC_PER_SEC);
			return 1;
		}
	}

	return 0;
}

static int
kiblnd_conn_timed_out_locked(struct kib_conn *conn)
{
	return  kiblnd_check_txs_locked(conn, &conn->ibc_tx_queue) ||
		kiblnd_check_txs_locked(conn, &conn->ibc_tx_noops) ||
		kiblnd_check_txs_locked(conn, &conn->ibc_tx_queue_rsrvd) ||
		kiblnd_check_txs_locked(conn, &conn->ibc_tx_queue_nocred) ||
		kiblnd_check_txs_locked(conn, &conn->ibc_active_txs);
}

static void
kiblnd_check_conns(int idx)
{
	LIST_HEAD(closes);
	LIST_HEAD(aborting);
	LIST_HEAD(checksends);
	LIST_HEAD(timedout_txs);
	struct hlist_head *peers = &kiblnd_data.kib_peers[idx];
	struct kib_peer_ni *peer_ni;
	struct kib_conn *conn;
	struct kib_tx *tx, *tx_tmp;
	unsigned long flags;

	/* NB. We expect to have a look at all the peers and not find any
	 * RDMAs to time out, so we just use a shared lock while we
	 * take a look...
	 */
	write_lock_irqsave(&kiblnd_data.kib_global_lock, flags);

	hlist_for_each_entry(peer_ni, peers, ibp_list) {
		/* Check tx_deadline */
		list_for_each_entry_safe(tx, tx_tmp, &peer_ni->ibp_tx_queue, tx_list) {
			if (ktime_compare(ktime_get(), tx->tx_deadline) >= 0) {
				CWARN("Timed out tx for %s: %lld seconds\n",
				      libcfs_nidstr(&peer_ni->ibp_nid),
				      ktime_ms_delta(ktime_get(),
						     tx->tx_deadline) / MSEC_PER_SEC);
				list_move(&tx->tx_list, &timedout_txs);
			}
		}

		/* check for connect request timeouts (rdma_connect()) */
		list_for_each_entry(conn, &peer_ni->ibp_connreqs, ibc_list) {
			s64 d;

			d = ktime_ms_delta(ktime_get(), conn->ibc_last_send);
			if (d <= kiblnd_connreq_timeout_ms())
				continue;

			CNETERR("Timed out for RDMA connect request with %s (%llds), aborting\n",
				libcfs_nidstr(&peer_ni->ibp_nid),
				d / MSEC_PER_SEC);

			list_add(&conn->ibc_connd_list, &aborting);
			kiblnd_conn_addref(conn);
		}

		list_for_each_entry(conn, &peer_ni->ibp_conns, ibc_list) {
			int timedout;
			int sendnoop;

			LASSERT(conn->ibc_state == IBLND_CONN_ESTABLISHED);

			spin_lock(&conn->ibc_lock);

			sendnoop = kiblnd_need_noop(conn);
			timedout = kiblnd_conn_timed_out_locked(conn);
			if (!sendnoop && !timedout) {
				spin_unlock(&conn->ibc_lock);
				continue;
			}

			if (timedout) {
				CERROR("Timed out RDMA with %s (%lld): c: %u, oc: %u, rc: %u\n",
				       libcfs_nidstr(&peer_ni->ibp_nid),
				       ktime_get_seconds()
				       - peer_ni->ibp_last_alive,
				       conn->ibc_credits,
				       conn->ibc_outstanding_credits,
				       conn->ibc_reserved_credits);
#ifdef O2IBLND_CONN_STATE_DEBUG
				kiblnd_dump_conn_dbg(conn);
#endif
				list_add(&conn->ibc_connd_list, &closes);
			} else {
				list_add(&conn->ibc_connd_list, &checksends);
			}
			/* +ref for 'closes' or 'checksends' */
			kiblnd_conn_addref(conn);

			spin_unlock(&conn->ibc_lock);
		}
	}

	write_unlock_irqrestore(&kiblnd_data.kib_global_lock, flags);

	if (!list_empty(&timedout_txs))
		kiblnd_txlist_done(&timedout_txs, -ETIMEDOUT,
				   LNET_MSG_STATUS_NETWORK_TIMEOUT);

	/* aborting timeout connection requests */
	while ((conn = list_first_entry_or_null(&aborting,
						struct kib_conn,
						ibc_connd_list)) != NULL) {
		list_del(&conn->ibc_connd_list);
		kiblnd_abort_connreq(conn);
		kiblnd_conn_decref(conn);
	}

	/* Handle timeout by closing the whole
	 * connection. We can only be sure RDMA activity
	 * has ceased once the QP has been modified.
	 */
	while ((conn = list_first_entry_or_null(&closes,
						struct kib_conn,
						ibc_connd_list)) != NULL) {
		list_del(&conn->ibc_connd_list);
		kiblnd_close_conn(conn, -ETIMEDOUT);
		kiblnd_conn_decref(conn);
	}

	/* In case we have enough credits to return via a
	 * NOOP, but there were no non-blocking tx descs
	 * free to do it last time...
	 */
	while ((conn = list_first_entry_or_null(&checksends,
						struct kib_conn,
						ibc_connd_list)) != NULL) {
		list_del(&conn->ibc_connd_list);

		spin_lock(&conn->ibc_lock);
		kiblnd_check_sends_locked(conn);
		spin_unlock(&conn->ibc_lock);

		kiblnd_conn_decref(conn);
	}
}

static void
kiblnd_disconnect_conn(struct kib_conn *conn)
{
	LASSERT(!in_interrupt());
	LASSERT(current == kiblnd_data.kib_connd);
	LASSERT(conn->ibc_state == IBLND_CONN_CLOSING);
#ifdef O2IBLND_CONN_STATE_DEBUG
	kiblnd_dump_conn_dbg(conn);
#endif
	rdma_disconnect(conn->ibc_cmid);
	kiblnd_finalise_conn(conn);

	kiblnd_peer_notify(conn->ibc_peer);
}

/*
 * High-water for reconnection to the same peer_ni, reconnection attempt should
 * be delayed after trying more than KIB_RECONN_HIGH_RACE.
 */
#define KIB_RECONN_HIGH_RACE	10
/*
 * Allow connd to take a break and handle other things after consecutive
 * reconnection attemps.
 */
#define KIB_RECONN_BREAK	100

int
kiblnd_connd(void *arg)
{
	spinlock_t *lock = &kiblnd_data.kib_connd_lock;
	wait_queue_entry_t wait;
	unsigned long flags;
	struct kib_conn *conn;
	int timeout;
	int i;
	bool dropped_lock;
	int peer_index = 0;
	unsigned long deadline = jiffies;

	init_wait(&wait);
	kiblnd_data.kib_connd = current;

	spin_lock_irqsave(lock, flags);

	while (!kiblnd_data.kib_shutdown) {
		int reconn = 0;

		dropped_lock = false;

		conn = list_first_entry_or_null(&kiblnd_data.kib_connd_zombies,
						struct kib_conn, ibc_list);
		if (conn) {
			struct kib_peer_ni *peer_ni = NULL;

			list_del(&conn->ibc_list);
			if (conn->ibc_reconnect) {
				peer_ni = conn->ibc_peer;
				kiblnd_peer_addref(peer_ni);
			}

			spin_unlock_irqrestore(lock, flags);
			dropped_lock = true;

			kiblnd_destroy_conn(conn);

			spin_lock_irqsave(lock, flags);
			if (!peer_ni) {
				LIBCFS_FREE(conn, sizeof(*conn));
				continue;
			}

			conn->ibc_peer = peer_ni;
			if (peer_ni->ibp_reconnected < KIB_RECONN_HIGH_RACE)
				list_add_tail(&conn->ibc_list,
					      &kiblnd_data.kib_reconn_list);
			else
				list_add_tail(&conn->ibc_list,
					      &kiblnd_data.kib_reconn_wait);
		}

		conn = list_first_entry_or_null(&kiblnd_data.kib_connd_conns,
						struct kib_conn, ibc_list);
		if (conn) {
			list_del(&conn->ibc_list);

			spin_unlock_irqrestore(lock, flags);
			dropped_lock = true;

			kiblnd_disconnect_conn(conn);
			kiblnd_conn_decref(conn);

			spin_lock_irqsave(lock, flags);
		}

		while (reconn < KIB_RECONN_BREAK) {
			if (kiblnd_data.kib_reconn_sec !=
			    ktime_get_real_seconds()) {
				kiblnd_data.kib_reconn_sec = ktime_get_real_seconds();
				list_splice_init(&kiblnd_data.kib_reconn_wait,
						 &kiblnd_data.kib_reconn_list);
			}

			conn = list_first_entry_or_null(&kiblnd_data.kib_reconn_list,
							struct kib_conn,
							ibc_list);
			if (!conn)
				break;

			list_del(&conn->ibc_list);

			spin_unlock_irqrestore(lock, flags);
			dropped_lock = true;

			reconn += kiblnd_reconnect_peer(conn->ibc_peer);
			kiblnd_peer_decref(conn->ibc_peer);
			LIBCFS_FREE(conn, sizeof(*conn));

			spin_lock_irqsave(lock, flags);
		}

		/* careful with the jiffy wrap... */
		timeout = (int)(deadline - jiffies);
		if (timeout <= 0) {
			const int n = 4;
			const int p = 1;
			int chunk = HASH_SIZE(kiblnd_data.kib_peers);
			unsigned int lnd_timeout;

			spin_unlock_irqrestore(lock, flags);
			dropped_lock = true;

			/* Time to check for RDMA timeouts on a few more
			 * peers: I do checks every 'p' seconds on a
			 * proportion of the peer_ni table and I need to check
			 * every connection 'n' times within a timeout
			 * interval, to ensure I detect a timeout on any
			 * connection within (n+1)/n times the timeout
			 * interval.
			 */

			lnd_timeout = kiblnd_timeout();
			if (lnd_timeout > n * p)
				chunk = (chunk * n * p) / lnd_timeout;
			if (chunk == 0)
				chunk = 1;

			for (i = 0; i < chunk; i++) {
				kiblnd_check_conns(peer_index);
				peer_index = (peer_index + 1) %
					HASH_SIZE(kiblnd_data.kib_peers);
			}

			deadline += cfs_time_seconds(p);
			spin_lock_irqsave(lock, flags);
		}

		if (dropped_lock)
			continue;

		/* Nothing to do for 'timeout'  */
		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&kiblnd_data.kib_connd_waitq, &wait);
		spin_unlock_irqrestore(lock, flags);

		schedule_timeout(timeout);

		remove_wait_queue(&kiblnd_data.kib_connd_waitq, &wait);
		spin_lock_irqsave(lock, flags);
	}

	spin_unlock_irqrestore(lock, flags);

	kiblnd_thread_fini();
	return 0;
}

void
kiblnd_qp_event(struct ib_event *event, void *arg)
{
	struct kib_conn *conn = arg;

	switch (event->event) {
	case IB_EVENT_COMM_EST:
		CDEBUG(D_NET, "%s established\n",
		       libcfs_nidstr(&conn->ibc_peer->ibp_nid));
		/* We received a packet but connection isn't established
		 * probably handshake packet was lost, so free to
		 * force make connection established
		 */
		rdma_notify(conn->ibc_cmid, IB_EVENT_COMM_EST);
		return;

	case IB_EVENT_PORT_ERR:
	case IB_EVENT_DEVICE_FATAL:
		CERROR("Fatal device error for NI %s\n",
		       libcfs_nidstr(&conn->ibc_peer->ibp_ni->ni_nid));
		atomic_set(&conn->ibc_peer->ibp_ni->ni_fatal_error_on, 1);
		return;

	case IB_EVENT_PORT_ACTIVE:
		CERROR("Port reactivated for NI %s\n",
		       libcfs_nidstr(&conn->ibc_peer->ibp_ni->ni_nid));
		atomic_set(&conn->ibc_peer->ibp_ni->ni_fatal_error_on, 0);
		return;

	default:
		CERROR("%s: Async QP event type %d\n",
		       libcfs_nidstr(&conn->ibc_peer->ibp_nid), event->event);
		return;
	}
}

static void
kiblnd_complete(struct ib_wc *wc)
{
	switch (kiblnd_wreqid2type(wc->wr_id)) {
	default:
		LBUG();

	case IBLND_WID_MR:
		if (wc->status != IB_WC_SUCCESS &&
		    wc->status != IB_WC_WR_FLUSH_ERR)
			CNETERR("FastReg failed: %d\n", wc->status);
		return;

	case IBLND_WID_RDMA:
		/* We only get RDMA completion notification if it fails.  All
		 * subsequent work items, including the final SEND will fail
		 * too.  However we can't print out any more info about the
		 * failing RDMA because 'tx' might be back on the idle list or
		 * even reused already if we didn't manage to post all our work
		 * items
		 */
		CNETERR("RDMA (tx: %p) failed: %d\n",
			kiblnd_wreqid2ptr(wc->wr_id), wc->status);
		return;

	case IBLND_WID_TX:
		kiblnd_tx_complete(kiblnd_wreqid2ptr(wc->wr_id), wc->status);
		return;

	case IBLND_WID_RX:
		kiblnd_rx_complete(kiblnd_wreqid2ptr(wc->wr_id), wc->status,
				   wc->byte_len);
		return;
	}
}

void
kiblnd_cq_completion(struct ib_cq *cq, void *arg)
{
	/* NB I'm not allowed to schedule this conn once its refcount has
	 * reached 0.  Since fundamentally I'm racing with scheduler threads
	 * consuming my CQ I could be called after all completions have
	 * occurred.  But in this case, ibc_nrx == 0 && ibc_nsends_posted == 0
	 * and this CQ is about to be destroyed so I NOOP.
	 */
	struct kib_conn	*conn = arg;
	struct kib_sched_info *sched = conn->ibc_sched;
	unsigned long flags;

	LASSERT(cq == conn->ibc_cq);

	spin_lock_irqsave(&sched->ibs_lock, flags);

	conn->ibc_ready = 1;

	if (!conn->ibc_scheduled &&
	    (conn->ibc_nrx > 0 ||
	     conn->ibc_nsends_posted > 0)) {
		kiblnd_conn_addref(conn); /* +1 ref for sched_conns */
		kiblnd_dump_conn_dbg(conn);
		conn->ibc_scheduled = 1;
		list_add_tail(&conn->ibc_sched_list, &sched->ibs_conns);

		if (waitqueue_active(&sched->ibs_waitq))
			wake_up(&sched->ibs_waitq);
	}

	spin_unlock_irqrestore(&sched->ibs_lock, flags);
}

void
kiblnd_cq_event(struct ib_event *event, void *arg)
{
	struct kib_conn *conn = arg;

	CERROR("%s: async CQ event type %d\n",
	       libcfs_nidstr(&conn->ibc_peer->ibp_nid), event->event);
}

int
kiblnd_scheduler(void *arg)
{
	long id = (long)arg;
	struct kib_sched_info *sched;
	struct kib_conn	*conn;
	wait_queue_entry_t wait;
	unsigned long flags;
	struct ib_wc wc;
	bool did_something;
	int rc;

	init_wait(&wait);

	sched = kiblnd_data.kib_scheds[KIB_THREAD_CPT(id)];

	rc = cfs_cpt_bind(lnet_cpt_table(), sched->ibs_cpt);
	if (rc != 0)
		CWARN("Unable to bind on CPU partition %d, please verify whether all CPUs are healthy and reload modules if necessary, otherwise your system might under risk of low performance\n", sched->ibs_cpt);

	spin_lock_irqsave(&sched->ibs_lock, flags);

	while (!kiblnd_data.kib_shutdown) {
		if (need_resched()) {
			spin_unlock_irqrestore(&sched->ibs_lock, flags);

			cond_resched();

			spin_lock_irqsave(&sched->ibs_lock, flags);
		}

		did_something = false;

		conn = list_first_entry_or_null(&sched->ibs_conns,
						struct kib_conn,
						ibc_sched_list);
		if (conn) {
			/* take over kib_sched_conns' ref on conn... */
			LASSERT(conn->ibc_scheduled);
			list_del(&conn->ibc_sched_list);
			conn->ibc_ready = 0;

			spin_unlock_irqrestore(&sched->ibs_lock, flags);

			wc.wr_id = IBLND_WID_INVAL;

			rc = ib_poll_cq(conn->ibc_cq, 1, &wc);
			if (rc == 0) {
				rc = ib_req_notify_cq(conn->ibc_cq,
						      IB_CQ_NEXT_COMP);
				if (rc < 0) {
					CWARN("%s: ib_req_notify_cq failed: closing connection %p: rc = %d\n",
					      libcfs_nidstr(&conn->ibc_peer->ibp_nid),
					      conn, rc);
					kiblnd_close_conn(conn, -EIO);
					kiblnd_conn_decref(conn);
					spin_lock_irqsave(&sched->ibs_lock,
							  flags);
					continue;
				}

				rc = ib_poll_cq(conn->ibc_cq, 1, &wc);
			}

			if (unlikely(rc > 0 && wc.wr_id == IBLND_WID_INVAL)) {
				LCONSOLE_ERROR(
					"ib_poll_cq (rc: %d) returned invalid wr_id, opcode %d, status: %d, vendor_err: %d, conn: %s status: %d\n please upgrade firmware and OFED or contact vendor.\n",
					rc, wc.opcode, wc.status, wc.vendor_err,
					libcfs_nidstr(&conn->ibc_peer->ibp_nid),
					conn->ibc_state);
				rc = -EINVAL;
			}

			if (rc < 0) {
				CWARN("%s: ib_poll_cq failed: closing connection %p: rc = %d\n",
				      libcfs_nidstr(&conn->ibc_peer->ibp_nid),
				      conn, rc);
				kiblnd_close_conn(conn, -EIO);
				kiblnd_conn_decref(conn);
				spin_lock_irqsave(&sched->ibs_lock, flags);
				continue;
			}

			spin_lock_irqsave(&sched->ibs_lock, flags);

			if (rc != 0 || conn->ibc_ready) {
				/* There may be another completion waiting; get
				 * another scheduler to check while I handle
				 * this one...
				 *
				 * +1 ref for sched_conns
				 */
				kiblnd_conn_addref(conn);
				list_add_tail(&conn->ibc_sched_list,
					      &sched->ibs_conns);
				if (waitqueue_active(&sched->ibs_waitq))
					wake_up(&sched->ibs_waitq);
			} else {
				conn->ibc_scheduled = 0;
			}

			if (rc != 0) {
				spin_unlock_irqrestore(&sched->ibs_lock, flags);
				kiblnd_complete(&wc);

				spin_lock_irqsave(&sched->ibs_lock, flags);
			}

			kiblnd_conn_decref(conn); /* ..drop my ref from above */
			did_something = true;
		}

		if (did_something)
			continue;

		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue_exclusive(&sched->ibs_waitq, &wait);
		spin_unlock_irqrestore(&sched->ibs_lock, flags);

		schedule();

		remove_wait_queue(&sched->ibs_waitq, &wait);
		set_current_state(TASK_RUNNING);
		spin_lock_irqsave(&sched->ibs_lock, flags);
	}

	spin_unlock_irqrestore(&sched->ibs_lock, flags);

	kiblnd_thread_fini();
	return 0;
}

int
kiblnd_failover_thread(void *arg)
{
	rwlock_t *glock = &kiblnd_data.kib_global_lock;
	struct kib_dev *dev;
	struct net *ns = arg;
	wait_queue_entry_t wait;
	unsigned long flags;
	int rc;

	LASSERT(*kiblnd_tunables.kib_dev_failover != 0);

	init_wait(&wait);
	write_lock_irqsave(glock, flags);

	while (!kiblnd_data.kib_shutdown) {
		bool do_failover = false;
		int long_sleep;

		list_for_each_entry(dev, &kiblnd_data.kib_failed_devs,
				    ibd_fail_list) {
			if (ktime_get_seconds() < dev->ibd_next_failover)
				continue;
			do_failover = true;
			break;
		}

		if (do_failover) {
			list_del_init(&dev->ibd_fail_list);
			dev->ibd_failover = 1;
			write_unlock_irqrestore(glock, flags);

			rc = kiblnd_dev_failover(dev, ns);

			write_lock_irqsave(glock, flags);

			LASSERT(dev->ibd_failover);
			dev->ibd_failover = 0;
			if (rc >= 0) { /* Device is OK or failover succeed */
				dev->ibd_next_failover = ktime_get_seconds() + 3;
				continue;
			}

			/* failed to failover, retry later */
			dev->ibd_next_failover = ktime_get_seconds() +
				min(dev->ibd_failed_failover, 10);
			if (kiblnd_dev_can_failover(dev)) {
				list_add_tail(&dev->ibd_fail_list,
					      &kiblnd_data.kib_failed_devs);
			}

			continue;
		}

		/* long sleep if no more pending failover */
		long_sleep = list_empty(&kiblnd_data.kib_failed_devs);

		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&kiblnd_data.kib_failover_waitq, &wait);
		write_unlock_irqrestore(glock, flags);

		rc = schedule_timeout(long_sleep ? cfs_time_seconds(10) :
				      cfs_time_seconds(1));
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&kiblnd_data.kib_failover_waitq, &wait);
		write_lock_irqsave(glock, flags);

		if (!long_sleep || rc != 0)
			continue;

		/* have a long sleep, routine check all active devices,
		 * we need checking like this because if there is not active
		 * connection on the dev and no SEND from local, we may listen
		 * on wrong HCA for ever while there is a bonding failover
		 */
		list_for_each_entry(dev, &kiblnd_data.kib_devs, ibd_list) {
			if (kiblnd_dev_can_failover(dev)) {
				list_add_tail(&dev->ibd_fail_list,
					      &kiblnd_data.kib_failed_devs);
			}
		}
	}

	write_unlock_irqrestore(glock, flags);

	kiblnd_thread_fini();
	return 0;
}
