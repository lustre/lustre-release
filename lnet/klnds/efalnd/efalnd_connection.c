// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2024-2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Yonatan Nachum <ynachum@amazon.com>
 */

#include <linux/jiffies.h>

#include <rdma/ib_verbs.h>

#include "efalnd.h"

#define MAX_IDLE_CONN		32
#define RESP_CONN_EXTRA_TIME	300

static inline struct kefa_conn_probe_msg *
kefalnd_get_probe_from_msg(struct kefa_msg *msg)
{
	if (msg->hdr.proto_ver != EFALND_PROTO_VER_1)
		return &msg->msg_v2.u.conn_probe;

	return &msg->msg_v1.u.conn_probe;
}

static inline struct kefa_conn_probe_resp_msg *
kefalnd_get_probe_resp_from_msg(struct kefa_msg *msg)
{
	if (msg->hdr.proto_ver != EFALND_PROTO_VER_1)
		return &msg->msg_v2.u.conn_probe_resp;

	return &msg->msg_v1.u.conn_probe_resp;
}

static inline struct kefa_conn_req_msg *
kefalnd_get_conn_req_from_msg(struct kefa_msg *msg)
{
	return &msg->msg_v2.u.conn_request;
}

static inline struct kefa_conn_req_ack *
kefalnd_get_conn_req_ack_from_msg(struct kefa_msg *msg)
{
	return &msg->msg_v2.u.conn_request_ack;
}

static inline void
kefalnd_set_conn_state_locked(struct kefa_conn *conn,
			      enum kefa_conn_state new_state)
__must_hold(&conn->lock)
{
	CDEBUG(D_NET, "Connection[%s] type[%d] change state from[%d] to[%d]\n",
	       libcfs_nidstr(&conn->remote_nid), conn->type, conn->state,
	       new_state);

	conn->state = new_state;
}

static void
kefalnd_set_conn_state(struct kefa_conn *conn, enum kefa_conn_state new_state)
{
	unsigned long flags;

	spin_lock_irqsave(&conn->lock, flags);
	kefalnd_set_conn_state_locked(conn, new_state);
	spin_unlock_irqrestore(&conn->lock, flags);
}

static inline int
kefalnd_post_conn_message(struct kefa_conn *conn, struct kefa_tx *tx)
{
	struct kefa_dev *efa_dev = conn->efa_ni->efa_dev;
	struct kefa_peer_ni *peer_ni = conn->peer_ni;
	struct kefa_qp *cm_qp = efa_dev->cm_qp;
	struct ib_srd_wr *srd_wr;
	struct ib_send_wr *wr;
	unsigned long flags;
	int rc;

	tx->conn = conn;

	srd_wr = &tx->wrq.wr;
	wr = &srd_wr->wr;

	srd_wr->ah = conn->ah;

	atomic_set(&tx->ref_cnt, 1);
	atomic64_set(&tx->send_time, ktime_get_seconds());
	kefalnd_msg_set_epoch(tx->msg, conn->remote_epoch);

	spin_lock_irqsave(&conn->lock, flags);
	list_add_tail(&tx->list_node, &conn->active_tx);
	spin_unlock_irqrestore(&conn->lock, flags);

	if (nid_is_nid4(&conn->remote_nid)) {
		read_lock_irqsave(&peer_ni->peer_ni_lock, flags);
		srd_wr->remote_qpn = peer_ni->cm_qp.qp_num;
		srd_wr->remote_qkey = peer_ni->cm_qp.qkey;
		read_unlock_irqrestore(&peer_ni->peer_ni_lock, flags);
	} else {
		srd_wr->remote_qpn = kefalnd_large_nid_get_cm_qp_num(&conn->remote_nid);
		srd_wr->remote_qkey = kefalnd_large_nid_get_cm_qp_qkey(&conn->remote_nid);
	}

	rc = ib_post_send(cm_qp->ib_qp, wr, NULL);
	if (rc) {
		EFA_DEV_ERR(efa_dev,
			    "QP[%u] failed to post conn msg to peer NI[%s]. err[%d]\n",
			    cm_qp->ib_qp->qp_num,
			    libcfs_nidstr(&conn->remote_nid), rc);

		spin_lock_irqsave(&conn->lock, flags);
		list_del_init(&tx->list_node);
		spin_unlock_irqrestore(&conn->lock, flags);

		tx->conn = NULL;
		atomic_set(&tx->ref_cnt, 0);
		atomic64_set(&tx->send_time, 0);

		return rc;
	}

	return 0;
}

static u32
kefalnd_select_conn_qps(struct kefa_dev *efa_dev,
			struct kefa_qp_proto *data_qps)
{
	int i;

	for (i = 0; i < efa_dev->nqps; i++) {
		data_qps[i].qp_num = efa_dev->qps[i].ib_qp->qp_num;
		data_qps[i].qkey = efa_dev->qps[i].qkey;
	}

	return efa_dev->nqps;
}

static int
kefalnd_send_conn_req_ack(struct kefa_conn *conn, int status)
{
	struct kefa_dev *efa_dev = conn->efa_ni->efa_dev;
	struct kefa_conn_req_ack *ack_msg;
	struct kefa_tx *tx;
	int nob, rc;

	CDEBUG(D_NET, "Send connection ack from[%s] to[%s]\n",
	       libcfs_nidstr(&conn->local_nid),
	       libcfs_nidstr(&conn->remote_nid));

	tx = kefalnd_get_idle_tx(conn->efa_ni);
	if (!tx) {
		EFA_DEV_ERR(efa_dev,
			    "can't allocate conn req txd for peer NI[%s]\n",
			    libcfs_nidstr(&conn->remote_nid));

		return -ENOMEM;
	}

	nob = status ? sizeof(struct kefa_conn_req_ack) :
			offsetof(struct kefa_conn_req_ack,
				data_qps[efa_dev->nqps]);

	kefalnd_init_tx_protocol_msg(tx, conn, EFALND_MSG_CONN_REQ_ACK, nob,
				     conn->proto_ver);
	ack_msg = kefalnd_get_conn_req_ack_from_msg(tx->msg);
	ack_msg->lnd_ver = kefalnd_get_lnd_version();
	ack_msg->src_epoch = conn->efa_ni->ni_epoch;
	ack_msg->caps = 0;
	ack_msg->reserved = 0;

	ack_msg->src_conn_id = EFALND_INV_CONN;
	ack_msg->status = kefalnd_errno_to_efa_status(status);
	ack_msg->nqps = status ? 0 :
		kefalnd_select_conn_qps(efa_dev, &ack_msg->data_qps[0]);

	rc = kefalnd_post_conn_message(conn, tx);
	if (rc)
		kefalnd_tx_done(tx);

	return rc;
}

static int
kefalnd_send_conn_req(struct kefa_conn *conn)
{
	struct kefa_dev *efa_dev = conn->efa_ni->efa_dev;
	struct kefa_conn_req_msg *req;
	struct kefa_tx *tx;
	int nob, rc;

	LASSERT(conn->state == KEFA_CONN_ESTABLISH);

	CDEBUG(D_NET, "Send connection request from[%s] to[%s]\n",
	       libcfs_nidstr(&conn->local_nid),
	       libcfs_nidstr(&conn->remote_nid));

	tx = kefalnd_get_idle_tx(conn->efa_ni);
	if (!tx) {
		EFA_DEV_ERR(efa_dev,
			    "can't allocate conn req txd for peer NI[%s]\n",
			    libcfs_nidstr(&conn->remote_nid));

		return -ENOMEM;
	}

	nob = offsetof(struct kefa_conn_req_msg, data_qps[efa_dev->nqps]);
	kefalnd_init_tx_protocol_msg(tx, conn, EFALND_MSG_CONN_REQ, nob,
				     conn->proto_ver);

	req = kefalnd_get_conn_req_from_msg(tx->msg);
	req->lnd_ver = kefalnd_get_lnd_version();
	memcpy(req->src_gid, efa_dev->gid.raw, sizeof(req->src_gid));
	req->src_epoch = conn->efa_ni->ni_epoch;
	req->cm_qp.qp_num = efa_dev->cm_qp->ib_qp->qp_num;
	req->cm_qp.qkey = efa_dev->cm_qp->qkey;
	req->caps = 0;
	req->reserved = 0;

	req->requests = conn->requests;
	req->src_conn_id = EFALND_INV_CONN;
	req->nqps = kefalnd_select_conn_qps(efa_dev, &req->data_qps[0]);

	rc = kefalnd_post_conn_message(conn, tx);
	if (rc)
		kefalnd_tx_done(tx);

	return rc;
}

static int
kefalnd_send_conn_probe_resp(struct kefa_conn *conn, int status)
{
	struct kefa_dev *efa_dev = conn->efa_ni->efa_dev;
	struct kefa_conn_probe_resp_msg *probe_resp;
	struct kefa_tx *tx;
	int rc;

	CDEBUG(D_NET, "Send connection probe response from[%s] to[%s]\n",
	       libcfs_nidstr(&conn->local_nid),
	       libcfs_nidstr(&conn->remote_nid));

	tx = kefalnd_get_idle_tx(conn->efa_ni);
	if (!tx) {
		EFA_DEV_ERR(efa_dev,
			    "can't allocate conn req txd for peer NI[%s]\n",
			    libcfs_nidstr(&conn->remote_nid));

		return -ENOMEM;
	}

	kefalnd_init_tx_protocol_msg(tx, conn, EFALND_MSG_CONN_PROBE_RESP,
				     sizeof(struct kefa_conn_probe_resp_msg),
				     conn->proto_ver);

	probe_resp = kefalnd_get_probe_resp_from_msg(tx->msg);
	probe_resp->lnd_ver = kefalnd_get_lnd_version();
	probe_resp->src_epoch = conn->efa_ni->ni_epoch;
	probe_resp->caps = 0;
	probe_resp->min_proto_ver = EFALND_MIN_PROTO_VER;
	probe_resp->max_proto_ver = EFALND_MAX_PROTO_VER;
	probe_resp->status = kefalnd_errno_to_efa_status(status);

	rc = kefalnd_post_conn_message(conn, tx);
	if (rc)
		kefalnd_tx_done(tx);

	return rc;
}

static int
kefalnd_send_conn_probe(struct kefa_conn *conn)
{
	struct kefa_dev *efa_dev = conn->efa_ni->efa_dev;
	struct kefa_conn_probe_msg *probe;
	struct kefa_tx *tx;
	int rc;

	LASSERT(conn->state == KEFA_CONN_PROBE_EFA);

	CDEBUG(D_NET, "Send connection probe from[%s] to[%s]\n",
	       libcfs_nidstr(&conn->local_nid),
	       libcfs_nidstr(&conn->remote_nid));

	tx = kefalnd_get_idle_tx(conn->efa_ni);
	if (!tx) {
		EFA_DEV_ERR(efa_dev,
			    "can't allocate conn req txd for peer NI[%s]\n",
			    libcfs_nidstr(&conn->remote_nid));

		return -ENOMEM;
	}

	kefalnd_init_tx_protocol_msg(tx, conn, EFALND_MSG_CONN_PROBE,
				     sizeof(struct kefa_conn_probe_msg),
				     conn->proto_ver);

	probe = kefalnd_get_probe_from_msg(tx->msg);
	probe->lnd_ver = kefalnd_get_lnd_version();
	probe->src_epoch = conn->efa_ni->ni_epoch;
	memcpy(probe->src_gid, efa_dev->gid.raw, sizeof(probe->src_gid));
	probe->cm_qp.qp_num = efa_dev->cm_qp->ib_qp->qp_num;
	probe->cm_qp.qkey = efa_dev->cm_qp->qkey;
	probe->caps = 0;

	rc = kefalnd_post_conn_message(conn, tx);
	if (rc)
		kefalnd_tx_done(tx);

	return rc;
}

void
kefalnd_destroy_conn(struct kefa_conn *conn, enum lnet_msg_hstatus hstatus,
		     int status)
{
	struct kefa_tx *tx, *temp_tx;
	struct list_head cancel_tx;
	unsigned long flags;

	INIT_LIST_HEAD(&cancel_tx);

	spin_lock_irqsave(&conn->lock, flags);
	if (!list_empty(&conn->active_tx))
		EFA_DEV_WARN(conn->efa_ni->efa_dev,
			     "destroying conn to peer NI[%s] with active TXs\n",
			     libcfs_nidstr(&conn->remote_nid));

	list_splice_init(&conn->pend_tx, &cancel_tx);
	spin_unlock_irqrestore(&conn->lock, flags);

	list_for_each_entry_safe(tx, temp_tx, &cancel_tx, list_node) {
		kefalnd_force_cancel_tx(tx, hstatus, status);
	}

	if (!IS_ERR_OR_NULL(conn->ah))
		rdma_destroy_ah(conn->ah, RDMA_DESTROY_AH_SLEEPABLE);

	if (conn->peer_ni)
		kefalnd_put_peer_ni(conn->peer_ni);

	if (conn->data_qps)
		LIBCFS_FREE(conn->data_qps,
			    conn->nqps * sizeof(*conn->data_qps));

	LIBCFS_FREE(conn, sizeof(*conn));
}

static u64
kefalnd_nid_to_key(struct lnet_nid *nid)
{
	u64 key;

	key = ((u64)(nid->nid_addr[0] ^ nid->nid_addr[2])) << 32;
	key |= nid->nid_addr[1] ^ nid->nid_addr[3];

	return key;
}

static struct kefa_conn *
kefalnd_create_conn(struct kefa_ni *efa_ni, struct lnet_nid *peer_nid,
		    enum kefa_conn_type conn_type)
{
	struct kefa_dev *efa_dev = efa_ni->efa_dev;
	struct kefa_conn *conn;

	LIBCFS_CPT_ALLOC(conn, lnet_cpt_table(), efa_dev->cpt, sizeof(*conn));
	if (!conn) {
		EFA_DEV_ERR(efa_dev, "failed to allocate EFA connection\n");
		return ERR_PTR(-ENOMEM);
	}

	conn->efa_ni = efa_ni;
	conn->proto_ver = EFALND_MAX_PROTO_VER;
	conn->remote_nid = *peer_nid;
	conn->hash_key = kefalnd_nid_to_key(&conn->remote_nid);
	conn->local_nid = efa_ni->lnet_ni->ni_nid;
	conn->remote_epoch = 0;
	conn->last_use_time = ktime_get_seconds();
	conn->state = KEFA_CONN_INACTIVE;

	if (nid_same(&conn->local_nid, &conn->remote_nid))
		conn_type = KEFA_CONN_TYPE_LB;

	conn->type = conn_type;
	INIT_LIST_HEAD(&conn->pend_tx);
	INIT_LIST_HEAD(&conn->active_tx);
	INIT_LIST_HEAD(&conn->abort_tx);
	INIT_HLIST_NODE(&conn->ni_node);
	spin_lock_init(&conn->lock);

	return conn;
}

static int
kefalnd_init_self_conn_data_qps(struct kefa_conn *conn)
{
	struct kefa_dev *efa_dev = conn->efa_ni->efa_dev;
	int i;

	conn->nqps = efa_dev->nqps;

	LIBCFS_CPT_ALLOC(conn->data_qps, lnet_cpt_table(), efa_dev->cpt,
			 efa_dev->nqps * sizeof(*conn->data_qps));
	if (!conn->data_qps)
		return -ENOMEM;

	for (i = 0; i < efa_dev->nqps; i++) {
		conn->data_qps[i].qp_num = efa_dev->qps[i].ib_qp->qp_num;
		conn->data_qps[i].qkey = efa_dev->qps[i].qkey;
	}

	atomic_set(&conn->last_qp_idx, 0);
	return 0;
}

static int
kefalnd_init_conn_data_qps(struct kefa_conn *conn,
			   struct kefa_qp_proto *data_qps, u32 nqps)
{
	struct kefa_dev *efa_dev = conn->efa_ni->efa_dev;
	int i;

	if (nqps > EFALND_MAX_PEER_QPS)
		return -EOPNOTSUPP;

	conn->nqps = nqps;

	LIBCFS_CPT_ALLOC_GFP(conn->data_qps, lnet_cpt_table(), efa_dev->cpt,
			     nqps * sizeof(*conn->data_qps), GFP_ATOMIC);
	if (!conn->data_qps)
		return -ENOMEM;

	for (i = 0; i < nqps; i++) {
		conn->data_qps[i].qp_num = data_qps[i].qp_num;
		conn->data_qps[i].qkey = data_qps[i].qkey;
	}

	atomic_set(&conn->last_qp_idx, 0);
	return 0;
}

static int
kefalnd_init_conn_ah(struct kefa_conn *conn, union ib_gid *gid)
{
	struct kefa_dev *efa_dev = conn->efa_ni->efa_dev;
	struct rdma_ah_attr ah_attr = {};

	ah_attr.type = RDMA_AH_ATTR_TYPE_UNDEFINED;
	rdma_ah_set_make_grd(&ah_attr, 0);
	rdma_ah_set_dlid(&ah_attr, 0);
	rdma_ah_set_sl(&ah_attr, 0);
	rdma_ah_set_path_bits(&ah_attr, 0);
	rdma_ah_set_static_rate(&ah_attr, 0);
	rdma_ah_set_port_num(&ah_attr, 1);
	rdma_ah_set_grh(&ah_attr, gid, 0, 0, 0, 0);

	conn->ah = rdma_create_ah(efa_dev->pd, &ah_attr,
				  RDMA_CREATE_AH_SLEEPABLE);
	if (IS_ERR(conn->ah)) {
		EFA_DEV_ERR(efa_dev,
			    "failed to create AH to peer NI[%s]. err[%ld]\n",
			    libcfs_nidstr(&conn->remote_nid),
			    PTR_ERR(conn->ah));

		return PTR_ERR(conn->ah);
	}

	return 0;
}

static int
kefalnd_establish_conn(struct kefa_conn *conn)
{
	struct kefa_dev *efa_dev = conn->efa_ni->efa_dev;
	struct kefa_peer_ni *peer_ni;
	union ib_gid gid;
	int rc = 0;

	if (nid_is_nid4(&conn->remote_nid)) {
		kefalnd_set_conn_state(conn, KEFA_CONN_PROBE_TCP);
		peer_ni = kefalnd_find_remote_peer_ni(efa_dev,
						      &conn->remote_nid);
		if (IS_ERR_OR_NULL(peer_ni)) {
			EFA_DEV_DEBUG(efa_dev,
				      "failed to locate GID for NID %s. err[%ld]\n",
				      libcfs_nidstr(&conn->remote_nid),
				      PTR_ERR(peer_ni));
			return PTR_ERR(peer_ni);
		}

		gid = peer_ni->gid;
		conn->peer_ni = peer_ni;
	} else {
		kefalnd_large_nid_get_gid(&conn->remote_nid, &gid);
	}

	kefalnd_set_conn_state(conn, KEFA_CONN_PROBE_EFA);
	rc = kefalnd_init_conn_ah(conn, &gid);
	if (rc)
		return rc;

	if (conn->type == KEFA_CONN_TYPE_LB) {
		conn->remote_epoch = conn->efa_ni->ni_epoch;
		/* TODO: initialize self connection caps and requests */
		rc = kefalnd_init_self_conn_data_qps(conn);
		if (rc)
			return rc;

		kefalnd_set_conn_state(conn, KEFA_CONN_ACTIVE);
	} else {
		rc = kefalnd_send_conn_probe(conn);
	}

	return rc;
}

static struct kefa_conn *
kefalnd_lookup_conn_locked(struct kefa_ni *efa_ni, struct lnet_nid *nid,
			   enum kefa_conn_type conn_type)
__must_hold(&efa_ni->conn_lock)
{
	struct kefa_conn *conn;
	u64 key;

	key = kefalnd_nid_to_key(nid);
	hash_for_each_possible(efa_ni->conns, conn, ni_node, key) {
		/* Match a connection if its NID and the NID of the local NI it
		 * communicates over are the same and the type of the connection
		 * is the same to the requested one.
		 * No need to take connection lock here since any change to
		 * those fields is performed while holding the NI connections
		 * write lock.
		 */
		if (!nid_same(&conn->remote_nid, nid))
			continue;

		if (conn->type != conn_type && conn->type != KEFA_CONN_TYPE_LB)
			continue;

		conn->last_use_time = ktime_get_seconds();
		return conn;
	}
	return NULL;
}

static void
kefalnd_remove_conn_locked(struct kefa_conn *conn)
__must_hold(&conn->efa_ni->conn_lock)
{
	hash_del(&conn->ni_node);
}

static void
kefalnd_remove_conn(struct kefa_ni *efa_ni, struct kefa_conn *conn)
{
	unsigned long flags;

	write_lock_irqsave(&efa_ni->conn_lock, flags);
	kefalnd_remove_conn_locked(conn);
	write_unlock_irqrestore(&efa_ni->conn_lock, flags);
}

static void
kefalnd_add_conn_locked(struct kefa_ni *efa_ni, struct kefa_conn *conn)
__must_hold(&efa_ni->conn_lock)
{
	hash_add(efa_ni->conns, &conn->ni_node, conn->hash_key);
}

struct kefa_conn *
kefalnd_lookup_or_init_conn(struct kefa_ni *efa_ni, struct lnet_nid *nid,
			    enum kefa_conn_type conn_type)
{
	struct kefa_conn *conn, *new_conn;
	unsigned long flags;
	int rc;

	/* First time, just use a read lock since I expect to find live
	 * connection
	 */
	read_lock_irqsave(&efa_ni->conn_lock, flags);
	conn = kefalnd_lookup_conn_locked(efa_ni, nid, conn_type);
	if (conn) {
		read_unlock_irqrestore(&efa_ni->conn_lock, flags);
		return conn;
	}

	read_unlock_irqrestore(&efa_ni->conn_lock, flags);

	/* Create the new conn here since we can't sleep inside the critical
	 * section
	 */
	new_conn = kefalnd_create_conn(efa_ni, nid, conn_type);
	if (IS_ERR(new_conn))
		return new_conn;

	/* Retry with write lock */
	write_lock_irqsave(&efa_ni->conn_lock, flags);
	conn = kefalnd_lookup_conn_locked(efa_ni, nid, conn_type);
	if (conn) {
		write_unlock_irqrestore(&efa_ni->conn_lock, flags);
		kefalnd_destroy_conn(new_conn, LNET_MSG_STATUS_OK, 0);
		return conn;
	}

	/* Add the new connection atomically so anyone will see it */
	kefalnd_add_conn_locked(efa_ni, new_conn);
	write_unlock_irqrestore(&efa_ni->conn_lock, flags);

	/* We establish just for an initiator connection since its the initiator
	 * of the communication with the remote side.
	 */
	if (conn_type == KEFA_CONN_TYPE_RESPONDER)
		return new_conn;

	/* Connection establishment can be lock free since other users of the
	 * connection will just place the TX on the pending list if it isn't
	 * already live.
	 */
	rc = kefalnd_establish_conn(new_conn);
	if (rc) {
		kefalnd_remove_conn(efa_ni, new_conn);
		kefalnd_destroy_conn(new_conn, LNET_MSG_STATUS_REMOTE_TIMEOUT,
				     rc);
		return ERR_PTR(rc);
	}

	return new_conn;
}

struct kefa_conn *
kefalnd_lookup_conn(struct kefa_ni *efa_ni, struct lnet_nid *nid,
		    enum kefa_conn_type conn_type)
{
	struct kefa_conn *conn;
	unsigned long flags;

	read_lock_irqsave(&efa_ni->conn_lock, flags);
	conn = kefalnd_lookup_conn_locked(efa_ni, nid, conn_type);
	read_unlock_irqrestore(&efa_ni->conn_lock, flags);
	return conn;
}

static int
kefalnd_handle_conn_req_ack(struct kefa_ni *efa_ni,
			    struct lnet_nid *srcnid,
			    struct lnet_nid *dstnid,
			    struct kefa_conn_req_ack *ack_msg)
{
	enum lnet_msg_hstatus hstatus;
	struct kefa_conn *conn;
	unsigned long flags;
	int rc;

	CDEBUG(D_NET, "Received connection ack from[%s] to[%s]\n",
	       libcfs_nidstr(srcnid), libcfs_nidstr(dstnid));

	conn = kefalnd_lookup_conn(efa_ni, srcnid, KEFA_CONN_TYPE_INITIATOR);
	if (!conn) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "Unexpected connection from[%s] to[%s]\n",
			    libcfs_nidstr(srcnid), libcfs_nidstr(dstnid));

		return -ENOTCONN;
	}

	spin_lock_irqsave(&conn->lock, flags);
	if (conn->state != KEFA_CONN_ESTABLISH) {
		spin_unlock_irqrestore(&conn->lock, flags);
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "Unexpected connection state[%u] from[%s] to[%s]\n",
			    conn->state, libcfs_nidstr(srcnid),
			    libcfs_nidstr(dstnid));

		return -EINVAL;
	}

	spin_unlock_irqrestore(&conn->lock, flags);

	if (ack_msg->status) {
		rc = kefalnd_efa_status_to_errno(ack_msg->status);
		hstatus = LNET_MSG_STATUS_REMOTE_DROPPED;
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "conn request failed on remote err[%d] from[%s] to[%s]\n",
			    rc, libcfs_nidstr(srcnid), libcfs_nidstr(dstnid));

		goto cleanup_conn;
	}

	rc = kefalnd_init_conn_data_qps(conn,
					(struct kefa_qp_proto *)ack_msg->data_qps,
					ack_msg->nqps);
	if (rc) {
		hstatus = LNET_MSG_STATUS_LOCAL_ABORTED;
		goto cleanup_conn;
	}

	spin_lock_irqsave(&conn->lock, flags);
	kefalnd_set_conn_state_locked(conn, KEFA_CONN_ACTIVE);

	/* Post all pending TXs on the connection. */
	kefalnd_conn_post_tx_locked(conn);
	spin_unlock_irqrestore(&conn->lock, flags);

	return 0;

cleanup_conn:
	kefalnd_remove_conn(efa_ni, conn);
	kefalnd_destroy_conn(conn, hstatus, rc);
	return rc;
}

static int
kefalnd_handle_conn_req(struct kefa_ni *efa_ni,
			struct lnet_nid *srcnid,
			struct lnet_nid *dstnid,
			struct kefa_conn_req_msg *request_msg,
			u8 proto_ver)
{
	struct kefa_conn *conn;
	unsigned long flags;
	int rc;

	CDEBUG(D_NET, "Received connection request from[%s] to[%s]\n",
	       libcfs_nidstr(srcnid), libcfs_nidstr(dstnid));

	conn = kefalnd_lookup_conn(efa_ni, srcnid, KEFA_CONN_TYPE_RESPONDER);
	if (!conn) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "Unexpected connection from[%s] to[%s]\n",
			    libcfs_nidstr(srcnid), libcfs_nidstr(dstnid));

		return -ENOTCONN;
	}

	/* We currently asume connection probe comes before request so the
	 * connection must exits at this point and it can be active or during
	 * establishment.
	 */
	spin_lock_irqsave(&conn->lock, flags);
	switch (conn->state) {
	case KEFA_CONN_PROBE_EFA_PASSIVE:
		/* Regular path */
		/* TODO: validate requests make sense */
		conn->requests = request_msg->requests;
		conn->proto_ver = proto_ver;

		rc = kefalnd_init_conn_data_qps(conn,
						(struct kefa_qp_proto *)request_msg->data_qps,
						request_msg->nqps);
		if (rc) {
			spin_unlock_irqrestore(&conn->lock, flags);
			kefalnd_send_conn_req_ack(conn, rc);
			return rc;
		}

		kefalnd_set_conn_state_locked(conn, KEFA_CONN_ACTIVE);
		spin_unlock_irqrestore(&conn->lock, flags);
		break;

	case KEFA_CONN_ACTIVE:
		/* If the connection was already active and valid on probe. */
		spin_unlock_irqrestore(&conn->lock, flags);
		break;

	default:
		spin_unlock_irqrestore(&conn->lock, flags);
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "Unexpected connection state[%u] from[%s] to[%s]\n",
			    conn->state, libcfs_nidstr(srcnid),
			    libcfs_nidstr(dstnid));

		return -EINVAL;
	}

	rc = kefalnd_send_conn_req_ack(conn, 0);
	return rc;
}

static int
kefalnd_handle_conn_probe_resp(struct kefa_ni *efa_ni, struct lnet_nid *srcnid,
			       struct lnet_nid *dstnid,
			       struct kefa_conn_probe_resp_msg *probe_resp_msg,
			       u16 msg_nob)
{
	enum lnet_msg_hstatus hstatus;
	u8 min_proto, max_proto;
	struct kefa_conn *conn;
	unsigned long flags;
	int rc;

	CDEBUG(D_NET, "Received connection probe response from[%s] to[%s]\n",
	       libcfs_nidstr(srcnid), libcfs_nidstr(dstnid));

	conn = kefalnd_lookup_conn(efa_ni, srcnid, KEFA_CONN_TYPE_INITIATOR);
	if (!conn) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "Unexpected connection from[%s] to[%s]\n",
			    libcfs_nidstr(srcnid), libcfs_nidstr(dstnid));

		return -ENOTCONN;
	}

	spin_lock_irqsave(&conn->lock, flags);
	if (conn->state != KEFA_CONN_PROBE_EFA) {
		spin_unlock_irqrestore(&conn->lock, flags);
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "Unexpected connection state[%u] from[%s] to[%s]\n",
			    conn->state, libcfs_nidstr(srcnid),
			    libcfs_nidstr(dstnid));

		return -EINVAL;
	}

	spin_unlock_irqrestore(&conn->lock, flags);

	min_proto = probe_resp_msg->min_proto_ver;
	max_proto = probe_resp_msg->max_proto_ver;

	rc = kefalnd_efa_status_to_errno(probe_resp_msg->status);
	if (rc) {
		if (rc == -EPROTONOSUPPORT) {
			/* Check for supported proto versions overlap */
			if (min_t(u8, EFALND_MAX_PROTO_VER, max_proto) <
			    max_t(u8, EFALND_MIN_PROTO_VER, min_proto)) {
				hstatus = LNET_MSG_STATUS_LOCAL_ERROR;
				goto cleanup_conn;
			}

			/* Downgrade protocol version to remote's supported
			 * version and probe again.
			 */
			conn->proto_ver = min_t(u8, EFALND_MAX_PROTO_VER,
						max_proto);
			rc = kefalnd_send_conn_probe(conn);
			if (!rc)
				return 0;
		}

		hstatus = LNET_MSG_STATUS_REMOTE_DROPPED;
		goto cleanup_conn;
	}

	/* TODO: Based on received capabilities decide whether to communicate
	 * with the remote peer or deny the connection.
	 * Also take into account establishment version.
	 */
	conn->remote_caps = probe_resp_msg->caps;
	conn->requests = 0;
	conn->remote_epoch = probe_resp_msg->src_epoch;
	conn->proto_ver = min_t(u8, EFALND_MAX_PROTO_VER, max_proto);

	kefalnd_set_conn_state(conn, KEFA_CONN_ESTABLISH);
	rc = kefalnd_send_conn_req(conn);
	if (rc) {
		hstatus = LNET_MSG_STATUS_LOCAL_DROPPED;
		goto cleanup_conn;
	}

	return 0;

cleanup_conn:
	kefalnd_remove_conn(efa_ni, conn);
	kefalnd_destroy_conn(conn, hstatus, rc);
	return rc;
}

static void
kefalnd_deactivate_conn_locked(struct kefa_conn *conn)
__must_hold(&conn->efa_ni->conn_lock)
{
	struct kefa_ni *efa_ni = conn->efa_ni;

	kefalnd_remove_conn_locked(conn);

	/* We set the connection's hash key to 0 so it won't be found on
	 * lookup anymore and set its state to deactivating so the connection
	 * daemon will remove it.
	 */
	kefalnd_set_conn_state(conn, KEFA_CONN_DEACTIVATING);
	conn->hash_key = 0;

	kefalnd_add_conn_locked(efa_ni, conn);
}

void
kefalnd_deactivate_conn(struct kefa_conn *conn)
{
	struct kefa_ni *efa_ni = conn->efa_ni;
	unsigned long flags;

	write_lock_irqsave(&efa_ni->conn_lock, flags);
	kefalnd_deactivate_conn_locked(conn);
	write_unlock_irqrestore(&efa_ni->conn_lock, flags);
}

static struct kefa_conn *
kefalnd_refresh_connection(struct kefa_ni *efa_ni, struct kefa_conn *old_conn,
			   struct lnet_nid *nid, union ib_gid *gid, u16 cm_qpn,
			   u32 cm_qkey)
{
	struct kefa_peer_ni *peer_ni;
	struct kefa_conn *new_conn;
	unsigned long flags;

	new_conn = kefalnd_create_conn(efa_ni, nid, KEFA_CONN_TYPE_RESPONDER);
	if (IS_ERR(new_conn))
		return new_conn;

	kefalnd_set_conn_state(new_conn, KEFA_CONN_PROBE_EFA_PASSIVE);

	/* Old connection have refcount on peer NI so we expect to find it and
	 * update its fields afterwards.
	 */
	if (nid_is_nid4(nid)) {
		peer_ni = kefalnd_lookup_or_create_peer_ni(lnet_nid_to_nid4(nid),
							   gid, cm_qpn,
							   cm_qkey);
		if (IS_ERR(peer_ni)) {
			kefalnd_destroy_conn(new_conn,
					     LNET_MSG_STATUS_LOCAL_ERROR,
					     PTR_ERR(peer_ni));
			return ERR_CAST(peer_ni);
		}

		kefalnd_update_peer_ni(peer_ni, gid, cm_qpn, cm_qkey);
		new_conn->peer_ni = peer_ni;
	}

	/* We remove the old responder connection and insert a new one
	 * atomically.
	 */
	write_lock_irqsave(&efa_ni->conn_lock, flags);
	kefalnd_deactivate_conn_locked(old_conn);
	kefalnd_add_conn_locked(efa_ni, new_conn);
	write_unlock_irqrestore(&efa_ni->conn_lock, flags);

	return new_conn;
}

static int
kefalnd_handle_conn_probe(struct kefa_ni *efa_ni,
			  struct lnet_nid *srcnid,
			  struct lnet_nid *dstnid,
			  struct kefa_conn_probe_msg *probe_msg,
			  u8 proto_ver)
{
	struct kefa_conn *conn, *init_conn;
	struct kefa_peer_ni *peer_ni;
	bool init_conn_active;
	unsigned long flags;
	union ib_gid gid;
	int rc, resp_rc;

	CDEBUG(D_NET, "Received connection probe from[%s] to[%s]\n",
	       libcfs_nidstr(srcnid), libcfs_nidstr(dstnid));

	conn = kefalnd_lookup_or_init_conn(efa_ni, srcnid,
					   KEFA_CONN_TYPE_RESPONDER);
	if (!conn)
		return PTR_ERR(conn);

	memcpy(gid.raw, probe_msg->src_gid, sizeof(probe_msg->src_gid));

	spin_lock_irqsave(&conn->lock, flags);
	switch (conn->state) {
	case KEFA_CONN_INACTIVE:
		kefalnd_set_conn_state_locked(conn, KEFA_CONN_PROBE_EFA_PASSIVE);
		spin_unlock_irqrestore(&conn->lock, flags);
		if (nid_is_nid4(srcnid)) {
			peer_ni = kefalnd_lookup_or_create_peer_ni(lnet_nid_to_nid4(srcnid), &gid,
								   probe_msg->cm_qp.qp_num,
								   probe_msg->cm_qp.qkey);
			if (IS_ERR_OR_NULL(peer_ni)) {
				rc = PTR_ERR(peer_ni);
				goto cleanup_conn;
			}

			conn->peer_ni = peer_ni;
		}

		break;

	case KEFA_CONN_PROBE_EFA_PASSIVE:
		/* KEFA_CONN_PROBE_EFA_PASSIVE - This side received probe
		 * already and returned with an error that caused the initiator
		 * to retry.
		 */
		spin_unlock_irqrestore(&conn->lock, flags);
		goto proto_check;

	case KEFA_CONN_ACTIVE:
		/* If there is an active connection to the peer and the epochs
		 * are the same we can keep using the same connection.
		 */
		if (conn->remote_epoch == probe_msg->src_epoch) {
			spin_unlock_irqrestore(&conn->lock, flags);
			kefalnd_send_conn_probe_resp(conn, 0);
			return 0;
		}

		spin_unlock_irqrestore(&conn->lock, flags);
		conn = kefalnd_refresh_connection(efa_ni, conn, srcnid, &gid,
						  probe_msg->cm_qp.qp_num,
						  probe_msg->cm_qp.qkey);
		if (IS_ERR(conn))
			return PTR_ERR(conn);

		break;

	default:
		/* KEFA_CONN_PROBE_TCP/KEFA_CONN_PROBE_EFA - We don't expect to
		 * find an RX connection in those states since a connection can
		 * be in those states only if it is the initiator(TX connection).
		 * KEFA_CONN_DEACTIVATING - Can't happen since connection with
		 * deactivating state have 0 as NID so can't be fetched.
		 */
		spin_unlock_irqrestore(&conn->lock, flags);
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "Unexpected connection state[%u] from[%s] to[%s]\n",
			    conn->state, libcfs_nidstr(srcnid),
			    libcfs_nidstr(dstnid));

		return -EINVAL;
	}

	/* We check if TX connection is valid as well and if not remove it */
	init_conn = kefalnd_lookup_conn(efa_ni, srcnid,
					KEFA_CONN_TYPE_INITIATOR);
	if (init_conn) {
		spin_lock_irqsave(&init_conn->lock, flags);
		init_conn_active = init_conn->state == KEFA_CONN_ACTIVE;
		spin_unlock_irqrestore(&init_conn->lock, flags);

		if (init_conn_active &&
		    init_conn->remote_epoch != probe_msg->src_epoch)
			kefalnd_deactivate_conn(init_conn);
	}

	conn->remote_epoch = probe_msg->src_epoch;
	conn->remote_caps = probe_msg->caps;

	rc = kefalnd_init_conn_ah(conn, &gid);
	if (rc)
		goto cleanup_conn;

proto_check:
	resp_rc = proto_ver > EFALND_MAX_PROTO_VER ? -EPROTONOSUPPORT : 0;
	if (!resp_rc)
		conn->proto_ver = proto_ver;

	rc = kefalnd_send_conn_probe_resp(conn, resp_rc);
	if (rc)
		goto cleanup_conn;

	return 0;

cleanup_conn:
	kefalnd_remove_conn(efa_ni, conn);
	kefalnd_destroy_conn(conn, LNET_MSG_STATUS_LOCAL_ERROR, rc);
	return rc;
}

static inline u16
kefalnd_get_payload_size_from_msg(struct kefa_msg *msg)
{
	if (msg->hdr.proto_ver != EFALND_PROTO_VER_1)
		return msg->hdr.nob - offsetof(struct kefa_msg, msg_v2.u);

	return msg->hdr.nob - offsetof(struct kefa_msg, msg_v1.u);
}

void
kefalnd_handle_conn_establishment(struct kefa_ni *efa_ni, struct kefa_msg *msg)
{
	struct lnet_nid srcnid, dstnid;
	u8 proto_ver;

	kefalnd_get_srcnid_from_msg(msg, &srcnid);
	kefalnd_get_dstnid_from_msg(msg, &dstnid);
	proto_ver = msg->hdr.proto_ver;

	switch (msg->hdr.type) {
	default:
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "bad EFALND establishment message type[%x]\n",
			    msg->hdr.type);

		break;

	case EFALND_MSG_CONN_PROBE:
		kefalnd_handle_conn_probe(efa_ni, &srcnid, &dstnid,
					  kefalnd_get_probe_from_msg(msg),
					  proto_ver);
		break;

	case EFALND_MSG_CONN_PROBE_RESP:
		kefalnd_handle_conn_probe_resp(efa_ni, &srcnid, &dstnid,
					       kefalnd_get_probe_resp_from_msg(msg),
					       kefalnd_get_payload_size_from_msg(msg));
		break;

	case EFALND_MSG_CONN_REQ:
		kefalnd_handle_conn_req(efa_ni, &srcnid, &dstnid,
					kefalnd_get_conn_req_from_msg(msg),
					proto_ver);
		break;

	case EFALND_MSG_CONN_REQ_ACK:
		kefalnd_handle_conn_req_ack(efa_ni, &srcnid, &dstnid,
					    kefalnd_get_conn_req_ack_from_msg(msg));
		break;
	}
}

static void
kefalnd_cleanup_conn_txs(struct kefa_conn *conn, struct list_head *cancel_tx)
{
	int timeout = lnet_get_lnd_timeout();
	time64_t now = ktime_get_seconds();
	struct kefa_tx *tx, *temp_tx;
	unsigned long flags;

	spin_lock_irqsave(&conn->lock, flags);

	/* Tail of the list holds LRU elements */
	list_for_each_entry_safe(tx, temp_tx, &conn->active_tx, list_node) {
		time64_t tx_send_time = atomic64_read(&tx->send_time);

		if (tx_send_time == 0 || now < tx_send_time + timeout)
			break;

		/* We must call abort TX after increasing the refcount to
		 * prevent calling TX done which can lead to deadlock.
		 * Also we abort the Tx only if its refcount is not already 0
		 * which means its completion is in progress.
		 */
		if (atomic_inc_not_zero(&tx->ref_cnt)) {
			kefalnd_abort_tx(tx, LNET_MSG_STATUS_NETWORK_TIMEOUT,
					 -ETIMEDOUT);
			list_move_tail(&tx->list_node, &conn->abort_tx);
		}
	}

	list_splice_init(&conn->pend_tx, cancel_tx);

	spin_unlock_irqrestore(&conn->lock, flags);
}

static void
kefalnd_cleanup_ni_conns(struct kefa_ni *efa_ni)
{
	struct kefa_conn *removed_conn[MAX_IDLE_CONN] = { 0 };
	struct kefa_conn *idle_conn[MAX_IDLE_CONN] = { 0 };
	int init_timeout, resp_timeout, timeout, bkt, i = 0;
	struct kefa_tx *tx, *temp_tx;
	struct list_head cancel_tx;
	struct kefa_conn *conn;
	unsigned long flags;
	int num_removed = 0;
	int num_idle = 0;
	time64_t now;

	now = ktime_get_seconds();
	INIT_LIST_HEAD(&cancel_tx);
	init_timeout = efa_ni->lnet_ni->ni_net->net_tunables.lct_peer_timeout;
	resp_timeout = init_timeout + RESP_CONN_EXTRA_TIME;

	/* This assumes only a single thread can validate the NI connections at
	 * a time.
	 */
	read_lock_irqsave(&efa_ni->conn_lock, flags);
	hash_for_each(efa_ni->conns, bkt, conn, ni_node) {
		timeout = conn->type == KEFA_CONN_TYPE_INITIATOR ?
						init_timeout : resp_timeout;
		if (now > conn->last_use_time + timeout ||
		    conn->state == KEFA_CONN_DEACTIVATING) {
			idle_conn[num_idle] = conn;
			if (++num_idle == MAX_IDLE_CONN)
				break;
		}
	}

	read_unlock_irqrestore(&efa_ni->conn_lock, flags);

	/* No idle connections */
	if (num_idle == 0)
		return;

	write_lock_irqsave(&efa_ni->conn_lock, flags);
	for (i = 0; i < num_idle; i++) {
		conn = idle_conn[i];
		/* Validate last used under write lock to make sure no TX is
		 * racing with the daemon.
		 */
		timeout = conn->type == KEFA_CONN_TYPE_INITIATOR ?
				init_timeout : resp_timeout;

		if (now > conn->last_use_time + timeout)
			kefalnd_deactivate_conn_locked(conn);

		if (conn->state == KEFA_CONN_DEACTIVATING)
			kefalnd_cleanup_conn_txs(conn, &cancel_tx);

		if (now > conn->last_use_time + timeout &&
		    list_empty(&conn->active_tx) &&
		    list_empty(&conn->abort_tx)) {
			kefalnd_remove_conn_locked(conn);
			removed_conn[num_removed] = conn;
			num_removed++;
		}
	}

	write_unlock_irqrestore(&efa_ni->conn_lock, flags);

	for (i = 0; i < num_idle; i++) {
		conn = idle_conn[i];
		list_for_each_entry_safe(tx, temp_tx, &conn->abort_tx, list_node) {
			/* We only complete the TX when the only refcount is by
			 * the CM.
			 */
			if (atomic_read(&tx->ref_cnt) == 1) {
				atomic_dec(&tx->ref_cnt);
				kefalnd_tx_done(tx);
			}
		}

		list_for_each_entry_safe(tx, temp_tx, &cancel_tx, list_node)
			kefalnd_force_cancel_tx(tx,
						LNET_MSG_STATUS_LOCAL_ABORTED,
						-ETIMEDOUT);
	}

	for (i = 0; i < num_removed; i++)
		kefalnd_destroy_conn(removed_conn[i],
				     LNET_MSG_STATUS_LOCAL_ABORTED,
				     -ESHUTDOWN);
}

int
kefalnd_cm_daemon(void *arg)
{
	struct kefa_cm_deamon *cm_daemon;
	wait_queue_entry_t wait;
	struct kefa_ni *efa_ni;
	long id = (long)arg;
	int rc;

	cm_daemon = kefalnd.cm_daemons[KEFA_THREAD_CPT(id)];

	rc = cfs_cpt_bind(lnet_cpt_table(), cm_daemon->cpt);
	if (rc != 0)
		CWARN("failed to bind connection daemon thread to CPU partition %d\n",
		      cm_daemon->cpt);

	init_wait(&wait);

	while (!kefalnd.shutdown) {
		mutex_lock(&cm_daemon->ni_list_lock);
		list_for_each_entry(efa_ni, &cm_daemon->efa_ni_list, cm_node) {
			if (cm_daemon->iter % 5 == 0)
				kefalnd_cleanup_ni_conns(efa_ni);
		}
		mutex_unlock(&cm_daemon->ni_list_lock);

		cm_daemon->iter++;
		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&cm_daemon->waitq, &wait);

		schedule_timeout(cfs_time_seconds(1));

		remove_wait_queue(&cm_daemon->waitq, &wait);
	}

	kefalnd_thread_stop();
	return 0;
}

void
kefalnd_add_ni_to_cm_daemon(struct kefa_ni *efa_ni)
{
	struct kefa_cm_deamon *cm_daemon;

	cm_daemon = kefalnd.cm_daemons[efa_ni->efa_dev->cpt];

	mutex_lock(&cm_daemon->ni_list_lock);
	list_add_tail(&efa_ni->cm_node, &cm_daemon->efa_ni_list);
	mutex_unlock(&cm_daemon->ni_list_lock);
}

void
kefalnd_del_ni_from_cm_daemon(struct kefa_ni *efa_ni)
{
	struct kefa_cm_deamon *cm_daemon;

	cm_daemon = kefalnd.cm_daemons[efa_ni->efa_dev->cpt];

	mutex_lock(&cm_daemon->ni_list_lock);
	list_del_init(&efa_ni->cm_node);
	mutex_unlock(&cm_daemon->ni_list_lock);
}
