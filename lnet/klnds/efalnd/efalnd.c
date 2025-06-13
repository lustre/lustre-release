// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2023-2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Yehuda Yitschak <yehuday@amazon.com>
 * Author: Yonatan Nachum <ynachum@amazon.com>
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dmapool.h>
#include <linux/ethtool.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/pci.h>
#include <linux/random.h>
#include <linux/smp.h>

#include <rdma/ib_verbs.h>

#include "kcompat.h"
#include "efalnd.h"

static const struct lnet_lnd the_efalnd;
struct kefa_data kefalnd;

#ifndef DRV_MODULE_VERSION
#define DRV_MODULE_VERSION \
	__stringify(EFALND_MAJOR_VER) "."   \
	__stringify(EFALND_MINOR_VER) "."   \
	__stringify(EFALND_SUBMINOR_VER)
#endif

#define MAX_CQE_BATCH	16
#define SQ_DEPTH	4096
#define RQ_DEPTH	4096
#define CQ_DEPTH	(SQ_DEPTH + RQ_DEPTH)

#define kefalnd_thread_start(fn, data, namefmt, arg...)			\
	({								\
		struct task_struct *__task = kthread_run(fn, data, namefmt, ##arg); \
		if (!IS_ERR(__task))					\
			atomic_inc(&kefalnd.nthreads);			\
		PTR_ERR_OR_ZERO(__task);				\
	})

static char *
kefalnd_msgtype2str(int type)
{
	static char *msg_name[EFALND_MSG_MAX] = {
		[EFALND_MSG_RESERVED] = "RESERVED",
		[EFALND_MSG_CONN_PROBE] = "CONN_PROBE",
		[EFALND_MSG_CONN_PROBE_RESP] = "CONN_PROBE_RESP",
		[EFALND_MSG_CONN_REQ] = "CONN_REQ",
		[EFALND_MSG_CONN_REQ_ACK] = "CONN_REQ_ACK",
		[EFALND_MSG_IMMEDIATE] = "IMMEDIATE",
		[EFALND_MSG_NACK] = "NACK",
		[EFALND_MSG_PUTR_REQ] = "PUTR_REQ",
		[EFALND_MSG_PUTR_DONE] = "PUTR_DONE",
		[EFALND_MSG_GETR_REQ] = "GETR_REQ",
		[EFALND_MSG_GETR_ACK] = "GETR_ACK",
		[EFALND_MSG_GETR_DONE] = "GETR_DONE",
	};

	if (type >= EFALND_MSG_MAX)
		return "UKNOWN";

	return msg_name[type];
}

int
kefalnd_msgtype2size(int type, u8 proto_ver)
{
	int hdr_size_v2 = offsetof(struct kefa_msg, msg_v2.u);
	int hdr_size_v1 = offsetof(struct kefa_msg, msg_v1.u);

	switch (type) {
	case EFALND_MSG_IMMEDIATE:
		return offsetof(struct kefa_msg, msg_v2.u.immediate.payload[0]);

	case EFALND_MSG_PUTR_REQ:
		return hdr_size_v2 + sizeof(struct kefa_putr_req_msg_v2);

	case EFALND_MSG_GETR_REQ:
		return hdr_size_v2 + sizeof(struct kefa_getr_req_msg_v2);

	case EFALND_MSG_NACK:
	case EFALND_MSG_PUTR_DONE:
	case EFALND_MSG_GETR_DONE:
		return hdr_size_v2 + sizeof(struct kefa_completion_msg);

	case EFALND_MSG_GETR_ACK:
		return hdr_size_v2 + sizeof(struct kefa_getr_ack_msg);

	case EFALND_MSG_CONN_PROBE:
		if (proto_ver == EFALND_PROTO_VER_1)
			return hdr_size_v1 + sizeof(struct kefa_conn_probe_msg);

		return hdr_size_v2 + sizeof(struct kefa_conn_probe_msg);

	case EFALND_MSG_CONN_PROBE_RESP:
		if (proto_ver == EFALND_PROTO_VER_1)
			return hdr_size_v1 + sizeof(struct kefa_conn_probe_resp_msg);

		return hdr_size_v2 + sizeof(struct kefa_conn_probe_resp_msg);

	case EFALND_MSG_CONN_REQ:
		return offsetof(struct kefa_msg,
				msg_v2.u.conn_request.data_qps[0]);

	case EFALND_MSG_CONN_REQ_ACK:
		return offsetof(struct kefa_msg,
				msg_v2.u.conn_request_ack.data_qps[0]);

	default:
		return -1;
	}
}

int
kefalnd_efa_status_to_errno(s16 efa_status)
{
	switch (efa_status) {
	case KEFA_COMP_STATUS_OK:
		return 0;

	case KEFA_COMP_STATUS_UNSUPPORTED_OP:
		return -EOPNOTSUPP;

	case KEFA_COMP_STATUS_NO_MEMORY:
		return -ENOMEM;

	case KEFA_COMP_STATUS_COMM_FAILURE:
		return -ECOMM;

	case KEFA_COMP_STATUS_NO_LNET_MSG:
		return -ENODATA;

	case KEFA_COMP_STATUS_BAD_ADDRESS:
		return -EFAULT;

	case KEFA_COMP_STATUS_UNSUPPORTED_PROTO:
		return -EPROTONOSUPPORT;

	case KEFA_COMP_STATUS_DMA_FAILURE:
	case KEFA_COMP_STATUS_GENERAL_ERROR:
	default:
		return -EREMOTEIO;
	}
}

s16
kefalnd_errno_to_efa_status(int status)
{
	switch (status) {
	case 0:
		return KEFA_COMP_STATUS_OK;

	case -EOPNOTSUPP:
		return KEFA_COMP_STATUS_UNSUPPORTED_OP;

	case -ENOMEM:
		return KEFA_COMP_STATUS_NO_MEMORY;

	case -ECOMM:
		return KEFA_COMP_STATUS_COMM_FAILURE;

	case -ENODATA:
		return KEFA_COMP_STATUS_NO_LNET_MSG;

	case -EFAULT:
		return KEFA_COMP_STATUS_BAD_ADDRESS;

	case -EPROTONOSUPPORT:
		return KEFA_COMP_STATUS_UNSUPPORTED_PROTO;

	case -EIO:
		return KEFA_COMP_STATUS_DMA_FAILURE;

	case -EINVAL:
	default:
		return KEFA_COMP_STATUS_GENERAL_ERROR;
	}
}

static unsigned int
kefalnd_get_dev_prio(struct lnet_ni *ni, unsigned int dev_idx)
{
	struct kefa_ni *efa_ni = ni->ni_data;
	struct device *dev = NULL;

	if (efa_ni)
		dev = efa_ni->efa_dev->ib_dev->dma_device;

	return lnet_get_dev_prio(dev, dev_idx);
}

static inline int kefalnd_dma_map_sg(struct kefa_dev *efa_dev,
				     struct scatterlist *sg, int nents,
				     enum dma_data_direction direction)
{
	int count;

	count = lnet_rdma_map_sg_attrs(efa_dev->ib_dev->dma_device,
				       sg, nents, direction);

	if (count != 0)
		return count;

	count = ib_dma_map_sg(efa_dev->ib_dev, sg, nents, direction);
	return count ?: -EIO;
}

static inline void kefalnd_dma_unmap_sg(struct kefa_dev *efa_dev,
					struct scatterlist *sg, int nents,
					enum dma_data_direction direction)
{
	int count;

	count = lnet_rdma_unmap_sg(efa_dev->ib_dev->dma_device,
				   sg, nents, direction);
	if (count != 0)
		return;

	ib_dma_unmap_sg(efa_dev->ib_dev, sg, nents, direction);
}

void
kefalnd_get_srcnid_from_msg(struct kefa_msg *msg, struct lnet_nid *srcnid)
{
	if (msg->hdr.proto_ver != EFALND_PROTO_VER_1)
		*srcnid = msg->msg_v2.srcnid;
	else
		lnet_nid4_to_nid(msg->msg_v1.srcnid, srcnid);
}

void
kefalnd_get_dstnid_from_msg(struct kefa_msg *msg, struct lnet_nid *dstnid)
{
	if (msg->hdr.proto_ver != EFALND_PROTO_VER_1)
		*dstnid = msg->msg_v2.dstnid;
	else
		lnet_nid4_to_nid(msg->msg_v1.dstnid, dstnid);
}

static inline struct kefa_getr_ack_msg *
kefalnd_get_getr_ack_from_msg(struct kefa_msg *msg)
{
	return &msg->msg_v2.u.getr_ack;
}

static inline struct kefa_completion_msg *
kefalnd_get_completion_from_msg(struct kefa_msg *msg)
{
	return &msg->msg_v2.u.completion;
}

static int
kefalnd_obj_pool_init(struct kefa_ni *efa_ni, struct kefa_obj_pool *pool,
		      u32 pool_size, int cpt, size_t obj_size)
{
	pool->efa_ni = efa_ni;
	pool->pool_size = pool_size;
	pool->cpt = cpt;
	atomic_set(&pool->pending_work, false);
	spin_lock_init(&pool->lock);
	INIT_LIST_HEAD(&pool->free_obj);
	INIT_LIST_HEAD(&pool->free_pend_obj);

	LIBCFS_CPT_ALLOC(pool->obj_arr, lnet_cpt_table(),
			 cpt, pool_size * obj_size);
	if (!pool->obj_arr)
		return -ENOMEM;

	return 0;
}

static void
kefalnd_obj_pool_free(struct kefa_obj_pool *pool, struct list_head *node)
{
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	list_add_tail(node, &pool->free_obj);
	spin_unlock_irqrestore(&pool->lock, flags);
}

static void
kefalnd_obj_pool_put_on_pend_list(struct kefa_obj_pool *pool,
				  struct list_head *node)
{
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	list_add_tail(node, &pool->free_pend_obj);
	atomic_set(&pool->pending_work, true);
	spin_unlock_irqrestore(&pool->lock, flags);
}

static struct list_head *
kefalnd_obj_pool_alloc(struct kefa_obj_pool *pool)
{
	unsigned long flags;
	struct list_head *node;

	spin_lock_irqsave(&pool->lock, flags);

	if (list_empty(&pool->free_obj)) {
		spin_unlock_irqrestore(&pool->lock, flags);
		return NULL;
	}

	/* Get first object from the list. */
	node = pool->free_obj.next;
	list_del_init(node);

	spin_unlock_irqrestore(&pool->lock, flags);
	return node;
}

static inline struct kefa_fmr *
kefalnd_fmr_pool_alloc(struct kefa_obj_pool *fmr_pool)
{
	struct list_head *node;

	node = kefalnd_obj_pool_alloc(fmr_pool);
	return node ? list_entry(node, struct kefa_fmr, list_node) : NULL;
}

static struct kefa_fmr *
kefalnd_get_idle_fmr(struct kefa_ni *efa_ni)
{
	struct kefa_obj_pool *fmr_pool = &efa_ni->efa_dev->fmr_pool;
	struct kefa_fmr *fmr;

	fmr = kefalnd_fmr_pool_alloc(fmr_pool);
	if (!fmr)
		return NULL;

	LASSERT(fmr->state == KEFA_FMR_INACTIVE);

	return fmr;
}

static inline struct kefa_tx *
kefalnd_tx_pool_alloc(struct kefa_obj_pool *tx_pool)
{
	struct list_head *node;

	node = kefalnd_obj_pool_alloc(tx_pool);
	return node ? list_entry(node, struct kefa_tx, list_node) : NULL;
}

struct kefa_tx *
kefalnd_get_idle_tx(struct kefa_ni *efa_ni)
{
	struct kefa_obj_pool *tx_pool = &efa_ni->tx_pool;
	struct kefa_tx *tx;

	tx = kefalnd_tx_pool_alloc(tx_pool);
	if (!tx)
		return NULL;

	LASSERT(!tx->conn);
	LASSERT(!tx->lntmsg[0]);
	LASSERT(!tx->lntmsg[1]);

	tx->hstatus = LNET_MSG_STATUS_OK;
	tx->status = 0;

	return tx;
}

static inline u64
kefalnd_tx_to_idx(struct kefa_tx *tx)
{
	return tx - (struct kefa_tx *)tx->tx_pool->obj_arr;
}

static inline struct kefa_tx *
kefalnd_get_tx_by_idx(struct kefa_ni *efa_ni, u64 tx_idx)
{
	struct kefa_obj_pool *tx_pool = &efa_ni->tx_pool;

	if (tx_idx >= tx_pool->pool_size) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "received out of range TX[%llu] max[%u]\n",
			    tx_idx, tx_pool->pool_size);
		return NULL;
	}

	return (struct kefa_tx *)tx_pool->obj_arr + tx_idx;
}

static inline void
kefalnd_init_tx_protocol_sge(struct kefa_tx *tx, u32 lkey, u64 addr,
			     unsigned int len)
{
	struct ib_sge *sge = &tx->sge;

	*sge = (struct ib_sge) {
		.lkey	= lkey,
		.addr	= addr,
		.length = len,
	};
}

static int
kefalnd_init_msg(struct kefa_msg *msg, struct kefa_conn *conn, u8 proto_ver,
		 int type, int body_nob)
{
	struct kefa_hdr *hdr = &msg->hdr;
	struct kefa_msg_v1 *msg_v1;
	struct kefa_msg_v2 *msg_v2;
	int nob;

	hdr->magic = EFALND_MSG_MAGIC;
	hdr->proto_ver = proto_ver;
	hdr->type = type;

	if (proto_ver == EFALND_PROTO_VER_1) {
		msg_v1 = &msg->msg_v1;
		nob = offsetof(struct kefa_msg, msg_v1.u) + body_nob;
		LASSERT(nob <= EFALND_MSG_SIZE);
		hdr->nob = nob;

		msg_v1->srcnid = lnet_nid_to_nid4(&conn->local_nid);
		msg_v1->dstnid = lnet_nid_to_nid4(&conn->remote_nid);
		msg_v1->credits = 0;
		msg_v1->dst_conn_id = EFALND_INV_CONN;
	} else {
		msg_v2 = &msg->msg_v2;
		nob = offsetof(struct kefa_msg, msg_v2.u) + body_nob;
		LASSERT(nob <= EFALND_MSG_SIZE);
		hdr->nob = nob;

		msg_v2->srcnid = conn->local_nid;
		msg_v2->dstnid = conn->remote_nid;
		msg_v2->credits = 0;
		msg_v2->dst_conn_id = EFALND_INV_CONN;
	}

	return nob;
}

void
kefalnd_init_tx_protocol_msg(struct kefa_tx *tx, struct kefa_conn *conn,
			     int type, int body_nob, u8 proto_ver)
{
	struct ib_srd_rdma_wr *wrq;
	int total_nob;

	total_nob = kefalnd_init_msg(tx->msg, conn, proto_ver, type, body_nob);
	tx->type = type;

	wrq = &tx->wrq;
	*wrq = (struct ib_srd_rdma_wr) {
		.wr.wr = {
			.wr_id		= (u64)tx,
			.num_sge	= 1,
			.sg_list	= &tx->sge,
			.opcode		= IB_WR_SEND,
			.send_flags	= IB_SEND_SIGNALED,
			.next		= NULL,
		},
	};

	kefalnd_init_tx_protocol_sge(tx, tx->lkey, tx->msgaddr, total_nob);
}

static struct kefa_remote_qp *
kefalnd_conn_get_remote_qp(struct kefa_conn *conn)
{
	int remote_qpn = atomic_inc_return_relaxed(&conn->last_qp_idx);

	return conn->data_qps + ((u32)remote_qpn % conn->nqps);
}

static void
kefalnd_set_tx_remote_data(struct kefa_conn *conn, struct kefa_tx *tx)
{
	struct kefa_remote_qp *qp = kefalnd_conn_get_remote_qp(conn);
	struct ib_srd_wr *srd_wr;

	srd_wr = &tx->wrq.wr;
	srd_wr->ah = conn->ah;
	srd_wr->remote_qpn = qp->qp_num;
	srd_wr->remote_qkey = qp->qkey;
}

static inline struct kefa_qp *
kefalnd_device_get_qp(struct kefa_dev *efa_dev)
{
	int local_qpn = atomic_inc_return_relaxed(&efa_dev->local_qpn);

	return efa_dev->qps + (local_qpn % efa_dev->nqps);
}

void
kefalnd_conn_post_tx_locked(struct kefa_conn *conn)
__must_hold(&conn->lock)
{
	struct ib_send_wr *bad = NULL;
	struct kefa_tx *tx, *temp_tx;
	struct ib_send_wr *wr;
	struct kefa_qp *qp;
	time64_t now;
	int rc;

	qp = kefalnd_device_get_qp(conn->efa_ni->efa_dev);
	now = ktime_get_seconds();

	list_for_each_entry_safe(tx, temp_tx, &conn->pend_tx, list_node) {
		if (tx->fmr && tx->fmr->state == KEFA_FMR_ACTIVATING) {
			wr = &tx->fmr->reg_wr.wr;
		} else {
			wr = &tx->wrq.wr.wr;
			kefalnd_set_tx_remote_data(conn, tx);
			kefalnd_msg_set_epoch(tx->msg, conn->remote_epoch);
		}

		atomic64_set(&tx->send_time, now);
		atomic_inc(&tx->ref_cnt);
		list_move_tail(&tx->list_node, &conn->active_tx);
		rc = ib_post_send(qp->ib_qp, wr,
				  (const struct ib_send_wr **)&bad);
		if (rc) {
			if (rc != -ENOMEM) {
				/* We don't expect anything other than -ENOMEM here. */
				EFA_DEV_WARN(qp->efa_dev,
					     "QP[%u] failed to post send. err[%d]\n",
					     qp->ib_qp->qp_num, rc);
			}

			atomic64_set(&tx->send_time, 0);
			atomic_dec(&tx->ref_cnt);
			list_move(&tx->list_node, &conn->pend_tx);

			/* TODO - TX might stay stuck on connection.
			 * Need to trigger kefalnd_conn_post_tx_locked() from
			 * other context.
			 */
			break;
		}
	}
}

static void
kefalnd_launch_tx(struct kefa_conn *conn, struct kefa_tx *tx)
{
	unsigned long flags;

	spin_lock_irqsave(&conn->lock, flags);
	if (!list_empty(&tx->list_node))
		list_del_init(&tx->list_node);

	list_add_tail(&tx->list_node, &conn->pend_tx);

	tx->conn = conn;

	/* TODO - consider all pending connections. i.e. connection arbitration */
	if (conn->state == KEFA_CONN_ACTIVE)
		kefalnd_conn_post_tx_locked(conn);
	spin_unlock_irqrestore(&conn->lock, flags);
}

static inline void
kefalnd_post_finv_failure(struct kefa_dev *efa_dev, struct kefa_qp *qp,
			  struct kefa_fmr *fmr, int rc)
{
	if (rc != -ENOMEM) {
		/* We don't expect anything other than -ENOMEM here. */
		EFA_DEV_WARN(efa_dev,
			     "QP[%u] failed to post FINV[0x%x]. err[%d]\n",
			     qp->ib_qp->qp_num, fmr->mr->lkey, rc);
	}
}

static void
kefalnd_launch_pending_finvs(struct kefa_dev *efa_dev)
{
	struct kefa_obj_pool *fmr_pool = &efa_dev->fmr_pool;
	struct kefa_fmr *fmr, *temp_fmr;
	struct ib_send_wr *wr;
	unsigned long flags;
	struct kefa_qp *qp;
	int rc;

	spin_lock_irqsave(&fmr_pool->lock, flags);
	list_for_each_entry_safe(fmr, temp_fmr, &fmr_pool->free_pend_obj, list_node) {
		wr = &fmr->inv_wr;
		qp = kefalnd_device_get_qp(efa_dev);
		list_del_init(&fmr->list_node);
		rc = ib_post_send(qp->ib_qp, wr, NULL);
		if (rc) {
			kefalnd_post_finv_failure(efa_dev, qp, fmr, rc);
			list_add(&fmr->list_node, &fmr_pool->free_pend_obj);
			break;
		}
	}

	if (list_empty(&fmr_pool->free_pend_obj))
		atomic_set(&fmr_pool->pending_work, false);

	spin_unlock_irqrestore(&fmr_pool->lock, flags);
}

static void
kefalnd_launch_finv(struct kefa_dev *efa_dev, struct kefa_fmr *fmr)
{
	struct ib_send_wr *wr;
	struct kefa_qp *qp;
	int rc;

	wr = &fmr->inv_wr;
	qp = kefalnd_device_get_qp(efa_dev);
	rc = ib_post_send(qp->ib_qp, wr, NULL);
	if (rc) {
		kefalnd_post_finv_failure(efa_dev, qp, fmr, rc);
		kefalnd_obj_pool_put_on_pend_list(&efa_dev->fmr_pool,
						  &fmr->list_node);
	}

	if (atomic_read(&efa_dev->fmr_pool.pending_work))
		kefalnd_launch_pending_finvs(efa_dev);
}

static void
kefalnd_unmap_tx(struct kefa_tx *tx)
{
	struct kefa_dev *efa_dev = tx->tx_pool->efa_ni->efa_dev;
	struct kefa_fmr *fmr;

	if (tx->fmr) {
		fmr = tx->fmr;
		if (fmr->state == KEFA_FMR_ACTIVE) {
			fmr->state = KEFA_FMR_DEACTIVATING;
			kefalnd_launch_finv(efa_dev, fmr);
		} else {
			fmr->state = KEFA_FMR_INACTIVE;
			kefalnd_obj_pool_free(&efa_dev->fmr_pool,
					      &fmr->list_node);
		}

		tx->fmr = NULL;
	}

	if (tx->nfrags) {
		kefalnd_dma_unmap_sg(efa_dev, tx->frags, tx->nfrags,
				     tx->dmadir);
		tx->nfrags = 0;
	}
}

static int
kefalnd_map_tx(struct kefa_ni *efa_ni, struct kefa_tx *tx,
	       bool remote_access_fmr)
{
	struct kefa_dev *efa_dev = efa_ni->efa_dev;
	struct kefa_rdma_desc *rd = &tx->rdma_desc;
	int i, sg_nsegs, fmr_nsegs;
	struct ib_send_wr *inv_wr;
	struct ib_reg_wr *reg_wr;
	u32 nob;

	tx->dmadir = remote_access_fmr ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	sg_nsegs = kefalnd_dma_map_sg(efa_dev, tx->frags, tx->nfrags, tx->dmadir);
	if (unlikely(sg_nsegs < 0)) {
		EFA_DEV_ERR(efa_dev, "Failed to DMA map TX, err %d\n", sg_nsegs);
		return sg_nsegs;
	}

	for (i = 0, nob = 0; i < sg_nsegs; i++)
		nob += sg_dma_len(&tx->frags[i]);

	tx->fmr = kefalnd_get_idle_fmr(efa_ni);
	if (!tx->fmr)
		return -ENOMEM;

	fmr_nsegs = ib_map_mr_sg(tx->fmr->mr, tx->frags, tx->nfrags, 0,
				 PAGE_SIZE);
	if (unlikely(fmr_nsegs != sg_nsegs)) {
		EFA_DEV_ERR(efa_dev, "Failed to map MR, %d/%d elements\n",
			    fmr_nsegs, sg_nsegs);
		return fmr_nsegs < 0 ? fmr_nsegs : -EIO;
	}

	efa_inc_fast_reg_key_gen(tx->fmr->mr);
	tx->fmr->state = KEFA_FMR_ACTIVATING;

	reg_wr = &tx->fmr->reg_wr;
	memset(reg_wr, 0, sizeof(*reg_wr));
	reg_wr->wr.opcode = IB_WR_REG_MR;
	reg_wr->wr.wr_id  = (u64)tx;
	reg_wr->wr.num_sge = 0;
	reg_wr->wr.send_flags = 0;
	reg_wr->mr = tx->fmr->mr;
	reg_wr->key = tx->fmr->mr->lkey;
	reg_wr->access = IB_ACCESS_LOCAL_WRITE;
	if (remote_access_fmr)
		reg_wr->access |= IB_ACCESS_REMOTE_READ;

	inv_wr = &tx->fmr->inv_wr;
	memset(inv_wr, 0, sizeof(*inv_wr));
	inv_wr->opcode = IB_WR_LOCAL_INV;
	inv_wr->wr_id  = (u64)tx->fmr;
	inv_wr->ex.invalidate_rkey = tx->fmr->mr->lkey;

	rd->nob = nob;
	rd->addr = sg_dma_address(&tx->frags[0]);
	rd->key = remote_access_fmr ? tx->fmr->mr->rkey : tx->fmr->mr->lkey;

	return 0;
}

static int
kefalnd_bio_vec_to_sgl(struct kefa_ni *efa_ni, struct scatterlist *sg,
		       struct bio_vec *kiov, int nkiov, int offset, int nob)
{
	int fragnob, max_nkiov, sg_count = 0;

	LASSERT(nob > 0);
	LASSERT(nkiov > 0);

	/* Trasnalate from bio_vec to sg to use for mapping */
	while (offset >= kiov->bv_len) {
		offset -= kiov->bv_len;
		nkiov--;
		kiov++;
		LASSERT(nkiov > 0);
	}

	max_nkiov = nkiov;
	do {
		LASSERT(nkiov > 0);

		if (!sg) {
			EFA_DEV_ERR(efa_ni->efa_dev,
				    "lacking enough sg entries to map TX\n");
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
			CDEBUG(D_NET,
			       "fragnob %d < available page %d: with remaining %d kiovs with %d nob left\n",
			       fragnob, (int)(kiov->bv_len - offset), nkiov, nob);

			EFA_DEV_ERR(efa_ni->efa_dev, "no gaps support\n");
			return -EINVAL;
		}

		sg_set_page(sg, kiov->bv_page, fragnob,
			    kiov->bv_offset + offset);
		sg = sg_next(sg);

		offset = 0;
		kiov++;
		nkiov--;
		nob -= fragnob;
	} while (nob > 0);

	return sg_count;
}

static int
kefalnd_map_msg_iov(struct kefa_ni *efa_ni, struct kefa_tx *tx, int nkiov,
		    struct bio_vec *kiov, int offset, int nob,
		    bool remote_access_fmr)
{
	int rc;

	rc = kefalnd_bio_vec_to_sgl(efa_ni, tx->frags, kiov, nkiov,
				    offset, nob);
	if (rc < 0)
		goto out;

	tx->nfrags = rc;

	/* Map the SGs to our device */
	rc = kefalnd_map_tx(efa_ni, tx, remote_access_fmr);

out:
	if (rc != 0)
		tx->hstatus = LNET_MSG_STATUS_LOCAL_ERROR;

	return rc;
}

static void
kefalnd_init_comp_message(struct kefa_conn *conn, struct kefa_tx *tx, int type,
			  int status, u64 cookie)
{
	struct kefa_completion_msg *completion;

	kefalnd_init_tx_protocol_msg(tx, conn, type,
				     sizeof(struct kefa_completion_msg),
				     conn->proto_ver);

	completion = kefalnd_get_completion_from_msg(tx->msg);
	completion->cookie = cookie;
	completion->status = kefalnd_errno_to_efa_status(status);
}

static inline void
kefalnd_set_sync_data(struct kefa_tx *tx, u64 cookie)
{
	tx->send_sync = true;
	tx->cookie = cookie;
}

static void
kefalnd_send_sync_msg(struct kefa_tx *tx)
{
	LASSERT(tx->type == EFALND_MSG_PUTR_DONE ||
		tx->type == EFALND_MSG_GETR_DONE);

	CDEBUG(D_NET, "Sending last ctrl for TX type[%s] from[%s] to[%s]\n",
	       kefalnd_msgtype2str(tx->type),
	       libcfs_nidstr(&tx->conn->local_nid),
	       libcfs_nidstr(&tx->conn->remote_nid));

	tx->send_sync = false;
	kefalnd_init_comp_message(tx->conn, tx, tx->type, tx->status,
				  tx->cookie);
	kefalnd_launch_tx(tx->conn, tx);
}

void
kefalnd_tx_done(struct kefa_tx *tx)
{
	unsigned long flags;
	int i;

	/* Send last control message once all RDMAs completed.
	 * re-use the connection and message types set during RDMA submit
	 */
	if (tx->send_sync) {
		kefalnd_send_sync_msg(tx);
		return;
	}

	if (tx->conn) {
		spin_lock_irqsave(&tx->conn->lock, flags);
		if (!list_empty(&tx->list_node))
			list_del_init(&tx->list_node);

		spin_unlock_irqrestore(&tx->conn->lock, flags);
	}

	CDEBUG(D_NET, "Completed TX type[%s] from[%s] to[%s]\n",
	       kefalnd_msgtype2str(tx->type),
	       tx->conn ? libcfs_nidstr(&tx->conn->local_nid) : "NA",
	       tx->conn ? libcfs_nidstr(&tx->conn->remote_nid) : "NA");

	LASSERT(atomic_read(&tx->ref_cnt) == 0);
	LASSERT(list_empty(&tx->list_node));
	atomic64_set(&tx->send_time, 0);
	kefalnd_unmap_tx(tx);

	for (i = 0; i < 2; i++) {
		if (tx->lntmsg[i] == NULL)
			continue;

		/* propagate health status to LNet for requests */
		if (i == 0 && tx->lntmsg[i])
			tx->lntmsg[i]->msg_health_status = tx->hstatus;

		CDEBUG(D_NET, "Finalizing TX type[%s] from[%s] to[%s]\n",
		       kefalnd_msgtype2str(tx->type),
		       tx->conn ? libcfs_nidstr(&tx->conn->local_nid) : "NA",
		       tx->conn ? libcfs_nidstr(&tx->conn->remote_nid) : "NA");

		lnet_finalize(tx->lntmsg[i], tx->status);
		tx->lntmsg[i] = NULL;
	}

	tx->hstatus = LNET_MSG_STATUS_OK;
	tx->conn = NULL;
	tx->dmadir = DMA_BIDIRECTIONAL;
	tx->type = 0;

	kefalnd_obj_pool_free(tx->tx_pool, &tx->list_node);
}

void
kefalnd_abort_tx(struct kefa_tx *tx, enum lnet_msg_hstatus hstatus, int status)
{
	EFA_DEV_WARN(tx->conn->efa_ni->efa_dev,
		     "aborting TX type[%s] to peer NI[%s]\n",
		     kefalnd_msgtype2str(tx->type),
		     libcfs_nidstr(&tx->conn->remote_nid));

	tx->send_sync = false;
	tx->hstatus = hstatus;
	tx->status = status;

	/* Make sure response message refcount decreased only once */
	if (!atomic_xchg_relaxed(&tx->waiting_resp, false))
		return;

	if (atomic_dec_and_test(&tx->ref_cnt))
		kefalnd_tx_done(tx);
}

void
kefalnd_force_cancel_tx(struct kefa_tx *tx, enum lnet_msg_hstatus hstatus,
			int status)
{
	EFA_DEV_WARN(tx->conn->efa_ni->efa_dev,
		     "canceling TX type[%s] to peer NI[%s]\n",
		     kefalnd_msgtype2str(tx->type),
		     libcfs_nidstr(&tx->conn->remote_nid));

	tx->send_sync = false;
	tx->hstatus = hstatus;
	tx->status = status;

	atomic_set(&tx->waiting_resp, false);
	atomic_set(&tx->ref_cnt, 0);

	kefalnd_tx_done(tx);
}

static void
kefalnd_send_completion(struct kefa_ni *efa_ni, struct kefa_conn *conn,
			int type, int status, u64 cookie)
{
	struct kefa_tx *tx;

	tx = kefalnd_get_idle_tx(efa_ni);
	if (tx == NULL) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "can't allocate %s completion TX to peer NI[%s]\n",
			    kefalnd_msgtype2str(type),
			    libcfs_nidstr(&conn->remote_nid));

		return;
	}

	kefalnd_init_comp_message(conn, tx, type, status, cookie);

	kefalnd_launch_tx(conn, tx);
}

static inline void
kefalnd_fill_getr_msg(struct kefa_conn *conn, struct kefa_tx *tx,
		      struct lnet_hdr *hdr)
{
	struct kefa_msg *msg = tx->msg;

	kefalnd_init_tx_protocol_msg(tx, conn, EFALND_MSG_GETR_REQ,
				     sizeof(struct kefa_getr_req_msg_v2),
				     conn->proto_ver);

	lnet_hdr_to_nid16(hdr, &msg->msg_v2.u.getr_req.hdr);
	msg->msg_v2.u.getr_req.sink_cookie = kefalnd_tx_to_idx(tx);
}

static inline void
kefalnd_fill_putr_msg(struct kefa_conn *conn, struct kefa_tx *tx,
		      struct lnet_hdr *hdr)
{
	struct kefa_msg *msg = tx->msg;

	kefalnd_init_tx_protocol_msg(tx, conn, EFALND_MSG_PUTR_REQ,
				     sizeof(struct kefa_putr_req_msg_v2),
				     conn->proto_ver);

	lnet_hdr_to_nid16(hdr, &msg->msg_v2.u.putr_req.hdr);
	msg->msg_v2.u.putr_req.cookie = kefalnd_tx_to_idx(tx);
	msg->msg_v2.u.putr_req.rdma_desc = tx->rdma_desc;
}

static inline void
kefalnd_fill_imm_msg(struct kefa_conn *conn, struct lnet_msg *lntmsg,
		     struct kefa_tx *tx, struct lnet_hdr *hdr)
{
	struct kefa_msg *msg = tx->msg;
	int body_nob;

	body_nob = offsetof(struct kefa_immediate_msg_v2,
			    payload[lntmsg->msg_len]);
	kefalnd_init_tx_protocol_msg(tx, conn, EFALND_MSG_IMMEDIATE, body_nob,
				     conn->proto_ver);
	lnet_hdr_to_nid16(hdr, &msg->msg_v2.u.immediate.hdr);
	lnet_copy_kiov2flat(EFALND_MSG_SIZE, msg,
			    offsetof(struct kefa_msg, msg_v2.u.immediate.payload),
			    lntmsg->msg_niov, lntmsg->msg_kiov,
			    lntmsg->msg_offset, lntmsg->msg_len);
}

static int
kefalnd_send(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg)
{
	struct lnet_processid *target = &lntmsg->msg_target;
	struct lnet_libmd *msg_md = lntmsg->msg_md;
	struct lnet_hdr *hdr = &lntmsg->msg_hdr;
	struct kefa_ni *efa_ni = ni->ni_data;
	int type = lntmsg->msg_type;
	struct kefa_conn *conn;
	struct kefa_tx *tx;
	int nob, rc;
	bool gpu;

	tx = kefalnd_get_idle_tx(efa_ni);
	if (tx == NULL) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "can't allocate %s TX to peer NI[%s]\n",
			    lnet_msgtyp2str(type), libcfs_nidstr(&target->nid));

		return -ENOMEM;
	}

	conn = kefalnd_lookup_or_init_conn(efa_ni, &target->nid,
					   KEFA_CONN_TYPE_INITIATOR);
	if (IS_ERR(conn)) {
		EFA_DEV_DEBUG(efa_ni->efa_dev,
			      "can't establish connection to peer NI[%s]\n",
			      libcfs_nidstr(&target->nid));
		tx->hstatus = LNET_MSG_STATUS_REMOTE_ERROR;
		kefalnd_tx_done(tx);
		return -ENOTCONN;
	}

	CDEBUG(D_NET, "Request to send LNet %s from %s to %s size[%u]\n",
	       lnet_msgtyp2str(type),
	       libcfs_nidstr(&ni->ni_nid),
	       libcfs_nidstr(&target->nid),
	       type == LNET_MSG_GET ? msg_md->md_length : lntmsg->msg_len);

	gpu = lnet_md_is_gpu(msg_md);

	switch (type) {
	default:
		LBUG();
		return (-EIO);

	case LNET_MSG_ACK:
		LASSERT(lntmsg->msg_len == 0);
		break;

	case LNET_MSG_GET:
		/* use RDMA or SEND based on size */
		nob = offsetof(struct kefa_msg, msg_v2.u.immediate.payload[msg_md->md_length]);
		if (nob <= EFALND_NO_RDMA_THRESH && !gpu)
			break;

		/* RDMA based flow */
		rc = kefalnd_map_msg_iov(efa_ni, tx, msg_md->md_niov,
					 msg_md->md_kiov, 0, msg_md->md_length,
					 false);
		if (rc != 0) {
			EFA_DEV_ERR(efa_ni->efa_dev,
				    "can't setup GET destination for peer NI[%s]. err[%d]\n",
				    libcfs_nidstr(&target->nid), rc);

			kefalnd_tx_done(tx);
			return -EIO;
		}

		/* setup the message */
		kefalnd_fill_getr_msg(conn, tx, hdr);
		tx->lntmsg[1] = lnet_create_reply_msg(ni, lntmsg);
		if (tx->lntmsg[1] == NULL) {
			EFA_DEV_ERR(efa_ni->efa_dev,
				    "can't create reply for GET for peer NI[%s]\n",
				    libcfs_nidstr(&target->nid));

			tx->hstatus = LNET_MSG_STATUS_LOCAL_ERROR;
			kefalnd_tx_done(tx);
			return -EIO;
		}

		/* finalise lntmsg[0,1] on completion */
		tx->lntmsg[0] = lntmsg;
		atomic_inc(&tx->ref_cnt); /* wait for GETR_{ACK,NACK} */
		atomic_set(&tx->waiting_resp, true);
		kefalnd_launch_tx(conn, tx);
		return 0;

	case LNET_MSG_REPLY:
	case LNET_MSG_PUT:
		/* use RDMA or SEND based on size */
		nob = offsetof(struct kefa_msg, msg_v2.u.immediate.payload[lntmsg->msg_len]);
		if (nob <= EFALND_NO_RDMA_THRESH && !gpu)
			break;

		/* RDMA based flow */
		rc = kefalnd_map_msg_iov(efa_ni, tx, lntmsg->msg_niov,
					 lntmsg->msg_kiov, lntmsg->msg_offset,
					 lntmsg->msg_len, true);
		if (rc != 0) {
			EFA_DEV_ERR(efa_ni->efa_dev,
				    "can't setup PUT src for peer NI[%s]. err[%d]\n",
				    libcfs_nidstr(&target->nid), rc);

			kefalnd_tx_done(tx);
			return -EIO;
		}

		/* setup the message */
		kefalnd_fill_putr_msg(conn, tx, hdr);
		/* finalise lntmsg[0,1] on completion */
		tx->lntmsg[0] = lntmsg;
		atomic_inc(&tx->ref_cnt); /* wait for PUT_DONE */
		atomic_set(&tx->waiting_resp, true);
		kefalnd_launch_tx(conn, tx);
		return 0;
	}

	/* SEND based (non-RDMA flow) */
	kefalnd_fill_imm_msg(conn, lntmsg, tx, hdr);

	/* finalise lntmsg on completion */
	tx->lntmsg[0] = lntmsg;

	kefalnd_launch_tx(conn, tx);

	return 0;
}

static void
kefalnd_init_tx_rdma_read(struct kefa_conn *conn, struct kefa_tx *tx, int type,
			  struct kefa_rdma_desc *src_rdma, u64 dstcookie)
{
	struct kefa_rdma_desc *sink_rdma = &tx->rdma_desc;
	struct ib_srd_rdma_wr *wrq;
	struct ib_send_wr *ib_wr;
	struct ib_sge *sge;
	int sge_nob;

	LASSERT(!in_interrupt());
	LASSERT(type == EFALND_MSG_PUTR_DONE || type == EFALND_MSG_GETR_DONE);

	tx->type = type;

	sge_nob = min(src_rdma->nob, sink_rdma->nob);

	sge = &tx->sge;
	wrq = &tx->wrq;

	sge->addr = sink_rdma->addr;
	sge->lkey = sink_rdma->key;
	sge->length = sge_nob;

	ib_wr = &wrq->wr.wr;

	ib_wr->next = NULL;
	ib_wr->wr_id = (u64)tx;
	ib_wr->sg_list = sge;
	ib_wr->num_sge = 1; /* EFA supports a single SGE for RDMA */
	ib_wr->opcode = IB_WR_RDMA_READ;
	ib_wr->send_flags = 0;

	/* RDMA specific */
	wrq->remote_addr = src_rdma->addr;
	wrq->rkey = src_rdma->key;

	kefalnd_set_sync_data(tx, dstcookie);
}

static int
kefalnd_handle_putr_req(struct kefa_ni *efa_ni, struct kefa_conn *conn,
			struct lnet_msg *lntmsg, struct kefa_rdma_desc *src_rd,
			u64 src_cookie, int nob)
{
	struct kefa_tx *tx;
	int rc = 0;

	if (lntmsg == NULL) {
		kefalnd_send_completion(efa_ni, conn, EFALND_MSG_PUTR_DONE,
					-ENODATA, src_cookie);
		return 0;
	}

	tx = kefalnd_get_idle_tx(efa_ni);
	if (tx == NULL) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "can't allocate %s TX to peer NI[%s]\n",
			    kefalnd_msgtype2str(EFALND_MSG_PUTR_DONE),
			    libcfs_nidstr(&conn->remote_nid));

		return -ENOMEM;
	}

	if (likely(nob != 0))
		rc = kefalnd_map_msg_iov(efa_ni, tx, lntmsg->msg_niov,
					 lntmsg->msg_kiov, lntmsg->msg_offset,
					 nob, false);
	if (unlikely(rc != 0)) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "can't setup GET src for peer NI[%s]. err[%d]\n",
			    libcfs_nidstr(&conn->remote_nid), rc);

		kefalnd_tx_done(tx);
		kefalnd_send_completion(efa_ni, conn, EFALND_MSG_PUTR_DONE, rc,
					src_cookie);
		return rc;
	}

	kefalnd_init_tx_rdma_read(conn, tx, EFALND_MSG_PUTR_DONE, src_rd,
				  src_cookie);

	if (nob == 0) {
		/* No RDMA: local completion may happen now! */
		lnet_finalize(lntmsg, 0);
	} else {
		/* RDMA: lnet_finalize(lntmsg) when it completes */
		tx->lntmsg[0] = lntmsg;
	}

	kefalnd_launch_tx(conn, tx);
	return 0;
}

static inline int
kefalnd_handle_putr_req_v2(struct kefa_ni *efa_ni,
			   struct kefa_conn *conn,
			   struct lnet_msg *lntmsg,
			   struct kefa_putr_req_msg_v2 *putr_req,
			   int nob)
{
	return kefalnd_handle_putr_req(efa_ni, conn, lntmsg,
				       &putr_req->rdma_desc,
				       putr_req->cookie, nob);
}

static int
kefalnd_handle_getr_req(struct kefa_ni *efa_ni, struct kefa_conn *conn,
			struct lnet_msg *lntmsg, u64 sink_cookie)
{
	struct kefa_getr_ack_msg *getr_ack;
	struct kefa_tx *tx;
	unsigned int nob;
	int rc = 0;

	if (lntmsg == NULL) {
		kefalnd_send_completion(efa_ni, conn, EFALND_MSG_NACK, -ENODATA,
					sink_cookie);
		return 0;
	}

	nob = lntmsg->msg_len;

	tx = kefalnd_get_idle_tx(efa_ni);
	if (tx == NULL) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "can't allocate %s TX to peer NI[%s]\n",
			    kefalnd_msgtype2str(EFALND_MSG_GETR_ACK),
			    libcfs_nidstr(&conn->remote_nid));

		return -ENOMEM;
	}

	if (nob != 0)
		rc = kefalnd_map_msg_iov(efa_ni, tx, lntmsg->msg_niov,
					 lntmsg->msg_kiov, lntmsg->msg_offset,
					 nob, true);
	if (rc != 0) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "can't setup GET src for peer NI[%s]. err[%d]\n",
			    libcfs_nidstr(&conn->remote_nid), rc);

		kefalnd_tx_done(tx);
		kefalnd_send_completion(efa_ni, conn, EFALND_MSG_NACK, rc,
					sink_cookie);
		return rc;
	}

	if (nob == 0) {
		/* No RDMA: local completion may happen now! */
		lnet_finalize(lntmsg, 0);
	} else {
		/* RDMA: lnet_finalize(lntmsg) when it completes */
		tx->lntmsg[0] = lntmsg;
	}

	kefalnd_init_tx_protocol_msg(tx, conn, EFALND_MSG_GETR_ACK,
				     sizeof(struct kefa_getr_ack_msg),
				     conn->proto_ver);

	getr_ack = kefalnd_get_getr_ack_from_msg(tx->msg);
	getr_ack->sink_cookie = sink_cookie;
	getr_ack->src_cookie = kefalnd_tx_to_idx(tx);
	getr_ack->rdma_desc = tx->rdma_desc;

	atomic_inc(&tx->ref_cnt); /* Wait for GETR_DONE */
	atomic_set(&tx->waiting_resp, true);

	kefalnd_launch_tx(conn, tx);
	return 0;
}

static inline int
kefalnd_handle_getr_req_v2(struct kefa_ni *efa_ni,
			   struct kefa_conn *conn,
			   struct lnet_msg *lntmsg,
			   struct kefa_getr_req_msg_v2 *getr_req)
{
	return kefalnd_handle_getr_req(efa_ni, conn, lntmsg,
				       getr_req->sink_cookie);
}

static int
kefalnd_refill_rx(struct kefa_qp *qp, u32 budget)
{
	struct kefa_rx *rx, *tmp;
	struct ib_recv_wr *prev_wrq = NULL;
	struct ib_recv_wr *first_wrq = NULL;
	struct ib_recv_wr *bad_wrq = NULL;
	unsigned long flags;
	int rc = 0, wr_cnt = 0;

	spin_lock_irqsave(&qp->rq_lock, flags);

	budget = min(budget, qp->rq_space);

	/* prepare a list of recv WRs to submit */
	list_for_each_entry_safe(rx, tmp, &qp->free_rx, list_node) {
		if (budget == 0)
			break;

		LASSERT(rx->rx_nob >= 0);
		rx->rx_nob = -1; /* mark posted */

		list_move_tail(&rx->list_node, &qp->posted_rx);

		if (prev_wrq)
			prev_wrq->next = &rx->wrq;

		if (first_wrq == NULL)
			first_wrq = &rx->wrq;

		rx->wrq.next = NULL;
		prev_wrq = &rx->wrq;
		wr_cnt++;
		budget--;
	}

	if (unlikely(wr_cnt == 0)) {
		spin_unlock_irqrestore(&qp->rq_lock, flags);
		return 0;
	}

	rc = ib_post_recv(qp->ib_qp, first_wrq,
			  (const struct ib_recv_wr **)&bad_wrq);
	if (unlikely(rc != 0)) {
		spin_unlock_irqrestore(&qp->rq_lock, flags);
		EFA_DEV_ERR(qp->efa_dev,
			    "QP[%u] failed to post RX. err[%d], bad_wrq[%p]\n",
			    qp->ib_qp->qp_num, rc, bad_wrq);

		return -EIO;
	}

	qp->rq_space -= wr_cnt;

	spin_unlock_irqrestore(&qp->rq_lock, flags);
	return rc;
}

static int
kefalnd_free_rx(struct kefa_rx *rx)
{
	struct kefa_qp *qp = rx->qp;
	unsigned long flags;

	spin_lock_irqsave(&qp->rq_lock, flags);
	qp->rq_space++;
	list_move_tail(&rx->list_node, &qp->free_rx);
	spin_unlock_irqrestore(&qp->rq_lock, flags);

	return 0;
}

static int
kefalnd_recv(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg,
	    int delayed, unsigned int niov, struct bio_vec *kiov,
	    unsigned int offset, unsigned int mlen, unsigned int rlen)
{
	struct kefa_ni *efa_ni = ni->ni_data;
	struct kefa_rx *rx = private;
	unsigned int imm_offset;
	struct kefa_conn *conn;
	struct kefa_msg *msg;
	struct lnet_nid *nid;
	int imm_nob, rc = 0;

	msg = rx->msg;
	nid = &msg->msg_v2.srcnid;
	conn = kefalnd_lookup_conn(efa_ni, nid, KEFA_CONN_TYPE_RESPONDER);
	if (IS_ERR_OR_NULL(conn)) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "failed to get connection for RX from peer NI[%s]. err[%ld]\n",
			    libcfs_nidstr(nid), PTR_ERR(conn));

		return -ENOTCONN;
	}

	switch (msg->hdr.type) {
	default:
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "received unexpected efa msg[%s] from peer NI[%s]\n",
			    kefalnd_msgtype2str(msg->hdr.type),
			    libcfs_nidstr(nid));

		break;

	case EFALND_MSG_IMMEDIATE:
		imm_offset = offsetof(struct kefa_msg, msg_v2.u.immediate.payload);
		imm_nob = offsetof(struct kefa_msg, msg_v2.u.immediate.payload[rlen]);
		if (imm_nob > rx->rx_nob) {
			EFA_DEV_ERR(efa_ni->efa_dev,
				    "immediate message from peer NI[%s] too big: %d(%d)\n",
				    libcfs_nidstr(nid), imm_nob, rx->rx_nob);

			rc = -EPROTO;
			break;
		}

		lnet_copy_flat2kiov(niov, kiov, offset, EFALND_MSG_SIZE, msg,
				    imm_offset, mlen);
		lnet_finalize(lntmsg, 0);
		break;

	case EFALND_MSG_PUTR_REQ:
		rc = kefalnd_handle_putr_req_v2(efa_ni, conn, lntmsg,
						&msg->msg_v2.u.putr_req, mlen);
		break;

	case EFALND_MSG_GETR_REQ:
		rc = kefalnd_handle_getr_req_v2(efa_ni, conn, lntmsg,
						&msg->msg_v2.u.getr_req);
		break;
	}

	kefalnd_free_rx(rx);
	return rc;
}

static void
kefalnd_finv_complete(struct kefa_ni *efa_ni, struct ib_wc *wc)
{
	struct kefa_dev *efa_dev = efa_ni->efa_dev;
	struct kefa_fmr *fmr = (void *)wc->wr_id;

	if (!fmr) {
		/* Reaching here means FW or LND did something bad */
		CERROR("cpu[%u] received bad FINV completion with status[%u]\n",
		       smp_processor_id(), wc->status);
		return;
	}

	if (wc->status != IB_WC_SUCCESS) {
		EFA_DEV_WARN(efa_dev,
			     "QP[%u] received FINV[0x%x] completion with err[%u] vendor[%u]\n",
			     wc->qp->qp_num, fmr->mr->lkey, wc->status,
			     wc->vendor_err);

		kefalnd_obj_pool_put_on_pend_list(&efa_dev->fmr_pool,
						  &fmr->list_node);
		return;
	}

	fmr->state = KEFA_FMR_INACTIVE;
	kefalnd_obj_pool_free(&efa_dev->fmr_pool, &fmr->list_node);
}

static void
kefalnd_tx_complete(struct kefa_ni *efa_ni, struct ib_wc *wc)
{
	struct kefa_conn *conn;
	struct kefa_tx *tx;

	tx = (void *)wc->wr_id;
	if (!tx) {
		/* Reaching here means FW or LND did something bad */
		CERROR("cpu[%u] received bad TX completion with status[%u]",
		       smp_processor_id(), wc->status);
		return;
	}

	conn = tx->conn;
	if (!conn) {
		CERROR("TX[%p] received bad conn[%p], type[%s]", tx, conn,
		       kefalnd_msgtype2str(tx->type));

		return;
	}

	if (atomic_read(&tx->ref_cnt) <= 0) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "received completion on free TX\n");
		return;
	}

	if (wc->opcode == IB_WC_REG_MR) {
		if (wc->status == IB_WC_SUCCESS) {
			tx->fmr->state = KEFA_FMR_ACTIVE;
			kefalnd_launch_tx(tx->conn, tx);
		} else {
			EFA_DEV_ERR(efa_ni->efa_dev,
				    "QP[%u] received FRWR[0x%x] completion with err[%u] vendor[%u]\n",
				     wc->qp->qp_num, tx->fmr->mr->lkey,
				     wc->status, wc->vendor_err);

			kefalnd_abort_tx(tx, LNET_MSG_STATUS_LOCAL_DROPPED, -ECOMM);
		}
	} else if (wc->status != IB_WC_SUCCESS) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "QP[%u] received TX[%s] completion with err. opcode[%u] status[%u] vendor[%u] peer_ni[%s]\n",
			    wc->qp->qp_num, kefalnd_msgtype2str(tx->type),
			    wc->opcode, wc->status, wc->vendor_err,
			    libcfs_nidstr(&conn->remote_nid));

		kefalnd_abort_tx(tx, LNET_MSG_STATUS_REMOTE_DROPPED, -ECOMM);
		if (conn->type == KEFA_CONN_TYPE_INITIATOR)
			kefalnd_deactivate_conn(conn);
	}

	if (atomic_dec_and_test(&tx->ref_cnt))
		kefalnd_tx_done(tx);
}

static void
kefalnd_handle_completion(struct kefa_ni *efa_ni,
			  struct kefa_completion_msg *completion)
{
	int status = kefalnd_efa_status_to_errno(completion->status);
	u64 tx_idx = completion->cookie;
	struct kefa_tx *tx;

	tx = kefalnd_get_tx_by_idx(efa_ni, tx_idx);
	if (!tx)
		return;

	/* Response handling might race with TX abort, first 'wins' */
	if (!atomic_xchg_relaxed(&tx->waiting_resp, false))
		return;

	if (tx->status == 0) { /* success so far */
		if (status < 0) { /* failed? */
			tx->status = status;
			tx->hstatus = LNET_MSG_STATUS_REMOTE_ERROR;
		}
	}

	if (atomic_dec_and_test(&tx->ref_cnt))
		kefalnd_tx_done(tx);
}

static int
kefalnd_handle_getr_ack(struct kefa_ni *efa_ni,
			struct kefa_getr_ack_msg *getr_ack)
{
	struct kefa_conn *conn;
	struct kefa_tx *tx;

	tx = kefalnd_get_tx_by_idx(efa_ni, getr_ack->sink_cookie);
	if (!tx)
		return -EINVAL;

	/* Response handling might race with TX abort, first 'wins' */
	if (!atomic_xchg_relaxed(&tx->waiting_resp, false))
		return -EINVAL;

	conn = tx->conn;

	lnet_set_reply_msg_len(efa_ni->lnet_ni, tx->lntmsg[1],
			       getr_ack->rdma_desc.nob);

	/* source has mapped his buffers - let's read */
	kefalnd_init_tx_rdma_read(conn, tx, EFALND_MSG_GETR_DONE,
				  &getr_ack->rdma_desc, getr_ack->src_cookie);

	kefalnd_launch_tx(conn, tx);

	/* remove GETR_{ACK,NACK} reference only after we added RDMA ref_cnt.
	 * We check if TX is done here and not only decreasing the refcnt in
	 * case RDMA is finished before reaching this point.
	 */
	if (atomic_dec_and_test(&tx->ref_cnt))
		kefalnd_tx_done(tx);

	return 0;
}

static void
kefalnd_handle_lnet_request_msg(struct kefa_ni *efa_ni, struct kefa_rx *rx)
{
	struct kefa_msg *msg = rx->msg;
	int rc, rdma_req = 0;
	struct lnet_hdr hdr;

	switch (msg->hdr.type) {
	case EFALND_MSG_IMMEDIATE:
		lnet_hdr_from_nid16(&hdr, &msg->msg_v2.u.immediate.hdr);
		break;

	case EFALND_MSG_PUTR_REQ:
		rdma_req = 1;
		lnet_hdr_from_nid16(&hdr, &msg->msg_v2.u.putr_req.hdr);
		break;

	case EFALND_MSG_GETR_REQ:
		rdma_req = 1;
		lnet_hdr_from_nid16(&hdr, &msg->msg_v2.u.getr_req.hdr);
		break;

	default:
		LASSERTF(0, "message type[%u] doesn't have lnet header\n",
			 msg->hdr.type);
		break;
	}

	rc = lnet_parse(efa_ni->lnet_ni, &hdr, &hdr.src_nid, rx, rdma_req);
	if (rc < 0)
		EFA_DEV_ERR(efa_ni->efa_dev, "error parsing lnet msg\n");
}

static void
kefalnd_handle_rx(struct kefa_ni *efa_ni, struct kefa_rx *rx)
{
	struct kefa_msg *msg = rx->msg;
	bool free_rx = false;
	int rc = 0;

	switch (msg->hdr.type) {
	default:
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "bad EFALND message type %x from loopback\n",
			    msg->hdr.type);

		rc = -EPROTO;
		break;

	case EFALND_MSG_GETR_REQ:
	case EFALND_MSG_PUTR_REQ:
	case EFALND_MSG_IMMEDIATE:
		kefalnd_handle_lnet_request_msg(efa_ni, rx);
		break;

	case EFALND_MSG_GETR_ACK:
		kefalnd_handle_getr_ack(efa_ni, kefalnd_get_getr_ack_from_msg(msg));
		free_rx = true;
		break;

	case EFALND_MSG_NACK:
	case EFALND_MSG_PUTR_DONE:
	case EFALND_MSG_GETR_DONE:
		kefalnd_handle_completion(efa_ni, kefalnd_get_completion_from_msg(msg));
		free_rx = true;
		break;

	case EFALND_MSG_CONN_PROBE:
	case EFALND_MSG_CONN_PROBE_RESP:
	case EFALND_MSG_CONN_REQ:
	case EFALND_MSG_CONN_REQ_ACK:
		kefalnd_handle_conn_establishment(efa_ni, msg);
		free_rx = true;
		break;
	}

	if (free_rx || rc < 0)
		kefalnd_free_rx(rx);

	kefalnd_refill_rx(rx->qp, 1);
}

static int
kefalnd_unpack_header_v2(struct kefa_ni *efa_ni, struct kefa_msg_v2 *msg_v2,
			 u8 type, int rx_nob)
{
	const int base_hdr_size = offsetof(struct kefa_msg, msg_v2.u);
	struct kefa_dev *efa_dev = efa_ni->efa_dev;

	if (rx_nob < base_hdr_size) {
		EFA_DEV_ERR(efa_dev, "short message: %d\n", rx_nob);
		return -EPROTO;
	}

	if (type != EFALND_MSG_CONN_PROBE &&
	    msg_v2->dst_epoch != efa_ni->ni_epoch) {
		EFA_DEV_ERR(efa_dev, "RX[%u] epoch mismatch: recv[%llu], expected[%llu]\n",
			    type, msg_v2->dst_epoch, efa_ni->ni_epoch);
		return -EPROTO;
	}

	if (LNET_NID_IS_ANY(&msg_v2->srcnid)) {
		EFA_DEV_ERR(efa_dev, "bad src nid: %s\n",
			    libcfs_nidstr(&msg_v2->srcnid));
		return -EPROTO;
	}

	return 0;
}

static int
kefalnd_unpack_header_v1(struct kefa_ni *efa_ni, struct kefa_msg_v1 *msg_v1,
			 u8 type, int rx_nob)
{
	const int base_hdr_size = offsetof(struct kefa_msg, msg_v1.u);
	struct kefa_dev *efa_dev = efa_ni->efa_dev;

	if (type != EFALND_MSG_CONN_PROBE &&
	    type != EFALND_MSG_CONN_PROBE_RESP) {
		EFA_DEV_ERR(efa_dev, "unsupported V1 protocol[%s]\n",
			    kefalnd_msgtype2str(type));
		return -EPROTO;
	}

	if (rx_nob < base_hdr_size) {
		EFA_DEV_ERR(efa_dev, "short message: %d\n", rx_nob);
		return -EPROTO;
	}

	if (type != EFALND_MSG_CONN_PROBE &&
	    msg_v1->dst_epoch != efa_ni->ni_epoch) {
		EFA_DEV_ERR(efa_dev, "RX[%u] epoch mismatch: recv[%llu], expected[%llu]\n",
			    type, msg_v1->dst_epoch, efa_ni->ni_epoch);
		return -EPROTO;
	}

	if (msg_v1->srcnid == LNET_NID_ANY) {
		EFA_DEV_ERR(efa_dev, "bad src nid: %s\n",
			    libcfs_nid2str(msg_v1->srcnid));
		return -EPROTO;
	}

	return 0;
}

static int
kefalnd_unpack_msg(struct kefa_ni *efa_ni, struct kefa_rx *rx, struct ib_wc *wc)
{
	const int min_hdr_size = sizeof(struct kefa_hdr);
	struct kefa_msg *msg = rx->msg;
	struct kefa_hdr *hdr;
	struct lnet_nid nid;
	int rc = 0;

	hdr = &msg->hdr;
	if (rx->rx_nob < min_hdr_size) {
		EFA_DEV_ERR(efa_ni->efa_dev, "short message: %d\n", rx->rx_nob);
		return -EPROTO;
	}

	if (hdr->magic != EFALND_MSG_MAGIC) {
		EFA_DEV_ERR(efa_ni->efa_dev, "bad magic: %08x\n", hdr->magic);
		return -EPROTO;
	}

	if (hdr->proto_ver > EFALND_MAX_PROTO_VER ||
	    (hdr->type != EFALND_MSG_CONN_PROBE && hdr->proto_ver < EFALND_MIN_PROTO_VER)) {
		EFA_DEV_ERR(efa_ni->efa_dev, "bad protocol version: %x\n",
			    hdr->proto_ver);
		return -EPROTO;
	}

	if (hdr->nob > rx->rx_nob) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "short message: got %d, wanted %d\n",
			    rx->rx_nob, hdr->nob);

		return -EPROTO;
	}

	if (hdr->nob < kefalnd_msgtype2size(hdr->type, hdr->proto_ver)) {
		EFA_DEV_ERR(efa_ni->efa_dev, "short %s: %d(%d)\n",
			    kefalnd_msgtype2str(hdr->type), hdr->nob,
			    kefalnd_msgtype2size(hdr->type, hdr->proto_ver));

		return -EPROTO;
	}

	if (hdr->proto_ver != EFALND_PROTO_VER_1)
		rc = kefalnd_unpack_header_v2(efa_ni, &msg->msg_v2, hdr->type,
					      rx->rx_nob);
	else
		rc = kefalnd_unpack_header_v1(efa_ni, &msg->msg_v1, hdr->type,
					      rx->rx_nob);

	if (rc)
		goto bad_pkt;

	return 0;

bad_pkt:
	kefalnd_get_srcnid_from_msg(msg, &nid);
	EFA_DEV_ERR(efa_ni->efa_dev,
		    "QP[%u] failed RX unpacking from peer NI[%s].\n",
		    wc->qp->qp_num, libcfs_nidstr(&nid));

	return -EPROTO;
}

static void
kefalnd_rx_complete(struct kefa_ni *efa_ni, struct ib_wc *wc)
{
	struct kefa_rx *rx;
	int nob, rc;

	rx = (void *)wc->wr_id;
	nob = wc->byte_len;
	if (!rx || nob == 0) {
		/* Reaching here means FW or LND did something bad */
		CERROR("cpu[%u] received bad RX handle with status[%u] nob[%u]",
		       smp_processor_id(), wc->status, nob);
		return;
	}

	if (wc->status != IB_WC_SUCCESS) {
		EFA_DEV_ERR(efa_ni->efa_dev,
			    "QP[%u] received RX completion with err[%u]\n",
			    wc->qp->qp_num, wc->status);

		goto failed;
	}

	LASSERT(rx->rx_nob < 0);	/* was posted */
	rx->rx_nob = nob;

	rc = kefalnd_unpack_msg(efa_ni, rx, wc);
	if (rc)
		goto failed;

	kefalnd_handle_rx(efa_ni, rx);
	return;

failed:
	kefalnd_free_rx(rx);
}

static void
kefalnd_complete(struct kefa_ni *efa_ni, struct ib_wc *wc)
{
	switch (wc->opcode) {
	default:
		LBUG();

	case IB_WC_SEND:
	case IB_WC_REG_MR:
	case IB_WC_RDMA_READ:
		kefalnd_tx_complete(efa_ni, wc);
		return;

	case IB_WC_LOCAL_INV:
		kefalnd_finv_complete(efa_ni, wc);
		return;

	case IB_WC_RECV:
		kefalnd_rx_complete(efa_ni, wc);
		return;
	}
}

static int
kefalnd_scheduler(void *arg)
{
	struct kefa_cq *cq = NULL;
	struct kefa_sched *sched;
	wait_queue_entry_t wait;
	long id = (long)arg;
	unsigned long flags;
	int rc, cqe_cnt, i;
	struct ib_wc *wc;

	sched = kefalnd.scheds[KEFA_THREAD_CPT(id)];

	LIBCFS_CPT_ALLOC(wc, lnet_cpt_table(), sched->cpt,
			 MAX_CQE_BATCH * sizeof(*wc));
	if (!wc) {
		CERROR("Failed to allocate memory for scheduler WCs pool\n");
		return -ENOMEM;
	}

	rc = cfs_cpt_bind(lnet_cpt_table(), sched->cpt);
	if (rc != 0)
		CWARN("Failed to bind shceduler thread to CPU partition %d\n",
		      sched->cpt);

	init_wait(&wait);

	while (!kefalnd.shutdown) {
		spin_lock_irqsave(&sched->lock, flags);
		cq = list_first_entry_or_null(&sched->pend_cqs, struct kefa_cq, sched_node);
		if (!cq) {
			spin_unlock_irqrestore(&sched->lock, flags);
			set_current_state(TASK_INTERRUPTIBLE);
			add_wait_queue_exclusive(&sched->waitq, &wait);
			schedule();
			remove_wait_queue(&sched->waitq, &wait);
			set_current_state(TASK_RUNNING);
			continue;
		}
		list_del_init(&cq->sched_node);
		spin_unlock_irqrestore(&sched->lock, flags);

again:
		cqe_cnt = ib_poll_cq(cq->ib_cq, MAX_CQE_BATCH, wc);
		if (cqe_cnt < 0) {
			/* TODO - handle error is fatal */
			EFA_DEV_ERR(cq->efa_dev, "poll CQ failed. err[%d]\n",
				    cqe_cnt);
			continue;
		}

		if (cqe_cnt == 0) {
			/* TODO - consider releasing CQ on every CQ poll */
			rc = ib_req_notify_cq(cq->ib_cq,
					      IB_CQ_NEXT_COMP |
					      IB_CQ_REPORT_MISSED_EVENTS);
			if (rc < 0) {
				/* TODO - This is fatal, handle error flow */
				EFA_DEV_ERR(cq->efa_dev,
					    "request notify CQ failed. err[%d]\n",
					    rc);
			}

			/* We missed some CQEs. try again */
			if (rc > 0)
				goto again;

			/* Try acquire a new CQ */
			continue;
		}

		/* return the CQ so other threads can take the next batch */
		spin_lock_irqsave(&sched->lock, flags);
		if (list_empty(&cq->sched_node))
			list_add_tail(&cq->sched_node, &sched->pend_cqs);
		spin_unlock_irqrestore(&sched->lock, flags);

		for (i = 0; i < cqe_cnt; i++)
			kefalnd_complete(cq->efa_dev->efa_ni, wc + i);

		/* respect periodic scheduling  */
		if (need_resched())
			cond_resched();
	}

	LIBCFS_FREE(wc, MAX_CQE_BATCH * sizeof(*wc));

	kefalnd_thread_stop();
	return 0;
}

static void
kefalnd_destroy_all_conns(struct kefa_ni *efa_ni)
{
	struct kefa_conn *conn;
	struct hlist_node *tmp;
	int bkt;

	hash_for_each_safe(efa_ni->conns, bkt, tmp, conn, ni_node) {
		hlist_del_init(&conn->ni_node);
		kefalnd_destroy_conn(conn, LNET_MSG_STATUS_LOCAL_ABORTED,
				     -ENODEV);
	}
}

static int
kefalnd_start_scheduler(struct kefa_sched *sched)
{
	int rc = 0;
	int nthrs;
	int i;

	if (sched->nthreads == 0) {
		/* decide thread count for new interface */
		if (*kefalnd_tunables.kefa_nscheds > 0) {
			nthrs = sched->nthreads_max;
		} else {
			/* re-calculate thread count in case cpt changed */
			nthrs = cfs_cpt_weight(lnet_cpt_table(), sched->cpt);
			nthrs = min(max(EFALND_MIN_SCHED_THRS, nthrs >> 1), nthrs);
			nthrs = min(EFALND_MAX_SCHED_THRS, nthrs);
		}
	} else {
		LASSERT(sched->nthreads <= sched->nthreads_max);
		/* increase one thread if there is new interface */
		nthrs = (sched->nthreads < sched->nthreads_max);
	}


	for (i = 0; i < nthrs; i++) {
		long id = KEFA_THREAD_ID(sched->cpt, sched->nthreads + i);

		rc = kefalnd_thread_start(kefalnd_scheduler, (void *)id,
					  "kefalnd_s_%02ld_%02ld",
					  KEFA_THREAD_CPT(id),
					  KEFA_THREAD_TID(id));
		if (rc) {
			CWARN("Can't spawn thread %d for scheduler[%d]: rc[%d]\n",
			      sched->nthreads + i, sched->cpt, rc);
			break;
		}
	}

	sched->nthreads += i;
	return rc;
}

static int
kefalnd_start_cm_daemon(struct kefa_dev *efa_dev,
			struct kefa_cm_deamon *cm_daemon)
{
	int rc = 0;
	long id;

	id = KEFA_THREAD_ID(cm_daemon->cpt, 0);
	rc = kefalnd_thread_start(kefalnd_cm_daemon, (void *)id,
				  "kefalnd_cd_%02ld_%02ld",
				  KEFA_THREAD_CPT(id), KEFA_THREAD_TID(id));
	if (rc) {
		EFA_DEV_ERR(efa_dev, "can't spawn thread for connection daemon[%d]. err[%d]\n",
			    cm_daemon->cpt, rc);
	} else {
		cm_daemon->active = true;
	}

	return rc;
}

static int
kefalnd_dev_start_threads(struct kefa_dev *efa_dev)
{
	struct kefa_cm_deamon *cm_daemon;
	struct kefa_sched *sched;
	int rc;

	sched = kefalnd.scheds[efa_dev->cpt];
	rc = kefalnd_start_scheduler(sched);
	if (rc) {
		EFA_DEV_ERR(efa_dev, "failed to start scheduler threads\n");
		return rc;
	}

	cm_daemon = kefalnd.cm_daemons[efa_dev->cpt];
	if (cm_daemon->active)
		return 0;

	rc = kefalnd_start_cm_daemon(efa_dev, cm_daemon);
	if (rc) {
		EFA_DEV_ERR(efa_dev,
			    "failed to start connection daemon thread\n");
		return rc;
	}

	return 0;
}

static u32
kefalnd_get_tx_pool_size(struct kefa_ni *efa_ni)
{
	struct lnet_ioctl_config_lnd_cmn_tunables *net_tunables;
	struct lnet_ioctl_config_efalnd_tunables *efa_tunables;

	u32 tx_pool_size, lnd_nqps;

	efa_tunables = &efa_ni->lnet_ni->ni_lnd_tunables.lnd_tun_u.lnd_efa;
	net_tunables = &efa_ni->lnet_ni->ni_net->net_tunables;

	tx_pool_size = net_tunables->lct_max_tx_credits * 2;
	tx_pool_size = min_t(u32, tx_pool_size, EFALND_MAX_NI_TX_POOL);

	if (tx_pool_size < net_tunables->lct_max_tx_credits) {
		EFA_DEV_WARN(efa_ni->efa_dev,
			     "LNET NI credits[%d] exceeds EFA LND TX pool size[%d]\n",
			     net_tunables->lct_max_tx_credits, tx_pool_size);
	}

	lnd_nqps = efa_tunables->lnd_nqps;

	return tx_pool_size + lnd_nqps * RQ_DEPTH;
}

static void
kefalnd_destroy_tx_pool(struct kefa_ni *efa_ni)
{
	struct kefa_obj_pool *tx_pool = &efa_ni->tx_pool;
	u32 pool_size = tx_pool->pool_size;
	int i;

	if (!tx_pool->obj_arr)
		return;

	for (i = 0; i < pool_size; i++) {
		struct kefa_tx *tx = &((struct kefa_tx *)tx_pool->obj_arr)[i];

		if (tx->frags)
			LIBCFS_FREE(tx->frags, (EFALND_MAX_TX_FRAGS) * sizeof(*tx->frags));
		if (tx->msg) {
			ib_dma_unmap_single(efa_ni->efa_dev->ib_dev,
					    tx->msgaddr,
					    EFALND_MSG_SIZE_ALIGNED,
					    DMA_TO_DEVICE);
			kfree(tx->msg);
		}
	}
	LIBCFS_FREE(tx_pool->obj_arr, pool_size * sizeof(struct kefa_tx));
}

static int
kefalnd_create_tx_pool(struct kefa_ni *efa_ni, int cpt)
{
	struct kefa_obj_pool *tx_pool = &efa_ni->tx_pool;
	struct kefa_dev *efa_dev = efa_ni->efa_dev;
	u32 pool_size;
	int i, rc;

	memset(tx_pool, 0, sizeof(*tx_pool));

	pool_size = kefalnd_get_tx_pool_size(efa_ni);
	rc = kefalnd_obj_pool_init(efa_ni, tx_pool, pool_size, cpt,
				   sizeof(struct kefa_tx));
	if (rc != 0) {
		EFA_DEV_ERR(efa_dev, "cannot allocate TX pool\n");
		goto failed;
	}

	for (i = 0; i < pool_size; i++) {
		struct kefa_tx *tx = &((struct kefa_tx *)tx_pool->obj_arr)[i];

		tx->tx_pool = tx_pool;

		LIBCFS_CPT_ALLOC(tx->frags, lnet_cpt_table(), tx_pool->cpt,
				 EFALND_MAX_TX_FRAGS * sizeof(*tx->frags));
		if (!tx->frags) {
			EFA_DEV_ERR(efa_dev,
				    "can't allocate TX SG fragments\n");
			goto failed;
		}

		sg_init_table(tx->frags, EFALND_MAX_TX_FRAGS);

		tx->msg = cfs_cpt_malloc(lnet_cpt_table(), tx_pool->cpt,
					 EFALND_MSG_SIZE_ALIGNED, GFP_KERNEL);
		if (!tx->msg) {
			EFA_DEV_ERR(efa_dev,
				    "failed to allocate TX SGL buffer\n");
			goto failed;
		}

		tx->msgaddr = ib_dma_map_single(efa_dev->ib_dev, tx->msg,
						EFALND_MSG_SIZE_ALIGNED,
						DMA_TO_DEVICE);
		if (ib_dma_mapping_error(efa_dev->ib_dev, tx->msgaddr)) {
			EFA_DEV_ERR(efa_dev, "failed to map TX SGL buffer\n");
			kfree(tx->msg);
			tx->msg = NULL;
			goto failed;
		}

		tx->lkey = efa_dev->pd->local_dma_lkey;
		list_add_tail(&tx->list_node, &tx_pool->free_obj);
	}

	return 0;

failed:
	kefalnd_destroy_tx_pool(efa_ni);
	return -ENOMEM;
}

static int
kefalnd_init_rx_msgs(struct kefa_qp *qp)
{
	struct kefa_dev *efa_dev = qp->efa_dev;
	struct kefa_rx *rx;
	int i;

	for (i = 0; i < EFALND_RX_MSGS(qp); i++) {
		rx = qp->rx_msgs + i;

		rx->qp = qp;
		rx->rx_nob = 0;

		rx->msg = cfs_cpt_malloc(lnet_cpt_table(), efa_dev->cpt,
					 EFALND_MSG_SIZE_ALIGNED, GFP_KERNEL);
		if (!rx->msg) {
			EFA_DEV_ERR(qp->efa_dev, "failed to allocate RX SGE\n");
			return -ENOMEM;
		}

		rx->sge.addr = ib_dma_map_single(efa_dev->ib_dev, rx->msg,
						 EFALND_MSG_SIZE_ALIGNED,
						 DMA_FROM_DEVICE);
		if (ib_dma_mapping_error(efa_dev->ib_dev, rx->sge.addr)) {
			EFA_DEV_ERR(qp->efa_dev, "failed to map RX SGE\n");
			kfree(rx->msg);
			rx->msg = NULL;
			return -ENOMEM;
		}

		rx->sge.lkey = efa_dev->pd->local_dma_lkey;
		rx->sge.length = EFALND_MSG_SIZE;

		rx->wrq.sg_list = &rx->sge;
		rx->wrq.num_sge = 1;
		rx->wrq.wr_id = (u64)rx;
		INIT_LIST_HEAD(&rx->list_node);
		list_add_tail(&rx->list_node, &qp->free_rx);
	}
	return 0;
}

static void
kefalnd_destroy_qp(struct kefa_qp *qp)
{
	struct kefa_rx *rx;
	int rc, i;

	if (!IS_ERR_OR_NULL(qp->ib_qp)) {
		rc = ib_destroy_qp(qp->ib_qp);
		if (rc) {
			EFA_DEV_ERR(qp->efa_dev,
				    "failed to destroy QP[%u]. rc[%d]\n",
				    qp->ib_qp->qp_num, rc);
		}
	}

	if (qp->rx_msgs) {
		for (i = 0; i < EFALND_RX_MSGS(qp); i++) {
			rx = qp->rx_msgs + i;
			if (rx->msg) {
				ib_dma_unmap_single(qp->efa_dev->ib_dev,
						    rx->sge.addr,
						    EFALND_MSG_SIZE_ALIGNED,
						    DMA_FROM_DEVICE);
				kfree(rx->msg);
			}
		}

		LIBCFS_FREE(qp->rx_msgs, EFALND_RX_MSGS(qp) * sizeof(struct kefa_rx));
	}
}

static int
kefalnd_create_qp(struct kefa_dev *efa_dev, struct kefa_qp *qp,
		  struct kefa_cq *cq, u16 sq_depth, u16 rq_depth, u32 qkey)
{
	struct ib_qp_init_attr init_attr;
	struct ib_qp_attr qp_attr = {};
	struct ib_qp *ib_qp;
	int rc = 0;

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.cap.max_send_wr = sq_depth;
	init_attr.cap.max_recv_wr = rq_depth;

	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.qp_type = EFA_QPT_SRD;
	init_attr.send_cq = cq->ib_cq;
	init_attr.recv_cq = cq->ib_cq;
	init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;

	ib_qp = ib_create_qp(efa_dev->pd, &init_attr);
	if (IS_ERR(ib_qp)) {
		EFA_DEV_ERR(efa_dev, "failed to create QP. err[%ld]\n",
			    PTR_ERR(ib_qp));
		return PTR_ERR(ib_qp);
	}
	qp->ib_qp = ib_qp;

	/* EFA doesn't support CM so change QP to ready immediately */
	qp->qkey = qkey;
	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.cur_qp_state = IB_QPS_RESET;
	qp_attr.port_num = 1;
	qp_attr.qkey = qp->qkey;
	rc = ib_modify_qp(ib_qp, &qp_attr,
			  IB_QP_PKEY_INDEX | IB_QP_PORT | IB_QP_QKEY | IB_QP_STATE);
	if (rc) {
		EFA_DEV_ERR(efa_dev, "failed to set QP[%u] qkey\n",
			    ib_qp->qp_num);
		goto failed;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.cur_qp_state = qp_attr.qp_state;
	qp_attr.qp_state = IB_QPS_RTR;
	rc = ib_modify_qp(ib_qp, &qp_attr, IB_QP_STATE);
	if (rc) {
		EFA_DEV_ERR(efa_dev, "failed to set QP[%u] state to RTR\n",
			    ib_qp->qp_num);
		goto failed;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.rnr_retry = *kefalnd_tunables.kefa_rnr_retry_count;
	qp_attr.cur_qp_state = qp_attr.qp_state;
	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 1;
	rc = ib_modify_qp(ib_qp, &qp_attr,
			  IB_QP_STATE | IB_QP_SQ_PSN | IB_QP_RNR_RETRY);
	if (rc) {
		EFA_DEV_ERR(efa_dev, "failed to set QP[%u] state to RTS\n",
			    ib_qp->qp_num);
		goto failed;
	}

	qp->efa_dev = efa_dev;
	qp->rq_depth = rq_depth;
	qp->rq_space = rq_depth;
	qp->cq = cq;
	spin_lock_init(&qp->rq_lock);
	INIT_LIST_HEAD(&qp->free_rx);
	INIT_LIST_HEAD(&qp->posted_rx);

	/* allocate RX buffers */
	LIBCFS_CPT_ALLOC(qp->rx_msgs, lnet_cpt_table(), efa_dev->cpt,
			 EFALND_RX_MSGS(qp) * sizeof(*qp->rx_msgs));
	if (!qp->rx_msgs) {
		EFA_DEV_ERR(efa_dev, "cannot allocate RX buffers\n");
		rc = -ENOMEM;
		goto failed;
	}

	rc = kefalnd_init_rx_msgs(qp);
	if (rc) {
		EFA_DEV_ERR(efa_dev, "failed to init RX messages for QP[%u]\n",
			    ib_qp->qp_num);
		goto failed;
	}

	/* initial post receives */
	rc = kefalnd_refill_rx(qp, rq_depth);
	if (rc) {
		EFA_DEV_ERR(efa_dev, "can't post rx msg: %d\n", rc);
		goto failed;
	}

	return 0;
failed:
	kefalnd_destroy_qp(qp);
	return rc;
}

static void
kefalnd_destroy_qps(struct kefa_dev *efa_dev)
{
	int i;

	if (efa_dev->qps) {
		for (i = 0; i < efa_dev->nqps; i++)
			kefalnd_destroy_qp(&efa_dev->qps[i]);

		LIBCFS_FREE(efa_dev->qps, efa_dev->nqps * sizeof(*efa_dev->qps));
	}

	if (efa_dev->cm_qp) {
		kefalnd_destroy_qp(efa_dev->cm_qp);
		LIBCFS_FREE(efa_dev->cm_qp, sizeof(*efa_dev->cm_qp));
	}
}

/*  Create Data QPs to distribute traffic per device and manager QP for
 * connection establishment
 */
static int
kefalnd_create_qps(struct kefa_dev *efa_dev, int num_qps, int sq_depth,
		   int rq_depth)
{
	int i, rc = 0;
	u32 qkey;

	efa_dev->nqps = num_qps;

	LIBCFS_CPT_ALLOC(efa_dev->cm_qp, lnet_cpt_table(), efa_dev->cpt,
			 sizeof(*efa_dev->cm_qp));
	if (!efa_dev->cm_qp) {
		EFA_DEV_ERR(efa_dev,
			    "failed to allocate memory for manager QP\n");
		return -ENOMEM;
	}

	if (the_lnet.ln_nis_use_large_nids)
		qkey = (u16)get_random_u32();
	else
		qkey = EFALND_CM_STATIC_QKEY;

	rc = kefalnd_create_qp(efa_dev, efa_dev->cm_qp, efa_dev->cm_cq,
			       sq_depth, rq_depth, qkey);
	if (rc) {
		kefalnd_destroy_qps(efa_dev);
		return rc;
	}

	LIBCFS_CPT_ALLOC(efa_dev->qps, lnet_cpt_table(), efa_dev->cpt,
			 num_qps * sizeof(*efa_dev->qps));
	if (!efa_dev->qps) {
		EFA_DEV_ERR(efa_dev, "failed to allocate memory for data QP\n");
		kefalnd_destroy_qps(efa_dev);
		return -ENOMEM;
	}
	memset(efa_dev->qps, 0, num_qps * sizeof(*efa_dev->qps));

	for (i = 0; i < num_qps; i++) {
		/* bit 31 is reserved for privileged qkeys */
		qkey = get_random_u32() & ~BIT(31);
		rc = kefalnd_create_qp(efa_dev, &efa_dev->qps[i],
				       &efa_dev->cqs[i % efa_dev->ncqs],
				       sq_depth, rq_depth, qkey);
		if (rc)
			break;
	}

	if (rc)
		kefalnd_destroy_qps(efa_dev);

	return rc;
}

static void
kefalnd_deschedule_cq(struct kefa_cq *cq)
{
	unsigned long flags;
	struct kefa_sched *sched;

	sched = kefalnd.scheds[cq->cpt];

	/* TODO - handle cq processing be scheduler */
	spin_lock_irqsave(&sched->lock, flags);
	if (!list_empty(&cq->sched_node))
		list_del_init(&cq->sched_node);
	spin_unlock_irqrestore(&sched->lock, flags);
}

static struct kefa_sched *
kefalnd_schedule_cq(struct kefa_cq *cq)
{
	unsigned long flags;
	struct kefa_sched *sched;

	sched = kefalnd.scheds[cq->cpt];

	spin_lock_irqsave(&sched->lock, flags);
	if (list_empty(&cq->sched_node))
		list_add_tail(&cq->sched_node, &sched->pend_cqs);
	spin_unlock_irqrestore(&sched->lock, flags);

	return sched;
}

static void
kefalnd_cq_comp_handler(struct ib_cq *ib_cq, void *cq_ctxt)
{
	struct kefa_cq *cq = cq_ctxt;
	struct kefa_sched *sched;

	sched = kefalnd_schedule_cq(cq);
	wake_up(&sched->waitq);
}

static int
kefalnd_get_completion_vector(struct kefa_dev *efa_dev)
{
	int vectors;

	vectors = efa_dev->ib_dev->num_comp_vectors;
	if (vectors <= 1)
		return 0;

	return efa_dev->cpt % vectors;
}

static int
kefalnd_create_cq(struct kefa_dev *efa_dev, struct kefa_cq *cq, int cq_depth)
{
	struct ib_cq_init_attr cq_attr = {0};
	struct ib_cq *ib_cq;

	cq_attr.cqe = cq_depth;
	cq_attr.comp_vector = kefalnd_get_completion_vector(efa_dev);
	ib_cq = ib_create_cq(efa_dev->ib_dev, kefalnd_cq_comp_handler, NULL,
			     (void *)cq, &cq_attr);
	if (IS_ERR(ib_cq)) {
		EFA_DEV_ERR(efa_dev, "can't create CQ. err[%ld]\n",
			    PTR_ERR(ib_cq));
		return IS_ERR(ib_cq);
	}

	cq->cpt = efa_dev->cpt;
	cq->efa_dev = efa_dev;
	cq->ib_cq = ib_cq;
	INIT_LIST_HEAD(&cq->sched_node);

	return 0;
}

static void
kefalnd_destroy_cqs(struct kefa_dev *efa_dev)
{
	int i;

	if (efa_dev->cqs) {
		for (i = 0; i < efa_dev->ncqs; i++) {
			struct kefa_cq *cq = &efa_dev->cqs[i];

			if (!IS_ERR_OR_NULL(cq->ib_cq)) {
				kefalnd_deschedule_cq(cq);
				ib_destroy_cq(cq->ib_cq);
			}
		}

		LIBCFS_FREE(efa_dev->cqs, efa_dev->ncqs * sizeof(*efa_dev->cqs));
	}

	if (efa_dev->cm_cq) {
		if (!IS_ERR_OR_NULL(efa_dev->cm_cq->ib_cq)) {
			kefalnd_deschedule_cq(efa_dev->cm_cq);
			ib_destroy_cq(efa_dev->cm_cq->ib_cq);
		}

		LIBCFS_FREE(efa_dev->cm_cq, sizeof(*efa_dev->cm_cq));
	}
}

static int
kefalnd_create_cqs(struct kefa_dev *efa_dev, int num_cqs, int cq_depth)
{
	int i, rc = 0;

	efa_dev->ncqs = num_cqs;

	LIBCFS_CPT_ALLOC(efa_dev->cm_cq, lnet_cpt_table(), efa_dev->cpt,
			 sizeof(*efa_dev->cm_cq));
	if (!efa_dev->cm_cq) {
		EFA_DEV_ERR(efa_dev,
			    "failed to allocate memory for manager CQ\n");
		return -ENOMEM;
	}

	rc = kefalnd_create_cq(efa_dev, efa_dev->cm_cq, cq_depth);
	if (rc)
		return rc;

	kefalnd_schedule_cq(efa_dev->cm_cq);

	LIBCFS_CPT_ALLOC(efa_dev->cqs, lnet_cpt_table(), efa_dev->cpt,
			 num_cqs * sizeof(*efa_dev->cqs));
	if (!efa_dev->cqs) {
		EFA_DEV_ERR(efa_dev,
			    "failed to allocate memory for data CQs\n");
		kefalnd_destroy_cqs(efa_dev);
		return -ENOMEM;
	}

	for (i = 0; i < num_cqs; i++) {
		struct kefa_cq *cq = &efa_dev->cqs[i];

		rc = kefalnd_create_cq(efa_dev, cq, cq_depth);
		if (rc)
			break;

		kefalnd_schedule_cq(cq);
	}

	if (rc)
		kefalnd_destroy_cqs(efa_dev);

	return rc;
}

static int
kefalnd_dev_query(struct kefa_dev *efa_dev)
{
	int rc;

	rc = efa_dev->ib_dev->ops.query_gid(efa_dev->ib_dev, 0, 0,
					    &efa_dev->gid);
	if (rc) {
		EFA_DEV_ERR(efa_dev,
			    "failed to query EFA device GID. err[%u]\n", rc);
		return rc;
	}

	return 0;
}

static void
kefalnd_destroy_fmr_pool(struct kefa_obj_pool *fmr_pool)
{
	int i;

	if (!fmr_pool || !fmr_pool->obj_arr)
		return;

	for (i = 0; i < fmr_pool->pool_size; i++) {
		struct kefa_fmr *fmr = &((struct kefa_fmr *)fmr_pool->obj_arr)[i];

		if (!IS_ERR_OR_NULL(fmr->mr))
			ib_dereg_mr(fmr->mr);
	}

	LIBCFS_FREE(fmr_pool->obj_arr, fmr_pool->pool_size * sizeof(struct kefa_fmr));
}

static int
kefalnd_create_fmr_pool(struct kefa_ni *efa_ni, struct kefa_dev *efa_dev,
			u32 pool_size)
{
	struct kefa_obj_pool *fmr_pool = &efa_dev->fmr_pool;
	int i, rc = 0;

	memset(fmr_pool, 0, sizeof(*fmr_pool));

	rc = kefalnd_obj_pool_init(efa_ni, fmr_pool, pool_size, efa_dev->cpt,
				   sizeof(struct kefa_fmr));
	if (rc != 0) {
		EFA_DEV_ERR(efa_dev, "can't allocate FMR array\n");
		goto failed;
	}

	for (i = 0; i < pool_size; i++) {
		struct kefa_fmr *fmr = &((struct kefa_fmr *)fmr_pool->obj_arr)[i];

		fmr->mr = ib_alloc_mr(efa_dev->pd, IB_MR_TYPE_MEM_REG,
				      LNET_MAX_IOV);
		if (IS_ERR(fmr->mr)) {
			EFA_DEV_ERR(efa_dev, "failed to alloc mr. err[%ld]\n",
				    PTR_ERR(fmr->mr));
			rc = -ENOSPC;
			goto failed;
		}

		list_add_tail(&fmr->list_node, &fmr_pool->free_obj);
	}

	return 0;

failed:
	kefalnd_destroy_fmr_pool(fmr_pool);
	return rc;
}

static void
kefalnd_dev_destroy(struct kefa_dev *efa_dev, bool put_module)
{
	kefalnd_destroy_fmr_pool(&efa_dev->fmr_pool);

	if (efa_dev->qps)
		kefalnd_destroy_qps(efa_dev);

	if (efa_dev->cqs)
		kefalnd_destroy_cqs(efa_dev);

	if (!IS_ERR_OR_NULL(efa_dev->pd))
		ib_dealloc_pd(efa_dev->pd);

	if (put_module && efa_dev->ib_dev)
		module_put(efa_dev->ib_dev->ops.owner);

	if (efa_dev->ib_dev)
		ib_device_put(efa_dev->ib_dev);

	LIBCFS_FREE(efa_dev, sizeof(*efa_dev));
}

static struct kefa_dev *
kefalnd_dev_init(struct kefa_ni *efa_ni, char *ifname, __be32 ip_addr)
{
	struct lnet_ioctl_config_efalnd_tunables *tunables;
	struct lnet_ni *lnet_ni = efa_ni->lnet_ni;
	struct kefa_dev *efa_dev = NULL;
	bool took_module_ref = false;
	int cq_depth, qp_depth;
	int dev_numa_node, rc;

	CDEBUG(D_NET, "Initializing EFA device\n");

	LIBCFS_ALLOC(efa_dev, sizeof(*efa_dev));
	if (!efa_dev)
		return ERR_PTR(-ENOMEM);

	memset(efa_dev, 0, sizeof(*efa_dev));
	strscpy(efa_dev->ifname, ifname, sizeof(efa_dev->ifname));
	efa_dev->efa_ni = efa_ni;
	efa_dev->ifip = ip_addr;
	efa_dev->ib_dev = ib_device_get_by_name(efa_dev->ifname, RDMA_DRIVER_EFA);
	if (!efa_dev->ib_dev) {
		CERROR("Failed to find EFA IB device %s\n", efa_dev->ifname);
		rc = -ENODEV;
		goto failed;
	}

	if (!efa_dev->ib_dev->kverbs_provider) {
		EFA_DEV_ERR(efa_dev, "EFA driver does not support Kverbs\n");
		rc = -EINVAL;
		goto failed;
	}

	if (!try_module_get(efa_dev->ib_dev->ops.owner)) {
		EFA_DEV_ERR(efa_dev, "Failed to take reference on EFA driver\n");
		rc = -ENODEV;
		goto failed;
	}
	took_module_ref = true;

	rc = kefalnd_dev_query(efa_dev);
	if (rc)
		goto failed;

	dev_numa_node = ibdev_to_node(efa_dev->ib_dev);
	efa_dev->cpt = cfs_cpt_of_node(lnet_cpt_table(), dev_numa_node);
	if (efa_dev->cpt == CFS_CPT_ANY)
		efa_dev->cpt = 0;

	efa_dev->pd = ib_alloc_pd(efa_dev->ib_dev, 0);
	if (IS_ERR(efa_dev->pd)) {
		rc = PTR_ERR(efa_dev->pd);
		EFA_DEV_ERR(efa_dev, "can't allocate PD. err[%d]\n", rc);
		goto failed;
	}

	cq_depth = min(efa_dev->ib_dev->attrs.max_cqe, CQ_DEPTH);
	qp_depth = min(efa_dev->ib_dev->attrs.max_qp_wr, (cq_depth / 2));
	tunables = &lnet_ni->ni_lnd_tunables.lnd_tun_u.lnd_efa;
	rc = kefalnd_create_cqs(efa_dev, tunables->lnd_nqps, cq_depth);
	if (rc)
		goto failed;

	rc = kefalnd_create_qps(efa_dev, tunables->lnd_nqps, qp_depth, qp_depth);
	if (rc)
		goto failed;

	rc = kefalnd_create_fmr_pool(efa_ni, efa_dev,
				     kefalnd_get_tx_pool_size(efa_ni));
	if (rc)
		goto failed;

	return efa_dev;

failed:
	kefalnd_dev_destroy(efa_dev, took_module_ref);
	return ERR_PTR(rc);
}

static struct kefa_dev *
kefalnd_dev_search(char *ifname)
{
	struct kefa_ni *efa_ni;

	list_for_each_entry(efa_ni, &kefalnd.efa_ni_list, lnd_node) {
		if (strncmp(efa_ni->efa_dev->ifname, ifname,
			    sizeof(efa_ni->efa_dev->ifname)) == 0)
			return efa_ni->efa_dev;
	}

	return NULL;
}

static int
kefalnd_select_ipif(struct lnet_ni *ni, __be32 *ip_addr)
{
	char *ipif_name = *kefalnd_tunables.kefa_ipif_name;
	struct lnet_inetdev *ifaces = NULL;
	int i, nip, rc;

	rc = lnet_inet_enumerate(&ifaces, ni->ni_net_ns, false);
	if (rc < 0) {
		rc = -ENODEV;
		goto complete;
	}
	nip = rc;

	if (!ipif_name || strlen(ipif_name) == 0) {
		CDEBUG(D_NET, "Using first interface %s because ipif_name was not provided\n",
		       ifaces[0].li_name);

		if (ifaces[0].li_size != sizeof(*ip_addr)) {
			CERROR("Interface %s is IPv6 interface\n",
			       ifaces[0].li_name);
			rc = -ENODEV;
			goto complete;
		}

		*ip_addr = ifaces[0].li_ipaddr;
		rc = 0;
		goto complete;
	}

	for (i = 0; i < nip; i++) {
		if (strncmp(ipif_name, ifaces[i].li_name,
			    sizeof(ifaces[i].li_name)) == 0) {
			CDEBUG(D_NET, "Found matching interface %s\n",
			       ifaces[i].li_name);

			if (ifaces[i].li_size != sizeof(*ip_addr)) {
				CERROR("Interface %s is IPv6 interface\n",
				       ifaces[i].li_name);

				rc = -ENODEV;
				goto complete;
			}

			*ip_addr = ifaces[i].li_ipaddr;
			rc = 0;
			goto complete;
		}
	}
	CERROR("No interface %s found\n", ipif_name);
	rc = -ENODEV;

complete:
	kfree(ifaces);
	return rc;
}

/**
 * kefalnd_create_efa_nid() - Create EFA NID.
 * @efa_dev: The EFA device.
 *
 * Small NID:
 * The EFA 4 byte NID address is made of three parts: the host
 * identifier, PCI bus number, and PCI devfn number.
 * For example, if a node uses 172.43.23.2@tcp for TCP pings, the
 * EFA interface would be assigned 23.2.0.2@efa for EFA device with
 * bus number 0 and devfn number 2.
 *
 * Large NID:
 * The EFA 16 byte NID address is made of three parts: the device GID,
 * CM QP number and CM QP QKEY.
 *
 */
static void kefalnd_create_efa_nid(struct kefa_ni *efa_ni)
{
	struct lnet_nid *ni_nid = &efa_ni->lnet_ni->ni_nid;
	struct kefa_dev *efa_dev = efa_ni->efa_dev;
	struct kefa_qp *cm_qp = efa_dev->cm_qp;
	struct pci_dev *pci_dev;
	u32 addr;

	if (the_lnet.ln_nis_use_large_nids) {
		kefalnd_large_nid_create(ni_nid, &efa_dev->gid,
					 cm_qp->ib_qp->qp_num,
					 (u16)cm_qp->qkey);
	} else {
		pci_dev = to_pci_dev(efa_dev->ib_dev->dev.parent);
		addr = (__swab32(efa_dev->ifip) & 0xffff) << 16;
		addr = addr | ((pci_dev->bus->number & 0xff) << 8);
		addr = addr | (pci_dev->devfn & 0xff);

		ni_nid->nid_addr[0] = __swab32(addr);
		ni_nid->nid_size = 0;
	}
}

static void
kefalnd_base_shutdown(void)
{
	struct kefa_cm_deamon *cm_daemon;
	struct kefa_sched *sched;
	int i;

	CDEBUG(D_MALLOC, "Before LND cleanup: kmem[%lld]\n",
	       libcfs_kmem_read());

	kefalnd.shutdown = true;

	rcu_barrier();
	rhashtable_destroy(&kefalnd.peer_ni);

	cfs_percpt_for_each(sched, i, kefalnd.scheds)
		wake_up_all(&sched->waitq);

	cfs_percpt_for_each(cm_daemon, i, kefalnd.cm_daemons)
		wake_up_all(&cm_daemon->waitq);

	wait_var_event_warning(&kefalnd.nthreads,
			       !atomic_read(&kefalnd.nthreads),
			       "Waiting for %d threads to terminate\n",
			       atomic_read(&kefalnd.nthreads));

	cfs_percpt_free(kefalnd.scheds);
	cfs_percpt_free(kefalnd.cm_daemons);

	CDEBUG(D_MALLOC, "After LND cleanup: kmem[%lld]\n",
	       libcfs_kmem_read());

	kefalnd.init_state = EFALND_INIT_NONE;
	module_put(THIS_MODULE);
}

/* global initialization of EFA LND data */
static int
kefalnd_base_startup(void)
{
	struct kefa_cm_deamon *cm_daemon;
	struct kefa_sched *sched;
	int nthrs;
	int rc = 0, i;

	LASSERT(kefalnd.init_state == EFALND_INIT_NONE);

	CDEBUG(D_MALLOC, "Before LND startup: kmem[%lld]\n",
	       libcfs_kmem_read());

	/* take a reference count until we clear all module resources */
	if (!try_module_get(THIS_MODULE)) {
		rc = -ENETDOWN;
		goto failed;
	}

	memset(&kefalnd, 0, sizeof(kefalnd));
	INIT_LIST_HEAD(&kefalnd.efa_ni_list);
	rc = rhashtable_init(&kefalnd.peer_ni, &peer_ni_params);
	if (rc)
		goto failed;

	/* allocate a shceduler per NUMA node (cpt) */
	kefalnd.scheds = cfs_percpt_alloc(lnet_cpt_table(), sizeof(*sched));
	if (!kefalnd.scheds) {
		rc = -ENOMEM;
		goto hash_failed;
	}

	cfs_percpt_for_each(sched, i, kefalnd.scheds) {
		spin_lock_init(&sched->lock);

		nthrs = cfs_cpt_weight(lnet_cpt_table(), i);
		if (*kefalnd_tunables.kefa_nscheds > 0) {
			nthrs = min(nthrs, *kefalnd_tunables.kefa_nscheds);
		} else {
			/*
			 * Max to half of CPUs, another half is reserved for
			 * upper layer modules.
			 */
			nthrs = min(max(EFALND_MIN_SCHED_THRS, nthrs >> 1), nthrs);
		}

		sched->nthreads_max = nthrs;
		sched->cpt = i;
		INIT_LIST_HEAD(&sched->pend_cqs);
		init_waitqueue_head(&sched->waitq);
	}

	/* allocate a connection manager daemon per NUMA node (cpt) */
	kefalnd.cm_daemons = cfs_percpt_alloc(lnet_cpt_table(), sizeof(*cm_daemon));
	if (!kefalnd.cm_daemons) {
		rc = -ENOMEM;
		goto hash_failed;
	}

	cfs_percpt_for_each(cm_daemon, i, kefalnd.cm_daemons) {
		cm_daemon->cpt = i;
		cm_daemon->iter = 0;
		mutex_init(&cm_daemon->ni_list_lock);
		INIT_LIST_HEAD(&cm_daemon->efa_ni_list);
		init_waitqueue_head(&cm_daemon->waitq);
	}

	CDEBUG(D_MALLOC, "After LND startup: kmem[%lld]\n",
	       libcfs_kmem_read());

	kefalnd.init_state = EFALND_INIT_ALL;
	kefalnd.shutdown = false;
	return 0;

hash_failed:
	rhashtable_destroy(&kefalnd.peer_ni);
failed:
	if (kefalnd.scheds)
		cfs_percpt_free(kefalnd.scheds);

	return rc;
}

static void
kefalnd_shutdown(struct lnet_ni *ni)
{
	struct kefa_ni *efa_ni = ni->ni_data;
	struct kefa_dev *efa_dev = efa_ni->efa_dev;

	LASSERT(kefalnd.init_state == EFALND_INIT_ALL);

	CDEBUG(D_MALLOC, "Before NI[%s] cleanup: kmem[%lld]\n",
	       libcfs_nidstr(&ni->ni_nid), libcfs_kmem_read());

	if (!list_empty(&efa_ni->cm_node))
		kefalnd_del_ni_from_cm_daemon(efa_ni);

	if (efa_ni->self_peer_ni)
		kefalnd_put_peer_ni(efa_ni->self_peer_ni);

	/* remove network resources - connections pools, etc */
	kefalnd_destroy_tx_pool(efa_ni);
	kefalnd_destroy_all_conns(efa_ni);

	/* Remove the underlaying device if exists */
	if (efa_dev)
		kefalnd_dev_destroy(efa_dev, true);

	if (!list_empty(&efa_ni->lnd_node))
		list_del_init(&efa_ni->lnd_node);

	/* remove the NI itself */
	ni->ni_data = NULL;
	LIBCFS_FREE(efa_ni, sizeof(*efa_ni));

	CDEBUG(D_MALLOC, "After NI[%s] cleanup: kmem[%lld]\n",
	       libcfs_nidstr(&ni->ni_nid), libcfs_kmem_read());

	/* if there are no more NIs - destroy the global efalnd */
	if (list_empty(&kefalnd.efa_ni_list))
		kefalnd_base_shutdown();
}

static int
kefalnd_startup(struct lnet_ni *ni)
{
	struct kefa_dev *efa_dev;
	struct kefa_ni *efa_ni;
	__be32 ip_addr;
	char *ifname;
	int rc;

	if (kefalnd.init_state == EFALND_INIT_NONE) {
		rc = kefalnd_base_startup();
		if (rc != 0)
			return rc;
	}

	CDEBUG(D_MALLOC, "Before NI startup: kmem[%lld]\n", libcfs_kmem_read());

	LIBCFS_ALLOC(efa_ni, sizeof(*efa_ni));
	if (!efa_ni) {
		CERROR("Failed to allocate memory for EFA network\n");
		return -ENOMEM;
	}

	memset(efa_ni, 0, sizeof(*efa_ni));
	ni->ni_data = efa_ni;
	efa_ni->lnet_ni = ni;
	efa_ni->ni_epoch = ktime_get_real_ns();
	hash_init(efa_ni->conns);
	rwlock_init(&efa_ni->conn_lock);
	INIT_LIST_HEAD(&efa_ni->lnd_node);
	INIT_LIST_HEAD(&efa_ni->cm_node);

	if (ni->ni_interface) {
		ifname = ni->ni_interface;
	} else {
		CERROR("Missing interface name\n");
		rc = -EINVAL;
		goto failed;
	}

	kefalnd_tunables_setup(ni);

	rc = kefalnd_select_ipif(ni, &ip_addr);
	if (rc < 0) {
		goto failed;
	}

	efa_dev = kefalnd_dev_search(ifname);
	if (efa_dev) {
		CERROR("Device[%s] already exists\n", ifname);
		rc = -EINVAL;
		goto failed;
	}

	/* initialize the device */
	efa_dev = kefalnd_dev_init(efa_ni, ifname, ip_addr);
	if (IS_ERR(efa_dev)) {
		rc = PTR_ERR(efa_dev);
		CERROR("Failed to initialize device[%s]. err[%d]\n", ifname, rc);
		goto failed;
	}

	efa_ni->efa_dev = efa_dev;
	ni->ni_dev_cpt = efa_dev->cpt;

	kefalnd_create_efa_nid(efa_ni);
	if (nid_is_nid4(&ni->ni_nid)) {
		efa_ni->self_peer_ni =
			kefalnd_lookup_or_create_peer_ni(lnet_nid_to_nid4(&ni->ni_nid),
							 &efa_dev->gid,
							 efa_dev->cm_qp->ib_qp->qp_num,
							 efa_dev->cm_qp->qkey);
		if (!efa_ni->self_peer_ni) {
			rc = -ENODEV;
			goto failed;
		}
	}

	rc = kefalnd_create_tx_pool(efa_ni, efa_dev->cpt);
	if (rc != 0)
		goto failed;

	rc = kefalnd_dev_start_threads(efa_dev);
	if (rc != 0)
		goto failed;

	kefalnd_add_ni_to_cm_daemon(efa_ni);
	list_add_tail(&efa_ni->lnd_node, &kefalnd.efa_ni_list);

	CDEBUG(D_MALLOC, "After NI[%s] startup: kmem[%lld]\n",
	       ni->ni_interface, libcfs_kmem_read());

	LCONSOLE_INFO("Started NI[%s] EFA device[%s] FW[0x%llx] LND[%s] CPT[%d]\n",
		      libcfs_nidstr(&ni->ni_nid), efa_dev->ifname,
		      efa_dev->ib_dev->attrs.fw_ver,
		      DRV_MODULE_VERSION, efa_dev->cpt);

	return 0;

failed:
	kefalnd_shutdown(ni);
	return rc;
}

static const struct lnet_lnd the_efalnd = {
	.lnd_type		= EFALND,
	.lnd_startup		= kefalnd_startup,
	.lnd_shutdown		= kefalnd_shutdown,
	.lnd_send		= kefalnd_send,
	.lnd_recv		= kefalnd_recv,
	.lnd_get_dev_prio	= kefalnd_get_dev_prio,
	.lnd_get_nid_metadata	= kefalnd_get_nid_metadata,

};

static void __exit kefalnd_exit(void)
{
	CDEBUG(D_NET, "Exiting EFA LND\n");

	kefalnd_debugfs_exit();

	lnet_unregister_lnd(&the_efalnd);
}

static int __init kefalnd_init(void)
{
	int rc;

	memset(&kefalnd, 0, sizeof(kefalnd));

	CDEBUG(D_NET, "Entering EFA LND\n");
	rc = kefalnd_tunables_init();
	if (rc) {
		CERROR("failed to init tunables\n");
		return rc;
	}

	kefalnd_debugfs_init();

	lnet_register_lnd(&the_efalnd);
	return 0;
}

MODULE_SOFTDEP("pre: efa");

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("EFA LNet Network Driver");
MODULE_VERSION(DRV_MODULE_VERSION);
MODULE_LICENSE("GPL");

module_init(kefalnd_init);
module_exit(kefalnd_exit);
