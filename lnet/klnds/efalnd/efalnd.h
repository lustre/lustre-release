/* SPDX-License-Identifier: GPL-2.0 */

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

#ifndef _EFALND_EFALND_H_
#define _EFALND_EFALND_H_

#define DEBUG_SUBSYSTEM S_LND

#include <linux/bvec.h>
#include <linux/rhashtable.h>

#include <lnet/lib-lnet.h>
#include <lnet/lib-types.h>
#include <lnet/lnet_rdma.h>

#include <efa_verbs.h>

#include "efalnd_proto.h"

#define EFALND_MAJOR_VER        1
#define EFALND_MINOR_VER        2
#define EFALND_SUBMINOR_VER     0
#define EFALND_MAJOR_SHIFT	8

#define KEFA_IFNAME_SIZE		256
#define EFALND_CREDITS_MIN		8	/* Min # of peer_ni credits */
#define EFALND_CREDITS_MAX		255	/* Max # of peer_ni credits */

#define KEFA_THREAD_SHIFT		16
#define KEFA_THREAD_ID(cpt, tid)	((cpt) << KEFA_THREAD_SHIFT | (tid))
#define KEFA_THREAD_CPT(id)		((id) >> KEFA_THREAD_SHIFT)
#define KEFA_THREAD_TID(id)		((id) & ((1UL << KEFA_THREAD_SHIFT) - 1))

#define EFALND_MAX_MTU			(8900)
#define EFALND_MSG_SIZE			EFALND_MAX_MTU
#define EFALND_MSG_SIZE_ALIGNED		PAGE_ALIGN(EFALND_MSG_SIZE)
#define EFALND_MSG_PAGES		(EFALND_MSG_SIZE_ALIGNED / PAGE_SIZE)
#define EFALND_RX_MSGS(q)		(2 * (q)->rq_depth)

/* max # of fragments supported. + 1 for unaligned case */
#define EFALND_MAX_TX_FRAGS		(LNET_MAX_IOV + 1)

/* Max # of TXs each NI can allocate. */
#define EFALND_MAX_NI_TX_POOL		2048

/* default values in case no tunable was set */
#define EFALND_MIN_SCHED_THRS		2
#define EFALND_MAX_SCHED_THRS		4

 /* Used only for small NIDs */
#define EFALND_CM_STATIC_QKEY		(0x1111)

#define EFALND_NO_RDMA_THRESH		EFALND_MSG_SIZE

#define EFALND_CONN_HASH_BITS		7

#define EFALND_INV_CONN			((u32)~0U)

#define EFALND_MAX_PEER_QPS		256

#define EFALND_MIN_INIT_CONN_TIMEOUT	200

/*
 * NI large NID is of the following format:
 * |15            4|3       2|1         0|
 * +---------------+---------+-----------+
 * |      GID      | QP QKEY | QP Number |
 * +---------------+---------+-----------+
 * GID: EFA GID is 16 bytes with bytes 0-3 always constant.
 * QP Number: CM QP number for the remote to be able to establish connection.
 * QP QKEY: 2 byte QKEY to fit in the available area in EFA GID.
 */
#define EFALND_NID_CM_QP_NUM_OFFSET	0
#define EFALND_NID_CM_QP_NUM_SIZE	2
#define EFALND_NID_CM_QP_QKEY_OFFSET	2
#define EFALND_NID_CM_QP_QKEY_SIZE	2
#define EFALND_NID_GID_OFFSET		4
#define EFALND_NID_GID_SIZE		12

/* Define EFALND_CD so that we can easily add D_CONSOLE in test envs */
#define EFALND_CD (D_NET)

#define EFALND_FIELD_AVAIL(type, fld, sz) (offsetof(type, fld) < (sz))

#define EFA_DEV_DEBUG(dev, format, ...) CDEBUG(EFALND_CD, "Device[%s] " format, (dev)->ifname, ## __VA_ARGS__)
#define EFA_DEV_ERR(dev, format, ...) CERROR("Device[%s] " format, (dev)->ifname, ## __VA_ARGS__)
#define EFA_DEV_WARN(dev, format, ...) CWARN("Device[%s] " format, (dev)->ifname, ## __VA_ARGS__)

struct kefa_cq;
struct kefa_qp;
struct kefa_dev;
struct kefa_ni;
struct kefa_sched;
struct kefa_conn;
struct kefa_obj_pool;

extern struct kefa_tunables kefalnd_tunables;
extern struct kefa_data kefalnd;

enum efalnd_init_state {
	EFALND_INIT_NONE = 0,
	EFALND_INIT_ALL
};

struct kefa_remote_qp {
	u16 qp_num;
	u32 qkey;
};

struct kefa_peer_ni {
	struct kref refcount;             /* number of connections */
	u32 remote_nid_addr;              /* address of EFA NID */
	union ib_gid gid;
	struct kefa_remote_qp cm_qp;
	struct rhash_head linkage;
	rwlock_t peer_ni_lock;            /* protects kefa_peer_ni data */
	struct rcu_head rcu_read;         /* protects nid_gid_map lifetime */
};

static const struct rhashtable_params peer_ni_params = {
	.key_len     = sizeof(u32),
	.key_offset  = offsetof(struct kefa_peer_ni, remote_nid_addr),
	.head_offset = offsetof(struct kefa_peer_ni, linkage),
};

struct kefa_tunables {
	int *kefa_rnr_retry_count;
	/* # threads on each CPT */
	int *kefa_nscheds;
	char **kefa_ipif_name;
};

/* global singelton EFA data */
struct kefa_data {
	enum efalnd_init_state init_state;	/* init state of global data */
	struct list_head efa_ni_list;		/* list of EFA NIs */
	struct kefa_sched **scheds;		/* global schedulers */
	struct kefa_cm_deamon **cm_daemons;	/* Connection manager daemons */
	struct rhashtable peer_ni;
	atomic_t peer_ni_count;
	atomic_t nthreads;			/* # live threads */
	bool shutdown;				/* signal shutdown to threads */
};

struct kefa_obj_pool {
	struct kefa_ni *efa_ni;
	void *obj_arr;
	struct list_head free_obj;
	struct list_head free_pend_obj;	/* Objects pending to be freed */
	atomic_t pending_work;		/* Pending list have objects on */
	spinlock_t lock;		/* multithread lock */
	u32 pool_size;
	int cpt;
};

struct kefa_rx {
	struct list_head list_node;
	struct kefa_qp *qp;		/* owner QP */
	struct kefa_msg *msg;		/* message buffer (host vaddr) */
	struct ib_recv_wr wrq;		/* receive work item... */
	struct ib_sge sge;		/* ...and its memory */
	int rx_nob;			/* # bytes received (-1 while posted) */
};

struct kefa_qp {
	struct kefa_dev *efa_dev;
	struct kefa_cq *cq;
	struct ib_qp *ib_qp;
	struct kefa_rx *rx_msgs;	/* RX buffers posted to RQ */
	struct list_head posted_rx;	/* list of posted RX */
	struct list_head free_rx;	/* list of free RX */
	spinlock_t rq_lock;
	u32 rq_depth;
	u32 rq_space;
	u32 qkey;
};

struct kefa_cq {
	struct ib_cq *ib_cq;
	struct kefa_dev *efa_dev;	/* owner device */
	struct list_head sched_node;	/* node on scheduler */
	int cpt;
};

enum kefa_fmr_state {
	KEFA_FMR_INACTIVE = 0,
	KEFA_FMR_ACTIVATING,
	KEFA_FMR_ACTIVE,
	KEFA_FMR_DEACTIVATING,
};

struct kefa_fmr {
	struct ib_mr *mr;
	enum kefa_fmr_state state;
	struct list_head list_node;
	struct ib_reg_wr reg_wr;
	struct ib_send_wr inv_wr;
};

/* EFA device information */
struct kefa_dev {
	struct ib_device *ib_dev;
	char ifname[KEFA_IFNAME_SIZE];
	struct kefa_ni *efa_ni;	/* The EFA NI associated with the device */
	union ib_gid gid;
	struct ib_pd *pd;		/* PD */

	struct kefa_obj_pool fmr_pool;

	struct kefa_qp *qps;		/* QP set */
	atomic_t local_qpn;

	struct kefa_cq *cqs;		/* CQ set */

	struct kefa_qp *cm_qp;		/* Connection establishment QP */
	struct kefa_cq *cm_cq;

	__be32 ifip;			/* Eth interface IP */
	u32 nqps;
	u32 ncqs;
	int cpt;			/* CPU partition of the device */
};

/* transmit message */
struct kefa_tx {
	struct list_head list_node;	/* node on pool/conn list */
	struct kefa_obj_pool *tx_pool;	/* pool I'm from */
	struct kefa_conn *conn;		/* connection for TX */
	struct lnet_msg *lntmsg[2]; /* lnet msgs to finalize on completion */
	struct kefa_msg *msg;		/* message buffer (host vaddr) */
	dma_addr_t msgaddr;		/* message buffer (I/O addr) */
	struct ib_srd_rdma_wr wrq;	/* send work item... */
	struct ib_sge sge;		/* ...and its memory */
	u32 lkey;			/* lkey of sge buffers */
	enum lnet_msg_hstatus hstatus;	/* health status of tx */
	int status;			/* overall status */
	int nfrags;			/* # of mapped buffer fragments */
	struct scatterlist *frags;	/* mapped buffer fragments */
	struct kefa_rdma_desc rdma_desc;/* rdma descriptor to read/write */
	enum dma_data_direction dmadir;
	atomic_t ref_cnt;		/* track sends and completions */
	atomic_t waiting_resp;
	struct kefa_fmr *fmr;
	atomic64_t send_time;		/* send time of send in seconds */

	u8 type;
	bool send_sync;		/* send ctrl message after RDMA completes */
	u64 cookie;		/* opaque completion cookie for sync message */
};

/* Per Lnet network data */
struct kefa_ni {
	struct list_head lnd_node;	/* node in LND NI list */
	struct list_head cm_node;	/* node in connection manager daemon */
	struct kefa_dev *efa_dev;	/* underlying IB device */
	struct lnet_ni *lnet_ni;	/* LNet interface */
	u64 ni_epoch;			/* my epoch */
	struct kefa_obj_pool tx_pool;
	DECLARE_HASHTABLE(conns, EFALND_CONN_HASH_BITS);
	rwlock_t conn_lock;
	struct kefa_peer_ni *self_peer_ni;	/* Only valid for small NID NI*/
};

enum kefa_conn_state {
	KEFA_CONN_INACTIVE,
	KEFA_CONN_PROBE_TCP,
	KEFA_CONN_PROBE_EFA,
	KEFA_CONN_PROBE_EFA_PASSIVE,
	KEFA_CONN_ESTABLISH,
	KEFA_CONN_ACTIVE,
	KEFA_CONN_DEACTIVATING,
};

enum kefa_conn_type {
	KEFA_CONN_TYPE_LB,
	KEFA_CONN_TYPE_INITIATOR,
	KEFA_CONN_TYPE_RESPONDER,
};

struct kefa_conn {
	spinlock_t lock;
	enum kefa_conn_state state;
	struct list_head active_tx;	/* LRU list of active kefa_tx */
	struct list_head pend_tx;	/* list of pending kefa_tx */

	/* Fields that can be changed not under connection lock */
	struct ib_ah *ah;
	u64 remote_epoch;		/*The epoch of the remote connection */
	u8 proto_ver;
	u32 nqps;
	struct kefa_remote_qp *data_qps;
	atomic_t last_qp_idx;
	struct lnet_nid remote_nid;
	time64_t last_use_time;	/* last time the conn was used in seconds */
	struct hlist_node ni_node;	/* node on kefa_ni hashmap */
	struct kefa_ni *efa_ni;

	/* Low frequency fields */
	struct list_head abort_tx;	/* Only CM iterates this list */
	enum kefa_conn_type type;
	struct lnet_nid local_nid;
	struct kefa_peer_ni *peer_ni; /* my peer NI - only valid for small NID*/
	u64 remote_caps;
	u64 requests;
};

struct kefa_cm_deamon {
	struct mutex ni_list_lock;	/* multithread lock */
	struct list_head efa_ni_list;	/* list of EFA NIs */
	wait_queue_head_t waitq;
	bool active;
	int iter;
	int cpt;
};

struct kefa_sched {
	spinlock_t lock;		/* multithread lock */
	struct list_head pend_cqs;	/* CQs to poll */
	wait_queue_head_t waitq;
	int nthreads;			/* # of poll threads */
	int nthreads_max;		/* max # of threads */
	int cpt;			/* CPT id */
};

static inline u16
kefalnd_get_lnd_version(void)
{
	return ((EFALND_MAJOR_VER << EFALND_MAJOR_SHIFT) | EFALND_MINOR_VER);
}

static inline void
kefalnd_large_nid_create(struct lnet_nid *nid, const union ib_gid *gid,
			 u16 qp_num, u16 qp_qkey)
{
	u16 be_qp_num = cpu_to_be16(qp_num);
	u16 be_qp_qkey = cpu_to_be16(qp_qkey);

	memcpy((u8 *)nid->nid_addr + EFALND_NID_GID_OFFSET,
	       gid->raw + EFALND_NID_GID_OFFSET,
	       EFALND_NID_GID_SIZE);
	memcpy((u8 *)nid->nid_addr + EFALND_NID_CM_QP_NUM_OFFSET, &be_qp_num,
	       EFALND_NID_CM_QP_NUM_SIZE);
	memcpy((u8 *)nid->nid_addr + EFALND_NID_CM_QP_QKEY_OFFSET, &be_qp_qkey,
	       EFALND_NID_CM_QP_QKEY_SIZE);

	nid->nid_size = sizeof(union ib_gid) - 4;
}

static inline void
kefalnd_large_nid_get_gid(struct lnet_nid *nid, union ib_gid *gid)
{
	memcpy(gid->raw, nid->nid_addr, sizeof(gid->raw));
	gid->raw[0] = 0xfe;
	gid->raw[1] = 0x80;
	gid->raw[2] = 0;
	gid->raw[3] = 0;
}

static inline u16
kefalnd_large_nid_get_cm_qp_num(struct lnet_nid *nid)
{
	u16 qp_num;

	memcpy(&qp_num, (u8 *)nid->nid_addr + EFALND_NID_CM_QP_NUM_OFFSET,
	       sizeof(qp_num));

	return be16_to_cpu(qp_num);
}

static inline u16
kefalnd_large_nid_get_cm_qp_qkey(struct lnet_nid *nid)
{
	u16 qp_qkey;

	memcpy(&qp_qkey, (u8 *)nid->nid_addr + EFALND_NID_CM_QP_QKEY_OFFSET,
	       sizeof(qp_qkey));

	return be16_to_cpu(qp_qkey);
}

static inline void
kefalnd_thread_stop(void)
{
	atomic_dec(&kefalnd.nthreads);
}

static inline void
kefalnd_msg_set_epoch(struct kefa_msg *msg, u64 remote_epoch)
{
	if (msg->hdr.proto_ver != EFALND_PROTO_VER_1)
		msg->msg_v2.dst_epoch = remote_epoch;
	else
		msg->msg_v1.dst_epoch = remote_epoch;
}

int kefalnd_tunables_init(void);
int kefalnd_tunables_setup(struct lnet_ni *ni);

int kefalnd_msgtype2size(int type, u8 proto_ver);
int kefalnd_efa_status_to_errno(s16 efa_status);
s16 kefalnd_errno_to_efa_status(int status);
void kefalnd_tx_done(struct kefa_tx *tx);
void kefalnd_abort_tx(struct kefa_tx *tx, enum lnet_msg_hstatus hstatus,
		      int status);
/* Should be used only on TXs that we don't expect to get any completions for */
void kefalnd_force_cancel_tx(struct kefa_tx *tx, enum lnet_msg_hstatus hstatus,
			     int status);
void kefalnd_init_tx_protocol_msg(struct kefa_tx *tx, struct kefa_conn *conn,
				  int type, int body_nob, u8 proto_ver);
struct kefa_tx *kefalnd_get_idle_tx(struct kefa_ni *efa_ni);
void kefalnd_conn_post_tx_locked(struct kefa_conn *conn);
void kefalnd_get_srcnid_from_msg(struct kefa_msg *msg, struct lnet_nid *srcnid);
void kefalnd_get_dstnid_from_msg(struct kefa_msg *msg, struct lnet_nid *dstnid);

struct kefa_peer_ni *kefalnd_find_remote_peer_ni(struct kefa_dev *efa_dev,
						 struct lnet_nid *efa_nid);
struct kefa_peer_ni *kefalnd_lookup_or_create_peer_ni(lnet_nid_t nid,
						      union ib_gid *gid,
						      u16 cm_qpn, u32 cm_qkey);
void kefalnd_update_peer_ni(struct kefa_peer_ni *peer_ni, union ib_gid *gid,
			    u16 cm_qpn, u32 cm_qkey);
int kefalnd_get_nid_metadata(struct lnet_ni *ni,
			     struct lnet_nid_md_entry *md_entry);
void kefalnd_put_peer_ni(struct kefa_peer_ni *peer_ni);

void kefalnd_debugfs_init(void);
void kefalnd_debugfs_exit(void);

struct kefa_conn *kefalnd_lookup_conn(struct kefa_ni *efa_ni,
				      struct lnet_nid *nid,
				      enum kefa_conn_type conn_type);
struct kefa_conn *kefalnd_lookup_or_init_conn(struct kefa_ni *efa_ni,
					      struct lnet_nid *nid,
					      enum kefa_conn_type conn_type);
void kefalnd_handle_conn_establishment(struct kefa_ni *efa_ni,
				       struct kefa_msg *msg);
void kefalnd_deactivate_conn(struct kefa_conn *conn);
void kefalnd_destroy_conn(struct kefa_conn *conn, enum lnet_msg_hstatus hstatus,
			  int status);
int kefalnd_cm_daemon(void *arg);
void kefalnd_add_ni_to_cm_daemon(struct kefa_ni *efa_ni);
void kefalnd_del_ni_from_cm_daemon(struct kefa_ni *efa_ni);

#endif
