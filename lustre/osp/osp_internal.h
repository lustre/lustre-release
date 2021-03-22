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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osp/osp_internal.h
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 */

#ifndef _OSP_INTERNAL_H
#define _OSP_INTERNAL_H

#include <obd.h>
#include <obd_class.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <lustre_update.h>
#include <lu_target.h>

/*
 * Infrastructure to support tracking of last committed llog record
 */
struct osp_id_tracker {
	spinlock_t		 otr_lock;
	__u64			 otr_next_id;
	__u64			 otr_committed_id;
	/* callback is register once per diskfs -- that's the whole point */
	struct dt_txn_callback	 otr_tx_cb;
	/* single node can run many clusters */
	struct list_head	 otr_wakeup_list;
	struct list_head	 otr_list;
	/* underlying shared device */
	struct dt_device	*otr_dev;
	/* how many users of this tracker */
	atomic_t		 otr_refcount;
};

struct osp_precreate {
	/*
	 * Precreation pool
	 */

	/* last fid to assign in creation */
	struct lu_fid			 osp_pre_used_fid;
	/* last created id OST reported, next-created - available id's */
	struct lu_fid			 osp_pre_last_created_fid;
	/* how many ids are reserved in declare, we shouldn't block in create */
	__u64				 osp_pre_reserved;
	/* consumers (who needs new ids) wait here */
	wait_queue_head_t		 osp_pre_user_waitq;
	/* current precreation status: working, failed, stopping? */
	int				 osp_pre_status;
	/* how many objects to precreate next time */
	int				 osp_pre_create_count;
	int				 osp_pre_min_create_count;
	int				 osp_pre_max_create_count;
	/* whether to increase precreation window next time or not */
	int				 osp_pre_create_slow;
	/* cleaning up orphans or recreating missing objects */
	int				 osp_pre_recovering;
};

struct osp_update_request_sub {
	struct object_update_request	*ours_req; /* may be vmalloc'd */
	size_t				ours_req_size;
	/* Linked to osp_update_request->our_req_list */
	struct list_head		ours_list;
};

struct osp_update_request {
	int				our_flags;
	/* update request result */
	int				our_rc;

	/* List of osp_update_request_sub */
	struct list_head		our_req_list;
	int				our_req_nr;
	int				our_update_nr;

	struct list_head		our_cb_items;
	struct list_head		our_invalidate_cb_list;

	/* points to thandle if this update request belongs to one */
	struct osp_thandle		*our_th;

	__u64				our_version;
	__u64				our_generation;
	/* protect our_list and flag */
	spinlock_t			our_list_lock;
	/* linked to the list(ou_list) in osp_updates */
	struct list_head		our_list;
	__u32				our_batchid;
	__u32				our_req_ready:1;

};

struct osp_updates {
	struct list_head	ou_list;
	spinlock_t		ou_lock;
	wait_queue_head_t	ou_waitq;

	/* The next rpc version which supposed to be sent in
	 * osp_send_update_thread().*/
	__u64			ou_rpc_version;

	/* The rpc version assigned to the osp thandle during (osp_md_write()),
	 * which will be sent by this order. Note: the osp_thandle has be sent
	 * by this order to make sure the remote update log will follow the
	 * llog format rule. XXX: these probably should be removed once we
	 * invent new llog format */
	__u64			ou_version;

	/* The generation of current osp update RPC, which is used to make sure
	 * those stale RPC(with older generation) will not be sent, otherwise it
	 * will cause update lllog corruption */
	__u64			ou_generation;

	/* dedicate update thread */
	struct task_struct	*ou_update_task;
	struct lu_env		ou_env;
};

struct osp_rpc_lock {
	/** Lock protecting in-flight RPC concurrency. */
	struct mutex		rpcl_mutex;
	/** Used for MDS/RPC load testing purposes. */
	unsigned int		rpcl_fakes;
};

struct osp_device {
	struct dt_device		 opd_dt_dev;
	/* corresponded OST index */
	int				 opd_index;

	/* corrsponded MDT index, which will be used when connecting to OST
	 * for validating the connection (see ofd_parse_connect_data) */
	int				 opd_group;
	/* device used to store persistent state (llogs, last ids) */
	struct obd_export		*opd_storage_exp;
	struct dt_device		*opd_storage;
	struct dt_object		*opd_last_used_oid_file;
	struct dt_object		*opd_last_used_seq_file;

	/* stored persistently in LE format, updated directly to/from disk
	 * and required le64_to_cpu() conversion before use.
	 * Protected by opd_pre_lock */
	struct lu_fid			opd_last_used_fid;
	/* on disk copy last_used_fid.f_oid or idif */
	u64				opd_last_id;
	struct lu_fid			opd_gap_start_fid;
	int				 opd_gap_count;
	/* connection to OST */
	struct osp_rpc_lock		 opd_rpc_lock;
	struct obd_device		*opd_obd;
	struct obd_export		*opd_exp;
	struct obd_connect_data		*opd_connect_data;
	int				 opd_connects;
	/* connection status. */
	unsigned int			 opd_new_connection:1,
					 opd_got_disconnected:1,
					 opd_imp_connected:1,
					 opd_imp_active:1,
					 opd_imp_seen_connected:1,
					 opd_connect_mdt:1;

	/* whether local recovery is completed:
	 * reported via ->ldo_recovery_complete() */
	int				 opd_recovery_completed;

	/* precreate structure for OSP */
	struct osp_precreate		*opd_pre;
	/* dedicate precreate thread */
	struct task_struct		*opd_pre_task;
	spinlock_t			 opd_pre_lock;
	/* thread waits for signals about pool going empty */
	wait_queue_head_t		 opd_pre_waitq;

	/* send update thread */
	struct osp_updates		*opd_update;

	/*
	 * OST synchronization thread
	 */
	spinlock_t			 opd_sync_lock;
	/* unique generation, to recognize start of new records in the llog */
	struct llog_gen			 opd_sync_generation;
	/* number of changes to sync, used to wake up sync thread */
	atomic_t			 opd_sync_changes;
	/* processing of changes from previous mount is done? */
	int				 opd_sync_prev_done;
	/* found records */
	struct task_struct		*opd_sync_task;
	wait_queue_head_t		 opd_sync_waitq;
	/* list of in flight rpcs */
	struct list_head		 opd_sync_in_flight_list;
	/* list of remotely committed rpc */
	struct list_head		 opd_sync_committed_there;
	/* number of RPCs in flight - flow control */
	atomic_t			 opd_sync_rpcs_in_flight;
	int				 opd_sync_max_rpcs_in_flight;
	/* number of RPC in processing (including non-committed by OST) */
	atomic_t			 opd_sync_rpcs_in_progress;
	int				 opd_sync_max_rpcs_in_progress;
	/* osd api's commit cb control structure */
	struct dt_txn_callback		 opd_sync_txn_cb;
	/* last used change number -- semantically similar to transno */
	unsigned long			 opd_sync_last_used_id;
	/* last committed change number -- semantically similar to
	 * last_committed */
	__u64				 opd_sync_last_committed_id;
	/* last processed catalog index */
	int                              opd_sync_last_catalog_idx;
	/* number of processed records */
	atomic64_t			 opd_sync_processed_recs;
	/* stop processing new requests until barrier=0 */
	atomic_t			 opd_sync_barrier;
	wait_queue_head_t		 opd_sync_barrier_waitq;
	/* last generated id */
	ktime_t				 opd_sync_next_commit_cb;
	atomic_t			 opd_commits_registered;

	/*
	 * statfs related fields: OSP maintains it on its own
	 */
	struct obd_statfs		 opd_statfs;
	ktime_t				 opd_statfs_fresh_till;
	struct timer_list		 opd_statfs_timer;
	int				 opd_statfs_update_in_progress;
	/* how often to update statfs data */
	time64_t			 opd_statfs_maxage;

	struct dentry			*opd_debugfs;

	/* If the caller wants to do some idempotent async operations on
	 * remote server, it can append the async remote requests on the
	 * osp_device::opd_async_requests via declare() functions, these
	 * requests can be packed together and sent to the remote server
	 * via single OUT RPC later. */
	struct osp_update_request	*opd_async_requests;
	/* Protect current operations on opd_async_requests. */
	struct mutex			 opd_async_requests_mutex;
	struct list_head		 opd_async_updates;
	struct rw_semaphore		 opd_async_updates_rwsem;
	atomic_t			 opd_async_updates_count;

	/*
	 * Limit the object allocation using ENOSPC for opd_pre_status
	 */
	int				opd_reserved_mb_high;
	int				opd_reserved_mb_low;
};

#define opd_pre_used_fid		opd_pre->osp_pre_used_fid
#define opd_pre_last_created_fid	opd_pre->osp_pre_last_created_fid
#define opd_pre_reserved		opd_pre->osp_pre_reserved
#define opd_pre_user_waitq		opd_pre->osp_pre_user_waitq
#define opd_pre_status			opd_pre->osp_pre_status
#define opd_pre_create_count		opd_pre->osp_pre_create_count
#define opd_pre_min_create_count	opd_pre->osp_pre_min_create_count
#define opd_pre_max_create_count	opd_pre->osp_pre_max_create_count
#define opd_pre_create_slow		opd_pre->osp_pre_create_slow
#define opd_pre_recovering		opd_pre->osp_pre_recovering

extern struct kmem_cache *osp_object_kmem;

/* The first part of oxe_buf is xattr name, and is '\0' terminated.
 * The left part is for value, binary mode. */
struct osp_xattr_entry {
	struct list_head	 oxe_list;
	atomic_t		 oxe_ref;
	void			*oxe_value;
	size_t			 oxe_buflen;
	size_t			 oxe_namelen;
	size_t			 oxe_vallen;
	unsigned int		 oxe_exist:1,
				 oxe_ready:1;
	char			 oxe_buf[0];
};

/* this is a top object */
struct osp_object {
	struct lu_object_header	opo_header;
	struct dt_object	opo_obj;
	unsigned int		opo_reserved:1,
				opo_non_exist:1,
				opo_stale:1;

	/* read/write lock for md osp object */
	struct rw_semaphore	opo_sem;
	const struct lu_env	*opo_owner;
	struct lu_attr		opo_attr;
	struct list_head	opo_xattr_list;
	struct list_head	opo_invalidate_cb_list;
	/* Protect opo_ooa. */
	spinlock_t		opo_lock;
	/* to implement in-flight invalidation */
	atomic_t		opo_invalidate_seq;
	struct rw_semaphore	opo_invalidate_sem;
};

extern const struct lu_object_operations osp_lu_obj_ops;
extern const struct dt_object_operations osp_md_obj_ops;
extern const struct dt_body_operations osp_md_body_ops;

struct osp_thread_info {
	struct lu_buf		 osi_lb;
	struct lu_buf		 osi_lb2;
	struct lu_fid		 osi_fid;
	struct lu_attr		 osi_attr;
	struct ost_id		 osi_oi;
	struct ost_id		 osi_oi2;
	loff_t			 osi_off;
	union {
		struct llog_rec_hdr		osi_hdr;
		struct llog_unlink64_rec	osi_unlink;
		struct llog_setattr64_rec_v2	osi_setattr;
		struct llog_gen_rec		osi_gen;
	};
	struct llog_cookie	 osi_cookie;
	struct llog_catid	 osi_cid;
	struct lu_seq_range	 osi_seq;
	struct ldlm_res_id	 osi_resid;
	struct obdo		 osi_obdo;
};

/* Iterator for OSP */
struct osp_it {
	__u32			  ooi_pos_page;
	__u32			  ooi_pos_lu_page;
	__u32			  ooi_attr;
	__u32			  ooi_rec_size;
	int			  ooi_pos_ent;
	int			  ooi_total_npages;
	int			  ooi_valid_npages;
	unsigned int		  ooi_swab:1;
	__u64			  ooi_next;
	struct dt_object	 *ooi_obj;
	void			 *ooi_ent;
	struct page		 *ooi_cur_page;
	struct lu_idxpage	 *ooi_cur_idxpage;
	struct page		 **ooi_pages;
};

#define OSP_THANDLE_MAGIC	0x20141214
struct osp_thandle {
	struct thandle		 ot_super;

	/* OSP will use this thandle to update last oid*/
	struct thandle		*ot_storage_th;
	__u32			 ot_magic;
	struct list_head	 ot_commit_dcb_list;
	struct list_head	 ot_stop_dcb_list;
	struct osp_update_request *ot_our;
	atomic_t		 ot_refcount;
};

static inline struct osp_thandle *
thandle_to_osp_thandle(struct thandle *th)
{
	return container_of(th, struct osp_thandle, ot_super);
}

static inline struct osp_update_request *
thandle_to_osp_update_request(struct thandle *th)
{
	struct osp_thandle *oth;

	oth = thandle_to_osp_thandle(th);
	return oth->ot_our;
}

/* The transaction only include the updates on the remote node, and
 * no local updates at all */
static inline bool is_only_remote_trans(struct thandle *th)
{
	return th->th_top == NULL;
}

static inline void osp_objid_buf_prep(struct lu_buf *buf, loff_t *off,
				      __u64 *id, int index)
{
	/* Note: through id is only 32 bits, it will also write 64 bits
	 * for oid to keep compatibility with the previous version. */
	buf->lb_buf = (void *)id;
	buf->lb_len = sizeof(u64);
	*off = sizeof(u64) * index;
}

static inline void osp_objseq_buf_prep(struct lu_buf *buf, loff_t *off,
				       __u64 *seq, int index)
{
	buf->lb_buf = (void *)seq;
	buf->lb_len = sizeof(u64);
	*off = sizeof(u64) * index;
}

static inline void osp_buf_prep(struct lu_buf *lb, void *buf, int buf_len)
{
	lb->lb_buf = buf;
	lb->lb_len = buf_len;
}

extern struct lu_context_key osp_thread_key;

static inline struct osp_thread_info *osp_env_info(const struct lu_env *env)
{
	return lu_env_info(env, &osp_thread_key);
}

struct osp_txn_info {
	__u64   oti_current_id;
};

extern struct lu_context_key osp_txn_key;

static inline struct osp_txn_info *osp_txn_info(struct lu_context *ctx)
{
	struct osp_txn_info *info;

	info = lu_context_key_get(ctx, &osp_txn_key);
	return info;
}

extern const struct lu_device_operations osp_lu_ops;

static inline int lu_device_is_osp(struct lu_device *d)
{
	return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &osp_lu_ops);
}

static inline struct osp_device *lu2osp_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_osp(d));
	return container_of_safe(d, struct osp_device, opd_dt_dev.dd_lu_dev);
}

static inline struct lu_device *osp2lu_dev(struct osp_device *d)
{
	return &d->opd_dt_dev.dd_lu_dev;
}

static inline struct osp_device *dt2osp_dev(struct dt_device *d)
{
	LASSERT(lu_device_is_osp(&d->dd_lu_dev));
	return container_of_safe(d, struct osp_device, opd_dt_dev);
}

static inline struct osp_object *lu2osp_obj(struct lu_object *o)
{
	LASSERT(ergo(o != NULL, lu_device_is_osp(o->lo_dev)));
	return container_of_safe(o, struct osp_object, opo_obj.do_lu);
}

static inline struct lu_object *osp2lu_obj(struct osp_object *obj)
{
	return &obj->opo_obj.do_lu;
}

static inline struct osp_object *osp_obj(const struct lu_object *o)
{
	LASSERT(lu_device_is_osp(o->lo_dev));
	return container_of_safe(o, struct osp_object, opo_obj.do_lu);
}

static inline struct osp_object *dt2osp_obj(const struct dt_object *d)
{
	return osp_obj(&d->do_lu);
}

static inline struct dt_object *osp_object_child(struct osp_object *o)
{
	return container_of(lu_object_next(osp2lu_obj(o)),
			    struct dt_object, do_lu);
}

static inline struct seq_server_site *osp_seq_site(struct osp_device *osp)
{
	return osp->opd_dt_dev.dd_lu_dev.ld_site->ld_seq_site;
}

/**
 * Serializes in-flight MDT-modifying RPC requests to preserve idempotency.
 *
 * This mutex is used to implement execute-once semantics on the MDT.
 * The MDT stores the last transaction ID and result for every client in
 * its last_rcvd file. If the client doesn't get a reply, it can safely
 * resend the request and the MDT will reconstruct the reply being aware
 * that the request has already been executed. Without this lock,
 * execution status of concurrent in-flight requests would be
 * overwritten.
 *
 * This imlpementation limits the extent to which we can keep a full pipeline
 * of in-flight requests from a single client.  This limitation can be
 * overcome by allowing multiple slots per client in the last_rcvd file,
 * see LU-6864.
 */
#define OSP_FAKE_RPCL_IT ((void *)0x2c0012bfUL)

static inline void osp_init_rpc_lock(struct osp_device *osp)
{
	struct osp_rpc_lock *lck = &osp->opd_rpc_lock;

	mutex_init(&lck->rpcl_mutex);
	lck->rpcl_fakes = 0;
}

static inline void osp_get_rpc_lock(struct osp_device *osp)
{
	struct osp_rpc_lock *lck = &osp->opd_rpc_lock;

	/* This would normally block until the existing request finishes.
	 * If fail_loc is set it will block until the regular request is
	 * done, then increment rpcl_fakes.  Once that is non-zero it
	 * will only be cleared when all fake requests are finished.
	 * Only when all fake requests are finished can normal requests
	 * be sent, to ensure they are recoverable again.
	 */
 again:
	mutex_lock(&lck->rpcl_mutex);

	if (CFS_FAIL_CHECK_QUIET(OBD_FAIL_MDC_RPCS_SEM) ||
	    CFS_FAIL_CHECK_QUIET(OBD_FAIL_OSP_RPCS_SEM)) {
		lck->rpcl_fakes++;
		mutex_unlock(&lck->rpcl_mutex);

		return;
	}

	/* This will only happen when the CFS_FAIL_CHECK() was just turned
	 * off but there are still requests in progress.  Wait until they
	 * finish.  It doesn't need to be efficient in this extremely rare
	 * case, just have low overhead in the common case when it isn't true.
	 */
	if (unlikely(lck->rpcl_fakes)) {
		mutex_unlock(&lck->rpcl_mutex);
		schedule_timeout_uninterruptible(cfs_time_seconds(1) / 4);

		goto again;
	}
}

static inline void osp_put_rpc_lock(struct osp_device *osp)
{
	struct osp_rpc_lock *lck = &osp->opd_rpc_lock;

	if (lck->rpcl_fakes) { /* OBD_FAIL_OSP_RPCS_SEM */
		mutex_lock(&lck->rpcl_mutex);

		if (lck->rpcl_fakes) /* check again under lock */
			lck->rpcl_fakes--;
	}

	mutex_unlock(&lck->rpcl_mutex);
}

static inline int osp_fid_diff(const struct lu_fid *fid1,
			       const struct lu_fid *fid2)
{
	/* In 2.6+ ost_idx is packed into IDIF FID, while in 2.4 and 2.5 IDIF
	 * is always FID_SEQ_IDIF(0x100000000ULL), which does not include OST
	 * index in the seq. So we can not compare IDIF FID seq here */
	if (fid_is_idif(fid1) && fid_is_idif(fid2)) {
		__u32 ost_idx1 = fid_idif_ost_idx(fid1);
		__u32 ost_idx2 = fid_idif_ost_idx(fid2);

		LASSERTF(ost_idx1 == 0 || ost_idx2 == 0 || ost_idx1 == ost_idx2,
			 "fid1: "DFID", fid2: "DFID"\n", PFID(fid1),
			 PFID(fid2));

		return fid_idif_id(fid1->f_seq, fid1->f_oid, 0) -
		       fid_idif_id(fid2->f_seq, fid2->f_oid, 0);
	}

	LASSERTF(fid_seq(fid1) == fid_seq(fid2), "fid1:"DFID", fid2:"DFID"\n",
		 PFID(fid1), PFID(fid2));

	return fid_oid(fid1) - fid_oid(fid2);
}

static inline void osp_fid_to_obdid(struct lu_fid *last_fid, u64 *osi_id)
{
	if (fid_is_idif((last_fid)))
		*osi_id = fid_idif_id(fid_seq(last_fid), fid_oid(last_fid),
				      fid_ver(last_fid));
	else
		*osi_id = fid_oid(last_fid);
}

static inline void osp_update_last_fid(struct osp_device *d, struct lu_fid *fid)
{
	int diff = osp_fid_diff(fid, &d->opd_last_used_fid);
	struct lu_fid *gap_start = &d->opd_gap_start_fid;

	/*
	 * we might have lost precreated objects due to VBR and precreate
	 * orphans, the gap in objid can be calculated properly only here
	 */
	if (diff > 0) {
		if (diff > 1) {
			d->opd_gap_start_fid = d->opd_last_used_fid;
			if (fid_oid(gap_start) == LUSTRE_DATA_SEQ_MAX_WIDTH) {
				gap_start->f_seq++;
				gap_start->f_oid = fid_is_idif(gap_start) ?
							       0 : 1;
			} else {
				gap_start->f_oid++;
			}
			d->opd_gap_count = diff - 1;
			CDEBUG(D_HA, "Gap in objids: start="DFID", count =%d\n",
			       PFID(&d->opd_gap_start_fid), d->opd_gap_count);
		}
		d->opd_last_used_fid = *fid;
		osp_fid_to_obdid(fid, &d->opd_last_id);
	}
}

static int osp_fid_end_seq(const struct lu_env *env, struct lu_fid *fid)
{
	if (fid_is_idif(fid)) {
		struct osp_thread_info *info = osp_env_info(env);
		struct ost_id *oi = &info->osi_oi;

		fid_to_ostid(fid, oi);
		return ostid_id(oi) == IDIF_MAX_OID;
	} else {
		return fid_oid(fid) == LUSTRE_DATA_SEQ_MAX_WIDTH;
	}
}

static inline int osp_precreate_end_seq_nolock(const struct lu_env *env,
					       struct osp_device *osp)
{
	struct lu_fid *fid = &osp->opd_pre_last_created_fid;

	return osp_fid_end_seq(env, fid);
}

static inline int osp_precreate_end_seq(const struct lu_env *env,
					struct osp_device *osp)
{
	int rc;

	spin_lock(&osp->opd_pre_lock);
	rc = osp_precreate_end_seq_nolock(env, osp);
	spin_unlock(&osp->opd_pre_lock);
	return rc;
}

static inline int osp_is_fid_client(struct osp_device *osp)
{
	struct obd_import *imp = osp->opd_obd->u.cli.cl_import;

	return imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_FID;
}

struct object_update *
update_buffer_get_update(struct object_update_request *request,
			 unsigned int index);

int osp_extend_update_buffer(const struct lu_env *env,
			     struct osp_update_request *our);

struct osp_update_request_sub *
osp_current_object_update_request(struct osp_update_request *our);

int osp_object_update_request_create(struct osp_update_request *our,
				     size_t size);

#define OSP_UPDATE_RPC_PACK(env, out_something_pack, our, ...)		\
({									\
	struct object_update *object_update;				\
	size_t max_update_length;					\
	struct osp_update_request_sub *ours;				\
	int ret;							\
									\
	while (1) {							\
		ours = osp_current_object_update_request(our);		\
		LASSERT(ours != NULL);					\
		max_update_length = ours->ours_req_size -		\
			    object_update_request_size(ours->ours_req);	\
									\
		object_update = update_buffer_get_update(ours->ours_req,\
					 ours->ours_req->ourq_count);	\
		ret = out_something_pack(env, object_update,		\
					 &max_update_length,		\
					 __VA_ARGS__);			\
		if (ret == -E2BIG) {					\
			int rc1;					\
			/* Create new object update request */		\
			rc1 = osp_object_update_request_create(our,	\
				max_update_length  +			\
				offsetof(struct object_update_request,	\
					 ourq_updates[0]) + 1);		\
			if (rc1 != 0) {					\
				ret = rc1;				\
				break;					\
			}						\
			continue;					\
		} else {						\
			if (ret == 0) {					\
				ours->ours_req->ourq_count++;		\
				(our)->our_update_nr++;			\
				object_update->ou_batchid =		\
						     (our)->our_batchid;\
				object_update->ou_flags |=		\
						     (our)->our_flags;	\
			}						\
			break;						\
		}							\
	}								\
	ret;								\
})

typedef int (*osp_update_interpreter_t)(const struct lu_env *env,
					struct object_update_reply *rep,
					struct ptlrpc_request *req,
					struct osp_object *obj,
					void *data, int index, int rc);

/* osp_dev.c */
void osp_update_last_id(struct osp_device *d, u64 objid);

/* osp_trans.c */
int osp_insert_async_request(const struct lu_env *env, enum update_type op,
			     struct osp_object *obj, int count, __u16 *lens,
			     const void **bufs, void *data, __u32 repsize,
			     osp_update_interpreter_t interpreter);

int osp_unplug_async_request(const struct lu_env *env,
			     struct osp_device *osp,
			     struct osp_update_request *update);
int osp_trans_update_request_create(struct thandle *th);
struct thandle *osp_trans_create(const struct lu_env *env,
				 struct dt_device *d);
int osp_trans_start(const struct lu_env *env, struct dt_device *dt,
		    struct thandle *th);
int osp_insert_update_callback(const struct lu_env *env,
			       struct osp_update_request *update,
			       struct osp_object *obj, void *data,
			       osp_update_interpreter_t interpreter);

struct osp_update_request *osp_update_request_create(struct dt_device *dt);
void osp_update_request_destroy(const struct lu_env *env,
				struct osp_update_request *update);

int osp_send_update_thread(void *arg);
int osp_check_and_set_rpc_version(struct osp_thandle *oth,
				  struct osp_object *obj);

void osp_thandle_destroy(const struct lu_env *env, struct osp_thandle *oth);
static inline void osp_thandle_get(struct osp_thandle *oth)
{
	atomic_inc(&oth->ot_refcount);
}

static inline void osp_thandle_put(const struct lu_env *env,
				   struct osp_thandle *oth)
{
	if (atomic_dec_and_test(&oth->ot_refcount))
		osp_thandle_destroy(env, oth);
}

int osp_prep_update_req(const struct lu_env *env, struct obd_import *imp,
			struct osp_update_request *our,
			struct ptlrpc_request **reqp);
int osp_remote_sync(const struct lu_env *env, struct osp_device *osp,
		    struct osp_update_request *update,
		    struct ptlrpc_request **reqp);

struct thandle *osp_get_storage_thandle(const struct lu_env *env,
					struct thandle *th,
					struct osp_device *osp);
void osp_trans_callback(const struct lu_env *env,
			struct osp_thandle *oth, int rc);
void osp_invalidate_request(struct osp_device *osp);
/* osp_object.c */
int osp_attr_get(const struct lu_env *env, struct dt_object *dt,
		 struct lu_attr *attr);
int osp_xattr_get(const struct lu_env *env, struct dt_object *dt,
		  struct lu_buf *buf, const char *name);
int osp_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *buf, const char *name,
			  int flag, struct thandle *th);
int osp_xattr_set(const struct lu_env *env, struct dt_object *dt,
		  const struct lu_buf *buf, const char *name, int fl,
		  struct thandle *th);
int osp_declare_xattr_del(const struct lu_env *env, struct dt_object *dt,
			  const char *name, struct thandle *th);
int osp_xattr_del(const struct lu_env *env, struct dt_object *dt,
		  const char *name, struct thandle *th);
int osp_invalidate(const struct lu_env *env, struct dt_object *dt);
bool osp_check_stale(struct dt_object *dt);
void osp_obj_invalidate_cache(struct osp_object *obj);

int osp_trans_stop(const struct lu_env *env, struct dt_device *dt,
		   struct thandle *th);
int osp_trans_cb_add(struct thandle *th, struct dt_txn_commit_cb *dcb);

struct dt_it *osp_it_init(const struct lu_env *env, struct dt_object *dt,
			  __u32 attr);
void osp_it_fini(const struct lu_env *env, struct dt_it *di);
int osp_it_get(const struct lu_env *env, struct dt_it *di,
	       const struct dt_key *key);
void osp_it_put(const struct lu_env *env, struct dt_it *di);
__u64 osp_it_store(const struct lu_env *env, const struct dt_it *di);
int osp_it_key_rec(const struct lu_env *env, const struct dt_it *di,
		   void *key_rec);
int osp_it_next_page(const struct lu_env *env, struct dt_it *di);
/* osp_md_object.c */
int osp_md_declare_create(const struct lu_env *env, struct dt_object *dt,
			  struct lu_attr *attr, struct dt_allocation_hint *hint,
			  struct dt_object_format *dof, struct thandle *th);
int osp_md_create(const struct lu_env *env, struct dt_object *dt,
		  struct lu_attr *attr, struct dt_allocation_hint *hint,
		  struct dt_object_format *dof, struct thandle *th);
int osp_md_declare_attr_set(const struct lu_env *env, struct dt_object *dt,
			    const struct lu_attr *attr, struct thandle *th);
int osp_md_attr_set(const struct lu_env *env, struct dt_object *dt,
		    const struct lu_attr *attr, struct thandle *th);
extern const struct dt_index_operations osp_md_index_ops;

/* osp_precreate.c */
int osp_init_precreate(struct osp_device *d);
int osp_precreate_reserve(const struct lu_env *env,
			  struct osp_device *d, bool can_block);
__u64 osp_precreate_get_id(struct osp_device *d);
int osp_precreate_get_fid(const struct lu_env *env, struct osp_device *d,
			  struct lu_fid *fid);
void osp_precreate_fini(struct osp_device *d);
int osp_object_truncate(const struct lu_env *env, struct dt_object *dt, __u64);
void osp_pre_update_status(struct osp_device *d, int rc);
void osp_statfs_need_now(struct osp_device *d);
int osp_reset_last_used(const struct lu_env *env, struct osp_device *osp);
int osp_write_last_oid_seq_files(struct lu_env *env, struct osp_device *osp,
				 struct lu_fid *fid, int sync);
int osp_init_pre_fid(struct osp_device *osp);
int osp_init_statfs(struct osp_device *osp);
void osp_fini_statfs(struct osp_device *osp);
void osp_statfs_fini(struct osp_device *d);

/* lproc_osp.c */
void osp_tunables_init(struct osp_device *osp);
void osp_tunables_fini(struct osp_device *osp);

/* osp_sync.c */
int osp_sync_declare_add(const struct lu_env *env, struct osp_object *o,
			 enum llog_op_type type, struct thandle *th);
int osp_sync_add(const struct lu_env *env, struct osp_object *o,
		 enum llog_op_type type, struct thandle *th,
		 const struct lu_attr *attr);
int osp_sync_init(const struct lu_env *env, struct osp_device *d);
int osp_sync_fini(struct osp_device *d);
void osp_sync_check_for_work(struct osp_device *osp);
void osp_sync_force(const struct lu_env *env, struct osp_device *d);
int osp_sync_add_commit_cb_1s(const struct lu_env *env, struct osp_device *d,
			      struct thandle *th);

/* lwp_dev.c */
extern const struct obd_ops lwp_obd_device_ops;
extern struct lu_device_type lwp_device_type;

static inline struct lu_device *osp2top(const struct osp_device *osp)
{
	return osp->opd_dt_dev.dd_lu_dev.ld_site->ls_top_dev;
}

static inline void osp_set_req_replay(const struct osp_device *osp,
				      struct ptlrpc_request *req)
{
	struct obd_device *obd = osp2top(osp)->ld_obd;

	/* The RPC must be recovery related for the cases:
	 *
	 * 1. sent during recovery, or
	 * 2. sent before the recovery thread target_recovery_thread() start,
	 *    such as triggered by lod_sub_recovery_thread(). */
	if (obd->obd_recovering || (obd->obd_replayable && obd->obd_no_conn))
		req->rq_allow_replay = 1;
}

#endif
