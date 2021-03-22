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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _OFD_INTERNAL_H
#define _OFD_INTERNAL_H

#include <obd.h>
#include <obd_class.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <range_lock.h>

#define OFD_INIT_OBJID	0
#define OFD_PRECREATE_BATCH_DEFAULT (OBJ_SUBDIR_COUNT * 4)

/* on small filesystems we should not precreate too many objects in
 * a single transaction, otherwise we can overflow transactions */
#define OFD_PRECREATE_SMALL_FS		(1024ULL * 1024 * 1024)
#define OFD_PRECREATE_BATCH_SMALL	8

/* Limit the returned fields marked valid to those that we actually might set */
#define OFD_VALID_FLAGS (LA_TYPE | LA_MODE | LA_SIZE | LA_BLOCKS | \
			 LA_BLKSIZE | LA_ATIME | LA_MTIME | LA_CTIME)

#define OFD_SOFT_SYNC_LIMIT_DEFAULT 16

/*
 * update atime if on-disk value older than client's one
 * by OFD_ATIME_DIFF or more
 */
#define OFD_DEF_ATIME_DIFF	0 /* disabled */

/* request stats */
enum {
	LPROC_OFD_STATS_READ_BYTES = 0,
	LPROC_OFD_STATS_WRITE_BYTES,
	LPROC_OFD_STATS_READ,
	LPROC_OFD_STATS_WRITE,
	LPROC_OFD_STATS_GETATTR,
	LPROC_OFD_STATS_SETATTR,
	LPROC_OFD_STATS_PUNCH,
	LPROC_OFD_STATS_SYNC,
	LPROC_OFD_STATS_DESTROY,
	LPROC_OFD_STATS_CREATE,
	LPROC_OFD_STATS_STATFS,
	LPROC_OFD_STATS_GET_INFO,
	LPROC_OFD_STATS_SET_INFO,
	LPROC_OFD_STATS_QUOTACTL,
	LPROC_OFD_STATS_PREALLOC,
	LPROC_OFD_STATS_LAST,
};

static inline void ofd_counter_incr(struct obd_export *exp, int opcode,
				    char *jobid, long amount)
{
	if (exp->exp_obd && exp->exp_obd->obd_stats)
		lprocfs_counter_add(exp->exp_obd->obd_stats, opcode, amount);

	if (exp->exp_obd && exp->exp_obd->u.obt.obt_jobstats.ojs_hash &&
	    (exp_connect_flags(exp) & OBD_CONNECT_JOBSTATS))
		lprocfs_job_stats_log(exp->exp_obd, jobid, opcode, amount);

	if (exp->exp_nid_stats != NULL &&
	    exp->exp_nid_stats->nid_stats != NULL) {
		lprocfs_counter_add(exp->exp_nid_stats->nid_stats, opcode,
				    amount);
	}
}

struct ofd_seq {
	struct list_head	os_list;
	struct ost_id		os_oi;
	spinlock_t		os_last_oid_lock;
	struct mutex		os_create_lock;
	atomic_t		os_refc;
	atomic_t		os_precreate_in_progress;
	struct dt_object	*os_lastid_obj;
	unsigned long		os_destroys_in_progress:1,
				os_last_id_synced:1;
};

struct ofd_device {
	struct dt_device	 ofd_dt_dev;
	struct dt_device	*ofd_osd;
	struct obd_export	*ofd_osd_exp;
	/* DLM name-space for meta-data locks maintained by this server */
	struct ldlm_namespace	*ofd_namespace;

	/* last_rcvd file */
	struct lu_target	 ofd_lut;
	struct dt_object	*ofd_health_check_file;
	struct local_oid_storage *ofd_los;

	__u64			 ofd_inconsistency_self_detected;
	__u64			 ofd_inconsistency_self_repaired;

	struct ofd_access_log	*ofd_access_log;
	unsigned int		 ofd_access_log_size;
	unsigned int		 ofd_access_log_mask;

	struct list_head	ofd_seq_list;
	rwlock_t		ofd_seq_list_lock;
	int			ofd_seq_count;
	int			ofd_precreate_batch;
	spinlock_t		ofd_batch_lock;

	/* preferred BRW size, decided by storage type and capability */
	__u32			 ofd_brw_size;
	spinlock_t		 ofd_flags_lock;
	unsigned long		 ofd_raid_degraded:1,
				 /* sync journal on writes */
				 ofd_sync_journal:1,
				 /* Protected by ofd_lastid_rwsem. */
				 ofd_lastid_rebuilding:1,
				 ofd_record_fid_accessed:1,
				 ofd_lfsck_verify_pfid:1,
				 ofd_no_precreate:1,
				 ofd_skip_lfsck:1;
	struct seq_server_site	 ofd_seq_site;
	/* the limit of SOFT_SYNC RPCs that will trigger a soft sync */
	unsigned int		 ofd_soft_sync_limit;
	/* Protect ::ofd_lastid_rebuilding */
	struct rw_semaphore	 ofd_lastid_rwsem;
	__u64			 ofd_lastid_gen;
	struct task_struct	*ofd_inconsistency_task;
	struct list_head	 ofd_inconsistency_list;
	spinlock_t		 ofd_inconsistency_lock;
	/* Backwards compatibility */
	struct attribute	*ofd_read_cache_enable;
	struct attribute	*ofd_read_cache_max_filesize;
	struct attribute	*ofd_write_cache_enable;
	time64_t		 ofd_atime_diff;
};

static inline struct ofd_device *ofd_dev(struct lu_device *d)
{
	return container_of_safe(d, struct ofd_device, ofd_dt_dev.dd_lu_dev);
}

static inline struct obd_device *ofd_obd(struct ofd_device *ofd)
{
	return ofd->ofd_dt_dev.dd_lu_dev.ld_obd;
}

static inline struct ofd_device *ofd_exp(struct obd_export *exp)
{
	return ofd_dev(exp->exp_obd->obd_lu_dev);
}

static inline char *ofd_name(struct ofd_device *ofd)
{
	return ofd->ofd_dt_dev.dd_lu_dev.ld_obd->obd_name;
}

struct ofd_object {
	struct lu_object_header	ofo_header;
	struct dt_object	ofo_obj;
	struct filter_fid	ofo_ff;
	time64_t		ofo_atime_ondisk;
	unsigned int		ofo_pfid_checking:1,
				ofo_pfid_verified:1;
	struct range_lock_tree	ofo_write_tree;
};

static inline struct ofd_object *ofd_obj(struct lu_object *o)
{
	return container_of_safe(o, struct ofd_object, ofo_obj.do_lu);
}

static inline int ofd_object_exists(struct ofd_object *obj)
{
	LASSERT(obj != NULL);
	if (lu_object_is_dying(obj->ofo_obj.do_lu.lo_header))
		return 0;
	return lu_object_exists(&obj->ofo_obj.do_lu);
}

static inline struct dt_object *fo2dt(struct ofd_object *obj)
{
	return &obj->ofo_obj;
}

static inline struct dt_object *ofd_object_child(struct ofd_object *_obj)
{
	struct lu_object *lu = &(_obj)->ofo_obj.do_lu;

	return container_of(lu_object_next(lu), struct dt_object, do_lu);
}

static inline struct ofd_device *ofd_obj2dev(const struct ofd_object *fo)
{
	return ofd_dev(fo->ofo_obj.do_lu.lo_dev);
}

static inline void ofd_read_lock(const struct lu_env *env,
				 struct ofd_object *fo)
{
	struct dt_object  *next = ofd_object_child(fo);

	next->do_ops->do_read_lock(env, next, 0);
}

static inline void ofd_read_unlock(const struct lu_env *env,
				   struct ofd_object *fo)
{
	struct dt_object  *next = ofd_object_child(fo);

	next->do_ops->do_read_unlock(env, next);
}

static inline void ofd_write_lock(const struct lu_env *env,
				  struct ofd_object *fo)
{
	struct dt_object *next = ofd_object_child(fo);

	next->do_ops->do_write_lock(env, next, 0);
}

static inline void ofd_write_unlock(const struct lu_env *env,
				    struct ofd_object *fo)
{
	struct dt_object  *next = ofd_object_child(fo);

	next->do_ops->do_write_unlock(env, next);
}

/*
 * Common data shared by obdofd-level handlers. This is allocated per-thread
 * to reduce stack consumption.
 */
struct ofd_thread_info {
	const struct lu_env		*fti_env;

	struct obd_export		*fti_exp;
	__u64				 fti_xid;
	__u64				 fti_pre_version;

	struct lu_fid			 fti_fid;
	struct lu_attr			 fti_attr;
	struct lu_attr			 fti_attr2;
	struct ldlm_res_id		 fti_resid;
	struct filter_fid		 fti_mds_fid;
	struct ost_id			 fti_ostid;
	struct ofd_object		*fti_obj;
	union {
		char			 name[64]; /* for ofd_init0() */
		struct obd_statfs	 osfs;    /* for obdofd_statfs() */
	} fti_u;

	/* Ops object filename */
	struct lu_name			 fti_name;
	struct dt_object_format		 fti_dof;
	struct lu_buf			 fti_buf;
	loff_t				 fti_off;

	struct ost_lvb			 fti_lvb;
	union {
		struct lfsck_req_local	 fti_lrl;
		struct obd_connect_data	 fti_ocd;
	};
	struct range_lock		 fti_write_range;
	unsigned			 fti_range_locked:1;
};

extern void target_recovery_fini(struct obd_device *obd);
extern void target_recovery_init(struct lu_target *lut, svc_handler_t handler);

/* ofd_access_log.c */
bool ofd_access_log_size_is_valid(unsigned int size);
int ofd_access_log_module_init(void);
void ofd_access_log_module_exit(void);

struct ofd_access_log;
struct ofd_access_log *ofd_access_log_create(const char *ofd_name, size_t size);
void ofd_access_log_delete(struct ofd_access_log *oal);
void ofd_access(const struct lu_env *env, struct ofd_device *m,
		const struct lu_fid *parent_fid, __u64 begin, __u64 end,
		unsigned int size, unsigned int segment_count, int rw);

/* ofd_dev.c */
extern struct lu_context_key ofd_thread_key;
int ofd_postrecov(const struct lu_env *env, struct ofd_device *ofd);
int ofd_fiemap_get(const struct lu_env *env, struct ofd_device *ofd,
		   struct lu_fid *fid, struct fiemap *fiemap);

/* ofd_obd.c */
extern const struct obd_ops ofd_obd_ops;
int ofd_destroy_by_fid(const struct lu_env *env, struct ofd_device *ofd,
		       const struct lu_fid *fid, int orphan);
int ofd_statfs(const struct lu_env *env,  struct obd_export *exp,
	       struct obd_statfs *osfs, time64_t max_age, __u32 flags);
int ofd_obd_disconnect(struct obd_export *exp);

/* ofd_fs.c */
u64 ofd_seq_last_oid(struct ofd_seq *oseq);
void ofd_seq_last_oid_set(struct ofd_seq *oseq, u64 id);
int ofd_seq_last_oid_write(const struct lu_env *env, struct ofd_device *ofd,
			   struct ofd_seq *oseq);
int ofd_seqs_init(const struct lu_env *env, struct ofd_device *ofd);
struct ofd_seq *ofd_seq_get(struct ofd_device *ofd, u64 seq);
void ofd_seq_put(const struct lu_env *env, struct ofd_seq *oseq);

int ofd_fs_setup(const struct lu_env *env, struct ofd_device *ofd,
		 struct obd_device *obd);
void ofd_fs_cleanup(const struct lu_env *env, struct ofd_device *ofd);
int ofd_precreate_batch(struct ofd_device *ofd, int batch);
struct ofd_seq *ofd_seq_load(const struct lu_env *env, struct ofd_device *ofd,
			     u64 seq);
void ofd_seqs_fini(const struct lu_env *env, struct ofd_device *ofd);
void ofd_seqs_free(const struct lu_env *env, struct ofd_device *ofd);

/* ofd_io.c */
int ofd_start_inconsistency_verification_thread(struct ofd_device *ofd);
int ofd_stop_inconsistency_verification_thread(struct ofd_device *ofd);
int ofd_verify_ff(const struct lu_env *env, struct ofd_object *fo,
		  struct obdo *oa);
int ofd_verify_layout_version(const struct lu_env *env,
			      struct ofd_object *fo, const struct obdo *oa);
int ofd_preprw(const struct lu_env *env,int cmd, struct obd_export *exp,
	       struct obdo *oa, int objcount, struct obd_ioobj *obj,
	       struct niobuf_remote *rnb, int *nr_local,
	       struct niobuf_local *lnb);
int ofd_commitrw(const struct lu_env *env, int cmd, struct obd_export *exp,
		 struct obdo *oa, int objcount, struct obd_ioobj *obj,
		 struct niobuf_remote *rnb, int npages,
		 struct niobuf_local *lnb, int old_rc);

/* ofd_trans.c */
struct thandle *ofd_trans_create(const struct lu_env *env,
				 struct ofd_device *ofd);
int ofd_trans_start(const struct lu_env *env,
		    struct ofd_device *ofd, struct ofd_object *fo,
		    struct thandle *th);
int ofd_trans_stop(const struct lu_env *env, struct ofd_device *ofd,
		    struct thandle *th, int rc);
int ofd_txn_stop_cb(const struct lu_env *env, struct thandle *txn,
		    void *cookie);

/* lproc_ofd.c */
int ofd_tunables_init(struct ofd_device *ofd);
#ifdef CONFIG_PROC_FS
void ofd_stats_counter_init(struct lprocfs_stats *stats, unsigned int offset);
#else
static inline void ofd_stats_counter_init(struct lprocfs_stats *stats,
					  unsigned int offset) {}
#endif

/* ofd_objects.c */
struct ofd_object *ofd_object_find(const struct lu_env *env,
				   struct ofd_device *ofd,
				   const struct lu_fid *fid);
int ofd_object_ff_load(const struct lu_env *env, struct ofd_object *fo);
int ofd_object_ff_update(const struct lu_env *env, struct ofd_object *fo,
			 const struct obdo *oa, struct filter_fid *ff);
int ofd_precreate_objects(const struct lu_env *env, struct ofd_device *ofd,
			  u64 id, struct ofd_seq *oseq, int nr, int sync);

static inline void ofd_object_put(const struct lu_env *env,
				  struct ofd_object *fo)
{
	dt_object_put(env, &fo->ofo_obj);
}
int ofd_attr_set(const struct lu_env *env, struct ofd_object *fo,
		 struct lu_attr *la, struct obdo *oa);
int ofd_object_punch(const struct lu_env *env, struct ofd_object *fo,
		     __u64 start, __u64 end, struct lu_attr *la,
		     struct obdo *oa);
int ofd_object_fallocate(const struct lu_env *env, struct ofd_object *fo,
			 __u64 start, __u64 end, int mode, struct lu_attr *la,
			 struct obdo *oa);
int ofd_destroy(const struct lu_env *, struct ofd_object *, int);
int ofd_attr_get(const struct lu_env *env, struct ofd_object *fo,
		 struct lu_attr *la);
int ofd_attr_handle_id(const struct lu_env *env, struct ofd_object *fo,
			 struct lu_attr *la, int is_setattr);

static inline
struct ofd_object *ofd_object_find_exists(const struct lu_env *env,
					  struct ofd_device *ofd,
					  const struct lu_fid *fid)
{
	struct ofd_object *fo;

	fo = ofd_object_find(env, ofd, fid);
	if (!IS_ERR(fo) && !ofd_object_exists(fo)) {
		ofd_object_put(env, fo);
		fo = ERR_PTR(-ENOENT);
	}
	return fo;
}

/* ofd_dev.c */
int ofd_fid_set_index(const struct lu_env *env, struct ofd_device *ofd,
		      int index);
int ofd_fid_init(const struct lu_env *env, struct ofd_device *ofd);
int ofd_fid_fini(const struct lu_env *env, struct ofd_device *ofd);

/* ofd_lvb.c */
extern struct ldlm_valblock_ops ofd_lvbo;

/* ofd_dlm.c */
extern struct kmem_cache *ldlm_glimpse_work_kmem;

int ofd_intent_policy(const struct lu_env *env, struct ldlm_namespace *ns,
		      struct ldlm_lock **lockp, void *req_cookie,
		      enum ldlm_mode mode, __u64 flags, void *data);

static inline struct ofd_thread_info *ofd_info(const struct lu_env *env)
{
	return lu_env_info(env, &ofd_thread_key);
}

static inline struct ofd_thread_info *ofd_info_init(const struct lu_env *env,
						    struct obd_export *exp)
{
	struct ofd_thread_info *info;

	info = ofd_info(env);
	LASSERT(info->fti_exp == NULL);
	LASSERT(info->fti_env == NULL);
	LASSERT(info->fti_attr.la_valid == 0);

	info->fti_env = env;
	info->fti_exp = exp;
	info->fti_pre_version = 0;
	return info;
}

static inline struct ofd_thread_info *tsi2ofd_info(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct ofd_thread_info	*info;

	info = ofd_info(tsi->tsi_env);
	LASSERT(info->fti_exp == NULL);
	LASSERT(info->fti_env == NULL);
	LASSERT(info->fti_attr.la_valid == 0);

	info->fti_env = tsi->tsi_env;
	info->fti_exp = tsi->tsi_exp;

	info->fti_xid = req->rq_xid;
	/** VBR: take versions from request */
	if (req->rq_reqmsg != NULL &&
	    lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
		__u64 *pre_version = lustre_msg_get_versions(req->rq_reqmsg);

		info->fti_pre_version = pre_version ? pre_version[0] : 0;
	}
	return info;
}

/* sync on lock cancel is useless when we force a journal flush,
 * and if we enable async journal commit, we should also turn on
 * sync on lock cancel if it is not enabled already. */
static inline void ofd_slc_set(struct ofd_device *ofd)
{
	if (ofd->ofd_sync_journal == 1)
		ofd->ofd_lut.lut_sync_lock_cancel = SYNC_LOCK_CANCEL_NEVER;
	else if (ofd->ofd_lut.lut_sync_lock_cancel == SYNC_LOCK_CANCEL_NEVER)
		ofd->ofd_lut.lut_sync_lock_cancel = SYNC_LOCK_CANCEL_ALWAYS;
}

static inline int ofd_validate_seq(struct obd_export *exp, __u64 seq)
{
	struct filter_export_data *fed = &exp->exp_filter_data;

	if (unlikely(seq == FID_SEQ_OST_MDT0 && fed->fed_group != 0)) {
		/* IDIF request only operates on MDT0 group */
		CERROR("%s: Invalid sequence %#llx for group %u\n",
		       exp->exp_obd->obd_name, seq, fed->fed_group);
		RETURN(-EINVAL);
	}

	return 0;
}

#endif /* _OFD_INTERNAL_H */
