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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2014, Intel Corporation.
 * Use is subject to license terms.
 */

#include "lquota_internal.h"

#ifndef _QSD_INTERNAL_H
#define _QSD_INTERNAL_H

struct qsd_type_info;
struct qsd_fsinfo;

extern struct kmem_cache *upd_kmem;

/*
 * A QSD instance implements quota enforcement support for a given OSD.
 * The instance can be created via qsd_init() and then freed with qsd_fini().
 * This structure gathers all quota parameters and pointers to on-disk indexes
 * required on quota slave to:
 * i. acquire/release quota space from the QMT;
 * ii. allocate this quota space to local requests.
 */
struct qsd_instance {
	/* name of service which created this qsd instance */
	char			 qsd_svname[MAX_OBD_NAME];

	/* dt_device associated with this qsd instance */
	struct dt_device	*qsd_dev;

	/* procfs directory where information related to the underlying slaves
	 * are exported */
	struct proc_dir_entry	*qsd_proc;

	/* export used for the connection to quota master */
	struct obd_export	*qsd_exp;

	/* ldlm namespace used for quota locks */
	struct ldlm_namespace	*qsd_ns;

	/* on-disk directory where to store index files for this qsd instance */
	struct dt_object	*qsd_root;

	/* We create 2 quota slave instances:
	 * - one for user quota
	 * - one for group quota
	 *
	 * This will have to be revisited if new quota types are added in the
	 * future. For the time being, we can just use an array. */
	struct qsd_qtype_info	*qsd_type_array[LL_MAXQUOTAS];

	/* per-filesystem quota information */
	struct qsd_fsinfo	*qsd_fsinfo;

	/* link into qfs_qsd_list of qfs_fsinfo */
	struct list_head	 qsd_link;

	/* list of lqe entry which might need quota space adjustment */
	struct list_head	 qsd_adjust_list;

	/* lock protecting adjust list */
	spinlock_t		 qsd_adjust_lock;

	/* dedicated thread for updating slave index files. */
	struct task_struct	*qsd_upd_task;

	/* list of update tasks */
	struct list_head	 qsd_upd_list;

	/* r/w spinlock protecting:
	 * - the state flags
	 * - the qsd update list
	 * - the deferred list
	 * - flags of the qsd_qtype_info */
	rwlock_t		 qsd_lock;

	/* Default quota settings which apply to all identifiers */
	/* when blk qunit reaches this value, later write reqs from client
	 * should be sync. b=16642 */
	unsigned long		 qsd_sync_threshold;

	/* how long a service thread can wait for quota space.
	 * value dynamically computed from obd_timeout and at_max if not
	 * enforced here (via procfs) */
	int			 qsd_timeout;

	unsigned long		qsd_is_md:1,    /* managing quota for mdt */
				qsd_started:1,  /* instance is now started */
				qsd_prepared:1, /* qsd_prepare() successfully
						  * called */
				qsd_exp_valid:1,/* qsd_exp is now valid */
				qsd_stopping:1; /* qsd_instance is stopping */

};

/*
 * Per-type quota information.
 * Quota slave instance for a specific quota type. The qsd instance has one such
 * structure for each quota type (i.e. user & group).
 */
struct qsd_qtype_info {
	/* reference count incremented by each user of this structure */
	atomic_t		 qqi_ref;

	/* quota type, either USRQUOTA or GRPQUOTA
	 * immutable after creation. */
	int			 qqi_qtype;

	/* Global index FID to use for this quota type */
	struct lu_fid		 qqi_fid;

	/* Slave index FID allocated by the master */
	struct lu_fid		 qqi_slv_fid;

	/* back pointer to qsd device
	 * immutable after creation. */
	struct qsd_instance	*qqi_qsd;

	/* handle of global quota lock */
	struct lustre_handle	 qqi_lockh;

	/* Local index files storing quota settings for this quota type */
	struct dt_object	*qqi_acct_obj; /* accounting object */
	struct dt_object	*qqi_slv_obj;  /* slave index copy */
	struct dt_object	*qqi_glb_obj;  /* global index copy */

	/* Current object versions */
	__u64			 qqi_slv_ver; /* slave index version */
	__u64			 qqi_glb_ver; /* global index version */

	/* per quota ID information. All lquota entry are kept in a hash table
	 * and read from disk on cache miss. */
	struct lquota_site	*qqi_site;

	/* Reintegration thread */
	struct task_struct	*qqi_reint_task;

	/* statistics on operations performed by this slave */
	struct lprocfs_stats	*qqi_stats;

	/* deferred update for the global index copy */
	struct list_head	 qqi_deferred_glb;
	/* deferred update for the slave index copy */
	struct list_head	 qqi_deferred_slv;

	/* Various flags representing the current state of the slave for this
	 * quota type. */
	unsigned long		qqi_glb_uptodate:1, /* global index uptodate
							with master */
				qqi_slv_uptodate:1, /* slave index uptodate
							with master */
				qqi_reint:1,    /* in reintegration or not */
				qqi_acct_failed:1; /* failed to setup acct */

	/* A list of references to this instance, for debugging */
	struct lu_ref		qqi_reference;

	/* default quota setting*/
	__u64			qqi_default_hardlimit;
	__u64			qqi_default_softlimit;
	__u64			qqi_default_gracetime;
};

/*
 * Per-filesystem quota information
 * Structure tracking quota enforcement status on a per-filesystem basis
 */
struct qsd_fsinfo {
	/* filesystem name */
	char			qfs_name[MTI_NAME_MAXLEN];

	/* what type of quota is enabled for each resource type. */
	unsigned int		qfs_enabled[LQUOTA_NR_RES];

	/* list of all qsd_instance for this fs */
	struct list_head	qfs_qsd_list;
	struct mutex		qfs_mutex;

	/* link to the global quota fsinfo list.  */
	struct list_head	qfs_link;

	/* reference count */
	int			qfs_ref;
};

/*
 * Helper functions & prototypes
 */

/* helper routine to find qsd_instance associated a lquota_entry */
static inline struct qsd_qtype_info *lqe2qqi(struct lquota_entry *lqe)
{
	LASSERT(!lqe_is_master(lqe));
	return (struct qsd_qtype_info *)lqe->lqe_site->lqs_parent;
}

/* qqi_getref/putref is used to track users of a qqi structure  */
static inline void qqi_getref(struct qsd_qtype_info *qqi)
{
	atomic_inc(&qqi->qqi_ref);
}

static inline void qqi_putref(struct qsd_qtype_info *qqi)
{
	LASSERT(atomic_read(&qqi->qqi_ref) > 0);
	atomic_dec(&qqi->qqi_ref);
}

#define QSD_RES_TYPE(qsd) ((qsd)->qsd_is_md ? LQUOTA_RES_MD : LQUOTA_RES_DT)

/* udpate record for slave & global index copy */
struct qsd_upd_rec {
	struct list_head	qur_link; /* link into qsd_upd_list */
	union lquota_id		qur_qid;
	union lquota_rec	qur_rec;
	struct qsd_qtype_info  *qur_qqi;
	struct lquota_entry    *qur_lqe;
	__u64			qur_ver;
	bool			qur_global;
};

/* Common data shared by qsd-level handlers. This is allocated per-thread to
 * reduce stack consumption.  */
struct qsd_thread_info {
	union lquota_rec		qti_rec;
	union lquota_id			qti_id;
	struct lu_fid			qti_fid;
	struct ldlm_res_id		qti_resid;
	struct ldlm_enqueue_info	qti_einfo;
	struct lustre_handle		qti_lockh;
	__u64                           qti_slv_ver;
	struct lquota_lvb		qti_lvb;
	union {
		struct quota_body	qti_body;
		struct idx_info		qti_ii;
	};
	char				qti_buf[MTI_NAME_MAXLEN];
};

extern struct lu_context_key qsd_thread_key;

static inline
struct qsd_thread_info *qsd_info(const struct lu_env *env)
{
	return lu_env_info(env, &qsd_thread_key);
}

/* helper function to check whether a given quota type is enabled */
static inline int qsd_type_enabled(struct qsd_instance *qsd, int type)
{
	int	enabled, pool;

	LASSERT(qsd != NULL);
	LASSERT(type < LL_MAXQUOTAS);

	if (qsd->qsd_fsinfo == NULL)
		return 0;

	pool = qsd->qsd_is_md ? LQUOTA_RES_MD : LQUOTA_RES_DT;
	enabled = qsd->qsd_fsinfo->qfs_enabled[pool - LQUOTA_FIRST_RES];

	return enabled & BIT(type);
}

/* helper function to set new qunit and compute associated qtune value */
static inline void qsd_set_qunit(struct lquota_entry *lqe, __u64 qunit)
{
	if (lqe->lqe_qunit == qunit)
		return;

	lqe->lqe_qunit = qunit;

	/* With very large qunit support, we can't afford to have a static
	 * qtune value, e.g. with a 1PB qunit and qtune set to 50%, we would
	 * start pre-allocation when 512TB of free quota space remains.
	 * Therefore, we adapt qtune depending on the actual qunit value */
	if (qunit == 0)				/* if qunit is NULL           */
		lqe->lqe_qtune = 0;		/*  qtune = 0                 */
	else if (qunit == 1024)			/* if 1MB or 1K inodes        */
		lqe->lqe_qtune = qunit >> 1;	/*  => 50%                    */
	else if (qunit <= 1024 * 1024)		/* up to 1GB or 1M inodes     */
		lqe->lqe_qtune = qunit >> 2;	/*  => 25%                    */
	else if (qunit <= 4 * 1024 * 1024)	/* up to 16GB or 16M inodes   */
		lqe->lqe_qtune = qunit >> 3;	/*  => 12.5%                  */
	else					/* above 4GB/4M               */
		lqe->lqe_qtune = 1024 * 1024;	/*  value capped to 1GB/1M    */

	LQUOTA_DEBUG(lqe, "changing qunit & qtune");

	/* turn on pre-acquire when qunit is modified */
	lqe->lqe_nopreacq = false;
}

/* helper function to set/clear edquot flag */
static inline void qsd_set_edquot(struct lquota_entry *lqe, bool edquot)
{
	lqe->lqe_edquot = edquot;
	if (edquot)
		lqe->lqe_edquot_time = ktime_get_seconds();
}

#define QSD_WB_INTERVAL	60 /* 60 seconds */

/* helper function calculating how long a service thread should be waiting for
 * quota space */
static inline int qsd_wait_timeout(struct qsd_instance *qsd)
{
	if (qsd->qsd_timeout != 0)
		return qsd->qsd_timeout;
	return min_t(int, at_max / 2, obd_timeout / 2);
}

/* qsd_entry.c */
extern const struct lquota_entry_operations qsd_lqe_ops;
int qsd_refresh_usage(const struct lu_env *, struct lquota_entry *);
int qsd_update_index(const struct lu_env *, struct qsd_qtype_info *,
		     union lquota_id *, bool, __u64, void *);
int qsd_update_lqe(const struct lu_env *, struct lquota_entry *, bool,
		   void *);
int qsd_write_version(const struct lu_env *, struct qsd_qtype_info *,
		      __u64, bool);

/* qsd_lock.c */
extern struct ldlm_enqueue_info qsd_glb_einfo;
extern struct ldlm_enqueue_info qsd_id_einfo;
void qsd_update_default_quota(struct qsd_qtype_info *qqi, __u64 hardlimit,
			      __u64 softlimit, __u64 gracetime);
int qsd_id_lock_match(struct lustre_handle *, struct lustre_handle *);
int qsd_id_lock_cancel(const struct lu_env *, struct lquota_entry *);

/* qsd_reint.c */
int qsd_start_reint_thread(struct qsd_qtype_info *);
void qsd_stop_reint_thread(struct qsd_qtype_info *);

/* qsd_request.c */
typedef void (*qsd_req_completion_t) (const struct lu_env *,
				      struct qsd_qtype_info *,
				      struct quota_body *, struct quota_body *,
				      struct lustre_handle *,
				      struct lquota_lvb *, void *, int);
int qsd_send_dqacq(const struct lu_env *, struct obd_export *,
		   struct quota_body *, bool, qsd_req_completion_t,
		   struct qsd_qtype_info *, struct lustre_handle *,
		   struct lquota_entry *);
int qsd_intent_lock(const struct lu_env *, struct obd_export *,
		    struct quota_body *, bool, int, qsd_req_completion_t,
		    struct qsd_qtype_info *, struct lquota_lvb *, void *);
int qsd_fetch_index(const struct lu_env *, struct obd_export *,
		    struct idx_info *, unsigned int, struct page **, bool *);

/* qsd_writeback.c */
void qsd_bump_version(struct qsd_qtype_info *, __u64, bool);
void qsd_upd_schedule(struct qsd_qtype_info *, struct lquota_entry *,
		      union lquota_id *, union lquota_rec *, __u64, bool);
/* qsd_config.c */
struct qsd_fsinfo *qsd_get_fsinfo(char *, bool);
void qsd_put_fsinfo(struct qsd_fsinfo *);
int qsd_config(char *valstr, char *fsname, int pool);
int qsd_process_config(struct lustre_cfg *);

/* qsd_handler.c */
int qsd_adjust(const struct lu_env *, struct lquota_entry *);

/* qsd_writeback.c */
void qsd_upd_schedule(struct qsd_qtype_info *, struct lquota_entry *,
		      union lquota_id *, union lquota_rec *, __u64, bool);
void qsd_bump_version(struct qsd_qtype_info *, __u64, bool);
int qsd_start_upd_thread(struct qsd_instance *);
void qsd_stop_upd_thread(struct qsd_instance *);
void qsd_adjust_schedule(struct lquota_entry *, bool, bool);
#endif /* _QSD_INTERNAL_H */
