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
 * Copyright (c) 2012 Whamcloud, Inc.
 * Use is subject to license terms.
 */

#include "lquota_internal.h"

#ifndef _QSD_INTERNAL_H
#define _QSD_INTERNAL_H

struct qsd_type_info;

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

	/* pool ID is always 0 for now */
	int			 qsd_pool_id;

	/* dt_device associated with this qsd instance */
	struct dt_device	*qsd_dev;

	/* procfs directory where information related to the underlying slaves
	 * are exported */
	cfs_proc_dir_entry_t	*qsd_proc;

	/* on-disk directory where to store index files for this qsd instance */
	struct dt_object	*qsd_root;

	/* We create 2 quota slave instances:
	 * - one for user quota
	 * - one for group quota
	 *
	 * This will have to be revisited if new quota types are added in the
	 * future. For the time being, we can just use an array. */
	struct qsd_qtype_info	*qsd_type_array[MAXQUOTAS];

	unsigned long		 qsd_is_md:1,    /* managing quota for mdt */
				 qsd_stopping:1; /* qsd_instance is stopping */
};

/*
 * Per-type quota information.
 * Quota slave instance for a specific quota type. The qsd instance has one such
 * structure for each quota type (i.e. user & group).
 */
struct qsd_qtype_info {
	/* reference count incremented by each user of this structure */
	cfs_atomic_t		 qqi_ref;

	/* quota type, either USRQUOTA or GRPQUOTA
	 * immutable after creation. */
	int			 qqi_qtype;

	/* Global index FID to use for this quota type */
	struct lu_fid		 qqi_fid;

	/* back pointer to qsd device
	 * immutable after creation. */
	struct qsd_instance	*qqi_qsd;

	/* Local index files storing quota settings for this quota type */
	struct dt_object	*qqi_acct_obj; /* accounting object */
	struct dt_object	*qqi_slv_obj;  /* slave index copy */
	struct dt_object	*qqi_glb_obj;  /* global index copy */

	/* Current object versions */
	__u64			 qqi_slv_ver; /* slave index version */
	__u64			 qqi_glb_ver; /* global index version */
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
	cfs_atomic_inc(&qqi->qqi_ref);
}

static inline void qqi_putref(struct qsd_qtype_info *qqi)
{
	LASSERT(cfs_atomic_read(&qqi->qqi_ref) > 0);
	cfs_atomic_dec(&qqi->qqi_ref);
}

#define QSD_RES_TYPE(qsd) ((qsd)->qsd_is_md ? LQUOTA_RES_MD : LQUOTA_RES_DT)

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
	union ldlm_wire_lvb		qti_lvb;
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
	struct qsd_thread_info *info;

	info = lu_context_key_get(&env->le_ctx, &qsd_thread_key);
	if (info == NULL) {
		lu_env_refill((struct lu_env *)env);
		info = lu_context_key_get(&env->le_ctx, &qsd_thread_key);
	}
	LASSERT(info);
	return info;
}

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

/* qsd_entry.c */
extern struct lquota_entry_operations qsd_lqe_ops;
int qsd_refresh_usage(const struct lu_env *, struct lquota_entry *);
int qsd_update_index(const struct lu_env *, struct qsd_qtype_info *,
		     union lquota_id *, bool, __u64, void *);
int qsd_update_lqe(const struct lu_env *, struct lquota_entry *, bool,
		   void *);
int qsd_write_version(const struct lu_env *, struct qsd_qtype_info *,
		      __u64, bool);

/* qsd_request.c */
typedef void (*qsd_req_completion_t) (const struct lu_env *,
				      struct qsd_qtype_info *,
				      struct quota_body *, struct quota_body *,
				      struct lustre_handle *,
				      union ldlm_wire_lvb *, void *, int);
int qsd_send_dqacq(const struct lu_env *, struct obd_export *,
		   struct quota_body *, bool, qsd_req_completion_t,
		   struct qsd_qtype_info *, struct lustre_handle *,
		   struct lquota_entry *);
int qsd_intent_lock(const struct lu_env *, struct obd_export *,
		    struct quota_body *, bool, int, qsd_req_completion_t,
		    struct qsd_qtype_info *, union ldlm_wire_lvb *, void *);
int qsd_fetch_index(const struct lu_env *, struct obd_export *,
		    struct idx_info *, unsigned int, cfs_page_t **, bool *);

/* qsd_writeback.c */
/* XXX to be replaced with real function when reintegration landed. */
static inline void qsd_bump_version(struct qsd_qtype_info *qqi, __u64 ver,
				    bool global)
{
}

#endif /* _QSD_INTERNAL_H */
