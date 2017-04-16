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
 * Copyright (c) 2012, 2016, Intel Corporation.
 * Use is subject to license terms.
 */

#ifndef _QMT_INTERNAL_H
#define _QMT_INTERNAL_H

#include "lquota_internal.h"

/*
 * The Quota Master Target Device.
 * The qmt is responsible for:
 * - all interactions with MDT0 (provide request handlers, share ldlm namespace,
 *   manage ldlm lvbo, ...)
 * - all quota lock management (i.e. global quota locks as well as per-ID locks)
 * - manage the quota pool configuration
 *
 * That's the structure MDT0 connects to in mdt_quota_init().
 */
struct qmt_device {
	/* Super-class. dt_device/lu_device for this master target */
	struct dt_device	qmt_dt_dev;

	/* service name of this qmt */
	char			qmt_svname[MAX_OBD_NAME];

	/* Reference to the next device in the side stack
	 * The child device is actually the OSD device where we store the quota
	 * index files */
	struct obd_export	*qmt_child_exp;
	struct dt_device	*qmt_child;

	/* pointer to ldlm namespace to be used for quota locks */
	struct ldlm_namespace	*qmt_ns;

	/* Hash table containing a qmt_pool_info structure for each pool
	 * this quota master is in charge of. We only have 2 pools in this
	 * hash for the time being:
	 * - one for quota management on the default metadata pool
	 * - one for quota managment on the default data pool
	 *
	 * Once we support quota on non-default pools, then more pools will
	 * be added to this hash table and pool master setup would have to be
	 * handled via configuration logs */
	struct cfs_hash		*qmt_pool_hash;

	/* List of pools managed by this master target */
	struct list_head	 qmt_pool_list;

	/* procfs root directory for this qmt */
	struct proc_dir_entry	*qmt_proc;

	/* dedicated thread in charge of space rebalancing */
	struct ptlrpc_thread	 qmt_reba_thread;

	/* list of lqe entry which need space rebalancing */
	struct list_head	 qmt_reba_list;

	/* lock protecting rebalancing list */
	spinlock_t		 qmt_reba_lock;

	unsigned long		 qmt_stopping:1; /* qmt is stopping */

};

/*
 * Per-pool quota information.
 * The qmt creates one such structure for each pool
 * with quota enforced. All the structures are kept in a hash which is used to
 * determine whether or not quota is enforced for a given pool.
 * We currently only support the default data pool and default metadata pool
 * with the pool_id 0.
 */
struct qmt_pool_info {
	/* link to qmt's pool hash */
	struct hlist_node	 qpi_hash;

	/* chained list of all pools managed by the same qmt */
	struct list_head	 qpi_linkage;

	/* Pool key composed of pool_id | (pool_type << 16)
	 * Only pool ID 0 is supported for now and the pool type is either
	 * QUOTA_RES_MD or QUOTA_RES_DT.
	 * immutable after creation. */
	__u32			 qpi_key;

	/* track users of this pool instance */
	atomic_t		 qpi_ref;

	/* back pointer to master target
	 * immutable after creation. */
	struct qmt_device	*qpi_qmt;

	/* pointer to dt object associated with global indexes for both user
	 * and group quota */
	struct dt_object	*qpi_glb_obj[LL_MAXQUOTAS];

	/* A pool supports two different quota types: user and group quota.
	 * Each quota type has its own global index and lquota_entry hash table.
	 */
	struct lquota_site	*qpi_site[LL_MAXQUOTAS];

	/* number of slaves registered for each quota types */
	int			 qpi_slv_nr[LL_MAXQUOTAS];

	/* reference on lqe (ID 0) storing grace time. */
	struct lquota_entry	*qpi_grace_lqe[LL_MAXQUOTAS];

	/* procfs root directory for this pool */
	struct proc_dir_entry	*qpi_proc;

	/* pool directory where all indexes related to this pool instance are
	 * stored */
	struct dt_object	*qpi_root;

	/* Global quota parameters which apply to all quota type */
	/* the least value of qunit */
	unsigned long		 qpi_least_qunit;

	/* Least value of qunit when soft limit is exceeded.
	 *
	 * When soft limit is exceeded, qunit will be shrinked to least_qunit
	 * (1M for block limit), that results in significant write performance
	 * drop since the client will turn to sync write from now on.
	 *
	 * To retain the write performance in an acceptable level, we choose
	 * to sacrifice grace time accuracy a bit and use a larger least_qunit
	 * when soft limit is exceeded. It's (qpi_least_qunit * 4) by default,
	 * and user may enlarge it via procfs to get even better performance
	 * (with the cost of losing more grace time accuracy).
	 *
	 * See qmt_calc_softlimit().
	 */
	unsigned long		 qpi_soft_least_qunit;
};

/*
 * Helper routines and prototypes
 */

/* helper routine to find qmt_pool_info associated a lquota_entry */
static inline struct qmt_pool_info *lqe2qpi(struct lquota_entry *lqe)
{
	LASSERT(lqe_is_master(lqe));
	return (struct qmt_pool_info *)lqe->lqe_site->lqs_parent;
}

/* return true if someone holds either a read or write lock on the lqe */
static inline bool lqe_is_locked(struct lquota_entry *lqe)
{
	LASSERT(lqe_is_master(lqe));
	if (down_write_trylock(&lqe->lqe_sem) == 0)
		return true;
	lqe_write_unlock(lqe);
	return false;
}

/* value to be restored if someone wrong happens during lqe writeback */
struct qmt_lqe_restore {
	__u64	qlr_hardlimit;
	__u64	qlr_softlimit;
	__u64	qlr_gracetime;
	__u64	qlr_granted;
	__u64	qlr_qunit;
};

/* Common data shared by qmt handlers */
struct qmt_thread_info {
	union lquota_rec	qti_rec;
	union lquota_id		qti_id;
	char			qti_buf[MTI_NAME_MAXLEN];
	struct lu_fid		qti_fid;
	struct ldlm_res_id	qti_resid;
	union ldlm_gl_desc	qti_gl_desc;
	struct quota_body	qti_body;
	struct qmt_lqe_restore	qti_restore;
};

extern struct lu_context_key qmt_thread_key;

/* helper function to extract qmt_thread_info from current environment */
static inline
struct qmt_thread_info *qmt_info(const struct lu_env *env)
{
	struct qmt_thread_info	*info;

	info = lu_context_key_get(&env->le_ctx, &qmt_thread_key);
	if (info == NULL) {
		lu_env_refill((struct lu_env *)env);
		info = lu_context_key_get(&env->le_ctx, &qmt_thread_key);
	}
	LASSERT(info);
	return info;
}

/* helper routine to convert a lu_device into a qmt_device */
static inline struct qmt_device *lu2qmt_dev(struct lu_device *ld)
{
	return container_of0(lu2dt_dev(ld), struct qmt_device, qmt_dt_dev);
}

/* helper routine to convert a qmt_device into lu_device */
static inline struct lu_device *qmt2lu_dev(struct qmt_device *qmt)
{
	return &qmt->qmt_dt_dev.dd_lu_dev;
}

#define LQE_ROOT(lqe)    (lqe2qpi(lqe)->qpi_root)
#define LQE_GLB_OBJ(lqe) (lqe2qpi(lqe)->qpi_glb_obj[lqe->lqe_site->lqs_qtype])

/* helper function returning grace time to use for a given lquota entry */
static inline __u64 qmt_lqe_grace(struct lquota_entry *lqe)
{
	struct qmt_pool_info	*pool = lqe2qpi(lqe);
	struct lquota_entry	*grace_lqe;

	grace_lqe = pool->qpi_grace_lqe[lqe->lqe_site->lqs_qtype];
	LASSERT(grace_lqe != NULL);

	return grace_lqe->lqe_gracetime;
}

static inline void qmt_restore(struct lquota_entry *lqe,
			       struct qmt_lqe_restore *restore)
{
	lqe->lqe_hardlimit = restore->qlr_hardlimit;
	lqe->lqe_softlimit = restore->qlr_softlimit;
	lqe->lqe_gracetime = restore->qlr_gracetime;
	lqe->lqe_granted   = restore->qlr_granted;
	lqe->lqe_qunit     = restore->qlr_qunit;
}

#define QMT_GRANT(lqe, slv, cnt)             \
	do {                                 \
		(lqe)->lqe_granted += (cnt); \
		(slv) += (cnt);              \
	} while (0)
#define QMT_REL(lqe, slv, cnt)               \
	do {                                 \
		(lqe)->lqe_granted -= (cnt); \
		(slv) -= (cnt);              \
	} while (0)

/* helper routine returning true when reached hardlimit */
static inline bool qmt_hard_exhausted(struct lquota_entry *lqe)
{
	if (lqe->lqe_hardlimit != 0 && lqe->lqe_granted >= lqe->lqe_hardlimit)
		return true;
	return false;
}

/* helper routine returning true when reached softlimit */
static inline bool qmt_soft_exhausted(struct lquota_entry *lqe, __u64 now)
{
	if (lqe->lqe_softlimit != 0 && lqe->lqe_granted > lqe->lqe_softlimit &&
	    lqe->lqe_gracetime != 0 && now >= lqe->lqe_gracetime)
		return true;
	return false;
}

/* helper routine returning true when the id has run out of quota space:
 * - reached hardlimit
 * OR
 * - reached softlimit and grace time expired already */
static inline bool qmt_space_exhausted(struct lquota_entry *lqe, __u64 now)
{
	return (qmt_hard_exhausted(lqe) || qmt_soft_exhausted(lqe, now));
}

/* number of seconds to wait for slaves to release quota space after
 * rebalancing */
#define QMT_REBA_TIMEOUT 2

/* qmt_pool.c */
void qmt_pool_fini(const struct lu_env *, struct qmt_device *);
int qmt_pool_init(const struct lu_env *, struct qmt_device *);
int qmt_pool_prepare(const struct lu_env *, struct qmt_device *,
		   struct dt_object *);
int qmt_pool_new_conn(const struct lu_env *, struct qmt_device *,
		      struct lu_fid *, struct lu_fid *, __u64 *,
		      struct obd_uuid *);
struct lquota_entry *qmt_pool_lqe_lookup(const struct lu_env *,
					 struct qmt_device *, int, int, int,
					 union lquota_id *);
/* qmt_entry.c */
extern struct lquota_entry_operations qmt_lqe_ops;
struct thandle *qmt_trans_start_with_slv(const struct lu_env *,
					 struct lquota_entry *,
					 struct dt_object *,
					 struct qmt_lqe_restore *);
struct thandle *qmt_trans_start(const struct lu_env *, struct lquota_entry *,
				struct qmt_lqe_restore *);
int qmt_glb_write(const struct lu_env *, struct thandle *,
		  struct lquota_entry *, __u32, __u64 *);
int qmt_slv_write(const struct lu_env *, struct thandle *,
		  struct lquota_entry *, struct dt_object *, __u32, __u64 *,
		  __u64);
int qmt_slv_read(const struct lu_env *, struct lquota_entry *,
		 struct dt_object *, __u64 *);
int qmt_validate_limits(struct lquota_entry *, __u64, __u64);
void qmt_adjust_qunit(const struct lu_env *, struct lquota_entry *);
void qmt_adjust_edquot(struct lquota_entry *, __u64);
void qmt_revalidate(const struct lu_env *, struct lquota_entry *);
__u64 qmt_alloc_expand(struct lquota_entry *, __u64, __u64);

/* qmt_handler.c */
int qmt_dqacq0(const struct lu_env *, struct lquota_entry *,
	       struct qmt_device *, struct obd_uuid *, __u32, __u64, __u64,
	       struct quota_body *);

/* qmt_lock.c */
int qmt_intent_policy(const struct lu_env *, struct lu_device *,
		      struct ptlrpc_request *, struct ldlm_lock **, int);
int qmt_lvbo_init(struct lu_device *, struct ldlm_resource *);
int qmt_lvbo_update(struct lu_device *, struct ldlm_resource *,
		    struct ptlrpc_request *, int);
int qmt_lvbo_size(struct lu_device *, struct ldlm_lock *);
int qmt_lvbo_fill(struct lu_device *, struct ldlm_lock *, void *, int);
int qmt_lvbo_free(struct lu_device *, struct ldlm_resource *);
int qmt_start_reba_thread(struct qmt_device *);
void qmt_stop_reba_thread(struct qmt_device *);
void qmt_glb_lock_notify(const struct lu_env *, struct lquota_entry *, __u64);
void qmt_id_lock_notify(struct qmt_device *, struct lquota_entry *);
#endif /* _QMT_INTERNAL_H */
