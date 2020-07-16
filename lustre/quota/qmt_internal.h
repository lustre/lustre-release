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
 * Copyright (c) 2012, 2017, Intel Corporation.
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
	/* root directory for this qmt */
	struct dt_object	*qmt_root;

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
	/* rw semaphore to protect pool list */
	struct rw_semaphore	 qmt_pool_lock;

	/* procfs root directory for this qmt */
	struct proc_dir_entry	*qmt_proc;

	/* dedicated thread in charge of space rebalancing */
	struct task_struct	*qmt_reba_task;

	/* list of lqe entry which need space rebalancing */
	struct list_head	 qmt_reba_list;

	/* lock protecting rebalancing list */
	spinlock_t		 qmt_reba_lock;

	unsigned long		 qmt_stopping:1; /* qmt is stopping */

};

struct qmt_pool_info;
#define QPI_MAXNAME	(LOV_MAXPOOLNAME + 1)
#define qmt_pool_global(qpi) \
	(!strncmp(qpi->qpi_name, GLB_POOL_NAME, \
		  strlen(GLB_POOL_NAME) + 1) ? true : false)
/* Draft for mdt pools */
union qmt_sarray {
	struct lu_tgt_pool	osts;
};

/* Since DOM support, data resources can exist
 * on both MDT and OST targets. */
enum {
	QMT_STYPE_MDT,
	QMT_STYPE_OST,
	QMT_STYPE_CNT
};

enum {
	/* set while recalc_thread is working */
	QPI_FLAG_RECALC_OFFSET,
};

/*
 * Per-pool quota information.
 * The qmt creates one such structure for each pool
 * with quota enforced. All the structures are kept in a list.
 * We currently only support the default data pool and default metadata pool.
 */
struct qmt_pool_info {
	/* chained list of all pools managed by the same qmt */
	struct list_head	 qpi_linkage;

	/* Could be  LQUOTA_RES_MD or LQUOTA_RES_DT */
	int			 qpi_rtype;
	char			 qpi_name[QPI_MAXNAME];

	union qmt_sarray	 qpi_sarr;
	/* recalculation thread pointer */
	struct task_struct	*qpi_recalc_task;
	/* rw semaphore to avoid acquire/release during
	 * pool recalculation. */
	struct rw_semaphore	 qpi_recalc_sem;
	unsigned long		 qpi_flags;

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
	int			 qpi_slv_nr[QMT_STYPE_CNT][LL_MAXQUOTAS];

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

static inline int qpi_slv_nr(struct qmt_pool_info *pool, int qtype)
{
	int i, sum = 0;

	for (i = 0; i < QMT_STYPE_CNT; i++)
		sum += pool->qpi_slv_nr[i][qtype];

	return sum;
}

static inline int qpi_slv_nr_by_rtype(struct qmt_pool_info *pool, int qtype)
{
	if (pool->qpi_rtype == LQUOTA_RES_DT)
		/* Here should be qpi_slv_nr() if MDTs will be added
		 * to quota pools */
		return pool->qpi_slv_nr[QMT_STYPE_OST][qtype];
	else
		return pool->qpi_slv_nr[QMT_STYPE_MDT][qtype];
}
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

#define QMT_MAX_POOL_NUM	16
/* Common data shared by qmt handlers */
struct qmt_thread_info {
	union lquota_rec	 qti_rec;
	union lquota_id		 qti_id;
	char			 qti_buf[MTI_NAME_MAXLEN];
	struct lu_fid		 qti_fid;
	struct ldlm_res_id	 qti_resid;
	union ldlm_gl_desc	 qti_gl_desc;
	struct quota_body	 qti_body;
	union {
		struct qmt_lqe_restore	qti_lqes_rstr_small[QMT_MAX_POOL_NUM];
		struct qmt_lqe_restore	*qti_lqes_rstr;
	};
	union {
		struct qmt_pool_info	*qti_pools_small[QMT_MAX_POOL_NUM];
		/* Pointer to an array of qpis in case when
		 * qti_pools_cnt > QMT_MAX_POOL_NUM. */
		struct qmt_pool_info	**qti_pools;
	};
	/* The number of pools in qti_pools */
	int			 qti_pools_cnt;
	/* Maximum number of elements in qti_pools array.
	 * By default it is QMT_MAX_POOL_NUM. */
	int			 qti_pools_num;
	int			 qti_glbl_lqe_idx;
	/* The same is for lqe ... */
	union {
		struct lquota_entry	*qti_lqes_small[QMT_MAX_POOL_NUM];
		/* Pointer to an array of lqes in case when
		 * qti_lqes_cnt > QMT_MAX_POOL_NUM. */
		struct lquota_entry	**qti_lqes;
	};
	/* The number of lqes in qti_lqes */
	int			 qti_lqes_cnt;
	/* Maximum number of elements in qti_lqes array.
	 * By default it is QMT_MAX_POOL_NUM. */
	int			 qti_lqes_num;
};

extern struct lu_context_key qmt_thread_key;

/* helper function to extract qmt_thread_info from current environment */
static inline
struct qmt_thread_info *qmt_info(const struct lu_env *env)
{
	return lu_env_info(env, &qmt_thread_key);
}

#define qti_lqes_num(env)	(qmt_info(env)->qti_lqes_num)
#define qti_lqes_cnt(env)	(qmt_info(env)->qti_lqes_cnt)
#define qti_glbl_lqe_idx(env)	(qmt_info(env)->qti_glbl_lqe_idx)
#define qti_lqes(env)		(qti_lqes_num(env) > QMT_MAX_POOL_NUM ? \
					qmt_info(env)->qti_lqes : \
					qmt_info(env)->qti_lqes_small)
#define qti_lqes_rstr(env)	(qti_lqes_num(env) > QMT_MAX_POOL_NUM ? \
					qmt_info(env)->qti_lqes_rstr : \
					qmt_info(env)->qti_lqes_rstr_small)
#define qti_lqes_glbl(env)	(qti_lqes(env)[qti_glbl_lqe_idx(env)])
#define qti_lqe_hard(env, i)	(qti_lqes(env)[i]->lqe_hardlimit)
#define qti_lqe_soft(env, i)	(qti_lqes(env)[i]->lqe_softlimit)
#define qti_lqe_granted(env, i)	(qti_lqes(env)[i]->lqe_granted)
#define qti_lqe_qunit(env, i)	(qti_lqes(env)[i]->lqe_qunit)

/* helper routine to convert a lu_device into a qmt_device */
static inline struct qmt_device *lu2qmt_dev(struct lu_device *ld)
{
	return container_of_safe(lu2dt_dev(ld), struct qmt_device, qmt_dt_dev);
}

/* helper routine to convert a qmt_device into lu_device */
static inline struct lu_device *qmt2lu_dev(struct qmt_device *qmt)
{
	return &qmt->qmt_dt_dev.dd_lu_dev;
}

#define LQE_ROOT(lqe)    (lqe2qpi(lqe)->qpi_root)
#define LQE_GLB_OBJ(lqe) (lqe2qpi(lqe)->qpi_glb_obj[lqe_qtype(lqe)])

/* helper function returning grace time to use for a given lquota entry */
static inline __u64 qmt_lqe_grace(struct lquota_entry *lqe)
{
	struct qmt_pool_info	*pool = lqe2qpi(lqe);
	struct lquota_entry	*grace_lqe;

	grace_lqe = pool->qpi_grace_lqe[lqe_qtype(lqe)];
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

static inline void qmt_restore_lqes(const struct lu_env *env)
{
	int i;

	for (i = 0; i < qti_lqes_cnt(env); i++)
		qmt_restore(qti_lqes(env)[i], &qti_lqes_rstr(env)[i]);
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

static inline bool qmt_space_exhausted_lqes(const struct lu_env *env, __u64 now)
{
	bool exhausted = false;
	int i;

	for (i = 0; i < qti_lqes_cnt(env) && !exhausted; i++)
		exhausted |= qmt_space_exhausted(qti_lqes(env)[i], now);

	return exhausted;
}

/* helper routine clearing the default quota setting  */
static inline void qmt_lqe_clear_default(struct lquota_entry *lqe)
{
	lqe->lqe_is_default = false;
	lqe->lqe_gracetime &= ~((__u64)LQUOTA_FLAG_DEFAULT <<
							LQUOTA_GRACE_BITS);
}

/* number of seconds to wait for slaves to release quota space after
 * rebalancing */
#define QMT_REBA_TIMEOUT 2

/* qmt_pool.c */

void qmt_pool_free(const struct lu_env *, struct qmt_pool_info *);
/*
 * Reference counter management for qmt_pool_info structures
 */
static inline void qpi_getref(struct qmt_pool_info *pool)
{
	atomic_inc(&pool->qpi_ref);
}

static inline void qpi_putref(const struct lu_env *env,
			      struct qmt_pool_info *pool)
{
	LASSERT(atomic_read(&pool->qpi_ref) > 0);
	if (atomic_dec_and_test(&pool->qpi_ref))
		qmt_pool_free(env, pool);
}


void qmt_pool_fini(const struct lu_env *, struct qmt_device *);
int qmt_pool_init(const struct lu_env *, struct qmt_device *);
int qmt_pool_prepare(const struct lu_env *, struct qmt_device *,
		   struct dt_object *, char *);
int qmt_pool_new_conn(const struct lu_env *, struct qmt_device *,
		      struct lu_fid *, struct lu_fid *, __u64 *,
		      struct obd_uuid *);

#define GLB_POOL_NAME	"0x0"
#define qmt_pool_lookup_glb(env, qmt, type) \
		qmt_pool_lookup(env, qmt, type, NULL, -1, false)
#define qmt_pool_lookup_name(env, qmt, type, name) \
		qmt_pool_lookup(env, qmt, type, name, -1, false)
#define qmt_pool_lookup_arr(env, qmt, type, idx) \
		qmt_pool_lookup(env, qmt, type, NULL, idx, true)
struct qmt_pool_info *qmt_pool_lookup(const struct lu_env *env,
					     struct qmt_device *qmt,
					     int rtype,
					     char *pool_name,
					     int idx,
					     bool add);
struct lquota_entry *qmt_pool_lqe_lookup(const struct lu_env *,
					 struct qmt_device *, int, int,
					 union lquota_id *, char *);
int qmt_pool_lqes_lookup(const struct lu_env *, struct qmt_device *, int,
			 int, int, union lquota_id *, char *, int);
int qmt_pool_lqes_lookup_spec(const struct lu_env *env, struct qmt_device *qmt,
			      int rtype, int qtype, union lquota_id *qid);
void qmt_lqes_sort(const struct lu_env *env);
int qmt_pool_new(struct obd_device *obd, char *poolname);
int qmt_pool_add(struct obd_device *obd, char *poolname, char *ostname);
int qmt_pool_rem(struct obd_device *obd, char *poolname, char *ostname);
int qmt_pool_del(struct obd_device *obd, char *poolname);

struct rw_semaphore *qmt_sarr_rwsem(struct qmt_pool_info *qpi);
int qmt_sarr_get_idx(struct qmt_pool_info *qpi, int arr_idx);
unsigned int qmt_sarr_count(struct qmt_pool_info *qpi);

/* qmt_entry.c */
extern const struct lquota_entry_operations qmt_lqe_ops;
int qmt_lqe_set_default(const struct lu_env *env, struct qmt_pool_info *pool,
			struct lquota_entry *lqe, bool create_record);
struct thandle *qmt_trans_start_with_slv(const struct lu_env *,
					 struct lquota_entry *,
					 struct dt_object *,
					 bool);
struct thandle *qmt_trans_start(const struct lu_env *, struct lquota_entry *);
int qmt_glb_write_lqes(const struct lu_env *, struct thandle *, __u32, __u64 *);
int qmt_glb_write(const struct lu_env *, struct thandle *,
		  struct lquota_entry *, __u32, __u64 *);
int qmt_slv_write(const struct lu_env *, struct thandle *,
		  struct lquota_entry *, struct dt_object *, __u32, __u64 *,
		  __u64);
int qmt_slv_read(const struct lu_env *,  union lquota_id *,
		 struct dt_object *, __u64 *);
int qmt_validate_limits(struct lquota_entry *, __u64, __u64);
bool qmt_adjust_qunit(const struct lu_env *, struct lquota_entry *);
bool qmt_adjust_edquot(struct lquota_entry *, __u64);

#define qmt_adjust_edquot_notify(env, qmt, now, qb_flags) \
	  qmt_adjust_edquot_qunit_notify(env, qmt, now, true, false, qb_flags)
#define qmt_adjust_qunit_notify(env, qmt, qb_flags) \
	  qmt_adjust_edquot_qunit_notify(env, qmt, 0, false, true, qb_flags)
#define qmt_adjust_and_notify(env, qmt, now, qb_flags) \
	  qmt_adjust_edquot_qunit_notify(env, qmt, now, true, true, qb_flags)
bool qmt_adjust_edquot_qunit_notify(const struct lu_env *, struct qmt_device *,
				    __u64, bool, bool, __u32);
bool qmt_revalidate(const struct lu_env *, struct lquota_entry *);
void qmt_revalidate_lqes(const struct lu_env *, struct qmt_device *, __u32);
__u64 qmt_alloc_expand(struct lquota_entry *, __u64, __u64);

void qti_lqes_init(const struct lu_env *env);
int qti_lqes_add(const struct lu_env *env, struct lquota_entry *lqe);
void qti_lqes_del(const struct lu_env *env, int index);
void qti_lqes_fini(const struct lu_env *env);
int qti_lqes_min_qunit(const struct lu_env *env);
int qti_lqes_edquot(const struct lu_env *env);
int qti_lqes_restore_init(const struct lu_env *env);
void qti_lqes_restore_fini(const struct lu_env *env);
void qti_lqes_write_lock(const struct lu_env *env);
void qti_lqes_write_unlock(const struct lu_env *env);

struct lqe_glbl_data *qmt_alloc_lqe_gd(struct qmt_pool_info *, int);
void qmt_free_lqe_gd(struct lqe_glbl_data *);
void qmt_setup_lqe_gd(const struct lu_env *,  struct qmt_device *,
		    struct lquota_entry *, struct lqe_glbl_data *, int);
#define qmt_seed_glbe_edquot(env, lqeg) \
		qmt_seed_glbe_all(env, lqeg, false, true)
#define qmt_seed_glbe_qunit(env, lqeg) \
		qmt_seed_glbe_all(env, lqeg, true, false)
#define qmt_seed_glbe(env, lqeg) \
		qmt_seed_glbe_all(env, lqeg, true, true)
void qmt_seed_glbe_all(const struct lu_env *, struct lqe_glbl_data *,
		       bool , bool);

/* qmt_handler.c */
int qmt_set_with_lqe(const struct lu_env *env, struct qmt_device *qmt,
		     struct lquota_entry *lqe, __u64 hard, __u64 soft,
		     __u64 time, __u32 valid, bool is_default, bool is_updated);
int qmt_dqacq0(const struct lu_env *, struct qmt_device *, struct obd_uuid *,
	       __u32, __u64, __u64, struct quota_body *);
int qmt_uuid2idx(struct obd_uuid *, int *);

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
