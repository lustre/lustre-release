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
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

/*
 * A Quota Master Target has a list(qmt_pool_list) where it stores qmt_pool_info
 * structures. There is one such structure for each pool managed by the QMT.
 *
 * Each pool can have different quota types enforced (typically user & group
 * quota). A pool is in charge of managing lquota_entry structures for each
 * quota type. This is done by creating one lquota_entry site per quota
 * type. A site stores entries in a hash table and read quota settings from disk
 * when a given ID isn't present in the hash.
 *
 * The pool API exported here is the following:
 * - qmt_pool_init(): initializes the general QMT structures used to manage
 *                    pools.
 * - qmt_pool_fini(): frees the structures allocated by qmt_pool_fini().
 * - qmt_pool_prepare(): sets up the on-disk indexes associated with each pool.
 * - qmt_pool_new_conn(): is used to create a new slave index file.
 * - qmt_pool_lqe_lookup(): returns an up-to-date lquota entry associated with
 *                          a given ID.
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <obd_class.h>
#include <lprocfs_status.h>
#include "qmt_internal.h"

static inline int qmt_sarr_pool_init(struct qmt_pool_info *qpi);
static inline int qmt_sarr_pool_add(struct qmt_pool_info *qpi,
				    int idx, int min);
static inline int qmt_sarr_pool_rem(struct qmt_pool_info *qpi, int idx);
static inline int qmt_sarr_pool_free(struct qmt_pool_info *qpi);
static inline int qmt_sarr_check_idx(struct qmt_pool_info *qpi, int idx);
static inline void qmt_stop_pool_recalc(struct qmt_pool_info *qpi);

/*
 * Static helper functions not used outside the scope of this file
 */

static inline void qpi_putref_locked(struct qmt_pool_info *pool)
{
	LASSERT(atomic_read(&pool->qpi_ref) > 1);
	atomic_dec(&pool->qpi_ref);
}

/* some procfs helpers */
static int qpi_state_seq_show(struct seq_file *m, void *data)
{
	struct qmt_pool_info	*pool = m->private;
	int			 type;

	LASSERT(pool != NULL);

	seq_printf(m, "pool:\n"
		   "    id: %u\n"
		   "    type: %s\n"
		   "    ref: %d\n"
		   "    least qunit: %lu\n",
		   0,
		   RES_NAME(pool->qpi_rtype),
		   atomic_read(&pool->qpi_ref),
		   pool->qpi_least_qunit);

	for (type = 0; type < LL_MAXQUOTAS; type++)
		seq_printf(m, "    %s:\n"
			   "        #slv: %d\n"
			   "        #lqe: %d\n",
			   qtype_name(type),
			   qpi_slv_nr(pool, type),
		    atomic_read(&pool->qpi_site[type]->lqs_hash->hs_count));

	return 0;
}
LPROC_SEQ_FOPS_RO(qpi_state);

static int qpi_soft_least_qunit_seq_show(struct seq_file *m, void *data)
{
	struct qmt_pool_info	*pool = m->private;
	LASSERT(pool != NULL);

	seq_printf(m, "%lu\n", pool->qpi_soft_least_qunit);
	return 0;
}

static ssize_t
qpi_soft_least_qunit_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct qmt_pool_info *pool = m->private;
	long long least_qunit;
	int qunit, rc;

	LASSERT(pool != NULL);

	/* Not tuneable for inode limit */
	if (pool->qpi_rtype != LQUOTA_RES_DT)
		return -EINVAL;

	rc = kstrtoll_from_user(buffer, count, 0, &least_qunit);
	if (rc)
		return rc;

	/* Miminal qpi_soft_least_qunit */
	qunit = pool->qpi_least_qunit << 2;
	/* The value must be power of miminal qpi_soft_least_qunit, see
	 * how the qunit is adjusted in qmt_adjust_qunit(). */
	while (qunit > 0 && qunit < least_qunit)
		qunit <<= 2;
	if (qunit <= 0)
		qunit = INT_MAX & ~3;

	pool->qpi_soft_least_qunit = qunit;
	return count;
}
LPROC_SEQ_FOPS(qpi_soft_least_qunit);

static struct lprocfs_vars lprocfs_quota_qpi_vars[] = {
	{ .name	=	"info",
	  .fops	=	&qpi_state_fops	},
	{ .name =	"soft_least_qunit",
	  .fops =	&qpi_soft_least_qunit_fops },
	{ NULL }
};

/*
 * Allocate a new qmt_pool_info structure and add it to qmt_pool_list.
 *
 * \param env       - is the environment passed by the caller
 * \param qmt       - is the quota master target
 * \param pool_type - is the resource type of this pool instance, either
 *                    LQUOTA_RES_MD or LQUOTA_RES_DT.
 *
 * \retval - 0 on success, appropriate error on failure
 */
static int qmt_pool_alloc(const struct lu_env *env, struct qmt_device *qmt,
			  char *pool_name, int pool_type)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct qmt_pool_info	*pool;
	int			 rc = 0;
	ENTRY;

	OBD_ALLOC_PTR(pool);
	if (pool == NULL)
		RETURN(-ENOMEM);
	INIT_LIST_HEAD(&pool->qpi_linkage);
	init_rwsem(&pool->qpi_recalc_sem);

	pool->qpi_rtype = pool_type;

	/* initialize refcount to 1, hash table will then grab an additional
	 * reference */
	atomic_set(&pool->qpi_ref, 1);

	/* set up least qunit size to use for this pool */
	pool->qpi_least_qunit = LQUOTA_LEAST_QUNIT(pool_type);
	if (pool_type == LQUOTA_RES_DT)
		pool->qpi_soft_least_qunit = pool->qpi_least_qunit << 2;
	else
		pool->qpi_soft_least_qunit = pool->qpi_least_qunit;

	/* grab reference on master target that this pool belongs to */
	lu_device_get(qmt2lu_dev(qmt));
	lu_ref_add(&qmt2lu_dev(qmt)->ld_reference, "pool", pool);
	pool->qpi_qmt = qmt;

	/* create pool proc directory */
	snprintf(qti->qti_buf, LQUOTA_NAME_MAX, "%s-%s",
		 RES_NAME(pool_type), pool_name);
	strncpy(pool->qpi_name, pool_name, QPI_MAXNAME);
	pool->qpi_proc = lprocfs_register(qti->qti_buf, qmt->qmt_proc,
					  lprocfs_quota_qpi_vars, pool);
	if (IS_ERR(pool->qpi_proc)) {
		rc = PTR_ERR(pool->qpi_proc);
		CERROR("%s: failed to create proc entry for pool %s (%d)\n",
		       qmt->qmt_svname, qti->qti_buf, rc);
		pool->qpi_proc = NULL;
		GOTO(out, rc);
	}

	rc = qmt_sarr_pool_init(pool);
	if (rc)
		GOTO(out, rc);

	/* add to qmt pool list */
	down_write(&qmt->qmt_pool_lock);
	list_add_tail(&pool->qpi_linkage, &qmt->qmt_pool_list);
	up_write(&qmt->qmt_pool_lock);
	EXIT;
out:
	if (rc)
		/* this frees the pool structure since refcount is equal to 1 */
		qpi_putref(env, pool);
	return rc;
}

/*
 * Delete a qmt_pool_info instance and all structures associated.
 *
 * \param env  - is the environment passed by the caller
 * \param pool - is the qmt_pool_info structure to free
 */
void qmt_pool_free(const struct lu_env *env, struct qmt_pool_info *pool)
{
	struct	qmt_device *qmt = pool->qpi_qmt;
	int	qtype;
	ENTRY;

	/* remove from list */
	down_write(&qmt->qmt_pool_lock);
	list_del_init(&pool->qpi_linkage);
	up_write(&qmt->qmt_pool_lock);

	if (atomic_read(&pool->qpi_ref) > 0)
		RETURN_EXIT;

	qmt_stop_pool_recalc(pool);
	qmt_sarr_pool_free(pool);

	/* release proc entry */
	if (pool->qpi_proc) {
		lprocfs_remove(&pool->qpi_proc);
		pool->qpi_proc = NULL;
	}

	/* release per-quota type site used to manage quota entries as well as
	 * references to global index files */
	for (qtype = 0; qtype < LL_MAXQUOTAS; qtype++) {
		/* release lqe storing grace time */
		if (pool->qpi_grace_lqe[qtype] != NULL)
			lqe_putref(pool->qpi_grace_lqe[qtype]);

		/* release site */
		if (pool->qpi_site[qtype] != NULL &&
		    !IS_ERR(pool->qpi_site[qtype]))
			lquota_site_free(env, pool->qpi_site[qtype]);
		/* release reference to global index */
		if (pool->qpi_glb_obj[qtype] != NULL &&
		    !IS_ERR(pool->qpi_glb_obj[qtype]))
			dt_object_put(env, pool->qpi_glb_obj[qtype]);
	}

	/* release reference on pool directory */
	if (pool->qpi_root != NULL && !IS_ERR(pool->qpi_root))
		dt_object_put(env, pool->qpi_root);

	/* release reference on the master target */
	if (pool->qpi_qmt != NULL) {
		struct lu_device *ld = qmt2lu_dev(pool->qpi_qmt);

		lu_ref_del(&ld->ld_reference, "pool", pool);
		lu_device_put(ld);
		pool->qpi_qmt = NULL;
	}

	LASSERT(list_empty(&pool->qpi_linkage));
	OBD_FREE_PTR(pool);
}

static inline void qti_pools_init(const struct lu_env *env)
{
	struct qmt_thread_info	*qti = qmt_info(env);

	qti->qti_pools_cnt = 0;
	qti->qti_pools_num = QMT_MAX_POOL_NUM;
}

#define qti_pools(qti)	(qti->qti_pools_num > QMT_MAX_POOL_NUM ? \
				qti->qti_pools : qti->qti_pools_small)
#define qti_pools_env(env) \
	(qmt_info(env)->qti_pools_num > QMT_MAX_POOL_NUM ? \
		qmt_info(env)->qti_pools : qmt_info(env)->qti_pools_small)
#define qti_pools_cnt(env)	(qmt_info(env)->qti_pools_cnt)

static inline int qti_pools_add(const struct lu_env *env,
				struct qmt_pool_info *qpi)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct qmt_pool_info	**pools = qti->qti_pools;

	pools = qti_pools(qti);
	LASSERTF(qti->qti_pools_num >= QMT_MAX_POOL_NUM,
		 "Forgot init? %p\n", qti);

	if (qti->qti_pools_cnt > qti->qti_pools_num) {
		OBD_ALLOC(pools, sizeof(qpi) * qti->qti_pools_num * 2);
		if (!pools)
			return -ENOMEM;
		memcpy(pools, qti_pools(qti), qti->qti_pools_cnt * sizeof(qpi));
		/* Don't need to free, if it is the very 1st allocation */
		if (qti->qti_pools_num > QMT_MAX_POOL_NUM)
			OBD_FREE(qti->qti_pools,
				 qti->qti_pools_num * sizeof(qpi));
		qti->qti_pools = pools;
		qti->qti_pools_num *= 2;
	}

	qpi_getref(qpi);
	/* Take this to protect pool's lqes against changing by
	 * recalculation thread. This would be unlocked at
	 * qti_pools_fini. */
	down_read(&qpi->qpi_recalc_sem);
	if (qmt_pool_global(qpi) && qti_pools_cnt(env) > 0) {
		pools[qti->qti_pools_cnt++] = pools[0];
		/* Store global pool always at index 0 */
		pools[0] = qpi;
	} else {
		pools[qti->qti_pools_cnt++] = qpi;
	}

	CDEBUG(D_QUOTA, "Pool %s is added, pools %p qti_pools %p pool_num %d\n",
	       qpi->qpi_name, pools, qti->qti_pools, qti->qti_pools_cnt);

	return 0;
}

static inline void qti_pools_fini(const struct lu_env *env)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct qmt_pool_info	**pools = qti->qti_pools;
	int i;

	LASSERT(qti->qti_pools_cnt > 0);

	pools = qti_pools(qti);
	for (i = 0; i < qti->qti_pools_cnt; i++) {
		up_read(&pools[i]->qpi_recalc_sem);
		qpi_putref(env, pools[i]);
	}

	if (qti->qti_pools_num > QMT_MAX_POOL_NUM)
		OBD_FREE(qti->qti_pools,
			 qti->qti_pools_num * sizeof(struct qmt_pool_info *));
}

/*
 * Look-up a pool in a list based on the type.
 *
 * \param env	- is the environment passed by the caller
 * \param qmt	- is the quota master target
 * \param rtype - is the type of this pool, either LQUOTA_RES_MD or
 *                    LQUOTA_RES_DT.
 * \param pool_name - is the pool name to search for
 * \param idx	- OST or MDT index to search for. When it is >= 0, function
 *		returns array with pointers to all pools that include
 *		targets with requested index.
 * \param add	- add to qti_pool_arr if true
 */
struct qmt_pool_info *qmt_pool_lookup(const struct lu_env *env,
					     struct qmt_device *qmt,
					     int rtype,
					     char *pool_name,
					     int idx, bool add)
{
	struct qmt_pool_info	*pos, *pool;
	int rc;
	ENTRY;

	down_read(&qmt->qmt_pool_lock);
	if (list_empty(&qmt->qmt_pool_list)) {
		up_read(&qmt->qmt_pool_lock);
		RETURN(ERR_PTR(-ENOENT));
	}

	CDEBUG(D_QUOTA, "type %d name %s index %d\n",
	       rtype, pool_name ?: "<none>", idx);
	/* Now just find a pool with correct type in a list. Further we need
	 * to go through the list and find a pool that includes requested OST
	 * or MDT. Possibly this would return a list of pools that includes
	 * needed target(OST/MDT). */
	pool = NULL;
	if (idx == -1 && !pool_name)
		pool_name = GLB_POOL_NAME;

	list_for_each_entry(pos, &qmt->qmt_pool_list, qpi_linkage) {
		if (pos->qpi_rtype != rtype)
			continue;

		if (idx >= 0 && !qmt_sarr_check_idx(pos, idx)) {
			rc = qti_pools_add(env, pos);
			if (rc)
				GOTO(out_err, rc);
			continue;
		}

		if (pool_name && !strncmp(pool_name, pos->qpi_name,
					  LOV_MAXPOOLNAME)) {
			pool = pos;
			if (add) {
				rc = qti_pools_add(env, pos);
				if (rc)
					GOTO(out_err, rc);
			} else {
				qpi_getref(pool);
			}
			break;
		}
	}
	up_read(&qmt->qmt_pool_lock);

	if (idx >= 0 && qti_pools_cnt(env))
		pool = qti_pools_env(env)[0];

	RETURN(pool ? : ERR_PTR(-ENOENT));
out_err:
	CERROR("%s: cannot add pool %s: err = %d\n",
		qmt->qmt_svname, pos->qpi_name, rc);
	RETURN(ERR_PTR(rc));
}

/*
 * Functions implementing the pool API, used by the qmt handlers
 */

/*
 * Destroy all pools which are still in the pool list.
 *
 * \param env - is the environment passed by the caller
 * \param qmt - is the quota master target
 *
 */
void qmt_pool_fini(const struct lu_env *env, struct qmt_device *qmt)
{
	struct qmt_pool_info *pool, *tmp;
	ENTRY;

	/* parse list of pool and destroy each element */
	list_for_each_entry_safe(pool, tmp, &qmt->qmt_pool_list, qpi_linkage) {
		/* release extra reference taken in qmt_pool_alloc */
		qpi_putref(env, pool);
	}
	LASSERT(list_empty(&qmt->qmt_pool_list));

	EXIT;
}

/*
 * Initialize pool configure for the quota master target. For now, we only
 * support the default data (i.e. all OSTs) and metadata (i.e. all the MDTs)
 * pool which are instantiated in this function.
 *
 * \param env - is the environment passed by the caller
 * \param qmt - is the quota master target for which we have to initialize the
 *              pool configuration
 *
 * \retval - 0 on success, appropriate error on failure
 */
int qmt_pool_init(const struct lu_env *env, struct qmt_device *qmt)
{
	int	res, rc = 0;
	ENTRY;

	INIT_LIST_HEAD(&qmt->qmt_pool_list);
	init_rwsem(&qmt->qmt_pool_lock);

	/* Instantiate pool master for the default data and metadata pool.
	 * This code will have to be revisited once we support quota on
	 * non-default pools */
	for (res = LQUOTA_FIRST_RES; res < LQUOTA_LAST_RES; res++) {
		rc = qmt_pool_alloc(env, qmt, GLB_POOL_NAME, res);
		if (rc)
			break;
	}

	if (rc)
		qmt_pool_fini(env, qmt);

	RETURN(rc);
}

static int qmt_slv_cnt(const struct lu_env *env, struct lu_fid *glb_fid,
		       char *slv_name, struct lu_fid *slv_fid, void *arg)
{
	struct obd_uuid uuid;
	int (*nr)[QMT_STYPE_CNT][LL_MAXQUOTAS] = arg;
	int stype, qtype;
	int rc;

	rc = lquota_extract_fid(glb_fid, NULL, &qtype);
	LASSERT(!rc);

	obd_str2uuid(&uuid, slv_name);
	stype = qmt_uuid2idx(&uuid, NULL);
	if (stype < 0)
		return stype;
	/* one more slave */
	(*nr)[stype][qtype]++;
	CDEBUG(D_QUOTA, "slv_name %s stype %d qtype %d nr %d\n",
			slv_name, stype, qtype, (*nr)[stype][qtype]);

	return 0;
}

/*
 * Set up on-disk index files associated with each pool.
 *
 * \param env - is the environment passed by the caller
 * \param qmt - is the quota master target for which we have to initialize the
 *              pool configuration
 * \param qmt_root - is the on-disk directory created for the QMT.
 * \param name - is the pool name that we need to setup. Setup all pools
 *		 in qmt_pool_list when name is NULL.
 *
 * \retval - 0 on success, appropriate error on failure
 */
int qmt_pool_prepare(const struct lu_env *env, struct qmt_device *qmt,
		     struct dt_object *qmt_root, char *name)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_glb_rec	*rec = &qti->qti_glb_rec;
	struct qmt_pool_info	*pool;
	struct dt_device	*dev = NULL;
	dt_obj_version_t	 version;
	struct list_head	*pos;
	int			 rc = 0, i, qtype;
	ENTRY;

	/* iterate over each pool in the list and allocate a quota site for each
	 * one. This involves creating a global index file on disk */
	list_for_each(pos, &qmt->qmt_pool_list) {
		struct dt_object	*obj;
		struct lquota_entry	*lqe;
		char			*pool_name;
		int			 rtype;

		pool = list_entry(pos, struct qmt_pool_info,
				  qpi_linkage);

		pool_name = pool->qpi_name;
		if (name && strncmp(pool_name, name, LOV_MAXPOOLNAME))
			continue;
		rtype = pool->qpi_rtype;
		if (dev == NULL)
			dev = pool->qpi_qmt->qmt_child;

		/* allocate directory for this pool */
		snprintf(qti->qti_buf, LQUOTA_NAME_MAX, "%s-%s",
			 RES_NAME(rtype), pool_name);
		obj = lquota_disk_dir_find_create(env, qmt->qmt_child, qmt_root,
						  qti->qti_buf);
		if (IS_ERR(obj))
			RETURN(PTR_ERR(obj));
		pool->qpi_root = obj;

		for (qtype = 0; qtype < LL_MAXQUOTAS; qtype++) {
			/* Generating FID of global index in charge of storing
			 * settings for this quota type */
			lquota_generate_fid(&qti->qti_fid, rtype, qtype);

			/* open/create the global index file for this quota
			 * type. If name is set, it means we came here from
			 * qmt_pool_new and can create glb index with a
			 * local generated FID. */
			obj = lquota_disk_glb_find_create(env, dev,
							  pool->qpi_root,
							  &qti->qti_fid,
							  name ? true : false);
			if (IS_ERR(obj)) {
				rc = PTR_ERR(obj);
				CERROR("%s: failed to create glb index copy for %s type: rc = %d\n",
				       qmt->qmt_svname, qtype_name(qtype), rc);
				RETURN(rc);
			}

			pool->qpi_glb_obj[qtype] = obj;

			version = dt_version_get(env, obj);
			/* set default grace time for newly created index */
			if (version == 0) {
				rec->qbr_hardlimit = 0;
				rec->qbr_softlimit = 0;
				rec->qbr_granted = 0;
				rec->qbr_time = rtype == LQUOTA_RES_MD ?
					MAX_IQ_TIME : MAX_DQ_TIME;

				rc = lquota_disk_write_glb(env, obj, 0, rec);
				if (rc) {
					CERROR("%s: failed to set default grace time for %s type: rc = %d\n",
					       qmt->qmt_svname, qtype_name(qtype), rc);
					RETURN(rc);
				}

				rc = lquota_disk_update_ver(env, dev, obj, 1);
				if (rc) {
					CERROR("%s: failed to set initial version for %s type: rc = %d\n",
					       qmt->qmt_svname, qtype_name(qtype), rc);
					RETURN(rc);
				}
			}

			/* create quota entry site for this quota type */
			pool->qpi_site[qtype] = lquota_site_alloc(env, pool,
								  true, qtype,
								  &qmt_lqe_ops);
			if (IS_ERR(pool->qpi_site[qtype])) {
				rc = PTR_ERR(pool->qpi_site[qtype]);
				CERROR("%s: failed to create site for %s type: rc = %d\n",
				       qmt->qmt_svname, qtype_name(qtype), rc);
				RETURN(rc);
			}

			/* count number of slaves which already connected to
			 * the master in the past */
			for (i = 0; i < QMT_STYPE_CNT; i++)
				pool->qpi_slv_nr[i][qtype] = 0;

			rc = lquota_disk_for_each_slv(env, pool->qpi_root,
						      &qti->qti_fid,
						      qmt_slv_cnt,
						      &pool->qpi_slv_nr);
			if (rc) {
				CERROR("%s: failed to scan & count slave indexes for %s type: rc = %d\n",
				       qmt->qmt_svname, qtype_name(qtype), rc);
				RETURN(rc);
			}

			/* Global grace time is stored in quota settings of
			 * ID 0. */
			qti->qti_id.qid_uid = 0;

			/* look-up quota entry storing grace time */
			lqe = lqe_locate(env, pool->qpi_site[qtype],
					 &qti->qti_id);
			if (IS_ERR(lqe))
				RETURN(PTR_ERR(lqe));
			pool->qpi_grace_lqe[qtype] = lqe;
#ifdef CONFIG_PROC_FS
			/* add procfs file to dump the global index, mostly for
			 * debugging purpose */
			snprintf(qti->qti_buf, MTI_NAME_MAXLEN,
				 "glb-%s", qtype_name(qtype));
			rc = lprocfs_seq_create(pool->qpi_proc, qti->qti_buf,
						0444, &lprocfs_quota_seq_fops,
						obj);
			if (rc)
				CWARN("%s: Error adding procfs file for global quota index "DFID": rc = %d\n",
				      qmt->qmt_svname, PFID(&qti->qti_fid), rc);
#endif
		}
		if (name)
			break;
	}

	RETURN(0);
}

/*
 * Handle new slave connection. Called when a slave enqueues the global quota
 * lock at the beginning of the reintegration procedure.
 *
 * \param env - is the environment passed by the caller
 * \parap qmt - is the quota master target handling this request
 * \param glb_fid - is the fid of the global index file
 * \param slv_fid - is the fid of the newly created slave index file
 * \param slv_ver - is the current version of the slave index file
 * \param uuid    - is the uuid of slave which is (re)connecting to the master
 *                  target
 *
 * \retval - 0 on success, appropriate error on failure
 */
int qmt_pool_new_conn(const struct lu_env *env, struct qmt_device *qmt,
		      struct lu_fid *glb_fid, struct lu_fid *slv_fid,
		      __u64 *slv_ver, struct obd_uuid *uuid)
{
	struct qmt_pool_info	*pool;
	struct dt_object	*slv_obj;
	int			 pool_type, qtype, stype;
	bool			 created = false;
	int			 idx, i, rc = 0;

	stype = qmt_uuid2idx(uuid, &idx);
	if (stype < 0)
		RETURN(stype);

	/* extract pool info from global index FID */
	rc = lquota_extract_fid(glb_fid, &pool_type, &qtype);
	if (rc)
		RETURN(rc);

	/* look-up pool in charge of this global index FID */
	qti_pools_init(env);
	pool = qmt_pool_lookup_arr(env, qmt, pool_type, idx);
	if (IS_ERR(pool))
		RETURN(PTR_ERR(pool));

	/* look-up slave index file */
	slv_obj = lquota_disk_slv_find(env, qmt->qmt_child, pool->qpi_root,
				       glb_fid, uuid);
	if (IS_ERR(slv_obj) && PTR_ERR(slv_obj) == -ENOENT) {
		/* create slave index file */
		slv_obj = lquota_disk_slv_find_create(env, qmt->qmt_child,
						      pool->qpi_root, glb_fid,
						      uuid, false);
		created = true;
	}
	if (IS_ERR(slv_obj)) {
		rc = PTR_ERR(slv_obj);
		CERROR("%s: failed to create quota slave index file for %s (%d)"
		       "\n", qmt->qmt_svname, obd_uuid2str(uuid), rc);
		GOTO(out, rc);
	}

	/* retrieve slave fid & current object version */
	memcpy(slv_fid, lu_object_fid(&slv_obj->do_lu), sizeof(*slv_fid));
	*slv_ver = dt_version_get(env, slv_obj);
	dt_object_put(env, slv_obj);
	if (created)
		for (i = 0; i < qti_pools_cnt(env); i++)
			qti_pools_env(env)[i]->qpi_slv_nr[stype][qtype]++;
out:
	qti_pools_fini(env);
	RETURN(rc);
}

/*
 * Look-up a lquota_entry in the pool hash and allocate it if not found.
 *
 * \param env - is the environment passed by the caller
 * \param qmt - is the quota master target for which we have to initialize the
 *              pool configuration
 * \param pool_type - is the pool type, either LQUOTA_RES_MD or LQUOTA_RES_DT.
 * \param qtype     - is the quota type, either user or group.
 * \param qid       - is the quota ID to look-up
 *
 * \retval - valid pointer to lquota entry on success, appropriate error on
 *           failure
 */
struct lquota_entry *qmt_pool_lqe_lookup(const struct lu_env *env,
					 struct qmt_device *qmt,
					 int pool_type, int qtype,
					 union lquota_id *qid,
					 char *pool_name)
{
	struct qmt_pool_info	*pool;
	struct lquota_entry	*lqe;
	ENTRY;

	/* look-up pool responsible for this global index FID */
	pool = qmt_pool_lookup_name(env, qmt, pool_type, pool_name);
	if (IS_ERR(pool))
		RETURN(ERR_CAST(pool));

	if (qid->qid_uid == 0) {
		/* caller wants to access grace time, no need to look up the
		 * entry since we keep a reference on ID 0 all the time */
		lqe = pool->qpi_grace_lqe[qtype];
		lqe_getref(lqe);
		GOTO(out, lqe);
	}

	/* now that we have the pool, let's look-up the quota entry in the
	 * right quota site */
	lqe = lqe_locate(env, pool->qpi_site[qtype], qid);
out:
	qpi_putref(env, pool);
	RETURN(lqe);
}

int qmt_pool_lqes_lookup(const struct lu_env *env,
			 struct qmt_device *qmt,
			 int rtype, int stype,
			 int qtype, union lquota_id *qid,
			 char *pool_name, int idx)
{
	struct qmt_pool_info	*pool;
	struct lquota_entry	*lqe;
	int rc, i;
	ENTRY;

	/* Until MDT pools are not emplemented, all MDTs belong to
	 * global pool, thus lookup lqes only from global pool. */
	if (rtype == LQUOTA_RES_DT && stype == QMT_STYPE_MDT)
		idx = -1;

	qti_pools_init(env);
	rc = 0;
	/* look-up pool responsible for this global index FID */
	pool = qmt_pool_lookup_arr(env, qmt, rtype, idx);
	if (IS_ERR(pool)) {
		qti_pools_fini(env);
		RETURN(PTR_ERR(pool));
	}

	/* now that we have the pool, let's look-up the quota entry in the
	 * right quota site */
	qti_lqes_init(env);
	for (i = 0; i < qti_pools_cnt(env); i++) {
		pool = qti_pools_env(env)[i];
		lqe = lqe_locate(env, pool->qpi_site[qtype], qid);
		if (IS_ERR(lqe)) {
			qti_lqes_fini(env);
			GOTO(out, rc = PTR_ERR(lqe));
		}
		/* Only release could be done for not enforced lqe
		 * (see qmt_dqacq0). However slave could request to
		 * release more than not global lqe had granted before
		 * lqe_enforced was cleared. It is legal case,
		 * because even if current lqe is not enforced,
		 * lqes from other pools are still active and avilable
		 * for acquiring. Furthermore, skip not enforced lqe
		 * to don't make extra allocations. */
		/*if (!lqe_is_glbl(lqe) && !lqe->lqe_enforced) {
			lqe_putref(lqe);
			continue;
		}*/
		qti_lqes_add(env, lqe);
	}
	LASSERT(qti_lqes_glbl(env)->lqe_is_global);

out:
	qti_pools_fini(env);
	RETURN(rc);
}

static int lqes_cmp(const void *arg1, const void *arg2)
{
	const struct lquota_entry *lqe1, *lqe2;

	lqe1 = *(const struct lquota_entry **)arg1;
	lqe2 = *(const struct lquota_entry **)arg2;
	if (lqe1->lqe_qunit > lqe2->lqe_qunit)
		return 1;
	if (lqe1->lqe_qunit < lqe2->lqe_qunit)
		return -1;
	return 0;
}

void qmt_lqes_sort(const struct lu_env *env)
{
	sort(qti_lqes(env), qti_lqes_cnt(env), sizeof(void *), lqes_cmp, NULL);
	/* global lqe was moved during sorting */
	if (!qti_lqes_glbl(env)->lqe_is_global) {
		int i;
		for (i = 0; i < qti_lqes_cnt(env); i++) {
			if (qti_lqes(env)[i]->lqe_is_global) {
				qti_glbl_lqe_idx(env) = i;
				break;
			}
		}
	}
}

int qmt_pool_lqes_lookup_spec(const struct lu_env *env, struct qmt_device *qmt,
			      int rtype, int qtype, union lquota_id *qid)
{
	struct qmt_pool_info	*pos;
	struct lquota_entry	*lqe;
	int rc = 0;

	qti_lqes_init(env);
	down_read(&qmt->qmt_pool_lock);
	if (list_empty(&qmt->qmt_pool_list)) {
		up_read(&qmt->qmt_pool_lock);
		RETURN(-ENOENT);
	}

	list_for_each_entry(pos, &qmt->qmt_pool_list, qpi_linkage) {
		if (pos->qpi_rtype != rtype)
			continue;
		/* Don't take into account pools without slaves */
		if (!qpi_slv_nr(pos, qtype))
			continue;
		lqe = lqe_find(env, pos->qpi_site[qtype], qid);
		/* ENOENT is valid case for lqe from non global pool
		 * that hasn't limits, i.e. not enforced. Continue even
		 * in case of error - we can handle already found lqes */
		if (IS_ERR_OR_NULL(lqe)) {
			/* let know that something went wrong */
			rc = lqe ? PTR_ERR(lqe) : -ENOENT;
			continue;
		}
		if (!lqe->lqe_enforced) {
			/* no settings for this qid_uid */
			lqe_putref(lqe);
			continue;
		}
		qti_lqes_add(env, lqe);
		CDEBUG(D_QUOTA, "adding lqe %p from pool %s\n",
				 lqe, pos->qpi_name);
	}
	up_read(&qmt->qmt_pool_lock);
	RETURN(rc);
}

/**
 * Allocate a new pool for the specified device.
 *
 * Allocate a new pool_desc structure for the specified \a new_pool
 * device to create a pool with the given \a poolname.  The new pool
 * structure is created with a single reference, and is freed when the
 * reference count drops to zero.
 *
 * \param[in] obd	Lustre OBD device on which to add a pool iterator
 * \param[in] poolname	the name of the pool to be created
 *
 * \retval		0 in case of success
 * \retval		negative error code in case of error
 */
int qmt_pool_new(struct obd_device *obd, char *poolname)
{
	struct qmt_device	*qmt = lu2qmt_dev(obd->obd_lu_dev);
	struct qmt_pool_info *qpi;
	struct lu_env env;
	int rc;
	ENTRY;

	if (strnlen(poolname, LOV_MAXPOOLNAME + 1) > LOV_MAXPOOLNAME)
		RETURN(-ENAMETOOLONG);

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: can't init env: rc = %d\n", obd->obd_name, rc);
		RETURN(rc);
	}

	qpi = qmt_pool_lookup_name(&env, qmt, LQUOTA_RES_DT, poolname);
	if (!IS_ERR(qpi)) {
		/* Valid case when several MDTs are mounted
		 * at the same node. */
		CDEBUG(D_QUOTA, "pool %s already exists\n", poolname);
		qpi_putref(&env, qpi);
		GOTO(out_env, rc = -EEXIST);
	}
	if (PTR_ERR(qpi) != -ENOENT) {
		CWARN("%s: pool %s lookup failed: rc = %ld\n",
		      obd->obd_name, poolname, PTR_ERR(qpi));
		GOTO(out_env, rc = PTR_ERR(qpi));
	}

	/* Now allocate and prepare only DATA pool.
	 * Further when MDT pools will be ready we need to add
	 * a cycle here and setup pools of both types. Another
	 * approach is to find out pool of which type should be
	 * created. */
	rc = qmt_pool_alloc(&env, qmt, poolname, LQUOTA_RES_DT);
	if (rc) {
		CERROR("%s: can't alloc pool %s: rc = %d\n",
		       obd->obd_name, poolname, rc);
		GOTO(out_env, rc);
	}

	rc = qmt_pool_prepare(&env, qmt, qmt->qmt_root, poolname);
	if (rc) {
		CERROR("%s: can't prepare pool for %s: rc = %d\n",
		       obd->obd_name, poolname, rc);
		GOTO(out_err, rc);
	}

	CDEBUG(D_QUOTA, "Quota pool "LOV_POOLNAMEF" added\n",
	       poolname);

	GOTO(out_env, rc);
out_err:
	qpi = qmt_pool_lookup_name(&env, qmt, LQUOTA_RES_DT, poolname);
	if (!IS_ERR(qpi)) {
		qpi_putref(&env, qpi);
		qpi_putref(&env, qpi);
	}
out_env:
	lu_env_fini(&env);
	return rc;
}

static int
qmt_obj_recalc(const struct lu_env *env, struct dt_object *obj,
	       struct lquota_site *site)
{
	struct qmt_thread_info *qti = qmt_info(env);
	union lquota_id *qid = &qti->qti_id;
	const struct dt_it_ops *iops;
	struct dt_key *key;
	struct dt_it *it;
	__u64 granted;
	int rc;
	ENTRY;

	iops = &obj->do_index_ops->dio_it;

	it = iops->init(env, obj, 0);
	if (IS_ERR(it)) {
		CWARN("quota: initialize it for "DFID" failed: rc = %ld\n",
		      PFID(&qti->qti_fid), PTR_ERR(it));
		RETURN(PTR_ERR(it));
	}

	rc = iops->load(env, it, 0);
	if (rc < 0) {
		CWARN("quota: load first entry for "DFID" failed: rc = %d\n",
		      PFID(&qti->qti_fid), rc);
		GOTO(out, rc);
	} else if (rc == 0) {
		rc = iops->next(env, it);
		if (rc != 0)
			GOTO(out, rc = (rc < 0) ? rc : 0);
	}

	do {
		struct lquota_entry *lqe;

		key = iops->key(env, it);
		if (IS_ERR(key)) {
			CWARN("quota: error key for "DFID": rc = %ld\n",
			      PFID(&qti->qti_fid), PTR_ERR(key));
			GOTO(out, rc = PTR_ERR(key));
		}

		/* skip the root user/group */
		if (*((__u64 *)key) == 0)
			goto next;

		qid->qid_uid = *((__u64 *)key);

		rc = qmt_slv_read(env, qid, obj, &granted);
		if (!granted)
			goto next;

		lqe = lqe_locate(env, site, qid);
		if (IS_ERR(lqe))
			GOTO(out, rc = PTR_ERR(lqe));
		lqe_write_lock(lqe);
		lqe->lqe_recalc_granted += granted;
		lqe_write_unlock(lqe);
		lqe_putref(lqe);
next:
		rc = iops->next(env, it);
		if (rc < 0)
			CWARN("quota: failed to parse index "DFID
			      ", ->next error: rc = %d\n",
			      PFID(&qti->qti_fid), rc);
	} while (rc == 0 && !kthread_should_stop());

out:
	iops->put(env, it);
	iops->fini(env, it);
	RETURN(rc);
}

static int qmt_site_recalc_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			      struct hlist_node *hnode, void *data)
{
	struct lquota_entry	*lqe;
	struct lu_env *env = data;

	lqe = hlist_entry(hnode, struct lquota_entry, lqe_hash);
	LASSERT(atomic_read(&lqe->lqe_ref) > 0);

	lqe_write_lock(lqe);
	if (lqe->lqe_granted != lqe->lqe_recalc_granted) {
		struct qmt_device *qmt = lqe2qpi(lqe)->qpi_qmt;
		struct thandle *th;
		bool need_notify = false;
		int rc;

		LQUOTA_DEBUG(lqe, "lqe_recalc_granted %llu\n",
			     lqe->lqe_recalc_granted);
		lqe->lqe_granted = lqe->lqe_recalc_granted;
		/* Always returns true, if there is no slaves in a pool */
		need_notify |= qmt_adjust_qunit(env, lqe);
		need_notify |= qmt_adjust_edquot(lqe, ktime_get_real_seconds());
		if (need_notify) {
			/* Find all lqes with lqe_id to reseed lgd array */
			rc = qmt_pool_lqes_lookup_spec(env, qmt, lqe_rtype(lqe),
						lqe_qtype(lqe), &lqe->lqe_id);
			if (!rc && qti_lqes_glbl(env)->lqe_glbl_data) {
				qmt_seed_glbe(env,
					qti_lqes_glbl(env)->lqe_glbl_data);
				qmt_id_lock_notify(qmt, qti_lqes_glbl(env));
			}
			qti_lqes_fini(env);
		}
		th = dt_trans_create(env, qmt->qmt_child);
		if (IS_ERR(th))
			goto out;

		rc = lquota_disk_declare_write(env, th,
					       LQE_GLB_OBJ(lqe),
					       &lqe->lqe_id);
		if (rc)
			GOTO(out_stop, rc);

		rc = dt_trans_start_local(env, qmt->qmt_child, th);
		if (rc)
			GOTO(out_stop, rc);

		qmt_glb_write(env, th, lqe, 0, NULL);
out_stop:
		dt_trans_stop(env, qmt->qmt_child, th);
	}
out:
	lqe->lqe_recalc_granted = 0;
	lqe_write_unlock(lqe);

	return 0;
}

#define MDT_DEV_NAME_LEN (LUSTRE_MAXFSNAME + sizeof("-MDT0000"))
static struct obd_device *qmt_get_mgc(struct qmt_device *qmt)
{
	char mdt_name[MDT_DEV_NAME_LEN];
	struct lustre_mount_info *lmi;
	struct obd_device *obd;
	int rc;
	ENTRY;

	rc = server_name2fsname(qmt->qmt_svname, mdt_name, NULL);
	if (rc) {
		CERROR("quota: cannot get server name from %s: rc = %d\n",
		       qmt->qmt_svname, rc);
		RETURN(ERR_PTR(rc));
	}

	strlcat(mdt_name, "-MDT0000", MDT_DEV_NAME_LEN);
	lmi = server_get_mount(mdt_name);
	if (lmi == NULL) {
		rc = -ENOENT;
		CERROR("%s: cannot get mount info from %s: rc = %d\n",
		       qmt->qmt_svname, mdt_name, rc);
		RETURN(ERR_PTR(rc));
	}
	obd = s2lsi(lmi->lmi_sb)->lsi_mgc;
	lustre_put_lsi(lmi->lmi_sb);

	RETURN(obd);
}

static int qmt_pool_recalc(void *args)
{
	struct qmt_pool_info *pool, *glbl_pool;
	struct rw_semaphore *sem = NULL;
	struct obd_device *obd;
	struct lu_env env;
	int i, rc, qtype, slaves_cnt;
	ENTRY;

	pool = args;

	obd = qmt_get_mgc(pool->qpi_qmt);
	if (IS_ERR(obd))
		GOTO(out, rc = PTR_ERR(obd));
	else
		/* Waiting for the end of processing mgs config.
		 * It is needed to be sure all pools are configured. */
		while (obd->obd_process_conf)
			schedule_timeout_uninterruptible(cfs_time_seconds(1));

	sem = qmt_sarr_rwsem(pool);
	LASSERT(sem);
	down_read(sem);
	/* Hold this to be sure that OSTs from this pool
	 * can't do acquire/release.
	 *
	 * I guess below write semaphore could be a bottleneck
	 * as qmt_dqacq would be blocked trying to hold
	 * read_lock at qmt_pool_lookup->qti_pools_add.
	 * But on the other hand adding/removing OSTs to the pool is
	 * a rare operation. If finally this would be a problem,
	 * we can consider another approach. For example we can
	 * iterate through the POOL's lqes. Take lqe, hold lqe_write_lock
	 * and go through appropriate OSTs. I don't use this approach now
	 * as newly created pool hasn't lqes entries. So firstly we need
	 * to get this lqes from the global pool index file. This
	 * solution looks more complex, so leave it as it is. */
	down_write(&pool->qpi_recalc_sem);

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: cannot init env: rc = %d\n", obd->obd_name, rc);
		GOTO(out, rc);
	}

	glbl_pool = qmt_pool_lookup_glb(&env, pool->qpi_qmt, pool->qpi_rtype);
	if (IS_ERR(glbl_pool))
		GOTO(out_env, rc = PTR_ERR(glbl_pool));

	slaves_cnt = qmt_sarr_count(pool);
	CDEBUG(D_QUOTA, "Starting pool recalculation for %d slaves in %s\n",
	       slaves_cnt, pool->qpi_name);

	for (qtype = 0; qtype < LL_MAXQUOTAS; qtype++) {
		for (i = 0; i < slaves_cnt; i++) {
			struct qmt_thread_info	*qti = qmt_info(&env);
			struct dt_object *slv_obj;
			struct obd_uuid uuid;
			int idx;

			if (kthread_should_stop())
				GOTO(out_stop, rc = 0);
			idx = qmt_sarr_get_idx(pool, i);
			LASSERT(idx >= 0);

			/* We don't need fsname here - anyway
			 * lquota_disk_slv_filename ignores it. */
			snprintf(uuid.uuid, UUID_MAX, "-OST%04x_UUID", idx);
			lquota_generate_fid(&qti->qti_fid, pool->qpi_rtype,
					    qtype);
			/* look-up index file associated with acquiring slave */
			slv_obj = lquota_disk_slv_find(&env,
						glbl_pool->qpi_qmt->qmt_child,
						glbl_pool->qpi_root,
						&qti->qti_fid,
						&uuid);
			if (IS_ERR(slv_obj))
				GOTO(out_stop, rc = PTR_ERR(slv_obj));

			CDEBUG(D_QUOTA, "slv_obj is found %p for uuid %s\n",
			       slv_obj, uuid.uuid);
			qmt_obj_recalc(&env, slv_obj, pool->qpi_site[qtype]);
			dt_object_put(&env, slv_obj);
		}
		/* Now go trough the site hash and compare lqe_granted
		 * with lqe_calc_granted. Write new value if disagree */

		cfs_hash_for_each(pool->qpi_site[qtype]->lqs_hash,
				  qmt_site_recalc_cb, &env);
	}
	GOTO(out_stop, rc);
out_stop:
	qpi_putref(&env, glbl_pool);
out_env:
	lu_env_fini(&env);
out:
	if (xchg(&pool->qpi_recalc_task, NULL) == NULL)
		/*
		 * Someone is waiting for us to stop - be sure not to exit
		 * before kthread_stop() gets a ref on the task.  No event
		 * will happen on 'pool, this is just a convenient way to
		 * wait.
		 */
		wait_var_event(pool, kthread_should_stop());

	clear_bit(QPI_FLAG_RECALC_OFFSET, &pool->qpi_flags);
	/* Pool can't be changed, since sem has been down.
	 * Thus until up_read, no one can restart recalc thread. */
	if (sem) {
		up_read(sem);
		up_write(&pool->qpi_recalc_sem);
	}
	qpi_putref(&env, pool);

	return rc;
}

static int qmt_start_pool_recalc(struct lu_env *env, struct qmt_pool_info *qpi)
{
	struct task_struct *task;
	int rc = 0;

	if (!test_and_set_bit(QPI_FLAG_RECALC_OFFSET, &qpi->qpi_flags)) {
		LASSERT(!qpi->qpi_recalc_task);

		qpi_getref(qpi);
		task = kthread_create(qmt_pool_recalc, qpi,
				      "qsd_reint_%s", qpi->qpi_name);
		if (IS_ERR(task)) {
			clear_bit(QPI_FLAG_RECALC_OFFSET, &qpi->qpi_flags);
			rc = PTR_ERR(task);
			qpi_putref(env, qpi);
		} else {
			qpi->qpi_recalc_task = task;
			/* Using park/unpark to start the thread ensures that
			 * the thread function does get calls, so the
			 * ref on qpi will be dropped
			 */
			kthread_park(task);
			kthread_unpark(task);
		}
	}

	RETURN(rc);
}

static inline void qmt_stop_pool_recalc(struct qmt_pool_info *qpi)
{
	struct task_struct *task;

	task = xchg(&qpi->qpi_recalc_task, NULL);
	if (task)
		kthread_stop(task);
}

static int qmt_pool_slv_nr_change(const struct lu_env *env,
				  struct qmt_pool_info *pool,
				  int idx, bool add)
{
	struct qmt_pool_info *glbl_pool;
	int qtype;

	glbl_pool = qmt_pool_lookup_glb(env, pool->qpi_qmt, LQUOTA_RES_DT);
	if (IS_ERR(glbl_pool))
		RETURN(PTR_ERR(glbl_pool));

	for (qtype = 0; qtype < LL_MAXQUOTAS; qtype++) {
		struct qmt_thread_info	*qti = qmt_info(env);
		struct dt_object *slv_obj;
		struct obd_uuid uuid;

		/* We don't need fsname here - anyway
		 * lquota_disk_slv_filename ignores it. */
		snprintf(uuid.uuid, UUID_MAX, "-OST%04x_UUID", idx);
		lquota_generate_fid(&qti->qti_fid, pool->qpi_rtype,
				    qtype);
		/* look-up index file associated with acquiring slave */
		slv_obj = lquota_disk_slv_find(env,
					glbl_pool->qpi_qmt->qmt_child,
					glbl_pool->qpi_root,
					&qti->qti_fid,
					&uuid);
		if (IS_ERR(slv_obj))
			continue;

		if (add)
			pool->qpi_slv_nr[QMT_STYPE_OST][qtype]++;
		else
			pool->qpi_slv_nr[QMT_STYPE_OST][qtype]--;
		dt_object_put(env, slv_obj);
	}
	qpi_putref(env, glbl_pool);

	return 0;
}

static int qmt_pool_add_rem(struct obd_device *obd, char *poolname,
			    char *slavename, bool add)
{
	struct qmt_device	*qmt = lu2qmt_dev(obd->obd_lu_dev);
	struct qmt_pool_info	*qpi;
	struct lu_env		 env;
	int			 rc, idx;
	ENTRY;

	if (strnlen(poolname, LOV_MAXPOOLNAME + 1) > LOV_MAXPOOLNAME)
		RETURN(-ENAMETOOLONG);

	CDEBUG(D_QUOTA, add ? "%s: pool %s, adding %s\n" :
			      "%s: pool %s, removing %s\n",
	      obd->obd_name, poolname, slavename);

	rc = server_name2index(slavename, &idx, NULL);
	if (rc != LDD_F_SV_TYPE_OST)
		RETURN(-EINVAL);

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: cannot init env: rc = %d\n", obd->obd_name, rc);
		RETURN(rc);
	}

	qpi = qmt_pool_lookup_name(&env, qmt, LQUOTA_RES_DT, poolname);
	if (IS_ERR(qpi)) {
		CWARN("%s: can't find pool %s: rc = %long\n",
		      obd->obd_name, poolname, PTR_ERR(qpi));
		GOTO(out, rc = PTR_ERR(qpi));
	}

	rc = add ? qmt_sarr_pool_add(qpi, idx, 32) :
		   qmt_sarr_pool_rem(qpi, idx);
	if (rc) {
		CERROR("%s: can't %s %s pool %s: rc = %d\n",
		       add ? "add to" : "remove", obd->obd_name,
		       slavename, poolname, rc);
		GOTO(out_putref, rc);
	}
	qmt_pool_slv_nr_change(&env, qpi, idx, add);
	qmt_start_pool_recalc(&env, qpi);

out_putref:
	qpi_putref(&env, qpi);
out:
	lu_env_fini(&env);
	RETURN(rc);
}



/**
 * Add a single target device to the named pool.
 *
 * \param[in] obd	OBD device on which to add the pool
 * \param[in] poolname	name of the pool to which to add the target \a slavename
 * \param[in] slavename	name of the target device to be added
 *
 * \retval		0 if \a slavename was (previously) added to the pool
 * \retval		negative error number on failure
 */
int qmt_pool_add(struct obd_device *obd, char *poolname, char *slavename)
{
	return qmt_pool_add_rem(obd, poolname, slavename, true);
}

/**
 * Remove the named target from the specified pool.
 *
 * \param[in] obd	OBD device from which to remove \a poolname
 * \param[in] poolname	name of the pool to be changed
 * \param[in] slavename	name of the target to remove from \a poolname
 *
 * \retval		0 on successfully removing \a slavename from the pool
 * \retval		negative number on error (e.g. \a slavename not in pool)
 */
int qmt_pool_rem(struct obd_device *obd, char *poolname, char *slavename)
{
	return qmt_pool_add_rem(obd, poolname, slavename, false);
}

/**
 * Remove the named pool from the QMT device.
 *
 * \param[in] obd	OBD device on which pool was previously created
 * \param[in] poolname	name of pool to remove from \a obd
 *
 * \retval		0 on successfully removing the pool
 * \retval		negative error numbers for failures
 */
int qmt_pool_del(struct obd_device *obd, char *poolname)
{
	struct qmt_device	*qmt = lu2qmt_dev(obd->obd_lu_dev);
	struct qmt_pool_info	*qpi;
	struct lu_fid		 fid;
	char			 buf[LQUOTA_NAME_MAX];
	struct lu_env		 env;
	int			 rc;
	int			 qtype;
	ENTRY;

	if (strnlen(poolname, LOV_MAXPOOLNAME + 1) > LOV_MAXPOOLNAME)
		RETURN(-ENAMETOOLONG);

	CDEBUG(D_QUOTA, "Removing quota pool "LOV_POOLNAMEF"\n",
	       poolname);

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: cannot init env: rc = %d\n", obd->obd_name, rc);
		RETURN(rc);
	}

	/* look-up pool in charge of this global index FID */
	qpi = qmt_pool_lookup_name(&env, qmt, LQUOTA_RES_DT, poolname);
	if (IS_ERR(qpi)) {
		/* Valid case for several MDTs at the same node -
		 * pool removed by the 1st MDT in config */
		CDEBUG(D_QUOTA, "Cannot find pool %s\n", poolname);
		lu_env_fini(&env);
		RETURN(PTR_ERR(qpi));
	}

	for (qtype = 0; qtype < LL_MAXQUOTAS; qtype++) {
		lquota_generate_fid(&fid, LQUOTA_RES_DT, qtype);
		snprintf(buf, LQUOTA_NAME_MAX, "0x%x", fid.f_oid);
		rc = local_object_unlink(&env, qmt->qmt_child,
					 qpi->qpi_root, buf);
		if (rc)
			CWARN("%s: cannot unlink %s from pool %s: rc = %d\n",
			      obd->obd_name, buf, poolname, rc);
	}

	/* put ref from look-up */
	qpi_putref(&env, qpi);
	/* put last ref to free qpi */
	qpi_putref(&env, qpi);

	snprintf(buf, LQUOTA_NAME_MAX, "%s-%s",
		 RES_NAME(LQUOTA_RES_DT), poolname);
	rc = local_object_unlink(&env, qmt->qmt_child, qmt->qmt_root, buf);
	if (rc)
		CWARN("%s: cannot unlink dir %s: rc = %d\n",
		      obd->obd_name, poolname, rc);

	lu_env_fini(&env);
	RETURN(0);
}

static inline int qmt_sarr_pool_init(struct qmt_pool_info *qpi)
{

	/* No need to initialize sarray for global pool
	 * as it always includes all slaves */
	if (qmt_pool_global(qpi))
		return 0;

	switch (qpi->qpi_rtype) {
	case LQUOTA_RES_DT:
		return lu_tgt_pool_init(&qpi->qpi_sarr.osts, 0);
	case LQUOTA_RES_MD:
	default:
		return 0;
	}
}

static inline int qmt_sarr_pool_add(struct qmt_pool_info *qpi, int idx, int min)
{
	switch (qpi->qpi_rtype) {
	case LQUOTA_RES_DT:
		return lu_tgt_pool_add(&qpi->qpi_sarr.osts, idx, min);
	case LQUOTA_RES_MD:
	default:
		return 0;
	}
}

static inline int qmt_sarr_pool_rem(struct qmt_pool_info *qpi, int idx)
{
	switch (qpi->qpi_rtype) {
	case LQUOTA_RES_DT:
		return lu_tgt_pool_remove(&qpi->qpi_sarr.osts, idx);
	case LQUOTA_RES_MD:
	default:
		return 0;
	}
}

static inline int qmt_sarr_pool_free(struct qmt_pool_info *qpi)
{
	if (qmt_pool_global(qpi))
		return 0;

	switch (qpi->qpi_rtype) {
	case LQUOTA_RES_DT:
		if (!qpi->qpi_sarr.osts.op_array)
			return 0;
		return lu_tgt_pool_free(&qpi->qpi_sarr.osts);
	case LQUOTA_RES_MD:
	default:
		return 0;
	}
}

static inline int qmt_sarr_check_idx(struct qmt_pool_info *qpi, int idx)
{
	if (qmt_pool_global(qpi))
		return 0;

	switch (qpi->qpi_rtype) {
	case LQUOTA_RES_DT:
		return lu_tgt_check_index(idx, &qpi->qpi_sarr.osts);
	case LQUOTA_RES_MD:
	default:
		return 0;
	}
}

struct rw_semaphore *qmt_sarr_rwsem(struct qmt_pool_info *qpi)
{
	switch (qpi->qpi_rtype) {
	case LQUOTA_RES_DT:
		/* to protect ost_pool use */
		return &qpi->qpi_sarr.osts.op_rw_sem;
	case LQUOTA_RES_MD:
	default:
		return NULL;
	}
}

int qmt_sarr_get_idx(struct qmt_pool_info *qpi, int arr_idx)
{

	if (qmt_pool_global(qpi))
		return arr_idx;

	switch (qpi->qpi_rtype) {
	case LQUOTA_RES_DT:
		LASSERTF(arr_idx < qpi->qpi_sarr.osts.op_count && arr_idx >= 0,
			 "idx invalid %d op_count %d\n", arr_idx,
			 qpi->qpi_sarr.osts.op_count);
		return qpi->qpi_sarr.osts.op_array[arr_idx];
	case LQUOTA_RES_MD:
	default:
		return -EINVAL;
	}
}

/* Number of slaves in a pool */
unsigned int qmt_sarr_count(struct qmt_pool_info *qpi)
{
	switch (qpi->qpi_rtype) {
	case LQUOTA_RES_DT:
		return qpi->qpi_sarr.osts.op_count;
	case LQUOTA_RES_MD:
	default:
		return -EINVAL;
	}
}
