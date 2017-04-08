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
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

/*
 * A Quota Master Target has a hash table where it stores qmt_pool_info
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

static void qmt_pool_free(const struct lu_env *, struct qmt_pool_info *);

/*
 * Static helper functions not used outside the scope of this file
 */

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

static inline void qpi_putref_locked(struct qmt_pool_info *pool)
{
	LASSERT(atomic_read(&pool->qpi_ref) > 1);
	atomic_dec(&pool->qpi_ref);
}

/*
 * Hash functions for qmt_pool_info management
 */

static unsigned
qpi_hash_hash(struct cfs_hash *hs, const void *key, unsigned mask)
{
	return cfs_hash_u32_hash(*((__u32 *)key), mask);
}

static void *qpi_hash_key(struct hlist_node *hnode)
{
	struct qmt_pool_info *pool;
	pool = hlist_entry(hnode, struct qmt_pool_info, qpi_hash);
	return &pool->qpi_key;
}

static int qpi_hash_keycmp(const void *key, struct hlist_node *hnode)
{
	struct qmt_pool_info *pool;
	pool = hlist_entry(hnode, struct qmt_pool_info, qpi_hash);
	return pool->qpi_key == *((__u32 *)key);
}

static void *qpi_hash_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct qmt_pool_info, qpi_hash);
}

static void qpi_hash_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct qmt_pool_info *pool;
	pool = hlist_entry(hnode, struct qmt_pool_info, qpi_hash);
	qpi_getref(pool);
}

static void qpi_hash_put_locked(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct qmt_pool_info *pool;
	pool = hlist_entry(hnode, struct qmt_pool_info, qpi_hash);
	qpi_putref_locked(pool);
}

static void qpi_hash_exit(struct cfs_hash *hs, struct hlist_node *hnode)
{
	CERROR("Should not have any item left!\n");
}

/* vector of hash operations */
static struct cfs_hash_ops qpi_hash_ops = {
	.hs_hash	= qpi_hash_hash,
	.hs_key		= qpi_hash_key,
	.hs_keycmp	= qpi_hash_keycmp,
	.hs_object	= qpi_hash_object,
	.hs_get		= qpi_hash_get,
	.hs_put_locked	= qpi_hash_put_locked,
	.hs_exit	= qpi_hash_exit
};

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
		   pool->qpi_key & 0x0000ffff,
		   RES_NAME(pool->qpi_key >> 16),
		   atomic_read(&pool->qpi_ref),
		   pool->qpi_least_qunit);

	for (type = 0; type < LL_MAXQUOTAS; type++)
		seq_printf(m, "    %s:\n"
			   "        #slv: %d\n"
			   "        #lqe: %d\n",
			   qtype_name(type),
			   pool->qpi_slv_nr[type],
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
	struct qmt_pool_info	*pool;
	int	qunit, rc;
	s64	least_qunit;

	pool = ((struct seq_file *)file->private_data)->private;
	LASSERT(pool != NULL);

	/* Not tuneable for inode limit */
	if (pool->qpi_key >> 16 != LQUOTA_RES_DT)
		return -EINVAL;

	rc = lprocfs_str_to_s64(buffer, count, &least_qunit);
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
 * Allocate a new qmt_pool_info structure and add it to the pool hash table
 * of the qmt.
 *
 * \param env       - is the environment passed by the caller
 * \param qmt       - is the quota master target
 * \param pool_id   - is the 16-bit pool identifier of the new pool to add
 * \param pool_type - is the resource type of this pool instance, either
 *                    LQUOTA_RES_MD or LQUOTA_RES_DT.
 *
 * \retval - 0 on success, appropriate error on failure
 */
static int qmt_pool_alloc(const struct lu_env *env, struct qmt_device *qmt,
			  int pool_id, int pool_type)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct qmt_pool_info	*pool;
	int			 rc = 0;
	ENTRY;

	OBD_ALLOC_PTR(pool);
	if (pool == NULL)
		RETURN(-ENOMEM);
	INIT_LIST_HEAD(&pool->qpi_linkage);

	/* assign key used by hash functions */
	pool->qpi_key = pool_id + (pool_type << 16);

	/* initialize refcount to 1, hash table will then grab an additional
	 * reference */
	atomic_set(&pool->qpi_ref, 1);

	/* set up least qunit size to use for this pool */
	pool->qpi_least_qunit = LQUOTA_LEAST_QUNIT(pool_type);
	if (pool_type == LQUOTA_RES_DT)
		pool->qpi_soft_least_qunit = pool->qpi_least_qunit << 2;
	else
		pool->qpi_soft_least_qunit = pool->qpi_least_qunit;

	/* create pool proc directory */
	sprintf(qti->qti_buf, "%s-0x%x", RES_NAME(pool_type), pool_id);
	pool->qpi_proc = lprocfs_register(qti->qti_buf, qmt->qmt_proc,
					  lprocfs_quota_qpi_vars, pool);
	if (IS_ERR(pool->qpi_proc)) {
		rc = PTR_ERR(pool->qpi_proc);
		CERROR("%s: failed to create proc entry for pool %s (%d)\n",
		       qmt->qmt_svname, qti->qti_buf, rc);
		pool->qpi_proc = NULL;
		GOTO(out, rc);
	}

	/* grab reference on master target that this pool belongs to */
	lu_device_get(qmt2lu_dev(qmt));
	lu_ref_add(&qmt2lu_dev(qmt)->ld_reference, "pool", pool);
	pool->qpi_qmt = qmt;

	/* add to qmt hash table */
	rc = cfs_hash_add_unique(qmt->qmt_pool_hash, &pool->qpi_key,
				 &pool->qpi_hash);
	if (rc) {
		CERROR("%s: failed to add pool %s to qmt hash (%d)\n",
		       qmt->qmt_svname, qti->qti_buf, rc);
		GOTO(out, rc);
	}

	/* add to qmt pool list */
	list_add_tail(&pool->qpi_linkage, &qmt->qmt_pool_list);
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
static void qmt_pool_free(const struct lu_env *env, struct qmt_pool_info *pool)
{
	int	qtype;
	ENTRY;

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

		lu_device_put(ld);
		lu_ref_del(&ld->ld_reference, "pool", pool);
		pool->qpi_qmt = NULL;
	}

	LASSERT(list_empty(&pool->qpi_linkage));
	OBD_FREE_PTR(pool);
}

/*
 * Look-up a pool in the hash table based on the pool ID and type.
 *
 * \param env     - is the environment passed by the caller
 * \param qmt     - is the quota master target
 * \param pool_id   - is the 16-bit identifier of the pool to look up
 * \param pool_type - is the type of this pool, either LQUOTA_RES_MD or
 *                    LQUOTA_RES_DT.
 */
static struct qmt_pool_info *qmt_pool_lookup(const struct lu_env *env,
					     struct qmt_device *qmt,
					     int pool_id, int pool_type)
{
	struct qmt_pool_info	*pool;
	__u32			 key;
	ENTRY;

	LASSERT(qmt->qmt_pool_hash != NULL);

	/* look-up pool in hash table */
	key = pool_id + (pool_type << 16);
	pool = cfs_hash_lookup(qmt->qmt_pool_hash, (void *)&key);
	if (pool == NULL) {
		/* this qmt isn't managing this pool! */
		CERROR("%s: looking up quota entry for a pool (0x%x/%d) which "
		       "isn't managed by this quota master target\n",
		       qmt->qmt_svname, pool_id, pool_type);
		RETURN(ERR_PTR(-ENOENT));
	}
	RETURN(pool);
}

/*
 * Functions implementing the pool API, used by the qmt handlers
 */

/*
 * Destroy all pools which are still in the hash table and free the pool
 * hash table.
 *
 * \param env - is the environment passed by the caller
 * \param qmt - is the quota master target
 *
 */
void qmt_pool_fini(const struct lu_env *env, struct qmt_device *qmt)
{
	struct qmt_pool_info	*pool;
	struct list_head	*pos, *n;
	ENTRY;

	if (qmt->qmt_pool_hash == NULL)
		RETURN_EXIT;

	/* parse list of pool and destroy each element */
	list_for_each_safe(pos, n, &qmt->qmt_pool_list) {
		pool = list_entry(pos, struct qmt_pool_info,
				  qpi_linkage);
		/* remove from hash */
		cfs_hash_del(qmt->qmt_pool_hash, &pool->qpi_key,
			     &pool->qpi_hash);

		/* remove from list */
		list_del_init(&pool->qpi_linkage);

		/* release extra reference taken in qmt_pool_alloc */
		qpi_putref(env, pool);
	}
	LASSERT(list_empty(&qmt->qmt_pool_list));

	cfs_hash_putref(qmt->qmt_pool_hash);
	qmt->qmt_pool_hash = NULL;
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

	/* initialize pool hash table */
	qmt->qmt_pool_hash = cfs_hash_create("POOL_HASH",
					     HASH_POOLS_CUR_BITS,
					     HASH_POOLS_MAX_BITS,
					     HASH_POOLS_BKT_BITS, 0,
					     CFS_HASH_MIN_THETA,
					     CFS_HASH_MAX_THETA,
					     &qpi_hash_ops,
					     CFS_HASH_DEFAULT);
	if (qmt->qmt_pool_hash == NULL) {
		CERROR("%s: failed to create pool hash table\n",
		       qmt->qmt_svname);
		RETURN(-ENOMEM);
	}

	/* initialize pool list */
	INIT_LIST_HEAD(&qmt->qmt_pool_list);

	/* Instantiate pool master for the default data and metadata pool (both
	 * have pool ID equals to 0).
	 * This code will have to be revisited once we support quota on
	 * non-default pools */
	for (res = LQUOTA_FIRST_RES; res < LQUOTA_LAST_RES; res++) {
		rc = qmt_pool_alloc(env, qmt, 0, res);
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
	int *nr = arg;

	/* one more slave */
	(*nr)++;

	return 0;
}

/*
 * Set up on-disk index files associated with each pool.
 *
 * \param env - is the environment passed by the caller
 * \param qmt - is the quota master target for which we have to initialize the
 *              pool configuration
 * \param qmt_root - is the on-disk directory created for the QMT.
 *
 * \retval - 0 on success, appropriate error on failure
 */
int qmt_pool_prepare(const struct lu_env *env, struct qmt_device *qmt,
		     struct dt_object *qmt_root)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_glb_rec	*rec = &qti->qti_glb_rec;
	struct qmt_pool_info	*pool;
	struct dt_device	*dev = NULL;
	dt_obj_version_t	 version;
	struct list_head	*pos;
	int			 rc = 0, qtype;
	ENTRY;

	LASSERT(qmt->qmt_pool_hash != NULL);

	/* iterate over each pool in the hash and allocate a quota site for each
	 * one. This involves creating a global index file on disk */
	list_for_each(pos, &qmt->qmt_pool_list) {
		struct dt_object	*obj;
		int			 pool_type, pool_id;
		struct lquota_entry	*lqe;

		pool = list_entry(pos, struct qmt_pool_info,
				  qpi_linkage);

		pool_id   = pool->qpi_key & 0x0000ffff;
		pool_type = pool->qpi_key >> 16;
		if (dev == NULL)
			dev = pool->qpi_qmt->qmt_child;

		/* allocate directory for this pool */
		sprintf(qti->qti_buf, "%s-0x%x", RES_NAME(pool_type), pool_id);
		obj = lquota_disk_dir_find_create(env, qmt->qmt_child, qmt_root,
						  qti->qti_buf);
		if (IS_ERR(obj))
			RETURN(PTR_ERR(obj));
		pool->qpi_root = obj;

		for (qtype = 0; qtype < LL_MAXQUOTAS; qtype++) {
			/* Generating FID of global index in charge of storing
			 * settings for this quota type */
			lquota_generate_fid(&qti->qti_fid, pool_id, pool_type,
					    qtype);

			/* open/create the global index file for this quota
			 * type */
			obj = lquota_disk_glb_find_create(env, dev,
							  pool->qpi_root,
							  &qti->qti_fid, false);
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
				rec->qbr_time = pool_type == LQUOTA_RES_MD ?
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
			pool->qpi_slv_nr[qtype] = 0;
			rc = lquota_disk_for_each_slv(env, pool->qpi_root,
						      &qti->qti_fid,
						      qmt_slv_cnt,
						      &pool->qpi_slv_nr[qtype]);
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
				CWARN("%s: Error adding procfs file for global"
				      "quota index "DFID", rc:%d\n",
				      qmt->qmt_svname, PFID(&qti->qti_fid), rc);
#endif
		}
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
	int			 pool_id, pool_type, qtype;
	bool			 created = false;
	int			 rc = 0;

	/* extract pool info from global index FID */
	rc = lquota_extract_fid(glb_fid, &pool_id, &pool_type, &qtype);
	if (rc)
		RETURN(rc);

	/* look-up pool in charge of this global index FID */
	pool = qmt_pool_lookup(env, qmt, pool_id, pool_type);
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
		pool->qpi_slv_nr[qtype]++;
out:
	qpi_putref(env, pool);
	RETURN(rc);
}

/*
 * Look-up a lquota_entry in the pool hash and allocate it if not found.
 *
 * \param env - is the environment passed by the caller
 * \param qmt - is the quota master target for which we have to initialize the
 *              pool configuration
 * \param pool_id   - is the 16-bit identifier of the pool
 * \param pool_type - is the pool type, either LQUOTA_RES_MD or LQUOTA_RES_DT.
 * \param qtype     - is the quota type, either user or group.
 * \param qid       - is the quota ID to look-up
 *
 * \retval - valid pointer to lquota entry on success, appropriate error on
 *           failure
 */
struct lquota_entry *qmt_pool_lqe_lookup(const struct lu_env *env,
					 struct qmt_device *qmt,
					 int pool_id, int pool_type,
					 int qtype, union lquota_id *qid)
{
	struct qmt_pool_info	*pool;
	struct lquota_entry	*lqe;
	ENTRY;

	/* look-up pool responsible for this global index FID */
	pool = qmt_pool_lookup(env, qmt, pool_id, pool_type);
	if (IS_ERR(pool))
		RETURN((void *)pool);

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
