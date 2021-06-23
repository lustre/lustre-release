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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * lustre/lod/lod_pool.c
 *
 * OST pool methods
 *
 * This file provides code related to the Logical Object Device (LOD)
 * handling of OST Pools on the MDT.  Pools are named lists of targets
 * that allow userspace to group targets that share a particlar property
 * together so that users or kernel helpers can make decisions about file
 * allocation based on these properties.  For example, pools could be
 * defined based on fault domains (e.g. separate racks of server nodes) so
 * that RAID-1 mirroring could select targets from independent fault
 * domains, or pools could define target performance characteristics so
 * that applicatins could select IOP-optimized storage or stream-optimized
 * storage for a particular output file.
 *
 * This file handles creation, lookup, and removal of pools themselves, as
 * well as adding and removing targets to pools.  It also handles lprocfs
 * display of configured pool.  The pools are accessed by name in the pool
 * hash, and are refcounted to ensure proper pool structure lifetimes.
 *
 * Author: Jacques-Charles LAFOUCRIERE <jc.lafoucriere@cea.fr>
 * Author: Alex Lyashkov <Alexey.Lyashkov@Sun.COM>
 * Author: Nathaniel Rutman <Nathan.Rutman@Sun.COM>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <libcfs/libcfs.h>
#include <libcfs/linux/linux-hash.h>
#include <libcfs/linux/linux-fs.h>
#include <obd.h>
#include "lod_internal.h"

#define pool_tgt(_p, _i) OST_TGT(lu2lod_dev((_p)->pool_lobd->obd_lu_dev), \
				 (_p)->pool_obds.op_array[_i])

/**
 * Get a reference on the specified pool.
 *
 * To ensure the pool descriptor is not freed before the caller is finished
 * with it.  Any process that is accessing \a pool directly needs to hold
 * reference on it, including /proc since a userspace thread may be holding
 * the /proc file open and busy in the kernel.
 *
 * \param[in] pool	pool descriptor on which to gain reference
 */
static void pool_getref(struct pool_desc *pool)
{
	CDEBUG(D_INFO, "pool %p\n", pool);
	atomic_inc(&pool->pool_refcount);
}

/**
 * Drop a reference on the specified pool and free its memory if needed.
 *
 * One reference is held by the LOD OBD device while it is configured, from
 * the time the configuration log defines the pool until the time when it is
 * dropped when the LOD OBD is cleaned up or the pool is deleted.  This means
 * that the pool will not be freed while the LOD device is configured, unless
 * it is explicitly destroyed by the sysadmin.  The pool structure is freed
 * after the last reference on the structure is released.
 *
 * \param[in] pool	pool descriptor to drop reference on and possibly free
 */
void lod_pool_putref(struct pool_desc *pool)
{
	CDEBUG(D_INFO, "pool %p\n", pool);
	if (atomic_dec_and_test(&pool->pool_refcount)) {
		LASSERT(list_empty(&pool->pool_list));
		LASSERT(pool->pool_proc_entry == NULL);
		lu_tgt_pool_free(&(pool->pool_rr.lqr_pool));
		lu_tgt_pool_free(&(pool->pool_obds));
		kfree_rcu(pool, pool_rcu);
		EXIT;
	}
}

static u32 pool_hashfh(const void *data, u32 len, u32 seed)
{
	const char *pool_name = data;

	return hashlen_hash(cfs_hashlen_string((void *)(unsigned long)seed,
					       pool_name));
}

static int pool_cmpfn(struct rhashtable_compare_arg *arg, const void *obj)
{
	const struct pool_desc *pool = obj;
	const char *pool_name = arg->key;

	return strcmp(pool_name, pool->pool_name);
}

static const struct rhashtable_params pools_hash_params = {
	.key_len	= 1, /* actually variable */
	.key_offset	= offsetof(struct pool_desc, pool_name),
	.head_offset	= offsetof(struct pool_desc, pool_hash),
	.hashfn		= pool_hashfh,
	.obj_cmpfn	= pool_cmpfn,
	.automatic_shrinking = true,
};

/*
 * Methods for /proc seq_file iteration of the defined pools.
 */

#define POOL_IT_MAGIC 0xB001CEA0
struct lod_pool_iterator {
	unsigned int	  lpi_magic;	/* POOL_IT_MAGIC */
	unsigned int	  lpi_idx;	/* from 0 to pool_tgt_size - 1 */
	struct pool_desc *lpi_pool;
};

/**
 * Return the next configured target within one pool for seq_file iteration.
 *
 * Iterator is used to go through the target entries of a single pool
 * (i.e. the list of OSTs configured for a named pool).
 * lpi_idx is the current target index in the pool's op_array[].
 *
 * The return type is a void * because this function is one of the
 * struct seq_operations methods and must match the function template.
 *
 * \param[in] seq	/proc sequence file iteration tracking structure
 * \param[in] v		unused
 * \param[in] pos	position within iteration; 0 to number of targets - 1
 *
 * \retval	struct pool_iterator of the next pool descriptor
 */
static void *pool_proc_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct lod_pool_iterator *iter = seq->private;
	int prev_idx;

	LASSERTF(iter->lpi_magic == POOL_IT_MAGIC, "%08X\n", iter->lpi_magic);

	(*pos)++;
	/* test if end of file */
	if (*pos > pool_tgt_count(iter->lpi_pool))
		return NULL;

	OBD_FAIL_TIMEOUT(OBD_FAIL_OST_LIST_ASSERT, cfs_fail_val);

	/* iterate to find a non empty entry */
	prev_idx = iter->lpi_idx;
	iter->lpi_idx++;
	if (iter->lpi_idx >= pool_tgt_count(iter->lpi_pool)) {
		iter->lpi_idx = prev_idx; /* we stay on the last entry */
		return NULL;
	}

	/* return != NULL to continue */
	return iter;
}

/**
 * Start seq_file iteration via /proc for a single pool.
 *
 * The \a pos parameter may be non-zero, indicating that the iteration
 * is starting at some offset in the target list.  Use the seq_file
 * private field to memorize the iterator so we can free it at stop().
 * Need to restore the private pointer to the pool before freeing it.
 *
 * \param[in] seq	new sequence file structure to initialize
 * \param[in] pos	initial target number at which to start iteration
 *
 * \retval		initialized pool iterator private structure
 * \retval		NULL if \a pos exceeds the number of targets in \a pool
 * \retval		negative error number on failure
 */
static void *pool_proc_start(struct seq_file *seq, loff_t *pos)
{
	struct pool_desc *pool = seq->private;
	struct lod_pool_iterator *iter;

	pool_getref(pool);
	if ((pool_tgt_count(pool) == 0) ||
	    (*pos >= pool_tgt_count(pool))) {
		/* iter is not created, so stop() has no way to
		 * find pool to dec ref */
		lod_pool_putref(pool);
		return NULL;
	}

	OBD_ALLOC_PTR(iter);
	if (iter == NULL)
		return ERR_PTR(-ENOMEM);
	iter->lpi_magic = POOL_IT_MAGIC;
	iter->lpi_pool = pool;
	iter->lpi_idx = 0;

	seq->private = iter;
	down_read(&pool_tgt_rw_sem(pool));
	if (*pos > 0) {
		loff_t i;
		void *ptr;

		i = 0;
		do {
			ptr = pool_proc_next(seq, &iter, &i);
		} while ((i < *pos) && (ptr != NULL));

		return ptr;
	}

	return iter;
}

/**
 * Finish seq_file iteration for a single pool.
 *
 * Once iteration has been completed, the pool_iterator struct must be
 * freed, and the seq_file private pointer restored to the pool, as it
 * was initially when pool_proc_start() was called.
 *
 * In some cases the stop() method may be called 2 times, without calling
 * the start() method (see seq_read() from fs/seq_file.c). We have to free
 * the private iterator struct only if seq->private points to the iterator.
 *
 * \param[in] seq	sequence file structure to clean up
 * \param[in] v		(unused)
 */
static void pool_proc_stop(struct seq_file *seq, void *v)
{
	struct lod_pool_iterator *iter = seq->private;

	if (iter != NULL && iter->lpi_magic == POOL_IT_MAGIC) {
		up_read(&pool_tgt_rw_sem(iter->lpi_pool));
		seq->private = iter->lpi_pool;
		lod_pool_putref(iter->lpi_pool);
		OBD_FREE_PTR(iter);
	}
}

/**
 * Print out one target entry from the pool for seq_file iteration.
 *
 * The currently referenced pool target is given by op_array[lpi_idx].
 *
 * \param[in] seq	new sequence file structure to initialize
 * \param[in] v		(unused)
 */
static int pool_proc_show(struct seq_file *seq, void *v)
{
	struct lod_pool_iterator *iter = v;
	struct lod_tgt_desc  *tgt;

	LASSERTF(iter->lpi_magic == POOL_IT_MAGIC, "%08X\n", iter->lpi_magic);
	LASSERT(iter->lpi_pool != NULL);
	LASSERT(iter->lpi_idx <= pool_tgt_count(iter->lpi_pool));

	tgt = pool_tgt(iter->lpi_pool, iter->lpi_idx);
	if (tgt != NULL)
		seq_printf(seq, "%s\n", obd_uuid2str(&(tgt->ltd_uuid)));

	return 0;
}

static const struct seq_operations pool_proc_ops = {
	.start	= pool_proc_start,
	.next	= pool_proc_next,
	.stop	= pool_proc_stop,
	.show	= pool_proc_show,
};

/**
 * Open a new /proc file for seq_file iteration of targets in one pool.
 *
 * Initialize the seq_file private pointer to reference the pool.
 *
 * \param inode	inode to store iteration state for /proc
 * \param file	file descriptor to store iteration methods
 *
 * \retval	0 for success
 * \retval	negative error number on failure
 */
static int pool_proc_open(struct inode *inode, struct file *file)
{
	int rc;

	rc = seq_open(file, &pool_proc_ops);
	if (!rc) {
		struct seq_file *seq = file->private_data;
		seq->private = PDE_DATA(inode);
	}
	return rc;
}

const static struct proc_ops pool_proc_operations = {
	.proc_open	= pool_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};

/**
 * Dump the pool target list into the Lustre debug log.
 *
 * This is a debugging function to allow dumping the list of targets
 * in \a pool to the Lustre kernel debug log at the given \a level.
 *
 * This is not currently called by any existing code, but can be called
 * from within gdb/crash to display the contents of the pool, or from
 * code under development.
 *
 * \param[in] level	Lustre debug level (D_INFO, D_WARN, D_ERROR, etc)
 * \param[in] pool	pool descriptor to be dumped
 */
void lod_dump_pool(int level, struct pool_desc *pool)
{
	unsigned int i;

	pool_getref(pool);

	CDEBUG(level, "pool "LOV_POOLNAMEF" has %d members\n",
	       pool->pool_name, pool->pool_obds.op_count);
	down_read(&pool_tgt_rw_sem(pool));

	for (i = 0; i < pool_tgt_count(pool) ; i++) {
		if (!pool_tgt(pool, i) || !(pool_tgt(pool, i))->ltd_exp)
			continue;
		CDEBUG(level, "pool "LOV_POOLNAMEF"[%d] = %s\n",
		       pool->pool_name, i,
		       obd_uuid2str(&((pool_tgt(pool, i))->ltd_uuid)));
	}

	up_read(&pool_tgt_rw_sem(pool));
	lod_pool_putref(pool);
}

static void pools_hash_exit(void *vpool, void *data)
{
	struct pool_desc *pool = vpool;

	lod_pool_putref(pool);
}

int lod_pool_hash_init(struct rhashtable *tbl)
{
	return rhashtable_init(tbl, &pools_hash_params);
}

void lod_pool_hash_destroy(struct rhashtable *tbl)
{
	rhashtable_free_and_destroy(tbl, pools_hash_exit, NULL);
}

bool lod_pool_exists(struct lod_device *lod, char *poolname)
{
	struct pool_desc *pool;

	rcu_read_lock();
	pool = rhashtable_lookup(&lod->lod_pools_hash_body,
				poolname,
				pools_hash_params);
	rcu_read_unlock();
	return pool != NULL;
}

static struct pool_desc *lod_pool_find(struct lod_device *lod, char *poolname)
{
	struct pool_desc *pool;

	rcu_read_lock();
	pool = rhashtable_lookup(&lod->lod_pools_hash_body,
				poolname,
				pools_hash_params);
	if (pool && !atomic_inc_not_zero(&pool->pool_refcount))
		pool = NULL;
	rcu_read_unlock();
	return pool;
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
int lod_pool_new(struct obd_device *obd, char *poolname)
{
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct pool_desc  *new_pool;
	int rc;
	ENTRY;

	if (strlen(poolname) > LOV_MAXPOOLNAME)
		RETURN(-ENAMETOOLONG);

	/* OBD_ALLOC_* doesn't work with direct kfree_rcu use */
	new_pool = kmalloc(sizeof(*new_pool), GFP_KERNEL);
	if (new_pool == NULL)
		RETURN(-ENOMEM);

	strlcpy(new_pool->pool_name, poolname, sizeof(new_pool->pool_name));
	new_pool->pool_spill_expire = 0;
	new_pool->pool_spill_is_active = false;
	new_pool->pool_spill_threshold_pct = 0;
	new_pool->pool_spill_target[0] = '\0';
	atomic_set(&new_pool->pool_spill_hit, 0);
	new_pool->pool_lobd = obd;
	atomic_set(&new_pool->pool_refcount, 1);
	rc = lu_tgt_pool_init(&new_pool->pool_obds, 0);
	if (rc)
		GOTO(out_free_pool, rc);

	lu_qos_rr_init(&new_pool->pool_rr);

	rc = lu_tgt_pool_init(&new_pool->pool_rr.lqr_pool, 0);
	if (rc)
		GOTO(out_free_pool_obds, rc);

#ifdef CONFIG_PROC_FS
	pool_getref(new_pool);
	new_pool->pool_proc_entry = lprocfs_add_simple(lod->lod_pool_proc_entry,
						       poolname, new_pool,
						       &pool_proc_operations);
	if (IS_ERR(new_pool->pool_proc_entry)) {
		CDEBUG(D_CONFIG, "%s: cannot add proc entry "LOV_POOLNAMEF"\n",
		       obd->obd_name, poolname);
		new_pool->pool_proc_entry = NULL;
		lod_pool_putref(new_pool);
	}

	pool_getref(new_pool);
	new_pool->pool_spill_proc_entry =
		lprocfs_register(poolname, lod->lod_spill_proc_entry,
			lprocfs_lod_spill_vars, new_pool);
	if (IS_ERR(new_pool->pool_spill_proc_entry)) {
		rc = PTR_ERR(new_pool->pool_spill_proc_entry);
		new_pool->pool_proc_entry = NULL;
		lod_pool_putref(new_pool);
	}

	CDEBUG(D_INFO, "pool %p - proc %p\n", new_pool,
	       new_pool->pool_proc_entry);
#endif

	spin_lock(&obd->obd_dev_lock);
	list_add_tail(&new_pool->pool_list, &lod->lod_pool_list);
	lod->lod_pool_count++;
	spin_unlock(&obd->obd_dev_lock);

	/* Add to hash table only when it is fully ready. */
	rc = rhashtable_lookup_insert_fast(&lod->lod_pools_hash_body,
					   &new_pool->pool_hash,
					   pools_hash_params);
	if (rc) {
		if (rc != -EEXIST)
			/*
			 * Hide -E2BIG and -EBUSY which
			 * are not helpful.
			 */
			rc = -ENOMEM;
		GOTO(out_err, rc);
	}

	CDEBUG(D_CONFIG, LOV_POOLNAMEF" is pool #%d\n",
			poolname, lod->lod_pool_count);

	RETURN(0);

out_err:
	spin_lock(&obd->obd_dev_lock);
	list_del_init(&new_pool->pool_list);
	lod->lod_pool_count--;
	spin_unlock(&obd->obd_dev_lock);

	lprocfs_remove(&new_pool->pool_spill_proc_entry);
	lprocfs_remove(&new_pool->pool_proc_entry);

	lu_tgt_pool_free(&new_pool->pool_rr.lqr_pool);
out_free_pool_obds:
	lu_tgt_pool_free(&new_pool->pool_obds);
out_free_pool:
	OBD_FREE_PTR(new_pool);
	return rc;
}

/**
 * Remove the named pool from the OBD device.
 *
 * \param[in] obd	OBD device on which pool was previously created
 * \param[in] poolname	name of pool to remove from \a obd
 *
 * \retval		0 on successfully removing the pool
 * \retval		negative error numbers for failures
 */
int lod_pool_del(struct obd_device *obd, char *poolname)
{
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct pool_desc  *pool;
	ENTRY;

	/* lookup and kill hash reference */
	rcu_read_lock();
	pool = rhashtable_lookup(&lod->lod_pools_hash_body, poolname,
				 pools_hash_params);
	if (pool && rhashtable_remove_fast(&lod->lod_pools_hash_body,
					   &pool->pool_hash,
					   pools_hash_params) != 0)
		pool = NULL;
	rcu_read_unlock();
	if (!pool)
		RETURN(-ENOENT);

	if (pool->pool_proc_entry != NULL) {
		CDEBUG(D_INFO, "proc entry %p\n", pool->pool_proc_entry);
		lprocfs_remove(&pool->pool_proc_entry);
		lod_pool_putref(pool);
	}
	if (pool->pool_spill_proc_entry != NULL) {
		CDEBUG(D_INFO, "proc entry %p\n", pool->pool_spill_proc_entry);
		lprocfs_remove(&pool->pool_spill_proc_entry);
		lod_pool_putref(pool);
	}

	spin_lock(&obd->obd_dev_lock);
	list_del_init(&pool->pool_list);
	lod->lod_pool_count--;
	spin_unlock(&obd->obd_dev_lock);

	/* release last reference */
	lod_pool_putref(pool);

	RETURN(0);
}

/**
 * Add a single target device to the named pool.
 *
 * Add the target specified by \a ostname to the specified \a poolname.
 *
 * \param[in] obd	OBD device on which to add the pool
 * \param[in] poolname	name of the pool to which to add the target \a ostname
 * \param[in] ostname	name of the target device to be added
 *
 * \retval		0 if \a ostname was (previously) added to the named pool
 * \retval		negative error number on failure
 */
int lod_pool_add(struct obd_device *obd, char *poolname, char *ostname)
{
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct obd_uuid ost_uuid;
	struct pool_desc *pool;
	struct lu_tgt_desc *tgt;
	int rc = -EINVAL;
	ENTRY;

	pool = lod_pool_find(lod, poolname);
	if (!pool)
		RETURN(-ENOENT);

	obd_str2uuid(&ost_uuid, ostname);

	/* search ost in lod array */
	lod_getref(&lod->lod_ost_descs);
	lod_foreach_ost(lod, tgt) {
		if (obd_uuid_equals(&ost_uuid, &tgt->ltd_uuid)) {
			rc = 0;
			break;
		}
	}

	if (rc)
		GOTO(out, rc);

	rc = lu_tgt_pool_add(&pool->pool_obds, tgt->ltd_index,
			     lod->lod_ost_count);
	if (rc)
		GOTO(out, rc);

	set_bit(LQ_DIRTY, &pool->pool_rr.lqr_flags);

	CDEBUG(D_CONFIG, "Added %s to "LOV_POOLNAMEF" as member %d\n",
			ostname, poolname,  pool_tgt_count(pool));

	EXIT;
out:
	lod_putref(lod, &lod->lod_ost_descs);
	lod_pool_putref(pool);
	return rc;
}

/**
 * Remove the named target from the specified pool.
 *
 * Remove one target named \a ostname from \a poolname.  The \a ostname
 * is searched for in the lod_device lod_ost_bitmap array, to ensure the
 * specified name actually exists in the pool.
 *
 * \param[in] obd	OBD device from which to remove \a poolname
 * \param[in] poolname	name of the pool to be changed
 * \param[in] ostname	name of the target to remove from \a poolname
 *
 * \retval		0 on successfully removing \a ostname from the pool
 * \retval		negative number on error (e.g. \a ostname not in pool)
 */
int lod_pool_remove(struct obd_device *obd, char *poolname, char *ostname)
{
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct lu_tgt_desc *ost;
	struct obd_uuid	ost_uuid;
	struct pool_desc *pool;
	int rc = -EINVAL;
	ENTRY;

	/* lookup and kill hash reference */
	pool = lod_pool_find(lod, poolname);
	if (!pool)
		RETURN(-ENOENT);

	obd_str2uuid(&ost_uuid, ostname);

	lod_getref(&lod->lod_ost_descs);
	lod_foreach_ost(lod, ost) {
		if (obd_uuid_equals(&ost_uuid, &ost->ltd_uuid)) {
			rc = 0;
			break;
		}
	}

	/* test if ost found in lod array */
	if (rc)
		GOTO(out, rc);

	lu_tgt_pool_remove(&pool->pool_obds, ost->ltd_index);
	set_bit(LQ_DIRTY, &pool->pool_rr.lqr_flags);

	CDEBUG(D_CONFIG, "%s removed from "LOV_POOLNAMEF"\n", ostname,
	       poolname);

	EXIT;
out:
	lod_putref(lod, &lod->lod_ost_descs);
	lod_pool_putref(pool);
	return rc;
}

/**
 * Check if the specified target exists in the pool.
 *
 * The caller may not have a reference on \a pool if it got the pool without
 * calling lod_find_pool() (e.g. directly from the lod pool list)
 *
 * \param[in] idx	Target index to check
 * \param[in] pool	Pool in which to check if target is added.
 *
 * \retval		0 successfully found index in \a pool
 * \retval		negative error if device not found in \a pool
 */
int lod_check_index_in_pool(__u32 idx, struct pool_desc *pool)
{
	int rc;

	pool_getref(pool);
	rc = lu_tgt_check_index(idx, &pool->pool_obds);
	lod_pool_putref(pool);
	return rc;
}

/**
 * Find the pool descriptor for the specified pool and return it with a
 * reference to the caller if found.
 *
 * \param[in] lod	LOD on which the pools are configured
 * \param[in] poolname	NUL-terminated name of the pool
 *
 * \retval	pointer to pool descriptor on success
 * \retval	NULL if \a poolname could not be found or poolname is empty
 */
struct pool_desc *lod_find_pool(struct lod_device *lod, char *poolname)
{
	struct pool_desc *pool;

	pool = NULL;
	if (poolname[0] != '\0') {
		pool = lod_pool_find(lod, poolname);
		if (!pool)
			CDEBUG(D_CONFIG,
			       "%s: request for an unknown pool (" LOV_POOLNAMEF ")\n",
			       lod->lod_child_exp->exp_obd->obd_name, poolname);
		if (pool != NULL && pool_tgt_count(pool) == 0) {
			CDEBUG(D_CONFIG, "%s: request for an empty pool ("
			       LOV_POOLNAMEF")\n",
			       lod->lod_child_exp->exp_obd->obd_name, poolname);
			/* pool is ignored, so we remove ref on it */
			lod_pool_putref(pool);
			pool = NULL;
		}
	}
	return pool;
}

void lod_spill_target_refresh(const struct lu_env *env, struct lod_device *lod,
			      struct pool_desc *pool)
{
	__u64 avail_bytes = 0, total_bytes = 0;
	struct lu_tgt_pool *osts;
	int i;

	if (ktime_get_seconds() < pool->pool_spill_expire)
		return;

	if (pool->pool_spill_threshold_pct == 0)
		return;

	lod_qos_statfs_update(env, lod, &lod->lod_ost_descs);

	down_write(&pool_tgt_rw_sem(pool));
	if (ktime_get_seconds() < pool->pool_spill_expire)
		goto out_sem;
	pool->pool_spill_expire = ktime_get_seconds() +
		lod->lod_ost_descs.ltd_lov_desc.ld_qos_maxage;

	osts = &(pool->pool_obds);
	for (i = 0; i < osts->op_count; i++) {
		int idx = osts->op_array[i];
		struct lod_tgt_desc *tgt;
		struct obd_statfs *sfs;

		if (!test_bit(idx, lod->lod_ost_bitmap))
			continue;
		tgt = OST_TGT(lod, idx);
		if (tgt->ltd_active == 0)
			continue;
		sfs = &tgt->ltd_statfs;

		avail_bytes += sfs->os_bavail * sfs->os_bsize;
		total_bytes += sfs->os_blocks * sfs->os_bsize;
	}
	if (total_bytes - avail_bytes >=
	    total_bytes * pool->pool_spill_threshold_pct / 100)
		pool->pool_spill_is_active = true;
	else
		pool->pool_spill_is_active = false;

out_sem:
	up_write(&pool_tgt_rw_sem(pool));
}

/*
 * to prevent infinite loops during spilling, lets limit number of passes
 */
#define LOD_SPILL_MAX	10

/*
 * XXX: consider a better schema to detect loops
 */
void lod_check_and_spill_pool(const struct lu_env *env, struct lod_device *lod,
			      char **poolname)
{
	struct pool_desc *pool;
	int replaced = 0;

	if (!poolname || !*poolname || (*poolname)[0] == '\0')
		return;
repeat:
	pool = lod_pool_find(lod, *poolname);
	if (!pool)
		return;

	lod_spill_target_refresh(env, lod, pool);
	if (pool->pool_spill_is_active) {
		if (++replaced >= LOD_SPILL_MAX)
			CWARN("%s: more than %d levels of pool spill for '%s->%s'\n",
			      lod2obd(lod)->obd_name, LOD_SPILL_MAX,
			      *poolname, pool->pool_spill_target);
		lod_set_pool(poolname, pool->pool_spill_target);
		atomic_inc(&pool->pool_spill_hit);
		lod_pool_putref(pool);
		if (replaced >= LOD_SPILL_MAX)
			return;
		goto repeat;
	}

	lod_pool_putref(pool);
}
