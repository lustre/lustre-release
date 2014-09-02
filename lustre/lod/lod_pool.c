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
 * Copyright (c) 2012, 2014 Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
		LASSERT(hlist_unhashed(&pool->pool_hash));
		LASSERT(list_empty(&pool->pool_list));
		LASSERT(pool->pool_proc_entry == NULL);
		lod_ost_pool_free(&(pool->pool_rr.lqr_pool));
		lod_ost_pool_free(&(pool->pool_obds));
		OBD_FREE_PTR(pool);
		EXIT;
	}
}

/**
 * Drop the refcount in cases where the caller holds a spinlock.
 *
 * This is needed if the caller cannot be blocked while freeing memory.
 * It assumes that there is some other known refcount held on the \a pool
 * and the memory cannot actually be freed, but the refcounting needs to
 * be kept accurate.
 *
 * \param[in] pool	pool descriptor on which to drop reference
 */
static void pool_putref_locked(struct pool_desc *pool)
{
	CDEBUG(D_INFO, "pool %p\n", pool);
	LASSERT(atomic_read(&pool->pool_refcount) > 1);

	atomic_dec(&pool->pool_refcount);
}

/*
 * Group of functions needed for cfs_hash implementation.  This
 * includes pool lookup, refcounting, and cleanup.
 */

/**
 * Hash the pool name for use by the cfs_hash handlers.
 *
 * Use the standard DJB2 hash function for ASCII strings in Lustre.
 *
 * \param[in] hash_body	hash structure where this key is embedded (unused)
 * \param[in] key	key to be hashed (in this case the pool name)
 * \param[in] mask	bitmask to limit the hash value to the desired size
 *
 * \retval		computed hash value from \a key and limited by \a mask
 */
static __u32 pool_hashfn(cfs_hash_t *hash_body, const void *key, unsigned mask)
{
	return cfs_hash_djb2_hash(key, strnlen(key, LOV_MAXPOOLNAME), mask);
}

/**
 * Return the actual key (pool name) from the hashed \a hnode.
 *
 * Allows extracting the key name when iterating over all hash entries.
 *
 * \param[in] hnode	hash node found by lookup or iteration
 *
 * \retval		char array referencing the pool name (no refcount)
 */
static void *pool_key(struct hlist_node *hnode)
{
	struct pool_desc *pool;

	pool = hlist_entry(hnode, struct pool_desc, pool_hash);
	return pool->pool_name;
}

/**
 * Check if the specified hash key matches the hash node.
 *
 * This is needed in case there is a hash key collision, allowing the hash
 * table lookup/iteration to distinguish between the two entries.
 *
 * \param[in] key	key (pool name) being searched for
 * \param[in] compared	current entry being compared
 *
 * \retval		0 if \a key is the same as the key of \a compared
 * \retval		1 if \a key is different from the key of \a compared
 */
static int pool_hashkey_keycmp(const void *key, struct hlist_node *compared)
{
	return !strncmp(key, pool_key(compared), LOV_MAXPOOLNAME);
}

/**
 * Return the actual pool data structure from the hash table entry.
 *
 * Once the hash table entry is found, extract the pool data from it.
 * The return type of this function is void * because it needs to be
 * assigned to the generic hash operations table.
 *
 * \param[in] hnode	hash table entry
 *
 * \retval		struct pool_desc for the specified \a hnode
 */
static void *pool_hashobject(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct pool_desc, pool_hash);
}

static void pool_hashrefcount_get(cfs_hash_t *hs, struct hlist_node *hnode)
{
	struct pool_desc *pool;

	pool = hlist_entry(hnode, struct pool_desc, pool_hash);
	pool_getref(pool);
}

static void pool_hashrefcount_put_locked(cfs_hash_t *hs,
					 struct hlist_node *hnode)
{
	struct pool_desc *pool;

	pool = hlist_entry(hnode, struct pool_desc, pool_hash);
	pool_putref_locked(pool);
}

cfs_hash_ops_t pool_hash_operations = {
	.hs_hash	= pool_hashfn,
	.hs_key		= pool_key,
	.hs_keycmp	= pool_hashkey_keycmp,
	.hs_object	= pool_hashobject,
	.hs_get		= pool_hashrefcount_get,
	.hs_put_locked  = pool_hashrefcount_put_locked,
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

	/* test if end of file */
	if (*pos >= pool_tgt_count(iter->lpi_pool))
		return NULL;

	/* iterate to find a non empty entry */
	prev_idx = iter->lpi_idx;
	down_read(&pool_tgt_rw_sem(iter->lpi_pool));
	iter->lpi_idx++;
	if (iter->lpi_idx == pool_tgt_count(iter->lpi_pool)) {
		iter->lpi_idx = prev_idx; /* we stay on the last entry */
		up_read(&pool_tgt_rw_sem(iter->lpi_pool));
		return NULL;
	}
	up_read(&pool_tgt_rw_sem(iter->lpi_pool));
	(*pos)++;
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

	down_read(&pool_tgt_rw_sem(iter->lpi_pool));
	tgt = pool_tgt(iter->lpi_pool, iter->lpi_idx);
	up_read(&pool_tgt_rw_sem(iter->lpi_pool));
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

static struct file_operations pool_proc_operations = {
	.open		= pool_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
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

/**
 * Initialize the pool data structures at startup.
 *
 * Allocate and initialize the pool data structures with the specified
 * array size.  If pool count is not specified (\a count == 0), then
 * POOL_INIT_COUNT will be used.  Allocating a non-zero initial array
 * size avoids the need to reallocate as new pools are added.
 *
 * \param[in] op	pool structure
 * \param[in] count	initial size of the target op_array[] array
 *
 * \retval		0 indicates successful pool initialization
 * \retval		negative error number on failure
 */
#define POOL_INIT_COUNT 2
int lod_ost_pool_init(struct ost_pool *op, unsigned int count)
{
	ENTRY;

	if (count == 0)
		count = POOL_INIT_COUNT;
	op->op_array = NULL;
	op->op_count = 0;
	init_rwsem(&op->op_rw_sem);
	op->op_size = count;
	OBD_ALLOC(op->op_array, op->op_size * sizeof(op->op_array[0]));
	if (op->op_array == NULL) {
		op->op_size = 0;
		RETURN(-ENOMEM);
	}
	EXIT;
	return 0;
}

/**
 * Increase the op_array size to hold more targets in this pool.
 *
 * The size is increased to at least \a min_count, but may be larger
 * for an existing pool since ->op_array[] is growing exponentially.
 * Caller must hold write op_rwlock.
 *
 * \param[in] op	pool structure
 * \param[in] min_count	minimum number of entries to handle
 *
 * \retval		0 on success
 * \retval		negative error number on failure.
 */
int lod_ost_pool_extend(struct ost_pool *op, unsigned int min_count)
{
	__u32 *new;
	int new_size;

	LASSERT(min_count != 0);

	if (op->op_count < op->op_size)
		return 0;

	new_size = max(min_count, 2 * op->op_size);
	OBD_ALLOC(new, new_size * sizeof(op->op_array[0]));
	if (new == NULL)
		return -ENOMEM;

	/* copy old array to new one */
	memcpy(new, op->op_array, op->op_size * sizeof(op->op_array[0]));
	OBD_FREE(op->op_array, op->op_size * sizeof(op->op_array[0]));
	op->op_array = new;
	op->op_size = new_size;

	return 0;
}

/**
 * Add a new target to an existing pool.
 *
 * Add a new target device to the pool previously created and returned by
 * lod_pool_new().  Each target can only be in each pool at most one time.
 *
 * \param[in] op	target pool to add new entry
 * \param[in] idx	pool index number to add to the \a op array
 * \param[in] min_count	minimum number of entries to expect in the pool
 *
 * \retval		0 if target could be added to the pool
 * \retval		negative error if target \a idx was not added
 */
int lod_ost_pool_add(struct ost_pool *op, __u32 idx, unsigned int min_count)
{
	unsigned int i;
	int rc = 0;
	ENTRY;

	down_write(&op->op_rw_sem);

	rc = lod_ost_pool_extend(op, min_count);
	if (rc)
		GOTO(out, rc);

	/* search ost in pool array */
	for (i = 0; i < op->op_count; i++) {
		if (op->op_array[i] == idx)
			GOTO(out, rc = -EEXIST);
	}
	/* ost not found we add it */
	op->op_array[op->op_count] = idx;
	op->op_count++;
	EXIT;
out:
	up_write(&op->op_rw_sem);
	return rc;
}

/**
 * Remove an existing pool from the system.
 *
 * The specified pool must have previously been allocated by
 * lod_pool_new() and not have any target members in the pool.
 * If the removed target is not the last, compact the array
 * to remove empty spaces.
 *
 * \param[in] op	pointer to the original data structure
 * \param[in] idx	target index to be removed
 *
 * \retval		0 on success
 * \retval		negative error number on failure
 */
int lod_ost_pool_remove(struct ost_pool *op, __u32 idx)
{
	unsigned int i;
	ENTRY;

	down_write(&op->op_rw_sem);

	for (i = 0; i < op->op_count; i++) {
		if (op->op_array[i] == idx) {
			memmove(&op->op_array[i], &op->op_array[i + 1],
				(op->op_count - i - 1) *
				sizeof(op->op_array[0]));
			op->op_count--;
			up_write(&op->op_rw_sem);
			EXIT;
			return 0;
		}
	}

	up_write(&op->op_rw_sem);
	RETURN(-EINVAL);
}

/**
 * Free the pool after it was emptied and removed from /proc.
 *
 * Note that all of the child/target entries referenced by this pool
 * must have been removed by lod_ost_pool_remove() before it can be
 * deleted from memory.
 *
 * \param[in] op	pool to be freed.
 *
 * \retval		0 on success or if pool was already freed
 */
int lod_ost_pool_free(struct ost_pool *op)
{
	ENTRY;

	if (op->op_size == 0)
		RETURN(0);

	down_write(&op->op_rw_sem);

	OBD_FREE(op->op_array, op->op_size * sizeof(op->op_array[0]));
	op->op_array = NULL;
	op->op_count = 0;
	op->op_size = 0;

	up_write(&op->op_rw_sem);
	RETURN(0);
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

	OBD_ALLOC_PTR(new_pool);
	if (new_pool == NULL)
		RETURN(-ENOMEM);

	strlcpy(new_pool->pool_name, poolname, sizeof(new_pool->pool_name));
	new_pool->pool_lobd = obd;
	atomic_set(&new_pool->pool_refcount, 1);
	rc = lod_ost_pool_init(&new_pool->pool_obds, 0);
	if (rc)
		GOTO(out_err, rc);

	memset(&new_pool->pool_rr, 0, sizeof(new_pool->pool_rr));
	rc = lod_ost_pool_init(&new_pool->pool_rr.lqr_pool, 0);
	if (rc)
		GOTO(out_free_pool_obds, rc);

	INIT_HLIST_NODE(&new_pool->pool_hash);

#ifdef LPROCFS
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
	CDEBUG(D_INFO, "pool %p - proc %p\n", new_pool,
	       new_pool->pool_proc_entry);
#endif

	spin_lock(&obd->obd_dev_lock);
	list_add_tail(&new_pool->pool_list, &lod->lod_pool_list);
	lod->lod_pool_count++;
	spin_unlock(&obd->obd_dev_lock);

	/* add to find only when it fully ready  */
	rc = cfs_hash_add_unique(lod->lod_pools_hash_body, poolname,
				 &new_pool->pool_hash);
	if (rc)
		GOTO(out_err, rc = -EEXIST);

	CDEBUG(D_CONFIG, LOV_POOLNAMEF" is pool #%d\n",
			poolname, lod->lod_pool_count);

	RETURN(0);

out_err:
	spin_lock(&obd->obd_dev_lock);
	list_del_init(&new_pool->pool_list);
	lod->lod_pool_count--;
	spin_unlock(&obd->obd_dev_lock);

	lprocfs_remove(&new_pool->pool_proc_entry);

	lod_ost_pool_free(&new_pool->pool_rr.lqr_pool);
out_free_pool_obds:
	lod_ost_pool_free(&new_pool->pool_obds);
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
	pool = cfs_hash_del_key(lod->lod_pools_hash_body, poolname);
	if (pool == NULL)
		RETURN(-ENOENT);

	if (pool->pool_proc_entry != NULL) {
		CDEBUG(D_INFO, "proc entry %p\n", pool->pool_proc_entry);
		lprocfs_remove(&pool->pool_proc_entry);
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
	struct lod_device	*lod = lu2lod_dev(obd->obd_lu_dev);
	struct obd_uuid		 ost_uuid;
	struct pool_desc	*pool;
	unsigned int		 idx;
	int			 rc = -EINVAL;
	ENTRY;

	pool = cfs_hash_lookup(lod->lod_pools_hash_body, poolname);
	if (pool == NULL)
		RETURN(-ENOENT);

	obd_str2uuid(&ost_uuid, ostname);

	/* search ost in lod array */
	lod_getref(&lod->lod_ost_descs);
	lod_foreach_ost(lod, idx) {
		if (obd_uuid_equals(&ost_uuid, &OST_TGT(lod, idx)->ltd_uuid)) {
			rc = 0;
			break;
		}
	}

	if (rc)
		GOTO(out, rc);

	rc = lod_ost_pool_add(&pool->pool_obds, idx, lod->lod_osts_size);
	if (rc)
		GOTO(out, rc);

	pool->pool_rr.lqr_dirty = 1;

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
	struct lod_device	*lod = lu2lod_dev(obd->obd_lu_dev);
	struct obd_uuid		 ost_uuid;
	struct pool_desc	*pool;
	unsigned int		 idx;
	int			 rc = -EINVAL;
	ENTRY;

	pool = cfs_hash_lookup(lod->lod_pools_hash_body, poolname);
	if (pool == NULL)
		RETURN(-ENOENT);

	obd_str2uuid(&ost_uuid, ostname);

	lod_getref(&lod->lod_ost_descs);
	cfs_foreach_bit(lod->lod_ost_bitmap, idx) {
		if (obd_uuid_equals(&ost_uuid, &OST_TGT(lod, idx)->ltd_uuid)) {
			rc = 0;
			break;
		}
	}

	/* test if ost found in lod array */
	if (rc)
		GOTO(out, rc);

	lod_ost_pool_remove(&pool->pool_obds, idx);

	pool->pool_rr.lqr_dirty = 1;

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
	unsigned int i;
	int rc;
	ENTRY;

	pool_getref(pool);

	down_read(&pool_tgt_rw_sem(pool));

	for (i = 0; i < pool_tgt_count(pool); i++) {
		if (pool_tgt_array(pool)[i] == idx)
			GOTO(out, rc = 0);
	}
	rc = -ENOENT;
	EXIT;
out:
	up_read(&pool_tgt_rw_sem(pool));

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
		pool = cfs_hash_lookup(lod->lod_pools_hash_body, poolname);
		if (pool == NULL)
			CDEBUG(D_CONFIG, "%s: request for an unknown pool ("
			       LOV_POOLNAMEF")\n",
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

