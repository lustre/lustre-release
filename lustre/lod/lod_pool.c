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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lod/lod_pool.c
 *
 * OST pool methods
 *
 * Author: Jacques-Charles LAFOUCRIERE <jc.lafoucriere@cea.fr>
 * Author: Alex Lyashkov <Alexey.Lyashkov@Sun.COM>
 * Author: Nathaniel Rutman <Nathan.Rutman@Sun.COM>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <libcfs/libcfs.h>
#include <obd.h>
#include "lod_internal.h"

#define pool_tgt(_p, _i) \
	OST_TGT(lu2lod_dev((_p)->pool_lobd->obd_lu_dev),(_p)->pool_obds.op_array[_i])

static void lod_pool_getref(struct pool_desc *pool)
{
	CDEBUG(D_INFO, "pool %p\n", pool);
	atomic_inc(&pool->pool_refcount);
}

void lod_pool_putref(struct pool_desc *pool)
{
	CDEBUG(D_INFO, "pool %p\n", pool);
	if (atomic_dec_and_test(&pool->pool_refcount)) {
		LASSERT(cfs_hlist_unhashed(&pool->pool_hash));
		LASSERT(cfs_list_empty(&pool->pool_list));
		LASSERT(pool->pool_proc_entry == NULL);
		lod_ost_pool_free(&(pool->pool_rr.lqr_pool));
		lod_ost_pool_free(&(pool->pool_obds));
		OBD_FREE_PTR(pool);
		EXIT;
	}
}

void lod_pool_putref_locked(struct pool_desc *pool)
{
	CDEBUG(D_INFO, "pool %p\n", pool);
	LASSERT(atomic_read(&pool->pool_refcount) > 1);

	atomic_dec(&pool->pool_refcount);
}


/*
 * hash function using a Rotating Hash algorithm
 * Knuth, D. The Art of Computer Programming,
 * Volume 3: Sorting and Searching,
 * Chapter 6.4.
 * Addison Wesley, 1973
 */
static __u32 pool_hashfn(cfs_hash_t *hash_body, const void *key, unsigned mask)
{
	int i;
	__u32 result;
	char *poolname;

	result = 0;
	poolname = (char *)key;
	for (i = 0; i < LOV_MAXPOOLNAME; i++) {
		if (poolname[i] == '\0')
			break;
		result = (result << 4)^(result >> 28) ^  poolname[i];
	}
	return (result % mask);
}

static void *pool_key(cfs_hlist_node_t *hnode)
{
	struct pool_desc *pool;

	pool = cfs_hlist_entry(hnode, struct pool_desc, pool_hash);
	return (pool->pool_name);
}

static int pool_hashkey_keycmp(const void *key, cfs_hlist_node_t *compared_hnode)
{
	char *pool_name;
	struct pool_desc *pool;

	pool_name = (char *)key;
	pool = cfs_hlist_entry(compared_hnode, struct pool_desc, pool_hash);
	return !strncmp(pool_name, pool->pool_name, LOV_MAXPOOLNAME);
}

static void *pool_hashobject(cfs_hlist_node_t *hnode)
{
	return cfs_hlist_entry(hnode, struct pool_desc, pool_hash);
}

static void pool_hashrefcount_get(cfs_hash_t *hs, cfs_hlist_node_t *hnode)
{
	struct pool_desc *pool;

	pool = cfs_hlist_entry(hnode, struct pool_desc, pool_hash);
	lod_pool_getref(pool);
}

static void pool_hashrefcount_put_locked(cfs_hash_t *hs,
		cfs_hlist_node_t *hnode)
{
	struct pool_desc *pool;

	pool = cfs_hlist_entry(hnode, struct pool_desc, pool_hash);
	lod_pool_putref_locked(pool);
}

cfs_hash_ops_t pool_hash_operations = {
	.hs_hash        = pool_hashfn,
	.hs_key         = pool_key,
	.hs_keycmp      = pool_hashkey_keycmp,
	.hs_object      = pool_hashobject,
	.hs_get         = pool_hashrefcount_get,
	.hs_put_locked  = pool_hashrefcount_put_locked,
};

#ifdef LPROCFS
/* ifdef needed for liblustre support */
/*
 * pool /proc seq_file methods
 */
/*
 * iterator is used to go through the target pool entries
 * index is the current entry index in the lp_array[] array
 * index >= pos returned to the seq_file interface
 * pos is from 0 to (pool->pool_obds.op_count - 1)
 */
#define POOL_IT_MAGIC 0xB001CEA0
struct lod_pool_iterator {
	int		  lpi_magic;
	int		  lpi_idx;	/* from 0 to pool_tgt_size - 1 */
	struct pool_desc *lpi_pool;
};

static void *pool_proc_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct lod_pool_iterator *iter = s->private;
	int prev_idx;

	LASSERTF(iter->lpi_magic == POOL_IT_MAGIC, "%08X", iter->lpi_magic);

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

static void *pool_proc_start(struct seq_file *s, loff_t *pos)
{
	struct pool_desc *pool = s->private;
	struct lod_pool_iterator *iter;

	lod_pool_getref(pool);
	if ((pool_tgt_count(pool) == 0) ||
	    (*pos >= pool_tgt_count(pool))) {
		/* iter is not created, so stop() has no way to
		 * find pool to dec ref */
		lod_pool_putref(pool);
		return NULL;
	}

	OBD_ALLOC_PTR(iter);
	if (!iter)
		return ERR_PTR(-ENOMEM);
	iter->lpi_magic = POOL_IT_MAGIC;
	iter->lpi_pool = pool;
	iter->lpi_idx = 0;

	/* we use seq_file private field to memorized iterator so
	 * we can free it at stop() */
	/* /!\ do not forget to restore it to pool before freeing it */
	s->private = iter;
	if (*pos > 0) {
		loff_t i;
		void *ptr;

		i = 0;
		do {
			ptr = pool_proc_next(s, &iter, &i);
		} while ((i < *pos) && (ptr != NULL));
		return ptr;
	}
	return iter;
}

static void pool_proc_stop(struct seq_file *s, void *v)
{
	struct lod_pool_iterator *iter = s->private;

	/* in some cases stop() method is called 2 times, without
	 * calling start() method (see seq_read() from fs/seq_file.c)
	 * we have to free only if s->private is an iterator */
	if (iter != NULL && (iter->lpi_magic == POOL_IT_MAGIC)) {
		/* we restore s->private so next call to pool_proc_start()
		 * will work */
		s->private = iter->lpi_pool;
		lod_pool_putref(iter->lpi_pool);
		OBD_FREE_PTR(iter);
	}
	return;
}

static int pool_proc_show(struct seq_file *s, void *v)
{
	struct lod_pool_iterator *iter = v;
	struct lod_tgt_desc  *osc_desc;

	LASSERTF(iter->lpi_magic == POOL_IT_MAGIC, "%08X", iter->lpi_magic);
	LASSERT(iter->lpi_pool != NULL);
	LASSERT(iter->lpi_idx <= pool_tgt_count(iter->lpi_pool));

	down_read(&pool_tgt_rw_sem(iter->lpi_pool));
	osc_desc = pool_tgt(iter->lpi_pool, iter->lpi_idx);
	up_read(&pool_tgt_rw_sem(iter->lpi_pool));
	if (osc_desc)
		seq_printf(s, "%s\n", obd_uuid2str(&(osc_desc->ltd_uuid)));

	return 0;
}

static struct seq_operations pool_proc_ops = {
	.start	= pool_proc_start,
	.next	= pool_proc_next,
	.stop	= pool_proc_stop,
	.show	= pool_proc_show,
};

static int pool_proc_open(struct inode *inode, struct file *file)
{
	int rc;

	rc = seq_open(file, &pool_proc_ops);
	if (!rc) {
		struct seq_file *s = file->private_data;
		s->private = PDE_DATA(inode);
	}
	return rc;
}

static struct file_operations pool_proc_operations = {
	.open		= pool_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
#endif /* LPROCFS */

void lod_dump_pool(int level, struct pool_desc *pool)
{
	int i;

	lod_pool_getref(pool);

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

#define LOD_POOL_INIT_COUNT 2
int lod_ost_pool_init(struct ost_pool *op, unsigned int count)
{
	ENTRY;

	if (count == 0)
		count = LOD_POOL_INIT_COUNT;
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

/* Caller must hold write op_rwlock */
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

int lod_ost_pool_add(struct ost_pool *op, __u32 idx, unsigned int min_count)
{
	int rc = 0, i;
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

int lod_ost_pool_remove(struct ost_pool *op, __u32 idx)
{
	int i;
	ENTRY;

	down_write(&op->op_rw_sem);

	for (i = 0; i < op->op_count; i++) {
		if (op->op_array[i] == idx) {
			memmove(&op->op_array[i], &op->op_array[i + 1],
				(op->op_count - i - 1) * sizeof(op->op_array[0]));
			op->op_count--;
			up_write(&op->op_rw_sem);
			EXIT;
			return 0;
		}
	}

	up_write(&op->op_rw_sem);
	RETURN(-EINVAL);
}

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

	strncpy(new_pool->pool_name, poolname, LOV_MAXPOOLNAME);
	new_pool->pool_name[LOV_MAXPOOLNAME] = '\0';
	new_pool->pool_lobd = obd;
	/* ref count init to 1 because when created a pool is always used
	 * up to deletion
	 */
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
	lod_pool_getref(new_pool);
	new_pool->pool_proc_entry = lprocfs_add_simple(lod->lod_pool_proc_entry,
						       poolname,
#ifndef HAVE_ONLY_PROCFS_SEQ
						       NULL, NULL,
#endif
						       new_pool,
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
	cfs_list_add_tail(&new_pool->pool_list, &lod->lod_pool_list);
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
	cfs_list_del_init(&new_pool->pool_list);
	lod->lod_pool_count--;
	spin_unlock(&obd->obd_dev_lock);

	lprocfs_remove(&new_pool->pool_proc_entry);

	lod_ost_pool_free(&new_pool->pool_rr.lqr_pool);
out_free_pool_obds:
	lod_ost_pool_free(&new_pool->pool_obds);
	OBD_FREE_PTR(new_pool);
	return rc;
}

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
	cfs_list_del_init(&pool->pool_list);
	lod->lod_pool_count--;
	spin_unlock(&obd->obd_dev_lock);

	/* release last reference */
	lod_pool_putref(pool);

	RETURN(0);
}


int lod_pool_add(struct obd_device *obd, char *poolname, char *ostname)
{
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct obd_uuid    ost_uuid;
	struct pool_desc  *pool;
	unsigned int	   idx;
	int		   rc = -EINVAL;
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

int lod_pool_remove(struct obd_device *obd, char *poolname, char *ostname)
{
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct obd_uuid    ost_uuid;
	struct pool_desc  *pool;
	unsigned int       idx;
	int                rc = -EINVAL;
	ENTRY;

	pool = cfs_hash_lookup(lod->lod_pools_hash_body, poolname);
	if (pool == NULL)
		RETURN(-ENOENT);

	obd_str2uuid(&ost_uuid, ostname);

	lod_getref(&lod->lod_ost_descs);
	/* search ost in lod array, to get index */
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

int lod_check_index_in_pool(__u32 idx, struct pool_desc *pool)
{
	int i, rc;
	ENTRY;

	/* caller may no have a ref on pool if it got the pool
	 * without calling lod_find_pool() (e.g. go through the lod pool
	 * list)
	 */
	lod_pool_getref(pool);

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

