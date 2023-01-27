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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/lov/lov_pool.c
 *
 * OST pool methods
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
#include "lov_internal.h"

#define pool_tgt(_p, _i) \
		_p->pool_lobd->u.lov.lov_tgts[_p->pool_obds.op_array[_i]]

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

static void lov_pool_getref(struct pool_desc *pool)
{
	CDEBUG(D_INFO, "pool %p\n", pool);
	atomic_inc(&pool->pool_refcount);
}

void lov_pool_putref(struct pool_desc *pool)
{
	CDEBUG(D_INFO, "pool %p\n", pool);
	if (atomic_dec_and_test(&pool->pool_refcount)) {
		LASSERT(list_empty(&pool->pool_list));
		LASSERT(pool->pool_proc_entry == NULL);
		lu_tgt_pool_free(&(pool->pool_obds));
		kfree_rcu(pool, pool_rcu);
		EXIT;
	}
}

#ifdef CONFIG_PROC_FS
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
struct pool_iterator {
        int magic;
        struct pool_desc *pool;
        int idx;        /* from 0 to pool_tgt_size - 1 */
};

static void *pool_proc_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct pool_iterator *iter = (struct pool_iterator *)s->private;
	int prev_idx;

	LASSERTF(iter->magic == POOL_IT_MAGIC, "%08X\n", iter->magic);

	(*pos)++;
	/* test if end of file */
	if (*pos > pool_tgt_count(iter->pool))
		return NULL;

	/* iterate to find a non empty entry */
	prev_idx = iter->idx;
	iter->idx++;
	if (iter->idx >= pool_tgt_count(iter->pool)) {
		iter->idx = prev_idx; /* we stay on the last entry */
		return NULL;
	}
	/* return != NULL to continue */
	return iter;
}

static void *pool_proc_start(struct seq_file *s, loff_t *pos)
{
        struct pool_desc *pool = (struct pool_desc *)s->private;
        struct pool_iterator *iter;

        lov_pool_getref(pool);
        if ((pool_tgt_count(pool) == 0) ||
            (*pos >= pool_tgt_count(pool))) {
                /* iter is not created, so stop() has no way to
                 * find pool to dec ref */
                lov_pool_putref(pool);
                return NULL;
        }

        OBD_ALLOC_PTR(iter);
        if (!iter)
                return ERR_PTR(-ENOMEM);
        iter->magic = POOL_IT_MAGIC;
        iter->pool = pool;
        iter->idx = 0;

        /* we use seq_file private field to memorized iterator so
         * we can free it at stop() */
        /* /!\ do not forget to restore it to pool before freeing it */
        s->private = iter;
	down_read(&pool_tgt_rw_sem(pool));
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
        struct pool_iterator *iter = (struct pool_iterator *)s->private;

        /* in some cases stop() method is called 2 times, without
         * calling start() method (see seq_read() from fs/seq_file.c)
         * we have to free only if s->private is an iterator */
        if ((iter) && (iter->magic == POOL_IT_MAGIC)) {
		up_read(&pool_tgt_rw_sem(iter->pool));
                /* we restore s->private so next call to pool_proc_start()
                 * will work */
                s->private = iter->pool;
                lov_pool_putref(iter->pool);
                OBD_FREE_PTR(iter);
        }
}

static int pool_proc_show(struct seq_file *s, void *v)
{
        struct pool_iterator *iter = (struct pool_iterator *)v;
        struct lov_tgt_desc *tgt;

	LASSERTF(iter->magic == POOL_IT_MAGIC, "%08X\n", iter->magic);
	LASSERT(iter->pool != NULL);
	LASSERT(iter->idx <= pool_tgt_count(iter->pool));

        tgt = pool_tgt(iter->pool, iter->idx);
        if (tgt)
                seq_printf(s, "%s\n", obd_uuid2str(&(tgt->ltd_uuid)));

        return 0;
}

static const struct seq_operations pool_proc_ops = {
	.start		= pool_proc_start,
	.next		= pool_proc_next,
	.stop		= pool_proc_stop,
	.show		= pool_proc_show,
};

static int pool_proc_open(struct inode *inode, struct file *file)
{
        int rc;

        rc = seq_open(file, &pool_proc_ops);
        if (!rc) {
                struct seq_file *s = file->private_data;
		s->private = pde_data(inode);
        }
        return rc;
}

const static struct proc_ops pool_proc_operations = {
	.proc_open	= pool_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};
#endif /* CONFIG_PROC_FS */

static void pools_hash_exit(void *vpool, void *data)
{
	struct pool_desc *pool = vpool;

	lov_pool_putref(pool);
}

int lov_pool_hash_init(struct rhashtable *tbl)
{
	return rhashtable_init(tbl, &pools_hash_params);
}

void lov_pool_hash_destroy(struct rhashtable *tbl)
{
	rhashtable_free_and_destroy(tbl, pools_hash_exit, NULL);
}

int lov_pool_new(struct obd_device *obd, char *poolname)
{
        struct lov_obd *lov;
        struct pool_desc *new_pool;
        int rc;
        ENTRY;

        lov = &(obd->u.lov);

        if (strlen(poolname) > LOV_MAXPOOLNAME)
                RETURN(-ENAMETOOLONG);

	/* OBD_ALLOC doesn't work with direct use of kfree_rcu */
	new_pool = kmalloc(sizeof(*new_pool), GFP_KERNEL);
        if (new_pool == NULL)
                RETURN(-ENOMEM);

	strlcpy(new_pool->pool_name, poolname, sizeof(new_pool->pool_name));
	new_pool->pool_lobd = obd;
	/* ref count init to 1 because when created a pool is always used
	 * up to deletion
	 */
	atomic_set(&new_pool->pool_refcount, 1);
	rc = lu_tgt_pool_init(&new_pool->pool_obds, 0);
	if (rc)
		GOTO(out_free_pool, rc);

#ifdef CONFIG_PROC_FS
	/* get ref for /proc file */
        lov_pool_getref(new_pool);
	new_pool->pool_proc_entry = lprocfs_add_simple(lov->lov_pool_proc_entry,
						       poolname, new_pool,
						       &pool_proc_operations);
	if (IS_ERR(new_pool->pool_proc_entry)) {
		CWARN("Cannot add proc pool entry "LOV_POOLNAMEF"\n", poolname);
		new_pool->pool_proc_entry = NULL;
		lov_pool_putref(new_pool);
	}
	CDEBUG(D_INFO, "pool %p - proc %p\n",
	       new_pool, new_pool->pool_proc_entry);
#endif

	spin_lock(&obd->obd_dev_lock);
	list_add_tail(&new_pool->pool_list, &lov->lov_pool_list);
	lov->lov_pool_count++;
	spin_unlock(&obd->obd_dev_lock);

	/* Add to hash table only when it is fully ready. */
	rc = rhashtable_lookup_insert_fast(&lov->lov_pools_hash_body,
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
               poolname, lov->lov_pool_count);

        RETURN(0);

out_err:
	spin_lock(&obd->obd_dev_lock);
	list_del_init(&new_pool->pool_list);
	lov->lov_pool_count--;
	spin_unlock(&obd->obd_dev_lock);
        lprocfs_remove(&new_pool->pool_proc_entry);
	lu_tgt_pool_free(&new_pool->pool_obds);
out_free_pool:
	OBD_FREE_PTR(new_pool);

	return rc;
}

struct pool_desc *lov_pool_find(struct obd_device *obd, char *poolname)
{
	struct pool_desc *pool;
	struct lov_obd *lov = &obd->u.lov;

	rcu_read_lock();
	pool = rhashtable_lookup(&lov->lov_pools_hash_body,
				 poolname,
				 pools_hash_params);
	if (pool && !atomic_inc_not_zero(&pool->pool_refcount))
		pool = NULL;
	rcu_read_unlock();

	return pool;
}

int lov_pool_del(struct obd_device *obd, char *poolname)
{
        struct lov_obd *lov;
        struct pool_desc *pool;
        ENTRY;

        lov = &(obd->u.lov);

	/* lookup and kill hash reference */
	rcu_read_lock();
	pool = rhashtable_lookup(&lov->lov_pools_hash_body, poolname,
				 pools_hash_params);
	if (pool && rhashtable_remove_fast(&lov->lov_pools_hash_body,
					   &pool->pool_hash,
					   pools_hash_params) != 0)
		pool = NULL;
	rcu_read_unlock();
	if (!pool)
		RETURN(-ENOENT);

        if (pool->pool_proc_entry != NULL) {
                CDEBUG(D_INFO, "proc entry %p\n", pool->pool_proc_entry);
                lprocfs_remove(&pool->pool_proc_entry);
                lov_pool_putref(pool);
        }

	spin_lock(&obd->obd_dev_lock);
	list_del_init(&pool->pool_list);
	lov->lov_pool_count--;
	spin_unlock(&obd->obd_dev_lock);

	/* release last reference */
	lov_pool_putref(pool);

	RETURN(0);
}


int lov_pool_add(struct obd_device *obd, char *poolname, char *ostname)
{
        struct obd_uuid ost_uuid;
        struct lov_obd *lov;
        struct pool_desc *pool;
        unsigned int lov_idx;
        int rc;
        ENTRY;

        lov = &(obd->u.lov);

	rcu_read_lock();
	pool = rhashtable_lookup(&lov->lov_pools_hash_body, poolname,
				 pools_hash_params);
	if (pool && !atomic_inc_not_zero(&pool->pool_refcount))
		pool = NULL;
	rcu_read_unlock();
	if (!pool)
		RETURN(-ENOENT);

        obd_str2uuid(&ost_uuid, ostname);


        /* search ost in lov array */
	lov_tgts_getref(obd);
        for (lov_idx = 0; lov_idx < lov->desc.ld_tgt_count; lov_idx++) {
                if (!lov->lov_tgts[lov_idx])
                        continue;
                if (obd_uuid_equals(&ost_uuid,
                                    &(lov->lov_tgts[lov_idx]->ltd_uuid)))
                        break;
        }
        /* test if ost found in lov */
        if (lov_idx == lov->desc.ld_tgt_count)
                GOTO(out, rc = -EINVAL);

	rc = lu_tgt_pool_add(&pool->pool_obds, lov_idx, lov->lov_tgt_size);
        if (rc)
                GOTO(out, rc);

        CDEBUG(D_CONFIG, "Added %s to "LOV_POOLNAMEF" as member %d\n",
               ostname, poolname,  pool_tgt_count(pool));

        EXIT;
out:
	lov_tgts_putref(obd);
	lov_pool_putref(pool);

	return rc;
}

int lov_pool_remove(struct obd_device *obd, char *poolname, char *ostname)
{
        struct obd_uuid ost_uuid;
        struct lov_obd *lov;
        struct pool_desc *pool;
        unsigned int lov_idx;
        int rc = 0;
        ENTRY;

        lov = &(obd->u.lov);

	/* lookup and kill hash reference */
	rcu_read_lock();
	pool = rhashtable_lookup(&lov->lov_pools_hash_body, poolname,
				 pools_hash_params);
	if (pool && !atomic_inc_not_zero(&pool->pool_refcount))
		pool = NULL;
	rcu_read_unlock();
	if (!pool)
		RETURN(-ENOENT);

        obd_str2uuid(&ost_uuid, ostname);

	lov_tgts_getref(obd);
        /* search ost in lov array, to get index */
        for (lov_idx = 0; lov_idx < lov->desc.ld_tgt_count; lov_idx++) {
                if (!lov->lov_tgts[lov_idx])
                        continue;

                if (obd_uuid_equals(&ost_uuid,
                                    &(lov->lov_tgts[lov_idx]->ltd_uuid)))
                        break;
        }

        /* test if ost found in lov */
        if (lov_idx == lov->desc.ld_tgt_count)
                GOTO(out, rc = -EINVAL);

	lu_tgt_pool_remove(&pool->pool_obds, lov_idx);

        CDEBUG(D_CONFIG, "%s removed from "LOV_POOLNAMEF"\n", ostname,
               poolname);

        EXIT;
out:
	lov_tgts_putref(obd);
	lov_pool_putref(pool);

	return rc;
}
