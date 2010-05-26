/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/hash.c
 *
 * Implement a hash class for hash process in lustre system.
 *
 * Author: YuZhangyong <yzy@clusterfs.com>
 *
 * 2008-08-15: Brian Behlendorf <behlendorf1@llnl.gov>
 * - Simplified API and improved documentation
 * - Added per-hash feature flags:
 *   * CFS_HASH_DEBUG additional validation
 *   * CFS_HASH_REHASH dynamic rehashing
 * - Added per-hash statistics
 * - General performance enhancements
 *
 * 2009-07-31: Liang Zhen <zhen.liang@sun.com>
 * - move all stuff to libcfs
 * - don't allow cur_bits != max_bits without setting of CFS_HASH_REHASH
 * - ignore hs_rwlock if without CFS_HASH_REHASH setting
 * - buckets are allocated one by one(intead of contiguous memory),
 *   to avoid unnecessary cacheline conflict
 */

#include <libcfs/libcfs.h>

static void cfs_hash_destroy(cfs_hash_t *hs);

static void
cfs_hash_rlock(cfs_hash_t *hs)
{
        if ((hs->hs_flags & CFS_HASH_REHASH) != 0)
                cfs_read_lock(&hs->hs_rwlock);
}

static void
cfs_hash_runlock(cfs_hash_t *hs)
{
        if ((hs->hs_flags & CFS_HASH_REHASH) != 0)
                cfs_read_unlock(&hs->hs_rwlock);
}

static void
cfs_hash_wlock(cfs_hash_t *hs)
{
        if ((hs->hs_flags & CFS_HASH_REHASH) != 0)
                cfs_write_lock(&hs->hs_rwlock);
}

static void
cfs_hash_wunlock(cfs_hash_t *hs)
{
        if ((hs->hs_flags & CFS_HASH_REHASH) != 0)
                cfs_write_unlock(&hs->hs_rwlock);
}

/**
 * Initialize new libcfs hash, where:
 * @name     - Descriptive hash name
 * @cur_bits - Initial hash table size, in bits
 * @max_bits - Maximum allowed hash table resize, in bits
 * @ops      - Registered hash table operations
 * @flags    - CFS_HASH_REHASH enable synamic hash resizing
 *           - CFS_HASH_SORT enable chained hash sort
 */
cfs_hash_t *
cfs_hash_create(char *name, unsigned int cur_bits,
                unsigned int max_bits, cfs_hash_ops_t *ops, int flags)
{
        cfs_hash_t    *hs;
        int            i;
        ENTRY;

        LASSERT(name != NULL);
        LASSERT(ops != NULL);
        /* The following ops are required for all hash table types */
        LASSERT(ops->hs_hash != NULL);
        LASSERT(ops->hs_key != NULL);
        LASSERT(ops->hs_compare != NULL);
        LASSERT(ops->hs_get != NULL);
        LASSERT(ops->hs_put != NULL);

        LASSERT(cur_bits > 0);
        LASSERT(max_bits >= cur_bits);
        LASSERT(max_bits < 31);
        LASSERT(cur_bits == max_bits || (flags & CFS_HASH_REHASH) != 0);

        CFS_ALLOC_PTR(hs);
        if (!hs)
                RETURN(NULL);

        strncpy(hs->hs_name, name, sizeof(hs->hs_name));
        hs->hs_name[sizeof(hs->hs_name) - 1] = '\0';
        cfs_atomic_set(&hs->hs_rehash_count, 0);
        cfs_atomic_set(&hs->hs_refcount, 1);
        cfs_atomic_set(&hs->hs_count, 0);
        cfs_rwlock_init(&hs->hs_rwlock);
        hs->hs_cur_bits = cur_bits;
        hs->hs_cur_mask = (1 << cur_bits) - 1;
        hs->hs_min_bits = cur_bits;
        hs->hs_max_bits = max_bits;
        /* XXX: need to fixup cfs_hash_rehash_bits() before this can be
         *      anything other than 0.5 and 2.0 */
        hs->hs_min_theta = 1 << (CFS_HASH_THETA_BITS - 1);
        hs->hs_max_theta = 1 << (CFS_HASH_THETA_BITS + 1);
        hs->hs_ops = ops;
        hs->hs_flags = flags;

        /* theta * 1000 */
        __cfs_hash_set_theta(hs, 500, 2000);

        LIBCFS_ALLOC(hs->hs_buckets,
                     sizeof(*hs->hs_buckets) << hs->hs_cur_bits);
        if (hs->hs_buckets == NULL) {
                CFS_FREE_PTR(hs);
                RETURN(NULL);
        }

        for (i = 0; i <= hs->hs_cur_mask; i++) {
                CFS_ALLOC_PTR(hs->hs_buckets[i]);
                if (hs->hs_buckets[i] == NULL) {
                        cfs_hash_destroy(hs);
                        return NULL;
                }

                CFS_INIT_HLIST_HEAD(&hs->hs_buckets[i]->hsb_head);
                cfs_rwlock_init(&hs->hs_buckets[i]->hsb_rwlock);
                cfs_atomic_set(&hs->hs_buckets[i]->hsb_count, 0);
        }

        return hs;
}
CFS_EXPORT_SYMBOL(cfs_hash_create);

/**
 * Cleanup libcfs hash @hs.
 */
static void
cfs_hash_destroy(cfs_hash_t *hs)
{
        cfs_hash_bucket_t    *hsb;
        cfs_hlist_node_t     *hnode;
        cfs_hlist_node_t     *pos;
        int                   i;
        ENTRY;

        LASSERT(hs != NULL);

        cfs_hash_wlock(hs);

        cfs_hash_for_each_bucket(hs, hsb, i) {
                if (hsb == NULL)
                        continue;

                cfs_write_lock(&hsb->hsb_rwlock);
                cfs_hlist_for_each_safe(hnode, pos, &(hsb->hsb_head)) {
                        __cfs_hash_bucket_validate(hs, hsb, hnode);
                        __cfs_hash_bucket_del(hs, hsb, hnode);
                        cfs_hash_exit(hs, hnode);
                }

                LASSERT(cfs_hlist_empty(&(hsb->hsb_head)));
                LASSERT(cfs_atomic_read(&hsb->hsb_count) == 0);
                cfs_write_unlock(&hsb->hsb_rwlock);
                CFS_FREE_PTR(hsb);
        }

        LASSERT(cfs_atomic_read(&hs->hs_count) == 0);
        cfs_hash_wunlock(hs);

        LIBCFS_FREE(hs->hs_buckets,
                    sizeof(*hs->hs_buckets) << hs->hs_cur_bits);
        CFS_FREE_PTR(hs);
        EXIT;
}

cfs_hash_t *cfs_hash_getref(cfs_hash_t *hs)
{
        if (cfs_atomic_inc_not_zero(&hs->hs_refcount))
                return hs;
        return NULL;
}
CFS_EXPORT_SYMBOL(cfs_hash_getref);

void cfs_hash_putref(cfs_hash_t *hs)
{
        if (cfs_atomic_dec_and_test(&hs->hs_refcount))
                cfs_hash_destroy(hs);
}
CFS_EXPORT_SYMBOL(cfs_hash_putref);

static inline unsigned int
cfs_hash_rehash_bits(cfs_hash_t *hs)
{
        if (!(hs->hs_flags & CFS_HASH_REHASH))
                return 0;

        /* XXX: need to handle case with max_theta != 2.0
         *      and the case with min_theta != 0.5 */
        if ((hs->hs_cur_bits < hs->hs_max_bits) &&
            (__cfs_hash_theta(hs) > hs->hs_max_theta))
                return hs->hs_cur_bits + 1;

        if ((hs->hs_cur_bits > hs->hs_min_bits) &&
            (__cfs_hash_theta(hs) < hs->hs_min_theta))
                return hs->hs_cur_bits - 1;

        return 0;
}

/**
 * Add item @hnode to libcfs hash @hs using @key.  The registered
 * ops->hs_get function will be called when the item is added.
 */
void
cfs_hash_add(cfs_hash_t *hs, void *key, cfs_hlist_node_t *hnode)
{
        cfs_hash_bucket_t    *hsb;
        int                   bits;
        unsigned              i;
        ENTRY;

        __cfs_hash_key_validate(hs, key, hnode);

        cfs_hash_rlock(hs);
        i = cfs_hash_id(hs, key, hs->hs_cur_mask);
        hsb = hs->hs_buckets[i];
        LASSERT(i <= hs->hs_cur_mask);
        LASSERT(cfs_hlist_unhashed(hnode));

        cfs_write_lock(&hsb->hsb_rwlock);
        __cfs_hash_bucket_add(hs, hsb, hnode);
        cfs_write_unlock(&hsb->hsb_rwlock);

        bits = cfs_hash_rehash_bits(hs);
        cfs_hash_runlock(hs);
        if (bits)
                cfs_hash_rehash(hs, bits);

        EXIT;
}
CFS_EXPORT_SYMBOL(cfs_hash_add);

static cfs_hlist_node_t *
cfs_hash_findadd_unique_hnode(cfs_hash_t *hs, void *key,
                              cfs_hlist_node_t *hnode)
{
        int                   bits = 0;
        cfs_hlist_node_t     *ehnode;
        cfs_hash_bucket_t    *hsb;
        unsigned              i;
        ENTRY;

        __cfs_hash_key_validate(hs, key, hnode);

        cfs_hash_rlock(hs);
        i = cfs_hash_id(hs, key, hs->hs_cur_mask);
        hsb = hs->hs_buckets[i];
        LASSERT(i <= hs->hs_cur_mask);
        LASSERT(cfs_hlist_unhashed(hnode));

        cfs_write_lock(&hsb->hsb_rwlock);
        ehnode = __cfs_hash_bucket_lookup(hs, hsb, key);
        if (ehnode) {
                cfs_hash_get(hs, ehnode);
        } else {
                __cfs_hash_bucket_add(hs, hsb, hnode);
                ehnode = hnode;
                bits = cfs_hash_rehash_bits(hs);
        }
        cfs_write_unlock(&hsb->hsb_rwlock);
        cfs_hash_runlock(hs);
        if (bits)
                cfs_hash_rehash(hs, bits);

        RETURN(ehnode);
}

/**
 * Add item @hnode to libcfs hash @hs using @key.  The registered
 * ops->hs_get function will be called if the item was added.
 * Returns 0 on success or -EALREADY on key collisions.
 */
int
cfs_hash_add_unique(cfs_hash_t *hs, void *key, cfs_hlist_node_t *hnode)
{
        cfs_hlist_node_t    *ehnode;
        ENTRY;

        ehnode = cfs_hash_findadd_unique_hnode(hs, key, hnode);
        if (ehnode != hnode) {
                cfs_hash_put(hs, ehnode);
                RETURN(-EALREADY);
        }
        RETURN(0);
}
CFS_EXPORT_SYMBOL(cfs_hash_add_unique);

/**
 * Add item @hnode to libcfs hash @hs using @key.  If this @key
 * already exists in the hash then ops->hs_get will be called on the
 * conflicting entry and that entry will be returned to the caller.
 * Otherwise ops->hs_get is called on the item which was added.
 */
void *
cfs_hash_findadd_unique(cfs_hash_t *hs, void *key,
                        cfs_hlist_node_t *hnode)
{
        cfs_hlist_node_t     *ehnode;
        void                 *obj;
        ENTRY;

        ehnode = cfs_hash_findadd_unique_hnode(hs, key, hnode);
        obj = cfs_hash_get(hs, ehnode);
        cfs_hash_put(hs, ehnode);
        RETURN(obj);
}
CFS_EXPORT_SYMBOL(cfs_hash_findadd_unique);

/**
 * Delete item @hnode from the libcfs hash @hs using @key.  The @key
 * is required to ensure the correct hash bucket is locked since there
 * is no direct linkage from the item to the bucket.  The object
 * removed from the hash will be returned and obs->hs_put is called
 * on the removed object.
 */
void *
cfs_hash_del(cfs_hash_t *hs, void *key, cfs_hlist_node_t *hnode)
{
        cfs_hash_bucket_t    *hsb;
        void                 *obj;
        unsigned              i;
        ENTRY;

        __cfs_hash_key_validate(hs, key, hnode);

        cfs_hash_rlock(hs);
        i = cfs_hash_id(hs, key, hs->hs_cur_mask);
        hsb = hs->hs_buckets[i];
        LASSERT(i <= hs->hs_cur_mask);
        LASSERT(!cfs_hlist_unhashed(hnode));

        cfs_write_lock(&hsb->hsb_rwlock);
        obj = __cfs_hash_bucket_del(hs, hsb, hnode);
        cfs_write_unlock(&hsb->hsb_rwlock);
        cfs_hash_runlock(hs);

        RETURN(obj);
}
CFS_EXPORT_SYMBOL(cfs_hash_del);

/**
 * Delete item from the libcfs hash @hs when @func return true.
 * The write lock being hold during loop for each bucket to avoid
 * any object be reference.
 */
void
cfs_hash_cond_del(cfs_hash_t *hs, cfs_hash_cond_opt_cb_t func, void *data)
{
        cfs_hlist_node_t       *hnode;
        cfs_hlist_node_t       *pos;
        cfs_hash_bucket_t      *hsb;
        int                    i;
        ENTRY;

        cfs_hash_wlock(hs);
        cfs_hash_for_each_bucket(hs, hsb, i) {
                cfs_write_lock(&hsb->hsb_rwlock);
                cfs_hlist_for_each_safe(hnode, pos, &(hsb->hsb_head)) {
                        __cfs_hash_bucket_validate(hs, hsb, hnode);
                        if (func(cfs_hash_get(hs, hnode), data))
                                __cfs_hash_bucket_del(hs, hsb, hnode);
                        (void)cfs_hash_put(hs, hnode);
                }
                cfs_write_unlock(&hsb->hsb_rwlock);
        }
        cfs_hash_wunlock(hs);

        EXIT;
}
CFS_EXPORT_SYMBOL(cfs_hash_cond_del);

/**
 * Delete item given @key in libcfs hash @hs.  The first @key found in
 * the hash will be removed, if the key exists multiple times in the hash
 * @hs this function must be called once per key.  The removed object
 * will be returned and ops->hs_put is called on the removed object.
 */
void *
cfs_hash_del_key(cfs_hash_t *hs, void *key)
{
        void                 *obj = NULL;
        cfs_hlist_node_t     *hnode;
        cfs_hash_bucket_t    *hsb;
        unsigned              i;
        ENTRY;

        cfs_hash_rlock(hs);
        i = cfs_hash_id(hs, key, hs->hs_cur_mask);
        hsb = hs->hs_buckets[i];
        LASSERT(i <= hs->hs_cur_mask);

        cfs_write_lock(&hsb->hsb_rwlock);
        hnode = __cfs_hash_bucket_lookup(hs, hsb, key);
        if (hnode)
                obj = __cfs_hash_bucket_del(hs, hsb, hnode);

        cfs_write_unlock(&hsb->hsb_rwlock);
        cfs_hash_runlock(hs);

        RETURN(obj);
}
CFS_EXPORT_SYMBOL(cfs_hash_del_key);

/**
 * Lookup an item using @key in the libcfs hash @hs and return it.
 * If the @key is found in the hash hs->hs_get() is called and the
 * matching objects is returned.  It is the callers responsibility
 * to call the counterpart ops->hs_put using the cfs_hash_put() macro
 * when when finished with the object.  If the @key was not found
 * in the hash @hs NULL is returned.
 */
void *
cfs_hash_lookup(cfs_hash_t *hs, void *key)
{
        void                 *obj = NULL;
        cfs_hlist_node_t     *hnode;
        cfs_hash_bucket_t    *hsb;
        unsigned              i;
        ENTRY;

        cfs_hash_rlock(hs);
        i = cfs_hash_id(hs, key, hs->hs_cur_mask);
        hsb = hs->hs_buckets[i];
        LASSERT(i <= hs->hs_cur_mask);

        cfs_read_lock(&hsb->hsb_rwlock);
        hnode = __cfs_hash_bucket_lookup(hs, hsb, key);
        if (hnode)
                obj = cfs_hash_get(hs, hnode);

        cfs_read_unlock(&hsb->hsb_rwlock);
        cfs_hash_runlock(hs);

        RETURN(obj);
}
CFS_EXPORT_SYMBOL(cfs_hash_lookup);

/**
 * For each item in the libcfs hash @hs call the passed callback @func
 * and pass to it as an argument each hash item and the private @data.
 * Before each callback ops->hs_get will be called, and after each
 * callback ops->hs_put will be called.  Finally, during the callback
 * the bucket lock is held so the callback must never sleep.
 */
void
cfs_hash_for_each(cfs_hash_t *hs,
                  cfs_hash_for_each_cb_t func, void *data)
{
        cfs_hlist_node_t     *hnode;
        cfs_hash_bucket_t    *hsb;
        void                 *obj;
        int                   i;
        ENTRY;

        cfs_hash_rlock(hs);
        cfs_hash_for_each_bucket(hs, hsb, i) {
                cfs_read_lock(&hsb->hsb_rwlock);
                cfs_hlist_for_each(hnode, &(hsb->hsb_head)) {
                        __cfs_hash_bucket_validate(hs, hsb, hnode);
                        obj = cfs_hash_get(hs, hnode);
                        func(obj, data);
                        (void)cfs_hash_put(hs, hnode);
                }
                cfs_read_unlock(&hsb->hsb_rwlock);
        }
        cfs_hash_runlock(hs);

        EXIT;
}
CFS_EXPORT_SYMBOL(cfs_hash_for_each);

/**
 * For each item in the libcfs hash @hs call the passed callback @func
 * and pass to it as an argument each hash item and the private @data.
 * Before each callback ops->hs_get will be called, and after each
 * callback ops->hs_put will be called.  During the callback the
 * bucket lock will not be held will allows for the current item
 * to be removed from the hash during the callback.  However, care
 * should be taken to prevent other callers from operating on the
 * hash concurrently or list corruption may occur.
 */
void
cfs_hash_for_each_safe(cfs_hash_t *hs,
                       cfs_hash_for_each_cb_t func, void *data)
{
        cfs_hlist_node_t     *hnode;
        cfs_hlist_node_t     *pos;
        cfs_hash_bucket_t    *hsb;
        void                 *obj;
        int                   i;
        ENTRY;

        cfs_hash_rlock(hs);
        cfs_hash_for_each_bucket(hs, hsb, i) {
                cfs_read_lock(&hsb->hsb_rwlock);
                cfs_hlist_for_each_safe(hnode, pos, &(hsb->hsb_head)) {
                        __cfs_hash_bucket_validate(hs, hsb, hnode);
                        obj = cfs_hash_get(hs, hnode);
                        cfs_read_unlock(&hsb->hsb_rwlock);
                        func(obj, data);
                        cfs_read_lock(&hsb->hsb_rwlock);
                        (void)cfs_hash_put(hs, hnode);
                }
                cfs_read_unlock(&hsb->hsb_rwlock);
        }
        cfs_hash_runlock(hs);
        EXIT;
}
CFS_EXPORT_SYMBOL(cfs_hash_for_each_safe);

/**
 * For each hash bucket in the libcfs hash @hs call the passed callback
 * @func until all the hash buckets are empty.  The passed callback @func
 * or the previously registered callback hs->hs_put must remove the item
 * from the hash.  You may either use the cfs_hash_del() or hlist_del()
 * functions.  No rwlocks will be held during the callback @func it is
 * safe to sleep if needed.  This function will not terminate until the
 * hash is empty.  Note it is still possible to concurrently add new
 * items in to the hash.  It is the callers responsibility to ensure
 * the required locking is in place to prevent concurrent insertions.
 */
void
cfs_hash_for_each_empty(cfs_hash_t *hs,
                        cfs_hash_for_each_cb_t func, void *data)
{
        cfs_hlist_node_t     *hnode;
        cfs_hash_bucket_t    *hsb;
        cfs_hash_bucket_t    **hsb_last = NULL;
        void                 *obj;
        int                   i = 0;
        ENTRY;

restart:
        cfs_hash_rlock(hs);
        /* If the hash table has changed since we last held lh_rwlock,
         * we need to start traversing the list from the start. */
        if (hs->hs_buckets != hsb_last) {
                i = 0;
                hsb_last = hs->hs_buckets;
        }
        cfs_hash_for_each_bucket_restart(hs, hsb, i) {
                cfs_write_lock(&hsb->hsb_rwlock);
                while (!cfs_hlist_empty(&hsb->hsb_head)) {
                        hnode =  hsb->hsb_head.first;
                        __cfs_hash_bucket_validate(hs, hsb, hnode);
                        obj = cfs_hash_get(hs, hnode);
                        cfs_write_unlock(&hsb->hsb_rwlock);
                        cfs_hash_runlock(hs);
                        func(obj, data);
                        (void)cfs_hash_put(hs, hnode);
                        cfs_cond_resched();
                        goto restart;
                }
                cfs_write_unlock(&hsb->hsb_rwlock);
        }
        cfs_hash_runlock(hs);
        EXIT;
}
CFS_EXPORT_SYMBOL(cfs_hash_for_each_empty);

/*
 * For each item in the libcfs hash @hs which matches the @key call
 * the passed callback @func and pass to it as an argument each hash
 * item and the private @data.  Before each callback ops->hs_get will
 * be called, and after each callback ops->hs_put will be called.
 * Finally, during the callback the bucket lock is held so the
 * callback must never sleep.
   */
void
cfs_hash_for_each_key(cfs_hash_t *hs, void *key,
                      cfs_hash_for_each_cb_t func, void *data)
{
        cfs_hlist_node_t     *hnode;
        cfs_hash_bucket_t    *hsb;
        unsigned              i;
        ENTRY;

        cfs_hash_rlock(hs);
        i = cfs_hash_id(hs, key, hs->hs_cur_mask);
        hsb = hs->hs_buckets[i];
        LASSERT(i <= hs->hs_cur_mask);

        cfs_read_lock(&hsb->hsb_rwlock);
        cfs_hlist_for_each(hnode, &(hsb->hsb_head)) {
                __cfs_hash_bucket_validate(hs, hsb, hnode);

                if (!cfs_hash_compare(hs, key, hnode))
                        continue;

                func(cfs_hash_get(hs, hnode), data);
                (void)cfs_hash_put(hs, hnode);
        }

        cfs_read_unlock(&hsb->hsb_rwlock);
        cfs_hash_runlock(hs);

        EXIT;
}
CFS_EXPORT_SYMBOL(cfs_hash_for_each_key);

/**
 * Rehash the libcfs hash @hs to the given @bits.  This can be used
 * to grow the hash size when excessive chaining is detected, or to
 * shrink the hash when it is larger than needed.  When the CFS_HASH_REHASH
 * flag is set in @hs the libcfs hash may be dynamically rehashed
 * during addition or removal if the hash's theta value exceeds
 * either the hs->hs_min_theta or hs->max_theta values.  By default
 * these values are tuned to keep the chained hash depth small, and
 * this approach assumes a reasonably uniform hashing function.  The
 * theta thresholds for @hs are tunable via cfs_hash_set_theta().
 */
int
cfs_hash_rehash(cfs_hash_t *hs, int bits)
{
        cfs_hlist_node_t      *hnode;
        cfs_hlist_node_t      *pos;
        cfs_hash_bucket_t    **old_buckets;
        cfs_hash_bucket_t    **rehash_buckets;
        cfs_hash_bucket_t     *hs_hsb;
        cfs_hash_bucket_t     *rehash_hsb;
        int                    i;
        int                    theta;
        int                    old_mask;
        int                    old_bits;
        int                    new_mask = (1 << bits) - 1;
        int                    rc = 0;
        void                  *key;
        ENTRY;

        LASSERT(!cfs_in_interrupt());
        LASSERT(new_mask > 0);
        LASSERT((hs->hs_flags & CFS_HASH_REHASH) != 0);

        LIBCFS_ALLOC(rehash_buckets, sizeof(*rehash_buckets) << bits);
        if (!rehash_buckets)
                RETURN(-ENOMEM);

        for (i = 0; i <= new_mask; i++) {
                CFS_ALLOC_PTR(rehash_buckets[i]);
                if (rehash_buckets[i] == NULL)
                        GOTO(free, rc = -ENOMEM);

                CFS_INIT_HLIST_HEAD(&rehash_buckets[i]->hsb_head);
                cfs_rwlock_init(&rehash_buckets[i]->hsb_rwlock);
                cfs_atomic_set(&rehash_buckets[i]->hsb_count, 0);
        }

        cfs_hash_wlock(hs);

        /*
         * Early return for multiple concurrent racing callers,
         * ensure we only trigger the rehash if it is still needed.
         */
        theta = __cfs_hash_theta(hs);
        if ((theta >= hs->hs_min_theta) && (theta <= hs->hs_max_theta)) {
                cfs_hash_wunlock(hs);
                GOTO(free, rc = -EALREADY);
        }

        old_bits = hs->hs_cur_bits;
        old_buckets = hs->hs_buckets;
        old_mask = (1 << old_bits) - 1;

        hs->hs_cur_bits = bits;
        hs->hs_cur_mask = (1 << bits) - 1;
        hs->hs_buckets = rehash_buckets;
        cfs_atomic_inc(&hs->hs_rehash_count);

        for (i = 0; i <= old_mask; i++) {
                hs_hsb = old_buckets[i];

                cfs_write_lock(&hs_hsb->hsb_rwlock);
                cfs_hlist_for_each_safe(hnode, pos, &(hs_hsb->hsb_head)) {
                        key = cfs_hash_key(hs, hnode);
                        LASSERT(key);

                        /*
                         * Validate hnode is in the correct bucket.
                         */
                        if (unlikely(hs->hs_flags & CFS_HASH_DEBUG))
                                LASSERT(cfs_hash_id(hs, key, old_mask) == i);

                        /*
                         * Delete from old hash bucket.
                         */
                        cfs_hlist_del(hnode);
                        LASSERT(cfs_atomic_read(&hs_hsb->hsb_count) > 0);
                        cfs_atomic_dec(&hs_hsb->hsb_count);

                        /*
                         * Add to rehash bucket, ops->hs_key must be defined.
                         */
                        rehash_hsb = rehash_buckets[cfs_hash_id(hs, key,
                                                                new_mask)];
                        cfs_hlist_add_head(hnode, &(rehash_hsb->hsb_head));
                        cfs_atomic_inc(&rehash_hsb->hsb_count);
                }

                LASSERT(cfs_hlist_empty(&(hs_hsb->hsb_head)));
                LASSERT(cfs_atomic_read(&hs_hsb->hsb_count) == 0);
                cfs_write_unlock(&hs_hsb->hsb_rwlock);
        }

        cfs_hash_wunlock(hs);
        rehash_buckets = old_buckets;
        i = (1 << old_bits);
        bits = old_bits;
 free:
        while (--i >= 0)
                CFS_FREE_PTR(rehash_buckets[i]);
        LIBCFS_FREE(rehash_buckets, sizeof(*rehash_buckets) << bits);
        RETURN(rc);
}
CFS_EXPORT_SYMBOL(cfs_hash_rehash);

/**
 * Rehash the object referenced by @hnode in the libcfs hash @hs.  The
 * @old_key must be provided to locate the objects previous location
 * in the hash, and the @new_key will be used to reinsert the object.
 * Use this function instead of a cfs_hash_add() + cfs_hash_del()
 * combo when it is critical that there is no window in time where the
 * object is missing from the hash.  When an object is being rehashed
 * the registered cfs_hash_get() and cfs_hash_put() functions will
 * not be called.
 */
void cfs_hash_rehash_key(cfs_hash_t *hs, void *old_key, void *new_key,
                         cfs_hlist_node_t *hnode)
{
        cfs_hash_bucket_t     *old_hsb;
        cfs_hash_bucket_t     *new_hsb;
        unsigned               i;
        unsigned               j;
        ENTRY;

        __cfs_hash_key_validate(hs, new_key, hnode);
        LASSERT(!cfs_hlist_unhashed(hnode));

        cfs_hash_rlock(hs);

        i = cfs_hash_id(hs, old_key, hs->hs_cur_mask);
        old_hsb = hs->hs_buckets[i];
        LASSERT(i <= hs->hs_cur_mask);

        j = cfs_hash_id(hs, new_key, hs->hs_cur_mask);
        new_hsb = hs->hs_buckets[j];
        LASSERT(j <= hs->hs_cur_mask);

        if (i < j) { /* write_lock ordering */
                cfs_write_lock(&old_hsb->hsb_rwlock);
                cfs_write_lock(&new_hsb->hsb_rwlock);
        } else if (i > j) {
                cfs_write_lock(&new_hsb->hsb_rwlock);
                cfs_write_lock(&old_hsb->hsb_rwlock);
        } else { /* do nothing */
                cfs_hash_runlock(hs);
                EXIT;
                return;
        }

        /*
         * Migrate item between hash buckets without calling
         * the cfs_hash_get() and cfs_hash_put() callback functions.
         */
        cfs_hlist_del(hnode);
        LASSERT(cfs_atomic_read(&old_hsb->hsb_count) > 0);
        cfs_atomic_dec(&old_hsb->hsb_count);
        cfs_hlist_add_head(hnode, &(new_hsb->hsb_head));
        cfs_atomic_inc(&new_hsb->hsb_count);

        cfs_write_unlock(&new_hsb->hsb_rwlock);
        cfs_write_unlock(&old_hsb->hsb_rwlock);
        cfs_hash_runlock(hs);

        EXIT;
}
CFS_EXPORT_SYMBOL(cfs_hash_rehash_key);

int cfs_hash_debug_header(char *str, int size)
{
        return snprintf(str, size,
                 "%-*s%6s%6s%6s%6s%6s%6s%6s%7s%6s%s\n", CFS_MAX_HASH_NAME,
                 "name", "cur", "min", "max", "theta", "t-min", "t-max",
                 "flags", "rehash", "count", " distribution");
}
CFS_EXPORT_SYMBOL(cfs_hash_debug_header);

int cfs_hash_debug_str(cfs_hash_t *hs, char *str, int size)
{
        cfs_hash_bucket_t     *hsb;
        int                    theta;
        int                    i;
        int                    c = 0;
        int                    dist[8] = { 0, };

        if (str == NULL || size == 0)
                return 0;

        cfs_hash_rlock(hs);
        theta = __cfs_hash_theta(hs);

        c += snprintf(str + c, size - c, "%-*s ",
                      CFS_MAX_HASH_NAME, hs->hs_name);
        c += snprintf(str + c, size - c, "%5d ",  1 << hs->hs_cur_bits);
        c += snprintf(str + c, size - c, "%5d ",  1 << hs->hs_min_bits);
        c += snprintf(str + c, size - c, "%5d ",  1 << hs->hs_max_bits);
        c += snprintf(str + c, size - c, "%d.%03d ",
                      __cfs_hash_theta_int(theta),
                      __cfs_hash_theta_frac(theta));
        c += snprintf(str + c, size - c, "%d.%03d ",
                      __cfs_hash_theta_int(hs->hs_min_theta),
                      __cfs_hash_theta_frac(hs->hs_min_theta));
        c += snprintf(str + c, size - c, "%d.%03d ",
                      __cfs_hash_theta_int(hs->hs_max_theta),
                      __cfs_hash_theta_frac(hs->hs_max_theta));
        c += snprintf(str + c, size - c, " 0x%02x ", hs->hs_flags);
        c += snprintf(str + c, size - c, "%6d ",
                      cfs_atomic_read(&hs->hs_rehash_count));
        c += snprintf(str + c, size - c, "%5d ",
                      cfs_atomic_read(&hs->hs_count));

        /*
         * The distribution is a summary of the chained hash depth in
         * each of the libcfs hash buckets.  Each buckets hsb_count is
         * divided by the hash theta value and used to generate a
         * histogram of the hash distribution.  A uniform hash will
         * result in all hash buckets being close to the average thus
         * only the first few entries in the histogram will be non-zero.
         * If you hash function results in a non-uniform hash the will
         * be observable by outlier bucks in the distribution histogram.
         *
         * Uniform hash distribution:      128/128/0/0/0/0/0/0
         * Non-Uniform hash distribution:  128/125/0/0/0/0/2/1
         */
        cfs_hash_for_each_bucket(hs, hsb, i)
                dist[min(__cfs_fls(cfs_atomic_read(&hsb->hsb_count)/max(theta,1)),7)]++;

        for (i = 0; i < 8; i++)
                c += snprintf(str + c, size - c, "%d%c",  dist[i],
                              (i == 7) ? '\n' : '/');

        cfs_hash_runlock(hs);

        return c;
}
CFS_EXPORT_SYMBOL(cfs_hash_debug_str);
