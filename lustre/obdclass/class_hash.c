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
 * lustre/obdclass/class_hash.c
 *
 * Implement a hash class for hash process in lustre system.
 *
 * Author: YuZhangyong <yzy@clusterfs.com>
 *
 * 2008-08-15: Brian Behlendorf <behlendorf1@llnl.gov>
 * - Simplified API and improved documentation
 * - Added per-hash feature flags:
 *   * LH_DEBUG additional validation
 *   * LH_REHASH dynamic rehashing
 * - Added per-hash statistics
 * - General performance enhancements
 */

#ifndef __KERNEL__
#include <liblustre.h>
#include <obd.h>
#endif

#include <class_hash.h>

/**
 * Initialize new lustre hash, where:
 * @name     - Descriptive hash name
 * @cur_bits - Initial hash table size, in bits
 * @max_bits - Maximum allowed hash table resize, in bits
 * @ops      - Registered hash table operations
 * @flags    - LH_REHASH enable synamic hash resizing
 *           - LH_SORT enable chained hash sort
 */
lustre_hash_t *
lustre_hash_init(char *name, unsigned int cur_bits, unsigned int max_bits,
                 lustre_hash_ops_t *ops, int flags)
{
        lustre_hash_t *lh;
        int            i;
        ENTRY;
  
        LASSERT(name != NULL);
        LASSERT(ops != NULL);

        LASSERT(cur_bits > 0);
        LASSERT(max_bits >= cur_bits);
        LASSERT(max_bits < 31);
  
        OBD_ALLOC_PTR(lh);
        if (!lh)
                RETURN(NULL);
  
        strncpy(lh->lh_name, name, sizeof(lh->lh_name));
        atomic_set(&lh->lh_rehash_count, 0);
        atomic_set(&lh->lh_count, 0);
        rwlock_init(&lh->lh_rwlock);
        lh->lh_cur_bits = cur_bits;
        lh->lh_cur_mask = (1 << cur_bits) - 1;
        lh->lh_min_bits = cur_bits;
        lh->lh_max_bits = max_bits;
        /* XXX: need to fixup lustre_hash_rehash_bits() before this can be
         *      anything other than 0.5 and 2.0 */
        lh->lh_min_theta = 1 << (LH_THETA_BITS - 1);
        lh->lh_max_theta = 1 << (LH_THETA_BITS + 1);
        lh->lh_ops = ops;
        lh->lh_flags = flags;

        /* theta * 1000 */
        __lustre_hash_set_theta(lh, 500, 2000);

        OBD_VMALLOC(lh->lh_buckets, sizeof(*lh->lh_buckets) << lh->lh_cur_bits);
        if (!lh->lh_buckets) {
                OBD_FREE_PTR(lh);
                RETURN(NULL);
        }
  
        for (i = 0; i <= lh->lh_cur_mask; i++) {
                INIT_HLIST_HEAD(&lh->lh_buckets[i].lhb_head);
                rwlock_init(&lh->lh_buckets[i].lhb_rwlock);
                atomic_set(&lh->lh_buckets[i].lhb_count, 0);
        }
  
        return lh;
}
EXPORT_SYMBOL(lustre_hash_init);
  
/**
 * Cleanup lustre hash @lh.
 */
void
lustre_hash_exit(lustre_hash_t *lh)
{
        lustre_hash_bucket_t *lhb;
        struct hlist_node    *hnode;
        struct hlist_node    *pos;
        int                   i;
        ENTRY;

        LASSERT(lh != NULL);
  
        write_lock(&lh->lh_rwlock);
  
        lh_for_each_bucket(lh, lhb, i) {
                write_lock(&lhb->lhb_rwlock);
                hlist_for_each_safe(hnode, pos, &(lhb->lhb_head)) {
                        __lustre_hash_bucket_validate(lh, lhb, hnode);
                        __lustre_hash_bucket_del(lh, lhb, hnode);
                        lh_exit(lh, hnode);
                }
  
                LASSERT(hlist_empty(&(lhb->lhb_head)));
                LASSERT(atomic_read(&lhb->lhb_count) == 0);
                write_unlock(&lhb->lhb_rwlock);
        }
  
        OBD_VFREE(lh->lh_buckets, sizeof(*lh->lh_buckets) << lh->lh_cur_bits);
        LASSERT(atomic_read(&lh->lh_count) == 0);
        write_unlock(&lh->lh_rwlock);
  
        OBD_FREE_PTR(lh);
        EXIT;
}
EXPORT_SYMBOL(lustre_hash_exit);

static inline unsigned int lustre_hash_rehash_bits(lustre_hash_t *lh)
{
        if (!(lh->lh_flags & LH_REHASH))
                return 0;

        /* XXX: need to handle case with max_theta != 2.0 
         *      and the case with min_theta != 0.5 */
        if ((lh->lh_cur_bits < lh->lh_max_bits) &&
            (__lustre_hash_theta(lh) > lh->lh_max_theta))
                return lh->lh_cur_bits + 1;

        if ((lh->lh_cur_bits > lh->lh_min_bits) &&
            (__lustre_hash_theta(lh) < lh->lh_min_theta))
                return lh->lh_cur_bits - 1;

        return 0;
}
  
/**
 * Add item @hnode to lustre hash @lh using @key.  The registered
 * ops->lh_get function will be called when the item is added.
 */
void
lustre_hash_add(lustre_hash_t *lh, void *key, struct hlist_node *hnode)
{
        lustre_hash_bucket_t *lhb;
        int                   bits;
        unsigned              i;
        ENTRY;
  
        __lustre_hash_key_validate(lh, key, hnode);

        read_lock(&lh->lh_rwlock);
        i = lh_hash(lh, key, lh->lh_cur_mask);
        lhb = &lh->lh_buckets[i];
        LASSERT(i <= lh->lh_cur_mask);
        LASSERT(hlist_unhashed(hnode));

        write_lock(&lhb->lhb_rwlock);
        __lustre_hash_bucket_add(lh, lhb, hnode);
        write_unlock(&lhb->lhb_rwlock);

        bits = lustre_hash_rehash_bits(lh);
        read_unlock(&lh->lh_rwlock);
        if (bits)
                lustre_hash_rehash(lh, bits);
  
        EXIT;
}
EXPORT_SYMBOL(lustre_hash_add);

static struct hlist_node *
lustre_hash_findadd_unique_hnode(lustre_hash_t *lh, void *key,
                                 struct hlist_node *hnode)
{
        int                   bits = 0;
        struct hlist_node    *ehnode;
        lustre_hash_bucket_t *lhb;
        unsigned              i;
        ENTRY;
  
        __lustre_hash_key_validate(lh, key, hnode);
  
        read_lock(&lh->lh_rwlock);
        i = lh_hash(lh, key, lh->lh_cur_mask);
        lhb = &lh->lh_buckets[i];
        LASSERT(i <= lh->lh_cur_mask);
        LASSERT(hlist_unhashed(hnode));

        write_lock(&lhb->lhb_rwlock);
        ehnode = __lustre_hash_bucket_lookup(lh, lhb, key);
        if (ehnode) {
                lh_get(lh, ehnode);
        } else {
                __lustre_hash_bucket_add(lh, lhb, hnode);
                ehnode = hnode;
                bits = lustre_hash_rehash_bits(lh);
        }
        write_unlock(&lhb->lhb_rwlock);
        read_unlock(&lh->lh_rwlock);
        if (bits)
                lustre_hash_rehash(lh, bits);
  
        RETURN(ehnode);
}
  
/**
 * Add item @hnode to lustre hash @lh using @key.  The registered
 * ops->lh_get function will be called if the item was added.
 * Returns 0 on success or -EALREADY on key collisions.
 */
int
lustre_hash_add_unique(lustre_hash_t *lh, void *key, struct hlist_node *hnode)
{
        struct hlist_node    *ehnode;
        ENTRY;
        
        ehnode = lustre_hash_findadd_unique_hnode(lh, key, hnode);
        if (ehnode != hnode) {
                lh_put(lh, ehnode);
                RETURN(-EALREADY);
        }
        RETURN(0);
}
EXPORT_SYMBOL(lustre_hash_add_unique);
  
/**
 * Add item @hnode to lustre hash @lh using @key.  If this @key
 * already exists in the hash then ops->lh_get will be called on the
 * conflicting entry and that entry will be returned to the caller.
 * Otherwise ops->lh_get is called on the item which was added.
 */
void *
lustre_hash_findadd_unique(lustre_hash_t *lh, void *key,
                           struct hlist_node *hnode)
{
        struct hlist_node    *ehnode;
        void                 *obj;
        ENTRY;
        
        ehnode = lustre_hash_findadd_unique_hnode(lh, key, hnode);
        obj = lh_get(lh, ehnode);
        lh_put(lh, ehnode);
        RETURN(obj);
}
EXPORT_SYMBOL(lustre_hash_findadd_unique);
  
/**
 * Delete item @hnode from the lustre hash @lh using @key.  The @key
 * is required to ensure the correct hash bucket is locked since there
 * is no direct linkage from the item to the bucket.  The object
 * removed from the hash will be returned and obs->lh_put is called
 * on the removed object.
 */
void *
lustre_hash_del(lustre_hash_t *lh, void *key, struct hlist_node *hnode)
{
        lustre_hash_bucket_t *lhb;
        unsigned              i;
        void                 *obj;
        ENTRY;
  
        __lustre_hash_key_validate(lh, key, hnode);
  
        read_lock(&lh->lh_rwlock);
        i = lh_hash(lh, key, lh->lh_cur_mask);
        lhb = &lh->lh_buckets[i];
        LASSERT(i <= lh->lh_cur_mask);
        LASSERT(!hlist_unhashed(hnode));

        write_lock(&lhb->lhb_rwlock);
        obj = __lustre_hash_bucket_del(lh, lhb, hnode);
        write_unlock(&lhb->lhb_rwlock);
        read_unlock(&lh->lh_rwlock);
  
        RETURN(obj);
}
EXPORT_SYMBOL(lustre_hash_del);
  
/**
 * Delete item given @key in lustre hash @lh.  The first @key found in
 * the hash will be removed, if the key exists multiple times in the hash
 * @lh this function must be called once per key.  The removed object
 * will be returned and ops->lh_put is called on the removed object.
 */
void *
lustre_hash_del_key(lustre_hash_t *lh, void *key)
{
        struct hlist_node    *hnode;
        lustre_hash_bucket_t *lhb;
        unsigned              i;
        void                 *obj = NULL;
        ENTRY;
  
        read_lock(&lh->lh_rwlock);
        i = lh_hash(lh, key, lh->lh_cur_mask);
        lhb = &lh->lh_buckets[i];
        LASSERT(i <= lh->lh_cur_mask);

        write_lock(&lhb->lhb_rwlock);
        hnode = __lustre_hash_bucket_lookup(lh, lhb, key);
        if (hnode)
                obj = __lustre_hash_bucket_del(lh, lhb, hnode);

        write_unlock(&lhb->lhb_rwlock);
        read_unlock(&lh->lh_rwlock);
  
        RETURN(obj);
}
EXPORT_SYMBOL(lustre_hash_del_key);
  
/**
 * Lookup an item using @key in the lustre hash @lh and return it.
 * If the @key is found in the hash lh->lh_get() is called and the
 * matching objects is returned.  It is the callers responsibility
 * to call the counterpart ops->lh_put using the lh_put() macro
 * when when finished with the object.  If the @key was not found
 * in the hash @lh NULL is returned.
 */
void *
lustre_hash_lookup(lustre_hash_t *lh, void *key)
{
        struct hlist_node    *hnode;
        lustre_hash_bucket_t *lhb;
        unsigned              i;
        void                 *obj = NULL;
        ENTRY;
  
        read_lock(&lh->lh_rwlock);
        i = lh_hash(lh, key, lh->lh_cur_mask);
        lhb = &lh->lh_buckets[i];
        LASSERT(i <= lh->lh_cur_mask);

        read_lock(&lhb->lhb_rwlock);
        hnode = __lustre_hash_bucket_lookup(lh, lhb, key);
        if (hnode)
                obj = lh_get(lh, hnode);
  
        read_unlock(&lhb->lhb_rwlock);
        read_unlock(&lh->lh_rwlock);
  
        RETURN(obj);
}
EXPORT_SYMBOL(lustre_hash_lookup);
  
/**
 * For each item in the lustre hash @lh call the passed callback @func
 * and pass to it as an argument each hash item and the private @data.
 * Before each callback ops->lh_get will be called, and after each
 * callback ops->lh_put will be called.  Finally, during the callback
 * the bucket lock is held so the callback must never sleep.
 */
void
lustre_hash_for_each(lustre_hash_t *lh, lh_for_each_cb func, void *data)
{
        struct hlist_node    *hnode;
        lustre_hash_bucket_t *lhb;
        void                 *obj;
        int                   i;
        ENTRY;
  
        read_lock(&lh->lh_rwlock);
        lh_for_each_bucket(lh, lhb, i) {
                read_lock(&lhb->lhb_rwlock);
                hlist_for_each(hnode, &(lhb->lhb_head)) {
                        __lustre_hash_bucket_validate(lh, lhb, hnode);
                        obj = lh_get(lh, hnode);
                        func(obj, data);
                        (void)lh_put(lh, hnode);
                }
                read_unlock(&lhb->lhb_rwlock);
        }
        read_unlock(&lh->lh_rwlock);

        EXIT;
}
EXPORT_SYMBOL(lustre_hash_for_each);
  
/**
 * For each item in the lustre hash @lh call the passed callback @func
 * and pass to it as an argument each hash item and the private @data.
 * Before each callback ops->lh_get will be called, and after each
 * callback ops->lh_put will be called.  During the callback the
 * bucket lock will not be held will allows for the current item
 * to be removed from the hash during the callback.  However, care
 * should be taken to prevent other callers from operating on the
 * hash concurrently or list corruption may occur.
 */
void
lustre_hash_for_each_safe(lustre_hash_t *lh, lh_for_each_cb func, void *data)
{
        struct hlist_node    *hnode;
        struct hlist_node    *pos;
        lustre_hash_bucket_t *lhb;
        void                 *obj;
        int                   i;
        ENTRY;
  
        read_lock(&lh->lh_rwlock);
        lh_for_each_bucket(lh, lhb, i) {
                read_lock(&lhb->lhb_rwlock);
                hlist_for_each_safe(hnode, pos, &(lhb->lhb_head)) {
                        __lustre_hash_bucket_validate(lh, lhb, hnode);
                        obj = lh_get(lh, hnode);
                        read_unlock(&lhb->lhb_rwlock);
                        func(obj, data);
                        read_lock(&lhb->lhb_rwlock);
                        (void)lh_put(lh, hnode);
                }
                read_unlock(&lhb->lhb_rwlock);
        }
        read_unlock(&lh->lh_rwlock);
        EXIT;
}
EXPORT_SYMBOL(lustre_hash_for_each_safe);
  
/**
 * For each hash bucket in the lustre hash @lh call the passed callback
 * @func until all the hash buckets are empty.  The passed callback @func
 * or the previously registered callback lh->lh_put must remove the item
 * from the hash.  You may either use the lustre_hash_del() or hlist_del()
 * functions.  No rwlocks will be held during the callback @func it is
 * safe to sleep if needed.  This function will not terminate until the
 * hash is empty.  Note it is still possible to concurrently add new
 * items in to the hash.  It is the callers responsibility to ensure
 * the required locking is in place to prevent concurrent insertions.
 */
void
lustre_hash_for_each_empty(lustre_hash_t *lh, lh_for_each_cb func, void *data)
{
        struct hlist_node    *hnode;
        lustre_hash_bucket_t *lhb;
        void                 *obj;
        int                   i;
        ENTRY;
  
restart:
        read_lock(&lh->lh_rwlock);
        lh_for_each_bucket(lh, lhb, i) {
                write_lock(&lhb->lhb_rwlock);
                while (!hlist_empty(&lhb->lhb_head)) {
                        hnode =  lhb->lhb_head.first;
                        __lustre_hash_bucket_validate(lh, lhb, hnode);
                        obj = lh_get(lh, hnode);
                        write_unlock(&lhb->lhb_rwlock);
                        read_unlock(&lh->lh_rwlock);
                        func(obj, data);
                        (void)lh_put(lh, hnode);
                        goto restart;
                }
                write_unlock(&lhb->lhb_rwlock);
        }
        read_unlock(&lh->lh_rwlock);
        EXIT;
}
EXPORT_SYMBOL(lustre_hash_for_each_empty);

/*
 * For each item in the lustre hash @lh which matches the @key call
 * the passed callback @func and pass to it as an argument each hash
 * item and the private @data.  Before each callback ops->lh_get will
 * be called, and after each callback ops->lh_put will be called.
 * Finally, during the callback the bucket lock is held so the
 * callback must never sleep.
   */
void
lustre_hash_for_each_key(lustre_hash_t *lh, void *key,
                         lh_for_each_cb func, void *data)
{
        struct hlist_node    *hnode;
        lustre_hash_bucket_t *lhb;
        unsigned              i;
        ENTRY;
  
        read_lock(&lh->lh_rwlock);
        i = lh_hash(lh, key, lh->lh_cur_mask);
        lhb = &lh->lh_buckets[i];
        LASSERT(i <= lh->lh_cur_mask);
  
        read_lock(&lhb->lhb_rwlock);
        hlist_for_each(hnode, &(lhb->lhb_head)) {
                __lustre_hash_bucket_validate(lh, lhb, hnode);
  
                if (!lh_compare(lh, key, hnode))
                        continue;
  
                func(lh_get(lh, hnode), data);
                (void)lh_put(lh, hnode);
        }
  
        read_unlock(&lhb->lhb_rwlock);
        read_unlock(&lh->lh_rwlock);
  
        EXIT;
}
EXPORT_SYMBOL(lustre_hash_for_each_key);
  
/**
 * Rehash the lustre hash @lh to the given @bits.  This can be used
 * to grow the hash size when excessive chaining is detected, or to
 * shrink the hash when it is larger than needed.  When the LH_REHASH
 * flag is set in @lh the lustre hash may be dynamically rehashed
 * during addition or removal if the hash's theta value exceeds
 * either the lh->lh_min_theta or lh->max_theta values.  By default
 * these values are tuned to keep the chained hash depth small, and
 * this approach assumes a reasonably uniform hashing function.  The
 * theta thresholds for @lh are tunable via lustre_hash_set_theta().
 */
int
lustre_hash_rehash(lustre_hash_t *lh, int bits)
{
        struct hlist_node     *hnode;
        struct hlist_node     *pos;
        lustre_hash_bucket_t  *lh_buckets;
        lustre_hash_bucket_t  *rehash_buckets;
        lustre_hash_bucket_t  *lh_lhb;
        lustre_hash_bucket_t  *rehash_lhb;
        int                    i;
        int                    theta;
        int                    lh_mask;
        int                    lh_bits;
        int                    mask = (1 << bits) - 1;
        void                  *key;
        ENTRY;
  
        LASSERT(!in_interrupt());
        LASSERT(mask > 0);

        OBD_VMALLOC(rehash_buckets, sizeof(*rehash_buckets) << bits);
        if (!rehash_buckets)
                RETURN(-ENOMEM);
  
        for (i = 0; i <= mask; i++) {
                INIT_HLIST_HEAD(&rehash_buckets[i].lhb_head);
                rwlock_init(&rehash_buckets[i].lhb_rwlock);
                atomic_set(&rehash_buckets[i].lhb_count, 0);
        }
  
        write_lock(&lh->lh_rwlock);

        /* 
         * Early return for multiple concurrent racing callers,
         * ensure we only trigger the rehash if it is still needed. 
         */
        theta = __lustre_hash_theta(lh);
        if ((theta >= lh->lh_min_theta) && (theta <= lh->lh_max_theta)) {
                OBD_VFREE(rehash_buckets, sizeof(*rehash_buckets) << bits);
                write_unlock(&lh->lh_rwlock);
                RETURN(-EALREADY);
        }
  
        lh_bits = lh->lh_cur_bits;
        lh_buckets = lh->lh_buckets;
        lh_mask = (1 << lh_bits) - 1;
  
        lh->lh_cur_bits = bits;
        lh->lh_cur_mask = (1 << bits) - 1;
        lh->lh_buckets = rehash_buckets;
        atomic_inc(&lh->lh_rehash_count);

        for (i = 0; i <= lh_mask; i++) {
                lh_lhb = &lh_buckets[i];

                write_lock(&lh_lhb->lhb_rwlock);
                hlist_for_each_safe(hnode, pos, &(lh_lhb->lhb_head)) {
                        key = lh_key(lh, hnode);
                        LASSERT(key);

                        /* 
                         * Validate hnode is in the correct bucket.
                         */
                        if (unlikely(lh->lh_flags & LH_DEBUG))
                                LASSERT(lh_hash(lh, key, lh_mask) == i);

                        /* 
                         * Delete from old hash bucket.
                         */
                        hlist_del(hnode);
                        LASSERT(atomic_read(&lh_lhb->lhb_count) > 0);
                        atomic_dec(&lh_lhb->lhb_count);

                        /* 
                         * Add to rehash bucket, ops->lh_key must be defined. 
                         */
                        rehash_lhb = &rehash_buckets[lh_hash(lh, key, mask)];
                        hlist_add_head(hnode, &(rehash_lhb->lhb_head));
                        atomic_inc(&rehash_lhb->lhb_count);
                }
  
                LASSERT(hlist_empty(&(lh_lhb->lhb_head)));
                LASSERT(atomic_read(&lh_lhb->lhb_count) == 0);
                write_unlock(&lh_lhb->lhb_rwlock);
        }
  
        OBD_VFREE(lh_buckets, sizeof(*lh_buckets) << lh_bits);
        write_unlock(&lh->lh_rwlock);
  
        RETURN(0);
}
EXPORT_SYMBOL(lustre_hash_rehash);
  
/**
 * Rehash the object referenced by @hnode in the lustre hash @lh.  The
 * @old_key must be provided to locate the objects previous location
 * in the hash, and the @new_key will be used to reinsert the object.
 * Use this function instead of a lustre_hash_add() + lustre_hash_del()
 * combo when it is critical that there is no window in time where the
 * object is missing from the hash.  When an object is being rehashed
 * the registered lh_get() and lh_put() functions will not be called.
 */
void lustre_hash_rehash_key(lustre_hash_t *lh, void *old_key, void *new_key,
                            struct hlist_node *hnode)
{
        lustre_hash_bucket_t  *old_lhb;
        lustre_hash_bucket_t  *new_lhb;
        unsigned               i;
        int                    j;
        ENTRY;
  
        __lustre_hash_key_validate(lh, new_key, hnode);
        LASSERT(!hlist_unhashed(hnode));
  
        read_lock(&lh->lh_rwlock);
  
        i = lh_hash(lh, old_key, lh->lh_cur_mask);
        old_lhb = &lh->lh_buckets[i];
        LASSERT(i <= lh->lh_cur_mask);

        j = lh_hash(lh, new_key, lh->lh_cur_mask);
        new_lhb = &lh->lh_buckets[j];
        LASSERT(j <= lh->lh_cur_mask);

        write_lock(&old_lhb->lhb_rwlock);
        write_lock(&new_lhb->lhb_rwlock);

        /* 
         * Migrate item between hash buckets without calling
         * the lh_get() and lh_put() callback functions. 
         */
        hlist_del(hnode);
        LASSERT(atomic_read(&old_lhb->lhb_count) > 0);
        atomic_dec(&old_lhb->lhb_count);
        hlist_add_head(hnode, &(new_lhb->lhb_head));
        atomic_inc(&new_lhb->lhb_count);

        write_unlock(&new_lhb->lhb_rwlock);
        write_unlock(&old_lhb->lhb_rwlock);
        read_unlock(&lh->lh_rwlock);
  
        EXIT;
}
EXPORT_SYMBOL(lustre_hash_rehash_key);
  
int lustre_hash_debug_header(char *str, int size)
{
        return snprintf(str, size,
                 "%-36s%6s%6s%6s%6s%6s%6s%6s%7s%6s%s\n",
                 "name", "cur", "min", "max", "theta", "t-min", "t-max",
                 "flags", "rehash", "count", " distribution");
}
EXPORT_SYMBOL(lustre_hash_debug_header);

int lustre_hash_debug_str(lustre_hash_t *lh, char *str, int size)
{
        lustre_hash_bucket_t  *lhb;
        int                    theta;
        int                    i;
        int                    c = 0;
        int                    dist[8] = { 0, };

        if (str == NULL || size == 0)
                return 0;

        read_lock(&lh->lh_rwlock);
        theta = __lustre_hash_theta(lh);

        c += snprintf(str + c, size - c, "%-36s ", lh->lh_name);
        c += snprintf(str + c, size - c, "%5d ",  1 << lh->lh_cur_bits);
        c += snprintf(str + c, size - c, "%5d ",  1 << lh->lh_min_bits);
        c += snprintf(str + c, size - c, "%5d ",  1 << lh->lh_max_bits);
        c += snprintf(str + c, size - c, "%d.%03d ",
                      __lustre_hash_theta_int(theta),
                      __lustre_hash_theta_frac(theta));
        c += snprintf(str + c, size - c, "%d.%03d ",
                      __lustre_hash_theta_int(lh->lh_min_theta),
                      __lustre_hash_theta_frac(lh->lh_min_theta));
        c += snprintf(str + c, size - c, "%d.%03d ",
                      __lustre_hash_theta_int(lh->lh_max_theta),
                      __lustre_hash_theta_frac(lh->lh_max_theta));
        c += snprintf(str + c, size - c, " 0x%02x ", lh->lh_flags);
        c += snprintf(str + c, size - c, "%6d ",
                      atomic_read(&lh->lh_rehash_count));
        c += snprintf(str + c, size - c, "%5d ",
                      atomic_read(&lh->lh_count));

        /* 
         * The distribution is a summary of the chained hash depth in
         * each of the lustre hash buckets.  Each buckets lhb_count is
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
        lh_for_each_bucket(lh, lhb, i)
                dist[min(__fls(atomic_read(&lhb->lhb_count)/max(theta,1)),7)]++;

        for (i = 0; i < 8; i++)
                c += snprintf(str + c, size - c, "%d%c",  dist[i],
                              (i == 7) ? '\n' : '/');
  
        read_unlock(&lh->lh_rwlock);
  
        return c;
}
EXPORT_SYMBOL(lustre_hash_debug_str);
