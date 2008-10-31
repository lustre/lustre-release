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
 */

#ifndef __CLASS_HASH_H
#define __CLASS_HASH_H

#include <lustre_lib.h>

struct lustre_hash_ops;

typedef struct lustre_hash_bucket {
        struct hlist_head           lhb_head;       /* entries list */
        atomic_t                    lhb_count;      /* current entries */
        rwlock_t                    lhb_rwlock;     /* lustre_hash_bucket */
} lustre_hash_bucket_t;

#define LUSTRE_MAX_HASH_NAME 16

typedef struct lustre_hash {
        int                         lh_cur_size;    /* current hash size */
        int                         lh_min_size;    /* min hash size */
        int                         lh_max_size;    /* max hash size */
        int                         lh_min_theta;   /* resize min threshold */
        int                         lh_max_theta;   /* resize max threshold */
        int                         lh_flags;       /* hash flags */
        atomic_t                    lh_count;       /* current entries */
        atomic_t                    lh_rehash_count;/* resize count */
        struct lustre_hash_bucket  *lh_buckets;     /* hash buckets */
        struct lustre_hash_ops     *lh_ops;         /* hash operations */
        rwlock_t                    lh_rwlock;      /* lustre_hash */
        char                        lh_name[LUSTRE_MAX_HASH_NAME];
} lustre_hash_t;

typedef struct lustre_hash_ops {
        unsigned (*lh_hash)(lustre_hash_t *lh, void *key, unsigned mask);
        void *   (*lh_key)(struct hlist_node *hnode);
        int      (*lh_compare)(void *key, struct hlist_node *hnode);
        void *   (*lh_get)(struct hlist_node *hnode);
        void *   (*lh_put)(struct hlist_node *hnode);
        void     (*lh_exit)(struct hlist_node *hnode);
} lustre_hash_ops_t;

#define LH_DEBUG        0x0001          /* Enable expensive debug checks */
#define LH_REHASH       0x0002          /* Enable dynamic hash resizing */

#define LHO(lh)         (lh)->lh_ops
#define LHP(lh, op)     (lh)->lh_ops->lh_ ## op

static inline unsigned
lh_hash(lustre_hash_t *lh, void *key, unsigned mask)
{
        LASSERT(lh);
        LASSERT(LHO(lh));

        if (LHP(lh, hash))
                return LHP(lh, hash)(lh, key, mask);

        return -EOPNOTSUPP;
}

static inline void *
lh_key(lustre_hash_t *lh, struct hlist_node *hnode)
{
        LASSERT(lh);
        LASSERT(hnode);
        LASSERT(LHO(lh));

        if (LHP(lh, key))
                return LHP(lh, key)(hnode);

        return NULL;
}

/* Returns 1 on a match,
 * XXX: This would be better if it returned, -1, 0, or 1 for
 *      <, =, > respectivly.  It could then be used to implement
 *      a LH_SORT feature flags which could keep each lustre hash
 *      bucket in order.  This would increase insertion times
 *      but could reduce lookup times for deep chains.  Ideally,
 *      the rehash should keep chain depth short but if that
 *      ends up not being the case this would be a nice feature.
 */
static inline int
lh_compare(lustre_hash_t *lh, void *key, struct hlist_node *hnode)
{
        LASSERT(lh);
        LASSERT(hnode);
        LASSERT(LHO(lh));

        if (LHP(lh, compare))
                return LHP(lh, compare)(key, hnode);

        return -EOPNOTSUPP;
}

static inline void *
lh_get(lustre_hash_t *lh, struct hlist_node *hnode)
{
        LASSERT(lh);
        LASSERT(hnode);
        LASSERT(LHO(lh));

        if (LHP(lh, get))
                return LHP(lh, get)(hnode);

        return NULL;
}

static inline void *
lh_put(lustre_hash_t *lh, struct hlist_node *hnode)
{
        LASSERT(lh);
        LASSERT(hnode);
        LASSERT(LHO(lh));

        if (LHP(lh, put))
                return LHP(lh, put)(hnode);

        return NULL;
}

static inline void
lh_exit(lustre_hash_t *lh, struct hlist_node *hnode)
{
        LASSERT(lh);
        LASSERT(hnode);
        LASSERT(LHO(lh));

        if (LHP(lh, exit))
                return LHP(lh, exit)(hnode);
}

/* Validate hnode references the correct key */
static inline void
__lustre_hash_key_validate(lustre_hash_t *lh, void *key,
                           struct hlist_node *hnode)
{
        if (unlikely(lh->lh_flags & LH_DEBUG))
                LASSERT(lh_compare(lh, key, hnode));
}

/* Validate hnode is in the correct bucket */
static inline void
__lustre_hash_bucket_validate(lustre_hash_t *lh, lustre_hash_bucket_t *lhb,
                              struct hlist_node *hnode)
{
        unsigned i;

        if (unlikely(lh->lh_flags & LH_DEBUG)) {
                i = lh_hash(lh, lh_key(lh, hnode), lh->lh_cur_size - 1);
                LASSERT(&lh->lh_buckets[i] == lhb);
        }
}

static inline struct hlist_node *
__lustre_hash_bucket_lookup(lustre_hash_t *lh,
                            lustre_hash_bucket_t *lhb, void *key)
{
        struct hlist_node *hnode;

        hlist_for_each(hnode, &lhb->lhb_head)
                if (lh_compare(lh, key, hnode))
                        return hnode;

        return NULL;
}

static inline void *
__lustre_hash_bucket_add(lustre_hash_t *lh,
                         lustre_hash_bucket_t *lhb,
                         struct hlist_node *hnode)
{
        hlist_add_head(hnode, &(lhb->lhb_head));
        atomic_inc(&lhb->lhb_count);
        atomic_inc(&lh->lh_count);

        return lh_get(lh, hnode);
}

static inline void *
__lustre_hash_bucket_del(lustre_hash_t *lh,
                         lustre_hash_bucket_t *lhb,
                         struct hlist_node *hnode)
{
        hlist_del_init(hnode);
        LASSERT(atomic_read(&lhb->lhb_count) > 0);
        atomic_dec(&lhb->lhb_count);
        LASSERT(atomic_read(&lh->lh_count) > 0);
        atomic_dec(&lh->lh_count);

        return lh_put(lh, hnode);
}

/* Hash init/cleanup functions */
lustre_hash_t *lustre_hash_init(char *name, unsigned int cur_size, 
                                unsigned int max_size,
                                lustre_hash_ops_t *ops, int flags);
void lustre_hash_exit(lustre_hash_t *lh);

/* Hash addition functions */
void lustre_hash_add(lustre_hash_t *lh, void *key,
                     struct hlist_node *hnode);
int  lustre_hash_add_unique(lustre_hash_t *lh, void *key,
                            struct hlist_node *hnode);
void *lustre_hash_findadd_unique(lustre_hash_t *lh, void *key,
                                 struct hlist_node *hnode);

/* Hash deletion functions */
void *lustre_hash_del(lustre_hash_t *lh, void *key, struct hlist_node *hnode);
void *lustre_hash_del_key(lustre_hash_t *lh, void *key);

/* Hash lookup/for_each functions */
void *lustre_hash_lookup(lustre_hash_t *lh, void *key);
typedef void (*lh_for_each_cb)(void *obj, void *data);
void lustre_hash_for_each(lustre_hash_t *lh, lh_for_each_cb, void *data);
void lustre_hash_for_each_safe(lustre_hash_t *lh, lh_for_each_cb, void *data);
void lustre_hash_for_each_empty(lustre_hash_t *lh, lh_for_each_cb, void *data);
void lustre_hash_for_each_key(lustre_hash_t *lh, void *key,
                              lh_for_each_cb, void *data);

/* Rehash - Theta is calculated to be the average chained
 * hash depth assuming a perfectly uniform hash funcion. */
int lustre_hash_rehash(lustre_hash_t *lh, int size);
void lustre_hash_rehash_key(lustre_hash_t *lh, void *old_key,
                            void *new_key, struct hlist_node *hnode);


static inline int
__lustre_hash_theta(lustre_hash_t *lh)
{
        return ((atomic_read(&lh->lh_count) * 1000) / lh->lh_cur_size);
}

static inline void
__lustre_hash_set_theta(lustre_hash_t *lh, int min, int max)
{
        LASSERT(min < max);
        lh->lh_min_theta = min;
        lh->lh_min_theta = max;
}

/* Generic debug formatting routines mainly for proc handler */
int lustre_hash_debug_header(char *str, int size);
int lustre_hash_debug_str(lustre_hash_t *lh, char *str, int size);

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define CFS_GOLDEN_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define CFS_GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001ULL

/*
 * Generic djb2 hash algorithm for character arrays.
 */
static inline unsigned
lh_djb2_hash(void *key, size_t size, unsigned mask)
{
        unsigned i, hash = 5381;

        LASSERT(key != NULL);

        for (i = 0; i < size; i++)
                hash = hash * 33 + ((char *)key)[i];

        return (hash & mask);
}

/*
 * Generic u32 hash algorithm.
 */
static inline unsigned
lh_u32_hash(__u32 key, unsigned mask)
{
        return ((key * CFS_GOLDEN_RATIO_PRIME_32) & mask);
}

/*
 * Generic u64 hash algorithm.
 */
static inline unsigned
lh_u64_hash(__u64 key, unsigned mask)
{
        return ((unsigned)(key * CFS_GOLDEN_RATIO_PRIME_64) & mask);
}

#define lh_for_each_bucket(lh, lhb, pos)         \
        for (pos = 0;                            \
             pos < lh->lh_cur_size &&            \
             ({ lhb = &lh->lh_buckets[i]; 1; }); \
             pos++)

#endif /* __CLASS_HASH_H */
