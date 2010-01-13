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
 * libcfs/include/libcfs/libcfs_hash.h
 *
 * Hashing routines
 *
 */

#ifndef __LIBCFS_HASH_H__
#define __LIBCFS_HASH_H__
/*
 * Knuth recommends primes in approximately golden ratio to the maximum
 * integer representable by a machine word for multiplicative hashing.
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * These primes are chosen to be bit-sparse, that is operations on
 * them can use shifts and additions instead of multiplications for
 * machines where multiplications are slow.
 */
/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define CFS_GOLDEN_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define CFS_GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001ULL

/*
 * Ideally we would use HAVE_HASH_LONG for this, but on linux we configure
 * the linux kernel and user space at the same time, so we need to differentiate
 * between them explicitely. If this is not needed on other architectures, then
 * we'll need to move the functions to archi specific headers.
 */

#if (defined __linux__ && defined __KERNEL__)
#include <linux/hash.h>

#define cfs_hash_long(val, bits)    hash_long(val, bits)
#else
/* Fast hashing routine for a long.
   (C) 2002 William Lee Irwin III, IBM */

#if BITS_PER_LONG == 32
/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define CFS_GOLDEN_RATIO_PRIME          CFS_GOLDEN_RATIO_PRIME_32
#elif BITS_PER_LONG == 64
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define CFS_GOLDEN_RATIO_PRIME          CFS_GOLDEN_RATIO_PRIME_64
#else
#error Define CFS_GOLDEN_RATIO_PRIME for your wordsize.
#endif

static inline unsigned long cfs_hash_long(unsigned long val, unsigned int bits)
{
	unsigned long hash = val;

#if BITS_PER_LONG == 64
	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	unsigned long n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;
#else
	/* On some cpus multiply is faster, on others gcc will do shifts */
	hash *= CFS_GOLDEN_RATIO_PRIME;
#endif

	/* High bits are more random, so use them. */
	return hash >> (BITS_PER_LONG - bits);
}
#if 0
static inline unsigned long hash_ptr(void *ptr, unsigned int bits)
{
	return cfs_hash_long((unsigned long)ptr, bits);
}
#endif

/* !(__linux__ && __KERNEL__) */
#endif

struct cfs_hash_ops;

typedef struct cfs_hash_bucket {
        cfs_hlist_head_t            hsb_head;       /* entries list */
        cfs_atomic_t                hsb_count;      /* current entries */
        cfs_rwlock_t                hsb_rwlock;     /* cfs_hash_bucket */
} cfs_hash_bucket_t;

#define CFS_MAX_HASH_NAME 16

typedef struct cfs_hash {
        int                         hs_cur_bits;    /* current hash bits */
        int                         hs_cur_mask;    /* current hash mask */
        int                         hs_min_bits;    /* min hash bits */
        int                         hs_max_bits;    /* max hash bits */
        int                         hs_min_theta;   /* resize min threshold */
        int                         hs_max_theta;   /* resize max threshold */
        int                         hs_flags;       /* hash flags */
        cfs_atomic_t                hs_count;       /* current entries */
        cfs_atomic_t                hs_rehash_count;/* resize count */
        struct cfs_hash_bucket    **hs_buckets;     /* hash buckets */
        struct cfs_hash_ops        *hs_ops;         /* hash operations */
        cfs_rwlock_t                hs_rwlock;      /* cfs_hash */
        char                        hs_name[CFS_MAX_HASH_NAME];
} cfs_hash_t;

typedef struct cfs_hash_ops {
        unsigned (*hs_hash)(cfs_hash_t *hs, void *key, unsigned mask);
        void *   (*hs_key)(cfs_hlist_node_t *hnode);
        int      (*hs_compare)(void *key, cfs_hlist_node_t *hnode);
        void *   (*hs_get)(cfs_hlist_node_t *hnode);
        void *   (*hs_put)(cfs_hlist_node_t *hnode);
        void     (*hs_exit)(cfs_hlist_node_t *hnode);
} cfs_hash_ops_t;

#define CFS_HASH_DEBUG          0x0001  /* Enable expensive debug checks */
#define CFS_HASH_REHASH         0x0002  /* Enable dynamic hash resizing */

#define CFS_HO(hs)             (hs)->hs_ops
#define CFS_HOP(hs, op)        (hs)->hs_ops->hs_ ## op

static inline unsigned
cfs_hash_id(cfs_hash_t *hs, void *key, unsigned mask)
{
        LASSERT(hs);
        LASSERT(CFS_HO(hs));
        LASSERT(CFS_HOP(hs, hash));

        return CFS_HOP(hs, hash)(hs, key, mask);
}

static inline void *
cfs_hash_key(cfs_hash_t *hs, cfs_hlist_node_t *hnode)
{
        LASSERT(hs);
        LASSERT(hnode);
        LASSERT(CFS_HO(hs));

        if (CFS_HOP(hs, key))
                return CFS_HOP(hs, key)(hnode);

        return NULL;
}

/* Returns 1 on a match,
 * XXX: This would be better if it returned, -1, 0, or 1 for
 *      <, =, > respectivly.  It could then be used to implement
 *      a CFS_HASH_SORT feature flags which could keep each hash
 *      bucket in order.  This would increase insertion times
 *      but could reduce lookup times for deep chains.  Ideally,
 *      the rehash should keep chain depth short but if that
 *      ends up not being the case this would be a nice feature.
 */
static inline int
cfs_hash_compare(cfs_hash_t *hs, void *key, cfs_hlist_node_t *hnode)
{
        LASSERT(hs);
        LASSERT(hnode);
        LASSERT(CFS_HO(hs));

        if (CFS_HOP(hs, compare))
                return CFS_HOP(hs, compare)(key, hnode);

        return -EOPNOTSUPP;
}

static inline void *
cfs_hash_get(cfs_hash_t *hs, cfs_hlist_node_t *hnode)
{
        LASSERT(hs);
        LASSERT(hnode);
        LASSERT(CFS_HO(hs));

        if (CFS_HOP(hs, get))
                return CFS_HOP(hs, get)(hnode);

        return NULL;
}

static inline void *
cfs_hash_put(cfs_hash_t *hs, cfs_hlist_node_t *hnode)
{
        LASSERT(hs);
        LASSERT(hnode);
        LASSERT(CFS_HO(hs));

        if (CFS_HOP(hs, put))
                return CFS_HOP(hs, put)(hnode);

        return NULL;
}

static inline void
cfs_hash_exit(cfs_hash_t *hs, cfs_hlist_node_t *hnode)
{
        LASSERT(hs);
        LASSERT(hnode);
        LASSERT(CFS_HO(hs));

        if (CFS_HOP(hs, exit))
                return CFS_HOP(hs, exit)(hnode);
}

/* Validate hnode references the correct key */
static inline void
__cfs_hash_key_validate(cfs_hash_t *hs, void *key,
                        cfs_hlist_node_t *hnode)
{
        if (unlikely(hs->hs_flags & CFS_HASH_DEBUG))
                LASSERT(cfs_hash_compare(hs, key, hnode) > 0);
}

/* Validate hnode is in the correct bucket */
static inline void
__cfs_hash_bucket_validate(cfs_hash_t *hs, cfs_hash_bucket_t *hsb,
                           cfs_hlist_node_t *hnode)
{
        unsigned i;

        if (unlikely(hs->hs_flags & CFS_HASH_DEBUG)) {
                i = cfs_hash_id(hs, cfs_hash_key(hs, hnode), hs->hs_cur_mask);
                LASSERT(hs->hs_buckets[i] == hsb);
        }
}

static inline cfs_hlist_node_t *
__cfs_hash_bucket_lookup(cfs_hash_t *hs,
                         cfs_hash_bucket_t *hsb, void *key)
{
        cfs_hlist_node_t *hnode;

        cfs_hlist_for_each(hnode, &hsb->hsb_head)
                if (cfs_hash_compare(hs, key, hnode) > 0)
                        return hnode;

        return NULL;
}

static inline void *
__cfs_hash_bucket_add(cfs_hash_t *hs,
                      cfs_hash_bucket_t *hsb,
                      cfs_hlist_node_t *hnode)
{
        cfs_hlist_add_head(hnode, &(hsb->hsb_head));
        cfs_atomic_inc(&hsb->hsb_count);
        cfs_atomic_inc(&hs->hs_count);

        return cfs_hash_get(hs, hnode);
}

static inline void *
__cfs_hash_bucket_del(cfs_hash_t *hs,
                      cfs_hash_bucket_t *hsb,
                      cfs_hlist_node_t *hnode)
{
        cfs_hlist_del_init(hnode);
        LASSERT(cfs_atomic_read(&hsb->hsb_count) > 0);
        cfs_atomic_dec(&hsb->hsb_count);
        LASSERT(cfs_atomic_read(&hs->hs_count) > 0);
        cfs_atomic_dec(&hs->hs_count);

        return cfs_hash_put(hs, hnode);
}

/* Hash init/cleanup functions */
cfs_hash_t *cfs_hash_create(char *name, unsigned int cur_bits,
                            unsigned int max_bits,
                            cfs_hash_ops_t *ops, int flags);
void cfs_hash_destroy(cfs_hash_t *hs);

/* Hash addition functions */
void cfs_hash_add(cfs_hash_t *hs, void *key,
                  cfs_hlist_node_t *hnode);
int cfs_hash_add_unique(cfs_hash_t *hs, void *key,
                        cfs_hlist_node_t *hnode);
void *cfs_hash_findadd_unique(cfs_hash_t *hs, void *key,
                              cfs_hlist_node_t *hnode);

/* Hash deletion functions */
void *cfs_hash_del(cfs_hash_t *hs, void *key, cfs_hlist_node_t *hnode);
void *cfs_hash_del_key(cfs_hash_t *hs, void *key);

/* Hash lookup/for_each functions */
void *cfs_hash_lookup(cfs_hash_t *hs, void *key);
typedef void (*cfs_hash_for_each_cb_t)(void *obj, void *data);
void cfs_hash_for_each(cfs_hash_t *hs, cfs_hash_for_each_cb_t, void *data);
void cfs_hash_for_each_safe(cfs_hash_t *hs, cfs_hash_for_each_cb_t, void *data);
void cfs_hash_for_each_empty(cfs_hash_t *hs, cfs_hash_for_each_cb_t, void *data);
void cfs_hash_for_each_key(cfs_hash_t *hs, void *key,
                           cfs_hash_for_each_cb_t, void *data);

/*
 * Rehash - Theta is calculated to be the average chained
 * hash depth assuming a perfectly uniform hash funcion.
 */
int cfs_hash_rehash(cfs_hash_t *hs, int bits);
void cfs_hash_rehash_key(cfs_hash_t *hs, void *old_key,
                         void *new_key, cfs_hlist_node_t *hnode);


#define CFS_HASH_THETA_BITS  10

/* Return integer component of theta */
static inline int __cfs_hash_theta_int(int theta)
{
        return (theta >> CFS_HASH_THETA_BITS);
}

/* Return a fractional value between 0 and 999 */
static inline int __cfs_hash_theta_frac(int theta)
{
        return ((theta * 1000) >> CFS_HASH_THETA_BITS) -
               (__cfs_hash_theta_int(theta) * 1000);
}

static inline int __cfs_hash_theta(cfs_hash_t *hs)
{
        return (cfs_atomic_read(&hs->hs_count) <<
                CFS_HASH_THETA_BITS) >> hs->hs_cur_bits;
}

static inline void __cfs_hash_set_theta(cfs_hash_t *hs, int min, int max)
{
        LASSERT(min < max);
        hs->hs_min_theta = min;
        hs->hs_max_theta = max;
}

/* Generic debug formatting routines mainly for proc handler */
int cfs_hash_debug_header(char *str, int size);
int cfs_hash_debug_str(cfs_hash_t *hs, char *str, int size);

/*
 * Generic djb2 hash algorithm for character arrays.
 */
static inline unsigned
cfs_hash_djb2_hash(void *key, size_t size, unsigned mask)
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
cfs_hash_u32_hash(__u32 key, unsigned mask)
{
        return ((key * CFS_GOLDEN_RATIO_PRIME_32) & mask);
}

/*
 * Generic u64 hash algorithm.
 */
static inline unsigned
cfs_hash_u64_hash(__u64 key, unsigned mask)
{
        return ((unsigned)(key * CFS_GOLDEN_RATIO_PRIME_64) & mask);
}

#define cfs_hash_for_each_bucket(hs, hsb, pos)   \
        for (pos = 0;                            \
             pos <= hs->hs_cur_mask &&           \
             (hsb = hs->hs_buckets[pos]);       \
             pos++)

#define cfs_hash_for_each_bucket_restart(hs, hsb, pos)  \
        for (/* pos=0 done once by caller */;           \
             pos <= hs->hs_cur_mask &&                  \
             (hsb = hs->hs_buckets[pos]);              \
             pos++)
/* !__LIBCFS__HASH_H__ */
#endif
