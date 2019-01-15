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

#ifndef __LIBCFS_LINUX_HASH_H__
#define __LIBCFS_LINUX_HASH_H__

#include <linux/dcache.h>

u64 cfs_hashlen_string(const void *salt, const char *name);

#ifndef hashlen_hash
#define hashlen_hash(hashlen) ((u32)(hashlen))
#endif

#ifndef HAVE_STRINGHASH
#ifndef hashlen_create
#define hashlen_create(hash, len) ((u64)(len)<<32 | (u32)(hash))
#endif
#endif /* !HAVE_STRINGHASH */

#ifdef HAVE_LINUX_RHASHTABLE_H
#include <linux/rhashtable.h>

#ifndef HAVE_RHLTABLE
struct rhlist_head {
	struct rhash_head		rhead;
	struct rhlist_head __rcu	*next;
};

struct rhltable {
	struct rhashtable ht;
};

#define rhl_for_each_entry_rcu(tpos, pos, list, member)                 \
	for (pos = list; pos && rht_entry(tpos, pos, member);           \
		pos = rcu_dereference_raw(pos->next))

static inline int rhltable_init(struct rhltable *hlt,
				const struct rhashtable_params *params)
{
	return rhashtable_init(&hlt->ht, params);
}

static inline struct rhlist_head *rhltable_lookup(
	struct rhltable *hlt, const void *key,
	const struct rhashtable_params params)
{
	struct rhashtable *ht = &hlt->ht;
	struct rhashtable_compare_arg arg = {
		.ht = ht,
		.key = key,
	};
	struct bucket_table *tbl;
	struct rhash_head *he;
	unsigned int hash;

	tbl = rht_dereference_rcu(ht->tbl, ht);
restart:
	hash = rht_key_hashfn(ht, tbl, key, params);
	rht_for_each_rcu(he, tbl, hash) {
		if (params.obj_cmpfn ?
		    params.obj_cmpfn(&arg, rht_obj(ht, he)) :
		    rhashtable_compare(&arg, rht_obj(ht, he)))
			continue;
		return he ? container_of(he, struct rhlist_head, rhead) : NULL;
	}

	/* Ensure we see any new tables. */
	smp_rmb();

	tbl = rht_dereference_rcu(tbl->future_tbl, ht);
	if (unlikely(tbl))
		goto restart;

	return NULL;
}

static inline int rhltable_insert_key(
	struct rhltable *hlt, const void *key, struct rhlist_head *list,
	const struct rhashtable_params params)
{
#ifdef HAVE_HASHTABLE_INSERT_FAST_RETURN_INT
	return __rhashtable_insert_fast(&hlt->ht, key, &list->rhead,
					params);
#else
	return PTR_ERR(__rhashtable_insert_fast(&hlt->ht, key, &list->rhead,
						params));
#endif
}

static inline int rhltable_remove(
	struct rhltable *hlt, struct rhlist_head *list,
	const struct rhashtable_params params)
{
	return rhashtable_remove_fast(&hlt->ht, &list->rhead, params);
}

static inline void rhltable_free_and_destroy(struct rhltable *hlt,
					     void (*free_fn)(void *ptr,
							     void *arg),
					     void *arg)
{
	rhashtable_free_and_destroy(&hlt->ht, free_fn, arg);
}

static inline void rhltable_destroy(struct rhltable *hlt)
{
	rhltable_free_and_destroy(hlt, NULL, NULL);
}

static inline void rhltable_walk_enter(struct rhltable *hlt,
				       struct rhashtable_iter *iter)
{
	rhashtable_walk_init(&hlt->ht, iter);
}
#endif /* !HAVE_RHLTABLE */

#ifdef HAVE_BROKEN_HASH_64

#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

static inline u32 cfs_hash_32(u32 val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return (val * GOLDEN_RATIO_32) >> (32 - bits);
}

static __always_inline u32 cfs_hash_64(u64 val, unsigned int bits)
{
#if BITS_PER_LONG == 64
	/* 64x64-bit multiply is efficient on all 64-bit processors */
	return val * GOLDEN_RATIO_64 >> (64 - bits);
#else
	/* Hash 64 bits using only 32x32-bit multiply. */
	return cfs_hash_32(((u32)val ^ ((val >> 32) * GOLDEN_RATIO_32)), bits);
#endif
}
#else

#define cfs_hash_32	hash_32
#define cfs_hash_64	hash_64

#endif /* HAVE_BROKEN_HASH_64 */

#ifndef HAVE_RHASHTABLE_LOOKUP_GET_INSERT_FAST
/**
 * rhashtable_lookup_get_insert_fast - lookup and insert object into hash table
 * @ht:         hash table
 * @obj:        pointer to hash head inside object
 * @params:     hash table parameters
 *
 * Just like rhashtable_lookup_insert_fast(), but this function returns the
 * object if it exists, NULL if it did not and the insertion was successful,
 * and an ERR_PTR otherwise.
 */
static inline void *rhashtable_lookup_get_insert_fast(
	struct rhashtable *ht, struct rhash_head *obj,
	const struct rhashtable_params params)
{
	const char *key;
	void *ret;
	int rc;

	rc = rhashtable_lookup_insert_fast(ht, obj, params);
	switch (rc) {
	case -EEXIST:
		key = rht_obj(ht, obj);
		ret = rhashtable_lookup_fast(ht, key, params);
		break;
	case 0:
		ret = NULL;
		break;
	default:
		ret = ERR_PTR(rc);
		break;
	}
	return ret;
}
#endif /* !HAVE_RHASHTABLE_LOOKUP_GET_INSERT_FAST */

#ifndef HAVE_RHASHTABLE_LOOKUP
/*
 * The function rhashtable_lookup() and rhashtable_lookup_fast()
 * are almost the same except rhashtable_lookup() doesn't
 * take the RCU read lock. Since this is the case and only
 * SLES12 SP3 lacks rhashtable_lookup() just duplicate the
 * SLES12 SP3 rhashtable_lookup_fast() minus the RCU read lock.
 */
static inline void *rhashtable_lookup(
	struct rhashtable *ht, const void *key,
	const struct rhashtable_params params)
{
	struct rhashtable_compare_arg arg = {
		.ht = ht,
		.key = key,
	};
	const struct bucket_table *tbl;
	struct rhash_head *he;
	unsigned int hash;

	tbl = rht_dereference_rcu(ht->tbl, ht);
restart:
	hash = rht_key_hashfn(ht, tbl, key, params);
	rht_for_each_rcu(he, tbl, hash) {
		if (params.obj_cmpfn ?
		    params.obj_cmpfn(&arg, rht_obj(ht, he)) :
		    rhashtable_compare(&arg, rht_obj(ht, he)))
			continue;
		return rht_obj(ht, he);
	}

	/* Ensure we see any new tables. */
	smp_rmb();

	tbl = rht_dereference_rcu(tbl->future_tbl, ht);
	if (unlikely(tbl))
		goto restart;

	return NULL;
}
#endif /* !HAVE_RHASHTABLE_LOOKUP */
#else
#define rhashtable_init(ht, param) 0
#define rhashtable_destroy(ht) do {} while (0)
#endif /* HAVE_LINUX_RHASHTABLE_H */

#endif /* __LIBCFS_LINUX_HASH_H__ */
