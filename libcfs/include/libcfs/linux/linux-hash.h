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
#include <linux/rhashtable.h>

u64 cfs_hashlen_string(const void *salt, const char *name);

#ifndef hashlen_hash
#define hashlen_hash(hashlen) ((u32)(hashlen))
#endif

#ifndef HAVE_STRINGHASH
#ifndef hashlen_create
#define hashlen_create(hash, len) ((u64)(len)<<32 | (u32)(hash))
#endif
#endif /* !HAVE_STRINGHASH */

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

#endif /* __LIBCFS_LINUX_HASH_H__ */
