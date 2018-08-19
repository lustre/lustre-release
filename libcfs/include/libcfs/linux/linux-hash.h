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

#endif /* __LIBCFS_LINUX_MISC_H__ */
