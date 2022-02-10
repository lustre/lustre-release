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
 * Copyright (c) 2023, Whamcloud.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 */

#ifndef _UPCALL_CACHE_INTERNAL_H
#define _UPCALL_CACHE_INTERNAL_H

#include <upcall_cache.h>

/* protected by cache lock */
static void free_entry(struct upcall_cache *cache,
		       struct upcall_cache_entry *entry)
{
	if (cache->uc_ops->free_entry)
		cache->uc_ops->free_entry(cache, entry);

	list_del(&entry->ue_hash);
	CDEBUG(D_OTHER, "destroy cache entry %p for key %llu\n",
	       entry, entry->ue_key);
	LIBCFS_FREE(entry, sizeof(*entry));
}

static inline void get_entry(struct upcall_cache_entry *entry)
{
	atomic_inc(&entry->ue_refcount);
}

static inline void put_entry(struct upcall_cache *cache,
			     struct upcall_cache_entry *entry)
{
	if (atomic_dec_and_test(&entry->ue_refcount) &&
	    (UC_CACHE_IS_INVALID(entry) || UC_CACHE_IS_EXPIRED(entry))) {
		free_entry(cache, entry);
	}
}

#ifdef HAVE_SERVER_SUPPORT
void refresh_entry_internal(struct upcall_cache *cache,
			    struct upcall_cache_entry *entry,
			    __u32 fsgid, struct group_info **ginfo);
int upcall_cache_get_entry_internal(struct upcall_cache *cache,
				    struct upcall_cache_entry *entry,
				    void *args, gid_t *fsgid,
				    struct group_info **ginfo);
#else /* HAVE_SERVER_SUPPORT */
static inline
void refresh_entry_internal(struct upcall_cache *cache,
			    struct upcall_cache_entry *entry,
			    __u32 fsgid, struct group_info **ginfo)
{ }
static inline int upcall_cache_get_entry_internal(struct upcall_cache *cache,
					       struct upcall_cache_entry *entry,
					       void *args, gid_t *fsgid,
					       struct group_info **ginfo)
{
	return -EOPNOTSUPP;
}
#endif

#endif /* _UPCALL_CACHE_INTERNAL_H */
