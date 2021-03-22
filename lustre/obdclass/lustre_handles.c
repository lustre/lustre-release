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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/lustre_handles.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/random.h>

#include <obd_support.h>
#include <lustre_handles.h>
#include <lustre_lib.h>


static __u64 handle_base;
#define HANDLE_INCR 7
static DEFINE_SPINLOCK(handle_base_lock);

static struct handle_bucket {
	spinlock_t lock;
	struct hlist_head	head;
} *handle_hash;

#define HANDLE_HASH_SIZE (1 << 16)
#define HANDLE_HASH_MASK (HANDLE_HASH_SIZE - 1)

/*
 * Generate a unique 64bit cookie (hash) for a handle and insert it into
 * global (per-node) hash-table.
 */
void class_handle_hash(struct portals_handle *h, const char *owner)
{
	struct handle_bucket *bucket;

	ENTRY;

	LASSERT(h != NULL);
	LASSERT(hlist_unhashed(&h->h_link));

	/*
	 * This is fast, but simplistic cookie generation algorithm, it will
	 * need a re-do at some point in the future for security.
	 */
	spin_lock(&handle_base_lock);
	handle_base += HANDLE_INCR;

	if (unlikely(handle_base == 0)) {
		/*
		 * Cookie of zero is "dangerous", because in many places it's
		 * assumed that 0 means "unassigned" handle, not bound to any
		 * object.
		 */
		CWARN("The universe has been exhausted: cookie wrap-around.\n");
		handle_base += HANDLE_INCR;
	}
	h->h_cookie = handle_base;
	spin_unlock(&handle_base_lock);

	h->h_owner = owner;

	bucket = &handle_hash[h->h_cookie & HANDLE_HASH_MASK];
	spin_lock(&bucket->lock);
	hlist_add_head_rcu(&h->h_link, &bucket->head);
	spin_unlock(&bucket->lock);

	CDEBUG(D_INFO, "added object %p with handle %#llx to hash\n",
	       h, h->h_cookie);
	EXIT;
}
EXPORT_SYMBOL(class_handle_hash);

static void class_handle_unhash_nolock(struct portals_handle *h)
{
	if (hlist_unhashed(&h->h_link)) {
		CERROR("removing an already-removed handle (%#llx)\n",
		       h->h_cookie);
		return;
	}

	CDEBUG(D_INFO, "removing object %p with handle %#llx from hash\n",
	       h, h->h_cookie);

	hlist_del_init_rcu(&h->h_link);
}

void class_handle_unhash(struct portals_handle *h)
{
	struct handle_bucket *bucket;
	bucket = handle_hash + (h->h_cookie & HANDLE_HASH_MASK);

	spin_lock(&bucket->lock);
	class_handle_unhash_nolock(h);
	spin_unlock(&bucket->lock);
}
EXPORT_SYMBOL(class_handle_unhash);

void *class_handle2object(u64 cookie, const char *owner)
{
	struct handle_bucket *bucket;
	struct portals_handle *h;
	void *retval = NULL;

	ENTRY;

	LASSERT(handle_hash != NULL);

	/*
	 * Be careful when you want to change this code. See the
	 * rcu_read_lock() definition on top this file. - jxiong
	 */
	bucket = handle_hash + (cookie & HANDLE_HASH_MASK);

	rcu_read_lock();
	hlist_for_each_entry_rcu(h, &bucket->head, h_link) {
		if (h->h_cookie != cookie || h->h_owner != owner)
			continue;

		if (refcount_inc_not_zero(&h->h_ref)) {
			CDEBUG(D_INFO, "GET %s %p refcount=%d\n",
			       h->h_owner, h,
			       refcount_read(&h->h_ref));
			retval = h;
		}
		break;
	}
	rcu_read_unlock();

	RETURN(retval);
}
EXPORT_SYMBOL(class_handle2object);

int class_handle_init(void)
{
	struct handle_bucket *bucket;

	LASSERT(handle_hash == NULL);

	OBD_ALLOC_PTR_ARRAY_LARGE(handle_hash, HANDLE_HASH_SIZE);
	if (handle_hash == NULL)
		return -ENOMEM;

	for (bucket = handle_hash + HANDLE_HASH_SIZE - 1; bucket >= handle_hash;
	     bucket--) {
		INIT_HLIST_HEAD(&bucket->head);
		spin_lock_init(&bucket->lock);
	}

	get_random_bytes(&handle_base, sizeof(handle_base));
	LASSERT(handle_base != 0ULL);

	return 0;
}

static int cleanup_all_handles(void)
{
	int rc;
	int i;

	for (rc = i = 0; i < HANDLE_HASH_SIZE; i++) {
		struct portals_handle *h;

		spin_lock(&handle_hash[i].lock);
		hlist_for_each_entry_rcu(h, &handle_hash[i].head, h_link) {
			CERROR("force clean handle %#llx addr %p owner %p\n",
			       h->h_cookie, h, h->h_owner);

			class_handle_unhash_nolock(h);
			rc++;
		}
		spin_unlock(&handle_hash[i].lock);
	}

	return rc;
}

void class_handle_cleanup(void)
{
	int count;

	LASSERT(handle_hash != NULL);

	count = cleanup_all_handles();

	OBD_FREE_PTR_ARRAY_LARGE(handle_hash, HANDLE_HASH_SIZE);
	handle_hash = NULL;

	if (count != 0)
		CERROR("handle_count at cleanup: %d\n", count);
}
