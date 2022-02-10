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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/upcall_cache.c
 *
 * Supplementary groups cache.
 */
#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/libcfs.h>
#include <uapi/linux/lnet/lnet-types.h>
#include <upcall_cache.h>
#include "upcall_cache_internal.h"

static struct upcall_cache_entry *alloc_entry(struct upcall_cache *cache,
					      __u64 key, void *args)
{
	struct upcall_cache_entry *entry;

	LIBCFS_ALLOC(entry, sizeof(*entry));
	if (!entry)
		return NULL;

	UC_CACHE_SET_NEW(entry);
	INIT_LIST_HEAD(&entry->ue_hash);
	entry->ue_key = key;
	atomic_set(&entry->ue_refcount, 0);
	init_waitqueue_head(&entry->ue_waitq);
	entry->ue_acquire_expire = 0;
	entry->ue_expire = 0;
	if (cache->uc_ops->init_entry)
		cache->uc_ops->init_entry(entry, args);
	return entry;
}

static inline int upcall_compare(struct upcall_cache *cache,
				 struct upcall_cache_entry *entry,
				 __u64 key, void *args)
{
	if (entry->ue_key != key)
		return -1;

	if (cache->uc_ops->upcall_compare)
		return cache->uc_ops->upcall_compare(cache, entry, key, args);

	return 0;
}

static inline int downcall_compare(struct upcall_cache *cache,
				   struct upcall_cache_entry *entry,
				   __u64 key, void *args)
{
	if (entry->ue_key != key)
		return -1;

	if (cache->uc_ops->downcall_compare)
		return cache->uc_ops->downcall_compare(cache, entry, key, args);

	return 0;
}

static inline void write_lock_from_read(rwlock_t *lock, bool *writelock)
{
	if (!*writelock) {
		read_unlock(lock);
		write_lock(lock);
		*writelock = true;
	}
}

static int check_unlink_entry(struct upcall_cache *cache,
			      struct upcall_cache_entry *entry,
			      bool writelock)
{
	time64_t now = ktime_get_seconds();

	if (UC_CACHE_IS_VALID(entry) && now < entry->ue_expire)
		return 0;

	if (UC_CACHE_IS_ACQUIRING(entry)) {
		if (entry->ue_acquire_expire == 0 ||
		    now < entry->ue_acquire_expire)
			return 0;

		if (writelock) {
			UC_CACHE_SET_EXPIRED(entry);
			wake_up(&entry->ue_waitq);
		}
	} else if (!UC_CACHE_IS_INVALID(entry) && writelock) {
		UC_CACHE_SET_EXPIRED(entry);
	}

	if (writelock) {
		list_del_init(&entry->ue_hash);
		if (!atomic_read(&entry->ue_refcount))
			free_entry(cache, entry);
	}
	return 1;
}

int upcall_cache_set_upcall(struct upcall_cache *cache, const char *buffer,
			    size_t count, bool path_only)
{
	char *upcall;
	int rc = 0;

	if (count >= UC_CACHE_UPCALL_MAXPATH)
		return -E2BIG;

	OBD_ALLOC(upcall, count + 1);
	if (upcall == NULL)
		return -ENOMEM;

	/* Remove any extraneous bits from the upcall (e.g. linefeeds) */
	if (sscanf(buffer, "%s", upcall) != 1)
		GOTO(out, rc = -EINVAL);

	/* Accepted values are:
	 * - an absolute path to an executable
	 * - if path_only is false: "none", case insensitive
	 */
	if (upcall[0] != '/') {
		if (!path_only && strcasecmp(upcall, "NONE") == 0)
			snprintf(upcall, count + 1, "NONE");
		else
			GOTO(out, rc = -EINVAL);
	}

	down_write(&cache->uc_upcall_rwsem);
	strncpy(cache->uc_upcall, upcall, count + 1);
	up_write(&cache->uc_upcall_rwsem);

out:
	OBD_FREE(upcall, count + 1);
	return rc;
}
EXPORT_SYMBOL(upcall_cache_set_upcall);

static inline int refresh_entry(struct upcall_cache *cache,
				struct upcall_cache_entry *entry, __u32 fsgid)
{
	LASSERT(cache->uc_ops->do_upcall);
	return cache->uc_ops->do_upcall(cache, entry);
}

struct upcall_cache_entry *upcall_cache_get_entry(struct upcall_cache *cache,
						  __u64 key, void *args)
{
	struct upcall_cache_entry *entry = NULL, *new = NULL, *next;
	gid_t fsgid = (__u32)__kgid_val(INVALID_GID);
	struct group_info *ginfo = NULL;
	bool failedacquiring = false;
	struct list_head *head;
	wait_queue_entry_t wait;
	bool writelock;
	int rc = 0, found;

	ENTRY;

	LASSERT(cache);

	head = &cache->uc_hashtable[UC_CACHE_HASH_INDEX(key,
							cache->uc_hashsize)];
find_again:
	found = 0;
	if (new) {
		write_lock(&cache->uc_lock);
		writelock = true;
	} else {
		read_lock(&cache->uc_lock);
		writelock = false;
	}
find_with_lock:
	list_for_each_entry_safe(entry, next, head, ue_hash) {
		/* check invalid & expired items */
		if (check_unlink_entry(cache, entry, writelock))
			continue;
		if (upcall_compare(cache, entry, key, args) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		if (!new) {
			if (writelock)
				write_unlock(&cache->uc_lock);
			else
				read_unlock(&cache->uc_lock);
			new = alloc_entry(cache, key, args);
			if (!new) {
				CERROR("%s: fail to alloc entry: rc = %d\n",
				       cache->uc_name, -ENOMEM);
				RETURN(ERR_PTR(-ENOMEM));
			}
			goto find_again;
		} else {
			list_add(&new->ue_hash, head);
			entry = new;
		}
	} else {
		if (new) {
			free_entry(cache, new);
			new = NULL;
		} else if (!writelock) {
			/* We found an entry while holding the read lock, so
			 * convert it to a write lock and find again, to check
			 * that entry was not modified/freed in between.
			 */
			write_lock_from_read(&cache->uc_lock, &writelock);
			found = 0;
			goto find_with_lock;
		}
		list_move(&entry->ue_hash, head);
	}
	/* now we hold a write lock */
	get_entry(entry);

	/* special processing of supp groups for identity upcall */
	if (strcmp(cache->uc_upcall, IDENTITY_UPCALL_INTERNAL) == 0) {
		write_unlock(&cache->uc_lock);
		rc = upcall_cache_get_entry_internal(cache, entry, args,
						     &fsgid, &ginfo);
		write_lock(&cache->uc_lock);
		if (rc)
			GOTO(out, entry = ERR_PTR(rc));
	}

	/* acquire for new one */
	if (UC_CACHE_IS_NEW(entry)) {
		UC_CACHE_CLEAR_NEW(entry);
		if (strcmp(cache->uc_upcall, IDENTITY_UPCALL_INTERNAL) == 0) {
			refresh_entry_internal(cache, entry, fsgid, &ginfo);
		} else {
			UC_CACHE_SET_ACQUIRING(entry);
			write_unlock(&cache->uc_lock);
			rc = refresh_entry(cache, entry, fsgid);
			write_lock(&cache->uc_lock);
		}
		entry->ue_acquire_expire = ktime_get_seconds() +
					   cache->uc_acquire_expire;
		if (rc < 0) {
			UC_CACHE_CLEAR_ACQUIRING(entry);
			UC_CACHE_SET_INVALID(entry);
			wake_up(&entry->ue_waitq);
			if (unlikely(rc == -EREMCHG)) {
				put_entry(cache, entry);
				GOTO(out, entry = ERR_PTR(rc));
			}
		}
	}
	/* someone (and only one) is doing upcall upon this item,
	 * wait it to complete */
	if (UC_CACHE_IS_ACQUIRING(entry)) {
		long expiry = (entry == new) ?
			      cfs_time_seconds(cache->uc_acquire_expire) :
			      MAX_SCHEDULE_TIMEOUT;
		long left;

		init_wait(&wait);
		add_wait_queue(&entry->ue_waitq, &wait);
		set_current_state(TASK_INTERRUPTIBLE);
		write_unlock(&cache->uc_lock);

		left = schedule_timeout(expiry);

		write_lock(&cache->uc_lock);
		remove_wait_queue(&entry->ue_waitq, &wait);
		if (UC_CACHE_IS_ACQUIRING(entry)) {
			/* we're interrupted or upcall failed in the middle */
			rc = left > 0 ? -EINTR : -ETIMEDOUT;
			/* if we waited uc_acquire_expire, we can try again
			 * with same data, but only if acquire is replayable
			 */
			if (left <= 0 && !cache->uc_acquire_replay)
				failedacquiring = true;
			put_entry(cache, entry);
			if (!failedacquiring) {
				write_unlock(&cache->uc_lock);
				failedacquiring = true;
				new = NULL;
				CDEBUG(D_OTHER,
				       "retry acquire for key %llu (got %d)\n",
				       entry->ue_key, rc);
				goto find_again;
			}
			wake_up_all(&entry->ue_waitq);
			CERROR("%s: acquire for key %lld after %llu: rc = %d\n",
			       cache->uc_name, entry->ue_key,
			       cache->uc_acquire_expire, rc);
			GOTO(out, entry = ERR_PTR(rc));
		}
	}

	/* invalid means error, don't need to try again */
	if (UC_CACHE_IS_INVALID(entry)) {
		put_entry(cache, entry);
		GOTO(out, entry = ERR_PTR(-EIDRM));
	}

	/* check expired
	 * We can't refresh the existing one because some
	 * memory might be shared by multiple processes.
	 */
	if (check_unlink_entry(cache, entry, writelock)) {
		/* if expired, try again. but if this entry is
		 * created by me but too quickly turn to expired
		 * without any error, should at least give a
		 * chance to use it once.
		 */
		if (entry != new) {
			/* as stated above, we already hold a write lock */
			put_entry(cache, entry);
			write_unlock(&cache->uc_lock);
			new = NULL;
			goto find_again;
		}
	}

	/* Now we know it's good */
out:
	if (writelock)
		write_unlock(&cache->uc_lock);
	else
		read_unlock(&cache->uc_lock);
	if (ginfo)
		groups_free(ginfo);
	RETURN(entry);
}
EXPORT_SYMBOL(upcall_cache_get_entry);

void upcall_cache_get_entry_raw(struct upcall_cache_entry *entry)
{
	get_entry(entry);
}
EXPORT_SYMBOL(upcall_cache_get_entry_raw);

void upcall_cache_update_entry(struct upcall_cache *cache,
			       struct upcall_cache_entry *entry,
			       time64_t expire, int state)
{
	write_lock(&cache->uc_lock);
	entry->ue_expire = expire;
	if (!state)
		UC_CACHE_SET_VALID(entry);
	else
		entry->ue_flags |= state;
	write_unlock(&cache->uc_lock);
}
EXPORT_SYMBOL(upcall_cache_update_entry);

void upcall_cache_put_entry(struct upcall_cache *cache,
			    struct upcall_cache_entry *entry)
{
	ENTRY;

	if (!entry) {
		EXIT;
		return;
	}

	LASSERT(atomic_read(&entry->ue_refcount) > 0);
	write_lock(&cache->uc_lock);
	put_entry(cache, entry);
	write_unlock(&cache->uc_lock);
	EXIT;
}
EXPORT_SYMBOL(upcall_cache_put_entry);

int upcall_cache_downcall(struct upcall_cache *cache, __u32 err, __u64 key,
			  void *args)
{
	struct upcall_cache_entry *entry = NULL;
	struct list_head *head;
	int found = 0, rc = 0;
	bool writelock = false;
	ENTRY;

	LASSERT(cache);

	head = &cache->uc_hashtable[UC_CACHE_HASH_INDEX(key,
							cache->uc_hashsize)];

	read_lock(&cache->uc_lock);
	list_for_each_entry(entry, head, ue_hash) {
		if (downcall_compare(cache, entry, key, args) == 0) {
			found = 1;
			get_entry(entry);
			break;
		}
	}

	if (!found) {
		CDEBUG(D_OTHER, "%s: upcall for key %llu not expected\n",
		       cache->uc_name, key);
		/* haven't found, it's possible */
		read_unlock(&cache->uc_lock);
		RETURN(-EINVAL);
	}

	if (err) {
		CDEBUG(D_OTHER, "%s: upcall for key %llu returned %d\n",
		       cache->uc_name, entry->ue_key, err);
		write_lock_from_read(&cache->uc_lock, &writelock);
		GOTO(out, rc = err);
	}

	if (!UC_CACHE_IS_ACQUIRING(entry)) {
		CDEBUG(D_RPCTRACE, "%s: found uptodate entry %p (key %llu)"
		       "\n", cache->uc_name, entry, entry->ue_key);
		write_lock_from_read(&cache->uc_lock, &writelock);
		GOTO(out, rc = 0);
	}

	if (UC_CACHE_IS_INVALID(entry) || UC_CACHE_IS_EXPIRED(entry)) {
		CERROR("%s: found a stale entry %p (key %llu) in ioctl\n",
		       cache->uc_name, entry, entry->ue_key);
		write_lock_from_read(&cache->uc_lock, &writelock);
		GOTO(out, rc = -EINVAL);
	}

	read_unlock(&cache->uc_lock);
	if (cache->uc_ops->parse_downcall)
		rc = cache->uc_ops->parse_downcall(cache, entry, args);
	write_lock(&cache->uc_lock);
	if (rc)
		GOTO(out, rc);

	if (!entry->ue_expire)
		entry->ue_expire = ktime_get_seconds() + cache->uc_entry_expire;
	UC_CACHE_SET_VALID(entry);
	CDEBUG(D_OTHER, "%s: created upcall cache entry %p for key %llu\n",
	       cache->uc_name, entry, entry->ue_key);
out:
	/* 'goto out' needs to make sure to take a write lock first */
	if (rc) {
		UC_CACHE_SET_INVALID(entry);
		list_del_init(&entry->ue_hash);
	}
	UC_CACHE_CLEAR_ACQUIRING(entry);
	wake_up(&entry->ue_waitq);
	put_entry(cache, entry);
	write_unlock(&cache->uc_lock);

	RETURN(rc);
}
EXPORT_SYMBOL(upcall_cache_downcall);

void upcall_cache_flush(struct upcall_cache *cache, int force)
{
	struct upcall_cache_entry *entry, *next;
	int i;
	ENTRY;

	write_lock(&cache->uc_lock);
	for (i = 0; i < cache->uc_hashsize; i++) {
		list_for_each_entry_safe(entry, next,
					 &cache->uc_hashtable[i], ue_hash) {
			if (!force && atomic_read(&entry->ue_refcount)) {
				UC_CACHE_SET_EXPIRED(entry);
				continue;
			}
			LASSERT(!atomic_read(&entry->ue_refcount));
			free_entry(cache, entry);
		}
	}
	write_unlock(&cache->uc_lock);
	EXIT;
}
EXPORT_SYMBOL(upcall_cache_flush);

void upcall_cache_flush_one(struct upcall_cache *cache, __u64 key, void *args)
{
	struct list_head *head;
	struct upcall_cache_entry *entry;
	int found = 0;
	ENTRY;

	head = &cache->uc_hashtable[UC_CACHE_HASH_INDEX(key,
							cache->uc_hashsize)];

	write_lock(&cache->uc_lock);
	list_for_each_entry(entry, head, ue_hash) {
		if (upcall_compare(cache, entry, key, args) == 0) {
			found = 1;
			break;
		}
	}

	if (found) {
		CWARN("%s: flush entry %p: key %llu, ref %d, fl %x, "
		      "cur %lld, ex %lld/%lld\n",
		      cache->uc_name, entry, entry->ue_key,
		      atomic_read(&entry->ue_refcount), entry->ue_flags,
		      ktime_get_real_seconds(), entry->ue_acquire_expire,
		      entry->ue_expire);
		get_entry(entry);
		UC_CACHE_SET_EXPIRED(entry);
		put_entry(cache, entry);
	}
	write_unlock(&cache->uc_lock);
}
EXPORT_SYMBOL(upcall_cache_flush_one);

struct upcall_cache *upcall_cache_init(const char *name, const char *upcall,
				       int hashsz, time64_t entry_expire,
				       time64_t acquire_expire, bool replayable,
				       struct upcall_cache_ops *ops)
{
	struct upcall_cache *cache;
	int i;
	ENTRY;

	LIBCFS_ALLOC(cache, sizeof(*cache));
	if (!cache)
		RETURN(ERR_PTR(-ENOMEM));

	rwlock_init(&cache->uc_lock);
	init_rwsem(&cache->uc_upcall_rwsem);
	cache->uc_hashsize = hashsz;
	LIBCFS_ALLOC(cache->uc_hashtable,
		     sizeof(*cache->uc_hashtable) * cache->uc_hashsize);
	if (!cache->uc_hashtable)
		RETURN(ERR_PTR(-ENOMEM));
	for (i = 0; i < cache->uc_hashsize; i++)
		INIT_LIST_HEAD(&cache->uc_hashtable[i]);
	strscpy(cache->uc_name, name, sizeof(cache->uc_name));
	/* upcall pathname proc tunable */
	strscpy(cache->uc_upcall, upcall, sizeof(cache->uc_upcall));
	cache->uc_entry_expire = entry_expire;
	cache->uc_acquire_expire = acquire_expire;
	cache->uc_acquire_replay = replayable;
	cache->uc_ops = ops;

	RETURN(cache);
}
EXPORT_SYMBOL(upcall_cache_init);

void upcall_cache_cleanup(struct upcall_cache *cache)
{
	if (!cache)
		return;
	upcall_cache_flush_all(cache);
	LIBCFS_FREE(cache->uc_hashtable,
		    sizeof(*cache->uc_hashtable) * cache->uc_hashsize);
	LIBCFS_FREE(cache, sizeof(*cache));
}
EXPORT_SYMBOL(upcall_cache_cleanup);
