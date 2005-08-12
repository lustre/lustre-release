/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LOV
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/lustre_ucache.h>

/* FIXME
 * current ucache implementation is simply took from group hash code, almost
 * without any change. it's very simple and have very limited functionality,
 * and probably it's also only suitable for usage of group hash.
 */

void upcall_cache_init_entry(struct upcall_cache *cache,
                             struct upcall_cache_entry *entry,
                             __u64 key)
{
        UC_CACHE_SET_NEW(entry);
        INIT_LIST_HEAD(&entry->ue_hash);
        atomic_set(&entry->ue_refcount, 0);
        entry->ue_key = key;
        entry->ue_cache = cache;
        init_waitqueue_head(&entry->ue_waitq);
}
EXPORT_SYMBOL(upcall_cache_init_entry);

static inline struct upcall_cache_entry *
alloc_entry(struct upcall_cache *cache, __u64 key)
{
        LASSERT(cache->alloc_entry);
        return cache->alloc_entry(cache, key);
}

static void free_entry(struct upcall_cache_entry *entry)
{
        struct upcall_cache *cache = entry->ue_cache;

        LASSERT(cache);
        LASSERT(cache->free_entry);
        LASSERT(atomic_read(&entry->ue_refcount) == 0);

        CDEBUG(D_SEC, "%s: destroy entry %p for key "LPU64"\n",
               cache->uc_name, entry, entry->ue_key);

        list_del(&entry->ue_hash);
        cache->free_entry(cache, entry);
}

static inline void get_entry(struct upcall_cache_entry *entry)
{
        atomic_inc(&entry->ue_refcount);
}

static inline void put_entry(struct upcall_cache_entry *entry)
{
        if (atomic_dec_and_test(&entry->ue_refcount) &&
            !UC_CACHE_IS_VALID(entry)) {
                free_entry(entry);
        }
}

static inline int refresh_entry(struct upcall_cache_entry *entry)
{
        struct upcall_cache *cache = entry->ue_cache;

        LASSERT(cache);
        LASSERT(cache->make_upcall);

        return cache->make_upcall(cache, entry);
}

static int check_unlink_entry(struct upcall_cache_entry *entry)
{
        /* upcall will be issued upon new entries immediately
         * after they are created
         */
        LASSERT(!UC_CACHE_IS_NEW(entry));

        if (UC_CACHE_IS_VALID(entry) &&
            time_before(get_seconds(), entry->ue_expire))
                return 0;

        if (UC_CACHE_IS_ACQUIRING(entry)) {
                if (time_before(get_seconds(), entry->ue_acquire_expire))
                        return 0;
                else {
                        UC_CACHE_SET_EXPIRED(entry);
                        wake_up_all(&entry->ue_waitq);
                }
        } else if (!UC_CACHE_IS_INVALID(entry)) {
                UC_CACHE_SET_EXPIRED(entry);
        }

        list_del_init(&entry->ue_hash);
        if (!atomic_read(&entry->ue_refcount))
                free_entry(entry);
        return 1;
}

/* XXX
 * currently always use write_lock
 */
static struct upcall_cache_entry *
__get_entry(struct upcall_cache *cache, unsigned int hash, __u64 key,
            int create, int async)
{
        struct list_head *head;
        struct upcall_cache_entry *entry, *next, *new = NULL;
        int found = 0, rc;
        ENTRY;

        LASSERT(hash < cache->uc_hashsize);
        head = &cache->uc_hashtable[hash];

find_again:
        write_lock(&cache->uc_hashlock);
        list_for_each_entry_safe(entry, next, head, ue_hash) {
                if (check_unlink_entry(entry))
                        continue;
                if (entry->ue_key == key) {
                        found = 1;
                        break;
                }
        }

        if (!found) {
                if (!create)
                        RETURN(NULL);
                if (!new) {
                        write_unlock(&cache->uc_hashlock);
                        new = alloc_entry(cache, key);
                        if (!new) {
                                CERROR("fail to alloc entry\n");
                                RETURN(NULL);
                        }
                        goto find_again;
                } else {
                        list_add(&new->ue_hash, head);
                        entry = new;
                }
        } else {
                if (new) {
                        free_entry(new);
                        new = NULL;
                }
                list_move(&entry->ue_hash, head);
        }
        get_entry(entry);

        /* as for this moment, we have found matched entry
         * and hold a ref of it. if it's NEW (we created it),
         * we must give it a push to refresh
         */
        if (UC_CACHE_IS_NEW(entry)) {
                LASSERT(entry == new);
                UC_CACHE_SET_ACQUIRING(entry);
                UC_CACHE_CLEAR_NEW(entry);
                entry->ue_acquire_expire = get_seconds() +
                                           cache->uc_acquire_expire;

                write_unlock(&cache->uc_hashlock);
                rc = refresh_entry(entry);
                write_lock(&cache->uc_hashlock);
                if (rc) {
                        UC_CACHE_CLEAR_ACQUIRING(entry);
                        UC_CACHE_SET_INVALID(entry);
                }
        }

        /* caller don't want to wait */
        if (async) {
                write_unlock(&cache->uc_hashlock);
                RETURN(entry);
        }

        /* someone (and only one) is doing upcall upon
         * this item, just wait it complete
         */
        if (UC_CACHE_IS_ACQUIRING(entry)) {
                wait_queue_t wait;

                init_waitqueue_entry(&wait, current);
                add_wait_queue(&entry->ue_waitq, &wait);
                set_current_state(TASK_INTERRUPTIBLE);
                write_unlock(&cache->uc_hashlock);

                schedule_timeout(cache->uc_acquire_expire * HZ);

                write_lock(&cache->uc_hashlock);
                remove_wait_queue(&entry->ue_waitq, &wait);
                if (UC_CACHE_IS_ACQUIRING(entry)) {
                        /* we're interrupted or upcall failed
                         * in the middle
                         */
                        CERROR("%s: entry %p not refreshed: key "LPU64", "
                               "ref %d fl %u, cur %lu, ex %ld/%ld\n",
                               cache->uc_name, entry, entry->ue_key,
                               atomic_read(&entry->ue_refcount),
                               entry->ue_flags, get_seconds(),
                               entry->ue_acquire_expire, entry->ue_expire);
                        put_entry(entry);
                        write_unlock(&cache->uc_hashlock);
                        CERROR("Interrupted? Or check whether %s is in place\n",
                               cache->uc_upcall);
                        RETURN(NULL);
                }
                /* fall through */
        }

        /* invalid means error, don't need to try again */
        if (UC_CACHE_IS_INVALID(entry)) {
                put_entry(entry);
                write_unlock(&cache->uc_hashlock);
                RETURN(NULL);
        }

        /* check expired 
         * We can't refresh the existed one because some
         * memory might be shared by multiple processes.
         */
        if (check_unlink_entry(entry)) {
                /* if expired, try again. but if this entry is
                 * created by me and too quickly turn to expired
                 * without any error, should at least give a
                 * chance to use it once.
                 */
                if (entry != new) {
                        put_entry(entry);
                        write_unlock(&cache->uc_hashlock);
                        new = NULL;
                        goto find_again;
                }
        }
        
        /* Now we know it's good */
        write_unlock(&cache->uc_hashlock);

        RETURN(entry);
}

struct upcall_cache_entry *
upcall_cache_get_entry(struct upcall_cache *cache, __u64 key)
{
        unsigned int hash;

        LASSERT(cache->hash);

        hash = cache->hash(cache, key);

        return __get_entry(cache, hash, key, 1, 0);
}
EXPORT_SYMBOL(upcall_cache_get_entry);

void upcall_cache_put_entry(struct upcall_cache_entry *entry)
{
        struct upcall_cache *cache = entry->ue_cache;

        write_lock(&cache->uc_hashlock);
        LASSERTF(atomic_read(&entry->ue_refcount) > 0,
                 "%s: entry %p: ref %d\n", cache->uc_name, entry,
                 atomic_read(&entry->ue_refcount));
        put_entry(entry);
        write_unlock(&cache->uc_hashlock);
}
EXPORT_SYMBOL(upcall_cache_put_entry);

int upcall_cache_downcall(struct upcall_cache *cache, __u64 key, void *args)
{
        struct list_head *head;
        struct upcall_cache_entry *entry;
        int found = 0, rc;
        unsigned int hash;
        ENTRY;

        hash = cache->hash(cache, key);
        LASSERT(hash < cache->uc_hashsize);

        head = &cache->uc_hashtable[hash];

        write_lock(&cache->uc_hashlock);
        list_for_each_entry(entry, head, ue_hash) {
                if (entry->ue_key == key) {
                        found = 1;
                        break;
                }
        }
        if (!found) {
                /* haven't found, it's possible */
                write_unlock(&cache->uc_hashlock);
                CWARN("%s: key "LPU64" entry dosen't found\n",
                      cache->uc_name, key);
                RETURN(-EINVAL);
        }

        if (!UC_CACHE_IS_ACQUIRING(entry)) {
                if (UC_CACHE_IS_VALID(entry)) {
                        /* This should not happen, just give a warning
                         * at this moment.
                         */
                        CWARN("%s: entry %p(key "LPU64", cur %lu, ex %ld/%ld) "
                              "already valid\n", cache->uc_name,
                              entry, entry->ue_key, get_seconds(),
                              entry->ue_acquire_expire, entry->ue_expire);
                        GOTO(out, rc = 0);
                }

                CWARN("%s: stale entry %p: key "LPU64", ref %d, fl %u, "
                      "cur %lu, ex %ld/%ld\n",
                      cache->uc_name, entry, entry->ue_key,
                      atomic_read(&entry->ue_refcount),
                      entry->ue_flags, get_seconds(),
                      entry->ue_acquire_expire, entry->ue_expire);
                GOTO(out, rc = -EINVAL);
        }

        if (!UC_CACHE_IS_ACQUIRING(entry) ||
            UC_CACHE_IS_INVALID(entry) ||
            UC_CACHE_IS_EXPIRED(entry)) {
                CWARN("%s: invalid entry %p: key "LPU64", ref %d, fl %u, "
                      "cur %lu, ex %ld/%ld\n",
                      cache->uc_name, entry, entry->ue_key,
                      atomic_read(&entry->ue_refcount),
                      entry->ue_flags, get_seconds(), 
                      entry->ue_acquire_expire, entry->ue_expire);
                GOTO(out, rc = -EINVAL);
        }

        atomic_inc(&entry->ue_refcount);
        write_unlock(&cache->uc_hashlock);
        rc = cache->parse_downcall(cache, entry, args);
        write_lock(&cache->uc_hashlock);
        atomic_dec(&entry->ue_refcount);

        if (rc < 0) {
                UC_CACHE_SET_INVALID(entry);
                list_del_init(&entry->ue_hash);
                GOTO(out, rc);
        } else if (rc == 0) {
                entry->ue_expire = get_seconds() + cache->uc_entry_expire;
        } else {
                entry->ue_expire = get_seconds() + cache->uc_err_entry_expire;
        }

        UC_CACHE_SET_VALID(entry);
        CDEBUG(D_SEC, "%s: create ucache entry %p(key "LPU64")\n",
               cache->uc_name, entry, entry->ue_key);
out:
        wake_up_all(&entry->ue_waitq);
        write_unlock(&cache->uc_hashlock);
        RETURN(rc);
}
EXPORT_SYMBOL(upcall_cache_downcall);

void upcall_cache_flush_one(struct upcall_cache *cache, __u64 key)
{
        struct list_head *head;
        struct upcall_cache_entry *entry;
        unsigned int hash;
        int found = 0;
        ENTRY;

        hash = cache->hash(cache, key);
        LASSERT(hash < cache->uc_hashsize);
        head = &cache->uc_hashtable[hash];

        write_lock(&cache->uc_hashlock);
        list_for_each_entry(entry, head, ue_hash) {
                if (entry->ue_key == key) {
                        found = 1;
                        break;
                }
        }

        if (found) {
                CWARN("%s: flush entry %p: key "LPU64", ref %d, fl %x, "
                      "cur %lu, ex %ld/%ld\n",
                      cache->uc_name, entry, entry->ue_key,
                      atomic_read(&entry->ue_refcount), entry->ue_flags,
                      get_seconds(), entry->ue_acquire_expire,
                      entry->ue_expire);
                UC_CACHE_SET_EXPIRED(entry);
                if (!atomic_read(&entry->ue_refcount))
                        free_entry(entry);
        }
        write_unlock(&cache->uc_hashlock);
}
EXPORT_SYMBOL(upcall_cache_flush_one);

static void cache_flush(struct upcall_cache *cache, int force, int sync)
{
        struct upcall_cache_entry *entry, *next;
        int i;
        ENTRY;

        write_lock(&cache->uc_hashlock);
        for (i = 0; i < cache->uc_hashsize; i++) {
                list_for_each_entry_safe(entry, next,
                                         &cache->uc_hashtable[i], ue_hash) {
                        if (!force && atomic_read(&entry->ue_refcount)) {
                                UC_CACHE_SET_EXPIRED(entry);
                                continue;
                        }
                        LASSERT(!atomic_read(&entry->ue_refcount));
                        free_entry(entry);
                }
        }
        write_unlock(&cache->uc_hashlock);
        EXIT;
}

void upcall_cache_flush_idle(struct upcall_cache *cache)
{
        cache_flush(cache, 0, 0);
}

void upcall_cache_flush_all(struct upcall_cache *cache)
{
        cache_flush(cache, 1, 0);
}
EXPORT_SYMBOL(upcall_cache_flush_idle);
EXPORT_SYMBOL(upcall_cache_flush_all);
