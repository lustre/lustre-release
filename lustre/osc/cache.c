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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 * lustre/osc/cache.c
 *
 * Cache of triples - object, lock, extent
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
# include <linux/version.h>
# include <linux/module.h>
# include <linux/list.h>
#else                           /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <lustre_dlm.h>
#include <lustre_cache.h>
#include <obd.h>
#include <lustre_debug.h>

#include "osc_internal.h"

/* Adding @lock to the @cache */
int cache_add_lock(struct lustre_cache *cache, struct lustre_handle *lockh)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);

        if (!lock)      // Lock disappeared under us.
                return 0;

        spin_lock(&cache->lc_locks_list_lock);
        list_add_tail(&lock->l_cache_locks_list, &cache->lc_locks_list);
        spin_unlock(&cache->lc_locks_list_lock);

        LDLM_LOCK_PUT(lock);

        return 0;
}

/* Tries to add @extent to lock represented by @lockh if non-NULL, otherwise
   just tries to match some suitable lock by resource and data contained in
   @extent */
/* Should be called with oap->lock held (except on initial addition, see
   comment in osc_request.c*/
int cache_add_extent(struct lustre_cache *cache, struct ldlm_res_id *res,
                     struct osc_async_page *extent, struct lustre_handle *lockh)
{
        struct lustre_handle tmplockh;
        ldlm_policy_data_t tmpex;
        struct ldlm_lock *lock = NULL;
        ENTRY;

        /* Don't add anything second time */
        if (!list_empty(&extent->oap_page_list)) {
                LBUG();
                RETURN(0);
        }

        if (lockh && lustre_handle_is_used(lockh)) {
                lock = ldlm_handle2lock(lockh);
                if (!lock)
                        RETURN(-ENOLCK);

                LASSERTF(lock->l_policy_data.l_extent.start <=
                         extent->oap_obj_off &&
                         extent->oap_obj_off + CFS_PAGE_SIZE - 1 <=
                         lock->l_policy_data.l_extent.end,
                         "Got wrong lock [" LPU64 "," LPU64 "] for page with "
                         "offset " LPU64 "\n",
                         lock->l_policy_data.l_extent.start,
                         lock->l_policy_data.l_extent.end, extent->oap_obj_off);
        } else {
                int mode;
                /* Real extent width calculation here once we have real
                 * extents
                 */
                tmpex.l_extent.start = extent->oap_obj_off;
                tmpex.l_extent.end = tmpex.l_extent.start + CFS_PAGE_SIZE - 1;

                /* XXX find lock from extent or something like that */
                /* The lock mode does not matter. If this is dirty page - then
                 * there could be only one PW lock. If the page is clean,
                 * any PR lock is good
                 */
                mode = ldlm_lock_match(cache->lc_obd->obd_namespace,
                                       LDLM_FL_BLOCK_GRANTED |
                                       LDLM_FL_CBPENDING, res, LDLM_EXTENT,
                                       &tmpex, LCK_PW | LCK_PR, &tmplockh);

                if (mode <= 0) {
                        CDEBUG(D_CACHE, "No lock to attach " LPU64 "->" LPU64
                               " extent to!\n", tmpex.l_extent.start,
                               tmpex.l_extent.end);
                        RETURN((mode < 0) ? mode : -ENOLCK);
                }

                lock = ldlm_handle2lock(&tmplockh);
                if (!lock) {    // Race - lock disappeared under us (eviction?)
                        CDEBUG(D_CACHE, "Newly matched lock just disappeared "
                               "under us\n");
                        RETURN(-ENOLCK);
                }
                ldlm_lock_decref(&tmplockh, mode);
        }

        spin_lock(&lock->l_extents_list_lock);
        list_add_tail(&extent->oap_page_list, &lock->l_extents_list);
        spin_unlock(&lock->l_extents_list_lock);
        extent->oap_ldlm_lock = lock;
        LDLM_LOCK_PUT(lock);

        RETURN(0);
}

static void cache_extent_removal_get(struct page_removal_cb_element *element)
{
        atomic_inc(&element->prce_refcnt);
}

static void cache_extent_removal_put(struct page_removal_cb_element *element)
{
        if(atomic_dec_and_test(&element->prce_refcnt))
                OBD_FREE_PTR(element);
}

static int cache_extent_removal_event(struct lustre_cache *cache,
                                      void *data, int discard)
{
        struct page *page = data;
        struct list_head *iter;
        struct page_removal_cb_element *element;

        read_lock(&cache->lc_page_removal_cb_lock);
        iter = cache->lc_page_removal_callback_list.next;
        while(iter != &cache->lc_page_removal_callback_list) {
                element = list_entry(iter, struct page_removal_cb_element, prce_list);
                cache_extent_removal_get(element);
                read_unlock(&cache->lc_page_removal_cb_lock);

                element->prce_callback(page, discard);

                read_lock(&cache->lc_page_removal_cb_lock);
                iter = iter->next;
                cache_extent_removal_put(element);
        }
        read_unlock(&cache->lc_page_removal_cb_lock);

        return 0;
}

/* Registers set of pin/remove callbacks for extents. Current limitation is
   there could be only one pin_cb per cache.
   @pin_cb is called when we have the page locked to pin it in memory so that
   it does not disappear after we release page lock (which we need to do
   to avoid deadlocks).
   @func_cb is removal callback that is called after page and all spinlocks are
   released, and is supposed to clean the page and remove it from all
   (vfs) caches it might be in */
int cache_add_extent_removal_cb(struct lustre_cache *cache,
                                obd_page_removal_cb_t func_cb,
                                obd_pin_extent_cb pin_cb)
{
        struct page_removal_cb_element *element;

        if (!func_cb)
                return 0;

        OBD_ALLOC_PTR(element);
        if (!element)
                return -ENOMEM;
        element->prce_callback = func_cb;
        atomic_set(&element->prce_refcnt, 1);

        write_lock(&cache->lc_page_removal_cb_lock);
        list_add_tail(&element->prce_list,
                      &cache->lc_page_removal_callback_list);
        write_unlock(&cache->lc_page_removal_cb_lock);

        cache->lc_pin_extent_cb = pin_cb;
        return 0;
}
EXPORT_SYMBOL(cache_add_extent_removal_cb);

/* Unregister exntent removal callback registered earlier. If the list of
   registered removal callbacks becomes empty, we also clear pin callback
   since it could only be one */
int cache_del_extent_removal_cb(struct lustre_cache *cache,
                                obd_page_removal_cb_t func_cb)
{
        int found = 0;
        struct page_removal_cb_element *element, *t;

        write_lock(&cache->lc_page_removal_cb_lock);
        list_for_each_entry_safe(element, t,
                                 &cache->lc_page_removal_callback_list,
                                 prce_list) {
                if (element->prce_callback == func_cb) {
                        list_del(&element->prce_list);
                        write_unlock(&cache->lc_page_removal_cb_lock);
                        found = 1;
                        cache_extent_removal_put(element);
                        write_lock(&cache->lc_page_removal_cb_lock);
                        /* We continue iterating the list in case this function
                           was registered more than once */
                }
        }
        write_unlock(&cache->lc_page_removal_cb_lock);

        if (list_empty(&cache->lc_page_removal_callback_list))
                cache->lc_pin_extent_cb = NULL;

        return !found;
}
EXPORT_SYMBOL(cache_del_extent_removal_cb);

static int cache_remove_extent_nolock(struct lustre_cache *cache,
                                      struct osc_async_page *extent)
{
        int have_lock = !!extent->oap_ldlm_lock;
        /* We used to check oap_ldlm_lock for non NULL here, but it might be
           NULL, in fact, due to parallel page eviction clearing it and waiting
           on a lock's page list lock */
        extent->oap_ldlm_lock = NULL;

        if (!list_empty(&extent->oap_page_list))
                list_del_init(&extent->oap_page_list);

        return have_lock;
}

/* Request the @extent to be removed from cache and locks it belongs to. */
void cache_remove_extent(struct lustre_cache *cache,
                         struct osc_async_page *extent)
{
        struct ldlm_lock *lock;

        spin_lock(&extent->oap_lock);
        lock = extent->oap_ldlm_lock;

        extent->oap_ldlm_lock = NULL;
        spin_unlock(&extent->oap_lock);

        /* No lock - means this extent is not in any list */
        if (!lock)
                return;

        spin_lock(&lock->l_extents_list_lock);
        if (!list_empty(&extent->oap_page_list))
                list_del_init(&extent->oap_page_list);
        spin_unlock(&lock->l_extents_list_lock);
}

/* Iterate through list of extents in given lock identified by @lockh,
   calling @cb_func for every such extent. Also passed @data to every call.
   Stops iterating prematurely if @cb_func returns nonzero. */
int cache_iterate_extents(struct lustre_cache *cache,
                          struct lustre_handle *lockh,
                          cache_iterate_extents_cb_t cb_func, void *data)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        struct osc_async_page *extent, *t;

        if (!lock)      // Lock disappeared
                return 0;
        /* Parallel page removal from mem pressure can race with us */
        spin_lock(&lock->l_extents_list_lock);
        list_for_each_entry_safe(extent, t, &lock->l_extents_list,
                                 oap_page_list) {
                if (cb_func(cache, lockh, extent, data))
                        break;
        }
        spin_unlock(&lock->l_extents_list_lock);
        LDLM_LOCK_PUT(lock);

        return 0;
}

static int cache_remove_extents_from_lock(struct lustre_cache *cache,
                                          struct ldlm_lock *lock, void *data)
{
        struct osc_async_page *extent;
        void *ext_data;

        LASSERT(lock);

        spin_lock(&lock->l_extents_list_lock);
        while (!list_empty(&lock->l_extents_list)) {
                extent = list_entry(lock->l_extents_list.next,
                                    struct osc_async_page, oap_page_list);

                spin_lock(&extent->oap_lock);
                /* If there is no lock referenced from this oap, it means
                   there is parallel page-removal process waiting to free that
                   page on l_extents_list_lock and it holds page lock.
                   We need this page to completely go away and for that to
                   happen we will just try to truncate it here too.
                   Serialisation on page lock will achieve that goal for us. */
                /* Try to add extent back to the cache first, but only if we
                 * cancel read lock, write locks cannot have other overlapping
                 * locks. If adding is not possible (or canceling pw lock),
                 * then remove extent from cache */
                if (!cache_remove_extent_nolock(cache, extent) ||
                    (lock->l_granted_mode == LCK_PW) ||
                    cache_add_extent(cache, &lock->l_resource->lr_name, extent,
                                     NULL)) {
                        /* We need to remember this oap_page value now,
                           once we release spinlocks, extent struct
                           might be freed and we endup requesting
                           page with address 0x5a5a5a5a in
                           cache_extent_removal_event */
                        ext_data = extent->oap_page;
                        cache->lc_pin_extent_cb(extent->oap_page);
                        spin_unlock(&extent->oap_lock);
                        spin_unlock(&lock->l_extents_list_lock);
                        cache_extent_removal_event(cache, ext_data,
                                                   lock->
                                                   l_flags &
                                                   LDLM_FL_DISCARD_DATA);
                        spin_lock(&lock->l_extents_list_lock);
                } else {
                        spin_unlock(&extent->oap_lock);
                }
        }
        spin_unlock(&lock->l_extents_list_lock);

        return 0;
}

/* Remoes @lock from cache after necessary checks. */
int cache_remove_lock(struct lustre_cache *cache, struct lustre_handle *lockh)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);

        if (!lock)  // The lock was removed by somebody just now, nothing to do
                return 0;

        cache_remove_extents_from_lock(cache, lock, NULL /*data */ );

        spin_lock(&cache->lc_locks_list_lock);
        list_del_init(&lock->l_cache_locks_list);
        spin_unlock(&cache->lc_locks_list_lock);

        LDLM_LOCK_PUT(lock);

        return 0;
}

/* Supposed to iterate through all locks in the cache for given resource.
   Not implemented atthe moment. */
int cache_iterate_locks(struct lustre_cache *cache, struct ldlm_res_id *res,
                        cache_iterate_locks_cb_t cb_fun, void *data)
{
        return -ENOTSUPP;
}

/* Create lustre cache and attach it to @obd */
struct lustre_cache *cache_create(struct obd_device *obd)
{
        struct lustre_cache *cache;

        OBD_ALLOC(cache, sizeof(*cache));
        if (!cache)
                GOTO(out, NULL);
        spin_lock_init(&cache->lc_locks_list_lock);
        CFS_INIT_LIST_HEAD(&cache->lc_locks_list);
        CFS_INIT_LIST_HEAD(&cache->lc_page_removal_callback_list);
        rwlock_init(&cache->lc_page_removal_cb_lock);
        cache->lc_obd = obd;

      out:
        return cache;
}

/* Destroy @cache and free its memory */
int cache_destroy(struct lustre_cache *cache)
{
        if (cache) {
                spin_lock(&cache->lc_locks_list_lock);
                if (!list_empty(&cache->lc_locks_list)) {
                        struct ldlm_lock *lock, *tmp;
                        CERROR("still have locks in the list on cleanup:\n");

                        list_for_each_entry_safe(lock, tmp,
                                                 &cache->lc_locks_list,
                                                 l_cache_locks_list) {
                                list_del_init(&lock->l_cache_locks_list);
                                /* XXX: Of course natural idea would be to print
                                   offending locks here, but if we use
                                   e.g. LDLM_ERROR, we will likely crash here,
                                   as LDLM error tries to access e.g.
                                   nonexisting namespace. Normally this kind of
                                   case could only happen when somebody did not
                                   release lock reference and we have other ways
                                   to detect this. */
                                /* Make sure there are no pages left under the
                                   lock */
                                LASSERT(list_empty(&lock->l_extents_list));
                        }
                }
                spin_unlock(&cache->lc_locks_list_lock);
                LASSERT(list_empty(&cache->lc_page_removal_callback_list));
                OBD_FREE(cache, sizeof(*cache));
        }

        return 0;
}
