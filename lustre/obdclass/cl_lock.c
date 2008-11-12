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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Client Extent Lock.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <obd_class.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <libcfs/list.h>
/* lu_time_global_{init,fini}() */
#include <lu_time.h>

#include <cl_object.h>
#include "cl_internal.h"

/** Lock class of cl_lock::cll_guard */
static struct lock_class_key cl_lock_guard_class;
static cfs_mem_cache_t *cl_lock_kmem;

static struct lu_kmem_descr cl_lock_caches[] = {
        {
                .ckd_cache = &cl_lock_kmem,
                .ckd_name  = "cl_lock_kmem",
                .ckd_size  = sizeof (struct cl_lock)
        },
        {
                .ckd_cache = NULL
        }
};

/**
 * Basic lock invariant that is maintained at all times. Caller either has a
 * reference to \a lock, or somehow assures that \a lock cannot be freed.
 *
 * \see cl_lock_invariant()
 */
static int cl_lock_invariant_trusted(const struct lu_env *env,
                                     const struct cl_lock *lock)
{
        return
                cl_is_lock(lock) &&
                ergo(lock->cll_state == CLS_FREEING, lock->cll_holds == 0) &&
                atomic_read(&lock->cll_ref) >= lock->cll_holds &&
                lock->cll_holds >= lock->cll_users &&
                lock->cll_holds >= 0 &&
                lock->cll_users >= 0 &&
                lock->cll_depth >= 0;
}

/**
 * Stronger lock invariant, checking that caller has a reference on a lock.
 *
 * \see cl_lock_invariant_trusted()
 */
static int cl_lock_invariant(const struct lu_env *env,
                             const struct cl_lock *lock)
{
        int result;

        result = atomic_read(&lock->cll_ref) > 0 &&
                cl_lock_invariant_trusted(env, lock);
        if (!result && env != NULL)
                CL_LOCK_DEBUG(D_ERROR, env, lock, "invariant broken");
        return result;
}

#define RETIP ((unsigned long)__builtin_return_address(0))

#ifdef CONFIG_LOCKDEP
static struct lock_class_key cl_lock_key;

static void cl_lock_lockdep_init(struct cl_lock *lock)
{
        lockdep_set_class_and_name(lock, &cl_lock_key, "EXT");
}

static void cl_lock_lockdep_acquire(const struct lu_env *env,
                                    struct cl_lock *lock, __u32 enqflags)
{
        cl_env_info(env)->clt_nr_locks_acquired++;
        lock_acquire(&lock->dep_map, !!(enqflags & CEF_ASYNC),
                     /* try: */ 0, lock->cll_descr.cld_mode <= CLM_READ,
                     /* check: */ 2, RETIP);
}

static void cl_lock_lockdep_release(const struct lu_env *env,
                                    struct cl_lock *lock)
{
        cl_env_info(env)->clt_nr_locks_acquired--;
        lock_release(&lock->dep_map, 0, RETIP);
}

#else /* !CONFIG_LOCKDEP */

static void cl_lock_lockdep_init(struct cl_lock *lock)
{}
static void cl_lock_lockdep_acquire(const struct lu_env *env,
                                    struct cl_lock *lock, __u32 enqflags)
{}
static void cl_lock_lockdep_release(const struct lu_env *env,
                                    struct cl_lock *lock)
{}

#endif /* !CONFIG_LOCKDEP */

/**
 * Adds lock slice to the compound lock.
 *
 * This is called by cl_object_operations::coo_lock_init() methods to add a
 * per-layer state to the lock. New state is added at the end of
 * cl_lock::cll_layers list, that is, it is at the bottom of the stack.
 *
 * \see cl_req_slice_add(), cl_page_slice_add(), cl_io_slice_add()
 */
void cl_lock_slice_add(struct cl_lock *lock, struct cl_lock_slice *slice,
                       struct cl_object *obj,
                       const struct cl_lock_operations *ops)
{
        ENTRY;
        slice->cls_lock = lock;
        list_add_tail(&slice->cls_linkage, &lock->cll_layers);
        slice->cls_obj = obj;
        slice->cls_ops = ops;
        EXIT;
}
EXPORT_SYMBOL(cl_lock_slice_add);

/**
 * Returns true iff a lock with the mode \a has provides at least the same
 * guarantees as a lock with the mode \a need.
 */
int cl_lock_mode_match(enum cl_lock_mode has, enum cl_lock_mode need)
{
        LINVRNT(need == CLM_READ || need == CLM_WRITE || need == CLM_PHANTOM);
        LINVRNT(has == CLM_READ || has == CLM_WRITE || has == CLM_PHANTOM);
        CLASSERT(CLM_PHANTOM < CLM_READ);
        CLASSERT(CLM_READ < CLM_WRITE);

        return need <= has;
}
EXPORT_SYMBOL(cl_lock_mode_match);

/**
 * Returns true iff extent portions of lock descriptions match.
 */
int cl_lock_ext_match(const struct cl_lock_descr *has,
                      const struct cl_lock_descr *need)
{
        return
                has->cld_start <= need->cld_start &&
                has->cld_end >= need->cld_end &&
                cl_lock_mode_match(has->cld_mode, need->cld_mode);
}
EXPORT_SYMBOL(cl_lock_ext_match);

/**
 * Returns true iff a lock with the description \a has provides at least the
 * same guarantees as a lock with the description \a need.
 */
int cl_lock_descr_match(const struct cl_lock_descr *has,
                        const struct cl_lock_descr *need)
{
        return
                cl_object_same(has->cld_obj, need->cld_obj) &&
                cl_lock_ext_match(has, need);
}
EXPORT_SYMBOL(cl_lock_descr_match);

static void cl_lock_free(const struct lu_env *env, struct cl_lock *lock)
{
        struct cl_object *obj = lock->cll_descr.cld_obj;

        LASSERT(cl_is_lock(lock));
        LINVRNT(!cl_lock_is_mutexed(lock));
        LINVRNT(!mutex_is_locked(&lock->cll_guard));

        ENTRY;
        might_sleep();
        while (!list_empty(&lock->cll_layers)) {
                struct cl_lock_slice *slice;

                slice = list_entry(lock->cll_layers.next, struct cl_lock_slice,
                                   cls_linkage);
                list_del_init(lock->cll_layers.next);
                slice->cls_ops->clo_fini(env, slice);
        }
        atomic_dec(&cl_object_site(obj)->cs_locks.cs_total);
        atomic_dec(&cl_object_site(obj)->cs_locks_state[lock->cll_state]);
        lu_object_ref_del_at(&obj->co_lu, lock->cll_obj_ref, "cl_lock", lock);
        cl_object_put(env, obj);
        lu_ref_fini(&lock->cll_reference);
        lu_ref_fini(&lock->cll_holders);
        mutex_destroy(&lock->cll_guard);
        OBD_SLAB_FREE_PTR(lock, cl_lock_kmem);
        EXIT;
}

/**
 * Releases a reference on a lock.
 *
 * When last reference is released, lock is returned to the cache, unless it
 * is in cl_lock_state::CLS_FREEING state, in which case it is destroyed
 * immediately.
 *
 * \see cl_object_put(), cl_page_put()
 */
void cl_lock_put(const struct lu_env *env, struct cl_lock *lock)
{
        struct cl_object        *obj;
        struct cl_object_header *head;
        struct cl_site          *site;

        LINVRNT(cl_lock_invariant(env, lock));
        ENTRY;
        obj = lock->cll_descr.cld_obj;
        LINVRNT(obj != NULL);
        head = cl_object_header(obj);
        site = cl_object_site(obj);

        CDEBUG(D_DLMTRACE, "releasing reference: %d %p %lu\n",
               atomic_read(&lock->cll_ref), lock, RETIP);

        if (atomic_dec_and_test(&lock->cll_ref)) {
                if (lock->cll_state == CLS_FREEING) {
                        LASSERT(list_empty(&lock->cll_linkage));
                        cl_lock_free(env, lock);
                }
                atomic_dec(&site->cs_locks.cs_busy);
        }
        EXIT;
}
EXPORT_SYMBOL(cl_lock_put);

/**
 * Acquires an additional reference to a lock.
 *
 * This can be called only by caller already possessing a reference to \a
 * lock.
 *
 * \see cl_object_get(), cl_page_get()
 */
void cl_lock_get(struct cl_lock *lock)
{
        LINVRNT(cl_lock_invariant(NULL, lock));
        CDEBUG(D_DLMTRACE|D_TRACE, "acquiring reference: %d %p %lu\n",
               atomic_read(&lock->cll_ref), lock, RETIP);
        atomic_inc(&lock->cll_ref);
}
EXPORT_SYMBOL(cl_lock_get);

/**
 * Acquires a reference to a lock.
 *
 * This is much like cl_lock_get(), except that this function can be used to
 * acquire initial reference to the cached lock. Caller has to deal with all
 * possible races. Use with care!
 *
 * \see cl_page_get_trust()
 */
void cl_lock_get_trust(struct cl_lock *lock)
{
        struct cl_site *site = cl_object_site(lock->cll_descr.cld_obj);

        LASSERT(cl_is_lock(lock));
        CDEBUG(D_DLMTRACE|D_TRACE, "acquiring trusted reference: %d %p %lu\n",
               atomic_read(&lock->cll_ref), lock, RETIP);
        if (atomic_inc_return(&lock->cll_ref) == 1)
                atomic_inc(&site->cs_locks.cs_busy);
}
EXPORT_SYMBOL(cl_lock_get_trust);

/**
 * Helper function destroying the lock that wasn't completely initialized.
 *
 * Other threads can acquire references to the top-lock through its
 * sub-locks. Hence, it cannot be cl_lock_free()-ed immediately.
 */
static void cl_lock_finish(const struct lu_env *env, struct cl_lock *lock)
{
        cl_lock_mutex_get(env, lock);
        cl_lock_delete(env, lock);
        cl_lock_mutex_put(env, lock);
        cl_lock_put(env, lock);
}

static struct cl_lock *cl_lock_alloc(const struct lu_env *env,
                                     struct cl_object *obj,
                                     const struct cl_io *io,
                                     const struct cl_lock_descr *descr)
{
        struct cl_lock          *lock;
        struct lu_object_header *head;
        struct cl_site          *site = cl_object_site(obj);

        ENTRY;
        OBD_SLAB_ALLOC_PTR(lock, cl_lock_kmem);
        if (lock != NULL) {
                atomic_set(&lock->cll_ref, 1);
                lock->cll_descr = *descr;
                lock->cll_state = CLS_NEW;
                cl_object_get(obj);
                lock->cll_obj_ref = lu_object_ref_add(&obj->co_lu,
                                                      "cl_lock", lock);
                CFS_INIT_LIST_HEAD(&lock->cll_layers);
                CFS_INIT_LIST_HEAD(&lock->cll_linkage);
                CFS_INIT_LIST_HEAD(&lock->cll_inclosure);
                lu_ref_init(&lock->cll_reference);
                lu_ref_init(&lock->cll_holders);
                mutex_init(&lock->cll_guard);
                lockdep_set_class(&lock->cll_guard, &cl_lock_guard_class);
                cfs_waitq_init(&lock->cll_wq);
                head = obj->co_lu.lo_header;
                atomic_inc(&site->cs_locks_state[CLS_NEW]);
                atomic_inc(&site->cs_locks.cs_total);
                atomic_inc(&site->cs_locks.cs_created);
                cl_lock_lockdep_init(lock);
                list_for_each_entry(obj, &head->loh_layers, co_lu.lo_linkage) {
                        int err;

                        err = obj->co_ops->coo_lock_init(env, obj, lock, io);
                        if (err != 0) {
                                cl_lock_finish(env, lock);
                                lock = ERR_PTR(err);
                                break;
                        }
                }
        } else
                lock = ERR_PTR(-ENOMEM);
        RETURN(lock);
}

/**
 * Returns true iff lock is "suitable" for given io. E.g., locks acquired by
 * truncate and O_APPEND cannot be reused for read/non-append-write, as they
 * cover multiple stripes and can trigger cascading timeouts.
 */
static int cl_lock_fits_into(const struct lu_env *env,
                             const struct cl_lock *lock,
                             const struct cl_lock_descr *need,
                             const struct cl_io *io)
{
        const struct cl_lock_slice *slice;

        LINVRNT(cl_lock_invariant_trusted(env, lock));
        ENTRY;
        list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
                if (slice->cls_ops->clo_fits_into != NULL &&
                    !slice->cls_ops->clo_fits_into(env, slice, need, io))
                        RETURN(0);
        }
        RETURN(1);
}

static struct cl_lock *cl_lock_lookup(const struct lu_env *env,
                                      struct cl_object *obj,
                                      const struct cl_io *io,
                                      const struct cl_lock_descr *need)
{
        struct cl_lock          *lock;
        struct cl_object_header *head;
        struct cl_site          *site;

        ENTRY;

        head = cl_object_header(obj);
        site = cl_object_site(obj);
        LINVRNT(spin_is_locked(&head->coh_lock_guard));
        atomic_inc(&site->cs_locks.cs_lookup);
        list_for_each_entry(lock, &head->coh_locks, cll_linkage) {
                int matched;

                LASSERT(cl_is_lock(lock));
                matched = cl_lock_ext_match(&lock->cll_descr, need) &&
                        lock->cll_state < CLS_FREEING &&
                        !(lock->cll_flags & CLF_CANCELLED) &&
                        cl_lock_fits_into(env, lock, need, io);
                CDEBUG(D_DLMTRACE, "has: "DDESCR"(%i) need: "DDESCR": %d\n",
                       PDESCR(&lock->cll_descr), lock->cll_state, PDESCR(need),
                       matched);
                if (matched) {
                        cl_lock_get_trust(lock);
                        /* move the lock to the LRU head */
                        list_move(&lock->cll_linkage, &head->coh_locks);
                        atomic_inc(&cl_object_site(obj)->cs_locks.cs_hit);
                        RETURN(lock);
                }
        }
        RETURN(NULL);
}

/**
 * Returns a lock matching description \a need.
 *
 * This is the main entry point into the cl_lock caching interface. First, a
 * cache (implemented as a per-object linked list) is consulted. If lock is
 * found there, it is returned immediately. Otherwise new lock is allocated
 * and returned. In any case, additional reference to lock is acquired.
 *
 * \see cl_object_find(), cl_page_find()
 */
static struct cl_lock *cl_lock_find(const struct lu_env *env,
                                    const struct cl_io *io,
                                    const struct cl_lock_descr *need)
{
        struct cl_object_header *head;
        struct cl_object        *obj;
        struct cl_lock          *lock;
        struct cl_site          *site;

        ENTRY;

        obj  = need->cld_obj;
        head = cl_object_header(obj);
        site = cl_object_site(obj);

        spin_lock(&head->coh_lock_guard);
        lock = cl_lock_lookup(env, obj, io, need);
        spin_unlock(&head->coh_lock_guard);

        if (lock == NULL) {
                lock = cl_lock_alloc(env, obj, io, need);
                if (!IS_ERR(lock)) {
                        struct cl_lock *ghost;

                        spin_lock(&head->coh_lock_guard);
                        ghost = cl_lock_lookup(env, obj, io, need);
                        if (ghost == NULL) {
                                list_add(&lock->cll_linkage, &head->coh_locks);
                                spin_unlock(&head->coh_lock_guard);
                                atomic_inc(&site->cs_locks.cs_busy);
                        } else {
                                spin_unlock(&head->coh_lock_guard);
                                /*
                                 * Other threads can acquire references to the
                                 * top-lock through its sub-locks. Hence, it
                                 * cannot be cl_lock_free()-ed immediately.
                                 */
                                cl_lock_finish(env, lock);
                                lock = ghost;
                        }
                }
        }
        RETURN(lock);
}

/**
 * Returns existing lock matching given description. This is similar to
 * cl_lock_find() except that no new lock is created, and returned lock is
 * guaranteed to be in enum cl_lock_state::CLS_HELD state.
 */
struct cl_lock *cl_lock_peek(const struct lu_env *env, const struct cl_io *io,
                             const struct cl_lock_descr *need,
                             const char *scope, const void *source)
{
        struct cl_object_header *head;
        struct cl_object        *obj;
        struct cl_lock          *lock;

        obj  = need->cld_obj;
        head = cl_object_header(obj);

        spin_lock(&head->coh_lock_guard);
        lock = cl_lock_lookup(env, obj, io, need);
        spin_unlock(&head->coh_lock_guard);

        if (lock != NULL) {
                int ok;

                cl_lock_mutex_get(env, lock);
                if (lock->cll_state == CLS_CACHED)
                        cl_use_try(env, lock);
                ok = lock->cll_state == CLS_HELD;
                if (ok) {
                        cl_lock_hold_add(env, lock, scope, source);
                        cl_lock_user_add(env, lock);
                }
                cl_lock_mutex_put(env, lock);
                if (!ok) {
                        cl_lock_put(env, lock);
                        lock = NULL;
                }
        }
        return lock;
}
EXPORT_SYMBOL(cl_lock_peek);

/**
 * Returns a slice within a lock, corresponding to the given layer in the
 * device stack.
 *
 * \see cl_page_at()
 */
const struct cl_lock_slice *cl_lock_at(const struct cl_lock *lock,
                                       const struct lu_device_type *dtype)
{
        const struct cl_lock_slice *slice;

        LINVRNT(cl_lock_invariant_trusted(NULL, lock));
        ENTRY;

        list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
                if (slice->cls_obj->co_lu.lo_dev->ld_type == dtype)
                        RETURN(slice);
        }
        RETURN(NULL);
}
EXPORT_SYMBOL(cl_lock_at);

static void cl_lock_trace(struct cl_thread_info *info,
                          const char *prefix, const struct cl_lock *lock)
{
        CDEBUG(D_DLMTRACE|D_TRACE, "%s: %i@%p %p %i %i\n", prefix,
               atomic_read(&lock->cll_ref), lock, lock->cll_guarder,
               lock->cll_depth, info->clt_nr_locks_locked);
}

static void cl_lock_mutex_tail(const struct lu_env *env, struct cl_lock *lock)
{
        struct cl_thread_info *info;

        info = cl_env_info(env);
        lock->cll_depth++;
        info->clt_nr_locks_locked++;
        lu_ref_add(&info->clt_locks_locked, "cll_guard", lock);
        cl_lock_trace(info, "got mutex", lock);
}

/**
 * Locks cl_lock object.
 *
 * This is used to manipulate cl_lock fields, and to serialize state
 * transitions in the lock state machine.
 *
 * \post cl_lock_is_mutexed(lock)
 *
 * \see cl_lock_mutex_put()
 */
void cl_lock_mutex_get(const struct lu_env *env, struct cl_lock *lock)
{
        LINVRNT(cl_lock_invariant(env, lock));

        if (lock->cll_guarder == cfs_current()) {
                LINVRNT(cl_lock_is_mutexed(lock));
                LINVRNT(lock->cll_depth > 0);
        } else {
                struct cl_object_header *hdr;

                LINVRNT(lock->cll_guarder != cfs_current());
                hdr = cl_object_header(lock->cll_descr.cld_obj);
                mutex_lock_nested(&lock->cll_guard, hdr->coh_nesting);
                lock->cll_guarder = cfs_current();
                LINVRNT(lock->cll_depth == 0);
        }
        cl_lock_mutex_tail(env, lock);
}
EXPORT_SYMBOL(cl_lock_mutex_get);

/**
 * Try-locks cl_lock object.
 *
 * \retval 0 \a lock was successfully locked
 *
 * \retval -EBUSY \a lock cannot be locked right now
 *
 * \post ergo(result == 0, cl_lock_is_mutexed(lock))
 *
 * \see cl_lock_mutex_get()
 */
int cl_lock_mutex_try(const struct lu_env *env, struct cl_lock *lock)
{
        int result;

        LINVRNT(cl_lock_invariant_trusted(env, lock));
        ENTRY;

        result = 0;
        if (lock->cll_guarder == cfs_current()) {
                LINVRNT(lock->cll_depth > 0);
                cl_lock_mutex_tail(env, lock);
        } else if (mutex_trylock(&lock->cll_guard)) {
                LINVRNT(lock->cll_depth == 0);
                lock->cll_guarder = cfs_current();
                cl_lock_mutex_tail(env, lock);
        } else
                result = -EBUSY;
        RETURN(result);
}
EXPORT_SYMBOL(cl_lock_mutex_try);

/**
 * Unlocks cl_lock object.
 *
 * \pre cl_lock_is_mutexed(lock)
 *
 * \see cl_lock_mutex_get()
 */
void cl_lock_mutex_put(const struct lu_env *env, struct cl_lock *lock)
{
        struct cl_thread_info *info;

        LINVRNT(cl_lock_invariant(env, lock));
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(lock->cll_guarder == cfs_current());
        LINVRNT(lock->cll_depth > 0);

        info = cl_env_info(env);
        LINVRNT(info->clt_nr_locks_locked > 0);

        cl_lock_trace(info, "put mutex", lock);
        lu_ref_del(&info->clt_locks_locked, "cll_guard", lock);
        info->clt_nr_locks_locked--;
        if (--lock->cll_depth == 0) {
                lock->cll_guarder = NULL;
                mutex_unlock(&lock->cll_guard);
        }
}
EXPORT_SYMBOL(cl_lock_mutex_put);

/**
 * Returns true iff lock's mutex is owned by the current thread.
 */
int cl_lock_is_mutexed(struct cl_lock *lock)
{
        return lock->cll_guarder == cfs_current();
}
EXPORT_SYMBOL(cl_lock_is_mutexed);

/**
 * Returns number of cl_lock mutices held by the current thread (environment).
 */
int cl_lock_nr_mutexed(const struct lu_env *env)
{
        return cl_env_info(env)->clt_nr_locks_locked;
}
EXPORT_SYMBOL(cl_lock_nr_mutexed);

static void cl_lock_cancel0(const struct lu_env *env, struct cl_lock *lock)
{
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));
        ENTRY;
        if (!(lock->cll_flags & CLF_CANCELLED)) {
                const struct cl_lock_slice *slice;

                lock->cll_flags |= CLF_CANCELLED;
                list_for_each_entry_reverse(slice, &lock->cll_layers,
                                            cls_linkage) {
                        if (slice->cls_ops->clo_cancel != NULL)
                                slice->cls_ops->clo_cancel(env, slice);
                }
        }
        EXIT;
}

static void cl_lock_delete0(const struct lu_env *env, struct cl_lock *lock)
{
        struct cl_object_header    *head;
        const struct cl_lock_slice *slice;

        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));

        ENTRY;
        if (lock->cll_state < CLS_FREEING) {
                cl_lock_state_set(env, lock, CLS_FREEING);

                head = cl_object_header(lock->cll_descr.cld_obj);

                spin_lock(&head->coh_lock_guard);
                list_del_init(&lock->cll_linkage);
                /*
                 * No locks, no pages. This is only valid for bottom sub-locks
                 * and head->coh_nesting == 1 check assumes two level top-sub
                 * hierarchy.
                 */
                LASSERT(ergo(head->coh_nesting == 1 &&
                             list_empty(&head->coh_locks), !head->coh_pages));
                spin_unlock(&head->coh_lock_guard);
                /*
                 * From now on, no new references to this lock can be acquired
                 * by cl_lock_lookup().
                 */
                list_for_each_entry_reverse(slice, &lock->cll_layers,
                                            cls_linkage) {
                        if (slice->cls_ops->clo_delete != NULL)
                                slice->cls_ops->clo_delete(env, slice);
                }
                /*
                 * From now on, no new references to this lock can be acquired
                 * by layer-specific means (like a pointer from struct
                 * ldlm_lock in osc, or a pointer from top-lock to sub-lock in
                 * lov).
                 *
                 * Lock will be finally freed in cl_lock_put() when last of
                 * existing references goes away.
                 */
        }
        EXIT;
}

static void cl_lock_hold_mod(const struct lu_env *env, struct cl_lock *lock,
                             int delta)
{
        struct cl_thread_info   *cti;
        struct cl_object_header *hdr;

        cti = cl_env_info(env);
        hdr = cl_object_header(lock->cll_descr.cld_obj);
        lock->cll_holds += delta;
        if (hdr->coh_nesting == 0) {
                cti->clt_nr_held += delta;
                LASSERT(cti->clt_nr_held >= 0);
        }
}

static void cl_lock_used_mod(const struct lu_env *env, struct cl_lock *lock,
                             int delta)
{
        struct cl_thread_info   *cti;
        struct cl_object_header *hdr;

        cti = cl_env_info(env);
        hdr = cl_object_header(lock->cll_descr.cld_obj);
        lock->cll_users += delta;
        if (hdr->coh_nesting == 0) {
                cti->clt_nr_used += delta;
                LASSERT(cti->clt_nr_used >= 0);
        }
}

static void cl_lock_hold_release(const struct lu_env *env, struct cl_lock *lock,
                                 const char *scope, const void *source)
{
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));
        LASSERT(lock->cll_holds > 0);

        ENTRY;
        lu_ref_del(&lock->cll_holders, scope, source);
        cl_lock_hold_mod(env, lock, -1);
        if (lock->cll_holds == 0) {
                if (lock->cll_descr.cld_mode == CLM_PHANTOM)
                        /*
                         * If lock is still phantom when user is done with
                         * it---destroy the lock.
                         */
                        lock->cll_flags |= CLF_CANCELPEND|CLF_DOOMED;
                if (lock->cll_flags & CLF_CANCELPEND) {
                        lock->cll_flags &= ~CLF_CANCELPEND;
                        cl_lock_cancel0(env, lock);
                }
                if (lock->cll_flags & CLF_DOOMED) {
                        /* no longer doomed: it's dead... Jim. */
                        lock->cll_flags &= ~CLF_DOOMED;
                        cl_lock_delete0(env, lock);
                }
        }
        EXIT;
}


/**
 * Waits until lock state is changed.
 *
 * This function is called with cl_lock mutex locked, atomically releases
 * mutex and goes to sleep, waiting for a lock state change (signaled by
 * cl_lock_signal()), and re-acquires the mutex before return.
 *
 * This function is used to wait until lock state machine makes some progress
 * and to emulate synchronous operations on top of asynchronous lock
 * interface.
 *
 * \retval -EINTR wait was interrupted
 *
 * \retval 0 wait wasn't interrupted
 *
 * \pre cl_lock_is_mutexed(lock)
 *
 * \see cl_lock_signal()
 */
int cl_lock_state_wait(const struct lu_env *env, struct cl_lock *lock)
{
        cfs_waitlink_t waiter;
        int result;

        ENTRY;
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));
        LASSERT(lock->cll_depth == 1);
        LASSERT(lock->cll_state != CLS_FREEING); /* too late to wait */

        result = lock->cll_error;
        if (result == 0 && !(lock->cll_flags & CLF_STATE)) {
                cfs_waitlink_init(&waiter);
                cfs_waitq_add(&lock->cll_wq, &waiter);
                set_current_state(CFS_TASK_INTERRUPTIBLE);
                cl_lock_mutex_put(env, lock);

                LASSERT(cl_lock_nr_mutexed(env) == 0);
                cfs_waitq_wait(&waiter, CFS_TASK_INTERRUPTIBLE);

                cl_lock_mutex_get(env, lock);
                set_current_state(CFS_TASK_RUNNING);
                cfs_waitq_del(&lock->cll_wq, &waiter);
                result = cfs_signal_pending() ? -EINTR : 0;
        }
        lock->cll_flags &= ~CLF_STATE;
        RETURN(result);
}
EXPORT_SYMBOL(cl_lock_state_wait);

static void cl_lock_state_signal(const struct lu_env *env, struct cl_lock *lock,
                                 enum cl_lock_state state)
{
        const struct cl_lock_slice *slice;

        ENTRY;
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));

        list_for_each_entry(slice, &lock->cll_layers, cls_linkage)
                if (slice->cls_ops->clo_state != NULL)
                        slice->cls_ops->clo_state(env, slice, state);
        lock->cll_flags |= CLF_STATE;
        cfs_waitq_broadcast(&lock->cll_wq);
        EXIT;
}

/**
 * Notifies waiters that lock state changed.
 *
 * Wakes up all waiters sleeping in cl_lock_state_wait(), also notifies all
 * layers about state change by calling cl_lock_operations::clo_state()
 * top-to-bottom.
 */
void cl_lock_signal(const struct lu_env *env, struct cl_lock *lock)
{
        ENTRY;
        cl_lock_state_signal(env, lock, lock->cll_state);
        EXIT;
}
EXPORT_SYMBOL(cl_lock_signal);

/**
 * Changes lock state.
 *
 * This function is invoked to notify layers that lock state changed, possible
 * as a result of an asynchronous event such as call-back reception.
 *
 * \post lock->cll_state == state
 *
 * \see cl_lock_operations::clo_state()
 */
void cl_lock_state_set(const struct lu_env *env, struct cl_lock *lock,
                       enum cl_lock_state state)
{
        struct cl_site *site = cl_object_site(lock->cll_descr.cld_obj);

        ENTRY;
        LASSERT(lock->cll_state <= state ||
                (lock->cll_state == CLS_CACHED &&
                 (state == CLS_HELD || /* lock found in cache */
                  state == CLS_NEW     /* sub-lock canceled */)) ||
                /* sub-lock canceled during unlocking */
                (lock->cll_state == CLS_UNLOCKING && state == CLS_NEW));

        if (lock->cll_state != state) {
                atomic_dec(&site->cs_locks_state[lock->cll_state]);
                atomic_inc(&site->cs_locks_state[state]);

                cl_lock_state_signal(env, lock, state);
                lock->cll_state = state;
        }
        EXIT;
}
EXPORT_SYMBOL(cl_lock_state_set);

/**
 * Yanks lock from the cache (cl_lock_state::CLS_CACHED state) by calling
 * cl_lock_operations::clo_use() top-to-bottom to notify layers.
 */
int cl_use_try(const struct lu_env *env, struct cl_lock *lock)
{
        int result;
        const struct cl_lock_slice *slice;

        ENTRY;
        result = -ENOSYS;
        list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
                if (slice->cls_ops->clo_use != NULL) {
                        result = slice->cls_ops->clo_use(env, slice);
                        if (result != 0)
                                break;
                }
        }
        LASSERT(result != -ENOSYS);
        if (result == 0)
                cl_lock_state_set(env, lock, CLS_HELD);
        RETURN(result);
}
EXPORT_SYMBOL(cl_use_try);

/**
 * Helper for cl_enqueue_try() that calls ->clo_enqueue() across all layers
 * top-to-bottom.
 */
static int cl_enqueue_kick(const struct lu_env *env,
                           struct cl_lock *lock,
                           struct cl_io *io, __u32 flags)
{
        int result;
        const struct cl_lock_slice *slice;

        ENTRY;
        result = -ENOSYS;
        list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
                if (slice->cls_ops->clo_enqueue != NULL) {
                        result = slice->cls_ops->clo_enqueue(env,
                                                             slice, io, flags);
                        if (result != 0)
                                break;
                }
        }
        LASSERT(result != -ENOSYS);
        RETURN(result);
}

/**
 * Tries to enqueue a lock.
 *
 * This function is called repeatedly by cl_enqueue() until either lock is
 * enqueued, or error occurs. This function does not block waiting for
 * networking communication to complete.
 *
 * \post ergo(result == 0, lock->cll_state == CLS_ENQUEUED ||
 *                         lock->cll_state == CLS_HELD)
 *
 * \see cl_enqueue() cl_lock_operations::clo_enqueue()
 * \see cl_lock_state::CLS_ENQUEUED
 */
int cl_enqueue_try(const struct lu_env *env, struct cl_lock *lock,
                   struct cl_io *io, __u32 flags)
{
        int result;

        ENTRY;
        do {
                result = 0;

                LINVRNT(cl_lock_is_mutexed(lock));

                if (lock->cll_error != 0)
                        break;
                switch (lock->cll_state) {
                case CLS_NEW:
                        cl_lock_state_set(env, lock, CLS_QUEUING);
                        /* fall-through */
                case CLS_QUEUING:
                        /* kick layers. */
                        result = cl_enqueue_kick(env, lock, io, flags);
                        if (result == 0)
                                cl_lock_state_set(env, lock, CLS_ENQUEUED);
                        break;
                case CLS_UNLOCKING:
                        /* wait until unlocking finishes, and enqueue lock
                         * afresh. */
                        result = CLO_WAIT;
                        break;
                case CLS_CACHED:
                        /* yank lock from the cache. */
                        result = cl_use_try(env, lock);
                        break;
                case CLS_ENQUEUED:
                case CLS_HELD:
                        result = 0;
                        break;
                default:
                case CLS_FREEING:
                        /*
                         * impossible, only held locks with increased
                         * ->cll_holds can be enqueued, and they cannot be
                         * freed.
                         */
                        LBUG();
                }
        } while (result == CLO_REPEAT);
        if (result < 0)
                cl_lock_error(env, lock, result);
        RETURN(result ?: lock->cll_error);
}
EXPORT_SYMBOL(cl_enqueue_try);

static int cl_enqueue_locked(const struct lu_env *env, struct cl_lock *lock,
                             struct cl_io *io, __u32 enqflags)
{
        int result;

        ENTRY;

        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));
        LASSERT(lock->cll_holds > 0);

        cl_lock_user_add(env, lock);
        do {
                result = cl_enqueue_try(env, lock, io, enqflags);
                if (result == CLO_WAIT) {
                        result = cl_lock_state_wait(env, lock);
                        if (result == 0)
                                continue;
                }
                break;
        } while (1);
        if (result != 0) {
                cl_lock_user_del(env, lock);
                if (result != -EINTR)
                        cl_lock_error(env, lock, result);
        }
        LASSERT(ergo(result == 0, lock->cll_state == CLS_ENQUEUED ||
                     lock->cll_state == CLS_HELD));
        RETURN(result);
}

/**
 * Enqueues a lock.
 *
 * \pre current thread or io owns a hold on lock.
 *
 * \post ergo(result == 0, lock->users increased)
 * \post ergo(result == 0, lock->cll_state == CLS_ENQUEUED ||
 *                         lock->cll_state == CLS_HELD)
 */
int cl_enqueue(const struct lu_env *env, struct cl_lock *lock,
               struct cl_io *io, __u32 enqflags)
{
        int result;

        ENTRY;

        cl_lock_lockdep_acquire(env, lock, enqflags);
        cl_lock_mutex_get(env, lock);
        result = cl_enqueue_locked(env, lock, io, enqflags);
        cl_lock_mutex_put(env, lock);
        if (result != 0)
                cl_lock_lockdep_release(env, lock);
        LASSERT(ergo(result == 0, lock->cll_state == CLS_ENQUEUED ||
                     lock->cll_state == CLS_HELD));
        RETURN(result);
}
EXPORT_SYMBOL(cl_enqueue);

/**
 * Tries to unlock a lock.
 *
 * This function is called repeatedly by cl_unuse() until either lock is
 * unlocked, or error occurs.
 *
 * \ppre lock->cll_state <= CLS_HELD || lock->cll_state == CLS_UNLOCKING
 *
 * \post ergo(result == 0, lock->cll_state == CLS_CACHED)
 *
 * \see cl_unuse() cl_lock_operations::clo_unuse()
 * \see cl_lock_state::CLS_CACHED
 */
int cl_unuse_try(const struct lu_env *env, struct cl_lock *lock)
{
        const struct cl_lock_slice *slice;
        int                         result;

        ENTRY;
        if (lock->cll_state != CLS_UNLOCKING) {
                if (lock->cll_users > 1) {
                        cl_lock_user_del(env, lock);
                        RETURN(0);
                }
                /*
                 * New lock users (->cll_users) are not protecting unlocking
                 * from proceeding. From this point, lock eventually reaches
                 * CLS_CACHED, is reinitialized to CLS_NEW or fails into
                 * CLS_FREEING.
                 */
                cl_lock_state_set(env, lock, CLS_UNLOCKING);
        }
        do {
                result = 0;

                if (lock->cll_error != 0)
                        break;

                LINVRNT(cl_lock_is_mutexed(lock));
                LINVRNT(cl_lock_invariant(env, lock));
                LASSERT(lock->cll_state == CLS_UNLOCKING);
                LASSERT(lock->cll_users > 0);
                LASSERT(lock->cll_holds > 0);

                result = -ENOSYS;
                list_for_each_entry_reverse(slice, &lock->cll_layers,
                                            cls_linkage) {
                        if (slice->cls_ops->clo_unuse != NULL) {
                                result = slice->cls_ops->clo_unuse(env, slice);
                                if (result != 0)
                                        break;
                        }
                }
                LASSERT(result != -ENOSYS);
        } while (result == CLO_REPEAT);
        if (result != CLO_WAIT)
                /*
                 * Once there is no more need to iterate ->clo_unuse() calls,
                 * remove lock user. This is done even if unrecoverable error
                 * happened during unlocking, because nothing else can be
                 * done.
                 */
                cl_lock_user_del(env, lock);
        if (result == 0 || result == -ESTALE) {
                enum cl_lock_state state;

                /*
                 * Return lock back to the cache. This is the only
                 * place where lock is moved into CLS_CACHED state.
                 *
                 * If one of ->clo_unuse() methods returned -ESTALE, lock
                 * cannot be placed into cache and has to be
                 * re-initialized. This happens e.g., when a sub-lock was
                 * canceled while unlocking was in progress.
                 */
                state = result == 0 ? CLS_CACHED : CLS_NEW;
                cl_lock_state_set(env, lock, state);

                /*
                 * Hide -ESTALE error.
                 * If the lock is a glimpse lock, and it has multiple
                 * stripes. Assuming that one of its sublock returned -ENAVAIL,
                 * and other sublocks are matched write locks. In this case,
                 * we can't set this lock to error because otherwise some of
                 * its sublocks may not be canceled. This causes some dirty
                 * pages won't be written to OSTs. -jay
                 */
                result = 0;
        }
        result = result ?: lock->cll_error;
        if (result < 0)
                cl_lock_error(env, lock, result);
        RETURN(result);
}
EXPORT_SYMBOL(cl_unuse_try);

static void cl_unuse_locked(const struct lu_env *env, struct cl_lock *lock)
{
        ENTRY;
        LASSERT(lock->cll_state <= CLS_HELD);
        do {
                int result;

                result = cl_unuse_try(env, lock);
                if (result == CLO_WAIT) {
                        result = cl_lock_state_wait(env, lock);
                        if (result == 0)
                                continue;
                }
                break;
        } while (1);
        EXIT;
}

/**
 * Unlocks a lock.
 */
void cl_unuse(const struct lu_env *env, struct cl_lock *lock)
{
        ENTRY;
        cl_lock_mutex_get(env, lock);
        cl_unuse_locked(env, lock);
        cl_lock_mutex_put(env, lock);
        cl_lock_lockdep_release(env, lock);
        EXIT;
}
EXPORT_SYMBOL(cl_unuse);

/**
 * Tries to wait for a lock.
 *
 * This function is called repeatedly by cl_wait() until either lock is
 * granted, or error occurs. This function does not block waiting for network
 * communication to complete.
 *
 * \see cl_wait() cl_lock_operations::clo_wait()
 * \see cl_lock_state::CLS_HELD
 */
int cl_wait_try(const struct lu_env *env, struct cl_lock *lock)
{
        const struct cl_lock_slice *slice;
        int                         result;

        ENTRY;
        do {
                LINVRNT(cl_lock_is_mutexed(lock));
                LINVRNT(cl_lock_invariant(env, lock));
                LASSERT(lock->cll_state == CLS_ENQUEUED ||
                        lock->cll_state == CLS_HELD);
                LASSERT(lock->cll_users > 0);
                LASSERT(lock->cll_holds > 0);

                result = 0;
                if (lock->cll_error != 0)
                        break;
                if (lock->cll_state == CLS_HELD)
                        /* nothing to do */
                        break;

                result = -ENOSYS;
                list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
                        if (slice->cls_ops->clo_wait != NULL) {
                                result = slice->cls_ops->clo_wait(env, slice);
                                if (result != 0)
                                        break;
                        }
                }
                LASSERT(result != -ENOSYS);
                if (result == 0)
                        cl_lock_state_set(env, lock, CLS_HELD);
        } while (result == CLO_REPEAT);
        RETURN(result ?: lock->cll_error);
}
EXPORT_SYMBOL(cl_wait_try);

/**
 * Waits until enqueued lock is granted.
 *
 * \pre current thread or io owns a hold on the lock
 * \pre ergo(result == 0, lock->cll_state == CLS_ENQUEUED ||
 *                        lock->cll_state == CLS_HELD)
 *
 * \post ergo(result == 0, lock->cll_state == CLS_HELD)
 */
int cl_wait(const struct lu_env *env, struct cl_lock *lock)
{
        int result;

        ENTRY;
        cl_lock_mutex_get(env, lock);

        LINVRNT(cl_lock_invariant(env, lock));
        LASSERT(lock->cll_state == CLS_ENQUEUED || lock->cll_state == CLS_HELD);
        LASSERT(lock->cll_holds > 0);

        do {
                result = cl_wait_try(env, lock);
                if (result == CLO_WAIT) {
                        result = cl_lock_state_wait(env, lock);
                        if (result == 0)
                                continue;
                }
                break;
        } while (1);
        if (result < 0) {
                cl_lock_user_del(env, lock);
                if (result != -EINTR)
                        cl_lock_error(env, lock, result);
                cl_lock_lockdep_release(env, lock);
        }
        cl_lock_mutex_put(env, lock);
        LASSERT(ergo(result == 0, lock->cll_state == CLS_HELD));
        RETURN(result);
}
EXPORT_SYMBOL(cl_wait);

/**
 * Executes cl_lock_operations::clo_weigh(), and sums results to estimate lock
 * value.
 */
unsigned long cl_lock_weigh(const struct lu_env *env, struct cl_lock *lock)
{
        const struct cl_lock_slice *slice;
        unsigned long pound;
        unsigned long ounce;

        ENTRY;
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));

        pound = 0;
        list_for_each_entry_reverse(slice, &lock->cll_layers, cls_linkage) {
                if (slice->cls_ops->clo_weigh != NULL) {
                        ounce = slice->cls_ops->clo_weigh(env, slice);
                        pound += ounce;
                        if (pound < ounce) /* over-weight^Wflow */
                                pound = ~0UL;
                }
        }
        RETURN(pound);
}
EXPORT_SYMBOL(cl_lock_weigh);

/**
 * Notifies layers that lock description changed.
 *
 * The server can grant client a lock different from one that was requested
 * (e.g., larger in extent). This method is called when actually granted lock
 * description becomes known to let layers to accommodate for changed lock
 * description.
 *
 * \see cl_lock_operations::clo_modify()
 */
int cl_lock_modify(const struct lu_env *env, struct cl_lock *lock,
                   const struct cl_lock_descr *desc)
{
        const struct cl_lock_slice *slice;
        struct cl_object           *obj = lock->cll_descr.cld_obj;
        struct cl_object_header    *hdr = cl_object_header(obj);
        int result;

        ENTRY;
        /* don't allow object to change */
        LASSERT(obj == desc->cld_obj);
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));

        list_for_each_entry_reverse(slice, &lock->cll_layers, cls_linkage) {
                if (slice->cls_ops->clo_modify != NULL) {
                        result = slice->cls_ops->clo_modify(env, slice, desc);
                        if (result != 0)
                                RETURN(result);
                }
        }
        CL_LOCK_DEBUG(D_DLMTRACE, env, lock, " -> "DDESCR"@"DFID"\n",
                      PDESCR(desc), PFID(lu_object_fid(&desc->cld_obj->co_lu)));
        /*
         * Just replace description in place. Nothing more is needed for
         * now. If locks were indexed according to their extent and/or mode,
         * that index would have to be updated here.
         */
        spin_lock(&hdr->coh_lock_guard);
        lock->cll_descr = *desc;
        spin_unlock(&hdr->coh_lock_guard);
        RETURN(0);
}
EXPORT_SYMBOL(cl_lock_modify);

/**
 * Initializes lock closure with a given origin.
 *
 * \see cl_lock_closure
 */
void cl_lock_closure_init(const struct lu_env *env,
                          struct cl_lock_closure *closure,
                          struct cl_lock *origin, int wait)
{
        LINVRNT(cl_lock_is_mutexed(origin));
        LINVRNT(cl_lock_invariant(env, origin));

        CFS_INIT_LIST_HEAD(&closure->clc_list);
        closure->clc_origin = origin;
        closure->clc_wait   = wait;
        closure->clc_nr     = 0;
}
EXPORT_SYMBOL(cl_lock_closure_init);

/**
 * Builds a closure of \a lock.
 *
 * Building of a closure consists of adding initial lock (\a lock) into it,
 * and calling cl_lock_operations::clo_closure() methods of \a lock. These
 * methods might call cl_lock_closure_build() recursively again, adding more
 * locks to the closure, etc.
 *
 * \see cl_lock_closure
 */
int cl_lock_closure_build(const struct lu_env *env, struct cl_lock *lock,
                          struct cl_lock_closure *closure)
{
        const struct cl_lock_slice *slice;
        int result;

        ENTRY;
        LINVRNT(cl_lock_is_mutexed(closure->clc_origin));
        LINVRNT(cl_lock_invariant(env, closure->clc_origin));

        result = cl_lock_enclosure(env, lock, closure);
        if (result == 0) {
                list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
                        if (slice->cls_ops->clo_closure != NULL) {
                                result = slice->cls_ops->clo_closure(env, slice,
                                                                     closure);
                                if (result != 0)
                                        break;
                        }
                }
        }
        if (result != 0)
                cl_lock_disclosure(env, closure);
        RETURN(result);
}
EXPORT_SYMBOL(cl_lock_closure_build);

/**
 * Adds new lock to a closure.
 *
 * Try-locks \a lock and if succeeded, adds it to the closure (never more than
 * once). If try-lock failed, returns CLO_REPEAT, after optionally waiting
 * until next try-lock is likely to succeed.
 */
int cl_lock_enclosure(const struct lu_env *env, struct cl_lock *lock,
                      struct cl_lock_closure *closure)
{
        int result;
        ENTRY;
        if (!cl_lock_mutex_try(env, lock)) {
                /*
                 * If lock->cll_inclosure is not empty, lock is already in
                 * this closure.
                 */
                if (list_empty(&lock->cll_inclosure)) {
                        cl_lock_get_trust(lock);
                        lu_ref_add(&lock->cll_reference, "closure", closure);
                        list_add(&lock->cll_inclosure, &closure->clc_list);
                        closure->clc_nr++;
                } else
                        cl_lock_mutex_put(env, lock);
                result = 0;
        } else {
                cl_lock_disclosure(env, closure);
                if (closure->clc_wait) {
                        cl_lock_get_trust(lock);
                        lu_ref_add(&lock->cll_reference, "closure-w", closure);
                        cl_lock_mutex_put(env, closure->clc_origin);

                        LASSERT(cl_lock_nr_mutexed(env) == 0);
                        cl_lock_mutex_get(env, lock);
                        cl_lock_mutex_put(env, lock);

                        cl_lock_mutex_get(env, closure->clc_origin);
                        lu_ref_del(&lock->cll_reference, "closure-w", closure);
                        cl_lock_put(env, lock);
                }
                result = CLO_REPEAT;
        }
        RETURN(result);
}
EXPORT_SYMBOL(cl_lock_enclosure);

/** Releases mutices of enclosed locks. */
void cl_lock_disclosure(const struct lu_env *env,
                        struct cl_lock_closure *closure)
{
        struct cl_lock *scan;
        struct cl_lock *temp;

        list_for_each_entry_safe(scan, temp, &closure->clc_list, cll_inclosure){
                list_del_init(&scan->cll_inclosure);
                cl_lock_mutex_put(env, scan);
                lu_ref_del(&scan->cll_reference, "closure", closure);
                cl_lock_put(env, scan);
                closure->clc_nr--;
        }
        LASSERT(closure->clc_nr == 0);
}
EXPORT_SYMBOL(cl_lock_disclosure);

/** Finalizes a closure. */
void cl_lock_closure_fini(struct cl_lock_closure *closure)
{
        LASSERT(closure->clc_nr == 0);
        LASSERT(list_empty(&closure->clc_list));
}
EXPORT_SYMBOL(cl_lock_closure_fini);

/**
 * Destroys this lock. Notifies layers (bottom-to-top) that lock is being
 * destroyed, then destroy the lock. If there are holds on the lock, postpone
 * destruction until all holds are released. This is called when a decision is
 * made to destroy the lock in the future. E.g., when a blocking AST is
 * received on it, or fatal communication error happens.
 *
 * Caller must have a reference on this lock to prevent a situation, when
 * deleted lock lingers in memory for indefinite time, because nobody calls
 * cl_lock_put() to finish it.
 *
 * \pre atomic_read(&lock->cll_ref) > 0
 *
 * \see cl_lock_operations::clo_delete()
 * \see cl_lock::cll_holds
 */
void cl_lock_delete(const struct lu_env *env, struct cl_lock *lock)
{
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));

        ENTRY;
        if (lock->cll_holds == 0)
                cl_lock_delete0(env, lock);
        else
                lock->cll_flags |= CLF_DOOMED;
        EXIT;
}
EXPORT_SYMBOL(cl_lock_delete);

/**
 * Mark lock as irrecoverably failed, and mark it for destruction. This
 * happens when, e.g., server fails to grant a lock to us, or networking
 * time-out happens.
 *
 * \pre atomic_read(&lock->cll_ref) > 0
 *
 * \see clo_lock_delete()
 * \see cl_lock::cll_holds
 */
void cl_lock_error(const struct lu_env *env, struct cl_lock *lock, int error)
{
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));

        ENTRY;
        if (lock->cll_error == 0 && error != 0) {
                lock->cll_error = error;
                cl_lock_signal(env, lock);
                cl_lock_cancel(env, lock);
                cl_lock_delete(env, lock);
        }
        EXIT;
}
EXPORT_SYMBOL(cl_lock_error);

/**
 * Cancels this lock. Notifies layers
 * (bottom-to-top) that lock is being cancelled, then destroy the lock. If
 * there are holds on the lock, postpone cancellation until
 * all holds are released.
 *
 * Cancellation notification is delivered to layers at most once.
 *
 * \see cl_lock_operations::clo_cancel()
 * \see cl_lock::cll_holds
 */
void cl_lock_cancel(const struct lu_env *env, struct cl_lock *lock)
{
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));
        ENTRY;
        if (lock->cll_holds == 0)
                cl_lock_cancel0(env, lock);
        else
                lock->cll_flags |= CLF_CANCELPEND;
        EXIT;
}
EXPORT_SYMBOL(cl_lock_cancel);

/**
 * Finds an existing lock covering given page and optionally different from a
 * given \a except lock.
 */
struct cl_lock *cl_lock_at_page(const struct lu_env *env, struct cl_object *obj,
                                struct cl_page *page, struct cl_lock *except,
                                int pending, int canceld)
{
        struct cl_object_header *head;
        struct cl_lock          *scan;
        struct cl_lock          *lock;
        struct cl_lock_descr    *need;

        ENTRY;

        head = cl_object_header(obj);
        need = &cl_env_info(env)->clt_descr;
        lock = NULL;

        need->cld_mode = CLM_READ; /* CLM_READ matches both READ & WRITE, but
                                    * not PHANTOM */
        need->cld_start = need->cld_end = page->cp_index;

        spin_lock(&head->coh_lock_guard);
        list_for_each_entry(scan, &head->coh_locks, cll_linkage) {
                if (scan != except &&
                    cl_lock_ext_match(&scan->cll_descr, need) &&
                    scan->cll_state < CLS_FREEING &&
                    /*
                     * This check is racy as the lock can be canceled right
                     * after it is done, but this is fine, because page exists
                     * already.
                     */
                    (canceld || !(scan->cll_flags & CLF_CANCELLED)) &&
                    (pending || !(scan->cll_flags & CLF_CANCELPEND))) {
                        /* Don't increase cs_hit here since this
                         * is just a helper function. */
                        cl_lock_get_trust(scan);
                        lock = scan;
                        break;
                }
        }
        spin_unlock(&head->coh_lock_guard);
        RETURN(lock);
}
EXPORT_SYMBOL(cl_lock_at_page);

/**
 * Returns a list of pages protected (only) by a given lock.
 *
 * Scans an extent of page radix tree, corresponding to the \a lock and queues
 * all pages that are not protected by locks other than \a lock into \a queue.
 */
void cl_lock_page_list_fixup(const struct lu_env *env,
                             struct cl_io *io, struct cl_lock *lock,
                             struct cl_page_list *queue)
{
        struct cl_page        *page;
        struct cl_page        *temp;
        struct cl_page_list   *plist = &cl_env_info(env)->clt_list;

        LINVRNT(cl_lock_invariant(env, lock));
        ENTRY;

        /* Now, we have a list of cl_pages under the \a lock, we need
         * to check if some of pages are covered by other ldlm lock.
         * If this is the case, they aren't needed to be written out this time.
         *
         * For example, we have A:[0,200] & B:[100,300] PW locks on client, now
         * the latter is to be canceled, this means other client is
         * reading/writing [200,300] since A won't canceled. Actually
         * we just need to write the pages covered by [200,300]. This is safe,
         * since [100,200] is also protected lock A.
         */

        cl_page_list_init(plist);
        cl_page_list_for_each_safe(page, temp, queue) {
                pgoff_t                idx = page->cp_index;
                struct cl_lock        *found;
                struct cl_lock_descr  *descr;

                /* The algorithm counts on the index-ascending page index. */
                LASSERT(ergo(&temp->cp_batch != &queue->pl_pages,
                        page->cp_index < temp->cp_index));

                found = cl_lock_at_page(env, lock->cll_descr.cld_obj,
                                        page, lock, 0, 0);
                if (found == NULL)
                        continue;

                descr = &found->cll_descr;
                list_for_each_entry_safe_from(page, temp, &queue->pl_pages,
                                              cp_batch) {
                        idx = page->cp_index;
                        if (descr->cld_start > idx || descr->cld_end < idx)
                                break;
                        cl_page_list_move(plist, queue, page);
                }
                cl_lock_put(env, found);
        }

        /* The pages in plist are covered by other locks, don't handle them
         * this time.
         */
        if (io != NULL)
                cl_page_list_disown(env, io, plist);
        cl_page_list_fini(env, plist);
        EXIT;
}
EXPORT_SYMBOL(cl_lock_page_list_fixup);

/**
 * Invalidate pages protected by the given lock, sending them out to the
 * server first, if necessary.
 *
 * This function does the following:
 *
 *     - collects a list of pages to be invalidated,
 *
 *     - unmaps them from the user virtual memory,
 *
 *     - sends dirty pages to the server,
 *
 *     - waits for transfer completion,
 *
 *     - discards pages, and throws them out of memory.
 *
 * If \a discard is set, pages are discarded without sending them to the
 * server.
 *
 * If error happens on any step, the process continues anyway (the reasoning
 * behind this being that lock cancellation cannot be delayed indefinitely).
 */
int cl_lock_page_out(const struct lu_env *env, struct cl_lock *lock,
                     int discard)
{
        struct cl_thread_info *info  = cl_env_info(env);
        struct cl_io          *io    = &info->clt_io;
        struct cl_2queue      *queue = &info->clt_queue;
        struct cl_lock_descr  *descr = &lock->cll_descr;
        int                      result;
        int                      rc0;
        int                      rc1;

        LINVRNT(cl_lock_invariant(env, lock));
        ENTRY;

        io->ci_obj = cl_object_top(descr->cld_obj);
        result = cl_io_init(env, io, CIT_MISC, io->ci_obj);
        if (result == 0) {

                cl_2queue_init(queue);
                cl_page_gang_lookup(env, descr->cld_obj, io, descr->cld_start,
                                    descr->cld_end, &queue->c2_qin);
                if (queue->c2_qin.pl_nr > 0) {
                        result = cl_page_list_unmap(env, io, &queue->c2_qin);
                        if (!discard) {
                                rc0 = cl_io_submit_rw(env, io,
                                                      CRT_WRITE, queue);
                                rc1 = cl_page_list_own(env, io,
                                                       &queue->c2_qout);
                                result = result ?: rc0 ?: rc1;
                        }
                        cl_lock_page_list_fixup(env, io, lock, &queue->c2_qout);
                        cl_2queue_discard(env, io, queue);
                        cl_2queue_disown(env, io, queue);
                }
                cl_2queue_fini(env, queue);
        }
        cl_io_fini(env, io);
        RETURN(result);
}
EXPORT_SYMBOL(cl_lock_page_out);

/**
 * Eliminate all locks for a given object.
 *
 * Caller has to guarantee that no lock is in active use.
 *
 * \param cancel when this is set, cl_locks_prune() cancels locks before
 *               destroying.
 */
void cl_locks_prune(const struct lu_env *env, struct cl_object *obj, int cancel)
{
        struct cl_object_header *head;
        struct cl_lock          *lock;

        ENTRY;
        head = cl_object_header(obj);
        /*
         * If locks are destroyed without cancellation, all pages must be
         * already destroyed (as otherwise they will be left unprotected).
         */
        LASSERT(ergo(!cancel,
                     head->coh_tree.rnode == NULL && head->coh_pages == 0));

        spin_lock(&head->coh_lock_guard);
        while (!list_empty(&head->coh_locks)) {
                lock = container_of(head->coh_locks.next,
                                    struct cl_lock, cll_linkage);
                cl_lock_get_trust(lock);
                spin_unlock(&head->coh_lock_guard);
                lu_ref_add(&lock->cll_reference, "prune", cfs_current());
                cl_lock_mutex_get(env, lock);
                if (lock->cll_state < CLS_FREEING) {
                        LASSERT(lock->cll_holds == 0);
                        LASSERT(lock->cll_users == 0);
                        if (cancel)
                                cl_lock_cancel(env, lock);
                        cl_lock_delete(env, lock);
                }
                cl_lock_mutex_put(env, lock);
                lu_ref_del(&lock->cll_reference, "prune", cfs_current());
                cl_lock_put(env, lock);
                spin_lock(&head->coh_lock_guard);
        }
        spin_unlock(&head->coh_lock_guard);
        EXIT;
}
EXPORT_SYMBOL(cl_locks_prune);

/**
 * Returns true if \a addr is an address of an allocated cl_lock. Used in
 * assertions. This check is optimistically imprecise, i.e., it occasionally
 * returns true for the incorrect addresses, but if it returns false, then the
 * address is guaranteed to be incorrect. (Should be named cl_lockp().)
 *
 * \see cl_is_page()
 */
int cl_is_lock(const void *addr)
{
        return cfs_mem_is_in_cache(addr, cl_lock_kmem);
}
EXPORT_SYMBOL(cl_is_lock);

static struct cl_lock *cl_lock_hold_mutex(const struct lu_env *env,
                                          const struct cl_io *io,
                                          const struct cl_lock_descr *need,
                                          const char *scope, const void *source)
{
        struct cl_lock *lock;

        ENTRY;

        while (1) {
                lock = cl_lock_find(env, io, need);
                if (IS_ERR(lock))
                        break;
                cl_lock_mutex_get(env, lock);
                if (lock->cll_state < CLS_FREEING) {
                        cl_lock_hold_mod(env, lock, +1);
                        lu_ref_add(&lock->cll_holders, scope, source);
                        lu_ref_add(&lock->cll_reference, scope, source);
                        break;
                }
                cl_lock_mutex_put(env, lock);
                cl_lock_put(env, lock);
        }
        RETURN(lock);
}

/**
 * Returns a lock matching \a need description with a reference and a hold on
 * it.
 *
 * This is much like cl_lock_find(), except that cl_lock_hold() additionally
 * guarantees that lock is not in the CLS_FREEING state on return.
 */
struct cl_lock *cl_lock_hold(const struct lu_env *env, const struct cl_io *io,
                             const struct cl_lock_descr *need,
                             const char *scope, const void *source)
{
        struct cl_lock *lock;

        ENTRY;

        lock = cl_lock_hold_mutex(env, io, need, scope, source);
        if (!IS_ERR(lock))
                cl_lock_mutex_put(env, lock);
        RETURN(lock);
}
EXPORT_SYMBOL(cl_lock_hold);

/**
 * Main high-level entry point of cl_lock interface that finds existing or
 * enqueues new lock matching given description.
 */
struct cl_lock *cl_lock_request(const struct lu_env *env, struct cl_io *io,
                                const struct cl_lock_descr *need,
                                __u32 enqflags,
                                const char *scope, const void *source)
{
        struct cl_lock       *lock;
        const struct lu_fid  *fid;
        int                   rc;
        int                   iter;
        int warn;

        ENTRY;
        fid = lu_object_fid(&io->ci_obj->co_lu);
        iter = 0;
        do {
                warn = iter >= 16 && IS_PO2(iter);
                CDEBUG(warn ? D_WARNING : D_DLMTRACE,
                       DDESCR"@"DFID" %i %08x `%s'\n",
                       PDESCR(need), PFID(fid), iter, enqflags, scope);
                lock = cl_lock_hold_mutex(env, io, need, scope, source);
                if (!IS_ERR(lock)) {
                        rc = cl_enqueue_locked(env, lock, io, enqflags);
                        if (rc == 0) {
                                if (cl_lock_fits_into(env, lock, need, io)) {
                                        cl_lock_mutex_put(env, lock);
                                        cl_lock_lockdep_acquire(env,
                                                                lock, enqflags);
                                        break;
                                } else if (warn)
                                        CL_LOCK_DEBUG(D_WARNING, env, lock,
                                                      "got\n");
                                cl_unuse_locked(env, lock);
                        }
                        cl_lock_hold_release(env, lock, scope, source);
                        cl_lock_mutex_put(env, lock);
                        lu_ref_del(&lock->cll_reference, scope, source);
                        cl_lock_put(env, lock);
                        lock = ERR_PTR(rc);
                } else
                        rc = PTR_ERR(lock);
                iter++;
        } while (rc == 0);
        RETURN(lock);
}
EXPORT_SYMBOL(cl_lock_request);

/**
 * Adds a hold to a known lock.
 */
void cl_lock_hold_add(const struct lu_env *env, struct cl_lock *lock,
                      const char *scope, const void *source)
{
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));
        LASSERT(lock->cll_state != CLS_FREEING);

        ENTRY;
        cl_lock_hold_mod(env, lock, +1);
        cl_lock_get(lock);
        lu_ref_add(&lock->cll_holders, scope, source);
        lu_ref_add(&lock->cll_reference, scope, source);
        EXIT;
}
EXPORT_SYMBOL(cl_lock_hold_add);

/**
 * Releases a hold and a reference on a lock, on which caller acquired a
 * mutex.
 */
void cl_lock_unhold(const struct lu_env *env, struct cl_lock *lock,
                    const char *scope, const void *source)
{
        LINVRNT(cl_lock_invariant(env, lock));
        ENTRY;
        cl_lock_hold_release(env, lock, scope, source);
        lu_ref_del(&lock->cll_reference, scope, source);
        cl_lock_put(env, lock);
        EXIT;
}
EXPORT_SYMBOL(cl_lock_unhold);

/**
 * Releases a hold and a reference on a lock, obtained by cl_lock_hold().
 */
void cl_lock_release(const struct lu_env *env, struct cl_lock *lock,
                     const char *scope, const void *source)
{
        LINVRNT(cl_lock_invariant(env, lock));
        ENTRY;
        cl_lock_mutex_get(env, lock);
        cl_lock_hold_release(env, lock, scope, source);
        cl_lock_mutex_put(env, lock);
        lu_ref_del(&lock->cll_reference, scope, source);
        cl_lock_put(env, lock);
        EXIT;
}
EXPORT_SYMBOL(cl_lock_release);

void cl_lock_user_add(const struct lu_env *env, struct cl_lock *lock)
{
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));

        ENTRY;
        cl_lock_used_mod(env, lock, +1);
        EXIT;
}
EXPORT_SYMBOL(cl_lock_user_add);

int cl_lock_user_del(const struct lu_env *env, struct cl_lock *lock)
{
        LINVRNT(cl_lock_is_mutexed(lock));
        LINVRNT(cl_lock_invariant(env, lock));
        LASSERT(lock->cll_users > 0);

        ENTRY;
        cl_lock_used_mod(env, lock, -1);
        RETURN(lock->cll_users == 0);
}
EXPORT_SYMBOL(cl_lock_user_del);

/**
 * Check if two lock's mode are compatible.
 *
 * This returns true iff en-queuing \a lock2 won't cause cancellation of \a
 * lock1 even when these locks overlap.
 */
int cl_lock_compatible(const struct cl_lock *lock1, const struct cl_lock *lock2)
{
        enum cl_lock_mode mode1;
        enum cl_lock_mode mode2;

        ENTRY;
        mode1 = lock1->cll_descr.cld_mode;
        mode2 = lock2->cll_descr.cld_mode;
        RETURN(mode2 == CLM_PHANTOM ||
               (mode1 == CLM_READ && mode2 == CLM_READ));
}
EXPORT_SYMBOL(cl_lock_compatible);

const char *cl_lock_mode_name(const enum cl_lock_mode mode)
{
        static const char *names[] = {
                [CLM_PHANTOM] = "PHANTOM",
                [CLM_READ]    = "READ",
                [CLM_WRITE]   = "WRITE"
        };
        if (0 <= mode && mode < ARRAY_SIZE(names))
                return names[mode];
        else
                return "UNKNW";
}
EXPORT_SYMBOL(cl_lock_mode_name);

/**
 * Prints human readable representation of a lock description.
 */
void cl_lock_descr_print(const struct lu_env *env, void *cookie,
                       lu_printer_t printer,
                       const struct cl_lock_descr *descr)
{
        const struct lu_fid  *fid;

        fid = lu_object_fid(&descr->cld_obj->co_lu);
        (*printer)(env, cookie, DDESCR"@"DFID, PDESCR(descr), PFID(fid));
}
EXPORT_SYMBOL(cl_lock_descr_print);

/**
 * Prints human readable representation of \a lock to the \a f.
 */
void cl_lock_print(const struct lu_env *env, void *cookie,
                   lu_printer_t printer, const struct cl_lock *lock)
{
        const struct cl_lock_slice *slice;
        (*printer)(env, cookie, "lock@%p[%d %d %d %d %d %08lx] ",
                   lock, atomic_read(&lock->cll_ref),
                   lock->cll_state, lock->cll_error, lock->cll_holds,
                   lock->cll_users, lock->cll_flags);
        cl_lock_descr_print(env, cookie, printer, &lock->cll_descr);
        (*printer)(env, cookie, " {\n");

        list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
                (*printer)(env, cookie, "    %s@%p: ",
                           slice->cls_obj->co_lu.lo_dev->ld_type->ldt_name,
                           slice);
                if (slice->cls_ops->clo_print != NULL)
                        slice->cls_ops->clo_print(env, cookie, printer, slice);
                (*printer)(env, cookie, "\n");
        }
        (*printer)(env, cookie, "} lock@%p\n", lock);
}
EXPORT_SYMBOL(cl_lock_print);

int cl_lock_init(void)
{
        return lu_kmem_init(cl_lock_caches);
}

void cl_lock_fini(void)
{
        lu_kmem_fini(cl_lock_caches);
}
