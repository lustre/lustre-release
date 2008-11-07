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
 * Implementation of cl_lock for OSC layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

/** \addtogroup osc osc @{ */

#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else
# include <liblustre.h>
#endif
/* fid_build_reg_res_name() */
#include <lustre_fid.h>

#include "osc_cl_internal.h"

/*****************************************************************************
 *
 * Type conversions.
 *
 */

static const struct cl_lock_operations osc_lock_ops;
static const struct cl_lock_operations osc_lock_lockless_ops;

int osc_lock_is_lockless(const struct osc_lock *olck)
{
        return (olck->ols_cl.cls_ops == &osc_lock_lockless_ops);
}

/**
 * Returns a weak pointer to the ldlm lock identified by a handle. Returned
 * pointer cannot be dereferenced, as lock is not protected from concurrent
 * reclaim. This function is a helper for osc_lock_invariant().
 */
static struct ldlm_lock *osc_handle_ptr(struct lustre_handle *handle)
{
        struct ldlm_lock *lock;

        lock = ldlm_handle2lock(handle);
        if (lock != NULL)
                LDLM_LOCK_PUT(lock);
        return lock;
}

/**
 * Invariant that has to be true all of the time.
 */
static int osc_lock_invariant(struct osc_lock *ols)
{
        struct ldlm_lock *lock        = osc_handle_ptr(&ols->ols_handle);
        struct ldlm_lock *olock       = ols->ols_lock;
        int               handle_used = lustre_handle_is_used(&ols->ols_handle);

        return
                ergo(osc_lock_is_lockless(ols),
                     ols->ols_locklessable && ols->ols_lock == NULL)  ||
                (ergo(olock != NULL, handle_used) &&
                 ergo(olock != NULL,
                      olock->l_handle.h_cookie == ols->ols_handle.cookie) &&
                 /*
                  * Check that ->ols_handle and ->ols_lock are consistent, but
                  * take into account that they are set at the different time.
                  */
                 ergo(handle_used,
                      ergo(lock != NULL && olock != NULL, lock == olock) &&
                      ergo(lock == NULL, olock == NULL)) &&
                 ergo(ols->ols_state == OLS_CANCELLED,
                      olock == NULL && !handle_used) &&
                 /*
                  * DLM lock is destroyed only after we have seen cancellation
                  * ast.
                  */
                 ergo(olock != NULL && ols->ols_state < OLS_CANCELLED,
                      !olock->l_destroyed) &&
                 ergo(ols->ols_state == OLS_GRANTED,
                      olock != NULL &&
                      olock->l_req_mode == olock->l_granted_mode &&
                      ols->ols_hold));
}

/*****************************************************************************
 *
 * Lock operations.
 *
 */

/**
 * Breaks a link between osc_lock and dlm_lock.
 */
static void osc_lock_detach(const struct lu_env *env, struct osc_lock *olck)
{
        struct ldlm_lock *dlmlock;

        spin_lock(&osc_ast_guard);
        dlmlock = olck->ols_lock;
        if (dlmlock == NULL) {
                spin_unlock(&osc_ast_guard);
                return;
        }

        olck->ols_lock = NULL;
        /* wb(); --- for all who checks (ols->ols_lock != NULL) before
         * call to osc_lock_detach() */
        dlmlock->l_ast_data = NULL;
        olck->ols_handle.cookie = 0ULL;
        spin_unlock(&osc_ast_guard);

        lock_res_and_lock(dlmlock);
        if (dlmlock->l_granted_mode == dlmlock->l_req_mode) {
                struct cl_object *obj = olck->ols_cl.cls_obj;
                struct cl_attr *attr  = &osc_env_info(env)->oti_attr;
                __u64 old_kms = cl2osc(obj)->oo_oinfo->loi_kms;

                /* Update the kms. Need to loop all granted locks.
                 * Not a problem for the client */
                attr->cat_kms = ldlm_extent_shift_kms(dlmlock, old_kms);
                unlock_res_and_lock(dlmlock);

                cl_object_attr_lock(obj);
                cl_object_attr_set(env, obj, attr, CAT_KMS);
                cl_object_attr_unlock(obj);
        } else
                unlock_res_and_lock(dlmlock);

        /* release a reference taken in osc_lock_upcall0(). */
        lu_ref_del(&dlmlock->l_reference, "osc_lock", olck);
        LDLM_LOCK_RELEASE(dlmlock);
}

static int osc_lock_unuse(const struct lu_env *env,
                          const struct cl_lock_slice *slice)
{
        struct osc_lock *ols = cl2osc_lock(slice);
        int result;

        LASSERT(ols->ols_state == OLS_GRANTED ||
                ols->ols_state == OLS_UPCALL_RECEIVED);
        LINVRNT(osc_lock_invariant(ols));

        if (ols->ols_glimpse) {
                LASSERT(ols->ols_hold == 0);
                return 0;
        }
        LASSERT(ols->ols_hold);

        /*
         * Move lock into OLS_RELEASED state before calling osc_cancel_base()
         * so that possible synchronous cancellation (that always happens
         * e.g., for liblustre) sees that lock is released.
         */
        ols->ols_state = OLS_RELEASED;
        ols->ols_hold = 0;
        result = osc_cancel_base(&ols->ols_handle, ols->ols_einfo.ei_mode);
        ols->ols_has_ref = 0;
        return result;
}

static void osc_lock_fini(const struct lu_env *env,
                          struct cl_lock_slice *slice)
{
        struct osc_lock  *ols = cl2osc_lock(slice);

        LINVRNT(osc_lock_invariant(ols));
        /*
         * ->ols_hold can still be true at this point if, for example, a
         * thread that requested a lock was killed (and released a reference
         * to the lock), before reply from a server was received. In this case
         * lock is destroyed immediately after upcall.
         */
        if (ols->ols_hold)
                osc_lock_unuse(env, slice);
        if (ols->ols_lock != NULL)
                osc_lock_detach(env, ols);

        OBD_SLAB_FREE_PTR(ols, osc_lock_kmem);
}

void osc_lock_build_res(const struct lu_env *env, const struct osc_object *obj,
                        struct ldlm_res_id *resname)
{
        const struct lu_fid *fid = lu_object_fid(&obj->oo_cl.co_lu);
        if (0) {
                /*
                 * In the perfect world of the future, where ost servers talk
                 * idif-fids...
                 */
                fid_build_reg_res_name(fid, resname);
        } else {
                /*
                 * In reality, where ost server expects ->lsm_object_id and
                 * ->lsm_object_gr in rename.
                 */
                osc_build_res_name(obj->oo_oinfo->loi_id, obj->oo_oinfo->loi_gr,
                                   resname);
        }
}

static void osc_lock_build_policy(const struct lu_env *env,
                                  const struct cl_lock *lock,
                                  ldlm_policy_data_t *policy)
{
        const struct cl_lock_descr *d = &lock->cll_descr;

        osc_index2policy(policy, d->cld_obj, d->cld_start, d->cld_end);
}

static int osc_enq2ldlm_flags(__u32 enqflags)
{
        int result = 0;

        LASSERT((enqflags & ~(CEF_NONBLOCK|CEF_ASYNC|CEF_DISCARD_DATA)) == 0);

        if (enqflags & CEF_NONBLOCK)
                result |= LDLM_FL_BLOCK_NOWAIT;
        if (enqflags & CEF_ASYNC)
                result |= LDLM_FL_HAS_INTENT;
        if (enqflags & CEF_DISCARD_DATA)
                result |= LDLM_AST_DISCARD_DATA;
        return result;
}

/**
 * Global spin-lock protecting consistency of ldlm_lock::l_ast_data
 * pointers. Initialized in osc_init().
 */
spinlock_t osc_ast_guard;

static struct osc_lock *osc_ast_data_get(struct ldlm_lock *dlm_lock)
{
        struct osc_lock *olck;

        lock_res_and_lock(dlm_lock);
        spin_lock(&osc_ast_guard);
        olck = dlm_lock->l_ast_data;
        if (olck != NULL) {
                struct cl_lock *lock = olck->ols_cl.cls_lock;
                /*
                 * If osc_lock holds a reference on ldlm lock, return it even
                 * when cl_lock is in CLS_FREEING state. This way
                 *
                 *         osc_ast_data_get(dlmlock) == NULL
                 *
                 * guarantees that all osc references on dlmlock were
                 * released. osc_dlm_blocking_ast0() relies on that.
                 */
                if (lock->cll_state < CLS_FREEING || olck->ols_has_ref) {
                        cl_lock_get_trust(lock);
                        lu_ref_add_atomic(&lock->cll_reference,
                                          "ast", cfs_current());
                } else
                        olck = NULL;
        }
        spin_unlock(&osc_ast_guard);
        unlock_res_and_lock(dlm_lock);
        return olck;
}

static void osc_ast_data_put(const struct lu_env *env, struct osc_lock *olck)
{
        struct cl_lock *lock;

        lock = olck->ols_cl.cls_lock;
        lu_ref_del(&lock->cll_reference, "ast", cfs_current());
        cl_lock_put(env, lock);
}

static void osc_lock_to_lockless(struct osc_lock *olck)
{
        struct cl_lock_slice *slice = &olck->ols_cl;
        struct cl_lock  *lock       = slice->cls_lock;

        /*
         * TODO: Discover which locks we need to convert the lock
         * to ldlmlockless.
         */
        LASSERT(cl_lock_is_mutexed(lock));
        slice->cls_ops = &osc_lock_lockless_ops;
}

/**
 * Updates object attributes from a lock value block (lvb) received together
 * with the DLM lock reply from the server. Copy of osc_update_enqueue()
 * logic.
 *
 * This can be optimized to not update attributes when lock is a result of a
 * local match.
 */
static void osc_lock_lvb_update(const struct lu_env *env, struct osc_lock *olck,
                                int rc)
{
        struct ost_lvb    *lvb;
        struct cl_object  *obj;
        struct lov_oinfo  *oinfo;
        struct cl_attr    *attr;
        unsigned           valid;

        ENTRY;

        if (!(olck->ols_flags & LDLM_FL_LVB_READY)) {
                EXIT;
                return;
        }

        lvb   = &olck->ols_lvb;
        obj   = olck->ols_cl.cls_obj;
        oinfo = cl2osc(obj)->oo_oinfo;
        attr  = &osc_env_info(env)->oti_attr;
        valid = CAT_BLOCKS | CAT_ATIME | CAT_CTIME | CAT_MTIME | CAT_SIZE;
        cl_lvb2attr(attr, lvb);

        cl_object_attr_lock(obj);
        if (rc == 0) {
                struct ldlm_lock  *dlmlock;
                __u64 size;

                dlmlock = olck->ols_lock;
                LASSERT(dlmlock != NULL);

                size = lvb->lvb_size;
                /* Extend KMS up to the end of this lock and no further
                 * A lock on [x,y] means a KMS of up to y + 1 bytes! */
                if (size > dlmlock->l_policy_data.l_extent.end)
                        size = dlmlock->l_policy_data.l_extent.end + 1;
                if (size >= oinfo->loi_kms) {
                        LDLM_DEBUG(dlmlock, "lock acquired, setting rss="LPU64
                                   ", kms="LPU64, lvb->lvb_size, size);
                        valid |= CAT_KMS;
                        attr->cat_kms = size;
                } else {
                        LDLM_DEBUG(dlmlock, "lock acquired, setting rss="
                                   LPU64"; leaving kms="LPU64", end="LPU64,
                                   lvb->lvb_size, oinfo->loi_kms,
                                   dlmlock->l_policy_data.l_extent.end);
                }
                ldlm_lock_allow_match(dlmlock);
        } else if (rc == -ENAVAIL && olck->ols_glimpse) {
                CDEBUG(D_INODE, "glimpsed, setting rss="LPU64"; leaving"
                       " kms="LPU64"\n", lvb->lvb_size, oinfo->loi_kms);
        } else
                valid = 0;

        if (valid != 0)
                cl_object_attr_set(env, obj, attr, valid);

        cl_object_attr_unlock(obj);

        EXIT;
}

static void osc_lock_granted(const struct lu_env *env, struct osc_lock *olck,
                             struct ldlm_lock *dlmlock, int rc)
{
        struct ldlm_extent   *ext;
        struct cl_lock       *lock;
        struct cl_lock_descr *descr;

        LASSERT(dlmlock->l_granted_mode == dlmlock->l_req_mode);

        ENTRY;
        if (olck->ols_state != OLS_GRANTED) {
                lock  = olck->ols_cl.cls_lock;
                ext   = &dlmlock->l_policy_data.l_extent;
                descr = &osc_env_info(env)->oti_descr;
                descr->cld_obj = lock->cll_descr.cld_obj;

                /* XXX check that ->l_granted_mode is valid. */
                descr->cld_mode  = osc_ldlm2cl_lock(dlmlock->l_granted_mode);
                descr->cld_start = cl_index(descr->cld_obj, ext->start);
                descr->cld_end   = cl_index(descr->cld_obj, ext->end);
                /*
                 * tell upper layers the extent of the lock that was actually
                 * granted
                 */
                cl_lock_modify(env, lock, descr);
                LINVRNT(osc_lock_invariant(olck));
                olck->ols_state = OLS_GRANTED;
                osc_lock_lvb_update(env, olck, rc);
                cl_lock_signal(env, lock);
        }
        EXIT;
}

static void osc_lock_upcall0(const struct lu_env *env, struct osc_lock *olck)

{
        struct ldlm_lock *dlmlock;

        ENTRY;

        dlmlock = ldlm_handle2lock_long(&olck->ols_handle, 0);
        LASSERT(dlmlock != NULL);

        lock_res_and_lock(dlmlock);
        spin_lock(&osc_ast_guard);
        LASSERT(dlmlock->l_ast_data == olck);
        LASSERT(olck->ols_lock == NULL);
        olck->ols_lock = dlmlock;
        spin_unlock(&osc_ast_guard);
        unlock_res_and_lock(dlmlock);

        /*
         * Lock might be not yet granted. In this case, completion ast
         * (osc_ldlm_completion_ast()) comes later and finishes lock
         * granting.
         */
        if (dlmlock->l_granted_mode == dlmlock->l_req_mode)
                osc_lock_granted(env, olck, dlmlock, 0);
        /*
         * osc_enqueue_interpret() decrefs asynchronous locks, counter
         * this.
         */
        ldlm_lock_addref(&olck->ols_handle, olck->ols_einfo.ei_mode);
        olck->ols_hold = olck->ols_has_ref = 1;

        /* lock reference taken by ldlm_handle2lock_long() is owned by
         * osc_lock and released in osc_lock_detach() */
        lu_ref_add(&dlmlock->l_reference, "osc_lock", olck);
}

/**
 * Lock upcall function that is executed either when a reply to ENQUEUE rpc is
 * received from a server, or after osc_enqueue_base() matched a local DLM
 * lock.
 */
static int osc_lock_upcall(void *cookie, int errcode)
{
        struct osc_lock      *olck  = cookie;
        struct cl_lock_slice *slice = &olck->ols_cl;
        struct cl_lock       *lock  = slice->cls_lock;
        struct lu_env        *env;

        int refcheck;

        ENTRY;
        /*
         * XXX environment should be created in ptlrpcd.
         */
        env = cl_env_get(&refcheck);
        if (!IS_ERR(env)) {
                int rc;

                cl_lock_mutex_get(env, lock);

                LASSERT(lock->cll_state >= CLS_QUEUING);
                if (olck->ols_state == OLS_ENQUEUED) {
                        olck->ols_state = OLS_UPCALL_RECEIVED;
                        rc = ldlm_error2errno(errcode);
                } else if (olck->ols_state == OLS_CANCELLED) {
                        rc = -EIO;
                } else {
                        CERROR("Impossible state: %i\n", olck->ols_state);
                        LBUG();
                }
                if (rc) {
                        struct ldlm_lock *dlmlock;

                        dlmlock = ldlm_handle2lock(&olck->ols_handle);
                        if (dlmlock != NULL) {
                                lock_res_and_lock(dlmlock);
                                spin_lock(&osc_ast_guard);
                                LASSERT(olck->ols_lock == NULL);
                                dlmlock->l_ast_data = NULL;
                                olck->ols_handle.cookie = 0ULL;
                                spin_unlock(&osc_ast_guard);
                                unlock_res_and_lock(dlmlock);
                                LDLM_LOCK_PUT(dlmlock);
                        }
                } else {
                        if (olck->ols_glimpse)
                                olck->ols_glimpse = 0;
                        osc_lock_upcall0(env, olck);
                }

                /* Error handling, some errors are tolerable. */
                if (olck->ols_locklessable && rc == -EUSERS) {
                        /* This is a tolerable error, turn this lock into
                         * lockless lock.
                         */
                        osc_object_set_contended(cl2osc(slice->cls_obj));
                        LASSERT(slice->cls_ops == &osc_lock_ops);

                        /* Change this lock to ldlmlock-less lock. */
                        osc_lock_to_lockless(olck);
                        olck->ols_state = OLS_GRANTED;
                        rc = 0;
                } else if (olck->ols_glimpse && rc == -ENAVAIL) {
                        osc_lock_lvb_update(env, olck, rc);
                        cl_lock_delete(env, lock);
                        /* Hide the error. */
                        rc = 0;
                }

                if (rc == 0)
                        /* on error, lock was signaled by cl_lock_error() */
                        cl_lock_signal(env, lock);
                else
                        cl_lock_error(env, lock, rc);

                cl_lock_mutex_put(env, lock);

                /* release cookie reference, acquired by osc_lock_enqueue() */
                lu_ref_del(&lock->cll_reference, "upcall", lock);
                cl_lock_put(env, lock);
                cl_env_put(env, &refcheck);
        } else
                /* should never happen, similar to osc_ldlm_blocking_ast(). */
                LBUG();
        RETURN(errcode);
}

/**
 * Core of osc_dlm_blocking_ast() logic.
 */
static void osc_lock_blocking(const struct lu_env *env,
                              struct ldlm_lock *dlmlock,
                              struct osc_lock *olck, int blocking)
{
        struct cl_lock *lock = olck->ols_cl.cls_lock;

        LASSERT(olck->ols_lock == dlmlock);
        CLASSERT(OLS_BLOCKED < OLS_CANCELLED);
        LASSERT(!osc_lock_is_lockless(olck));

        if (olck->ols_hold)
                /*
                 * Lock might be still addref-ed here, if e.g., blocking ast
                 * is sent for a failed lock.
                 */
                osc_lock_unuse(env, &olck->ols_cl);

        if (blocking && olck->ols_state < OLS_BLOCKED)
                /*
                 * Move osc_lock into OLS_BLOCKED before canceling the lock,
                 * because it recursively re-enters osc_lock_blocking(), with
                 * the state set to OLS_CANCELLED.
                 */
                olck->ols_state = OLS_BLOCKED;
        /*
         * cancel and destroy lock at least once no matter how blocking ast is
         * entered (see comment above osc_ldlm_blocking_ast() for use
         * cases). cl_lock_cancel() and cl_lock_delete() are idempotent.
         */
        cl_lock_cancel(env, lock);
        cl_lock_delete(env, lock);
}

/**
 * Helper for osc_dlm_blocking_ast() handling discrepancies between cl_lock
 * and ldlm_lock caches.
 */
static int osc_dlm_blocking_ast0(const struct lu_env *env,
                                 struct ldlm_lock *dlmlock,
                                 void *data, int flag)
{
        struct osc_lock *olck;
        struct cl_lock  *lock;
        int result;
        int cancel;

        LASSERT(flag == LDLM_CB_BLOCKING || flag == LDLM_CB_CANCELING);

        cancel = 0;
        olck = osc_ast_data_get(dlmlock);
        if (olck != NULL) {
                lock = olck->ols_cl.cls_lock;
                cl_lock_mutex_get(env, lock);
                LINVRNT(osc_lock_invariant(olck));
                if (olck->ols_ast_wait) {
                        /* wake up osc_lock_use() */
                        cl_lock_signal(env, lock);
                        olck->ols_ast_wait = 0;
                }
                /*
                 * Lock might have been canceled while this thread was
                 * sleeping for lock mutex, but olck is pinned in memory.
                 */
                if (olck == dlmlock->l_ast_data) {
                        /*
                         * NOTE: DLM sends blocking AST's for failed locks
                         *       (that are still in pre-OLS_GRANTED state)
                         *       too, and they have to be canceled otherwise
                         *       DLM lock is never destroyed and stuck in
                         *       the memory.
                         *
                         *       Alternatively, ldlm_cli_cancel() can be
                         *       called here directly for osc_locks with
                         *       ols_state < OLS_GRANTED to maintain an
                         *       invariant that ->clo_cancel() is only called
                         *       for locks that were granted.
                         */
                        LASSERT(data == olck);
                        osc_lock_blocking(env, dlmlock,
                                          olck, flag == LDLM_CB_BLOCKING);
                } else
                        cancel = 1;
                cl_lock_mutex_put(env, lock);
                osc_ast_data_put(env, olck);
        } else
                /*
                 * DLM lock exists, but there is no cl_lock attached to it.
                 * This is a `normal' race. cl_object and its cl_lock's can be
                 * removed by memory pressure, together with all pages.
                 */
                cancel = (flag == LDLM_CB_BLOCKING);

        if (cancel) {
                struct lustre_handle *lockh;

                lockh = &osc_env_info(env)->oti_handle;
                ldlm_lock2handle(dlmlock, lockh);
                result = ldlm_cli_cancel(lockh);
        } else
                result = 0;
        return result;
}

/**
 * Blocking ast invoked by ldlm when dlm lock is either blocking progress of
 * some other lock, or is canceled. This function is installed as a
 * ldlm_lock::l_blocking_ast() for client extent locks.
 *
 * Control flow is tricky, because ldlm uses the same call-back
 * (ldlm_lock::l_blocking_ast()) for both blocking and cancellation ast's.
 *
 * \param dlmlock lock for which ast occurred.
 *
 * \param new description of a conflicting lock in case of blocking ast.
 *
 * \param data value of dlmlock->l_ast_data
 *
 * \param flag LDLM_CB_BLOCKING or LDLM_CB_CANCELING. Used to distinguish
 *             cancellation and blocking ast's.
 *
 * Possible use cases:
 *
 *     - ldlm calls dlmlock->l_blocking_ast(..., LDLM_CB_CANCELING) to cancel
 *       lock due to lock lru pressure, or explicit user request to purge
 *       locks.
 *
 *     - ldlm calls dlmlock->l_blocking_ast(..., LDLM_CB_BLOCKING) to notify
 *       us that dlmlock conflicts with another lock that some client is
 *       enqueing. Lock is canceled.
 *
 *           - cl_lock_cancel() is called. osc_lock_cancel() calls
 *             ldlm_cli_cancel() that calls
 *
 *                  dlmlock->l_blocking_ast(..., LDLM_CB_CANCELING)
 *
 *             recursively entering osc_ldlm_blocking_ast().
 *
 *     - client cancels lock voluntary (e.g., as a part of early cancellation):
 *
 *           cl_lock_cancel()->
 *             osc_lock_cancel()->
 *               ldlm_cli_cancel()->
 *                 dlmlock->l_blocking_ast(..., LDLM_CB_CANCELING)
 *
 */
static int osc_ldlm_blocking_ast(struct ldlm_lock *dlmlock,
                                 struct ldlm_lock_desc *new, void *data,
                                 int flag)
{
        struct lu_env     *env;
        struct cl_env_nest nest;
        int                result;

        /*
         * This can be called in the context of outer IO, e.g.,
         *
         *     cl_enqueue()->...
         *       ->osc_enqueue_base()->...
         *         ->ldlm_prep_elc_req()->...
         *           ->ldlm_cancel_callback()->...
         *             ->osc_ldlm_blocking_ast()
         *
         * new environment has to be created to not corrupt outer context.
         */
        env = cl_env_nested_get(&nest);
        if (!IS_ERR(env))
                result = osc_dlm_blocking_ast0(env, dlmlock, data, flag);
        else {
                result = PTR_ERR(env);
                /*
                 * XXX This should never happen, as cl_lock is
                 * stuck. Pre-allocated environment a la vvp_inode_fini_env
                 * should be used.
                 */
                LBUG();
        }
        if (result != 0) {
                if (result == -ENODATA)
                        result = 0;
                else
                        CERROR("BAST failed: %d\n", result);
        }
        cl_env_nested_put(&nest, env);
        return result;
}

static int osc_ldlm_completion_ast(struct ldlm_lock *dlmlock,
                                   int flags, void *data)
{
        struct lu_env   *env;
        void            *env_cookie;
        struct osc_lock *olck;
        struct cl_lock  *lock;
        int refcheck;
        int result;
        int dlmrc;

        /* first, do dlm part of the work */
        dlmrc = ldlm_completion_ast_async(dlmlock, flags, data);
        /* then, notify cl_lock */
        env_cookie = cl_env_reenter();
        env = cl_env_get(&refcheck);
        if (!IS_ERR(env)) {
                olck = osc_ast_data_get(dlmlock);
                if (olck != NULL) {
                        lock = olck->ols_cl.cls_lock;
                        cl_lock_mutex_get(env, lock);
                        /*
                         * ldlm_handle_cp_callback() copied LVB from request
                         * to lock->l_lvb_data, store it in osc_lock.
                         */
                        LASSERT(dlmlock->l_lvb_data != NULL);
                        olck->ols_lvb = *(struct ost_lvb *)dlmlock->l_lvb_data;
                        if (olck->ols_lock == NULL)
                                /*
                                 * upcall (osc_lock_upcall()) hasn't yet been
                                 * called. Do nothing now, upcall will bind
                                 * olck to dlmlock and signal the waiters.
                                 *
                                 * This maintains an invariant that osc_lock
                                 * and ldlm_lock are always bound when
                                 * osc_lock is in OLS_GRANTED state.
                                 */
                                ;
                        else if (dlmlock->l_granted_mode != LCK_MINMODE)
                                osc_lock_granted(env, olck, dlmlock, dlmrc);
                        if (dlmrc != 0)
                                cl_lock_error(env, lock, dlmrc);
                        cl_lock_mutex_put(env, lock);
                        osc_ast_data_put(env, olck);
                        result = 0;
                } else
                        result = -ELDLM_NO_LOCK_DATA;
                cl_env_put(env, &refcheck);
        } else
                result = PTR_ERR(env);
        cl_env_reexit(env_cookie);
        return dlmrc ?: result;
}

static int osc_ldlm_glimpse_ast(struct ldlm_lock *dlmlock, void *data)
{
        struct ptlrpc_request  *req  = data;
        struct osc_lock        *olck;
        struct cl_lock         *lock;
        struct cl_object       *obj;
        struct lu_env          *env;
        struct ost_lvb         *lvb;
        struct req_capsule     *cap;
        int                     result;
        int                     refcheck;

        LASSERT(lustre_msg_get_opc(req->rq_reqmsg) == LDLM_GL_CALLBACK);

        env = cl_env_get(&refcheck);
        if (!IS_ERR(env)) {
                /*
                 * osc_ast_data_get() has to go after environment is
                 * allocated, because osc_ast_data() acquires a
                 * reference to a lock, and it can only be released in
                 * environment.
                 */
                olck = osc_ast_data_get(dlmlock);
                if (olck != NULL) {
                        cap = &req->rq_pill;
                        req_capsule_extend(cap, &RQF_LDLM_GL_CALLBACK);
                        req_capsule_set_size(cap, &RMF_DLM_LVB, RCL_SERVER,
                                             sizeof *lvb);
                        result = req_capsule_server_pack(cap);
                        if (result == 0) {
                                lvb = req_capsule_server_get(cap, &RMF_DLM_LVB);
                                lock = olck->ols_cl.cls_lock;
                                obj = lock->cll_descr.cld_obj;
                                result = cl_object_glimpse(env, obj, lvb);
                        }
                        osc_ast_data_put(env, olck);
                } else {
                        /*
                         * These errors are normal races, so we don't want to
                         * fill the console with messages by calling
                         * ptlrpc_error()
                         */
                        lustre_pack_reply(req, 1, NULL, NULL);
                        result = -ELDLM_NO_LOCK_DATA;
                }
                cl_env_put(env, &refcheck);
        } else
                result = PTR_ERR(env);
        req->rq_status = result;
        return result;
}

static unsigned long osc_lock_weigh(const struct lu_env *env,
                                    const struct cl_lock_slice *slice)
{
        /*
         * don't need to grab coh_page_guard since we don't care the exact #
         * of pages..
         */
        return cl_object_header(slice->cls_obj)->coh_pages;
}

/**
 * Get the weight of dlm lock for early cancellation.
 *
 * XXX: it should return the pages covered by this \a dlmlock.
 */
static unsigned long osc_ldlm_weigh_ast(struct ldlm_lock *dlmlock)
{
        struct lu_env           *env;
        int                      refcheck;
        void                    *cookie;
        struct osc_lock         *lock;
        struct cl_lock          *cll;
        unsigned long            weight;
        ENTRY;

        might_sleep();
        cookie = cl_env_reenter();
        /*
         * osc_ldlm_weigh_ast has a complex context since it might be called
         * because of lock canceling, or from user's input. We have to make
         * a new environment for it. Probably it is implementation safe to use
         * the upper context because cl_lock_put don't modify environment
         * variables. But in case of ..
         */
        env = cl_env_get(&refcheck);
        if (IS_ERR(env)) {
                /* Mostly because lack of memory, tend to eliminate this lock*/
                cl_env_reexit(cookie);
                RETURN(0);
        }

        LASSERT(dlmlock->l_resource->lr_type == LDLM_EXTENT);
        lock = osc_ast_data_get(dlmlock);
        if (lock == NULL) {
                /* cl_lock was destroyed because of memory pressure.
                 * It is much reasonable to assign this type of lock
                 * a lower cost.
                 */
                GOTO(out, weight = 0);
        }

        cll = lock->ols_cl.cls_lock;
        cl_lock_mutex_get(env, cll);
        weight = cl_lock_weigh(env, cll);
        cl_lock_mutex_put(env, cll);
        osc_ast_data_put(env, lock);
        EXIT;

out:
        cl_env_put(env, &refcheck);
        cl_env_reexit(cookie);
        return weight;
}

static void osc_lock_build_einfo(const struct lu_env *env,
                                 const struct cl_lock *clock,
                                 struct osc_lock *lock,
                                 struct ldlm_enqueue_info *einfo)
{
        enum cl_lock_mode mode;

        mode = clock->cll_descr.cld_mode;
        if (mode == CLM_PHANTOM)
                /*
                 * For now, enqueue all glimpse locks in read mode. In the
                 * future, client might choose to enqueue LCK_PW lock for
                 * glimpse on a file opened for write.
                 */
                mode = CLM_READ;

        einfo->ei_type   = LDLM_EXTENT;
        einfo->ei_mode   = osc_cl_lock2ldlm(mode);
        einfo->ei_cb_bl  = osc_ldlm_blocking_ast;
        einfo->ei_cb_cp  = osc_ldlm_completion_ast;
        einfo->ei_cb_gl  = osc_ldlm_glimpse_ast;
        einfo->ei_cb_wg  = osc_ldlm_weigh_ast;
        einfo->ei_cbdata = lock; /* value to be put into ->l_ast_data */
}

/**
 * Cancels \a conflict lock and waits until it reached CLS_FREEING state. This
 * is called as a part of enqueuing to cancel conflicting locks early.
 *
 * \retval            0: success, \a conflict was cancelled and destroyed.
 *
 * \retval   CLO_REPEAT: \a conflict was cancelled, but \a lock mutex was
 *                       released in the process. Repeat enqueing.
 *
 * \retval -EWOULDBLOCK: \a conflict cannot be cancelled immediately, and
 *                       either \a lock is non-blocking, or current thread
 *                       holds other locks, that prevent it from waiting
 *                       for cancel to complete.
 *
 * \retval          -ve: other error, including -EINTR.
 *
 */
static int osc_lock_cancel_wait(const struct lu_env *env, struct cl_lock *lock,
                                struct cl_lock *conflict, int canwait)
{
        int rc;

        LASSERT(cl_lock_is_mutexed(lock));
        LASSERT(cl_lock_is_mutexed(conflict));

        rc = 0;
        if (conflict->cll_state != CLS_FREEING) {
                cl_lock_cancel(env, conflict);
                cl_lock_delete(env, conflict);
                if (conflict->cll_flags & (CLF_CANCELPEND|CLF_DOOMED)) {
                        rc = -EWOULDBLOCK;
                        if (cl_lock_nr_mutexed(env) > 2)
                                /*
                                 * If mutices of locks other than @lock and
                                 * @scan are held by the current thread, it
                                 * cannot wait on @scan state change in a
                                 * dead-lock safe matter, so simply skip early
                                 * cancellation in this case.
                                 *
                                 * This means that early cancellation doesn't
                                 * work when there is even slight mutex
                                 * contention, as top-lock's mutex is usually
                                 * held at this time.
                                 */
                                ;
                        else if (canwait) {
                                /* Waiting for @scan to be destroyed */
                                cl_lock_mutex_put(env, lock);
                                do {
                                        rc = cl_lock_state_wait(env, conflict);
                                } while (!rc &&
                                         conflict->cll_state < CLS_FREEING);
                                /* mutex was released, repeat enqueue. */
                                rc = rc ?: CLO_REPEAT;
                                cl_lock_mutex_get(env, lock);
                        }
                }
                LASSERT(ergo(!rc, conflict->cll_state == CLS_FREEING));
                CDEBUG(D_INFO, "lock %p was %s freed now, rc (%d)\n",
                       conflict, rc ? "not":"", rc);
        }
        return rc;
}

/**
 * Cancel all conflicting locks and wait for them to be destroyed.
 *
 * This function is used for two purposes:
 *
 *     - early cancel all conflicting locks before starting IO, and
 *
 *     - guarantee that pages added to the page cache by lockless IO are never
 *       covered by locks other than lockless IO lock, and, hence, are not
 *       visible to other threads.
 */
static int osc_lock_enqueue_wait(const struct lu_env *env,
                                 const struct osc_lock *olck)
{
        struct cl_lock          *lock    = olck->ols_cl.cls_lock;
        struct cl_lock_descr    *descr   = &lock->cll_descr;
        struct cl_object_header *hdr     = cl_object_header(descr->cld_obj);
        struct cl_lock_closure  *closure = &osc_env_info(env)->oti_closure;
        struct cl_lock          *scan;
        struct cl_lock          *temp;
        int lockless                     = osc_lock_is_lockless(olck);
        int rc                           = 0;
        int canwait;
        int stop;
        ENTRY;

        LASSERT(cl_lock_is_mutexed(lock));
        LASSERT(lock->cll_state == CLS_QUEUING);

        /*
         * XXX This function could be sped up if we had asynchronous
         * cancellation.
         */

        canwait =
                !(olck->ols_flags & LDLM_FL_BLOCK_NOWAIT) &&
                cl_lock_nr_mutexed(env) == 1;
        cl_lock_closure_init(env, closure, lock, canwait);
        spin_lock(&hdr->coh_lock_guard);
        list_for_each_entry_safe(scan, temp, &hdr->coh_locks, cll_linkage) {
                if (scan == lock)
                        continue;

                if (scan->cll_state < CLS_QUEUING ||
                    scan->cll_state == CLS_FREEING ||
                    scan->cll_descr.cld_start > descr->cld_end ||
                    scan->cll_descr.cld_end < descr->cld_start)
                        continue;

                /* overlapped and living locks. */
                /* A tricky case for lockless pages:
                 * We need to cancel the compatible locks if we're enqueuing
                 * a lockless lock, for example:
                 * imagine that client has PR lock on [0, 1000], and thread T0
                 * is doing lockless IO in [500, 1500] region. Concurrent
                 * thread T1 can see lockless data in [500, 1000], which is
                 * wrong, because these data are possibly stale.
                 */
                if (!lockless && cl_lock_compatible(scan, lock))
                        continue;

                /* Now @scan is conflicting with @lock, this means current
                 * thread have to sleep for @scan being destroyed. */
                cl_lock_get_trust(scan);
                if (&temp->cll_linkage != &hdr->coh_locks)
                        cl_lock_get_trust(temp);
                spin_unlock(&hdr->coh_lock_guard);
                lu_ref_add(&scan->cll_reference, "cancel-wait", lock);

                LASSERT(list_empty(&closure->clc_list));
                rc = cl_lock_closure_build(env, scan, closure);
                if (rc == 0) {
                        rc = osc_lock_cancel_wait(env, lock, scan, canwait);
                        cl_lock_disclosure(env, closure);
                        if (rc == -EWOULDBLOCK)
                                rc = 0;
                }
                if (rc == CLO_REPEAT && !canwait)
                        /* cannot wait... no early cancellation. */
                        rc = 0;

                lu_ref_del(&scan->cll_reference, "cancel-wait", lock);
                cl_lock_put(env, scan);
                spin_lock(&hdr->coh_lock_guard);
                /*
                 * Lock list could have been modified, while spin-lock was
                 * released. Check that it is safe to continue.
                 */
                stop = list_empty(&temp->cll_linkage);
                if (&temp->cll_linkage != &hdr->coh_locks)
                        cl_lock_put(env, temp);
                if (stop || rc != 0)
                        break;
        }
        spin_unlock(&hdr->coh_lock_guard);
        cl_lock_closure_fini(closure);
        RETURN(rc);
}

/**
 * Deadlock avoidance for osc_lock_enqueue(). Consider following scenario:
 *
 *     - Thread0: obtains PR:[0, 10]. Lock is busy.
 *
 *     - Thread1: enqueues PW:[5, 50]. Blocking ast is sent to
 *       PR:[0, 10], but cancellation of busy lock is postponed.
 *
 *     - Thread0: enqueue PR:[30, 40]. Lock is locally matched to
 *       PW:[5, 50], and thread0 waits for the lock completion never
 *       releasing PR:[0, 10]---deadlock.
 *
 * The second PR lock can be glimpse (it is to deal with that situation that
 * ll_glimpse_size() has second argument, preventing local match of
 * not-yet-granted locks, see bug 10295). Similar situation is possible in the
 * case of memory mapped user level buffer.
 *
 * To prevent this we can detect a situation when current "thread" or "io"
 * already holds a lock on this object and either add LDLM_FL_BLOCK_GRANTED to
 * the ols->ols_flags, or prevent local match with PW locks.
 */
static int osc_deadlock_is_possible(const struct lu_env *env,
                                    struct cl_lock *lock)
{
        struct cl_object        *obj;
        struct cl_object_header *head;
        struct cl_lock          *scan;
        struct osc_io           *oio;

        int result;

        ENTRY;

        LASSERT(cl_lock_is_mutexed(lock));

        oio  = osc_env_io(env);
        obj  = lock->cll_descr.cld_obj;
        head = cl_object_header(obj);

        result = 0;
        spin_lock(&head->coh_lock_guard);
        list_for_each_entry(scan, &head->coh_locks, cll_linkage) {
                if (scan != lock) {
                        struct osc_lock *oscan;

                        oscan = osc_lock_at(scan);
                        LASSERT(oscan != NULL);
                        if (oscan->ols_owner == oio) {
                                result = 1;
                                break;
                        }
                }
        }
        spin_unlock(&head->coh_lock_guard);
        RETURN(result);
}

/**
 * Implementation of cl_lock_operations::clo_enqueue() method for osc
 * layer. This initiates ldlm enqueue:
 *
 *     - checks for possible dead-lock conditions (osc_deadlock_is_possible());
 *
 *     - cancels conflicting locks early (osc_lock_enqueue_wait());
 *
 *     - calls osc_enqueue_base() to do actual enqueue.
 *
 * osc_enqueue_base() is supplied with an upcall function that is executed
 * when lock is received either after a local cached ldlm lock is matched, or
 * when a reply from the server is received.
 *
 * This function does not wait for the network communication to complete.
 */
static int osc_lock_enqueue(const struct lu_env *env,
                            const struct cl_lock_slice *slice,
                            struct cl_io *_, __u32 enqflags)
{
        struct osc_lock          *ols     = cl2osc_lock(slice);
        struct cl_lock           *lock    = ols->ols_cl.cls_lock;
        struct osc_object        *obj     = cl2osc(slice->cls_obj);
        struct osc_thread_info   *info    = osc_env_info(env);
        struct ldlm_res_id       *resname = &info->oti_resname;
        ldlm_policy_data_t       *policy  = &info->oti_policy;
        struct ldlm_enqueue_info *einfo   = &ols->ols_einfo;
        int result;
        ENTRY;

        LASSERT(cl_lock_is_mutexed(lock));
        LASSERT(lock->cll_state == CLS_QUEUING);
        LASSERT(ols->ols_state == OLS_NEW);

        osc_lock_build_res(env, obj, resname);
        osc_lock_build_policy(env, lock, policy);
        ols->ols_flags = osc_enq2ldlm_flags(enqflags);
        if (ols->ols_locklessable)
                ols->ols_flags |= LDLM_FL_DENY_ON_CONTENTION;
        if (osc_deadlock_is_possible(env, lock))
                ols->ols_flags |= LDLM_FL_BLOCK_GRANTED;
        if (ols->ols_flags & LDLM_FL_HAS_INTENT)
                ols->ols_glimpse = 1;

        result = osc_lock_enqueue_wait(env, ols);
        if (result == 0) {
                /* a reference for lock, passed as an upcall cookie */
                cl_lock_get(lock);
                lu_ref_add(&lock->cll_reference, "upcall", lock);
                ols->ols_state = OLS_ENQUEUED;

                /*
                 * XXX: this is possible blocking point as
                 * ldlm_lock_match(LDLM_FL_LVB_READY) waits for
                 * LDLM_CP_CALLBACK.
                 */
                result = osc_enqueue_base(osc_export(obj), resname,
                                          &ols->ols_flags, policy,
                                          &ols->ols_lvb,
                                          obj->oo_oinfo->loi_kms_valid,
                                          osc_lock_upcall,
                                          ols, einfo, &ols->ols_handle,
                                          PTLRPCD_SET, 1);
                if (result != 0) {
                        lu_ref_del(&lock->cll_reference, "upcall", lock);
                        cl_lock_put(env, lock);
                }
        }

        RETURN(result);
}

static int osc_lock_wait(const struct lu_env *env,
                         const struct cl_lock_slice *slice)
{
        struct osc_lock *olck = cl2osc_lock(slice);
        struct cl_lock  *lock = olck->ols_cl.cls_lock;

        LINVRNT(osc_lock_invariant(olck));
        if (olck->ols_glimpse && olck->ols_state >= OLS_UPCALL_RECEIVED)
                return 0;

        LASSERT(equi(olck->ols_state >= OLS_UPCALL_RECEIVED &&
                     lock->cll_error == 0, olck->ols_lock != NULL));

        return lock->cll_error ?: olck->ols_state >= OLS_GRANTED ? 0 : CLO_WAIT;
}

/**
 * An implementation of cl_lock_operations::clo_use() method that pins cached
 * lock.
 */
static int osc_lock_use(const struct lu_env *env,
                        const struct cl_lock_slice *slice)
{
        struct osc_lock *olck = cl2osc_lock(slice);
        int rc;

        LASSERT(!olck->ols_hold);
        /*
         * Atomically check for LDLM_FL_CBPENDING and addref a lock if this
         * flag is not set. This protects us from a concurrent blocking ast.
         */
        rc = ldlm_lock_addref_try(&olck->ols_handle, olck->ols_einfo.ei_mode);
        if (rc == 0) {
                olck->ols_hold = olck->ols_has_ref = 1;
                olck->ols_state = OLS_GRANTED;
        } else {
                struct cl_lock *lock;

                /*
                 * Lock is being cancelled somewhere within
                 * ldlm_handle_bl_callback(): LDLM_FL_CBPENDING is already
                 * set, but osc_ldlm_blocking_ast() hasn't yet acquired
                 * cl_lock mutex.
                 */
                lock = slice->cls_lock;
                LASSERT(lock->cll_state == CLS_CACHED);
                LASSERT(lock->cll_users > 0);
                LASSERT(olck->ols_lock->l_flags & LDLM_FL_CBPENDING);
                /* set a flag for osc_dlm_blocking_ast0() to signal the
                 * lock.*/
                olck->ols_ast_wait = 1;
                rc = CLO_WAIT;
        }
        return rc;
}

static int osc_lock_flush(struct osc_lock *ols, int discard)
{
        struct cl_lock       *lock  = ols->ols_cl.cls_lock;
        struct cl_env_nest    nest;
        struct lu_env        *env;
        int result = 0;

        env = cl_env_nested_get(&nest);
        if (!IS_ERR(env)) {
                result = cl_lock_page_out(env, lock, discard);
                cl_env_nested_put(&nest, env);
        } else
                result = PTR_ERR(env);
        if (result == 0)
                ols->ols_flush = 1;
        return result;
}

/**
 * Implements cl_lock_operations::clo_cancel() method for osc layer. This is
 * called (as part of cl_lock_cancel()) when lock is canceled either voluntary
 * (LRU pressure, early cancellation, umount, etc.) or due to the conflict
 * with some other lock some where in the cluster. This function does the
 * following:
 *
 *     - invalidates all pages protected by this lock (after sending dirty
 *       ones to the server, as necessary);
 *
 *     - decref's underlying ldlm lock;
 *
 *     - cancels ldlm lock (ldlm_cli_cancel()).
 */
static void osc_lock_cancel(const struct lu_env *env,
                            const struct cl_lock_slice *slice)
{
        struct cl_lock   *lock    = slice->cls_lock;
        struct osc_lock  *olck    = cl2osc_lock(slice);
        struct ldlm_lock *dlmlock = olck->ols_lock;
        int               result;
        int               discard;

        LASSERT(cl_lock_is_mutexed(lock));
        LINVRNT(osc_lock_invariant(olck));

        if (dlmlock != NULL) {
                discard = dlmlock->l_flags & LDLM_FL_DISCARD_DATA;
                result = osc_lock_flush(olck, discard);
                if (olck->ols_hold)
                        osc_lock_unuse(env, slice);
                LASSERT(dlmlock->l_readers == 0 && dlmlock->l_writers == 0);
                result = ldlm_cli_cancel(&olck->ols_handle);
                if (result < 0)
                        CL_LOCK_DEBUG(D_ERROR, env, lock,
                                      "lock %p cancel failure with error(%d)\n",
                                      lock, result);
        }
        olck->ols_state = OLS_CANCELLED;
        osc_lock_detach(env, olck);
}

void cl_lock_page_list_fixup(const struct lu_env *env,
                             struct cl_io *io, struct cl_lock *lock,
                             struct cl_page_list *queue);

#ifdef INVARIANT_CHECK
/**
 * Returns true iff there are pages under \a olck not protected by other
 * locks.
 */
static int osc_lock_has_pages(struct osc_lock *olck)
{
        struct cl_lock       *lock;
        struct cl_lock_descr *descr;
        struct cl_object     *obj;
        struct osc_object    *oob;
        struct cl_page_list  *plist;
        struct cl_page       *page;
        struct cl_env_nest    nest;
        struct cl_io         *io;
        struct lu_env        *env;
        int                   result;

        env = cl_env_nested_get(&nest);
        if (!IS_ERR(env)) {
                obj   = olck->ols_cl.cls_obj;
                oob   = cl2osc(obj);
                io    = &oob->oo_debug_io;
                lock  = olck->ols_cl.cls_lock;
                descr = &lock->cll_descr;
                plist = &osc_env_info(env)->oti_plist;
                cl_page_list_init(plist);

                mutex_lock(&oob->oo_debug_mutex);

                io->ci_obj = cl_object_top(obj);
                cl_io_init(env, io, CIT_MISC, io->ci_obj);
                cl_page_gang_lookup(env, obj, io,
                                    descr->cld_start, descr->cld_end, plist);
                cl_lock_page_list_fixup(env, io, lock, plist);
                if (plist->pl_nr > 0) {
                        CL_LOCK_DEBUG(D_ERROR, env, lock, "still has pages\n");
                        cl_page_list_for_each(page, plist)
                                CL_PAGE_DEBUG(D_ERROR, env, page, "\n");
                }
                result = plist->pl_nr > 0;
                cl_page_list_disown(env, io, plist);
                cl_page_list_fini(env, plist);
                cl_io_fini(env, io);
                mutex_unlock(&oob->oo_debug_mutex);
                cl_env_nested_put(&nest, env);
        } else
                result = 0;
        return result;
}
#else
# define osc_lock_has_pages(olck) (0)
#endif /* INVARIANT_CHECK */

static void osc_lock_delete(const struct lu_env *env,
                            const struct cl_lock_slice *slice)
{
        struct osc_lock *olck;

        olck = cl2osc_lock(slice);
        LINVRNT(osc_lock_invariant(olck));
        LINVRNT(!osc_lock_has_pages(olck));

        if (olck->ols_hold)
                osc_lock_unuse(env, slice);
        osc_lock_detach(env, olck);
}

/**
 * Implements cl_lock_operations::clo_state() method for osc layer.
 *
 * Maintains osc_lock::ols_owner field.
 *
 * This assumes that lock always enters CLS_HELD (from some other state) in
 * the same IO context as one that requested the lock. This should not be a
 * problem, because context is by definition shared by all activity pertaining
 * to the same high-level IO.
 */
static void osc_lock_state(const struct lu_env *env,
                           const struct cl_lock_slice *slice,
                           enum cl_lock_state state)
{
        struct osc_lock *lock = cl2osc_lock(slice);
        struct osc_io   *oio  = osc_env_io(env);

        /*
         * XXX multiple io contexts can use the lock at the same time.
         */
        LINVRNT(osc_lock_invariant(lock));
        if (state == CLS_HELD && slice->cls_lock->cll_state != CLS_HELD) {
                LASSERT(lock->ols_owner == NULL);
                lock->ols_owner = oio;
        } else if (state != CLS_HELD)
                lock->ols_owner = NULL;
}

static int osc_lock_print(const struct lu_env *env, void *cookie,
                          lu_printer_t p, const struct cl_lock_slice *slice)
{
        struct osc_lock *lock = cl2osc_lock(slice);

        /*
         * XXX print ldlm lock and einfo properly.
         */
        (*p)(env, cookie, "%p %08x "LPU64" %d %p ",
             lock->ols_lock, lock->ols_flags, lock->ols_handle.cookie,
             lock->ols_state, lock->ols_owner);
        osc_lvb_print(env, cookie, p, &lock->ols_lvb);
        return 0;
}

static const struct cl_lock_operations osc_lock_ops = {
        .clo_fini    = osc_lock_fini,
        .clo_enqueue = osc_lock_enqueue,
        .clo_wait    = osc_lock_wait,
        .clo_unuse   = osc_lock_unuse,
        .clo_use     = osc_lock_use,
        .clo_delete  = osc_lock_delete,
        .clo_state   = osc_lock_state,
        .clo_cancel  = osc_lock_cancel,
        .clo_weigh   = osc_lock_weigh,
        .clo_print   = osc_lock_print
};

static int osc_lock_lockless_enqueue(const struct lu_env *env,
                                     const struct cl_lock_slice *slice,
                                     struct cl_io *_, __u32 enqflags)
{
        struct osc_lock          *ols     = cl2osc_lock(slice);
        struct cl_lock           *lock    = ols->ols_cl.cls_lock;
        int result;

        LASSERT(cl_lock_is_mutexed(lock));
        LASSERT(lock->cll_state == CLS_QUEUING);
        LASSERT(ols->ols_state == OLS_NEW);

        result = osc_lock_enqueue_wait(env, ols);
        if (result == 0)
                ols->ols_state = OLS_GRANTED;
        return result;
}

static int osc_lock_lockless_unuse(const struct lu_env *env,
                                   const struct cl_lock_slice *slice)
{
        struct osc_lock *ols = cl2osc_lock(slice);
        struct cl_lock *lock = slice->cls_lock;

        LASSERT(ols->ols_state == OLS_GRANTED);
        LINVRNT(osc_lock_invariant(ols));

        cl_lock_cancel(env, lock);
        cl_lock_delete(env, lock);
        return 0;
}

static void osc_lock_lockless_cancel(const struct lu_env *env,
                                     const struct cl_lock_slice *slice)
{
        struct osc_lock   *ols  = cl2osc_lock(slice);
        int result;

        result = osc_lock_flush(ols, 0);
        if (result)
                CERROR("Pages for lockless lock %p were not purged(%d)\n",
                       ols, result);
        ols->ols_state = OLS_CANCELLED;
}

static int osc_lock_lockless_wait(const struct lu_env *env,
                                  const struct cl_lock_slice *slice)
{
        struct osc_lock *olck = cl2osc_lock(slice);
        struct cl_lock  *lock = olck->ols_cl.cls_lock;

        LINVRNT(osc_lock_invariant(olck));
        LASSERT(olck->ols_state >= OLS_UPCALL_RECEIVED);

        return lock->cll_error;
}

static void osc_lock_lockless_state(const struct lu_env *env,
                                    const struct cl_lock_slice *slice,
                                    enum cl_lock_state state)
{
        struct osc_lock *lock = cl2osc_lock(slice);
        struct osc_io   *oio  = osc_env_io(env);

        LINVRNT(osc_lock_invariant(lock));
        if (state == CLS_HELD) {
                LASSERT(lock->ols_owner == NULL);
                lock->ols_owner = oio;
                oio->oi_lockless = 1;
        } else
                lock->ols_owner = NULL;
}

static int osc_lock_lockless_fits_into(const struct lu_env *env,
                                       const struct cl_lock_slice *slice,
                                       const struct cl_lock_descr *need,
                                       const struct cl_io *io)
{
        return 0;
}

static const struct cl_lock_operations osc_lock_lockless_ops = {
        .clo_fini      = osc_lock_fini,
        .clo_enqueue   = osc_lock_lockless_enqueue,
        .clo_wait      = osc_lock_lockless_wait,
        .clo_unuse     = osc_lock_lockless_unuse,
        .clo_state     = osc_lock_lockless_state,
        .clo_fits_into = osc_lock_lockless_fits_into,
        .clo_cancel    = osc_lock_lockless_cancel,
        .clo_print     = osc_lock_print
};

int osc_lock_init(const struct lu_env *env,
                  struct cl_object *obj, struct cl_lock *lock,
                  const struct cl_io *io)
{
        struct osc_lock   *clk;
        struct osc_io     *oio = osc_env_io(env);
        struct osc_object *oob = cl2osc(obj);
        int result;

        OBD_SLAB_ALLOC_PTR(clk, osc_lock_kmem);
        if (clk != NULL) {
                const struct cl_lock_operations *ops;
                const struct osc_device *osd = lu2osc_dev(obj->co_lu.lo_dev);
                struct obd_connect_data *ocd;

                osc_lock_build_einfo(env, lock, clk, &clk->ols_einfo);
                clk->ols_state = OLS_NEW;

                /*
                 * Check if we need to do lockless IO here.
                 * Following conditions must be satisfied:
                 * - the current IO must be locklessable;
                 * - the stripe is in contention;
                 * - requested lock is not a glimpse.
                 *
                 * if not, we have to inherit the locklessable flag to
                 * osc_lock, and let ost make the decision.
                 *
                 * Additional policy can be implemented here, e.g., never do
                 * lockless-io for large extents.
                 */
                LASSERT(io->ci_lockreq == CILR_MANDATORY ||
                        io->ci_lockreq == CILR_MAYBE ||
                        io->ci_lockreq == CILR_NEVER);
                ocd = &class_exp2cliimp(osc_export(oob))->imp_connect_data;
                clk->ols_locklessable = (io->ci_type != CIT_TRUNC) &&
                                (io->ci_lockreq == CILR_MAYBE) &&
                                (ocd->ocd_connect_flags & OBD_CONNECT_SRVLOCK);
                ops = &osc_lock_ops;
                if (io->ci_lockreq == CILR_NEVER ||
                    /* lockless IO */
                    (clk->ols_locklessable && osc_object_is_contended(oob)) ||
                     /* lockless truncate */
                    (io->ci_type == CIT_TRUNC &&
                     (ocd->ocd_connect_flags & OBD_CONNECT_TRUNCLOCK) &&
                     osd->od_lockless_truncate)) {
                        ops = &osc_lock_lockless_ops;
                        oio->oi_lockless     = 1;
                        clk->ols_locklessable = 1;
                }

                cl_lock_slice_add(lock, &clk->ols_cl, obj, ops);
                result = 0;
        } else
                result = -ENOMEM;
        return result;
}


/** @} osc */
