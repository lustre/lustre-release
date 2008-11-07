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
 * Implementation of cl_lock for LOV layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include "lov_cl_internal.h"

/** \addtogroup lov lov @{ */

static struct cl_lock_closure *lov_closure_get(const struct lu_env *env,
                                               struct cl_lock *parent);

/*****************************************************************************
 *
 * Lov lock operations.
 *
 */

static void lov_sublock_adopt(const struct lu_env *env, struct lov_lock *lck,
                              struct cl_lock *sublock, int idx,
                              struct lov_lock_link *link)
{
        struct lovsub_lock *lsl;
        struct cl_lock     *parent = lck->lls_cl.cls_lock;
        int                 rc;

        LASSERT(cl_lock_is_mutexed(parent));
        LASSERT(cl_lock_is_mutexed(sublock));
        ENTRY;

        lsl = cl2sub_lock(sublock);
        /*
         * check that sub-lock doesn't have lock link to this top-lock.
         */
        LASSERT(lov_lock_link_find(env, lck, lsl) == NULL);
        LASSERT(idx < lck->lls_nr);

        lck->lls_sub[idx].sub_lock = lsl;
        lck->lls_nr_filled++;
        LASSERT(lck->lls_nr_filled <= lck->lls_nr);
        list_add_tail(&link->lll_list, &lsl->lss_parents);
        link->lll_idx = idx;
        link->lll_super = lck;
        cl_lock_get(parent);
        lu_ref_add(&parent->cll_reference, "lov-child", sublock);
        lck->lls_sub[idx].sub_flags |= LSF_HELD;
        cl_lock_user_add(env, sublock);

        rc = lov_sublock_modify(env, lck, lsl, &sublock->cll_descr, idx);
        LASSERT(rc == 0); /* there is no way this can fail, currently */
        EXIT;
}

static struct cl_lock *lov_sublock_alloc(const struct lu_env *env,
                                         const struct cl_io *io,
                                         struct lov_lock *lck,
                                         int idx, struct lov_lock_link **out)
{
        struct cl_lock       *sublock;
        struct cl_lock       *parent;
        struct lov_lock_link *link;

        LASSERT(idx < lck->lls_nr);
        ENTRY;

        OBD_SLAB_ALLOC_PTR(link, lov_lock_link_kmem);
        if (link != NULL) {
                struct lov_lock_sub  *sub;
                struct cl_lock_descr *descr;

                parent = lck->lls_cl.cls_lock;
                sub    = &lck->lls_sub[idx];
                descr  = &sub->sub_descr;

                /* XXX maybe sub-io? */
                sublock = cl_lock_hold(env, io, descr, "lov-parent", parent);
                if (!IS_ERR(sublock))
                        *out = link;
                else
                        OBD_SLAB_FREE_PTR(link, lov_lock_link_kmem);
        } else
                sublock = ERR_PTR(-ENOMEM);
        RETURN(sublock);
}

static void lov_sublock_unlock(const struct lu_env *env,
                               struct lovsub_lock *lsl,
                               struct cl_lock_closure *closure)
{
        ENTRY;
        lsl->lss_active = NULL;
        cl_lock_disclosure(env, closure);
        EXIT;
}

static int lov_sublock_lock(const struct lu_env *env, struct lovsub_lock *lsl,
                            struct cl_lock_closure *closure)
{
        struct cl_lock *child;
        int             result;

        LASSERT(list_empty(&closure->clc_list));

        ENTRY;
        child = lsl->lss_cl.cls_lock;
        result = cl_lock_closure_build(env, child, closure);
        if (result == 0) {
                LASSERT(cl_lock_is_mutexed(child));
                lsl->lss_active = closure->clc_origin;
        }
        RETURN(result);
}

/**
 * Updates the result of a top-lock operation from a result of sub-lock
 * sub-operations. Top-operations like lov_lock_{enqueue,use,unuse}() iterate
 * over sub-locks and lov_subresult() is used to calculate return value of a
 * top-operation. To this end, possible return values of sub-operations are
 * ordered as
 *
 *     - 0                  success
 *     - CLO_WAIT           wait for event
 *     - CLO_REPEAT         repeat top-operation
 *     - -ne                fundamental error
 *
 * Top-level return code can only go down through this list. CLO_REPEAT
 * overwrites CLO_WAIT, because lock mutex was released and sleeping condition
 * has to be rechecked by the upper layer.
 */
static int lov_subresult(int result, int rc)
{
        int result_rank;
        int rc_rank;

        LASSERT(result <= 0 || result == CLO_REPEAT || result == CLO_WAIT);
        LASSERT(rc <= 0 || rc == CLO_REPEAT || rc == CLO_WAIT);
        CLASSERT(CLO_WAIT < CLO_REPEAT);

        ENTRY;

        /* calculate ranks in the ordering above */
        result_rank = result < 0 ? 1 + CLO_REPEAT : result;
        rc_rank = rc < 0 ? 1 + CLO_REPEAT : rc;

        if (result_rank < rc_rank)
                result = rc;
        RETURN(result);
}

/**
 * Creates sub-locks for a given lov_lock for the first time.
 *
 * Goes through all sub-objects of top-object, and creates sub-locks on every
 * sub-object intersecting with top-lock extent. This is complicated by the
 * fact that top-lock (that is being created) can be accessed concurrently
 * through already created sub-locks (possibly shared with other top-locks).
 */
static int lov_lock_sub_init(const struct lu_env *env,
                             struct lov_lock *lck, const struct cl_io *io)
{
        int result = 0;
        int i;
        int j;
        int nr;
        int stripe;
        int start_stripe;
        obd_off start;
        obd_off end;
        obd_off file_start;
        obd_off file_end;

        struct lov_object       *loo    = cl2lov(lck->lls_cl.cls_obj);
        struct lov_layout_raid0 *r0     = lov_r0(loo);
        struct cl_lock          *parent = lck->lls_cl.cls_lock;

        ENTRY;

        lck->lls_orig = parent->cll_descr;
        file_start = cl_offset(lov2cl(loo), parent->cll_descr.cld_start);
        file_end   = cl_offset(lov2cl(loo), parent->cll_descr.cld_end + 1) - 1;

        start_stripe = lov_stripe_number(r0->lo_lsm, file_start);
        for (i = 0, nr = 0; i < r0->lo_nr; i++) {
                /*
                 * XXX for wide striping smarter algorithm is desirable,
                 * breaking out of the loop, early.
                 */
                stripe = (start_stripe + i) % r0->lo_nr;
                if (lov_stripe_intersects(r0->lo_lsm, stripe,
                                          file_start, file_end, &start, &end))
                        nr++;
        }
        LASSERT(nr > 0);
        OBD_ALLOC(lck->lls_sub, nr * sizeof lck->lls_sub[0]);
        if (lck->lls_sub == NULL)
                RETURN(-ENOMEM);

        lck->lls_nr = nr;
        /*
         * First, fill in sub-lock descriptions in
         * lck->lls_sub[].sub_descr. They are used by lov_sublock_alloc()
         * (called below in this function, and by lov_lock_enqueue()) to
         * create sub-locks. At this moment, no other thread can access
         * top-lock.
         */
        for (j = 0, nr = 0; j < i; ++j) {
                stripe = (start_stripe + j) % r0->lo_nr;
                if (lov_stripe_intersects(r0->lo_lsm, stripe,
                                          file_start, file_end, &start, &end)) {
                        struct cl_lock_descr *descr;

                        descr = &lck->lls_sub[nr].sub_descr;

                        LASSERT(descr->cld_obj == NULL);
                        descr->cld_obj   = lovsub2cl(r0->lo_sub[stripe]);
                        descr->cld_start = cl_index(descr->cld_obj, start);
                        descr->cld_end   = cl_index(descr->cld_obj, end);
                        descr->cld_mode  = parent->cll_descr.cld_mode;
                        lck->lls_sub[nr].sub_got = *descr;
                        lck->lls_sub[nr].sub_stripe = stripe;
                        nr++;
                }
        }
        LASSERT(nr == lck->lls_nr);
        /*
         * Then, create sub-locks. Once at least one sub-lock was created,
         * top-lock can be reached by other threads.
         */
        for (i = 0; i < lck->lls_nr; ++i) {
                struct cl_lock       *sublock;
                struct lov_lock_link *link;

                if (lck->lls_sub[i].sub_lock == NULL) {
                        sublock = lov_sublock_alloc(env, io, lck, i, &link);
                        if (IS_ERR(sublock)) {
                                result = PTR_ERR(sublock);
                                break;
                        }
                        cl_lock_mutex_get(env, sublock);
                        cl_lock_mutex_get(env, parent);
                        /*
                         * recheck under mutex that sub-lock wasn't created
                         * concurrently, and that top-lock is still alive.
                         */
                        if (lck->lls_sub[i].sub_lock == NULL &&
                            parent->cll_state < CLS_FREEING) {
                                lov_sublock_adopt(env, lck, sublock, i, link);
                                cl_lock_mutex_put(env, parent);
                        } else {
                                cl_lock_mutex_put(env, parent);
                                cl_lock_unhold(env, sublock,
                                               "lov-parent", parent);
                        }
                        cl_lock_mutex_put(env, sublock);
                }
        }
        /*
         * Some sub-locks can be missing at this point. This is not a problem,
         * because enqueue will create them anyway. Main duty of this function
         * is to fill in sub-lock descriptions in a race free manner.
         */
        RETURN(result);
}

static int lov_sublock_release(const struct lu_env *env, struct lov_lock *lck,
                               int i, int deluser, int rc)
{
        struct cl_lock *parent = lck->lls_cl.cls_lock;

        LASSERT(cl_lock_is_mutexed(parent));
        ENTRY;

        if (lck->lls_sub[i].sub_flags & LSF_HELD) {
                struct cl_lock *sublock;
                int dying;

                LASSERT(lck->lls_sub[i].sub_lock != NULL);
                sublock = lck->lls_sub[i].sub_lock->lss_cl.cls_lock;
                LASSERT(cl_lock_is_mutexed(sublock));

                lck->lls_sub[i].sub_flags &= ~LSF_HELD;
                if (deluser)
                        cl_lock_user_del(env, sublock);
                /*
                 * If the last hold is released, and cancellation is pending
                 * for a sub-lock, release parent mutex, to avoid keeping it
                 * while sub-lock is being paged out.
                 */
                dying = (sublock->cll_descr.cld_mode == CLM_PHANTOM ||
                         (sublock->cll_flags & (CLF_CANCELPEND|CLF_DOOMED))) &&
                        sublock->cll_holds == 1;
                if (dying)
                        cl_lock_mutex_put(env, parent);
                cl_lock_unhold(env, sublock, "lov-parent", parent);
                if (dying) {
                        cl_lock_mutex_get(env, parent);
                        rc = lov_subresult(rc, CLO_REPEAT);
                }
                /*
                 * From now on lck->lls_sub[i].sub_lock is a "weak" pointer,
                 * not backed by a reference on a
                 * sub-lock. lovsub_lock_delete() will clear
                 * lck->lls_sub[i].sub_lock under semaphores, just before
                 * sub-lock is destroyed.
                 */
        }
        RETURN(rc);
}

static void lov_sublock_hold(const struct lu_env *env, struct lov_lock *lck,
                             int i)
{
        struct cl_lock *parent = lck->lls_cl.cls_lock;

        LASSERT(cl_lock_is_mutexed(parent));
        ENTRY;

        if (!(lck->lls_sub[i].sub_flags & LSF_HELD)) {
                struct cl_lock *sublock;

                LASSERT(lck->lls_sub[i].sub_lock != NULL);
                sublock = lck->lls_sub[i].sub_lock->lss_cl.cls_lock;
                LASSERT(cl_lock_is_mutexed(sublock));
                LASSERT(sublock->cll_state != CLS_FREEING);

                lck->lls_sub[i].sub_flags |= LSF_HELD;

                cl_lock_get_trust(sublock);
                cl_lock_hold_add(env, sublock, "lov-parent", parent);
                cl_lock_user_add(env, sublock);
                cl_lock_put(env, sublock);
        }
        EXIT;
}

static void lov_lock_fini(const struct lu_env *env,
                          struct cl_lock_slice *slice)
{
        struct lov_lock *lck;
        int i;

        ENTRY;
        lck = cl2lov_lock(slice);
        LASSERT(lck->lls_nr_filled == 0);
        if (lck->lls_sub != NULL) {
                for (i = 0; i < lck->lls_nr; ++i)
                        /*
                         * No sub-locks exists at this point, as sub-lock has
                         * a reference on its parent.
                         */
                        LASSERT(lck->lls_sub[i].sub_lock == NULL);
                OBD_FREE(lck->lls_sub, lck->lls_nr * sizeof lck->lls_sub[0]);
        }
        OBD_SLAB_FREE_PTR(lck, lov_lock_kmem);
        EXIT;
}

/**
 * Tries to advance a state machine of a given sub-lock toward enqueuing of
 * the top-lock.
 *
 * \retval 0 if state-transition can proceed
 * \retval -ve otherwise.
 */
static int lov_lock_enqueue_one(const struct lu_env *env, struct lov_lock *lck,
                                struct cl_lock *sublock,
                                struct cl_io *io, __u32 enqflags, int last)
{
        int result;

        ENTRY;
        /* first, try to enqueue a sub-lock ... */
        result = cl_enqueue_try(env, sublock, io, enqflags);
        if (sublock->cll_state == CLS_ENQUEUED)
                /* if it is enqueued, try to `wait' on it---maybe it's already
                 * granted */
                result = cl_wait_try(env, sublock);
        /*
         * If CEF_ASYNC flag is set, then all sub-locks can be enqueued in
         * parallel, otherwise---enqueue has to wait until sub-lock is granted
         * before proceeding to the next one.
         */
        if (result == CLO_WAIT && sublock->cll_state <= CLS_HELD &&
            enqflags & CEF_ASYNC && !last)
                result = 0;
        RETURN(result);
}

/**
 * Helper function for lov_lock_enqueue() that creates missing sub-lock.
 */
static int lov_sublock_fill(const struct lu_env *env, struct cl_lock *parent,
                            struct cl_io *io, struct lov_lock *lck, int idx)
{
        struct lov_lock_link *link;
        struct cl_lock       *sublock;
        int                   result;

        LASSERT(parent->cll_depth == 1);
        cl_lock_mutex_put(env, parent);
        sublock = lov_sublock_alloc(env, io, lck, idx, &link);
        if (!IS_ERR(sublock))
                cl_lock_mutex_get(env, sublock);
        cl_lock_mutex_get(env, parent);

        if (!IS_ERR(sublock)) {
                if (parent->cll_state == CLS_QUEUING &&
                    lck->lls_sub[idx].sub_lock == NULL)
                        lov_sublock_adopt(env, lck, sublock, idx, link);
                else {
                        /* other thread allocated sub-lock, or enqueue is no
                         * longer going on */
                        cl_lock_mutex_put(env, parent);
                        cl_lock_unhold(env, sublock, "lov-parent", parent);
                        cl_lock_mutex_get(env, parent);
                }
                cl_lock_mutex_put(env, sublock);
                result = CLO_REPEAT;
        } else
                result = PTR_ERR(sublock);
        return result;
}

/**
 * Implementation of cl_lock_operations::clo_enqueue() for lov layer. This
 * function is rather subtle, as it enqueues top-lock (i.e., advances top-lock
 * state machine from CLS_QUEUING to CLS_ENQUEUED states) by juggling sub-lock
 * state machines in the face of sub-locks sharing (by multiple top-locks),
 * and concurrent sub-lock cancellations.
 */
static int lov_lock_enqueue(const struct lu_env *env,
                            const struct cl_lock_slice *slice,
                            struct cl_io *io, __u32 enqflags)
{
        struct cl_lock         *lock    = slice->cls_lock;
        struct lov_lock        *lck     = cl2lov_lock(slice);
        struct cl_lock_closure *closure = lov_closure_get(env, lock);
        int i;
        int result;
        enum cl_lock_state minstate;

        ENTRY;

        for (result = 0, minstate = CLS_FREEING, i = 0; i < lck->lls_nr; ++i) {
                int rc;
                struct lovsub_lock *sub;
                struct cl_lock *sublock;

                if (lock->cll_state != CLS_QUEUING) {
                        /*
                         * Lock might have left QUEUING state if previous
                         * iteration released its mutex. Stop enqueing in this
                         * case and let the upper layer to decide what to do.
                         */
                        LASSERT(i > 0 && result != 0);
                        break;
                }

                sub = lck->lls_sub[i].sub_lock;
                /*
                 * Sub-lock might have been canceled, while top-lock was
                 * cached.
                 */
                if (sub == NULL) {
                        result = lov_sublock_fill(env, lock, io, lck, i);
                        /* lov_sublock_fill() released @lock mutex,
                         * restart. */
                        break;
                }
                sublock = sub->lss_cl.cls_lock;
                rc = lov_sublock_lock(env, sub, closure);
                if (rc == 0) {
                        lov_sublock_hold(env, lck, i);
                        rc = lov_lock_enqueue_one(env, lck, sublock, io,
                                                  enqflags,
                                                  i == lck->lls_nr - 1);
                        minstate = min(minstate, sublock->cll_state);
                        /*
                         * Don't hold a sub-lock in CLS_CACHED state, see
                         * description for lov_lock::lls_sub.
                         */
                        if (sublock->cll_state > CLS_HELD)
                                rc = lov_sublock_release(env, lck, i, 1, rc);
                        lov_sublock_unlock(env, sub, closure);
                }
                result = lov_subresult(result, rc);
                if (result < 0)
                        break;
        }
        cl_lock_closure_fini(closure);
        RETURN(result ?: minstate >= CLS_ENQUEUED ? 0 : CLO_WAIT);
}

static int lov_lock_unuse(const struct lu_env *env,
                          const struct cl_lock_slice *slice)
{
        struct lov_lock        *lck     = cl2lov_lock(slice);
        struct cl_lock_closure *closure = lov_closure_get(env, slice->cls_lock);
        int i;
        int result;

        ENTRY;

        for (result = 0, i = 0; i < lck->lls_nr; ++i) {
                int rc;
                struct lovsub_lock *sub;
                struct cl_lock *sublock;

                /* top-lock state cannot change concurrently, because single
                 * thread (one that released the last hold) carries unlocking
                 * to the completion. */
                LASSERT(slice->cls_lock->cll_state == CLS_UNLOCKING);
                sub = lck->lls_sub[i].sub_lock;
                if (sub == NULL)
                        continue;

                sublock = sub->lss_cl.cls_lock;
                rc = lov_sublock_lock(env, sub, closure);
                if (rc == 0) {
                        if (lck->lls_sub[i].sub_flags & LSF_HELD) {
                                LASSERT(sublock->cll_state == CLS_HELD);
                                rc = cl_unuse_try(env, sublock);
                                if (rc != CLO_WAIT)
                                        rc = lov_sublock_release(env, lck,
                                                                 i, 0, rc);
                        }
                        lov_sublock_unlock(env, sub, closure);
                }
                result = lov_subresult(result, rc);
                if (result < 0)
                        break;
        }
        if (result == 0 && lck->lls_unuse_race) {
                lck->lls_unuse_race = 0;
                result = -ESTALE;
        }
        cl_lock_closure_fini(closure);
        RETURN(result);
}

static int lov_lock_wait(const struct lu_env *env,
                         const struct cl_lock_slice *slice)
{
        struct lov_lock        *lck     = cl2lov_lock(slice);
        struct cl_lock_closure *closure = lov_closure_get(env, slice->cls_lock);
        enum cl_lock_state      minstate;
        int                     result;
        int                     i;

        ENTRY;

        for (result = 0, minstate = CLS_FREEING, i = 0; i < lck->lls_nr; ++i) {
                int rc;
                struct lovsub_lock *sub;
                struct cl_lock *sublock;

                sub = lck->lls_sub[i].sub_lock;
                LASSERT(sub != NULL);
                sublock = sub->lss_cl.cls_lock;
                rc = lov_sublock_lock(env, sub, closure);
                if (rc == 0) {
                        LASSERT(sublock->cll_state >= CLS_ENQUEUED);
                        if (sublock->cll_state < CLS_HELD)
                                rc = cl_wait_try(env, sublock);
                        minstate = min(minstate, sublock->cll_state);
                        lov_sublock_unlock(env, sub, closure);
                }
                result = lov_subresult(result, rc);
                if (result < 0)
                        break;
        }
        cl_lock_closure_fini(closure);
        RETURN(result ?: minstate >= CLS_HELD ? 0 : CLO_WAIT);
}

static int lov_lock_use(const struct lu_env *env,
                        const struct cl_lock_slice *slice)
{
        struct lov_lock        *lck     = cl2lov_lock(slice);
        struct cl_lock_closure *closure = lov_closure_get(env, slice->cls_lock);
        int                     result;
        int                     i;

        LASSERT(slice->cls_lock->cll_state == CLS_CACHED);
        ENTRY;

        for (result = 0, i = 0; i < lck->lls_nr; ++i) {
                int rc;
                struct lovsub_lock *sub;
                struct cl_lock *sublock;

                if (slice->cls_lock->cll_state != CLS_CACHED) {
                        /* see comment in lov_lock_enqueue(). */
                        LASSERT(i > 0 && result != 0);
                        break;
                }
                /*
                 * if a sub-lock was destroyed while top-lock was in
                 * CLS_CACHED state, top-lock would have been moved into
                 * CLS_NEW state, so all sub-locks have to be in place.
                 */
                sub = lck->lls_sub[i].sub_lock;
                LASSERT(sub != NULL);
                sublock = sub->lss_cl.cls_lock;
                rc = lov_sublock_lock(env, sub, closure);
                if (rc == 0) {
                        LASSERT(sublock->cll_state != CLS_FREEING);
                        lov_sublock_hold(env, lck, i);
                        if (sublock->cll_state == CLS_CACHED) {
                                rc = cl_use_try(env, sublock);
                                if (rc != 0)
                                        rc = lov_sublock_release(env, lck,
                                                                 i, 1, rc);
                        } else
                                rc = 0;
                        lov_sublock_unlock(env, sub, closure);
                }
                result = lov_subresult(result, rc);
                if (result < 0)
                        break;
        }
        cl_lock_closure_fini(closure);
        RETURN(result);
}

#if 0
static int lock_lock_multi_match()
{
        struct cl_lock          *lock    = slice->cls_lock;
        struct cl_lock_descr    *subneed = &lov_env_info(env)->lti_ldescr;
        struct lov_object       *loo     = cl2lov(lov->lls_cl.cls_obj);
        struct lov_layout_raid0 *r0      = lov_r0(loo);
        struct lov_lock_sub     *sub;
        struct cl_object        *subobj;
        obd_off  fstart;
        obd_off  fend;
        obd_off  start;
        obd_off  end;
        int i;

        fstart = cl_offset(need->cld_obj, need->cld_start);
        fend   = cl_offset(need->cld_obj, need->cld_end + 1) - 1;
        subneed->cld_mode = need->cld_mode;
        cl_lock_mutex_get(env, lock);
        for (i = 0; i < lov->lls_nr; ++i) {
                sub = &lov->lls_sub[i];
                if (sub->sub_lock == NULL)
                        continue;
                subobj = sub->sub_descr.cld_obj;
                if (!lov_stripe_intersects(r0->lo_lsm, sub->sub_stripe,
                                           fstart, fend, &start, &end))
                        continue;
                subneed->cld_start = cl_index(subobj, start);
                subneed->cld_end   = cl_index(subobj, end);
                subneed->cld_obj   = subobj;
                if (!cl_lock_ext_match(&sub->sub_got, subneed)) {
                        result = 0;
                        break;
                }
        }
        cl_lock_mutex_put(env, lock);
}
#endif

static int lov_is_same_stripe(struct lov_object *lov, int stripe,
                              const struct cl_lock_descr *descr)
{
        struct lov_stripe_md *lsm = lov_r0(lov)->lo_lsm;
        obd_off start;
        obd_off end;

        start = cl_offset(&lov->lo_cl, descr->cld_start);
        end   = cl_offset(&lov->lo_cl, descr->cld_end + 1) - 1;
        return
                end - start <= lsm->lsm_stripe_size &&
                stripe == lov_stripe_number(lsm, start) &&
                stripe == lov_stripe_number(lsm, end);
}

/**
 * An implementation of cl_lock_operations::clo_fits_into() method.
 *
 * Checks whether a lock (given by \a slice) is suitable for \a
 * io. Multi-stripe locks can be used only for "quick" io, like truncate, or
 * O_APPEND write.
 *
 * \see ccc_lock_fits_into().
 */
static int lov_lock_fits_into(const struct lu_env *env,
                              const struct cl_lock_slice *slice,
                              const struct cl_lock_descr *need,
                              const struct cl_io *io)
{
        struct lov_lock   *lov = cl2lov_lock(slice);
        struct lov_object *obj = cl2lov(slice->cls_obj);
        int result;

        LASSERT(cl_object_same(need->cld_obj, slice->cls_obj));
        LASSERT(lov->lls_nr > 0);

        ENTRY;

        if (lov->lls_nr == 1) {
                /*
                 * If a lock is on a single stripe, it's enough to check that
                 * @need lock matches actually granted stripe lock, and...
                 */
                result = cl_lock_ext_match(&lov->lls_sub[0].sub_got, need);
                if (result && lov_r0(obj)->lo_nr > 1)
                        /*
                         * ... @need is on the same stripe, if multiple
                         * stripes are possible at all for this object.
                         */
                        result = lov_is_same_stripe(cl2lov(slice->cls_obj),
                                                    lov->lls_sub[0].sub_stripe,
                                                    need);
        } else if (io->ci_type != CIT_TRUNC && io->ci_type != CIT_MISC &&
                   !cl_io_is_append(io) && need->cld_mode != CLM_PHANTOM)
                /*
                 * Multi-stripe locks are only suitable for `quick' IO and for
                 * glimpse.
                 */
                result = 0;
        else
                /*
                 * Most general case: multi-stripe existing lock, and
                 * (potentially) multi-stripe @need lock. Check that @need is
                 * covered by @lov's sub-locks.
                 *
                 * For now, ignore lock expansions made by the server, and
                 * match against original lock extent.
                 */
                result = cl_lock_ext_match(&lov->lls_orig, need);
        CDEBUG(D_DLMTRACE, DDESCR"/"DDESCR" %i %i/%i: %i\n",
               PDESCR(&lov->lls_orig), PDESCR(&lov->lls_sub[0].sub_got),
               lov->lls_sub[0].sub_stripe, lov->lls_nr, lov_r0(obj)->lo_nr,
               result);
        RETURN(result);
}

void lov_lock_unlink(const struct lu_env *env,
                     struct lov_lock_link *link, struct lovsub_lock *sub)
{
        struct lov_lock *lck    = link->lll_super;
        struct cl_lock  *parent = lck->lls_cl.cls_lock;

        LASSERT(cl_lock_is_mutexed(parent));
        LASSERT(cl_lock_is_mutexed(sub->lss_cl.cls_lock));
        ENTRY;

        list_del_init(&link->lll_list);
        LASSERT(lck->lls_sub[link->lll_idx].sub_lock == sub);
        /* yank this sub-lock from parent's array */
        lck->lls_sub[link->lll_idx].sub_lock = NULL;
        LASSERT(lck->lls_nr_filled > 0);
        lck->lls_nr_filled--;
        lu_ref_del(&parent->cll_reference, "lov-child", sub->lss_cl.cls_lock);
        cl_lock_put(env, parent);
        OBD_SLAB_FREE_PTR(link, lov_lock_link_kmem);
        EXIT;
}

struct lov_lock_link *lov_lock_link_find(const struct lu_env *env,
                                         struct lov_lock *lck,
                                         struct lovsub_lock *sub)
{
        struct lov_lock_link *scan;

        LASSERT(cl_lock_is_mutexed(sub->lss_cl.cls_lock));
        ENTRY;

        list_for_each_entry(scan, &sub->lss_parents, lll_list) {
                if (scan->lll_super == lck)
                        RETURN(scan);
        }
        RETURN(NULL);
}

/**
 * An implementation of cl_lock_operations::clo_delete() method. This is
 * invoked for "top-to-bottom" delete, when lock destruction starts from the
 * top-lock, e.g., as a result of inode destruction.
 *
 * Unlinks top-lock from all its sub-locks. Sub-locks are not deleted there:
 * this is done separately elsewhere:
 *
 *     - for inode destruction, lov_object_delete() calls cl_object_kill() for
 *       each sub-object, purging its locks;
 *
 *     - in other cases (e.g., a fatal error with a top-lock) sub-locks are
 *       left in the cache.
 */
static void lov_lock_delete(const struct lu_env *env,
                            const struct cl_lock_slice *slice)
{
        struct lov_lock        *lck     = cl2lov_lock(slice);
        struct cl_lock_closure *closure = lov_closure_get(env, slice->cls_lock);
        int i;

        LASSERT(slice->cls_lock->cll_state == CLS_FREEING);
        ENTRY;

        for (i = 0; i < lck->lls_nr; ++i) {
                struct lovsub_lock *lsl;
                struct cl_lock *sublock;
                int rc;

                lsl = lck->lls_sub[i].sub_lock;
                if (lsl == NULL)
                        continue;

                sublock = lsl->lss_cl.cls_lock;
                rc = lov_sublock_lock(env, lsl, closure);
                if (rc == 0) {
                        if (lck->lls_sub[i].sub_flags & LSF_HELD)
                                lov_sublock_release(env, lck, i, 1, 0);
                        if (sublock->cll_state < CLS_FREEING) {
                                struct lov_lock_link *link;

                                link = lov_lock_link_find(env, lck, lsl);
                                LASSERT(link != NULL);
                                lov_lock_unlink(env, link, lsl);
                                LASSERT(lck->lls_sub[i].sub_lock == NULL);
                        }
                        lov_sublock_unlock(env, lsl, closure);
                } else if (rc == CLO_REPEAT) {
                        --i; /* repeat with this lock */
                } else {
                        CL_LOCK_DEBUG(D_ERROR, env, sublock,
                                      "Cannot get sub-lock for delete: %i\n",
                                      rc);
                }
        }
        cl_lock_closure_fini(closure);
        EXIT;
}

static int lov_lock_print(const struct lu_env *env, void *cookie,
                          lu_printer_t p, const struct cl_lock_slice *slice)
{
        struct lov_lock *lck = cl2lov_lock(slice);
        int              i;

        (*p)(env, cookie, "%d\n", lck->lls_nr);
        for (i = 0; i < lck->lls_nr; ++i) {
                struct lov_lock_sub *sub;

                sub = &lck->lls_sub[i];
                (*p)(env, cookie, "    %d %x: ", i, sub->sub_flags);
                if (sub->sub_lock != NULL)
                        cl_lock_print(env, cookie, p,
                                      sub->sub_lock->lss_cl.cls_lock);
                else
                        (*p)(env, cookie, "---\n");
        }
        return 0;
}

static const struct cl_lock_operations lov_lock_ops = {
        .clo_fini      = lov_lock_fini,
        .clo_enqueue   = lov_lock_enqueue,
        .clo_wait      = lov_lock_wait,
        .clo_use       = lov_lock_use,
        .clo_unuse     = lov_lock_unuse,
        .clo_fits_into = lov_lock_fits_into,
        .clo_delete    = lov_lock_delete,
        .clo_print     = lov_lock_print
};

int lov_lock_init_raid0(const struct lu_env *env, struct cl_object *obj,
                        struct cl_lock *lock, const struct cl_io *io)
{
        struct lov_lock *lck;
        int result;

        ENTRY;
        OBD_SLAB_ALLOC_PTR(lck, lov_lock_kmem);
        if (lck != NULL) {
                cl_lock_slice_add(lock, &lck->lls_cl, obj, &lov_lock_ops);
                result = lov_lock_sub_init(env, lck, io);
        } else
                result = -ENOMEM;
        RETURN(result);
}

static struct cl_lock_closure *lov_closure_get(const struct lu_env *env,
                                               struct cl_lock *parent)
{
        struct cl_lock_closure *closure;

        closure = &lov_env_info(env)->lti_closure;
        LINVRNT(list_empty(&closure->clc_list));
        cl_lock_closure_init(env, closure, parent, 1);
        return closure;
}


/** @} lov */
