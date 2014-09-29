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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_extent.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

/**
 * This file contains implementation of EXTENT lock type
 *
 * EXTENT lock type is for locking a contiguous range of values, represented
 * by 64-bit starting and ending offsets (inclusive). There are several extent
 * lock modes, some of which may be mutually incompatible. Extent locks are
 * considered incompatible if their modes are incompatible and their extents
 * intersect.  See the lock mode compatibility matrix in lustre_dlm.h.
 */

#define DEBUG_SUBSYSTEM S_LDLM
#ifndef __KERNEL__
# include <liblustre.h>
#else
# include <libcfs/libcfs.h>
#endif

#include <lustre_dlm.h>
#include <obd_support.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_lib.h>

#include "ldlm_internal.h"

#ifdef HAVE_SERVER_SUPPORT
# define LDLM_MAX_GROWN_EXTENT (32 * 1024 * 1024 - 1)

/**
 * Fix up the ldlm_extent after expanding it.
 *
 * After expansion has been done, we might still want to do certain adjusting
 * based on overall contention of the resource and the like to avoid granting
 * overly wide locks.
 */
static void ldlm_extent_internal_policy_fixup(struct ldlm_lock *req,
                                              struct ldlm_extent *new_ex,
                                              int conflicting)
{
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_start = req->l_req_extent.start;
        __u64 req_end = req->l_req_extent.end;
        __u64 req_align, mask;

        if (conflicting > 32 && (req_mode == LCK_PW || req_mode == LCK_CW)) {
                if (req_end < req_start + LDLM_MAX_GROWN_EXTENT)
                        new_ex->end = min(req_start + LDLM_MAX_GROWN_EXTENT,
                                          new_ex->end);
        }

        if (new_ex->start == 0 && new_ex->end == OBD_OBJECT_EOF) {
                EXIT;
                return;
        }

        /* we need to ensure that the lock extent is properly aligned to what
         * the client requested. Also we need to make sure it's also server
         * page size aligned otherwise a server page can be covered by two
         * write locks. */
	mask = PAGE_CACHE_SIZE;
        req_align = (req_end + 1) | req_start;
        if (req_align != 0 && (req_align & (mask - 1)) == 0) {
                while ((req_align & mask) == 0)
                        mask <<= 1;
        }
        mask -= 1;
        /* We can only shrink the lock, not grow it.
         * This should never cause lock to be smaller than requested,
         * since requested lock was already aligned on these boundaries. */
        new_ex->start = ((new_ex->start - 1) | mask) + 1;
        new_ex->end = ((new_ex->end + 1) & ~mask) - 1;
        LASSERTF(new_ex->start <= req_start,
                 "mask "LPX64" grant start "LPU64" req start "LPU64"\n",
                 mask, new_ex->start, req_start);
        LASSERTF(new_ex->end >= req_end,
                 "mask "LPX64" grant end "LPU64" req end "LPU64"\n",
                 mask, new_ex->end, req_end);
}

/**
 * Return the maximum extent that:
 * - contains the requested extent
 * - does not overlap existing conflicting extents outside the requested one
 *
 * This allows clients to request a small required extent range, but if there
 * is no contention on the lock the full lock can be granted to the client.
 * This avoids the need for many smaller lock requests to be granted in the
 * common (uncontended) case.
 *
 * Use interval tree to expand the lock extent for granted lock.
 */
static void ldlm_extent_internal_policy_granted(struct ldlm_lock *req,
                                                struct ldlm_extent *new_ex)
{
        struct ldlm_resource *res = req->l_resource;
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_start = req->l_req_extent.start;
        __u64 req_end = req->l_req_extent.end;
        struct ldlm_interval_tree *tree;
        struct interval_node_extent limiter = { new_ex->start, new_ex->end };
        int conflicting = 0;
        int idx;
        ENTRY;

        lockmode_verify(req_mode);

	/* Using interval tree to handle the LDLM extent granted locks. */
        for (idx = 0; idx < LCK_MODE_NUM; idx++) {
                struct interval_node_extent ext = { req_start, req_end };

                tree = &res->lr_itree[idx];
                if (lockmode_compat(tree->lit_mode, req_mode))
                        continue;

                conflicting += tree->lit_size;
                if (conflicting > 4)
                        limiter.start = req_start;

                if (interval_is_overlapped(tree->lit_root, &ext))
                        CDEBUG(D_INFO, 
                               "req_mode = %d, tree->lit_mode = %d, "
                               "tree->lit_size = %d\n",
                               req_mode, tree->lit_mode, tree->lit_size);
                interval_expand(tree->lit_root, &ext, &limiter);
                limiter.start = max(limiter.start, ext.start);
                limiter.end = min(limiter.end, ext.end);
                if (limiter.start == req_start && limiter.end == req_end)
                        break;
        }

        new_ex->start = limiter.start;
        new_ex->end = limiter.end;
        LASSERT(new_ex->start <= req_start);
        LASSERT(new_ex->end >= req_end);

        ldlm_extent_internal_policy_fixup(req, new_ex, conflicting);
        EXIT;
}

/* The purpose of this function is to return:
 * - the maximum extent
 * - containing the requested extent
 * - and not overlapping existing conflicting extents outside the requested one
 */
static void
ldlm_extent_internal_policy_waiting(struct ldlm_lock *req,
                                    struct ldlm_extent *new_ex)
{
        cfs_list_t *tmp;
        struct ldlm_resource *res = req->l_resource;
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_start = req->l_req_extent.start;
        __u64 req_end = req->l_req_extent.end;
        int conflicting = 0;
        ENTRY;

        lockmode_verify(req_mode);

        /* for waiting locks */
        cfs_list_for_each(tmp, &res->lr_waiting) {
                struct ldlm_lock *lock;
                struct ldlm_extent *l_extent;

                lock = cfs_list_entry(tmp, struct ldlm_lock, l_res_link);
                l_extent = &lock->l_policy_data.l_extent;

                /* We already hit the minimum requested size, search no more */
                if (new_ex->start == req_start && new_ex->end == req_end) {
                        EXIT;
                        return;
                }

                /* Don't conflict with ourselves */
                if (req == lock)
                        continue;

                /* Locks are compatible, overlap doesn't matter */
                /* Until bug 20 is fixed, try to avoid granting overlapping
                 * locks on one client (they take a long time to cancel) */
                if (lockmode_compat(lock->l_req_mode, req_mode) &&
                    lock->l_export != req->l_export)
                        continue;

                /* If this is a high-traffic lock, don't grow downwards at all
                 * or grow upwards too much */
                ++conflicting;
                if (conflicting > 4)
                        new_ex->start = req_start;

                /* If lock doesn't overlap new_ex, skip it. */
                if (!ldlm_extent_overlap(l_extent, new_ex))
                        continue;

                /* Locks conflicting in requested extents and we can't satisfy
                 * both locks, so ignore it.  Either we will ping-pong this
                 * extent (we would regardless of what extent we granted) or
                 * lock is unused and it shouldn't limit our extent growth. */
                if (ldlm_extent_overlap(&lock->l_req_extent,&req->l_req_extent))
                        continue;

                /* We grow extents downwards only as far as they don't overlap
                 * with already-granted locks, on the assumption that clients
                 * will be writing beyond the initial requested end and would
                 * then need to enqueue a new lock beyond previous request.
                 * l_req_extent->end strictly < req_start, checked above. */
                if (l_extent->start < req_start && new_ex->start != req_start) {
                        if (l_extent->end >= req_start)
                                new_ex->start = req_start;
                        else
                                new_ex->start = min(l_extent->end+1, req_start);
                }

                /* If we need to cancel this lock anyways because our request
                 * overlaps the granted lock, we grow up to its requested
                 * extent start instead of limiting this extent, assuming that
                 * clients are writing forwards and the lock had over grown
                 * its extent downwards before we enqueued our request. */
                if (l_extent->end > req_end) {
                        if (l_extent->start <= req_end)
                                new_ex->end = max(lock->l_req_extent.start - 1,
                                                  req_end);
                        else
                                new_ex->end = max(l_extent->start - 1, req_end);
                }
        }

        ldlm_extent_internal_policy_fixup(req, new_ex, conflicting);
        EXIT;
}


/* In order to determine the largest possible extent we can grant, we need
 * to scan all of the queues. */
static void ldlm_extent_policy(struct ldlm_resource *res,
			       struct ldlm_lock *lock, __u64 *flags)
{
        struct ldlm_extent new_ex = { .start = 0, .end = OBD_OBJECT_EOF };

        if (lock->l_export == NULL)
                /*
                 * this is local lock taken by server (e.g., as a part of
                 * OST-side locking, or unlink handling). Expansion doesn't
                 * make a lot of sense for local locks, because they are
                 * dropped immediately on operation completion and would only
                 * conflict with other threads.
                 */
                return;

        if (lock->l_policy_data.l_extent.start == 0 &&
            lock->l_policy_data.l_extent.end == OBD_OBJECT_EOF)
                /* fast-path whole file locks */
                return;

        ldlm_extent_internal_policy_granted(lock, &new_ex);
        ldlm_extent_internal_policy_waiting(lock, &new_ex);

        if (new_ex.start != lock->l_policy_data.l_extent.start ||
            new_ex.end != lock->l_policy_data.l_extent.end) {
                *flags |= LDLM_FL_LOCK_CHANGED;
                lock->l_policy_data.l_extent.start = new_ex.start;
                lock->l_policy_data.l_extent.end = new_ex.end;
        }
}

static int ldlm_check_contention(struct ldlm_lock *lock, int contended_locks)
{
        struct ldlm_resource *res = lock->l_resource;
        cfs_time_t now = cfs_time_current();

        if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_SET_CONTENTION))
                return 1;

        CDEBUG(D_DLMTRACE, "contended locks = %d\n", contended_locks);
        if (contended_locks > ldlm_res_to_ns(res)->ns_contended_locks)
                res->lr_contention_time = now;
        return cfs_time_before(now, cfs_time_add(res->lr_contention_time,
                cfs_time_seconds(ldlm_res_to_ns(res)->ns_contention_time)));
}

struct ldlm_extent_compat_args {
        cfs_list_t *work_list;
        struct ldlm_lock *lock;
        ldlm_mode_t mode;
        int *locks;
        int *compat;
};

static enum interval_iter ldlm_extent_compat_cb(struct interval_node *n,
                                                void *data)
{
        struct ldlm_extent_compat_args *priv = data;
        struct ldlm_interval *node = to_ldlm_interval(n);
        struct ldlm_extent *extent;
        cfs_list_t *work_list = priv->work_list;
        struct ldlm_lock *lock, *enq = priv->lock;
        ldlm_mode_t mode = priv->mode;
        int count = 0;
        ENTRY;

        LASSERT(!cfs_list_empty(&node->li_group));

        cfs_list_for_each_entry(lock, &node->li_group, l_sl_policy) {
                /* interval tree is for granted lock */
                LASSERTF(mode == lock->l_granted_mode,
                         "mode = %s, lock->l_granted_mode = %s\n",
                         ldlm_lockname[mode],
                         ldlm_lockname[lock->l_granted_mode]);
                count++;
                if (lock->l_blocking_ast)
                        ldlm_add_ast_work_item(lock, enq, work_list);
        }

        /* don't count conflicting glimpse locks */
        extent = ldlm_interval_extent(node);
        if (!(mode == LCK_PR &&
            extent->start == 0 && extent->end == OBD_OBJECT_EOF))
                *priv->locks += count;

        if (priv->compat)
                *priv->compat = 0;

        RETURN(INTERVAL_ITER_CONT);
}

/**
 * Determine if the lock is compatible with all locks on the queue.
 *
 * If \a work_list is provided, conflicting locks are linked there.
 * If \a work_list is not provided, we exit this function on first conflict.
 *
 * \retval 0 if the lock is not compatible
 * \retval 1 if the lock is compatible
 * \retval 2 if \a req is a group lock and it is compatible and requires
 *           no further checking
 * \retval negative error, such as EWOULDBLOCK for group locks
 */
static int
ldlm_extent_compat_queue(cfs_list_t *queue, struct ldlm_lock *req,
			 __u64 *flags, ldlm_error_t *err,
			 cfs_list_t *work_list, int *contended_locks)
{
        cfs_list_t *tmp;
        struct ldlm_lock *lock;
        struct ldlm_resource *res = req->l_resource;
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_start = req->l_req_extent.start;
        __u64 req_end = req->l_req_extent.end;
        int compat = 1;
        int scan = 0;
        int check_contention;
        ENTRY;

        lockmode_verify(req_mode);

        /* Using interval tree for granted lock */
        if (queue == &res->lr_granted) {
                struct ldlm_interval_tree *tree;
                struct ldlm_extent_compat_args data = {.work_list = work_list,
                                               .lock = req,
                                               .locks = contended_locks,
                                               .compat = &compat };
                struct interval_node_extent ex = { .start = req_start,
                                                   .end = req_end };
                int idx, rc;

                for (idx = 0; idx < LCK_MODE_NUM; idx++) {
                        tree = &res->lr_itree[idx];
                        if (tree->lit_root == NULL) /* empty tree, skipped */
                                continue;

                        data.mode = tree->lit_mode;
                        if (lockmode_compat(req_mode, tree->lit_mode)) {
                                struct ldlm_interval *node;
                                struct ldlm_extent *extent;

                                if (req_mode != LCK_GROUP)
                                        continue;

                                /* group lock, grant it immediately if
                                 * compatible */
                                node = to_ldlm_interval(tree->lit_root);
                                extent = ldlm_interval_extent(node);
                                if (req->l_policy_data.l_extent.gid ==
                                    extent->gid)
                                        RETURN(2);
                        }

                        if (tree->lit_mode == LCK_GROUP) {
                                if (*flags & LDLM_FL_BLOCK_NOWAIT) {
                                        compat = -EWOULDBLOCK;
                                        goto destroylock;
                                }

                                *flags |= LDLM_FL_NO_TIMEOUT;
                                if (!work_list)
                                        RETURN(0);

                                /* if work list is not NULL,add all
                                   locks in the tree to work list */
                                compat = 0;
                                interval_iterate(tree->lit_root,
                                                 ldlm_extent_compat_cb, &data);
                                continue;
                        }

                        if (!work_list) {
                                rc = interval_is_overlapped(tree->lit_root,&ex);
                                if (rc)
                                        RETURN(0);
                        } else {
                                interval_search(tree->lit_root, &ex,
                                                ldlm_extent_compat_cb, &data);
                                if (!cfs_list_empty(work_list) && compat)
                                        compat = 0;
                        }
                }
        } else { /* for waiting queue */
                cfs_list_for_each(tmp, queue) {
                        check_contention = 1;

                        lock = cfs_list_entry(tmp, struct ldlm_lock,
                                              l_res_link);

			/* We stop walking the queue if we hit ourselves so
			 * we don't take conflicting locks enqueued after us
			 * into account, or we'd wait forever. */
                        if (req == lock)
                                break;

                        if (unlikely(scan)) {
                                /* We only get here if we are queuing GROUP lock
                                   and met some incompatible one. The main idea of this
                                   code is to insert GROUP lock past compatible GROUP
                                   lock in the waiting queue or if there is not any,
                                   then in front of first non-GROUP lock */
                                if (lock->l_req_mode != LCK_GROUP) {
                                        /* Ok, we hit non-GROUP lock, there should
                                         * be no more GROUP locks later on, queue in
                                         * front of first non-GROUP lock */

                                        ldlm_resource_insert_lock_after(lock, req);
                                        cfs_list_del_init(&lock->l_res_link);
                                        ldlm_resource_insert_lock_after(req, lock);
                                        compat = 0;
                                        break;
                                }
                                if (req->l_policy_data.l_extent.gid ==
                                    lock->l_policy_data.l_extent.gid) {
                                        /* found it */
                                        ldlm_resource_insert_lock_after(lock, req);
                                        compat = 0;
                                        break;
                                }
                                continue;
                        }

                        /* locks are compatible, overlap doesn't matter */
                        if (lockmode_compat(lock->l_req_mode, req_mode)) {
                                if (req_mode == LCK_PR &&
                                    ((lock->l_policy_data.l_extent.start <=
                                      req->l_policy_data.l_extent.start) &&
                                     (lock->l_policy_data.l_extent.end >=
                                      req->l_policy_data.l_extent.end))) {
                                        /* If we met a PR lock just like us or wider,
                                           and nobody down the list conflicted with
                                           it, that means we can skip processing of
                                           the rest of the list and safely place
                                           ourselves at the end of the list, or grant
                                           (dependent if we met an conflicting locks
                                           before in the list).
                                           In case of 1st enqueue only we continue
                                           traversing if there is something conflicting
                                           down the list because we need to make sure
                                           that something is marked as AST_SENT as well,
                                           in cse of empy worklist we would exit on
                                           first conflict met. */
                                        /* There IS a case where such flag is
                                           not set for a lock, yet it blocks
                                           something. Luckily for us this is
                                           only during destroy, so lock is
                                           exclusive. So here we are safe */
                                        if (!(lock->l_flags & LDLM_FL_AST_SENT)) {
                                                RETURN(compat);
                                        }
                                }

                                /* non-group locks are compatible, overlap doesn't
                                   matter */
                                if (likely(req_mode != LCK_GROUP))
                                        continue;

                                /* If we are trying to get a GROUP lock and there is
                                   another one of this kind, we need to compare gid */
                                if (req->l_policy_data.l_extent.gid ==
                                    lock->l_policy_data.l_extent.gid) {
                                        /* If existing lock with matched gid is granted,
                                           we grant new one too. */
                                        if (lock->l_req_mode == lock->l_granted_mode)
                                                RETURN(2);

                                        /* Otherwise we are scanning queue of waiting
                                         * locks and it means current request would
                                         * block along with existing lock (that is
                                         * already blocked.
                                         * If we are in nonblocking mode - return
                                         * immediately */
                                        if (*flags & LDLM_FL_BLOCK_NOWAIT) {
                                                compat = -EWOULDBLOCK;
                                                goto destroylock;
                                        }
                                        /* If this group lock is compatible with another
                                         * group lock on the waiting list, they must be
                                         * together in the list, so they can be granted
                                         * at the same time.  Otherwise the later lock
                                         * can get stuck behind another, incompatible,
                                         * lock. */
                                        ldlm_resource_insert_lock_after(lock, req);
                                        /* Because 'lock' is not granted, we can stop
                                         * processing this queue and return immediately.
                                         * There is no need to check the rest of the
                                         * list. */
                                        RETURN(0);
                                }
                        }

                        if (unlikely(req_mode == LCK_GROUP &&
                                     (lock->l_req_mode != lock->l_granted_mode))) {
                                scan = 1;
                                compat = 0;
                                if (lock->l_req_mode != LCK_GROUP) {
                                        /* Ok, we hit non-GROUP lock, there should be no
                                           more GROUP locks later on, queue in front of
                                           first non-GROUP lock */

                                        ldlm_resource_insert_lock_after(lock, req);
                                        cfs_list_del_init(&lock->l_res_link);
                                        ldlm_resource_insert_lock_after(req, lock);
                                        break;
                                }
                                if (req->l_policy_data.l_extent.gid ==
                                    lock->l_policy_data.l_extent.gid) {
                                        /* found it */
                                        ldlm_resource_insert_lock_after(lock, req);
                                        break;
                                }
                                continue;
                        }

                        if (unlikely(lock->l_req_mode == LCK_GROUP)) {
                                /* If compared lock is GROUP, then requested is PR/PW/
                                 * so this is not compatible; extent range does not
                                 * matter */
                                if (*flags & LDLM_FL_BLOCK_NOWAIT) {
                                        compat = -EWOULDBLOCK;
                                        goto destroylock;
                                } else {
                                        *flags |= LDLM_FL_NO_TIMEOUT;
                                }
                        } else if (lock->l_policy_data.l_extent.end < req_start ||
                                   lock->l_policy_data.l_extent.start > req_end) {
                                /* if a non group lock doesn't overlap skip it */
                                continue;
                        } else if (lock->l_req_extent.end < req_start ||
                                   lock->l_req_extent.start > req_end) {
                                /* false contention, the requests doesn't really overlap */
                                check_contention = 0;
                        }

                        if (!work_list)
                                RETURN(0);

                        /* don't count conflicting glimpse locks */
                        if (lock->l_req_mode == LCK_PR &&
                            lock->l_policy_data.l_extent.start == 0 &&
                            lock->l_policy_data.l_extent.end == OBD_OBJECT_EOF)
                                check_contention = 0;

                        *contended_locks += check_contention;

                        compat = 0;
                        if (lock->l_blocking_ast)
                                ldlm_add_ast_work_item(lock, req, work_list);
                }
        }

        if (ldlm_check_contention(req, *contended_locks) &&
            compat == 0 &&
            (*flags & LDLM_FL_DENY_ON_CONTENTION) &&
            req->l_req_mode != LCK_GROUP &&
            req_end - req_start <=
            ldlm_res_to_ns(req->l_resource)->ns_max_nolock_size)
                GOTO(destroylock, compat = -EUSERS);

        RETURN(compat);
destroylock:
        cfs_list_del_init(&req->l_res_link);
        ldlm_lock_destroy_nolock(req);
        *err = compat;
        RETURN(compat);
}

/**
 * Discard all AST work items from list.
 *
 * If for whatever reason we do not want to send ASTs to conflicting locks
 * anymore, disassemble the list with this function.
 */
static void discard_bl_list(cfs_list_t *bl_list)
{
        cfs_list_t *tmp, *pos;
        ENTRY;

        cfs_list_for_each_safe(pos, tmp, bl_list) {
                struct ldlm_lock *lock =
                        cfs_list_entry(pos, struct ldlm_lock, l_bl_ast);

                cfs_list_del_init(&lock->l_bl_ast);
                LASSERT(lock->l_flags & LDLM_FL_AST_SENT);
                lock->l_flags &= ~LDLM_FL_AST_SENT;
                LASSERT(lock->l_bl_ast_run == 0);
                LASSERT(lock->l_blocking_lock);
                LDLM_LOCK_RELEASE(lock->l_blocking_lock);
                lock->l_blocking_lock = NULL;
                LDLM_LOCK_RELEASE(lock);
        }
        EXIT;
}

/**
 * Process a granting attempt for extent lock.
 * Must be called with ns lock held.
 *
 * This function looks for any conflicts for \a lock in the granted or
 * waiting queues. The lock is granted if no conflicts are found in
 * either queue.
 *
 * If \a first_enq is 0 (ie, called from ldlm_reprocess_queue):
 *   - blocking ASTs have already been sent
 *
 * If \a first_enq is 1 (ie, called from ldlm_lock_enqueue):
 *   - blocking ASTs have not been sent yet, so list of conflicting locks
 *     would be collected and ASTs sent.
 */
int ldlm_process_extent_lock(struct ldlm_lock *lock, __u64 *flags,
			     int first_enq, ldlm_error_t *err,
			     cfs_list_t *work_list)
{
        struct ldlm_resource *res = lock->l_resource;
        CFS_LIST_HEAD(rpc_list);
        int rc, rc2;
        int contended_locks = 0;
        ENTRY;

	LASSERT(lock->l_granted_mode != lock->l_req_mode);
	LASSERT(cfs_list_empty(&res->lr_converting));
	LASSERT(!(*flags & LDLM_FL_DENY_ON_CONTENTION) ||
		!(lock->l_flags & LDLM_FL_AST_DISCARD_DATA));
	check_res_locked(res);
	*err = ELDLM_OK;

        if (!first_enq) {
                /* Careful observers will note that we don't handle -EWOULDBLOCK
                 * here, but it's ok for a non-obvious reason -- compat_queue
                 * can only return -EWOULDBLOCK if (flags & BLOCK_NOWAIT).
                 * flags should always be zero here, and if that ever stops
                 * being true, we want to find out. */
                LASSERT(*flags == 0);
                rc = ldlm_extent_compat_queue(&res->lr_granted, lock, flags,
                                              err, NULL, &contended_locks);
                if (rc == 1) {
                        rc = ldlm_extent_compat_queue(&res->lr_waiting, lock,
                                                      flags, err, NULL,
                                                      &contended_locks);
                }
                if (rc == 0)
                        RETURN(LDLM_ITER_STOP);

                ldlm_resource_unlink_lock(lock);

                if (!OBD_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_EVICT_RACE))
                        ldlm_extent_policy(res, lock, flags);
                ldlm_grant_lock(lock, work_list);
                RETURN(LDLM_ITER_CONTINUE);
        }

 restart:
        contended_locks = 0;
        rc = ldlm_extent_compat_queue(&res->lr_granted, lock, flags, err,
                                      &rpc_list, &contended_locks);
        if (rc < 0)
                GOTO(out, rc); /* lock was destroyed */
        if (rc == 2)
                goto grant;

        rc2 = ldlm_extent_compat_queue(&res->lr_waiting, lock, flags, err,
                                       &rpc_list, &contended_locks);
        if (rc2 < 0)
                GOTO(out, rc = rc2); /* lock was destroyed */

        if (rc + rc2 == 2) {
        grant:
                ldlm_extent_policy(res, lock, flags);
                ldlm_resource_unlink_lock(lock);
                ldlm_grant_lock(lock, NULL);
        } else {
                /* If either of the compat_queue()s returned failure, then we
                 * have ASTs to send and must go onto the waiting list.
                 *
                 * bug 2322: we used to unlink and re-add here, which was a
                 * terrible folly -- if we goto restart, we could get
                 * re-ordered!  Causes deadlock, because ASTs aren't sent! */
                if (cfs_list_empty(&lock->l_res_link))
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                unlock_res(res);
                rc = ldlm_run_ast_work(ldlm_res_to_ns(res), &rpc_list,
                                       LDLM_WORK_BL_AST);

                if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_OST_FAIL_RACE) &&
                    !ns_is_client(ldlm_res_to_ns(res)))
                        class_fail_export(lock->l_export);

		lock_res(res);
		if (rc == -ERESTART) {
			/* 15715: The lock was granted and destroyed after
			 * resource lock was dropped. Interval node was freed
			 * in ldlm_lock_destroy. Anyway, this always happens
			 * when a client is being evicted. So it would be
			 * ok to return an error. -jay */
			if (lock->l_flags & LDLM_FL_DESTROYED) {
				*err = -EAGAIN;
				GOTO(out, rc = -EAGAIN);
			}

			/* lock was granted while resource was unlocked. */
			if (lock->l_granted_mode == lock->l_req_mode) {
				/* bug 11300: if the lock has been granted,
				 * break earlier because otherwise, we will go
				 * to restart and ldlm_resource_unlink will be
				 * called and it causes the interval node to be
				 * freed. Then we will fail at
				 * ldlm_extent_add_lock() */
				*flags &= ~LDLM_FL_BLOCKED_MASK;
				GOTO(out, rc = 0);
			}

			GOTO(restart, -ERESTART);
		}

		/* this way we force client to wait for the lock
		 * endlessly once the lock is enqueued -bzzz */
		*flags |= LDLM_FL_BLOCK_GRANTED | LDLM_FL_NO_TIMEOUT;

	}
	RETURN(0);
out:
	if (!cfs_list_empty(&rpc_list)) {
		LASSERT(!(lock->l_flags & LDLM_FL_AST_DISCARD_DATA));
		discard_bl_list(&rpc_list);
	}
	RETURN(rc);
}
#endif /* HAVE_SERVER_SUPPORT */

/* When a lock is cancelled by a client, the KMS may undergo change if this
 * is the "highest lock".  This function returns the new KMS value.
 * Caller must hold lr_lock already.
 *
 * NB: A lock on [x,y] protects a KMS of up to y + 1 bytes! */
__u64 ldlm_extent_shift_kms(struct ldlm_lock *lock, __u64 old_kms)
{
        struct ldlm_resource *res = lock->l_resource;
        cfs_list_t *tmp;
        struct ldlm_lock *lck;
        __u64 kms = 0;
        ENTRY;

        /* don't let another thread in ldlm_extent_shift_kms race in
         * just after we finish and take our lock into account in its
         * calculation of the kms */
        lock->l_flags |= LDLM_FL_KMS_IGNORE;

        cfs_list_for_each(tmp, &res->lr_granted) {
                lck = cfs_list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lck->l_flags & LDLM_FL_KMS_IGNORE)
                        continue;

                if (lck->l_policy_data.l_extent.end >= old_kms)
                        RETURN(old_kms);

                /* This extent _has_ to be smaller than old_kms (checked above)
                 * so kms can only ever be smaller or the same as old_kms. */
                if (lck->l_policy_data.l_extent.end + 1 > kms)
                        kms = lck->l_policy_data.l_extent.end + 1;
        }
        LASSERTF(kms <= old_kms, "kms "LPU64" old_kms "LPU64"\n", kms, old_kms);

        RETURN(kms);
}
EXPORT_SYMBOL(ldlm_extent_shift_kms);

struct kmem_cache *ldlm_interval_slab;
struct ldlm_interval *ldlm_interval_alloc(struct ldlm_lock *lock)
{
	struct ldlm_interval *node;
	ENTRY;

	LASSERT(lock->l_resource->lr_type == LDLM_EXTENT);
	OBD_SLAB_ALLOC_PTR_GFP(node, ldlm_interval_slab, GFP_NOFS);
	if (node == NULL)
		RETURN(NULL);

	CFS_INIT_LIST_HEAD(&node->li_group);
	ldlm_interval_attach(node, lock);
	RETURN(node);
}

void ldlm_interval_free(struct ldlm_interval *node)
{
        if (node) {
                LASSERT(cfs_list_empty(&node->li_group));
                LASSERT(!interval_is_intree(&node->li_node));
                OBD_SLAB_FREE(node, ldlm_interval_slab, sizeof(*node));
        }
}

/* interval tree, for LDLM_EXTENT. */
void ldlm_interval_attach(struct ldlm_interval *n,
                          struct ldlm_lock *l)
{
        LASSERT(l->l_tree_node == NULL);
        LASSERT(l->l_resource->lr_type == LDLM_EXTENT);

        cfs_list_add_tail(&l->l_sl_policy, &n->li_group);
        l->l_tree_node = n;
}

struct ldlm_interval *ldlm_interval_detach(struct ldlm_lock *l)
{
        struct ldlm_interval *n = l->l_tree_node;

        if (n == NULL)
                return NULL;

        LASSERT(!cfs_list_empty(&n->li_group));
        l->l_tree_node = NULL;
        cfs_list_del_init(&l->l_sl_policy);

        return (cfs_list_empty(&n->li_group) ? n : NULL);
}

static inline int lock_mode_to_index(ldlm_mode_t mode)
{
        int index;

        LASSERT(mode != 0);
        LASSERT(IS_PO2(mode));
        for (index = -1; mode; index++, mode >>= 1) ;
        LASSERT(index < LCK_MODE_NUM);
        return index;
}

/** Add newly granted lock into interval tree for the resource. */
void ldlm_extent_add_lock(struct ldlm_resource *res,
                          struct ldlm_lock *lock)
{
        struct interval_node *found, **root;
        struct ldlm_interval *node;
        struct ldlm_extent *extent;
        int idx;

        LASSERT(lock->l_granted_mode == lock->l_req_mode);

        node = lock->l_tree_node;
        LASSERT(node != NULL);
        LASSERT(!interval_is_intree(&node->li_node));

        idx = lock_mode_to_index(lock->l_granted_mode);
        LASSERT(lock->l_granted_mode == 1 << idx);
        LASSERT(lock->l_granted_mode == res->lr_itree[idx].lit_mode);

        /* node extent initialize */
        extent = &lock->l_policy_data.l_extent;
        interval_set(&node->li_node, extent->start, extent->end);

        root = &res->lr_itree[idx].lit_root;
        found = interval_insert(&node->li_node, root);
        if (found) { /* The policy group found. */
                struct ldlm_interval *tmp = ldlm_interval_detach(lock);
                LASSERT(tmp != NULL);
                ldlm_interval_free(tmp);
                ldlm_interval_attach(to_ldlm_interval(found), lock);
        }
        res->lr_itree[idx].lit_size++;

        /* even though we use interval tree to manage the extent lock, we also
         * add the locks into grant list, for debug purpose, .. */
        ldlm_resource_add_lock(res, &res->lr_granted, lock);
}

/** Remove cancelled lock from resource interval tree. */
void ldlm_extent_unlink_lock(struct ldlm_lock *lock)
{
        struct ldlm_resource *res = lock->l_resource;
        struct ldlm_interval *node = lock->l_tree_node;
        struct ldlm_interval_tree *tree;
        int idx;

        if (!node || !interval_is_intree(&node->li_node)) /* duplicate unlink */
                return;

        idx = lock_mode_to_index(lock->l_granted_mode);
        LASSERT(lock->l_granted_mode == 1 << idx);
        tree = &res->lr_itree[idx];

        LASSERT(tree->lit_root != NULL); /* assure the tree is not null */

        tree->lit_size--;
        node = ldlm_interval_detach(lock);
        if (node) {
                interval_erase(&node->li_node, &tree->lit_root);
                ldlm_interval_free(node);
        }
}

void ldlm_extent_policy_wire_to_local(const ldlm_wire_policy_data_t *wpolicy,
                                     ldlm_policy_data_t *lpolicy)
{
        memset(lpolicy, 0, sizeof(*lpolicy));
        lpolicy->l_extent.start = wpolicy->l_extent.start;
        lpolicy->l_extent.end = wpolicy->l_extent.end;
        lpolicy->l_extent.gid = wpolicy->l_extent.gid;
}

void ldlm_extent_policy_local_to_wire(const ldlm_policy_data_t *lpolicy,
                                     ldlm_wire_policy_data_t *wpolicy)
{
        memset(wpolicy, 0, sizeof(*wpolicy));
        wpolicy->l_extent.start = lpolicy->l_extent.start;
        wpolicy->l_extent.end = lpolicy->l_extent.end;
        wpolicy->l_extent.gid = lpolicy->l_extent.gid;
}

