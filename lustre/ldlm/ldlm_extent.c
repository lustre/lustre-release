/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#define DEBUG_SUBSYSTEM S_LDLM
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <lustre_dlm.h>
#include <obd_support.h>
#include <lustre_lib.h>

#include "ldlm_internal.h"

/* The purpose of this function is to return:
 * - the maximum extent
 * - containing the requested extent
 * - and not overlapping existing conflicting extents outside the requested one
 */
static void
ldlm_extent_internal_policy(struct list_head *queue, struct ldlm_lock *req,
                            struct ldlm_extent *new_ex)
{
        struct list_head *tmp;
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_start = req->l_req_extent.start;
        __u64 req_end = req->l_req_extent.end;
        int conflicting = 0;
        ENTRY;

        lockmode_verify(req_mode);

        list_for_each(tmp, queue) {
                struct ldlm_lock *lock;
                struct ldlm_extent *l_extent;

                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                l_extent = &lock->l_policy_data.l_extent;

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
                if (l_extent->end < new_ex->start ||
                    l_extent->start > new_ex->end)
                        continue;

                /* Locks conflicting in requested extents and we can't satisfy
                 * both locks, so ignore it.  Either we will ping-pong this
                 * extent (we would regardless of what extent we granted) or
                 * lock is unused and it shouldn't limit our extent growth. */
                if (lock->l_req_extent.end >= req_start &&
                    lock->l_req_extent.start <= req_end)
                        continue;

                /* We grow extents downwards only as far as they don't overlap
                 * with already-granted locks, on the assumtion that clients
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

#define LDLM_MAX_GROWN_EXTENT (32 * 1024 * 1024 - 1)
        if (conflicting > 32 && (req_mode == LCK_PW || req_mode == LCK_CW)) {
                if (req_end < req_start + LDLM_MAX_GROWN_EXTENT)
                        new_ex->end = min(req_start + LDLM_MAX_GROWN_EXTENT,
                                          new_ex->end);
        }
        EXIT;
}

/* In order to determine the largest possible extent we can grant, we need
 * to scan all of the queues. */
static void ldlm_extent_policy(struct ldlm_resource *res,
                               struct ldlm_lock *lock, int *flags)
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

        ldlm_extent_internal_policy(&res->lr_granted, lock, &new_ex);
        ldlm_extent_internal_policy(&res->lr_waiting, lock, &new_ex);

        if (new_ex.start != lock->l_policy_data.l_extent.start ||
            new_ex.end != lock->l_policy_data.l_extent.end) {
                *flags |= LDLM_FL_LOCK_CHANGED;
                lock->l_policy_data.l_extent.start = new_ex.start;
                lock->l_policy_data.l_extent.end = new_ex.end;
        }
}

/* Determine if the lock is compatible with all locks on the queue.
 * We stop walking the queue if we hit ourselves so we don't take
 * conflicting locks enqueued after us into accound, or we'd wait forever.
 *
 * 0 if the lock is not compatible
 * 1 if the lock is compatible
 * 2 if this group lock is compatible and requires no further checking
 * negative error, such as EWOULDBLOCK for group locks
 */
static int
ldlm_extent_compat_queue(struct list_head *queue, struct ldlm_lock *req,
                         int *flags, ldlm_error_t *err,
                         struct list_head *work_list)
{
        struct list_head *tmp;
        struct ldlm_lock *lock;
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_start = req->l_req_extent.start;
        __u64 req_end = req->l_req_extent.end;
        int compat = 1;
        int scan = 0;
        ENTRY;

        lockmode_verify(req_mode);

        list_for_each(tmp, queue) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (req == lock)
                        RETURN(compat);

                if (unlikely(scan)) {
                        /* We only get here if we are queuing GROUP lock
                           and met some incompatible one. The main idea of this
                           code is to insert GROUP lock past compatible GROUP
                           lock in the waiting queue or if there is not any,
                           then in front of first non-GROUP lock */
                        if (lock->l_req_mode != LCK_GROUP) {
                        /* Ok, we hit non-GROUP lock, there should be no
                           more GROUP locks later on, queue in front of
                           first non-GROUP lock */

                                ldlm_resource_insert_lock_after(lock, req);
                                list_del_init(&lock->l_res_link);
                                ldlm_resource_insert_lock_after(req, lock);
                                RETURN(0);
                        }
                        if (req->l_policy_data.l_extent.gid ==
                             lock->l_policy_data.l_extent.gid) {
                                /* found it */
                                ldlm_resource_insert_lock_after(lock, req);
                                RETURN(0);
                        }
                        continue;
                }

                /* locks are compatible, overlap doesn't matter */
                if (lockmode_compat(lock->l_req_mode, req_mode)) {
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
                                list_del_init(&lock->l_res_link);
                                ldlm_resource_insert_lock_after(req, lock);
                                RETURN(0);
                        }
                        if (req->l_policy_data.l_extent.gid ==
                             lock->l_policy_data.l_extent.gid) {
                                /* found it */
                                ldlm_resource_insert_lock_after(lock, req);
                                RETURN(0);
                        }
                        continue;
                }

                if (unlikely(lock->l_req_mode == LCK_GROUP)) {
                        /* If compared lock is GROUP,then requested is PR/PW/ =>
                         * this is not compatible; extent range does not
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
                }

                if (!work_list)
                        RETURN(0);

                compat = 0;
                if (lock->l_blocking_ast)
                        ldlm_add_ast_work_item(lock, req, work_list);
        }

        RETURN(compat);
destroylock:
        list_del_init(&req->l_res_link);
        ldlm_lock_destroy_nolock(req);
        *err = compat;
        RETURN(compat);
}

/* If first_enq is 0 (ie, called from ldlm_reprocess_queue):
  *   - blocking ASTs have already been sent
  *   - the caller has already initialized req->lr_tmp
  *   - must call this function with the ns lock held
  *
  * If first_enq is 1 (ie, called from ldlm_lock_enqueue):
  *   - blocking ASTs have not been sent
  *   - the caller has NOT initialized req->lr_tmp, so we must
  *   - must call this function with the ns lock held once */
int ldlm_process_extent_lock(struct ldlm_lock *lock, int *flags, int first_enq,
                             ldlm_error_t *err, struct list_head *work_list)
{
        struct ldlm_resource *res = lock->l_resource;
        struct list_head rpc_list = CFS_LIST_HEAD_INIT(rpc_list);
        int rc, rc2;
        ENTRY;

        LASSERT(list_empty(&res->lr_converting));
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
                                              err, NULL);
                if (rc == 1) {
                        rc = ldlm_extent_compat_queue(&res->lr_waiting, lock,
                                                      flags, err, NULL);
                }
                if (rc == 0)
                        RETURN(LDLM_ITER_STOP);

                ldlm_resource_unlink_lock(lock);

                ldlm_extent_policy(res, lock, flags);
                ldlm_grant_lock(lock, work_list);
                RETURN(LDLM_ITER_CONTINUE);
        }

 restart:
        rc = ldlm_extent_compat_queue(&res->lr_granted, lock, flags, err, &rpc_list);
        if (rc < 0)
                GOTO(out, rc); /* lock was destroyed */
        if (rc == 2)
                goto grant;

        rc2 = ldlm_extent_compat_queue(&res->lr_waiting, lock, flags, err, &rpc_list);
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
                if (list_empty(&lock->l_res_link))
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                unlock_res(res);
                rc = ldlm_run_bl_ast_work(&rpc_list);
                lock_res(res);
                if (rc == -ERESTART)
                        GOTO(restart, -ERESTART);
                *flags |= LDLM_FL_BLOCK_GRANTED;
                /* this way we force client to wait for the lock
                 * endlessly once the lock is enqueued -bzzz */
                *flags |= LDLM_FL_NO_TIMEOUT;

        }
        rc = 0;
out:
        RETURN(rc);
}

/* When a lock is cancelled by a client, the KMS may undergo change if this
 * is the "highest lock".  This function returns the new KMS value.
 * Caller must hold ns_lock already.
 *
 * NB: A lock on [x,y] protects a KMS of up to y + 1 bytes! */
__u64 ldlm_extent_shift_kms(struct ldlm_lock *lock, __u64 old_kms)
{
        struct ldlm_resource *res = lock->l_resource;
        struct list_head *tmp;
        struct ldlm_lock *lck;
        __u64 kms = 0;
        ENTRY;

        /* don't let another thread in ldlm_extent_shift_kms race in
         * just after we finish and take our lock into account in its
         * calculation of the kms */
        lock->l_flags |= LDLM_FL_KMS_IGNORE;

        list_for_each(tmp, &res->lr_granted) {
                lck = list_entry(tmp, struct ldlm_lock, l_res_link);

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
