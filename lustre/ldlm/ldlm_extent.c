/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_LDLM
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <linux/lustre_dlm.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>

#include "ldlm_internal.h"

/* The purpose of this function is to return:
 * - the maximum extent
 * - containing the requested extent
 * - and not overlapping existing conflicting extents outside the requested one
 *
 * An alternative policy is to not shrink the new extent when conflicts exist */
static void
ldlm_extent_internal_policy(struct list_head *queue, struct ldlm_lock *req,
                            struct ldlm_extent *new_ex)
{
        struct list_head *tmp;
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_start = req->l_policy_data.l_extent.start;
        __u64 req_end = req->l_policy_data.l_extent.end;
        ENTRY;

        if (new_ex->start == req_start && new_ex->end == req_end) {
                EXIT;
                return;
        }

        list_for_each(tmp, queue) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (req == lock) {
                        EXIT;
                        return;
                }

                /* if lock doesn't overlap new_ex, skip it. */
                if (lock->l_policy_data.l_extent.end < new_ex->start ||
                    lock->l_policy_data.l_extent.start > new_ex->end)
                        continue;

                /* Locks are compatible, overlap doesn't matter */
                if (lockmode_compat(lock->l_req_mode, req_mode))
                        continue;

                if (lock->l_policy_data.l_extent.start < req_start) {
                        if (lock->l_policy_data.l_extent.end == ~0) {
                                new_ex->start = req_start;
                                new_ex->end = req_end;
                                EXIT;
                                return;
                        }
                        new_ex->start = MIN(lock->l_policy_data.l_extent.end+1,
                                            req_start);
                }

                if (lock->l_policy_data.l_extent.end > req_end) {
                        if (lock->l_policy_data.l_extent.start == 0) {
                                new_ex->start = req_start;
                                new_ex->end = req_end;
                                EXIT;
                                return;
                        }
                        new_ex->end = MAX(lock->l_policy_data.l_extent.start-1,
                                          req_end);
                }
        }
        EXIT;
}

/* Determine if the lock is compatible with all locks on the queue. */
static int
ldlm_extent_compat_queue(struct list_head *queue, struct ldlm_lock *req,
                         int send_cbs)
{
        struct list_head *tmp;
        struct ldlm_lock *lock;
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_start = req->l_policy_data.l_extent.start;
        __u64 req_end = req->l_policy_data.l_extent.end;
        int compat = 1;
        ENTRY;

        list_for_each(tmp, queue) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (req == lock)
                        RETURN(compat);

                /* locks are compatible, overlap doesn't matter */
                if (lockmode_compat(lock->l_req_mode, req_mode))
                        continue;

                /* if lock doesn't overlap skip it */
                if (lock->l_policy_data.l_extent.end < req_start ||
                    lock->l_policy_data.l_extent.start > req_end)
                        continue;

                if (!send_cbs)
                        RETURN(0);

                compat = 0;
                if (lock->l_blocking_ast)
                        ldlm_add_ast_work_item(lock, req, NULL, 0);
        }

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
                             ldlm_error_t *err)
{
        struct ldlm_resource *res = lock->l_resource;
        struct ldlm_extent new_ex = {0, ~0};
        struct list_head rpc_list = LIST_HEAD_INIT(rpc_list);
        int rc;
        ENTRY;

        LASSERT(list_empty(&res->lr_converting));

        if (!first_enq) {
                LASSERT(res->lr_tmp != NULL);
                rc = ldlm_extent_compat_queue(&res->lr_granted, lock, 0);
                if (!rc)
                        RETURN(LDLM_ITER_STOP);
                rc = ldlm_extent_compat_queue(&res->lr_waiting, lock, 0);
                if (!rc)
                        RETURN(LDLM_ITER_STOP);

                ldlm_resource_unlink_lock(lock);
                ldlm_grant_lock(lock, NULL, 0, 1);
                RETURN(LDLM_ITER_CONTINUE);
        }

        /* In order to determine the largest possible extent we can
         * grant, we need to scan all of the queues. */
        ldlm_extent_internal_policy(&res->lr_granted, lock, &new_ex);
        ldlm_extent_internal_policy(&res->lr_waiting, lock, &new_ex);

        if (new_ex.start != lock->l_policy_data.l_extent.start ||
            new_ex.end != lock->l_policy_data.l_extent.end)  {
                *flags |= LDLM_FL_LOCK_CHANGED;
                lock->l_policy_data.l_extent.start = new_ex.start;
                lock->l_policy_data.l_extent.end = new_ex.end;
        }

 restart:
        LASSERT(res->lr_tmp == NULL);
        res->lr_tmp = &rpc_list;
        rc = ldlm_extent_compat_queue(&res->lr_granted, lock, 1);
        rc += ldlm_extent_compat_queue(&res->lr_waiting, lock, 1);
        res->lr_tmp = NULL;

        if (rc != 2) {
                /* If either of the compat_queue()s returned 0, then we
                 * have ASTs to send and must go onto the waiting list.
                 *
                 * bug 2322: we used to unlink and re-add here, which was a
                 * terrible folly -- if we goto restart, we could get
                 * re-ordered!  Causes deadlock, because ASTs aren't sent! */
                if (list_empty(&lock->l_res_link))
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                l_unlock(&res->lr_namespace->ns_lock);
                rc = ldlm_run_ast_work(res->lr_namespace, &rpc_list);
                l_lock(&res->lr_namespace->ns_lock);
                if (rc == -ERESTART)
                        GOTO(restart, -ERESTART);
                *flags |= LDLM_FL_BLOCK_GRANTED;
        } else {
                ldlm_resource_unlink_lock(lock);
                ldlm_grant_lock(lock, NULL, 0, 0);
        }
        RETURN(0);
}
