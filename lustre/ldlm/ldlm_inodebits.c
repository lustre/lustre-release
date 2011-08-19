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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011 Whamcloud, Inc.
 *
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_inodebits.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LDLM
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <lustre_dlm.h>
#include <obd_support.h>
#include <lustre_lib.h>

#include "ldlm_internal.h"

/* Determine if the lock is compatible with all locks on the queue. */
static int
ldlm_inodebits_compat_queue(cfs_list_t *queue, struct ldlm_lock *req,
                            cfs_list_t *work_list)
{
        cfs_list_t *tmp;
        struct ldlm_lock *lock;
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_bits = req->l_policy_data.l_inodebits.bits;
        int compat = 1;
        ENTRY;

        LASSERT(req_bits); /* There is no sense in lock with no bits set,
                              I think. Also such a lock would be compatible
                               with any other bit lock */

        cfs_list_for_each(tmp, queue) {
                cfs_list_t *mode_tail;

                lock = cfs_list_entry(tmp, struct ldlm_lock, l_res_link);

                if (req == lock)
                        RETURN(compat);

                /* last lock in mode group */
                LASSERT(lock->l_sl_mode.prev != NULL);
                mode_tail = &cfs_list_entry(lock->l_sl_mode.prev,
                                            struct ldlm_lock,
                                            l_sl_mode)->l_res_link;

                /* locks are compatible, bits don't matter */
                if (lockmode_compat(lock->l_req_mode, req_mode)) {
                        /* jump to last lock in mode group */
                        tmp = mode_tail;
                        continue;
                }

                for (;;) {
                        cfs_list_t *head;

                        /* last lock in policy group */
                        tmp = &cfs_list_entry(lock->l_sl_policy.prev,
                                              struct ldlm_lock,
                                              l_sl_policy)->l_res_link;

                        /* locks with bits overlapped are conflicting locks */
                        if (lock->l_policy_data.l_inodebits.bits & req_bits) {
                                /* COS lock from the same client is
                                   not conflicting */
                                if (lock->l_req_mode == LCK_COS &&
                                    lock->l_client_cookie == req->l_client_cookie)
                                        goto not_conflicting;
                                /* conflicting policy */
                                if (!work_list)
                                        RETURN(0);

                                compat = 0;

                                /* add locks of the policy group to
                                 * @work_list as blocking locks for
                                 * @req */
                                if (lock->l_blocking_ast)
                                        ldlm_add_ast_work_item(lock, req,
                                                               work_list);
                                head = &lock->l_sl_policy;
                                cfs_list_for_each_entry(lock, head, l_sl_policy)
                                        if (lock->l_blocking_ast)
                                                ldlm_add_ast_work_item(lock, req,
                                                                       work_list);
                        }
                not_conflicting:
                        if (tmp == mode_tail)
                                break;

                        tmp = tmp->next;
                        lock = cfs_list_entry(tmp, struct ldlm_lock,
                                              l_res_link);
                } /* loop over policy groups within one mode group */
        } /* loop over mode groups within @queue */

        RETURN(compat);
}

/* If first_enq is 0 (ie, called from ldlm_reprocess_queue):
  *   - blocking ASTs have already been sent
  *   - must call this function with the ns lock held
  *
  * If first_enq is 1 (ie, called from ldlm_lock_enqueue):
  *   - blocking ASTs have not been sent
  *   - must call this function with the ns lock held once */
int ldlm_process_inodebits_lock(struct ldlm_lock *lock, int *flags,
                                int first_enq, ldlm_error_t *err,
                                cfs_list_t *work_list)
{
        struct ldlm_resource *res = lock->l_resource;
        CFS_LIST_HEAD(rpc_list);
        int rc;
        ENTRY;

        LASSERT(cfs_list_empty(&res->lr_converting));
        check_res_locked(res);

        if (!first_enq) {
                LASSERT(work_list != NULL);
                rc = ldlm_inodebits_compat_queue(&res->lr_granted, lock, NULL);
                if (!rc)
                        RETURN(LDLM_ITER_STOP);
                rc = ldlm_inodebits_compat_queue(&res->lr_waiting, lock, NULL);
                if (!rc)
                        RETURN(LDLM_ITER_STOP);

                ldlm_resource_unlink_lock(lock);
                ldlm_grant_lock(lock, work_list);
                RETURN(LDLM_ITER_CONTINUE);
        }

 restart:
        rc = ldlm_inodebits_compat_queue(&res->lr_granted, lock, &rpc_list);
        rc += ldlm_inodebits_compat_queue(&res->lr_waiting, lock, &rpc_list);

        if (rc != 2) {
                /* If either of the compat_queue()s returned 0, then we
                 * have ASTs to send and must go onto the waiting list.
                 *
                 * bug 2322: we used to unlink and re-add here, which was a
                 * terrible folly -- if we goto restart, we could get
                 * re-ordered!  Causes deadlock, because ASTs aren't sent! */
                if (cfs_list_empty(&lock->l_res_link))
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                unlock_res(res);
                rc = ldlm_run_ast_work(&rpc_list, LDLM_WORK_BL_AST);
                lock_res(res);
                if (rc == -ERESTART)
                        GOTO(restart, -ERESTART);
                *flags |= LDLM_FL_BLOCK_GRANTED;
        } else {
                ldlm_resource_unlink_lock(lock);
                ldlm_grant_lock(lock, NULL);
        }
        RETURN(0);
}

void ldlm_ibits_policy_wire_to_local(const ldlm_wire_policy_data_t *wpolicy,
                                     ldlm_policy_data_t *lpolicy)
{
        memset(lpolicy, 0, sizeof(*lpolicy));
        lpolicy->l_inodebits.bits = wpolicy->l_inodebits.bits;
}

void ldlm_ibits_policy_local_to_wire(const ldlm_policy_data_t *lpolicy,
                                     ldlm_wire_policy_data_t *wpolicy)
{
        memset(wpolicy, 0, sizeof(*wpolicy));
        wpolicy->l_inodebits.bits = lpolicy->l_inodebits.bits;
}
