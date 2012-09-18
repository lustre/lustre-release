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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_plain.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LDLM

#ifdef __KERNEL__
#include <lustre_dlm.h>
#include <obd_support.h>
#include <lustre_lib.h>
#else
#include <liblustre.h>
#endif

#include "ldlm_internal.h"

#ifdef HAVE_SERVER_SUPPORT
static inline int
ldlm_plain_compat_queue(cfs_list_t *queue, struct ldlm_lock *req,
                        cfs_list_t *work_list)
{
        cfs_list_t *tmp;
        struct ldlm_lock *lock;
        ldlm_mode_t req_mode = req->l_req_mode;
        int compat = 1;
        ENTRY;

        lockmode_verify(req_mode);

        cfs_list_for_each(tmp, queue) {
                lock = cfs_list_entry(tmp, struct ldlm_lock, l_res_link);

                if (req == lock)
                        RETURN(compat);

                 /* last lock in mode group */
                 tmp = &cfs_list_entry(lock->l_sl_mode.prev,
                                       struct ldlm_lock,
                                       l_sl_mode)->l_res_link;

                 if (lockmode_compat(lock->l_req_mode, req_mode))
                        continue;

                if (!work_list)
                        RETURN(0);

                compat = 0;

                /* add locks of the mode group to @work_list as
                 * blocking locks for @req */
                if (lock->l_blocking_ast)
                        ldlm_add_ast_work_item(lock, req, work_list);

                {
                        cfs_list_t *head;

                        head = &lock->l_sl_mode;
                        cfs_list_for_each_entry(lock, head, l_sl_mode)
                                if (lock->l_blocking_ast)
                                        ldlm_add_ast_work_item(lock, req,
                                                               work_list);
                }
        }

        RETURN(compat);
}

/* If first_enq is 0 (ie, called from ldlm_reprocess_queue):
 *   - blocking ASTs have already been sent
 *   - must call this function with the resource lock held
 *
 * If first_enq is 1 (ie, called from ldlm_lock_enqueue):
 *   - blocking ASTs have not been sent
 *   - must call this function with the resource lock held */
int ldlm_process_plain_lock(struct ldlm_lock *lock, int *flags, int first_enq,
                            ldlm_error_t *err, cfs_list_t *work_list)
{
        struct ldlm_resource *res = lock->l_resource;
        CFS_LIST_HEAD(rpc_list);
        int rc;
        ENTRY;

        check_res_locked(res);
        LASSERT(cfs_list_empty(&res->lr_converting));

        if (!first_enq) {
                LASSERT(work_list != NULL);
                rc = ldlm_plain_compat_queue(&res->lr_granted, lock, NULL);
                if (!rc)
                        RETURN(LDLM_ITER_STOP);
                rc = ldlm_plain_compat_queue(&res->lr_waiting, lock, NULL);
                if (!rc)
                        RETURN(LDLM_ITER_STOP);

                ldlm_resource_unlink_lock(lock);
                ldlm_grant_lock(lock, work_list);
                RETURN(LDLM_ITER_CONTINUE);
        }

 restart:
        rc = ldlm_plain_compat_queue(&res->lr_granted, lock, &rpc_list);
        rc += ldlm_plain_compat_queue(&res->lr_waiting, lock, &rpc_list);

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
                rc = ldlm_run_ast_work(ldlm_res_to_ns(res), &rpc_list,
                                       LDLM_WORK_BL_AST);
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
#endif /* HAVE_SERVER_SUPPORT */

void ldlm_plain_policy_wire_to_local(const ldlm_wire_policy_data_t *wpolicy,
                                     ldlm_policy_data_t *lpolicy)
{
        /* No policy for plain locks */
}

void ldlm_plain_policy_local_to_wire(const ldlm_policy_data_t *lpolicy,
                                     ldlm_wire_policy_data_t *wpolicy)
{
        /* No policy for plain locks */
}
