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

#ifdef __KERNEL__
#include <lustre_dlm.h>
#include <obd_support.h>
#include <lustre_lib.h>
#else
#include <liblustre.h>
#endif

#include "ldlm_internal.h"

static inline int
ldlm_plain_compat_queue(struct list_head *queue, struct ldlm_lock *req,
                        struct list_head *work_list)
{
        struct list_head *tmp;
        struct ldlm_lock *lock;
        ldlm_mode_t req_mode = req->l_req_mode;
        int compat = 1;
        ENTRY;

        lockmode_verify(req_mode);

        list_for_each(tmp, queue) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (req == lock)
                        RETURN(compat);

                /* last lock in mode group */
                tmp = &list_entry(lock->l_sl_mode.prev,
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
                        struct list_head *head;

                        head = &lock->l_sl_mode;
                        list_for_each_entry(lock, head, l_sl_mode)
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
                            ldlm_error_t *err, struct list_head *work_list)
{
        struct ldlm_resource *res = lock->l_resource;
        struct list_head rpc_list = CFS_LIST_HEAD_INIT(rpc_list);
        int rc;
        ENTRY;

        check_res_locked(res);
        LASSERT(list_empty(&res->lr_converting));

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
                if (list_empty(&lock->l_res_link))
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                unlock_res(res);
                rc = ldlm_run_bl_ast_work(&rpc_list);
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
