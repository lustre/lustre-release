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

#ifdef __KERNEL__
#include <linux/lustre_dlm.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#else
#include <liblustre.h>
#endif

static inline int
ldlm_plain_compat_queue(struct list_head *queue, struct ldlm_lock *req,
                        int first_enq)
{
        struct list_head *tmp;
        struct ldlm_lock *lock;
	ldlm_mode_t req_mode = req->l_req_mode;
        int compat = 1;
        ENTRY;

        list_for_each(tmp, queue) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lockmode_compat(lock->l_granted_mode, req_mode)) {
                        CDEBUG(D_DLMTRACE,"lock modes are compatible, next.\n");
                        continue;
                }

                compat = 0;

                if (first_enq)
                        break;

                if (lock->l_blocking_ast) {
                        CDEBUG(D_DLMTRACE, "lock %p incompatible; "
                               "sending blocking AST.\n", lock);
                        ldlm_add_ast_work_item(lock, req, NULL, 0);
                }
        }

        RETURN(compat);
}

int
ldlm_plain_enqueue(struct ldlm_lock *lock, int *flags, int first_enq,
                   ldlm_error_t *err)
{
        struct ldlm_resource *res = lock->l_resource;
	int compat;
        ENTRY;

        if (first_enq) {
                if (!list_empty(&res->lr_converting)) {
                        *flags |= LDLM_FL_BLOCK_CONV;
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                        RETURN(LDLM_ITER_STOP);
                }
                if (!list_empty(&res->lr_waiting)) {
                        *flags |= LDLM_FL_BLOCK_WAIT;
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                        RETURN(LDLM_ITER_STOP);
                }
        }

        /* If it's NOT the first enqueue of this lock then it must be
         * the first eligible lock in the queues because of the way that
         * ldlm_reprocess_all() works; i.e. ldlm_reprocess_all() tries
         * the locks in order and stops the first time a lock is blocked.
         * When this is the case we don't have to check the converting or
         * waiting queues. */

        /* FIXME: We may want to optimize by checking lr_most_restr */

        compat = ldlm_plain_compat_queue(&res->lr_granted, lock, first_enq);
        if (!compat) {
                if (first_enq) {
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                        *flags |= LDLM_FL_BLOCK_GRANTED;
                }
                RETURN(LDLM_ITER_STOP);
        }

        list_del_init(&lock->l_res_link);
        ldlm_grant_lock(lock, NULL, 0);
        RETURN(LDLM_ITER_CONTINUE);
}
