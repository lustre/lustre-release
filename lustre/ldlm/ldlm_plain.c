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

static int
ldlm_plain_compat_queue(struct list_head *queue, struct ldlm_lock *new,
                        int send_cbs, int first_enq)
{
        struct list_head *tmp, *pos;
	ldlm_mode_t mode = new->l_req_mode;
        int compat = 1;
        ENTRY;

        list_for_each_safe(tmp, pos, queue) {
                struct ldlm_lock *old;

                old = list_entry(tmp, struct ldlm_lock, l_res_link);
                if (old == new)
                        continue;

                if (lockmode_compat(old->l_req_mode, mode) &&
                    lockmode_compat(old->l_granted_mode, mode)) {
                        CDEBUG(D_OTHER, "lock modes are compatible, next.\n");
                        continue;
                }

                compat = 0;

                /* if we're reprocessing the lock then the blocking ASTs
                 * have already been sent. No need to continue. */
                if (!first_enq)
                        break;

                if (send_cbs && (old->l_blocking_ast != NULL)) {
                        CDEBUG(D_DLMTRACE, "lock %p incompatible; "
                               "sending blocking AST.\n", old);
                        ldlm_add_ast_work_item(old, new, NULL, 0);
                } else if (!(old->l_flags & LDLM_FL_LOCAL)) {
                        CDEBUG(D_DLMTRACE, "lock %p incompatible; "
                               "setting blocking AST.\n", old);
                        old->l_flags |= LDLM_FL_AST_SENT;
                } else {
                        CDEBUG(D_DLMTRACE, "local lock %p incompatible.\n",
                               old);
                }
        }

        RETURN(compat);
}

int
ldlm_plain_enqueue(struct ldlm_lock **lockp, void *cookie, int *flags,
                   int first_enq, ldlm_error_t *err)
{
        struct ldlm_lock *lock = *lockp;
        struct ldlm_resource *res = lock->l_resource;
	int convert_compat = 1;
	int waiting_compat = 1;
	int granted_compat = 1;
        ENTRY;

        /* FIXME: We may want to optimize by checking lr_most_restr */

        /* On the first enqueue of this lock scan all of the queues
         * to set the LDLM_FL_AST_SENT flag in conflicting locks.
         * When the completion AST on the client side runs and sees
         * this flag is will set the LDLM_FL_CB_PENDING flag in the
         * lock so the client will know to cancel the lock as soon
         * as possible. This saves us from sending a blocking AST
         * in addition to the completion AST.
         *
         * If it's NOT the first enqueue of this lock then it must be
         * the first eligible lock in the queues because of the way that
         * ldlm_reprocess_all() works. So we don't have to check the
         * converting or waiting queues. */
        if (first_enq) {
                if (!list_empty(&res->lr_converting)) {
                        convert_compat = 0;
                        ldlm_plain_compat_queue(&res->lr_converting,
                                                lock, 0, first_enq);
                }
                if (!list_empty(&res->lr_waiting)) {
                        waiting_compat = 0;
                        ldlm_plain_compat_queue(&res->lr_waiting,
                                                lock, 0, first_enq);
                }
        }
        granted_compat =
                ldlm_plain_compat_queue(&res->lr_granted, lock, 1, first_enq);

        if (!convert_compat) {
                *flags |= LDLM_FL_BLOCK_CONV;
                RETURN(LDLM_ITER_STOP);
        }
        if (!waiting_compat) {
                *flags |= LDLM_FL_BLOCK_WAIT;
                RETURN(LDLM_ITER_STOP);
        }
        if (!granted_compat) {
                *flags |= LDLM_FL_BLOCK_GRANTED;
                RETURN(LDLM_ITER_STOP);
        }

        list_del_init(&lock->l_res_link);
        ldlm_grant_lock(lock, NULL, 0);

        if (lock->l_flags & LDLM_FL_AST_SENT) {
                CDEBUG(D_DLMTRACE, "granted lock %p with AST set\n", lock);
                *flags |= (lock->l_flags & LDLM_FL_AST_SENT);
        }

        RETURN(LDLM_ITER_CONTINUE);
}
