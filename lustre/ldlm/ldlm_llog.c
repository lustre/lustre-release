/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *   Author: LinSongTao<lin.songtao@clusterfs.com>
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
#include <linux/lustre_dlm.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <libcfs/list.h>
#else
#include <liblustre.h>
#include <linux/obd_class.h>
#endif

#include "ldlm_internal.h"

#define l_llog_waitq   l_lru

static struct list_head ldlm_llog_waitq = LIST_HEAD_INIT(ldlm_llog_waitq);

int ldlm_llog_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                            void *data, int flag);


static inline void
ldlm_llog_destroy(struct ldlm_lock *lock, ldlm_mode_t mode, int flags)
{
        ENTRY;

        LDLM_DEBUG(lock, "ldlm_flock_destroy(mode: %d, flags: 0x%x)",
                   mode, flags);

        LASSERT(list_empty(&lock->l_flock_waitq));

        list_del_init(&lock->l_res_link);
        if (flags == LDLM_FL_WAIT_NOREPROC) {
                /* client side - set a flag to prevent sending a CANCEL */
                lock->l_flags |= LDLM_FL_LOCAL_ONLY | LDLM_FL_CBPENDING;
                ldlm_lock_decref_internal(lock, mode);
        }

        ldlm_lock_destroy(lock);
        EXIT;
}

int
ldlm_process_llog_lock(struct ldlm_lock *req, int *flags, int first_enq,
                       ldlm_error_t *err)
{
        struct ldlm_resource *res = req->l_resource;
        struct ldlm_namespace *ns = res->lr_namespace;
        struct list_head *tmp;
        struct list_head *ownlocks = NULL;
        struct ldlm_lock *lock = NULL;
        struct ldlm_lock *new = req;
        struct ldlm_lock *new2 = NULL;
        ldlm_mode_t mode = req->l_req_mode;
        int local = ns->ns_client;
        int added = (mode == LCK_NL);
        ENTRY;

        CDEBUG(D_DLMTRACE, "flags %#x \n", *flags);

        *err = ELDLM_OK;

        if (local) {
                /* No blocking ASTs are sent to the clients for
                 * Posix file & record locks */
                req->l_blocking_ast = NULL;
        } else {
                /* Called on the server for lock cancels. */
                req->l_blocking_ast = ldlm_llog_blocking_ast;
        }


        lockmode_verify(mode);

        /* This loop determines if there are existing locks
         * that conflict with the new lock request. */
        list_for_each(tmp, &res->lr_granted) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lockmode_compat(lock->l_granted_mode, mode))
                        continue;

                if (!first_enq)
                        RETURN(LDLM_ITER_CONTINUE);

                LASSERT(list_empty(&req->l_llog_waitq));
                list_add_tail(&req->l_llog_waitq, &ldlm_llog_waitq);

                ldlm_resource_add_lock(res, &res->lr_waiting, req);
                        //*flags |= LDLM_FL_BLOCK_GRANTED;
                RETURN(LDLM_ITER_STOP);
        }

        list_del_init(&req->l_llog_waitq);

        req->l_granted_mode = req->l_req_mode;

        /* Add req to the granted queue. */
        list_del_init(&req->l_res_link);

        /* insert new lock*/
        ldlm_resource_add_lock(res, &req->lr_granted, req);

        if (*flags != LDLM_FL_WAIT_NOREPROC) {
                if (first_enq) {
                        if (mode == LCK_NL) {
                                struct list_head rpc_list
                                                    = LIST_HEAD_INIT(rpc_list);
                                int rc;
restart:
                                res->lr_tmp = &rpc_list;
                                ldlm_reprocess_queue(res, &res->lr_waiting);
                                res->lr_tmp = NULL;

                                l_unlock(&ns->ns_lock);
                                rc = ldlm_run_ast_work(res->lr_namespace,
                                                       &rpc_list);
                                l_lock(&ns->ns_lock);
                                if (rc == -ERESTART)
                                        GOTO(restart, -ERESTART);
                       }
                } else {
                        LASSERT(req->l_completion_ast);
                        ldlm_add_ast_work_item(req, NULL, NULL, 0);
                }
        }

        /* In case we're reprocessing the requested lock we can't destroy
         * it until after calling ldlm_ast_work_item() above so that lawi()
         * can bump the reference count on req. Otherwise req could be freed
         * before the completion AST can be sent.  */
        if (added)
                ldlm_flock_destroy(req, mode, *flags);

        ldlm_resource_dump(D_OTHER, res);
        RETURN(LDLM_ITER_CONTINUE);
}

static void
ldlm_llog_interrupted_wait(void *data)
{
        struct ldlm_lock *lock;
        struct lustre_handle lockh;
        ENTRY;

        lock = (struct ldlm_lock *)data;

        /* take lock off the deadlock detection waitq. */
        list_del_init(&lock->l_llog_waitq);

        /* client side - set flag to prevent lock from being put on lru list */
        lock->l_flags |= LDLM_FL_CBPENDING;

        ldlm_lock_decref_internal(lock, lock->l_req_mode);
        ldlm_lock2handle(lock, &lockh);
        ldlm_cli_cancel(&lockh);
        EXIT;
}

int
ldlm_llog_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        struct ldlm_namespace *ns;
 //       struct file_lock *getlk = lock->l_ast_data;
 //       struct ldlm_flock_wait_data fwd;
        unsigned long irqflags;
        struct obd_device *obd;
        struct obd_import *imp = NULL;
        ldlm_error_t err;
        int rc = 0;
        struct l_wait_info lwi;
        ENTRY;

        CDEBUG(D_DLMTRACE, "flags: 0x%x data: %p getlk: %p\n",
               flags, data, getlk);

        if (!(flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                       LDLM_FL_BLOCK_CONV)))
                goto  granted;

        LDLM_DEBUG(lock, "client-side enqueue can not return a granted lock, "
                   "sleeping");

        obd = class_exp2obd(lock->l_conn_export);

        /* if this is a local lock, then there is no import */
        if (obd != NULL)
                imp = obd->u.cli.cl_import;

        if (imp != NULL) {
                spin_lock_irqsave(&imp->imp_lock, irqflags);
                fwd.fwd_generation = imp->imp_generation;
                spin_unlock_irqrestore(&imp->imp_lock, irqflags);
        }

        lwi = LWI_TIMEOUT_INTR(0, NULL, ldlm_flock_interrupted_wait, &fwd);

        /* Go to sleep until the lock is granted. */
        rc = l_wait_event(lock->l_waitq,
                          ((lock->l_req_mode == lock->l_granted_mode) ||
                           lock->l_destroyed), &lwi);

        LDLM_DEBUG(lock, "client-side enqueue waking up: rc = %d", rc);
        RETURN(rc);
 
granted:

        LDLM_DEBUG(lock, "client-side enqueue granted");
        ns = lock->l_resource->lr_namespace;
        l_lock(&ns->ns_lock);

        /* take lock off the deadlock detection waitq. */
        list_del_init(&lock->l_flock_waitq);

        /* ldlm_lock_enqueue() has already placed lock on the granted list. */
        list_del_init(&lock->l_res_link);

        /* We need to reprocess the lock to do merges or splits
         * with existing locks owned by this process. */
        ldlm_process_llog_lock(lock, NULL, 1, &err);
        if (flags == 0)
               wake_up(&lock->l_waitq);

        l_unlock(&ns->ns_lock);
        RETURN(0);
}
EXPORT_SYMBOL(ldlm_llog_completion_ast);

int ldlm_llog_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                           void *data, int flag)
{
        struct ldlm_namespace *ns;
        ENTRY;

        LASSERT(lock);
        LASSERT(flag == LDLM_CB_CANCELING);

        ns = lock->l_resource->lr_namespace;

        /* take lock off the deadlock detection waitq. */
        l_lock(&ns->ns_lock);
        list_del_init(&lock->l_flock_waitq);
        l_unlock(&ns->ns_lock);
        RETURN(0);
}
