/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
#include <signal.h>
#include <liblustre.h>
#endif

#include <lustre_dlm.h>
#include <obd_class.h>
#include <obd.h>

#include "ldlm_internal.h"

static void interrupted_completion_wait(void *data)
{
}

struct lock_wait_data {
        struct ldlm_lock *lwd_lock;
        __u32             lwd_conn_cnt;
};

int ldlm_expired_completion_wait(void *data)
{
        struct lock_wait_data *lwd = data;
        struct ldlm_lock *lock = lwd->lwd_lock;
        struct obd_import *imp;
        struct obd_device *obd;

        ENTRY;
        if (lock->l_conn_export == NULL) {
                static cfs_time_t next_dump = 0, last_dump = 0;

                LDLM_ERROR(lock, "lock timed out (enq %lus ago); not entering "
                           "recovery in server code, just going back to sleep",
                           lock->l_enqueued_time.tv_sec);
                if (cfs_time_after(cfs_time_current(), next_dump)) {
                        last_dump = next_dump;
                        next_dump = cfs_time_shift(300);
                        ldlm_namespace_dump(D_DLMTRACE,
                                            lock->l_resource->lr_namespace);
                        if (last_dump == 0)
                                libcfs_debug_dumplog();
                }
                RETURN(0);
        }

        obd = lock->l_conn_export->exp_obd;
        imp = obd->u.cli.cl_import;
        ptlrpc_fail_import(imp, lwd->lwd_conn_cnt);
        LDLM_ERROR(lock, "lock timed out (enqueued %lus ago), entering "
                   "recovery for %s@%s", lock->l_enqueued_time.tv_sec,
                   obd2cli_tgt(obd), imp->imp_connection->c_remote_uuid.uuid);

        RETURN(0);
}

int ldlm_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        /* XXX ALLOCATE - 160 bytes */
        struct lock_wait_data lwd;
        unsigned long irqflags;
        struct obd_device *obd;
        struct obd_import *imp = NULL;
        struct l_wait_info lwi;
        int rc = 0;
        ENTRY;

        if (flags == LDLM_FL_WAIT_NOREPROC) {
                LDLM_DEBUG(lock, "client-side enqueue waiting on pending lock");
                goto noreproc;
        }

        if (!(flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                       LDLM_FL_BLOCK_CONV))) {
                cfs_waitq_signal(&lock->l_waitq);
                RETURN(0);
        }

        LDLM_DEBUG(lock, "client-side enqueue returned a blocked lock, "
                   "sleeping");
        ldlm_lock_dump(D_OTHER, lock, 0);
        ldlm_reprocess_all(lock->l_resource);

noreproc:

        obd = class_exp2obd(lock->l_conn_export);

        /* if this is a local lock, then there is no import */
        if (obd != NULL)
                imp = obd->u.cli.cl_import;

        lwd.lwd_lock = lock;

        if (unlikely(flags & LDLM_FL_NO_TIMEOUT)) {
                LDLM_DEBUG(lock, "waiting indefinitely because of NO_TIMEOUT");
                lwi = LWI_INTR(interrupted_completion_wait, &lwd);
        } else {
                lwi = LWI_TIMEOUT_INTR(cfs_time_seconds(obd_timeout),
                                       ldlm_expired_completion_wait,
                                       interrupted_completion_wait, &lwd);
        }

        if (imp != NULL) {
                spin_lock_irqsave(&imp->imp_lock, irqflags);
                lwd.lwd_conn_cnt = imp->imp_conn_cnt;
                spin_unlock_irqrestore(&imp->imp_lock, irqflags);
        }

        /* Go to sleep until the lock is granted or cancelled. */
        rc = l_wait_event(lock->l_waitq,
                          ((lock->l_req_mode == lock->l_granted_mode) ||
                           (lock->l_flags & LDLM_FL_FAILED)), &lwi);

        if (lock->l_destroyed || lock->l_flags & LDLM_FL_FAILED) {
                LDLM_DEBUG(lock, "client-side enqueue waking up: destroyed");
                RETURN(-EIO);
        }

        if (rc) {
                LDLM_DEBUG(lock, "client-side enqueue waking up: failed (%d)",
                           rc);
                RETURN(rc);
        }

        LDLM_DEBUG(lock, "client-side enqueue waking up: granted");
        RETURN(0);
}

/*
 * ->l_blocking_ast() callback for LDLM locks acquired by server-side OBDs.
 */
int ldlm_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                      void *data, int flag)
{
        int do_ast;
        ENTRY;

        if (flag == LDLM_CB_CANCELING) {
                /* Don't need to do anything here. */
                RETURN(0);
        }

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        /* Get this: if ldlm_blocking_ast is racing with intent_policy, such
         * that ldlm_blocking_ast is called just before intent_policy method
         * takes the ns_lock, then by the time we get the lock, we might not
         * be the correct blocking function anymore.  So check, and return
         * early, if so. */
        if (lock->l_blocking_ast != ldlm_blocking_ast) {
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

        lock->l_flags |= LDLM_FL_CBPENDING;
        do_ast = (!lock->l_readers && !lock->l_writers);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        if (do_ast) {
                struct lustre_handle lockh;
                int rc;

                LDLM_DEBUG(lock, "already unused, calling ldlm_cli_cancel");
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0)
                        CERROR("ldlm_cli_cancel: %d\n", rc);
        } else {
                LDLM_DEBUG(lock, "Lock still has references, will be "
                           "cancelled later");
        }
        RETURN(0);
}

/*
 * ->l_glimpse_ast() for DLM extent locks acquired on the server-side. See
 * comment in filter_intent_policy() on why you may need this.
 */
int ldlm_glimpse_ast(struct ldlm_lock *lock, void *reqp)
{
        /*
         * Returning -ELDLM_NO_LOCK_DATA actually works, but the reason for
         * that is rather subtle: with OST-side locking, it may so happen that
         * _all_ extent locks are held by the OST. If client wants to obtain
         * current file size it calls ll{,u}_glimpse_size(), and (as locks are
         * on the server), dummy glimpse callback fires and does
         * nothing. Client still receives correct file size due to the
         * following fragment in filter_intent_policy():
         *
         * rc = l->l_glimpse_ast(l, NULL); // this will update the LVB
         * if (rc != 0 && res->lr_namespace->ns_lvbo &&
         *     res->lr_namespace->ns_lvbo->lvbo_update) {
         *         res->lr_namespace->ns_lvbo->lvbo_update(res, NULL, 0, 1);
         * }
         *
         * that is, after glimpse_ast() fails, filter_lvbo_update() runs, and
         * returns correct file size to the client.
         */
        return -ELDLM_NO_LOCK_DATA;
}

static int ldlm_cli_enqueue_local(struct ldlm_namespace *ns,
                                  struct ldlm_res_id res_id,
                                  __u32 type,
                                  ldlm_policy_data_t *policy,
                                  ldlm_mode_t mode,
                                  int *flags,
                                  ldlm_blocking_callback blocking,
                                  ldlm_completion_callback completion,
                                  ldlm_glimpse_callback glimpse,
                                  void *data, __u32 lvb_len,
                                  void *lvb_swabber,
                                  struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        int err;
        ENTRY;

        if (ns->ns_client) {
                CERROR("Trying to enqueue local lock in a shadow namespace\n");
                LBUG();
        }

        lock = ldlm_lock_create(ns, NULL, res_id, type, mode, blocking,
                                completion, glimpse, data, lvb_len);
        if (!lock)
                GOTO(out_nolock, err = -ENOMEM);
        LDLM_DEBUG(lock, "client-side local enqueue handler, new lock created");

        ldlm_lock_addref_internal(lock, mode);
        ldlm_lock2handle(lock, lockh);
        lock->l_flags |= LDLM_FL_LOCAL;
        lock->l_lvb_swabber = lvb_swabber;
        if (policy != NULL)
                lock->l_policy_data = *policy;
        if (type == LDLM_EXTENT)
                lock->l_req_extent = policy->l_extent;

        err = ldlm_lock_enqueue(ns, &lock, policy, flags);
        if (err != ELDLM_OK)
                GOTO(out, err);

        if (policy != NULL)
                *policy = lock->l_policy_data;
        if ((*flags) & LDLM_FL_LOCK_CHANGED)
                res_id = lock->l_resource->lr_name;

        LDLM_DEBUG_NOLOCK("client-side local enqueue handler END (lock %p)",
                          lock);

        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, *flags, NULL);

        LDLM_DEBUG(lock, "client-side local enqueue END");
        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
 out_nolock:
        return err;
}

static void failed_lock_cleanup(struct ldlm_namespace *ns,
                                struct ldlm_lock *lock,
                                struct lustre_handle *lockh, int mode)
{
        /* Set a flag to prevent us from sending a CANCEL (bug 407) */
        l_lock(&ns->ns_lock);
        lock->l_flags |= LDLM_FL_LOCAL_ONLY;
        LDLM_DEBUG(lock, "setting FL_LOCAL_ONLY");
        l_unlock(&ns->ns_lock);

        ldlm_lock_decref_and_cancel(lockh, mode);

        /* XXX - HACK because we shouldn't call ldlm_lock_destroy()
         *       from llite/file.c/ll_file_flock(). */
        if (lock->l_resource->lr_type == LDLM_FLOCK) {
                ldlm_lock_destroy(lock);
        }
}

int ldlm_cli_enqueue(struct obd_export *exp,
                     struct ptlrpc_request *req,
                     struct ldlm_namespace *ns,
                     struct ldlm_res_id res_id,
                     __u32 type,
                     ldlm_policy_data_t *policy,
                     ldlm_mode_t mode,
                     int *flags,
                     ldlm_blocking_callback blocking,
                     ldlm_completion_callback completion,
                     ldlm_glimpse_callback glimpse,
                     void *data,
                     void *lvb,
                     __u32 lvb_len,
                     void *lvb_swabber,
                     struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        int rc, size[] = {sizeof(*body), lvb_len}, req_passed_in = 1;
        int is_replay = *flags & LDLM_FL_REPLAY;
        int cleanup_phase = 0;
        ENTRY;

        if (exp == NULL) {
                LASSERT(!is_replay);
                rc = ldlm_cli_enqueue_local(ns, res_id, type, policy, mode,
                                            flags, blocking, completion,
                                            glimpse, data, lvb_len, lvb_swabber,
                                            lockh);
                RETURN(rc);
        }

        /* If we're replaying this lock, just check some invariants.
         * If we're creating a new lock, get everything all setup nice. */
        if (is_replay) {
                lock = ldlm_handle2lock(lockh);
                LDLM_DEBUG(lock, "client-side enqueue START");
                LASSERT(exp == lock->l_conn_export);
        } else {
                lock = ldlm_lock_create(ns, NULL, res_id, type, mode, blocking,
                                        completion, glimpse, data, lvb_len);
                if (lock == NULL)
                        RETURN(-ENOMEM);
                /* for the local lock, add the reference */
                ldlm_lock_addref_internal(lock, mode);
                ldlm_lock2handle(lock, lockh);
                lock->l_lvb_swabber = lvb_swabber;
                if (policy != NULL) {
                        /* INODEBITS_INTEROP: If the server does not support
                         * inodebits, we will request a plain lock in the
                         * descriptor (ldlm_lock2desc() below) but use an
                         * inodebits lock internally with both bits set.
                         */
                        if (type == LDLM_IBITS && !(exp->exp_connect_flags &
                                                    OBD_CONNECT_IBITS))
                                lock->l_policy_data.l_inodebits.bits =
                                        MDS_INODELOCK_LOOKUP |
                                        MDS_INODELOCK_UPDATE;
                        else
                                lock->l_policy_data = *policy;
                }

                if (type == LDLM_EXTENT)
                        lock->l_req_extent = policy->l_extent;
                LDLM_DEBUG(lock, "client-side enqueue START");
        }

        /* lock not sent to server yet */
        cleanup_phase = 2;

        if (req == NULL) {
                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_DLM_VERSION,
                                      LDLM_ENQUEUE, 1, size, NULL);
                if (req == NULL)
                        GOTO(cleanup, rc = -ENOMEM);
                req_passed_in = 0;
        } else {
                LASSERTF(req->rq_reqmsg->buflens[MDS_REQ_INTENT_LOCKREQ_OFF] ==
                         sizeof(*body), "buflen[%d] = %d, not %d\n",
                         MDS_REQ_INTENT_LOCKREQ_OFF,
                         req->rq_reqmsg->buflens[MDS_REQ_INTENT_LOCKREQ_OFF],
                         (int)sizeof(*body));
        }

        lock->l_conn_export = exp;
        lock->l_export = NULL;
        lock->l_blocking_ast = blocking;

        /* Dump lock data into the request buffer */
        body = lustre_msg_buf(req->rq_reqmsg, MDS_REQ_INTENT_LOCKREQ_OFF,
                              sizeof(*body));
        ldlm_lock2desc(lock, &body->lock_desc);
        body->lock_flags = *flags;

        body->lock_handle1 = *lockh;

        /* Continue as normal. */
        if (!req_passed_in) {
                size[0] = sizeof(*reply);
                req->rq_replen = lustre_msg_size(1 + (lvb_len > 0), size);
        }
        LDLM_DEBUG(lock, "sending request");
        rc = ptlrpc_queue_wait(req);

        if (rc != ELDLM_OK) {
                LASSERT(!is_replay);
                LDLM_DEBUG(lock, "client-side enqueue END (%s)",
                           rc == ELDLM_LOCK_ABORTED ? "ABORTED" : "FAILED");
                if (rc == ELDLM_LOCK_ABORTED) {
                        /* Before we return, swab the reply */
                        reply = lustre_swab_repbuf(req, 0, sizeof(*reply),
                                                   lustre_swab_ldlm_reply);
                        if (reply == NULL) {
                                CERROR("Can't unpack ldlm_reply\n");
                                rc = -EPROTO;
                        }
                        if (lvb_len) {
                                void *tmplvb;
                                tmplvb = lustre_swab_repbuf(req, 1, lvb_len,
                                                            lvb_swabber);
                                if (tmplvb == NULL)
                                        GOTO(cleanup, rc = -EPROTO);
                                if (lvb != NULL)
                                        memcpy(lvb, tmplvb, lvb_len);
                        }
                }
                GOTO(cleanup, rc);
        }

        /*
         * Liblustre client doesn't get extent locks, except for O_APPEND case
         * where [0, OBD_OBJECT_EOF] lock is taken, or truncate, where
         * [i_size, OBD_OBJECT_EOF] lock is taken.
         */
        LASSERT(ergo(LIBLUSTRE_CLIENT, type != LDLM_EXTENT ||
                     policy->l_extent.end == OBD_OBJECT_EOF));

        reply = lustre_swab_repbuf(req, 0, sizeof(*reply),
                                   lustre_swab_ldlm_reply);
        if (reply == NULL) {
                CERROR("Can't unpack ldlm_reply\n");
                GOTO(cleanup, rc = -EPROTO);
        }

        /* lock enqueued on the server */
        cleanup_phase = 1;

        l_lock(&ns->ns_lock);
        lock->l_remote_handle = reply->lock_handle;
        *flags = reply->lock_flags;
        lock->l_flags |= reply->lock_flags & LDLM_INHERIT_FLAGS;
        l_unlock(&ns->ns_lock);

        CDEBUG(D_INFO, "local: %p, remote cookie: "LPX64", flags: 0x%x\n",
               lock, reply->lock_handle.cookie, *flags);

        /* If enqueue returned a blocked lock but the completion handler has
         * already run, then it fixed up the resource and we don't need to do it
         * again. */
        if ((*flags) & LDLM_FL_LOCK_CHANGED) {
                int newmode = reply->lock_desc.l_req_mode;
                LASSERT(!is_replay);
                if (newmode && newmode != lock->l_req_mode) {
                        LDLM_DEBUG(lock, "server returned different mode %s",
                                   ldlm_lockname[newmode]);
                        lock->l_req_mode = newmode;
                }

                if (reply->lock_desc.l_resource.lr_name.name[0] !=
                    lock->l_resource->lr_name.name[0]) {
                        CDEBUG(D_INFO, "remote intent success, locking %ld "
                               "instead of %ld\n",
                              (long)reply->lock_desc.l_resource.lr_name.name[0],
                               (long)lock->l_resource->lr_name.name[0]);

                        ldlm_lock_change_resource(ns, lock,
                                           reply->lock_desc.l_resource.lr_name);
                        if (lock->l_resource == NULL) {
                                LBUG();
                                GOTO(cleanup, rc = -ENOMEM);
                        }
                        LDLM_DEBUG(lock, "client-side enqueue, new resource");
                }
                if (policy != NULL)
                        if (!(type == LDLM_IBITS && !(exp->exp_connect_flags &
                                                    OBD_CONNECT_IBITS)))
                                lock->l_policy_data =
                                                 reply->lock_desc.l_policy_data;
                if (type != LDLM_PLAIN)
                        LDLM_DEBUG(lock,"client-side enqueue, new policy data");
        }

        if ((*flags) & LDLM_FL_AST_SENT ||
            /* Cancel extent locks as soon as possible on a liblustre client,
             * because it cannot handle asynchronous ASTs robustly (see
             * bug 7311). */
            (LIBLUSTRE_CLIENT && type == LDLM_EXTENT)) {
                l_lock(&ns->ns_lock);
                lock->l_flags |= LDLM_FL_CBPENDING;
                l_unlock(&ns->ns_lock);
                LDLM_DEBUG(lock, "enqueue reply includes blocking AST");
        }

        /* If the lock has already been granted by a completion AST, don't
         * clobber the LVB with an older one. */
        if (lvb_len && (lock->l_req_mode != lock->l_granted_mode)) {
                void *tmplvb;
                tmplvb = lustre_swab_repbuf(req, 1, lvb_len, lvb_swabber);
                if (tmplvb == NULL)
                        GOTO(cleanup, rc = -EPROTO);
                memcpy(lock->l_lvb_data, tmplvb, lvb_len);
        }

        if (!is_replay) {
                rc = ldlm_lock_enqueue(ns, &lock, NULL, flags);
                if (lock->l_completion_ast != NULL) {
                        int err = lock->l_completion_ast(lock, *flags, NULL);
                        if (!rc)
                                rc = err;
                        if (rc)
                                cleanup_phase = 2;
                }
        }

        if (lvb_len && lvb != NULL) {
                /* Copy the LVB here, and not earlier, because the completion
                 * AST (if any) can override what we got in the reply */
                memcpy(lvb, lock->l_lvb_data, lvb_len);
        }

        LDLM_DEBUG(lock, "client-side enqueue END");
        EXIT;
cleanup:
        switch (cleanup_phase) {
        case 2:
                if (rc)
                        failed_lock_cleanup(ns, lock, lockh, mode);
        case 1:
                if (!req_passed_in && req != NULL)
                        ptlrpc_req_finished(req);
        }

        LDLM_LOCK_PUT(lock);
        return rc;
}

static int ldlm_cli_convert_local(struct ldlm_lock *lock, int new_mode,
                                  int *flags)
{
        struct ldlm_resource *res;
        int rc;
        ENTRY;
        if (lock->l_resource->lr_namespace->ns_client) {
                CERROR("Trying to cancel local lock\n");
                LBUG();
        }
        LDLM_DEBUG(lock, "client-side local convert");

        res = ldlm_lock_convert(lock, new_mode, flags);
        if (res) {
                ldlm_reprocess_all(res);
                rc = 0;
        } else {
                rc = EDEADLOCK;
        }
        LDLM_DEBUG(lock, "client-side local convert handler END");
        LDLM_LOCK_PUT(lock);
        RETURN(rc);
}

/* FIXME: one of ldlm_cli_convert or the server side should reject attempted
 * conversion of locks which are on the waiting or converting queue */
/* Caller of this code is supposed to take care of lock readers/writers
   accounting */
int ldlm_cli_convert(struct lustre_handle *lockh, int new_mode, int *flags)
{
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        struct ptlrpc_request *req;
        int rc, size = sizeof(*body);
        ENTRY;

        lock = ldlm_handle2lock(lockh);
        if (!lock) {
                LBUG();
                RETURN(-EINVAL);
        }
        *flags = 0;

        if (lock->l_conn_export == NULL)
                RETURN(ldlm_cli_convert_local(lock, new_mode, flags));

        LDLM_DEBUG(lock, "client-side convert");

        req = ptlrpc_prep_req(class_exp2cliimp(lock->l_conn_export),
                              LUSTRE_DLM_VERSION, LDLM_CONVERT, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        body->lock_handle1 = lock->l_remote_handle;

        body->lock_desc.l_req_mode = new_mode;
        body->lock_flags = *flags;

        size = sizeof(*reply);
        req->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(req);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        reply = lustre_swab_repbuf(req, 0, sizeof (*reply),
                                   lustre_swab_ldlm_reply);
        if (reply == NULL) {
                CERROR ("Can't unpack ldlm_reply\n");
                GOTO (out, rc = -EPROTO);
        }

        if (req->rq_status)
                GOTO(out, rc = req->rq_status);

        res = ldlm_lock_convert(lock, new_mode, &reply->lock_flags);
        if (res != NULL) {
                ldlm_reprocess_all(res);
                /* Go to sleep until the lock is granted. */
                /* FIXME: or cancelled. */
                if (lock->l_completion_ast) {
                        rc = lock->l_completion_ast(lock, LDLM_FL_WAIT_NOREPROC,
                                                    NULL);
                        if (rc)
                                GOTO(out, rc);
                }
        } else {
                rc = EDEADLOCK;
        }
        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
        ptlrpc_req_finished(req);
        return rc;
}

int ldlm_cli_cancel(struct lustre_handle *lockh)
{
        struct ptlrpc_request *req;
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        /* concurrent cancels on the same handle can happen */
        lock = __ldlm_handle2lock(lockh, LDLM_FL_CANCELING);
        if (lock == NULL)
                RETURN(0);

        if (lock->l_conn_export) {
                int local_only;
                struct obd_import *imp;

                LDLM_DEBUG(lock, "client-side cancel");
                /* Set this flag to prevent others from getting new references*/
                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                lock->l_flags |= LDLM_FL_CBPENDING;
                local_only = (lock->l_flags &
                              (LDLM_FL_LOCAL_ONLY|LDLM_FL_CANCEL_ON_BLOCK));
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                ldlm_cancel_callback(lock);

                if (local_only) {
                        CDEBUG(D_INFO, "not sending request (at caller's "
                               "instruction)\n");
                        goto local_cancel;
                }

        restart:
                imp = class_exp2cliimp(lock->l_conn_export);
                if (imp == NULL || imp->imp_invalid) {
                        CDEBUG(D_HA, "skipping cancel on invalid import %p\n",
                               imp);
                        goto local_cancel;
                }

                req = ptlrpc_prep_req(imp, LUSTRE_DLM_VERSION, LDLM_CANCEL,
                                      1, &size, NULL);
                if (!req)
                        GOTO(out, rc = -ENOMEM);
                req->rq_no_resend = 1;

                /* XXX FIXME bug 249 */
                req->rq_request_portal = LDLM_CANCEL_REQUEST_PORTAL;
                req->rq_reply_portal = LDLM_CANCEL_REPLY_PORTAL;

                body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
                body->lock_handle1 = lock->l_remote_handle;

                req->rq_replen = lustre_msg_size(0, NULL);

                rc = ptlrpc_queue_wait(req);

                if (rc == ESTALE) {
                        /* For PLAIN (inodebits) locks on liblustre clients
                           this is a valid race between us cancelling a lock
                           from lru and sending notification and server
                           cancelling our lock at the same time */
#ifndef __KERNEL__
                        if (lock->l_resource->lr_type != LDLM_PLAIN /* IBITS */)
#endif
                                CERROR("client/server (nid %s) out of sync"
                                       " -- not fatal, flags %d\n",
                                       libcfs_nid2str(req->rq_import->
                                                    imp_connection->c_peer.nid),
                                       lock->l_flags);
                } else if (rc == -ETIMEDOUT) {
                        ptlrpc_req_finished(req);
                        GOTO(restart, rc);
                } else if (rc != ELDLM_OK) {
                        CERROR("Got rc %d from cancel RPC: canceling "
                               "anyway\n", rc);
                }

                ptlrpc_req_finished(req);
        local_cancel:
                ldlm_lock_cancel(lock);
        } else {
                if (lock->l_resource->lr_namespace->ns_client) {
                        LDLM_ERROR(lock, "Trying to cancel local lock");
                        LBUG();
                }
                LDLM_DEBUG(lock, "client-side local cancel");
                ldlm_lock_cancel(lock);
                ldlm_reprocess_all(lock->l_resource);
                LDLM_DEBUG(lock, "client-side local cancel handler END");
        }

        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
        return rc;
}

/* when called with LDLM_ASYNC the blocking callback will be handled
 * in a thread and this function will return after the thread has been
 * asked to call the callback.  when called with LDLM_SYNC the blocking
 * callback will be performed in this function. */
int ldlm_cancel_lru(struct ldlm_namespace *ns, ldlm_sync_t sync)
{
        struct ldlm_lock *lock, *next;
        int count, rc = 0;
        CFS_LIST_HEAD(cblist);
        ENTRY;

#ifndef __KERNEL__
        sync = LDLM_SYNC; /* force to be sync in user space */
#endif

        l_lock(&ns->ns_lock);
        count = ns->ns_nr_unused - ns->ns_max_unused;

        if (count <= 0) {
                l_unlock(&ns->ns_lock);
                RETURN(0);
        }

        list_for_each_entry_safe(lock, next, &ns->ns_unused_list, l_lru) {
                LASSERT(!lock->l_readers && !lock->l_writers);

                /* If we have chosen to canecl this lock voluntarily, we better
                   send cancel notification to server, so that it frees
                   appropriate state. This might lead to a race where while
                   we are doing cancel here, server is also silently
                   cancelling this lock. */
                lock->l_flags &= ~LDLM_FL_CANCEL_ON_BLOCK;

                /* Setting the CBPENDING flag is a little misleading, but
                 * prevents an important race; namely, once CBPENDING is set,
                 * the lock can accumulate no more readers/writers.  Since
                 * readers and writers are already zero here, ldlm_lock_decref
                 * won't see this flag and call l_blocking_ast */
                lock->l_flags |= LDLM_FL_CBPENDING;

                LDLM_LOCK_GET(lock); /* dropped by bl thread */
                ldlm_lock_remove_from_lru(lock);

                /* We can't re-add to l_lru as it confuses the refcounting in
                 * ldlm_lock_remove_from_lru() if an AST arrives after we drop
                 * ns_lock below.  Use l_export_chain as that is unused on
                 * client, and lru is client-only (l_pending_chain is used by
                 * ldlm_chain_lock_for_replay() on client).  bug 5666 */
                if (sync != LDLM_ASYNC || ldlm_bl_to_thread(ns, NULL, lock)) {
                        LASSERTF(list_empty(&lock->l_export_chain),
                                 "lock %p next %p prev %p\n",
                                 lock, &lock->l_export_chain.next,
                                 &lock->l_export_chain.prev);
                        __LDLM_DEBUG(D_INFO, lock, "adding to LRU clear list");
                        list_add(&lock->l_export_chain, &cblist);
                }

                if (--count == 0)
                        break;
        }
        l_unlock(&ns->ns_lock);

        list_for_each_entry_safe(lock, next, &cblist, l_export_chain) {
                list_del_init(&lock->l_export_chain);
                ldlm_handle_bl_callback(ns, NULL, lock);
        }
        RETURN(rc);
}

static int ldlm_cli_cancel_unused_resource(struct ldlm_namespace *ns,
                                           struct ldlm_res_id res_id, int flags,
                                           void *opaque)
{
        struct ldlm_resource *res;
        struct list_head *tmp, *next, list = CFS_LIST_HEAD_INIT(list);
        struct ldlm_ast_work *w;
        ENTRY;

        res = ldlm_resource_get(ns, NULL, res_id, 0, 0);
        if (res == NULL) {
                /* This is not a problem. */
                CDEBUG(D_INFO, "No resource "LPU64"\n", res_id.name[0]);
                RETURN(0);
        }

        l_lock(&ns->ns_lock);
        list_for_each(tmp, &res->lr_granted) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (opaque != NULL && lock->l_ast_data != opaque) {
                        LDLM_ERROR(lock, "data %p doesn't match opaque %p",
                                   lock->l_ast_data, opaque);
                        //LBUG();
                        continue;
                }

                if (lock->l_readers || lock->l_writers) {
                        if (flags & LDLM_FL_WARN) {
                                LDLM_ERROR(lock, "lock in use");
                                //LBUG();
                        }
                        continue;
                }

                /* See CBPENDING comment in ldlm_cancel_lru */
                lock->l_flags |= LDLM_FL_CBPENDING;

                OBD_ALLOC(w, sizeof(*w));
                LASSERT(w);

                w->w_lock = LDLM_LOCK_GET(lock);

                list_add(&w->w_list, &list);
        }
        l_unlock(&ns->ns_lock);

        list_for_each_safe(tmp, next, &list) {
                struct lustre_handle lockh;
                int rc;
                w = list_entry(tmp, struct ldlm_ast_work, w_list);

                if (flags & LDLM_FL_LOCAL_ONLY) {
                        ldlm_lock_cancel(w->w_lock);
                } else {
                        ldlm_lock2handle(w->w_lock, &lockh);
                        rc = ldlm_cli_cancel(&lockh);
                        if (rc != ELDLM_OK)
                                CERROR("ldlm_cli_cancel: %d\n", rc);
                }
                list_del(&w->w_list);
                LDLM_LOCK_PUT(w->w_lock);
                OBD_FREE(w, sizeof(*w));
        }

        ldlm_resource_putref(res);

        RETURN(0);
}

/* Cancel all locks on a namespace (or a specific resource, if given)
 * that have 0 readers/writers.
 *
 * If flags & LDLM_FL_LOCAL_ONLY, throw the locks away without trying
 * to notify the server.
 * If flags & LDLM_FL_WARN, print a warning if some locks are still in use. */
int ldlm_cli_cancel_unused(struct ldlm_namespace *ns,
                           struct ldlm_res_id *res_id, int flags, void *opaque)
{
        int i;
        ENTRY;

        if (ns == NULL)
                RETURN(ELDLM_OK);

        if (res_id)
                RETURN(ldlm_cli_cancel_unused_resource(ns, *res_id, flags,
                                                       opaque));

        l_lock(&ns->ns_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                struct list_head *tmp, *pos;
                list_for_each_safe(tmp, pos, &(ns->ns_hash[i])) {
                        int rc;
                        struct ldlm_resource *res;
                        res = list_entry(tmp, struct ldlm_resource, lr_hash);
                        ldlm_resource_getref(res);

                        rc = ldlm_cli_cancel_unused_resource(ns, res->lr_name,
                                                             flags, opaque);

                        if (rc)
                                CERROR("cancel_unused_res ("LPU64"): %d\n",
                                       res->lr_name.name[0], rc);
                        ldlm_resource_putref(res);
                }
        }
        l_unlock(&ns->ns_lock);

        RETURN(ELDLM_OK);
}

/* join/split resource locks to/from lru list */
int ldlm_cli_join_lru(struct ldlm_namespace *ns,
                      struct ldlm_res_id *res_id, int join)
{
        struct ldlm_resource *res;
        struct ldlm_lock *lock, *n;
        int count = 0;
        ENTRY;

        LASSERT(ns->ns_client == LDLM_NAMESPACE_CLIENT);

        res = ldlm_resource_get(ns, NULL, *res_id, LDLM_EXTENT, 0);
        if (res == NULL)
                RETURN(count);
        LASSERT(res->lr_type == LDLM_EXTENT);

        l_lock(&ns->ns_lock);
        if (!join)
                goto split;

        list_for_each_entry_safe (lock, n, &res->lr_granted, l_res_link) {
                if (list_empty(&lock->l_lru) &&
                    !lock->l_readers && !lock->l_writers &&
                    !(lock->l_flags & LDLM_FL_LOCAL) &&
                    !(lock->l_flags & LDLM_FL_CBPENDING)) {
                        LASSERT(ns->ns_nr_unused >= 0);
                        list_add_tail(&lock->l_lru, &ns->ns_unused_list);
                        ns->ns_nr_unused++;
                        lock->l_flags &= ~LDLM_FL_NO_LRU;
                        LDLM_DEBUG(lock, "join lock to lru");
                        count++;
                }
        }
        goto unlock;
split:
        list_for_each_entry_safe (lock, n, &ns->ns_unused_list, l_lru) {
                if (lock->l_resource == res) {
                        ldlm_lock_remove_from_lru(lock);
                        lock->l_flags |= LDLM_FL_NO_LRU;
                        LDLM_DEBUG(lock, "split lock from lru");
                        count++;
                }
        }
unlock:
        l_unlock(&ns->ns_lock);
        ldlm_resource_putref(res);
        RETURN(count);
}

/* Lock iterators. */

int ldlm_resource_foreach(struct ldlm_resource *res, ldlm_iterator_t iter,
                          void *closure)
{
        struct list_head *tmp, *next;
        struct ldlm_lock *lock;
        int rc = LDLM_ITER_CONTINUE;
        struct ldlm_namespace *ns;

        ENTRY;

        if (!res)
                RETURN(LDLM_ITER_CONTINUE);

        ns = res->lr_namespace;
        l_lock(&ns->ns_lock);
        list_for_each_safe(tmp, next, &res->lr_granted) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (iter(lock, closure) == LDLM_ITER_STOP)
                        GOTO(out, rc = LDLM_ITER_STOP);
        }

        list_for_each_safe(tmp, next, &res->lr_converting) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (iter(lock, closure) == LDLM_ITER_STOP)
                        GOTO(out, rc = LDLM_ITER_STOP);
        }

        list_for_each_safe(tmp, next, &res->lr_waiting) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (iter(lock, closure) == LDLM_ITER_STOP)
                        GOTO(out, rc = LDLM_ITER_STOP);
        }
 out:
        l_unlock(&ns->ns_lock);
        RETURN(rc);
}

struct iter_helper_data {
        ldlm_iterator_t iter;
        void *closure;
};

static int ldlm_iter_helper(struct ldlm_lock *lock, void *closure)
{
        struct iter_helper_data *helper = closure;
        return helper->iter(lock, helper->closure);
}

static int ldlm_res_iter_helper(struct ldlm_resource *res, void *closure)
{
        return ldlm_resource_foreach(res, ldlm_iter_helper, closure);
}

int ldlm_namespace_foreach(struct ldlm_namespace *ns, ldlm_iterator_t iter,
                           void *closure)
{
        struct iter_helper_data helper = { iter: iter, closure: closure };
        return ldlm_namespace_foreach_res(ns, ldlm_res_iter_helper, &helper);
}

int ldlm_namespace_foreach_res(struct ldlm_namespace *ns,
                               ldlm_res_iterator_t iter, void *closure)
{
        int i, rc = LDLM_ITER_CONTINUE;

        ENTRY;
        l_lock(&ns->ns_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                struct list_head *tmp, *next;
                list_for_each_safe(tmp, next, &(ns->ns_hash[i])) {
                        struct ldlm_resource *res =
                                list_entry(tmp, struct ldlm_resource, lr_hash);

                        ldlm_resource_getref(res);
                        rc = iter(res, closure);
                        ldlm_resource_putref(res);
                        if (rc == LDLM_ITER_STOP)
                                GOTO(out, rc);
                }
        }
 out:
        l_unlock(&ns->ns_lock);
        RETURN(rc);
}

/* non-blocking function to manipulate a lock whose cb_data is being put away.*/
void ldlm_change_cbdata(struct ldlm_namespace *ns, struct ldlm_res_id *res_id,
                        ldlm_iterator_t iter, void *data)
{
        struct ldlm_resource *res;
        ENTRY;

        if (ns == NULL) {
                CERROR("must pass in namespace\n");
                LBUG();
        }

        res = ldlm_resource_get(ns, NULL, *res_id, 0, 0);
        if (res == NULL) {
                EXIT;
                return;
        }

        l_lock(&ns->ns_lock);
        ldlm_resource_foreach(res, iter, data);
        l_unlock(&ns->ns_lock);
        ldlm_resource_putref(res);
        EXIT;
}

/* Lock replay */

static int ldlm_chain_lock_for_replay(struct ldlm_lock *lock, void *closure)
{
        struct list_head *list = closure;

        /* we use l_pending_chain here, because it's unused on clients. */
        LASSERTF(list_empty(&lock->l_pending_chain),"lock %p next %p prev %p\n",
                 lock, &lock->l_pending_chain.next,&lock->l_pending_chain.prev);
        /* bug 9573: don't replay locks left after eviction */
        if (!(lock->l_flags & LDLM_FL_FAILED))
                list_add(&lock->l_pending_chain, list);
        return LDLM_ITER_CONTINUE;
}

static int replay_lock_interpret(struct ptlrpc_request *req,
                                    void * data, int rc)
{
        struct ldlm_lock *lock;
        struct ldlm_reply *reply;

        ENTRY;
        atomic_dec(&req->rq_import->imp_replay_inflight);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        lock = req->rq_async_args.pointer_arg[0];
        LASSERT(lock != NULL);

        reply = lustre_swab_repbuf(req, 0, sizeof (*reply),
                                   lustre_swab_ldlm_reply);
        if (reply == NULL) {
                CERROR("Can't unpack ldlm_reply\n");
                GOTO (out, rc = -EPROTO);
        }

        lock->l_remote_handle = reply->lock_handle;
        LDLM_DEBUG(lock, "replayed lock:");
        ptlrpc_import_recovery_state_machine(req->rq_import);
 out:
        if (rc != ELDLM_OK)
                ptlrpc_connect_import(req->rq_import, NULL);


        RETURN(rc);
}

static int replay_one_lock(struct obd_import *imp, struct ldlm_lock *lock)
{
        struct ptlrpc_request *req;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        int buffers = 1;
        int size[2];
        int flags;
        ENTRY;

        /* If this is reply-less callback lock, we cannot replay it, since
         * server might have long dropped it, but notification of that event was
         * lost by network. (and server granted conflicting lock already) */
        if (lock->l_flags & LDLM_FL_CANCEL_ON_BLOCK) {
                LDLM_DEBUG(lock, "Not replaying reply-less lock:");
                ldlm_lock_cancel(lock);
                RETURN(0);
        }
        /*
         * If granted mode matches the requested mode, this lock is granted.
         *
         * If they differ, but we have a granted mode, then we were granted
         * one mode and now want another: ergo, converting.
         *
         * If we haven't been granted anything and are on a resource list,
         * then we're blocked/waiting.
         *
         * If we haven't been granted anything and we're NOT on a resource list,
         * then we haven't got a reply yet and don't have a known disposition.
         * This happens whenever a lock enqueue is the request that triggers
         * recovery.
         */
        if (lock->l_granted_mode == lock->l_req_mode)
                flags = LDLM_FL_REPLAY | LDLM_FL_BLOCK_GRANTED;
        else if (lock->l_granted_mode)
                flags = LDLM_FL_REPLAY | LDLM_FL_BLOCK_CONV;
        else if (!list_empty(&lock->l_res_link))
                flags = LDLM_FL_REPLAY | LDLM_FL_BLOCK_WAIT;
        else
                flags = LDLM_FL_REPLAY;

        size[0] = sizeof(*body);
        req = ptlrpc_prep_req(imp, LUSTRE_DLM_VERSION, LDLM_ENQUEUE,
                              1, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        /* We're part of recovery, so don't wait for it. */
        req->rq_send_state = LUSTRE_IMP_REPLAY_LOCKS;

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        ldlm_lock2desc(lock, &body->lock_desc);
        body->lock_flags = flags;

        ldlm_lock2handle(lock, &body->lock_handle1);
        size[0] = sizeof(*reply);
        if (lock->l_lvb_len != 0) {
                buffers = 2;
                size[1] = lock->l_lvb_len;
        }
        req->rq_replen = lustre_msg_size(buffers, size);

        LDLM_DEBUG(lock, "replaying lock:");

        atomic_inc(&req->rq_import->imp_replay_inflight);
        req->rq_async_args.pointer_arg[0] = lock;
        req->rq_interpret_reply = replay_lock_interpret;
        ptlrpcd_add_req(req);

        RETURN(0);
}

int ldlm_replay_locks(struct obd_import *imp)
{
        struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
        struct list_head list;
        struct ldlm_lock *lock, *next;
        int rc = 0;

        ENTRY;
        CFS_INIT_LIST_HEAD(&list);

        LASSERT(atomic_read(&imp->imp_replay_inflight) == 0);

        /* ensure this doesn't fall to 0 before all have been queued */
        atomic_inc(&imp->imp_replay_inflight);

        l_lock(&ns->ns_lock);
        (void)ldlm_namespace_foreach(ns, ldlm_chain_lock_for_replay, &list);

        list_for_each_entry_safe(lock, next, &list, l_pending_chain) {
                list_del_init(&lock->l_pending_chain);
                if (rc)
                        continue; /* or try to do the rest? */
                rc = replay_one_lock(imp, lock);
        }
        l_unlock(&ns->ns_lock);

        atomic_dec(&imp->imp_replay_inflight);

        RETURN(rc);
}
