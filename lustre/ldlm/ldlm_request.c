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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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

int ldlm_enqueue_min = OBD_TIMEOUT_DEFAULT;
CFS_MODULE_PARM(ldlm_enqueue_min, "i", int, 0644,
                "lock enqueue timeout minimum");

static void interrupted_completion_wait(void *data)
{
}

struct lock_wait_data {
        struct ldlm_lock *lwd_lock;
        __u32             lwd_conn_cnt;
};

struct ldlm_async_args {
        struct lustre_handle lock_handle;
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

                LDLM_ERROR(lock, "lock timed out (enqueued at %lu, %lus ago); "
                           "not entering recovery in server code, just going "
                           "back to sleep", lock->l_enqueued_time.tv_sec,
                           cfs_time_current_sec() -
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
        LDLM_ERROR(lock, "lock timed out (enqueued at %lu, %lus ago), entering "
                   "recovery for %s@%s", lock->l_enqueued_time.tv_sec,
                   CURRENT_SECONDS - lock->l_enqueued_time.tv_sec,
                   obd2cli_tgt(obd), imp->imp_connection->c_remote_uuid.uuid);

        RETURN(0);
}

/* We use the same basis for both server side and client side functions
   from a single node. */
int ldlm_get_enq_timeout(struct ldlm_lock *lock)
{
        int timeout = at_get(&lock->l_resource->lr_namespace->ns_at_estimate);
        if (AT_OFF)
                return obd_timeout / 2;
        /* Since these are non-updating timeouts, we should be conservative.
           It would be nice to have some kind of "early reply" mechanism for
           lock callbacks too... */
        timeout = timeout + (timeout >> 1); /* 150% */
        return max(timeout, ldlm_enqueue_min);
}
EXPORT_SYMBOL(ldlm_get_enq_timeout);

static int is_granted_or_cancelled(struct ldlm_lock *lock)
{
        int ret = 0;

        lock_res_and_lock(lock);
        if (((lock->l_req_mode == lock->l_granted_mode) &&
             !(lock->l_flags & LDLM_FL_CP_REQD)) ||
            (lock->l_flags & LDLM_FL_FAILED))
                ret = 1;
        unlock_res_and_lock(lock);

        return ret;
}

int ldlm_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        /* XXX ALLOCATE - 160 bytes */
        struct lock_wait_data lwd;
        struct obd_device *obd;
        struct obd_import *imp = NULL;
        struct l_wait_info lwi;
        __u32 timeout;
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
        if (obd != NULL) {
                imp = obd->u.cli.cl_import;
        }

        /* Wait a long time for enqueue - server may have to callback a
           lock from another client.  Server will evict the other client if it
           doesn't respond reasonably, and then give us the lock. */
        timeout = ldlm_get_enq_timeout(lock) * 2;

        lwd.lwd_lock = lock;

        if (lock->l_flags & LDLM_FL_NO_TIMEOUT) {
                LDLM_DEBUG(lock, "waiting indefinitely because of NO_TIMEOUT");
                lwi = LWI_INTR(interrupted_completion_wait, &lwd);
        } else {
                lwi = LWI_TIMEOUT_INTR(cfs_time_seconds(timeout),
                                       ldlm_expired_completion_wait,
                                       interrupted_completion_wait, &lwd);
        }

        if (imp != NULL) {
                spin_lock(&imp->imp_lock);
                lwd.lwd_conn_cnt = imp->imp_conn_cnt;
                spin_unlock(&imp->imp_lock);
        }

        /* Go to sleep until the lock is granted or cancelled. */
        rc = l_wait_event(lock->l_waitq, is_granted_or_cancelled(lock), &lwi);

        if (lock->l_destroyed || lock->l_flags & LDLM_FL_FAILED) {
                LDLM_DEBUG(lock, "client-side enqueue waking up: destroyed");
                RETURN(-EIO);
        }

        if (rc) {
                LDLM_DEBUG(lock, "client-side enqueue waking up: failed (%d)",
                           rc);
                RETURN(rc);
        }

        LDLM_DEBUG(lock, "client-side enqueue waking up: granted after %lds",
                   cfs_time_current_sec() - lock->l_enqueued_time.tv_sec);

        /* Update our time estimate */
        at_add(&lock->l_resource->lr_namespace->ns_at_estimate,
               cfs_time_current_sec() - lock->l_enqueued_time.tv_sec);

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

        lock_res_and_lock(lock);
        /* Get this: if ldlm_blocking_ast is racing with intent_policy, such
         * that ldlm_blocking_ast is called just before intent_policy method
         * takes the ns_lock, then by the time we get the lock, we might not
         * be the correct blocking function anymore.  So check, and return
         * early, if so. */
        if (lock->l_blocking_ast != ldlm_blocking_ast) {
                unlock_res_and_lock(lock);
                RETURN(0);
        }

        lock->l_flags |= LDLM_FL_CBPENDING;
        do_ast = (!lock->l_readers && !lock->l_writers);
        unlock_res_and_lock(lock);

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

int ldlm_cli_enqueue_local(struct ldlm_namespace *ns,
                           struct ldlm_res_id *res_id,
                           ldlm_type_t type, ldlm_policy_data_t *policy,
                           ldlm_mode_t mode, int *flags,
                           ldlm_blocking_callback blocking,
                           ldlm_completion_callback completion,
                           ldlm_glimpse_callback glimpse,
                           void *data, __u32 lvb_len, void *lvb_swabber,
                           struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        int err;
        ENTRY;

        LASSERT(!(*flags & LDLM_FL_REPLAY));
        if (ns_is_client(ns)) {
                CERROR("Trying to enqueue local lock in a shadow namespace\n");
                LBUG();
        }

        lock = ldlm_lock_create(ns, *res_id, type, mode, blocking,
                                completion, glimpse, data, lvb_len);
        if (!lock)
                GOTO(out_nolock, err = -ENOMEM);
        LDLM_DEBUG(lock, "client-side local enqueue handler, new lock created");

        ldlm_lock_addref_internal(lock, mode);
        ldlm_lock2handle(lock, lockh);
        lock_res_and_lock(lock);
        lock->l_flags |= LDLM_FL_LOCAL;
        if (*flags & LDLM_FL_ATOMIC_CB)
                lock->l_flags |= LDLM_FL_ATOMIC_CB;
        lock->l_lvb_swabber = lvb_swabber;
        unlock_res_and_lock(lock);
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
                *res_id = lock->l_resource->lr_name;

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
        lock_res_and_lock(lock);
        lock->l_flags |= LDLM_FL_LOCAL_ONLY;
        unlock_res_and_lock(lock);
        LDLM_DEBUG(lock, "setting FL_LOCAL_ONLY");

        ldlm_lock_decref_and_cancel(lockh, mode);

        /* XXX - HACK because we shouldn't call ldlm_lock_destroy()
         *       from llite/file.c/ll_file_flock(). */
        if (lock->l_resource->lr_type == LDLM_FLOCK)
                ldlm_lock_destroy(lock);
}

int ldlm_cli_enqueue_fini(struct obd_export *exp, struct ptlrpc_request *req,
                          ldlm_type_t type, __u8 with_policy, ldlm_mode_t mode,
                          int *flags, void *lvb, __u32 lvb_len,
                          void *lvb_swabber, struct lustre_handle *lockh,int rc)
{
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        int is_replay = *flags & LDLM_FL_REPLAY;
        struct lustre_handle old_hash_key;
        struct ldlm_lock *lock;
        struct ldlm_reply *reply;
        int cleanup_phase = 1;
        ENTRY;

        lock = ldlm_handle2lock(lockh);
        /* ldlm_cli_enqueue is holding a reference on this lock. */
        if (!lock) {
                LASSERT(type == LDLM_FLOCK);
                RETURN(-ENOLCK);
        }

        if (rc != ELDLM_OK) {
                LASSERT(!is_replay);
                LDLM_DEBUG(lock, "client-side enqueue END (%s)",
                           rc == ELDLM_LOCK_ABORTED ? "ABORTED" : "FAILED");
                if (rc == ELDLM_LOCK_ABORTED) {
                        /* Before we return, swab the reply */
                        reply = lustre_swab_repbuf(req, DLM_LOCKREPLY_OFF,
                                                   sizeof(*reply),
                                                   lustre_swab_ldlm_reply);
                        if (reply == NULL) {
                                CERROR("Can't unpack ldlm_reply\n");
                                rc = -EPROTO;
                        }
                        if (lvb_len) {
                                void *tmplvb;
                                tmplvb = lustre_swab_repbuf(req,
                                                            DLM_REPLY_REC_OFF,
                                                            lvb_len,
                                                            lvb_swabber);
                                if (tmplvb == NULL)
                                        GOTO(cleanup, rc = -EPROTO);
                                if (lvb != NULL)
                                        memcpy(lvb, tmplvb, lvb_len);
                        }
                }
                GOTO(cleanup, rc);
        }

        reply = lustre_swab_repbuf(req, DLM_LOCKREPLY_OFF, sizeof(*reply),
                                   lustre_swab_ldlm_reply);
        if (reply == NULL) {
                CERROR("Can't unpack ldlm_reply\n");
                GOTO(cleanup, rc = -EPROTO);
        }

        /* lock enqueued on the server */
        cleanup_phase = 0;

        lock_res_and_lock(lock);
        old_hash_key = lock->l_remote_handle;
        lock->l_remote_handle = reply->lock_handle;

        /* Key change rehash lock in per-export hash with new key */
        if (exp->exp_lock_hash)
                lustre_hash_rehash_key(exp->exp_lock_hash, &old_hash_key,
                                       &lock->l_remote_handle,
                                       &lock->l_exp_hash);

        *flags = reply->lock_flags;
        lock->l_flags |= reply->lock_flags & LDLM_INHERIT_FLAGS;
        /* move NO_TIMEOUT flag to the lock to force ldlm_lock_match()
         * to wait with no timeout as well */
        lock->l_flags |= reply->lock_flags & LDLM_FL_NO_TIMEOUT;
        unlock_res_and_lock(lock);

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

                        rc = ldlm_lock_change_resource(ns, lock,
                                           reply->lock_desc.l_resource.lr_name);
                        if (rc || lock->l_resource == NULL)
                                GOTO(cleanup, rc = -ENOMEM);
                        LDLM_DEBUG(lock, "client-side enqueue, new resource");
                }
                if (with_policy)
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
                lock_res_and_lock(lock);
                lock->l_flags |= LDLM_FL_CBPENDING | LDLM_FL_BL_AST;
                unlock_res_and_lock(lock);
                LDLM_DEBUG(lock, "enqueue reply includes blocking AST");
        }

        /* If the lock has already been granted by a completion AST, don't
         * clobber the LVB with an older one. */
        if (lvb_len && (lock->l_req_mode != lock->l_granted_mode)) {
                void *tmplvb;
                tmplvb = lustre_swab_repbuf(req, DLM_REPLY_REC_OFF, lvb_len,
                                            lvb_swabber);
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
                        if (rc && type != LDLM_FLOCK) /* bug 9425, bug 10250 */
                                cleanup_phase = 1;
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
        if (cleanup_phase == 1 && rc)
                failed_lock_cleanup(ns, lock, lockh, mode);
        /* Put lock 2 times, the second reference is held by ldlm_cli_enqueue */
        LDLM_LOCK_PUT(lock);
        LDLM_LOCK_PUT(lock);
        return rc;
}

/* PAGE_SIZE-512 is to allow TCP/IP and LNET headers to fit into
 * a single page on the send/receive side. XXX: 512 should be changed
 * to more adequate value. */
static inline int ldlm_req_handles_avail(struct obd_export *exp,
                                         __u32 *size, int bufcount, int off)
{
        int avail = min_t(int, LDLM_MAXREQSIZE, CFS_PAGE_SIZE - 512);

        avail -= lustre_msg_size(class_exp2cliimp(exp)->imp_msg_magic,
                                 bufcount, size);
        if (likely(avail >= 0))
                avail /= (int)sizeof(struct lustre_handle);
        else
                avail = 0;
        avail += LDLM_LOCKREQ_HANDLES - off;

        return avail;
}

static inline int ldlm_cancel_handles_avail(struct obd_export *exp)
{
        __u32 size[2] = { sizeof(struct ptlrpc_body),
                        sizeof(struct ldlm_request) };
        return ldlm_req_handles_avail(exp, size, 2, 0);
}

/* Cancel lru locks and pack them into the enqueue request. Pack there the given
 * @count locks in @cancels. */
struct ptlrpc_request *ldlm_prep_elc_req(struct obd_export *exp, int version,
                                         int opc, int bufcount, __u32 *size,
                                         int bufoff, int canceloff,
                                         struct list_head *cancels, int count)
{
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        int flags, avail, to_free, pack = 0;
        struct ldlm_request *dlm = NULL;
        struct ptlrpc_request *req;
        CFS_LIST_HEAD(head);
        ENTRY;

        if (cancels == NULL)
                cancels = &head;
        if (exp_connect_cancelset(exp)) {
                /* Estimate the amount of free space in the request. */
                LASSERT(bufoff < bufcount);

                avail = ldlm_req_handles_avail(exp, size, bufcount, canceloff);
                flags = ns_connect_lru_resize(ns) ?
                        LDLM_CANCEL_LRUR : LDLM_CANCEL_AGED;
                to_free = !ns_connect_lru_resize(ns) &&
                          opc == LDLM_ENQUEUE ? 1 : 0;

                /* Cancel lru locks here _only_ if the server supports
                 * EARLY_CANCEL. Otherwise we have to send extra CANCEL
                 * rpc, what will make us slower. */
                if (avail > count)
                        count += ldlm_cancel_lru_local(ns, cancels, to_free,
                                                       avail - count, 0, flags);
                if (avail > count)
                        pack = count;
                else
                        pack = avail;
                size[bufoff] = ldlm_request_bufsize(pack, opc);
        }
        req = ptlrpc_prep_req(class_exp2cliimp(exp), version,
                              opc, bufcount, size, NULL);
        if (exp_connect_cancelset(exp) && req) {
                if (canceloff) {
                        dlm = lustre_msg_buf(req->rq_reqmsg, bufoff,
                                             sizeof(*dlm));
                        /* Skip first lock handler in ldlm_request_pack(),
                         * this method will incrment @lock_count according
                         * to the lock handle amount actually written to
                         * the buffer. */
                        dlm->lock_count = canceloff;
                }
                /* Pack into the request @pack lock handles. */
                ldlm_cli_cancel_list(cancels, pack, req, bufoff);
                /* Prepare and send separate cancel rpc for others. */
                ldlm_cli_cancel_list(cancels, count - pack, NULL, 0);
        } else {
                ldlm_lock_list_put(cancels, l_bl_ast, count);
        }
        RETURN(req);
}

struct ptlrpc_request *ldlm_prep_enqueue_req(struct obd_export *exp,
                                             int bufcount, __u32 *size,
                                             struct list_head *cancels,
                                             int count)
{
        return ldlm_prep_elc_req(exp, LUSTRE_DLM_VERSION, LDLM_ENQUEUE,
                                 bufcount, size, DLM_LOCKREQ_OFF,
                                 LDLM_ENQUEUE_CANCEL_OFF, cancels, count);
}

/* If a request has some specific initialisation it is passed in @reqp,
 * otherwise it is created in ldlm_cli_enqueue.
 *
 * Supports sync and async requests, pass @async flag accordingly. If a
 * request was created in ldlm_cli_enqueue and it is the async request,
 * pass it to the caller in @reqp. */
int ldlm_cli_enqueue(struct obd_export *exp, struct ptlrpc_request **reqp,
                     struct ldlm_enqueue_info *einfo, struct ldlm_res_id res_id,
                     ldlm_policy_data_t *policy, int *flags,
                     void *lvb, __u32 lvb_len, void *lvb_swabber,
                     struct lustre_handle *lockh, int async)
{
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        __u32 size[3] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREQ_OFF]     = sizeof(*body),
                        [DLM_REPLY_REC_OFF]   = lvb_len };
        int is_replay = *flags & LDLM_FL_REPLAY;
        int req_passed_in = 1, rc, err;
        struct ptlrpc_request *req;
        ENTRY;

        LASSERT(exp != NULL);

        /* If we're replaying this lock, just check some invariants.
         * If we're creating a new lock, get everything all setup nice. */
        if (is_replay) {
                lock = ldlm_handle2lock(lockh);
                LASSERT(lock != NULL);
                LDLM_DEBUG(lock, "client-side enqueue START");
                LASSERT(exp == lock->l_conn_export);
        } else {
                lock = ldlm_lock_create(ns, res_id, einfo->ei_type,
                                        einfo->ei_mode, einfo->ei_cb_bl,
                                        einfo->ei_cb_cp, einfo->ei_cb_gl,
                                        einfo->ei_cbdata, lvb_len);
                if (lock == NULL)
                        RETURN(-ENOMEM);
                /* for the local lock, add the reference */
                ldlm_lock_addref_internal(lock, einfo->ei_mode);
                ldlm_lock2handle(lock, lockh);
                lock->l_lvb_swabber = lvb_swabber;
                if (policy != NULL) {
                        /* INODEBITS_INTEROP: If the server does not support
                         * inodebits, we will request a plain lock in the
                         * descriptor (ldlm_lock2desc() below) but use an
                         * inodebits lock internally with both bits set.
                         */
                        if (einfo->ei_type == LDLM_IBITS &&
                            !(exp->exp_connect_flags & OBD_CONNECT_IBITS))
                                lock->l_policy_data.l_inodebits.bits =
                                        MDS_INODELOCK_LOOKUP |
                                        MDS_INODELOCK_UPDATE;
                        else
                                lock->l_policy_data = *policy;
                }

                if (einfo->ei_type == LDLM_EXTENT)
                        lock->l_req_extent = policy->l_extent;
                LDLM_DEBUG(lock, "client-side enqueue START");
        }

        /* lock not sent to server yet */

        if (reqp == NULL || *reqp == NULL) {
                req = ldlm_prep_enqueue_req(exp, 2, size, NULL, 0);
                if (req == NULL) {
                        failed_lock_cleanup(ns, lock, lockh, einfo->ei_mode);
                        LDLM_LOCK_PUT(lock);
                        RETURN(-ENOMEM);
                }
                req_passed_in = 0;
                if (reqp)
                        *reqp = req;
        } else {
                req = *reqp;
                LASSERTF(lustre_msg_buflen(req->rq_reqmsg, DLM_LOCKREQ_OFF) >=
                         sizeof(*body), "buflen[%d] = %d, not %d\n",
                         DLM_LOCKREQ_OFF,
                         lustre_msg_buflen(req->rq_reqmsg, DLM_LOCKREQ_OFF),
                         (int)sizeof(*body));
        }

        lock->l_conn_export = exp;
        lock->l_export = NULL;
        lock->l_blocking_ast = einfo->ei_cb_bl;

        /* Dump lock data into the request buffer */
        body = lustre_msg_buf(req->rq_reqmsg, DLM_LOCKREQ_OFF, sizeof(*body));
        ldlm_lock2desc(lock, &body->lock_desc);
        body->lock_flags = *flags;
        body->lock_handle[0] = *lockh;

        /* Continue as normal. */
        if (!req_passed_in) {
                size[DLM_LOCKREPLY_OFF] = sizeof(*reply);
                ptlrpc_req_set_repsize(req, 2 + (lvb_len > 0), size);
        }

        /*
         * Liblustre client doesn't get extent locks, except for O_APPEND case
         * where [0, OBD_OBJECT_EOF] lock is taken, or truncate, where
         * [i_size, OBD_OBJECT_EOF] lock is taken.
         */
        LASSERT(ergo(LIBLUSTRE_CLIENT, einfo->ei_type != LDLM_EXTENT ||
                     policy->l_extent.end == OBD_OBJECT_EOF));

        if (async) {
                LASSERT(reqp != NULL);
                RETURN(0);
        }

        LDLM_DEBUG(lock, "sending request");
        rc = ptlrpc_queue_wait(req);
        err = ldlm_cli_enqueue_fini(exp, req, einfo->ei_type, policy ? 1 : 0,
                                    einfo->ei_mode, flags, lvb, lvb_len,
                                    lvb_swabber, lockh, rc);

        /* If ldlm_cli_enqueue_fini did not find the lock, we need to free
         * one reference that we took */
        if (err == -ENOLCK)
                LDLM_LOCK_PUT(lock);
        else
                rc = err;

        if (!req_passed_in && req != NULL) {
                ptlrpc_req_finished(req);
                if (reqp)
                        *reqp = NULL;
        }

        RETURN(rc);
}

static int ldlm_cli_convert_local(struct ldlm_lock *lock, int new_mode,
                                  __u32 *flags)
{
        struct ldlm_resource *res;
        int rc;
        ENTRY;
        if (ns_is_client(lock->l_resource->lr_namespace)) {
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
int ldlm_cli_convert(struct lustre_handle *lockh, int new_mode, __u32 *flags)
{
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        struct ptlrpc_request *req;
        __u32 size[2] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREQ_OFF]     = sizeof(*body) };
        int rc;
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
                              LUSTRE_DLM_VERSION, LDLM_CONVERT, 2, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, DLM_LOCKREQ_OFF, sizeof(*body));
        body->lock_handle[0] = lock->l_remote_handle;

        body->lock_desc.l_req_mode = new_mode;
        body->lock_flags = *flags;

        size[DLM_LOCKREPLY_OFF] = sizeof(*reply);
        ptlrpc_req_set_repsize(req, 2, size);

        rc = ptlrpc_queue_wait(req);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        reply = lustre_swab_repbuf(req, DLM_LOCKREPLY_OFF, sizeof(*reply),
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

/* Cancel locks locally.
 * Returns:
 * LDLM_FL_LOCAL_ONLY if tere is no need in a CANCEL rpc to the server;
 * LDLM_FL_CANCELING otherwise;
 * LDLM_FL_BL_AST if there is a need in a separate CANCEL rpc. */
static int ldlm_cli_cancel_local(struct ldlm_lock *lock)
{
        int rc = LDLM_FL_LOCAL_ONLY;
        ENTRY;

        if (lock->l_conn_export) {
                int local_only;

                LDLM_DEBUG(lock, "client-side cancel");
                /* Set this flag to prevent others from getting new references*/
                lock_res_and_lock(lock);
                lock->l_flags |= LDLM_FL_CBPENDING;
                local_only = (lock->l_flags &
                              (LDLM_FL_LOCAL_ONLY|LDLM_FL_CANCEL_ON_BLOCK));
                ldlm_cancel_callback(lock);
                rc = (lock->l_flags & LDLM_FL_BL_AST) ?
                        LDLM_FL_BL_AST : LDLM_FL_CANCELING;
                unlock_res_and_lock(lock);

                if (local_only) {
                        CDEBUG(D_DLMTRACE, "not sending request (at caller's "
                               "instruction)\n");
                        rc = LDLM_FL_LOCAL_ONLY;
                }
                ldlm_lock_cancel(lock);
        } else {
                if (ns_is_client(lock->l_resource->lr_namespace)) {
                        LDLM_ERROR(lock, "Trying to cancel local lock");
                        LBUG();
                }
                LDLM_DEBUG(lock, "server-side local cancel");
                ldlm_lock_cancel(lock);
                ldlm_reprocess_all(lock->l_resource);
                LDLM_DEBUG(lock, "server-side local cancel handler END");
        }

        RETURN(rc);
}

/* Pack @count locks in @head into ldlm_request buffer at the offset @off,
   of the request @req. */
static void ldlm_cancel_pack(struct ptlrpc_request *req, int off,
                             struct list_head *head, int count)
{
        struct ldlm_request *dlm;
        struct ldlm_lock *lock;
        int max, packed = 0;
        ENTRY;

        dlm = lustre_msg_buf(req->rq_reqmsg, off, sizeof(*dlm));
        LASSERT(dlm != NULL);

        /* Check the room in the request buffer. */
        max = lustre_msg_buflen(req->rq_reqmsg, off) -
                sizeof(struct ldlm_request);
        max /= sizeof(struct lustre_handle);
        max += LDLM_LOCKREQ_HANDLES;
        LASSERT(max >= dlm->lock_count + count);

        /* XXX: it would be better to pack lock handles grouped by resource.
         * so that the server cancel would call filter_lvbo_update() less
         * frequently. */
        list_for_each_entry(lock, head, l_bl_ast) {
                if (!count--)
                        break;
                LASSERT(lock->l_conn_export);
                /* Pack the lock handle to the given request buffer. */
                LDLM_DEBUG(lock, "packing");
                dlm->lock_handle[dlm->lock_count++] = lock->l_remote_handle;
                packed++;
        }
        CDEBUG(D_DLMTRACE, "%d locks packed\n", packed);
        EXIT;
}

/* Prepare and send a batched cancel rpc, it will include count lock handles
 * of locks given in @head. */
int ldlm_cli_cancel_req(struct obd_export *exp,
                        struct list_head *cancels, int count)
{
        struct ptlrpc_request *req = NULL;
        struct ldlm_request *body;
        __u32 size[2] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREQ_OFF]     = sizeof(*body) };
        struct obd_import *imp;
        int free, sent = 0;
        int rc = 0;
        ENTRY;

        LASSERT(exp != NULL);
        LASSERT(count > 0);

        OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_PAUSE_CANCEL, obd_fail_val);

        if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_RACE))
                RETURN(count);

        free = ldlm_req_handles_avail(exp, size, 2, 0);
        if (count > free)
                count = free;

        size[DLM_LOCKREQ_OFF] = ldlm_request_bufsize(count, LDLM_CANCEL);
        while (1) {
                imp = class_exp2cliimp(exp);
                if (imp == NULL || imp->imp_invalid) {
                        CDEBUG(D_DLMTRACE,
                               "skipping cancel on invalid import %p\n", imp);
                        RETURN(count);
                }

                req = ptlrpc_prep_req(imp, LUSTRE_DLM_VERSION, LDLM_CANCEL, 2,
                                      size, NULL);
                if (!req)
                        GOTO(out, rc = -ENOMEM);

                req->rq_no_resend = 1;
                req->rq_no_delay = 1;

                req->rq_request_portal = LDLM_CANCEL_REQUEST_PORTAL;
                req->rq_reply_portal = LDLM_CANCEL_REPLY_PORTAL;
                ptlrpc_at_set_req_timeout(req);

                body = lustre_msg_buf(req->rq_reqmsg, DLM_LOCKREQ_OFF,
                                      sizeof(*body));
                ldlm_cancel_pack(req, DLM_LOCKREQ_OFF, cancels, count);

                ptlrpc_req_set_repsize(req, 1, NULL);
                rc = ptlrpc_queue_wait(req);

                if (rc == ESTALE) {
                        CDEBUG(D_DLMTRACE, "client/server (nid %s) "
                               "out of sync -- not fatal\n",
                               libcfs_nid2str(req->rq_import->
                                              imp_connection->c_peer.nid));
                        rc = 0;
                } else if (rc == -ETIMEDOUT && /* check there was no reconnect*/
                           req->rq_import_generation == imp->imp_generation) {
                        ptlrpc_req_finished(req);
                        continue;
                } else if (rc != ELDLM_OK) {
                        CERROR("Got rc %d from cancel RPC: canceling "
                               "anyway\n", rc);
                        break;
                }
                sent = count;
                break;
        }

        ptlrpc_req_finished(req);
        EXIT;
out:
        return sent ? sent : rc;
}

static inline struct ldlm_pool *ldlm_imp2pl(struct obd_import *imp)
{
        LASSERT(imp != NULL);
        return &imp->imp_obd->obd_namespace->ns_pool;
}

int ldlm_cli_update_pool(struct ptlrpc_request *req)
{
        struct obd_device *obd;
        __u64 old_slv, new_slv;
        __u32 new_limit;
        ENTRY;

        if (unlikely(!req->rq_import || !req->rq_import->imp_obd ||
                     !imp_connect_lru_resize(req->rq_import)))
        {
                /*
                 * Do nothing for corner cases.
                 */
                RETURN(0);
        }

        /*
         * In some cases RPC may contain slv and limit zeroed out. This is
         * the case when server does not support lru resize feature. This is
         * also possible in some recovery cases when server side reqs have no
         * ref to obd export and thus access to server side namespace is no
         * possible.
         */
        if (lustre_msg_get_slv(req->rq_repmsg) == 0 ||
            lustre_msg_get_limit(req->rq_repmsg) == 0) {
                DEBUG_REQ(D_HA, req, "Zero SLV or Limit found "
                          "(SLV: "LPU64", Limit: %u)",
                          lustre_msg_get_slv(req->rq_repmsg),
                          lustre_msg_get_limit(req->rq_repmsg));
                RETURN(0);
        }

        new_limit = lustre_msg_get_limit(req->rq_repmsg);
        new_slv = lustre_msg_get_slv(req->rq_repmsg);
        obd = req->rq_import->imp_obd;

        /*
         * Set new SLV and Limit to obd fields to make accessible for pool
         * thread. We do not access obd_namespace and pool directly here
         * as there is no reliable way to make sure that they are still
         * alive in cleanup time. Evil races are possible which may cause
         * oops in that time.
         */
        write_lock(&obd->obd_pool_lock);
        old_slv = obd->obd_pool_slv;
        obd->obd_pool_slv = new_slv;
        obd->obd_pool_limit = new_limit;
        write_unlock(&obd->obd_pool_lock);

        RETURN(0);
}
EXPORT_SYMBOL(ldlm_cli_update_pool);

int ldlm_cli_cancel(struct lustre_handle *lockh)
{
        struct ldlm_namespace *ns;
        int avail, flags, count = 1, rc = 0;
        struct ldlm_lock *lock;
        CFS_LIST_HEAD(cancels);
        ENTRY;

        /* concurrent cancels on the same handle can happen */
        lock = __ldlm_handle2lock(lockh, LDLM_FL_CANCELING);
        if (lock == NULL) {
                LDLM_DEBUG_NOLOCK("lock is already being destroyed\n");
                RETURN(0);
        }

        rc = ldlm_cli_cancel_local(lock);
        if (rc < 0 || rc == LDLM_FL_LOCAL_ONLY) {
                LDLM_LOCK_PUT(lock);
                RETURN(rc < 0 ? rc : 0);
        }
        /* Even if the lock is marked as LDLM_FL_BL_AST, this is a LDLM_CANCEL
         * rpc which goes to canceld portal, so we can cancel other lru locks
         * here and send them all as one LDLM_CANCEL rpc. */
        LASSERT(list_empty(&lock->l_bl_ast));
        list_add(&lock->l_bl_ast, &cancels);

        if (exp_connect_cancelset(lock->l_conn_export)) {
                avail = ldlm_cancel_handles_avail(lock->l_conn_export);
                LASSERT(avail > 0);

                ns = lock->l_resource->lr_namespace;
                flags = ns_connect_lru_resize(ns) ?
                        LDLM_CANCEL_LRUR : LDLM_CANCEL_AGED;
                count += ldlm_cancel_lru_local(ns, &cancels, 0, avail - 1,
                                               LDLM_FL_BL_AST, flags);
        }
        ldlm_cli_cancel_list(&cancels, count, NULL, 0);
        RETURN(0);
}

/* XXX until we will have compound requests and can cut cancels from generic rpc
 * we need send cancels with LDLM_FL_BL_AST flag as separate rpc */
static int ldlm_cancel_list(struct list_head *cancels, int count, int flags)
{
        CFS_LIST_HEAD(head);
        struct ldlm_lock *lock, *next;
        int left = 0, bl_ast = 0, rc;

        left = count;
        list_for_each_entry_safe(lock, next, cancels, l_bl_ast) {
                if (left-- == 0)
                        break;

                if (flags & LDLM_FL_LOCAL_ONLY) {
                        rc = LDLM_FL_LOCAL_ONLY;
                        ldlm_lock_cancel(lock);
                } else {
                        rc = ldlm_cli_cancel_local(lock);
                }
                if (!(flags & LDLM_FL_BL_AST) && (rc == LDLM_FL_BL_AST)) {
                        LDLM_DEBUG(lock, "Cancel lock separately");
                        list_del_init(&lock->l_bl_ast);
                        list_add(&lock->l_bl_ast, &head);
                        bl_ast ++;
                        continue;
                }
                if (rc == LDLM_FL_LOCAL_ONLY) {
                        /* CANCEL RPC should not be sent to server. */
                        list_del_init(&lock->l_bl_ast);
                        LDLM_LOCK_PUT(lock);
                        count--;
                }

        }
        if (bl_ast > 0) {
                count -= bl_ast;
                ldlm_cli_cancel_list(&head, bl_ast, NULL, 0);
        }

        RETURN(count);
}

/* Return 1 to stop lru processing and keep current lock cached. Return zero
 * otherwise. */
static ldlm_policy_res_t ldlm_cancel_shrink_policy(struct ldlm_namespace *ns,
                                                   struct ldlm_lock *lock,
                                                   int unused, int added,
                                                   int count)
{
        int lock_cost;
        __u64 page_nr;

        /* Stop lru processing when we reached passed @count or checked all
         * locks in lru. */
        if (count && added >= count)
                return LDLM_POLICY_KEEP_LOCK;

        if (lock->l_resource->lr_type == LDLM_EXTENT) {
                struct ldlm_extent *l_extent;

                /* For all extent locks cost is 1 + number of pages in
                 * their extent. */
                l_extent = &lock->l_policy_data.l_extent;
                page_nr = (l_extent->end - l_extent->start);
                do_div(page_nr, CFS_PAGE_SIZE);

#ifdef __KERNEL__
                /* XXX: In fact this is evil hack, we can't access inode
                 * here. For doing it right we need somehow to have number
                 * of covered by lock. This should be fixed later when 10718
                 * is landed. */
                if (lock->l_ast_data != NULL) {
                        struct inode *inode = lock->l_ast_data;
                        if (page_nr > inode->i_mapping->nrpages)
                                page_nr = inode->i_mapping->nrpages;
                }
#endif
                lock_cost = 1 + page_nr;
        } else {
                /* For all locks which are not extent ones cost is 1 */
                lock_cost = 1;
        }

        /* Keep all expensive locks in lru for the memory pressure time
         * cancel policy. They anyways may be canceled by lru resize
         * pplicy if they have not small enough CLV. */
        return lock_cost > ns->ns_shrink_thumb ?
                LDLM_POLICY_KEEP_LOCK : LDLM_POLICY_CANCEL_LOCK;
}

/* Return 1 to stop lru processing and keep current lock cached. Return zero
 * otherwise. */
static ldlm_policy_res_t ldlm_cancel_lrur_policy(struct ldlm_namespace *ns,
                                                 struct ldlm_lock *lock,
                                                 int unused, int added,
                                                 int count)
{
        cfs_time_t cur = cfs_time_current();
        struct ldlm_pool *pl = &ns->ns_pool;
        __u64 slv, lvf, lv;
        cfs_time_t la;

        /* Stop lru processing when we reached passed @count or checked all
         * locks in lru. */
        if (count && added >= count)
                return LDLM_POLICY_KEEP_LOCK;

        slv = ldlm_pool_get_slv(pl);
        lvf = ldlm_pool_get_lvf(pl);

        la = cfs_duration_sec(cfs_time_sub(cur,
                              lock->l_last_used));

        /* Stop when slv is not yet come from server or
         * lv is smaller than it is. */
        lv = lvf * la * unused;

        /* Inform pool about current CLV to see it via proc. */
        ldlm_pool_set_clv(pl, lv);
        return (slv == 1 || lv < slv) ?
                LDLM_POLICY_KEEP_LOCK : LDLM_POLICY_CANCEL_LOCK;
}

/* Return 1 to stop lru processing and keep current lock cached. Return zero
 * otherwise. */
static ldlm_policy_res_t ldlm_cancel_passed_policy(struct ldlm_namespace *ns,
                                                   struct ldlm_lock *lock,
                                                   int unused, int added,
                                                   int count)
{
        /* Stop lru processing when we reached passed @count or checked all
         * locks in lru. */
        return (added >= count) ?
                LDLM_POLICY_KEEP_LOCK : LDLM_POLICY_CANCEL_LOCK;
}

/* Return 1 to stop lru processing and keep current lock cached. Return zero
 * otherwise. */
static ldlm_policy_res_t ldlm_cancel_aged_policy(struct ldlm_namespace *ns,
                                                 struct ldlm_lock *lock,
                                                 int unused, int added,
                                                 int count)
{
        /* Stop lru processing if young lock is found and we reached passed
         * @count. */
        return ((added >= count) &&
                cfs_time_before(cfs_time_current(),
                                cfs_time_add(lock->l_last_used,
                                             ns->ns_max_age))) ?
                LDLM_POLICY_KEEP_LOCK : LDLM_POLICY_CANCEL_LOCK;
}

/* Return 1 to stop lru processing and keep current lock cached. Return zero
 * otherwise. */
static ldlm_policy_res_t ldlm_cancel_default_policy(struct ldlm_namespace *ns,
                                                    struct ldlm_lock *lock,
                                                    int unused, int added,
                                                    int count)
{
        /* Stop lru processing when we reached passed @count or checked all
         * locks in lru. */
        return (added >= count) ?
                LDLM_POLICY_KEEP_LOCK : LDLM_POLICY_CANCEL_LOCK;
}

typedef ldlm_policy_res_t (*ldlm_cancel_lru_policy_t)(struct ldlm_namespace *,
                                                      struct ldlm_lock *, int,
                                                      int, int);

static ldlm_cancel_lru_policy_t
ldlm_cancel_lru_policy(struct ldlm_namespace *ns, int flags)
{
        if (ns_connect_lru_resize(ns)) {
                if (flags & LDLM_CANCEL_SHRINK)
                        return ldlm_cancel_shrink_policy;
                else if (flags & LDLM_CANCEL_LRUR)
                        return ldlm_cancel_lrur_policy;
                else if (flags & LDLM_CANCEL_PASSED)
                        return ldlm_cancel_passed_policy;
        } else {
                if (flags & LDLM_CANCEL_AGED)
                        return ldlm_cancel_aged_policy;
        }

        return ldlm_cancel_default_policy;
}

/* - Free space in lru for @count new locks,
 *   redundant unused locks are canceled locally;
 * - also cancel locally unused aged locks;
 * - do not cancel more than @max locks;
 * - GET the found locks and add them into the @cancels list.
 *
 * A client lock can be added to the l_bl_ast list only when it is
 * marked LDLM_FL_CANCELING. Otherwise, somebody is already doing CANCEL.
 * There are the following use cases: ldlm_cancel_resource_local(),
 * ldlm_cancel_lru_local() and ldlm_cli_cancel(), which check&set this
 * flag properly. As any attempt to cancel a lock rely on this flag,
 * l_bl_ast list is accessed later without any special locking.
 *
 * Calling policies for enabled lru resize:
 * ----------------------------------------
 * flags & LDLM_CANCEL_LRUR - use lru resize policy (SLV from server) to
 *                            cancel not more than @count locks;
 *
 * flags & LDLM_CANCEL_PASSED - cancel @count number of old locks (located at
 *                              the beginning of lru list);
 *
 * flags & LDLM_CANCEL_SHRINK - cancel not more than @count locks according to
 *                              memory pressre policy function;
 *
 * flags & LDLM_CANCEL_AGED -   cancel locks according to "aged policy".
 */
int ldlm_cancel_lru_local(struct ldlm_namespace *ns, struct list_head *cancels,
                          int count, int max, int cancel_flags, int flags)
{
        ldlm_cancel_lru_policy_t pf;
        struct ldlm_lock *lock, *next;
        int added = 0, unused;
        ENTRY;

        spin_lock(&ns->ns_unused_lock);
        unused = ns->ns_nr_unused;

        if (!ns_connect_lru_resize(ns))
                count += unused - ns->ns_max_unused;

        pf = ldlm_cancel_lru_policy(ns, flags);
        LASSERT(pf != NULL);

        while (!list_empty(&ns->ns_unused_list)) {
                /* For any flags, stop scanning if @max is reached. */
                if (max && added >= max)
                        break;

                list_for_each_entry_safe(lock, next, &ns->ns_unused_list, l_lru){
                        /* No locks which got blocking requests. */
                        LASSERT(!(lock->l_flags & LDLM_FL_BL_AST));

                        /* Somebody is already doing CANCEL. No need in this
                         * lock in lru, do not traverse it again. */
                        if (!(lock->l_flags & LDLM_FL_CANCELING))
                                break;

                        ldlm_lock_remove_from_lru_nolock(lock);
                }
                if (&lock->l_lru == &ns->ns_unused_list)
                        break;

                /* Pass the lock through the policy filter and see if it
                 * should stay in lru.
                 *
                 * Even for shrinker policy we stop scanning if
                 * we find a lock that should stay in the cache.
                 * We should take into account lock age anyway
                 * as new lock even if it is small of weight is
                 * valuable resource.
                 *
                 * That is, for shrinker policy we drop only
                 * old locks, but additionally chose them by
                 * their weight. Big extent locks will stay in
                 * the cache. */
                if (pf(ns, lock, unused, added, count) == LDLM_POLICY_KEEP_LOCK)
                        break;

                LDLM_LOCK_GET(lock); /* dropped by bl thread */
                spin_unlock(&ns->ns_unused_lock);

                lock_res_and_lock(lock);
                /* Check flags again under the lock. */
                if ((lock->l_flags & LDLM_FL_CANCELING) ||
                    (ldlm_lock_remove_from_lru(lock) == 0)) {
                        /* other thread is removing lock from lru or
                         * somebody is already doing CANCEL or
                         * there is a blocking request which will send
                         * cancel by itseft or the lock is matched
                         * is already not unused. */
                        unlock_res_and_lock(lock);
                        LDLM_LOCK_PUT(lock);
                        spin_lock(&ns->ns_unused_lock);
                        continue;
                }
                LASSERT(!lock->l_readers && !lock->l_writers);

                /* If we have chosen to cancel this lock voluntarily, we
                 * better send cancel notification to server, so that it
                 * frees appropriate state. This might lead to a race
                 * where while we are doing cancel here, server is also
                 * silently cancelling this lock. */
                lock->l_flags &= ~LDLM_FL_CANCEL_ON_BLOCK;

                /* Setting the CBPENDING flag is a little misleading,
                 * but prevents an important race; namely, once
                 * CBPENDING is set, the lock can accumulate no more
                 * readers/writers. Since readers and writers are
                 * already zero here, ldlm_lock_decref() won't see
                 * this flag and call l_blocking_ast */
                lock->l_flags |= LDLM_FL_CBPENDING | LDLM_FL_CANCELING;

                /* We can't re-add to l_lru as it confuses the
                 * refcounting in ldlm_lock_remove_from_lru() if an AST
                 * arrives after we drop ns_lock below. We use l_bl_ast
                 * and can't use l_pending_chain as it is used both on
                 * server and client nevertheless bug 5666 says it is
                 * used only on server */
                LASSERT(list_empty(&lock->l_bl_ast));
                list_add(&lock->l_bl_ast, cancels);
                unlock_res_and_lock(lock);
                spin_lock(&ns->ns_unused_lock);
                added++;
                unused--;
        }
        spin_unlock(&ns->ns_unused_lock);
        RETURN(ldlm_cancel_list(cancels, added, cancel_flags));
}

/* Returns number of locks which could be canceled next time when
 * ldlm_cancel_lru() is called. Used from locks pool shrinker. */
int ldlm_cancel_lru_estimate(struct ldlm_namespace *ns,
                             int count, int max, int flags)
{
        ldlm_cancel_lru_policy_t pf;
        struct ldlm_lock *lock;
        int added = 0, unused;
        ENTRY;

        pf = ldlm_cancel_lru_policy(ns, flags);
        LASSERT(pf != NULL);
        spin_lock(&ns->ns_unused_lock);
        unused = ns->ns_nr_unused;

        list_for_each_entry(lock, &ns->ns_unused_list, l_lru) {
                /* For any flags, stop scanning if @max is reached. */
                if (max && added >= max)
                        break;

                /* Somebody is already doing CANCEL or there is a
                 * blocking request will send cancel. Let's not count
                 * this lock. */
                if ((lock->l_flags & LDLM_FL_CANCELING) ||
                    (lock->l_flags & LDLM_FL_BL_AST))
                        continue;

                /* Pass the lock through the policy filter and see if it
                 * should stay in lru. */
                if (pf(ns, lock, unused, added, count) == LDLM_POLICY_KEEP_LOCK)
                        break;

                added++;
                unused--;
        }
        spin_unlock(&ns->ns_unused_lock);
        RETURN(added);
}

/* when called with LDLM_ASYNC the blocking callback will be handled
 * in a thread and this function will return after the thread has been
 * asked to call the callback.  when called with LDLM_SYNC the blocking
 * callback will be performed in this function. */
int ldlm_cancel_lru(struct ldlm_namespace *ns, int nr, ldlm_sync_t sync,
                    int flags)
{
        CFS_LIST_HEAD(cancels);
        int count, rc;
        ENTRY;

#ifndef __KERNEL__
        sync = LDLM_SYNC; /* force to be sync in user space */
#endif
        count = ldlm_cancel_lru_local(ns, &cancels, nr, 0, 0, flags);
        if (sync == LDLM_ASYNC) {
                rc = ldlm_bl_to_thread_list(ns, NULL, &cancels, count);
                if (rc == 0)
                        RETURN(count);
        }

        /* If an error occured in ASYNC mode, or
         * this is SYNC mode, cancel the list. */
        ldlm_cli_cancel_list(&cancels, count, NULL, 0);
        RETURN(count);
}

/* Find and cancel locally unused locks found on resource, matched to the
 * given policy, mode. GET the found locks and add them into the @cancels
 * list. */
int ldlm_cancel_resource_local(struct ldlm_resource *res,
                               struct list_head *cancels,
                               ldlm_policy_data_t *policy,
                               ldlm_mode_t mode, int lock_flags,
                               int cancel_flags, void *opaque)
{
        struct ldlm_lock *lock;
        int count = 0;
        ENTRY;

        lock_res(res);
        list_for_each_entry(lock, &res->lr_granted, l_res_link) {
                if (opaque != NULL && lock->l_ast_data != opaque) {
                        LDLM_ERROR(lock, "data %p doesn't match opaque %p",
                                   lock->l_ast_data, opaque);
                        //LBUG();
                        continue;
                }

                if (lock->l_readers || lock->l_writers) {
                        if (cancel_flags & LDLM_FL_WARN) {
                                LDLM_ERROR(lock, "lock in use");
                                //LBUG();
                        }
                        continue;
                }

                /* If somebody is already doing CANCEL, or blocking ast came,
                 * skip this lock. */
                if (lock->l_flags & LDLM_FL_BL_AST ||
                    lock->l_flags & LDLM_FL_CANCELING)
                        continue;

                if (lockmode_compat(lock->l_granted_mode, mode))
                        continue;

                /* If policy is given and this is IBITS lock, add to list only
                 * those locks that match by policy. */
                if (policy && (lock->l_resource->lr_type == LDLM_IBITS) &&
                    !(lock->l_policy_data.l_inodebits.bits &
                      policy->l_inodebits.bits))
                        continue;

                /* See CBPENDING comment in ldlm_cancel_lru */
                lock->l_flags |= LDLM_FL_CBPENDING | LDLM_FL_CANCELING |
                        lock_flags;

                LASSERT(list_empty(&lock->l_bl_ast));
                list_add(&lock->l_bl_ast, cancels);
                LDLM_LOCK_GET(lock);
                count++;
        }
        unlock_res(res);

        /* Handle only @count inserted locks. */
        RETURN(ldlm_cancel_list(cancels, count, cancel_flags));
}

/* If @req is NULL, send CANCEL request to server with handles of locks
 * in the @cancels. If EARLY_CANCEL is not supported, send CANCEL requests
 * separately per lock.
 * If @req is not NULL, put handles of locks in @cancels into the request
 * buffer at the offset @off.
 * Destroy @cancels at the end. */
int ldlm_cli_cancel_list(struct list_head *cancels, int count,
                         struct ptlrpc_request *req, int off)
{
        struct ldlm_lock *lock;
        int res = 0;
        ENTRY;

        if (list_empty(cancels) || count == 0)
                RETURN(0);

        while (count) {
                LASSERT(!list_empty(cancels));
                lock = list_entry(cancels->next, struct ldlm_lock, l_bl_ast);
                LASSERT(lock->l_conn_export);

                if (exp_connect_cancelset(lock->l_conn_export)) {
                        res = count;
                        if (req)
                                ldlm_cancel_pack(req, off, cancels, count);
                        else
                                res = ldlm_cli_cancel_req(lock->l_conn_export,
                                                          cancels, count);
                } else {
                        res = ldlm_cli_cancel_req(lock->l_conn_export,
                                                  cancels, 1);
                }

                if (res < 0) {
                        CERROR("ldlm_cli_cancel_list: %d\n", res);
                        res = count;
                }

                count -= res;
                ldlm_lock_list_put(cancels, l_bl_ast, res);
        }
        RETURN(0);
}

static int ldlm_cli_cancel_unused_resource(struct ldlm_namespace *ns,
                                           struct ldlm_res_id res_id,
                                           int flags, void *opaque)
{
        struct ldlm_resource *res;
        CFS_LIST_HEAD(cancels);
        int count;
        int rc;
        ENTRY;

        res = ldlm_resource_get(ns, NULL, res_id, 0, 0);
        if (res == NULL) {
                /* This is not a problem. */
                CDEBUG(D_INFO, "No resource "LPU64"\n", res_id.name[0]);
                RETURN(0);
        }

        count = ldlm_cancel_resource_local(res, &cancels, NULL, LCK_MINMODE,
                                           0, flags, opaque);
        rc = ldlm_cli_cancel_list(&cancels, count, NULL, 0);
        if (rc != ELDLM_OK)
                CERROR("ldlm_cli_cancel_unused_resource: %d\n", rc);

        ldlm_resource_putref(res);
        RETURN(0);
}

static inline int have_no_nsresource(struct ldlm_namespace *ns)
{
        int no_resource = 0;

        spin_lock(&ns->ns_hash_lock);
        if (ns->ns_resources == 0)
                no_resource = 1;
        spin_unlock(&ns->ns_hash_lock);

        RETURN(no_resource);
}

/* Cancel all locks on a namespace (or a specific resource, if given)
 * that have 0 readers/writers.
 *
 * If flags & LDLM_FL_LOCAL_ONLY, throw the locks away without trying
 * to notify the server. */
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

        spin_lock(&ns->ns_hash_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                struct list_head *tmp;
                tmp = ns->ns_hash[i].next;
                while (tmp != &(ns->ns_hash[i])) {
                        struct ldlm_resource *res;
                        int rc;

                        res = list_entry(tmp, struct ldlm_resource, lr_hash);
                        ldlm_resource_getref(res);
                        spin_unlock(&ns->ns_hash_lock);

                        rc = ldlm_cli_cancel_unused_resource(ns, res->lr_name,
                                                             flags, opaque);

                        if (rc)
                                CERROR("ldlm_cli_cancel_unused ("LPU64"): %d\n",
                                       res->lr_name.name[0], rc);

                        spin_lock(&ns->ns_hash_lock);
                        tmp = tmp->next;
                        ldlm_resource_putref_locked(res);
                }
        }
        spin_unlock(&ns->ns_hash_lock);

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

        LASSERT(ns_is_client(ns));

        res = ldlm_resource_get(ns, NULL, *res_id, LDLM_EXTENT, 0);
        if (res == NULL)
                RETURN(count);
        LASSERT(res->lr_type == LDLM_EXTENT);

        lock_res(res);
        if (!join)
                goto split;

        list_for_each_entry_safe (lock, n, &res->lr_granted, l_res_link) {
                if (list_empty(&lock->l_lru) &&
                    !lock->l_readers && !lock->l_writers &&
                    !(lock->l_flags & LDLM_FL_LOCAL) &&
                    !(lock->l_flags & LDLM_FL_CBPENDING) &&
                    !(lock->l_flags & LDLM_FL_BL_AST)) {
                        ldlm_lock_add_to_lru(lock);
                        lock->l_flags &= ~LDLM_FL_NO_LRU;
                        LDLM_DEBUG(lock, "join lock to lru");
                        count++;
                }
        }
        goto unlock;
split:
        spin_lock(&ns->ns_unused_lock);
        list_for_each_entry_safe (lock, n, &ns->ns_unused_list, l_lru) {
                if (lock->l_resource == res) {
                        ldlm_lock_remove_from_lru_nolock(lock);
                        lock->l_flags |= LDLM_FL_NO_LRU;
                        LDLM_DEBUG(lock, "split lock from lru");
                        count++;
                }
        }
        spin_unlock(&ns->ns_unused_lock);
unlock:
        unlock_res(res);
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

        ENTRY;

        if (!res)
                RETURN(LDLM_ITER_CONTINUE);

        lock_res(res);
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
        unlock_res(res);
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
        struct ldlm_resource *res;
        struct list_head *tmp;

        ENTRY;
        spin_lock(&ns->ns_hash_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                tmp = ns->ns_hash[i].next;
                while (tmp != &(ns->ns_hash[i])) {
                        res = list_entry(tmp, struct ldlm_resource, lr_hash);
                        ldlm_resource_getref(res);
                        spin_unlock(&ns->ns_hash_lock);

                        rc = iter(res, closure);

                        spin_lock(&ns->ns_hash_lock);
                        tmp = tmp->next;
                        ldlm_resource_putref_locked(res);
                        if (rc == LDLM_ITER_STOP)
                                GOTO(out, rc);
                }
        }
 out:
        spin_unlock(&ns->ns_hash_lock);
        RETURN(rc);
}

/* non-blocking function to manipulate a lock whose cb_data is being put away.*/
void ldlm_resource_iterate(struct ldlm_namespace *ns, struct ldlm_res_id *res_id,
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

        ldlm_resource_foreach(res, iter, data);
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
                                 struct ldlm_async_args *aa, int rc)
{
        struct lustre_handle  old_hash_key;
        struct ldlm_lock     *lock;
        struct ldlm_reply    *reply;
        struct obd_export    *exp;

        ENTRY;
        atomic_dec(&req->rq_import->imp_replay_inflight);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        reply = lustre_swab_repbuf(req, DLM_LOCKREPLY_OFF, sizeof(*reply),
                                   lustre_swab_ldlm_reply);
        if (reply == NULL) {
                CERROR("Can't unpack ldlm_reply\n");
                GOTO (out, rc = -EPROTO);
        }

        lock = ldlm_handle2lock(&aa->lock_handle);
        if (!lock) {
                CERROR("received replay ack for unknown local cookie "LPX64
                       " remote cookie "LPX64 " from server %s id %s\n",
                       aa->lock_handle.cookie, reply->lock_handle.cookie,
                       req->rq_export->exp_client_uuid.uuid,
                       libcfs_id2str(req->rq_peer));
                GOTO(out, rc = -ESTALE);
        }

        old_hash_key = lock->l_remote_handle;
        lock->l_remote_handle = reply->lock_handle;

        /* Key change rehash lock in per-export hash with new key */
	exp = req->rq_export;
        if (exp && exp->exp_lock_hash)
                lustre_hash_rehash_key(exp->exp_lock_hash, &old_hash_key,
				       &lock->l_remote_handle,
                                       &lock->l_exp_hash);

        LDLM_DEBUG(lock, "replayed lock:");
        ptlrpc_import_recovery_state_machine(req->rq_import);
        LDLM_LOCK_PUT(lock);
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
        struct ldlm_async_args *aa;
        int buffers = 2;
        __u32 size[3] = { sizeof(struct ptlrpc_body) };
        int flags;
        ENTRY;


        /* Bug 11974: Do not replay a lock which is actively being canceled */
        if (lock->l_flags & LDLM_FL_CANCELING) {
                LDLM_DEBUG(lock, "Not replaying canceled lock:");
                RETURN(0);
        }

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

        size[DLM_LOCKREQ_OFF] = sizeof(*body);
        req = ptlrpc_prep_req(imp, LUSTRE_DLM_VERSION, LDLM_ENQUEUE, 2, size,
                              NULL);
        if (!req)
                RETURN(-ENOMEM);

        /* We're part of recovery, so don't wait for it. */
        req->rq_send_state = LUSTRE_IMP_REPLAY_LOCKS;

        body = lustre_msg_buf(req->rq_reqmsg, DLM_LOCKREQ_OFF, sizeof(*body));
        ldlm_lock2desc(lock, &body->lock_desc);
        body->lock_flags = flags;

        ldlm_lock2handle(lock, &body->lock_handle[0]);
        size[DLM_LOCKREPLY_OFF] = sizeof(*reply);
        if (lock->l_lvb_len != 0) {
                buffers = 3;
                size[DLM_REPLY_REC_OFF] = lock->l_lvb_len;
        }
        ptlrpc_req_set_repsize(req, buffers, size);

        LDLM_DEBUG(lock, "replaying lock:");

        atomic_inc(&req->rq_import->imp_replay_inflight);
        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->lock_handle = body->lock_handle[0];
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

        (void)ldlm_namespace_foreach(ns, ldlm_chain_lock_for_replay, &list);

        list_for_each_entry_safe(lock, next, &list, l_pending_chain) {
                list_del_init(&lock->l_pending_chain);
                if (rc)
                        continue; /* or try to do the rest? */
                rc = replay_one_lock(imp, lock);
        }

        atomic_dec(&imp->imp_replay_inflight);

        RETURN(rc);
}
