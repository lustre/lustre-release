/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
#include <signal.h>
#include <liblustre.h>
#endif

#include <linux/lustre_dlm.h>
#include <linux/obd_class.h>
#include <linux/obd.h>

static int interrupted_completion_wait(void *data)
{
        RETURN(1);
}

int ldlm_expired_completion_wait(void *data)
{
        struct ldlm_lock *lock = data;
        struct ptlrpc_connection *conn;
        struct obd_device *obd;

        if (!lock)
                CERROR("NULL lock\n");
        else if (!lock->l_connh)
                CERROR("lock %p has NULL connh\n", lock);
        else if (!(obd = class_conn2obd(lock->l_connh)))
                CERROR("lock %p has NULL obd\n", lock);
        else if (!(conn = obd->u.cli.cl_import.imp_connection))
                CERROR("lock %p has NULL connection\n", lock);
        else {
                LDLM_DEBUG(lock, "timed out waiting for completion");
                CERROR("lock %p timed out from %s\n", lock,
                       conn->c_remote_uuid.uuid);
                ldlm_lock_dump(D_ERROR, lock);
                class_signal_connection_failure(conn);
        }
        RETURN(0);
}

int ldlm_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        struct l_wait_info lwi =
                LWI_TIMEOUT_INTR(obd_timeout * HZ, ldlm_expired_completion_wait,
                                 interrupted_completion_wait, lock);
        int rc = 0;
        ENTRY;

        if (flags == LDLM_FL_WAIT_NOREPROC)
                goto noreproc;

        if (flags == 0) {
                wake_up(&lock->l_waitq);
                RETURN(0);
        }

        if (!(flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                       LDLM_FL_BLOCK_CONV)))
                RETURN(0);

        LDLM_DEBUG(lock, "client-side enqueue returned a blocked lock, "
                   "sleeping");
        ldlm_lock_dump(D_OTHER, lock);
        ldlm_reprocess_all(lock->l_resource);

 noreproc:
        /* Go to sleep until the lock is granted or cancelled. */
        rc = l_wait_event(lock->l_waitq,
                          ((lock->l_req_mode == lock->l_granted_mode) ||
                           lock->l_destroyed), &lwi);

        if (lock->l_destroyed) {
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

static int ldlm_cli_enqueue_local(struct ldlm_namespace *ns,
                                  struct lustre_handle *parent_lockh,
                                  struct ldlm_res_id res_id,
                                  __u32 type,
                                  void *cookie, int cookielen,
                                  ldlm_mode_t mode,
                                  int *flags,
                                  ldlm_completion_callback completion,
                                  ldlm_blocking_callback blocking,
                                  void *data,
                                  void *cp_data,
                                  struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        int err;
        ENTRY;

        if (ns->ns_client) {
                CERROR("Trying to enqueue local lock in a shadow namespace\n");
                LBUG();
        }

        lock = ldlm_lock_create(ns, parent_lockh, res_id, type, mode,
                                data, cp_data);
        if (!lock)
                GOTO(out_nolock, err = -ENOMEM);
        LDLM_DEBUG(lock, "client-side local enqueue handler, new lock created");

        ldlm_lock_addref_internal(lock, mode);
        ldlm_lock2handle(lock, lockh);
        lock->l_flags |= LDLM_FL_LOCAL;

        err = ldlm_lock_enqueue(ns, &lock, cookie, cookielen, flags, completion,
                                blocking);
        if (err != ELDLM_OK)
                GOTO(out, err);

        if (type == LDLM_EXTENT)
                memcpy(cookie, &lock->l_extent, sizeof(lock->l_extent));
        if ((*flags) & LDLM_FL_LOCK_CHANGED)
                memcpy(&res_id, &lock->l_resource->lr_name, sizeof(res_id));

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

int ldlm_cli_enqueue(struct lustre_handle *connh,
                     struct ptlrpc_request *req,
                     struct ldlm_namespace *ns,
                     struct lustre_handle *parent_lock_handle,
                     struct ldlm_res_id res_id,
                     __u32 type,
                     void *cookie, int cookielen,
                     ldlm_mode_t mode,
                     int *flags,
                     ldlm_completion_callback completion,
                     ldlm_blocking_callback blocking,
                     void *data,
                     void *cp_data,
                     struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        int rc, size = sizeof(*body), req_passed_in = 1, is_replay;
        ENTRY;

        is_replay = *flags & LDLM_FL_REPLAY;
        LASSERT(connh != NULL || !is_replay);

        if (connh == NULL) {
                rc = ldlm_cli_enqueue_local(ns, parent_lock_handle, res_id,
                                            type, cookie, cookielen, mode,
                                            flags, completion, blocking, data,
                                            cp_data, lockh);
                RETURN(rc);
        }

        /* If we're replaying this lock, just check some invariants.
         * If we're creating a new lock, get everything all setup nice. */
        if (is_replay) {
                lock = ldlm_handle2lock(lockh);
                LDLM_DEBUG(lock, "client-side enqueue START");
                LASSERT(connh == lock->l_connh);
        } else {
                lock = ldlm_lock_create(ns, parent_lock_handle, res_id, type,
                                        mode, data, cp_data);
                if (lock == NULL)
                        GOTO(out_nolock, rc = -ENOMEM);
                /* ugh.  I set this early (instead of waiting for _enqueue)
                 * because the completion AST might arrive early, and we need
                 * (in just this one case) to run the completion_cb even if it
                 * arrives before the reply. */
                lock->l_completion_ast = completion;
                LDLM_DEBUG(lock, "client-side enqueue START");
                /* for the local lock, add the reference */
                ldlm_lock_addref_internal(lock, mode);
                ldlm_lock2handle(lock, lockh);
                if (type == LDLM_EXTENT)
                        memcpy(&lock->l_extent, cookie,
                               sizeof(body->lock_desc.l_extent));
        }

        if (req == NULL) {
                req = ptlrpc_prep_req(class_conn2cliimp(connh), LDLM_ENQUEUE, 1,
                                      &size, NULL);
                if (!req)
                        GOTO(out, rc = -ENOMEM);
                req_passed_in = 0;
        } else if (req->rq_reqmsg->buflens[0] != sizeof(*body))
                LBUG();

        /* Dump lock data into the request buffer */
        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ldlm_lock2desc(lock, &body->lock_desc);
        body->lock_flags = *flags;

        memcpy(&body->lock_handle1, lockh, sizeof(*lockh));
        if (parent_lock_handle)
                memcpy(&body->lock_handle2, parent_lock_handle,
                       sizeof(body->lock_handle2));

        /* Continue as normal. */
        if (!req_passed_in) {
                size = sizeof(*reply);
                req->rq_replen = lustre_msg_size(1, &size);
        }
        lock->l_connh = connh;
        lock->l_export = NULL;

        LDLM_DEBUG(lock, "sending request");
        rc = ptlrpc_queue_wait(req);

        if (rc != ELDLM_OK) {
                LASSERT(!is_replay);
                LDLM_DEBUG(lock, "client-side enqueue END (%s)",
                           rc == ELDLM_LOCK_ABORTED ? "ABORTED" : "FAILED");
                /* Set a flag to prevent us from sending a CANCEL (bug 407) */
                l_lock(&ns->ns_lock);
                lock->l_flags |= LDLM_FL_CANCELING;
                l_unlock(&ns->ns_lock);

                ldlm_lock_decref_and_cancel(lockh, mode);
                GOTO(out_req, rc);
        }

        reply = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&lock->l_remote_handle, &reply->lock_handle,
               sizeof(lock->l_remote_handle));
        *flags = reply->lock_flags;

        CDEBUG(D_INFO, "local: %p, remote: %p, flags: %d\n", lock,
               (void *)(unsigned long)reply->lock_handle.addr, *flags);
        if (type == LDLM_EXTENT) {
                CDEBUG(D_INFO, "requested extent: "LPU64" -> "LPU64", got "
                       "extent "LPU64" -> "LPU64"\n",
                       body->lock_desc.l_extent.start,
                       body->lock_desc.l_extent.end,
                       reply->lock_extent.start, reply->lock_extent.end);
                cookie = &reply->lock_extent; /* FIXME bug 267 */
                cookielen = sizeof(reply->lock_extent);
        }

        /* If enqueue returned a blocked lock but the completion handler has
         * already run, then it fixed up the resource and we don't need to do it
         * again. */
        if ((*flags) & LDLM_FL_LOCK_CHANGED) {
                int newmode = reply->lock_mode;
                LASSERT(!is_replay);
                if (newmode && newmode != lock->l_req_mode) {
                        LDLM_DEBUG(lock, "server returned different mode %s",
                                   ldlm_lockname[newmode]);
                        lock->l_req_mode = newmode;
                }

                if (reply->lock_resource_name.name[0] !=
                    lock->l_resource->lr_name.name[0]) {
                        CDEBUG(D_INFO, "remote intent success, locking %ld "
                               "instead of %ld\n",
                               (long)reply->lock_resource_name.name[0],
                               (long)lock->l_resource->lr_name.name[0]);

                        ldlm_lock_change_resource(ns, lock,
                                                  reply->lock_resource_name);
                        if (lock->l_resource == NULL) {
                                LBUG();
                                GOTO(out_req, rc = -ENOMEM);
                        }
                        LDLM_DEBUG(lock, "client-side enqueue, new resource");
                }
        }

        if (!is_replay) {
                l_lock(&ns->ns_lock);
                lock->l_completion_ast = NULL;
                rc = ldlm_lock_enqueue(ns, &lock, cookie, cookielen, flags,
                                       completion, blocking);
                l_unlock(&ns->ns_lock);
                if (lock->l_completion_ast)
                        lock->l_completion_ast(lock, *flags, NULL);
        }

        LDLM_DEBUG(lock, "client-side enqueue END");
        EXIT;
 out_req:
        if (!req_passed_in)
                ptlrpc_req_finished(req);
 out:
        LDLM_LOCK_PUT(lock);
 out_nolock:
        return rc;
}

int ldlm_match_or_enqueue(struct lustre_handle *connh,
                          struct ptlrpc_request *req,
                          struct ldlm_namespace *ns,
                          struct lustre_handle *parent_lock_handle,
                          struct ldlm_res_id res_id,
                          __u32 type,
                          void *cookie, int cookielen,
                          ldlm_mode_t mode,
                          int *flags,
                          ldlm_completion_callback completion,
                          ldlm_blocking_callback blocking,
                          void *data,
                          void *cp_data,
                          struct lustre_handle *lockh)
{
        int rc;
        ENTRY;
        if (connh == NULL) {
                /* Just to make sure that I understand things --phil */
                LASSERT(*flags & LDLM_FL_LOCAL_ONLY);
        }

        LDLM_DEBUG_NOLOCK("resource "LPU64"/"LPU64, res_id.name[0],
                          res_id.name[1]);
        rc = ldlm_lock_match(ns, *flags, &res_id, type, cookie, cookielen, mode,
                             lockh);
        if (rc == 0) {
                rc = ldlm_cli_enqueue(connh, req, ns, parent_lock_handle,
                                      res_id, type, cookie, cookielen, mode,
                                      flags, completion, blocking, data,
                                      cp_data, lockh);
                if (rc != ELDLM_OK)
                        CERROR("ldlm_cli_enqueue: err: %d\n", rc);
                RETURN(rc);
        }
        RETURN(0);
}

int ldlm_cli_replay_enqueue(struct ldlm_lock *lock)
{
        struct lustre_handle lockh;
        struct ldlm_res_id junk;
        int flags = LDLM_FL_REPLAY;
        ldlm_lock2handle(lock, &lockh);
        return ldlm_cli_enqueue(lock->l_connh, NULL, NULL, NULL, junk,
                                lock->l_resource->lr_type, NULL, 0, -1, &flags,
                                NULL, NULL, NULL, 0, &lockh);
}

static int ldlm_cli_convert_local(struct ldlm_lock *lock, int new_mode,
                                  int *flags)
{
        ENTRY;
        if (lock->l_resource->lr_namespace->ns_client) {
                CERROR("Trying to cancel local lock\n");
                LBUG();
        }
        LDLM_DEBUG(lock, "client-side local convert");

        ldlm_lock_convert(lock, new_mode, flags);
        ldlm_reprocess_all(lock->l_resource);

        LDLM_DEBUG(lock, "client-side local convert handler END");
        LDLM_LOCK_PUT(lock);
        RETURN(0);
}

/* FIXME: one of ldlm_cli_convert or the server side should reject attempted
 * conversion of locks which are on the waiting or converting queue */
int ldlm_cli_convert(struct lustre_handle *lockh, int new_mode, int *flags)
{
        struct ldlm_request *body;
        struct lustre_handle *connh;
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
        connh = lock->l_connh;

        if (!connh)
                RETURN(ldlm_cli_convert_local(lock, new_mode, flags));

        LDLM_DEBUG(lock, "client-side convert");

        req = ptlrpc_prep_req(class_conn2cliimp(connh), LDLM_CONVERT, 1, &size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));

        body->lock_desc.l_req_mode = new_mode;
        body->lock_flags = *flags;

        size = sizeof(*reply);
        req->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(req);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        reply = lustre_msg_buf(req->rq_repmsg, 0);
        res = ldlm_lock_convert(lock, new_mode, &reply->lock_flags);
        if (res != NULL)
                ldlm_reprocess_all(res);
        /* Go to sleep until the lock is granted. */
        /* FIXME: or cancelled. */
        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, LDLM_FL_WAIT_NOREPROC, NULL);
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

        if (lock->l_connh) {
                int local_only;

                LDLM_DEBUG(lock, "client-side cancel");
                /* Set this flag to prevent others from getting new references*/
                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                lock->l_flags |= LDLM_FL_CBPENDING;
                ldlm_cancel_callback(lock);
                local_only = (lock->l_flags & LDLM_FL_LOCAL_ONLY);
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);

                if (local_only) {
                        CDEBUG(D_INFO, "not sending request (at caller's "
                               "instruction\n");
                        goto local_cancel;
                }

                req = ptlrpc_prep_req(class_conn2cliimp(lock->l_connh),
                                      LDLM_CANCEL, 1, &size, NULL);
                if (!req)
                        GOTO(out, rc = -ENOMEM);

                /* XXX FIXME bug 249 */
                req->rq_request_portal = LDLM_CANCEL_REQUEST_PORTAL;
                req->rq_reply_portal = LDLM_CANCEL_REPLY_PORTAL;

                body = lustre_msg_buf(req->rq_reqmsg, 0);
                memcpy(&body->lock_handle1, &lock->l_remote_handle,
                       sizeof(body->lock_handle1));

                req->rq_replen = lustre_msg_size(0, NULL);

                rc = ptlrpc_queue_wait(req);
                ptlrpc_req_finished(req);
                if (rc == ESTALE) {
                        CERROR("client/server out of sync\n");
                        LBUG();
                }
                if (rc != ELDLM_OK)
                        CERROR("Got rc %d from cancel RPC: canceling "
                               "anyway\n", rc);
        local_cancel:
                ldlm_lock_cancel(lock);
        } else {
                LDLM_DEBUG(lock, "client-side local cancel");
                if (lock->l_resource->lr_namespace->ns_client) {
                        CERROR("Trying to cancel local lock\n");
                        LBUG();
                }
                ldlm_lock_cancel(lock);
                ldlm_reprocess_all(lock->l_resource);
                LDLM_DEBUG(lock, "client-side local cancel handler END");
        }

        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
        return rc;
}

int ldlm_cancel_lru(struct ldlm_namespace *ns)
{
        struct list_head *tmp, *next, list = LIST_HEAD_INIT(list);
        int count, rc = 0;
        struct ldlm_ast_work *w;
        ENTRY;

        l_lock(&ns->ns_lock);
        count = ns->ns_nr_unused - ns->ns_max_unused;

        if (count <= 0) {
                l_unlock(&ns->ns_lock);
                RETURN(0);
        }

        list_for_each_safe(tmp, next, &ns->ns_unused_list) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_lru);

                LASSERT(!lock->l_readers && !lock->l_writers);

                /* Setting the CBPENDING flag is a little misleading, but
                 * prevents an important race; namely, once CBPENDING is set,
                 * the lock can accumulate no more readers/writers.  Since
                 * readers and writers are already zero here, ldlm_lock_decref
                 * won't see this flag and call l_blocking_ast */
                lock->l_flags |= LDLM_FL_CBPENDING;

                OBD_ALLOC(w, sizeof(*w));
                LASSERT(w);

                w->w_lock = LDLM_LOCK_GET(lock);
                list_add(&w->w_list, &list);
                ldlm_lock_remove_from_lru(lock);

                if (--count == 0)
                        break;
        }
        l_unlock(&ns->ns_lock);

        list_for_each_safe(tmp, next, &list) {
                struct lustre_handle lockh;
                int rc;
                w = list_entry(tmp, struct ldlm_ast_work, w_list);

                ldlm_lock2handle(w->w_lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc != ELDLM_OK)
                        CDEBUG(D_INFO, "ldlm_cli_cancel: %d\n", rc);

                list_del(&w->w_list);
                LDLM_LOCK_PUT(w->w_lock);
                OBD_FREE(w, sizeof(*w));
        }

        RETURN(rc);
}

int ldlm_cli_cancel_unused_resource(struct ldlm_namespace *ns,
                                    struct ldlm_res_id res_id, int flags)
{
        struct ldlm_resource *res;
        struct list_head *tmp, *next, list = LIST_HEAD_INIT(list);
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

                if (lock->l_readers || lock->l_writers)
                        continue;

                /* See CBPENDING comment in ldlm_cancel_lru */
                lock->l_flags |= LDLM_FL_CBPENDING;

                OBD_ALLOC(w, sizeof(*w));
                LASSERT(w);

                w->w_lock = LDLM_LOCK_GET(lock);

                /* Prevent the cancel callback from being called by setting
                 * LDLM_FL_CANCEL in the lock.  Very sneaky. -p */
                if (flags & LDLM_FL_NO_CALLBACK)
                        w->w_lock->l_flags |= LDLM_FL_CANCEL;

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
 * If flags & LDLM_FL_NO_CALLBACK, don't run the cancel callback. */
int ldlm_cli_cancel_unused(struct ldlm_namespace *ns,
                           struct ldlm_res_id *res_id, int flags)
{
        int i;
        ENTRY;

        if (ns == NULL)
                RETURN(ELDLM_OK);

        if (res_id)
                RETURN(ldlm_cli_cancel_unused_resource(ns, *res_id, flags));

        l_lock(&ns->ns_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                struct list_head *tmp, *pos;
                list_for_each_safe(tmp, pos, &(ns->ns_hash[i])) {
                        int rc;
                        struct ldlm_resource *res;
                        res = list_entry(tmp, struct ldlm_resource, lr_hash);
                        ldlm_resource_getref(res);

                        rc = ldlm_cli_cancel_unused_resource(ns, res->lr_name,
                                                             flags);

                        if (rc)
                                CERROR("cancel_unused_res ("LPU64"): %d\n",
                                       res->lr_name.name[0], rc);
                        ldlm_resource_putref(res);
                }
        }
        l_unlock(&ns->ns_lock);

        RETURN(ELDLM_OK);
}

/* Lock iterators. */

int ldlm_resource_foreach(struct ldlm_resource *res, ldlm_iterator_t iter,
                          void *closure)
{
        struct list_head *tmp, *next;
        struct ldlm_lock *lock;
        int rc = LDLM_ITER_CONTINUE;
        struct ldlm_namespace *ns = res->lr_namespace;

        ENTRY;

        if (!res)
                RETURN(LDLM_ITER_CONTINUE);

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

/* Lock replay */

static int ldlm_chain_lock_for_replay(struct ldlm_lock *lock, void *closure)
{
        struct list_head *list = closure;

        /* we use l_pending_chain here, because it's unused on clients. */
        list_add(&lock->l_pending_chain, list);
        return LDLM_ITER_CONTINUE;
}

static int replay_one_lock(struct obd_import *imp, struct ldlm_lock *lock)
{
        struct ptlrpc_request *req;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        int rc, size;
        int flags;

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
                
        size = sizeof(*body);
        req = ptlrpc_prep_req(imp, LDLM_ENQUEUE, 1, &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        /* We're part of recovery, so don't wait for it. */
        req->rq_level = LUSTRE_CONN_RECOVD;
        
        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ldlm_lock2desc(lock, &body->lock_desc);
        body->lock_flags = flags;

        ldlm_lock2handle(lock, &body->lock_handle1);
        size = sizeof(*reply);
        req->rq_replen = lustre_msg_size(1, &size);

        LDLM_DEBUG(lock, "replaying lock:");
        rc = ptlrpc_queue_wait(req);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        reply = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&lock->l_remote_handle, &reply->lock_handle,
               sizeof(lock->l_remote_handle));
        LDLM_DEBUG(lock, "replayed lock:");
 out:
        ptlrpc_req_finished(req);
        RETURN(rc);
}

int ldlm_replay_locks(struct obd_import *imp)
{
        struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
        struct list_head list, *pos, *next;
        struct ldlm_lock *lock;
        int rc = 0;
        
        ENTRY;
        INIT_LIST_HEAD(&list);

        l_lock(&ns->ns_lock);
        (void)ldlm_namespace_foreach(ns, ldlm_chain_lock_for_replay, &list);

        list_for_each_safe(pos, next, &list) {
                lock = list_entry(pos, struct ldlm_lock, l_pending_chain);
                rc = replay_one_lock(imp, lock);
                if (rc)
                        break; /* or try to do the rest? */
        }
        l_unlock(&ns->ns_lock);
        RETURN(rc);
}
