/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Cluster File Systems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/lustre_dlm.h>

int ldlm_completion_ast(struct ldlm_lock *lock, int flags)
{
        ENTRY;

        if (flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                      LDLM_FL_BLOCK_CONV)) {
                /* Go to sleep until the lock is granted. */
                /* FIXME: or cancelled. */
                LDLM_DEBUG(lock, "client-side enqueue returned a blocked lock,"
                           " sleeping");
                ldlm_lock_dump(lock);
                ldlm_reprocess_all(lock->l_resource);
                wait_event(lock->l_waitq, (lock->l_req_mode ==
                                           lock->l_granted_mode));
                LDLM_DEBUG(lock, "client-side enqueue waking up: granted");
        } else if (flags == LDLM_FL_WAIT_NOREPROC) {
                wait_event(lock->l_waitq, (lock->l_req_mode ==
                                           lock->l_granted_mode));
        } else if (flags == 0) {
                wake_up(&lock->l_waitq);
        }

        RETURN(0);
}

static int ldlm_cli_enqueue_local(struct ldlm_namespace *ns,
                                  struct lustre_handle *parent_lockh,
                                  __u64 *res_id,
                                  __u32 type,
                                  void *cookie, int cookielen,
                                  ldlm_mode_t mode,
                                  int *flags,
                                  ldlm_completion_callback completion,
                                  ldlm_blocking_callback blocking,
                                  void *data,
                                  __u32 data_len,
                                  struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        int err;

        if (ns->ns_client) {
                CERROR("Trying to cancel local lock\n");
                LBUG();
        }

        lock = ldlm_lock_create(ns, parent_lockh, res_id, type, mode, NULL, 0);
        if (!lock)
                GOTO(out_nolock, err = -ENOMEM);
        LDLM_DEBUG(lock, "client-side local enqueue handler, new lock created");

        ldlm_lock_addref_internal(lock, mode);
        ldlm_lock2handle(lock, lockh);
        lock->l_connh = NULL;

        err = ldlm_lock_enqueue(lock, cookie, cookielen, flags, completion,
                                blocking);
        if (err != ELDLM_OK)
                GOTO(out, err);

        if (type == LDLM_EXTENT)
                memcpy(cookie, &lock->l_extent, sizeof(lock->l_extent));
        if ((*flags) & LDLM_FL_LOCK_CHANGED)
                memcpy(res_id, lock->l_resource->lr_name, sizeof(*res_id));

        LDLM_DEBUG_NOLOCK("client-side local enqueue handler END (lock %p)",
                          lock);

        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, *flags);

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
                     __u64 *res_id,
                     __u32 type,
                     void *cookie, int cookielen,
                     ldlm_mode_t mode,
                     int *flags,
                     ldlm_completion_callback completion,
                     ldlm_blocking_callback blocking,
                     void *data,
                     __u32 data_len,
                     struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        int rc, size = sizeof(*body), req_passed_in = 1;
        ENTRY;

        if (connh == NULL)
                return ldlm_cli_enqueue_local(ns, parent_lock_handle, res_id,
                                              type, cookie, cookielen, mode,
                                              flags, completion, blocking, data,
                                              data_len, lockh);

        *flags = 0;
        lock = ldlm_lock_create(ns, parent_lock_handle, res_id, type, mode,
                                data, data_len);
        if (lock == NULL)
                GOTO(out_nolock, rc = -ENOMEM);
        LDLM_DEBUG(lock, "client-side enqueue START");
        /* for the local lock, add the reference */
        ldlm_lock_addref_internal(lock, mode);
        ldlm_lock2handle(lock, lockh);

        if (req == NULL) {
                req = ptlrpc_prep_req2(connh, LDLM_ENQUEUE, 1, &size, NULL);
                if (!req)
                        GOTO(out, rc = -ENOMEM);
                req_passed_in = 0;
        } else if (req->rq_reqmsg->buflens[0] != sizeof(*body))
                LBUG();

        /* Dump all of this data into the request buffer */
        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ldlm_lock2desc(lock, &body->lock_desc);
        /* Phil: make this part of ldlm_lock2desc */
        if (type == LDLM_EXTENT)
                memcpy(&body->lock_desc.l_extent, cookie,
                       sizeof(body->lock_desc.l_extent));
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
        lock->l_client = client_conn2cli(connh)->cl_client;

        rc = ptlrpc_queue_wait(req);
        /* FIXME: status check here? */
        rc = ptlrpc_check_status(req, rc);

        if (rc != ELDLM_OK) {
                LDLM_DEBUG(lock, "client-side enqueue END (%s)",
                           rc == ELDLM_LOCK_ABORTED ? "ABORTED" : "FAILED");
                ldlm_lock_decref(lockh, mode);
                /* FIXME: if we've already received a completion AST, this will
                 * LBUG! */
                ldlm_lock_destroy(lock);
                GOTO(out, rc);
        }

        reply = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&lock->l_remote_handle, &reply->lock_handle,
               sizeof(lock->l_remote_handle));
        if (type == LDLM_EXTENT)
                memcpy(cookie, &reply->lock_extent, sizeof(reply->lock_extent));
        *flags = reply->lock_flags;

        CDEBUG(D_INFO, "remote handle: %p, flags: %d\n",
               (void *)(unsigned long)reply->lock_handle.addr, *flags);
        CDEBUG(D_INFO, "extent: %Lu -> %Lu\n",
               (unsigned long long)reply->lock_extent.start,
               (unsigned long long)reply->lock_extent.end);

        /* If enqueue returned a blocked lock but the completion handler has
         * already run, then it fixed up the resource and we don't need to do it
         * again. */
        if ((*flags) & LDLM_FL_LOCK_CHANGED) {
                int newmode = reply->lock_mode;
                if (newmode && newmode != lock->l_req_mode) {
                        LDLM_DEBUG(lock, "server returned different mode %s",
                                   ldlm_lockname[newmode]);
                        lock->l_req_mode = newmode;
                }

                if (reply->lock_resource_name[0] !=
                    lock->l_resource->lr_name[0]) {
                        CDEBUG(D_INFO, "remote intent success, locking %ld "
                               "instead of %ld\n",
                               (long)reply->lock_resource_name[0],
                               (long)lock->l_resource->lr_name[0]);

                        ldlm_lock_change_resource(lock,
                                                  reply->lock_resource_name);
                        if (lock->l_resource == NULL) {
                                LBUG();
                                RETURN(-ENOMEM);
                        }
                        LDLM_DEBUG(lock, "client-side enqueue, new resource");
                }
        }

        if (!req_passed_in)
                ptlrpc_free_req(req);

        rc = ldlm_lock_enqueue(lock, cookie, cookielen, flags, completion,
                               blocking);
        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, *flags);

        LDLM_DEBUG(lock, "client-side enqueue END");
        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
 out_nolock:
        return rc;
}

int ldlm_match_or_enqueue(struct lustre_handle *connh,
                          struct ptlrpc_request *req,
                          struct ldlm_namespace *ns,
                          struct lustre_handle *parent_lock_handle,
                          __u64 *res_id,
                          __u32 type,
                          void *cookie, int cookielen,
                          ldlm_mode_t mode,
                          int *flags,
                          ldlm_completion_callback completion,
                          ldlm_blocking_callback blocking,
                          void *data,
                          __u32 data_len,
                          struct lustre_handle *lockh)
{
        int rc;
        ENTRY;
        rc = ldlm_lock_match(ns, res_id, type, cookie, cookielen, mode, lockh);
        if (rc == 0) {
                rc = ldlm_cli_enqueue(connh, req, ns,
                                      parent_lock_handle, res_id, type, cookie,
                                      cookielen, mode, flags, completion,
                                      blocking, data, data_len, lockh);
                if (rc != ELDLM_OK)
                        CERROR("ldlm_cli_enqueue: err: %d\n", rc);
                RETURN(rc);
        } else
                RETURN(0);
}

static int ldlm_cli_convert_local(struct ldlm_lock *lock, int new_mode,
                                  int *flags)
{

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
                return ldlm_cli_convert_local(lock, new_mode, flags);

        LDLM_DEBUG(lock, "client-side convert");

        req = ptlrpc_prep_req2(connh, LDLM_CONVERT, 1, &size, NULL);
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
        rc = ptlrpc_check_status(req, rc);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        reply = lustre_msg_buf(req->rq_repmsg, 0);
        res = ldlm_lock_convert(lock, new_mode, &reply->lock_flags);
        if (res != NULL)
                ldlm_reprocess_all(res);
        /* Go to sleep until the lock is granted. */
        /* FIXME: or cancelled. */
        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, LDLM_FL_WAIT_NOREPROC);
        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
        ptlrpc_free_req(req);
        return rc;
}

int ldlm_cli_cancel(struct lustre_handle *lockh)
{
        struct ptlrpc_request *req;
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        lock = ldlm_handle2lock(lockh);
        if (!lock) {
                /* It's possible that the decref that we did just before this
                 * cancel was the last reader/writer, and caused a cancel before
                 * we could call this function.  If we want to make this
                 * impossible (by adding a dec_and_cancel() or similar), then
                 * we can put the LBUG back. */
                //LBUG();
                RETURN(-EINVAL);
        }

        if (lock->l_connh) {
                LDLM_DEBUG(lock, "client-side cancel");
                /* Set this flag to prevent others from getting new references*/
                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                lock->l_flags |= LDLM_FL_CBPENDING;
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);

                req = ptlrpc_prep_req2(lock->l_connh, LDLM_CANCEL, 1, &size,
                                       NULL);
                if (!req)
                        GOTO(out, rc = -ENOMEM);

                body = lustre_msg_buf(req->rq_reqmsg, 0);
                memcpy(&body->lock_handle1, &lock->l_remote_handle,
                       sizeof(body->lock_handle1));

                req->rq_replen = lustre_msg_size(0, NULL);

                rc = ptlrpc_queue_wait(req);
                rc = ptlrpc_check_status(req, rc);
                ptlrpc_free_req(req);
                if (rc != ELDLM_OK)
                        GOTO(out, rc);

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

/* Cancel all locks on a given resource that have 0 readers/writers */
int ldlm_cli_cancel_unused(struct ldlm_namespace *ns, __u64 *res_id)
{
        struct ldlm_resource *res;
        struct list_head *tmp, *next, list = LIST_HEAD_INIT(list);
        struct ldlm_ast_work *w;
        ENTRY;

        res = ldlm_resource_get(ns, NULL, res_id, 0, 0);
        if (res == NULL)
                RETURN(-EINVAL);

        l_lock(&ns->ns_lock);
        list_for_each(tmp, &res->lr_granted) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lock->l_readers || lock->l_writers)
                        continue;

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
        }
        l_unlock(&ns->ns_lock);

        list_for_each_safe(tmp, next, &list) {
                struct lustre_handle lockh;
                int rc;
                w = list_entry(tmp, struct ldlm_ast_work, w_list);

                ldlm_lock2handle(w->w_lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc != ELDLM_OK)
                        CERROR("ldlm_cli_cancel: %d\n", rc);

                LDLM_LOCK_PUT(w->w_lock);
                list_del(&w->w_list);
                OBD_FREE(w, sizeof(*w));
        }

        RETURN(0);
}
