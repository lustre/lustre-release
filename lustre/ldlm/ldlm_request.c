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

int ldlm_cli_enqueue(struct ptlrpc_client *cl, struct ptlrpc_connection *conn, struct lustre_handle *connh, 
                     struct ptlrpc_request *req,
                     struct ldlm_namespace *ns,
                     struct lustre_handle *parent_lock_handle,
                     __u64 *res_id,
                     __u32 type,
                     void *cookie, int cookielen,
                     ldlm_mode_t mode,
                     int *flags,
                     ldlm_lock_callback callback,
                     void *data,
                     __u32 data_len,
                     struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        int rc, size = sizeof(*body), req_passed_in = 1;
        ENTRY;

        *flags = 0;
        lock = ldlm_lock_create(ns, parent_lock_handle, res_id, type, mode,
                                data, data_len);
        if (lock == NULL)
                GOTO(out, rc = -ENOMEM);
        /* for the local lock, add the reference */
        ldlm_lock_addref_internal(lock, mode);
        ldlm_lock2handle(lock, lockh);

        LDLM_DEBUG(lock, "client-side enqueue START");

        if (req == NULL) {
                req = ptlrpc_prep_req2(cl, conn, connh, 
                                       LDLM_ENQUEUE, 1, &size, NULL);
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

        ldlm_lock2handle(lock, &body->lock_handle1);
        if (parent_lock_handle)
                memcpy(&body->lock_handle2, parent_lock_handle,
                       sizeof(body->lock_handle2));

        /* Continue as normal. */
        if (!req_passed_in) {
                size = sizeof(*reply);
                req->rq_replen = lustre_msg_size(1, &size);
        }

        lock->l_connection = conn;
        lock->l_client = cl;

        rc = ptlrpc_queue_wait(req);
        /* FIXME: status check here? */
        rc = ptlrpc_check_status(req, rc);

        if (rc != ELDLM_OK) {
                LDLM_DEBUG(lock, "client-side enqueue END (%s)",
                           rc == ELDLM_LOCK_ABORTED ? "ABORTED" : "FAILED");
                ldlm_lock_put(lock);
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
        if (*flags & LDLM_FL_LOCK_CHANGED &&
            lock->l_req_mode != lock->l_granted_mode) {
                CDEBUG(D_INFO, "remote intent success, locking %ld instead of"
                       "%ld\n", (long)reply->lock_resource_name[0],
                       (long)lock->l_resource->lr_name[0]);

                ldlm_lock_change_resource(lock, reply->lock_resource_name);
                if (lock->l_resource == NULL) {
                        LBUG();
                        RETURN(-ENOMEM);
                }
                LDLM_DEBUG(lock, "client-side enqueue, new resource");
        }

        if (!req_passed_in)
                ptlrpc_free_req(req);

        rc = ldlm_lock_enqueue(lock, cookie, cookielen, flags, callback,
                                     callback);

        LDLM_DEBUG(lock, "client-side enqueue END");
        if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                      LDLM_FL_BLOCK_CONV)) {
                /* Go to sleep until the lock is granted. */
                /* FIXME: or cancelled. */
                CDEBUG(D_NET, "enqueue returned a blocked lock (%p), "
                       "going to sleep.\n", lock);
                ldlm_lock_dump(lock);
                wait_event_interruptible(lock->l_waitq, lock->l_req_mode ==
                                         lock->l_granted_mode);
                CDEBUG(D_NET, "waking up, the lock must be granted.\n");
        }
        ldlm_lock_put(lock);
        EXIT;
 out:
        return rc;
}

int ldlm_server_ast(struct lustre_handle *lockh, struct ldlm_lock_desc *desc,
                    void *data, __u32 data_len)
{
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        struct ptlrpc_client *cl;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        lock = ldlm_handle2lock(lockh);
        if (lock == NULL)
                LBUG();
        cl = &lock->l_resource->lr_namespace->ns_rpc_client;
        req = ptlrpc_prep_req(cl, lock->l_connection, LDLM_CALLBACK, 1,
                              &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));

        if (desc == NULL) {
                CDEBUG(D_NET, "Sending granted AST\n");
                ldlm_lock2desc(lock, &body->lock_desc);
        } else {
                CDEBUG(D_NET, "Sending blocked AST\n");
                memcpy(&body->lock_desc, desc, sizeof(*desc));
        }

        LDLM_DEBUG(lock, "server preparing %s AST",
                   desc == 0 ? "completion" : "blocked");

        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        ptlrpc_free_req(req);

        EXIT;
 out:
        ldlm_lock_put(lock);
        return rc;
}

int ldlm_cli_convert(struct ptlrpc_client *cl, struct lustre_handle *lockh,
                     struct lustre_handle *connh, 
                     int new_mode, int *flags)
{
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        struct ptlrpc_request *req;
        int rc, size = sizeof(*body);
        ENTRY;

        lock = ldlm_handle2lock(lockh);
        if (!lock)
                LBUG(); 
        *flags = 0;

        LDLM_DEBUG(lock, "client-side convert");

        req = ptlrpc_prep_req(cl, lock->l_connection,
                               LDLM_CONVERT, 1, &size, NULL);
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
        if (lock->l_req_mode != lock->l_granted_mode) {
                /* Go to sleep until the lock is granted. */
                /* FIXME: or cancelled. */
                CDEBUG(D_NET, "convert returned a blocked lock, "
                       "going to sleep.\n");
                wait_event_interruptible(lock->l_waitq, lock->l_req_mode ==
                                         lock->l_granted_mode);
                CDEBUG(D_NET, "waking up, the lock must be granted.\n");
        }
        ldlm_lock_put(lock);
        EXIT;
 out:
        ptlrpc_free_req(req);
        return rc;
}

int ldlm_cli_cancel(struct lustre_handle *lockh, 
                    struct lustre_handle *connh)
{
        struct ptlrpc_request *req;
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        int rc, size = sizeof(*body);
        ENTRY;

        lock = ldlm_handle2lock(lockh); 
        if (!lock)
                LBUG();

        LDLM_DEBUG(lock, "client-side cancel");
        req = ptlrpc_prep_req(lock->l_client, lock->l_connection,
                              LDLM_CANCEL, 1, &size, NULL);
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
        ldlm_lock_put(lock); 
        EXIT;
 out:
        return 0;
}
