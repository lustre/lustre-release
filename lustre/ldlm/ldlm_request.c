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

int ldlm_cli_enqueue(struct ptlrpc_client *cl, struct ptlrpc_connection *conn,
                     struct ldlm_namespace *ns,
                     struct ldlm_handle *parent_lock_handle,
                     __u64 *res_id,
                     __u32 type,
                     struct ldlm_extent *req_ex,
                     ldlm_mode_t mode,
                     int *flags,
                     void *data,
                     __u32 data_len,
                     struct ldlm_handle *lockh)
{
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        struct ptlrpc_request *req;
        char *bufs[2] = {NULL, data};
        int rc, size[2] = {sizeof(*body), data_len};
        ENTRY;

        *flags = 0;
        rc = ldlm_local_lock_create(ns, parent_lock_handle, res_id, type, mode,
                                    NULL, 0, lockh);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        lock = ldlm_handle2object(lockh);

        req = ptlrpc_prep_req(cl, conn, LDLM_ENQUEUE, 2, size, bufs);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        /* Dump all of this data into the request buffer */
        body = lustre_msg_buf(req->rq_reqmsg, 0);
        body->lock_desc.l_resource.lr_type = type;
        memcpy(body->lock_desc.l_resource.lr_name, res_id,
               sizeof(body->lock_desc.l_resource.lr_name));

        body->lock_desc.l_req_mode = mode;
        if (req_ex)
                memcpy(&body->lock_desc.l_extent, req_ex,
                       sizeof(body->lock_desc.l_extent));
        body->flags = *flags;

        memcpy(&body->lock_handle1, lockh, sizeof(body->lock_handle1));

        if (parent_lock_handle)
                memcpy(&body->lock_handle2, parent_lock_handle,
                       sizeof(body->lock_handle2));

        /* Continue as normal. */
        size[0] = sizeof(*reply);
        req->rq_replen = lustre_msg_size(1, size);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        if (rc != ELDLM_OK) {
                spin_lock(&lock->l_resource->lr_lock);
                ldlm_resource_put(lock->l_resource);
                spin_unlock(&lock->l_resource->lr_lock);
                ldlm_lock_free(lock);
                GOTO(out, rc);
        }

        lock->l_connection = conn;
        lock->l_client = cl;
        reply = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&lock->l_remote_handle, &reply->lock_handle,
               sizeof(lock->l_remote_handle));
        memcpy(req_ex, &reply->lock_extent, sizeof(*req_ex));
        *flags = reply->flags;

        CDEBUG(D_INFO, "remote handle: %p, flags: %d\n",
               (void *)(unsigned long)reply->lock_handle.addr, *flags);
        CDEBUG(D_INFO, "extent: %Lu -> %Lu\n",
               (unsigned long long)reply->lock_extent.start,
               (unsigned long long)reply->lock_extent.end);

        ptlrpc_free_req(req);

        rc = ldlm_local_lock_enqueue(lockh, req_ex, flags, NULL, NULL);

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
        EXIT;
 out:
        return rc;
}

int ldlm_cli_callback(struct ldlm_lock *lock, struct ldlm_lock *new,
                      void *data, __u32 data_len)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        struct obd_device *obddev = lock->l_resource->lr_namespace->ns_obddev;
        struct ptlrpc_client *cl = obddev->u.ldlm.ldlm_client;
        int rc, size[2] = {sizeof(*body), data_len};
        char *bufs[2] = {NULL, data};
        ENTRY;

        req = ptlrpc_prep_req(cl, lock->l_connection, LDLM_CALLBACK, 2, size,
                              bufs);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));

        if (new == NULL) {
                CDEBUG(D_NET, "Sending granted AST\n");
                ldlm_lock2desc(lock, &body->lock_desc);
        } else {
                CDEBUG(D_NET, "Sending blocked AST\n");
                ldlm_lock2desc(new, &body->lock_desc);
                ldlm_object2handle(new, &body->lock_handle2);
        }

        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        ptlrpc_free_req(req);

        EXIT;
 out:
        return rc;
}

int ldlm_cli_convert(struct ptlrpc_client *cl, struct ldlm_handle *lockh,
                     int new_mode, int *flags)
{
        struct ldlm_request *body;
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        struct ptlrpc_request *req;
        int rc, size[2] = {sizeof(*body), 0};
        char *bufs[2] = {NULL, NULL};
        ENTRY;

        lock = ldlm_handle2object(lockh);
        *flags = 0;

        size[1] = lock->l_data_len;
        bufs[1] = lock->l_data;
        req = ptlrpc_prep_req(cl, lock->l_connection, LDLM_CONVERT, 2, size,
                              bufs);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));

        body->lock_desc.l_req_mode = new_mode;
        body->flags = *flags;

        req->rq_replen = lustre_msg_size(1, size);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        body = lustre_msg_buf(req->rq_repmsg, 0);
        res = ldlm_local_lock_convert(lockh, new_mode, &body->flags);
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
        EXIT;
 out:
        ptlrpc_free_req(req);
        return rc;
}

int ldlm_cli_cancel(struct ptlrpc_client *cl, struct ldlm_lock *lock)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        struct ldlm_resource *res;
        int rc, size[2] = {sizeof(*body), 0};
        char *bufs[2] = {NULL, NULL};
        ENTRY;

        if (lock->l_data_len == sizeof(struct inode)) {
                /* FIXME: do something better than throwing away everything */
                struct inode *inode = lock->l_data;
                if (inode == NULL)
                        LBUG();
                down(&inode->i_sem);
                invalidate_inode_pages(inode);
                up(&inode->i_sem);
        }

        size[1] = lock->l_data_len;
        bufs[1] = lock->l_data;
        req = ptlrpc_prep_req(cl, lock->l_connection, LDLM_CANCEL, 2, size,
                              bufs);
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

        res = ldlm_local_lock_cancel(lock);
        if (res != NULL)
                ldlm_reprocess_all(res);
        EXIT;
 out:
        return rc;
}
