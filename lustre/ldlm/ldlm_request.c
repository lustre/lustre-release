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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/lustre_dlm.h>

#define LOOPBACK(x) (((x) & cpu_to_be32(0xff000000)) == cpu_to_be32(0x7f000000))

static int is_local_conn(struct ptlrpc_connection *conn)
{
        ENTRY;
        if (conn == NULL)
                RETURN(1);

        RETURN(LOOPBACK(conn->c_peer.peer_nid));
}

int ldlm_cli_enqueue(struct ptlrpc_client *cl, struct ptlrpc_connection *conn,
                     __u32 ns_id,
                     struct ldlm_handle *parent_lock_handle,
                     __u64 *res_id,
                     __u32 type,
                     struct ldlm_extent *req_ex,
                     ldlm_mode_t mode,
                     int *flags,
                     ldlm_lock_callback completion,
                     ldlm_lock_callback blocking,
                     void *data,
                     __u32 data_len,
                     struct ldlm_handle *lockh,
                     struct ptlrpc_request **request)
{
        struct ldlm_handle local_lockh;
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        struct ptlrpc_request *req = NULL;
        char *bufs[2] = {NULL, data};
        int rc, size[2] = {sizeof(*body), data_len};
        ldlm_error_t err;
        ENTRY;

        err = ldlm_local_lock_create(ns_id, parent_lock_handle, res_id,
                                     type, &local_lockh);
        if (err != ELDLM_OK)
                RETURN(err);

        lock = ldlm_handle2object(&local_lockh);
        /* Is this lock locally managed? */
        if (is_local_conn(conn))
                GOTO(local, 0);

        req = ptlrpc_prep_req(cl, conn, LDLM_ENQUEUE, 2, size, bufs);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        /* Dump all of this data into the request buffer */
        body = lustre_msg_buf(req->rq_reqmsg, 0);
        body->lock_desc.l_resource.lr_ns_id = ns_id;
        body->lock_desc.l_resource.lr_type = type;
        memcpy(body->lock_desc.l_resource.lr_name, res_id,
               sizeof(body->lock_desc.l_resource.lr_name));

        body->lock_desc.l_req_mode = mode;
        if (req_ex)
                memcpy(&body->lock_desc.l_extent, req_ex,
                       sizeof(body->lock_desc.l_extent));
        body->flags = *flags;

        memcpy(&body->lock_handle1, &local_lockh, sizeof(body->lock_handle1));

        if (parent_lock_handle)
                memcpy(&body->lock_handle2, parent_lock_handle,
                       sizeof(body->lock_handle2));

        /* Continue as normal. */
        size[0] = sizeof(*reply);
        req->rq_replen = lustre_msg_size(1, size);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        if (rc != ELDLM_OK) {
                ldlm_resource_put(lock->l_resource);
                ldlm_lock_free(lock);
                GOTO(out, rc);
        }

        lock->l_connection = conn;
        reply = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&lock->l_remote_handle, &reply->lock_handle,
               sizeof(lock->l_remote_handle));
        *flags = reply->flags;

        CERROR("remote handle: %p, flags: %d\n",
               (void *)(unsigned long)reply->lock_handle.addr, *flags);
        CERROR("extent: %Lu -> %Lu\n",
               (unsigned long long)reply->lock_extent.start,
               (unsigned long long)reply->lock_extent.end);

        EXIT;
 local:
        rc = ldlm_local_lock_enqueue(&local_lockh, mode, req_ex, flags,
                                     completion, blocking, data, data_len);
        if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                     LDLM_FL_BLOCK_CONV)) {
                /* Go to sleep until the lock is granted. */
                /* FIXME: or cancelled. */
                wait_event_interruptible(lock->l_waitq, lock->l_req_mode ==
                                         lock->l_granted_mode);
        }
 out:
        *request = req;
        return rc;
}

int ldlm_cli_namespace_new(struct obd_device *obddev, struct ptlrpc_client *cl,
                           struct ptlrpc_connection *conn, __u32 ns_id)
{
        struct ldlm_namespace *ns;
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        int rc, size = sizeof(*body);
        ENTRY;

        if (is_local_conn(conn))
                GOTO(local, 0);

        req = ptlrpc_prep_req(cl, conn, LDLM_NAMESPACE_NEW, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        body->lock_desc.l_resource.lr_ns_id = ns_id;

        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        ptlrpc_free_req(req);
        if (rc)
                GOTO(out, rc);

        EXIT;
 local:
        rc = ldlm_namespace_new(obddev, ns_id, &ns);
        if (rc != ELDLM_OK) {
                /* XXX: It succeeded remotely but failed locally. What to do? */
                CERROR("Local ldlm_namespace_new failed.\n");
        }
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

        if (new != NULL) {
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
                     int new_mode, int *flags, struct ptlrpc_request **request)
{
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        struct ldlm_lock *lock;
        struct ptlrpc_request *req = NULL;
        int rc, size[2] = {sizeof(*body), 0};
        char *bufs[2] = {NULL, NULL};
        ENTRY;

        lock = ldlm_handle2object(lockh);

        if (is_local_conn(lock->l_connection))
                GOTO(local, 0);

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

        reply = lustre_msg_buf(req->rq_repmsg, 0);
        *flags = reply->flags;

        EXIT;
 local:
        rc = ldlm_local_lock_convert(lockh, new_mode, flags);
 out:
        *request = req;
        return rc;
}

int ldlm_cli_cancel(struct ptlrpc_client *cl, struct ldlm_handle *lockh,
                    struct ptlrpc_request **request)
{
        struct ldlm_request *body;
        struct ldlm_lock *lock;
        struct ptlrpc_request *req = NULL;
        int rc, size[2] = {sizeof(*body), 0};
        char *bufs[2] = {NULL, NULL};
        ENTRY;

        lock = ldlm_handle2object(lockh);

        if (is_local_conn(lock->l_connection))
                GOTO(local, 0);

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
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        EXIT;
 local:
        rc = ldlm_local_lock_cancel(lockh);
 out:
        *request = req;
        return rc;
}
