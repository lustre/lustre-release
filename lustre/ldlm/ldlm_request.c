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

int ldlm_cli_enqueue(struct ptlrpc_client *cl, struct lustre_peer *peer,
                     __u32 ns_id,
                     struct ldlm_handle *parent_lock_handle,
                     __u64 *res_id,
                     __u32 type,
                     struct ldlm_extent *req_ex,
                     ldlm_mode_t mode,
                     int *flags,
                     void *data,
                     __u32 data_len,
                     struct ldlm_handle *lockh,
                     struct ptlrpc_request **request)
{
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        struct ptlrpc_request *req;
        char *bufs[2] = {NULL, data};
        int rc, size[2] = {sizeof(*body), data_len};

#if 0
        ldlm_local_lock_enqueue(obddev, ns_id, parent_lock_handle, res_id, type,
                                req_ex, mode, flags);
#endif                           

        /* FIXME: if this is a local lock, stop here. */

        req = ptlrpc_prep_req(cl, peer, LDLM_ENQUEUE, 2, size, bufs);
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

        /* FIXME: lock_handle1 will be the shadow handle */

        if (parent_lock_handle)
                memcpy(&body->lock_handle2, parent_lock_handle,
                       sizeof(body->lock_handle2));

        /* Continue as normal. */
        size[0] = sizeof(*reply);
        req->rq_replen = lustre_msg_size(1, size);

        rc = ptlrpc_queue_wait(cl, req);
        rc = ptlrpc_check_status(req, rc);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        reply = lustre_msg_buf(req->rq_repmsg, 0);
        CERROR("remote handle: %p\n",
               (void *)(unsigned long)reply->lock_handle.addr);
        CERROR("extent: %Lu -> %Lu\n", reply->lock_extent.start,
               reply->lock_extent.end);

        EXIT;
 out:
        *request = req;
        return rc;
}

int ldlm_cli_namespace_new(struct ptlrpc_client *cl, struct lustre_peer *peer,
                           __u32 ns_id, struct ptlrpc_request **request)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        int rc, size = sizeof(*body);

        req = ptlrpc_prep_req(cl, peer, LDLM_NAMESPACE_NEW, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        body->lock_desc.l_resource.lr_ns_id = ns_id;

        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(cl, req);
        rc = ptlrpc_check_status(req, rc);

        EXIT;
 out:
        *request = req;
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

        req = ptlrpc_prep_req(cl, &lock->l_peer, LDLM_CALLBACK, 2, size, bufs);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));

        if (new != NULL)
                ldlm_lock2desc(new, &body->lock_desc);

        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(cl, req);
        rc = ptlrpc_check_status(req, rc);
        ptlrpc_free_req(req);

        EXIT;
 out:
        return rc;
}
