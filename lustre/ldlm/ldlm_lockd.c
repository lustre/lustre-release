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

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/lustre_dlm.h>

extern kmem_cache_t *ldlm_resource_slab;
extern kmem_cache_t *ldlm_lock_slab;
extern int (*mds_reint_p)(int offset, struct ptlrpc_request *req);
extern int (*mds_getattr_name_p)(int offset, struct ptlrpc_request *req);

/* _ldlm_callback and local_callback setup the variables then call this common
 * code */
static int common_callback(struct ldlm_lock *lock, struct ldlm_lock *new,
                           ldlm_mode_t mode, void *data, __u32 data_len,
                           struct ptlrpc_request **reqp)
{
        ENTRY;

        if (!lock)
                LBUG();
        if (!lock->l_resource)
                LBUG();

        ldlm_lock_dump(lock);

        spin_lock(&lock->l_resource->lr_lock);
        spin_lock(&lock->l_lock);
        if (!new) {
                CDEBUG(D_INFO, "Got local completion AST for lock %p.\n", lock);
                lock->l_req_mode = mode;

                /* FIXME: the API is flawed if I have to do these refcount
                 * acrobatics (along with the _put() below). */
                lock->l_resource->lr_refcount++;

                /* _del_lock is safe for half-created locks that are not yet on
                 * a list. */
                ldlm_resource_del_lock(lock);
                ldlm_grant_lock(lock->l_resource, lock);

                ldlm_resource_put(lock->l_resource);

                wake_up(&lock->l_waitq);
                spin_unlock(&lock->l_lock);
                spin_unlock(&lock->l_resource->lr_lock);
        } else {
                CDEBUG(D_INFO, "Got local blocking AST for lock %p.\n", lock);
                lock->l_flags |= LDLM_FL_DYING;
                spin_unlock(&lock->l_lock);
                spin_unlock(&lock->l_resource->lr_lock);
                if (!lock->l_readers && !lock->l_writers) {
                        CDEBUG(D_INFO, "Lock already unused, calling "
                               "callback (%p).\n", lock->l_blocking_ast);
                        if (lock->l_blocking_ast != NULL)
                                lock->l_blocking_ast(lock, new, lock->l_data,
                                                     lock->l_data_len, reqp);
                } else {
                        CDEBUG(D_INFO, "Lock still has references; lock will be"
                               " cancelled later.\n");
                }
        }
        RETURN(0);
}

static int _ldlm_enqueue(struct obd_device *obddev, struct ptlrpc_service *svc,
                         struct ptlrpc_request *req)
{
        struct ldlm_reply *dlm_rep;
        struct ldlm_request *dlm_req;
        int rc, size = sizeof(*dlm_rep), cookielen = 0;
        __u32 flags;
        ldlm_error_t err;
        struct ldlm_lock *lock = NULL;
        ldlm_lock_callback callback;
        struct lustre_handle lockh;
        void *cookie = NULL;
        ENTRY;

        callback = ldlm_cli_callback;

        dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);
        if (dlm_req->lock_desc.l_resource.lr_type == LDLM_MDSINTENT) {
                /* In this case, the reply buffer is allocated deep in
                 * local_lock_enqueue by the policy function. */
                cookie = req;
                cookielen = sizeof(*req);
        } else {
                rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        CERROR("out of memory\n");
                        RETURN(-ENOMEM);
                }
                if (dlm_req->lock_desc.l_resource.lr_type == LDLM_EXTENT) {
                        cookie = &dlm_req->lock_desc.l_extent;
                        cookielen = sizeof(struct ldlm_extent);
                }
        }

        err = ldlm_local_lock_create(obddev->obd_namespace,
                                     &dlm_req->lock_handle2,
                                     dlm_req->lock_desc.l_resource.lr_name,
                                     dlm_req->lock_desc.l_resource.lr_type,
                                     dlm_req->lock_desc.l_req_mode,
                                     NULL, 0, &lockh);
        if (err != ELDLM_OK)
                GOTO(out, err);

        lock = lustre_handle2object(&lockh);
        memcpy(&lock->l_remote_handle, &dlm_req->lock_handle1,
               sizeof(lock->l_remote_handle));
        LDLM_DEBUG(lock, "server-side enqueue handler START");

        flags = dlm_req->lock_flags;
        err = ldlm_local_lock_enqueue(&lockh, cookie, cookielen, &flags,
                                      callback, callback);
        if (err != ELDLM_OK)
                GOTO(out, err);

        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0);
        dlm_rep->lock_flags = flags;

        memcpy(&dlm_rep->lock_handle, &lockh, sizeof(lockh));
        if (dlm_req->lock_desc.l_resource.lr_type == LDLM_EXTENT)
                memcpy(&dlm_rep->lock_extent, &lock->l_extent,
                       sizeof(lock->l_extent));
        if (dlm_rep->lock_flags & LDLM_FL_LOCK_CHANGED)
                memcpy(dlm_rep->lock_resource_name, lock->l_resource->lr_name,
                       sizeof(dlm_rep->lock_resource_name));

        lock->l_connection = ptlrpc_connection_addref(req->rq_connection);
        EXIT;
 out:
        req->rq_status = err;
        CDEBUG(D_INFO, "err = %d\n", err);

        if (ptlrpc_reply(svc, req))
                LBUG();

        if (!err)
                ldlm_reprocess_all(lock->l_resource);
        if (err)
                LDLM_DEBUG_NOLOCK("server-side enqueue handler END");
        else
                LDLM_DEBUG(lock, "server-side enqueue handler END");

        return 0;
}

static int _ldlm_convert(struct ptlrpc_service *svc, struct ptlrpc_request *req)
{
        struct ldlm_request *dlm_req;
        struct ldlm_reply *dlm_rep;
        struct ldlm_resource *res;
        struct ldlm_lock *lock;
        int rc, size = sizeof(*dlm_rep);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("out of memory\n");
                RETURN(-ENOMEM);
        }
        dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);
        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0);
        dlm_rep->lock_flags = dlm_req->lock_flags;

        lock = lustre_handle2object(&dlm_req->lock_handle1);
        LDLM_DEBUG(lock, "server-side convert handler START");

        res = ldlm_local_lock_convert(&dlm_req->lock_handle1,
                                      dlm_req->lock_desc.l_req_mode,
                                      &dlm_rep->lock_flags);
        req->rq_status = 0;
        if (ptlrpc_reply(svc, req) != 0)
                LBUG();

        ldlm_reprocess_all(res);
        LDLM_DEBUG(lock, "server-side convert handler END");

        RETURN(0);
}

static int _ldlm_cancel(struct ptlrpc_service *svc, struct ptlrpc_request *req)
{
        struct ldlm_request *dlm_req;
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        int rc;
        ENTRY;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("out of memory\n");
                RETURN(-ENOMEM);
        }
        dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);

        lock = lustre_handle2object(&dlm_req->lock_handle1);
        LDLM_DEBUG(lock, "server-side cancel handler START");
        res = ldlm_local_lock_cancel(lock);
        req->rq_status = 0;
        if (ptlrpc_reply(svc, req) != 0)
                LBUG();

        if (res != NULL)
                ldlm_reprocess_all(res);
        LDLM_DEBUG_NOLOCK("server-side cancel handler END");

        RETURN(0);
}

static int _ldlm_callback(struct ptlrpc_service *svc,
                          struct ptlrpc_request *req)
{
        struct ldlm_request *dlm_req;
        struct ldlm_lock *lock1, *lock2;
        int rc;
        ENTRY;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("out of memory\n");
                RETURN(-ENOMEM);
        }
        dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);

        /* We must send the reply first, so that the thread is free to handle
         * any requests made in common_callback() */
        rc = ptlrpc_reply(svc, req);
        if (rc != 0)
                RETURN(rc);

        lock1 = lustre_handle2object(&dlm_req->lock_handle1);
        lock2 = lustre_handle2object(&dlm_req->lock_handle2);

        LDLM_DEBUG(lock1, "client %s callback handler START",
                   lock2 == NULL ? "completion" : "blocked");

        common_callback(lock1, lock2, dlm_req->lock_desc.l_granted_mode, NULL,
                        0, NULL);

        LDLM_DEBUG_NOLOCK("client %s callback handler END (lock: %p)",
                   lock2 == NULL ? "completion" : "blocked", lock1);

        RETURN(0);
}

static int lustre_handle(struct obd_device *dev, struct ptlrpc_service *svc,
                       struct ptlrpc_request *req)
{
        struct obd_device *req_dev;
        int id, rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc) {
                CERROR("lustre_ldlm: Invalid request\n");
                GOTO(out, rc);
        }

        if (req->rq_reqmsg->type != PTL_RPC_MSG_REQUEST) {
                CERROR("lustre_ldlm: wrong packet type sent %d\n",
                       req->rq_reqmsg->type);
                GOTO(out, rc = -EINVAL);
        }

        id = req->rq_reqmsg->target_id;
        if (id < 0 || id > MAX_OBD_DEVICES)
                GOTO(out, rc = -ENODEV);
        req_dev = req->rq_obd = &obd_dev[id];

        switch (req->rq_reqmsg->opc) {
        case LDLM_ENQUEUE:
                CDEBUG(D_INODE, "enqueue\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_ENQUEUE, 0);
                rc = _ldlm_enqueue(req_dev, svc, req);
                break;

        case LDLM_CONVERT:
                CDEBUG(D_INODE, "convert\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CONVERT, 0);
                rc = _ldlm_convert(svc, req);
                break;

        case LDLM_CANCEL:
                CDEBUG(D_INODE, "cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CANCEL, 0);
                rc = _ldlm_cancel(svc, req);
                break;

        case LDLM_CALLBACK:
                CDEBUG(D_INODE, "callback\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CALLBACK, 0);
                rc = _ldlm_callback(svc, req);
                break;

        default:
                rc = ptlrpc_error(svc, req);
                RETURN(rc);
        }

        EXIT;
out:
        if (rc)
                RETURN(ptlrpc_error(svc, req));
        return 0;
}

static int ldlm_iocontrol(long cmd, struct obd_conn *conn, int len, void *karg,
                          void *uarg)
{
        struct obd_device *obddev = conn->oc_dev;
        struct ptlrpc_connection *connection;
        int err;
        ENTRY;

        if (_IOC_TYPE(cmd) != IOC_LDLM_TYPE || _IOC_NR(cmd) < IOC_LDLM_MIN_NR ||
            _IOC_NR(cmd) > IOC_LDLM_MAX_NR) {
                CDEBUG(D_IOCTL, "invalid ioctl (type %ld, nr %ld, size %ld)\n",
                       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
                RETURN(-EINVAL);
        }

        OBD_ALLOC(obddev->u.ldlm.ldlm_client,
                  sizeof(*obddev->u.ldlm.ldlm_client));
        ptlrpc_init_client(NULL, NULL,
                           LDLM_REQUEST_PORTAL, LDLM_REPLY_PORTAL,
                           obddev->u.ldlm.ldlm_client);
        connection = ptlrpc_uuid_to_connection("ldlm");
        if (!connection)
                CERROR("No LDLM UUID found: assuming ldlm is local.\n");

        switch (cmd) {
        case IOC_LDLM_TEST: {
                err = ldlm_test(obddev, connection);
                CERROR("-- done err %d\n", err);
                GOTO(out, err);
        }
        default:
                GOTO(out, err = -EINVAL);
        }

 out:
        if (connection)
                ptlrpc_put_connection(connection);
        OBD_FREE(obddev->u.ldlm.ldlm_client,
                 sizeof(*obddev->u.ldlm.ldlm_client));
        return err;
}

#define LDLM_NUM_THREADS        8

static int ldlm_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct ldlm_obd *ldlm = &obddev->u.ldlm;
        int rc;
        int i;
        ENTRY;

        MOD_INC_USE_COUNT;
        ldlm->ldlm_service =
                ptlrpc_init_svc(64 * 1024, LDLM_REQUEST_PORTAL,
                                LDLM_REPLY_PORTAL, "self", lustre_handle);
        if (!ldlm->ldlm_service) {
                LBUG();
                GOTO(out_dec, rc = -ENOMEM);
        }

        for (i = 0; i < LDLM_NUM_THREADS; i++) {
                rc = ptlrpc_start_thread(obddev, ldlm->ldlm_service,
                                         "lustre_dlm");
                /* XXX We could just continue if we had started at least
                 *     a few threads here.
                 */
                if (rc) {
                        CERROR("cannot start LDLM thread #%d: rc %d\n", i, rc);
                        LBUG();
                        GOTO(out_thread, rc);
                }
        }

        RETURN(0);

out_thread:
        ptlrpc_stop_all_threads(ldlm->ldlm_service);
        rpc_unregister_service(ldlm->ldlm_service);
        OBD_FREE(ldlm->ldlm_service, sizeof(*ldlm->ldlm_service));
out_dec:
        MOD_DEC_USE_COUNT;
        return rc;
}

static int ldlm_cleanup(struct obd_device *obddev)
{
        struct ldlm_obd *ldlm = &obddev->u.ldlm;
        ENTRY;

        ptlrpc_stop_all_threads(ldlm->ldlm_service);
        rpc_unregister_service(ldlm->ldlm_service);

        if (!list_empty(&ldlm->ldlm_service->srv_reqs)) {
                // XXX reply with errors and clean up
                CERROR("Request list not empty!\n");
        }

        OBD_FREE(ldlm->ldlm_service, sizeof(*ldlm->ldlm_service));

        if (mds_reint_p != NULL)
                inter_module_put("mds_reint");
        if (mds_getattr_name_p != NULL)
                inter_module_put("mds_getattr_name");

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

struct obd_ops ldlm_obd_ops = {
        o_iocontrol:   ldlm_iocontrol,
        o_setup:       ldlm_setup,
        o_cleanup:     ldlm_cleanup,
        o_connect:     gen_connect,
        o_disconnect:  gen_disconnect
};


static int __init ldlm_init(void)
{
        int rc = obd_register_type(&ldlm_obd_ops, OBD_LDLM_DEVICENAME);
        if (rc != 0)
                return rc;

        ldlm_resource_slab = kmem_cache_create("ldlm_resources",
                                               sizeof(struct ldlm_resource), 0,
                                               SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (ldlm_resource_slab == NULL)
                return -ENOMEM;

        ldlm_lock_slab = kmem_cache_create("ldlm_locks",
                                           sizeof(struct ldlm_lock), 0,
                                           SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (ldlm_lock_slab == NULL) {
                kmem_cache_destroy(ldlm_resource_slab);
                return -ENOMEM;
        }

        return 0;
}

static void __exit ldlm_exit(void)
{
        obd_unregister_type(OBD_LDLM_DEVICENAME);
        if (kmem_cache_destroy(ldlm_resource_slab) != 0)
                CERROR("couldn't free ldlm resource slab\n");
        if (kmem_cache_destroy(ldlm_lock_slab) != 0)
                CERROR("couldn't free ldlm lock slab\n");
}

EXPORT_SYMBOL(ldlm_local_lock_match);
EXPORT_SYMBOL(ldlm_lock_addref);
EXPORT_SYMBOL(ldlm_lock_decref);
EXPORT_SYMBOL(ldlm_cli_convert);
EXPORT_SYMBOL(ldlm_cli_enqueue);
EXPORT_SYMBOL(ldlm_cli_cancel);
EXPORT_SYMBOL(lustre_handle2object);
EXPORT_SYMBOL(ldlm_test);
EXPORT_SYMBOL(ldlm_lock_dump);
EXPORT_SYMBOL(ldlm_namespace_new);
EXPORT_SYMBOL(ldlm_namespace_free);

MODULE_AUTHOR("Cluster File Systems, Inc. <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lock Management Module v0.1");
MODULE_LICENSE("GPL");

module_init(ldlm_init);
module_exit(ldlm_exit);
