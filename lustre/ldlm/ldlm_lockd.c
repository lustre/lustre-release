/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>

extern kmem_cache_t *ldlm_resource_slab;
extern kmem_cache_t *ldlm_lock_slab;
extern struct list_head ldlm_namespace_list;
extern int (*mds_reint_p)(int offset, struct ptlrpc_request *req);
extern int (*mds_getattr_name_p)(int offset, struct ptlrpc_request *req);

static int ldlm_server_blocking_ast(struct ldlm_lock *lock,
                                    struct ldlm_lock_desc *desc,
                                    void *data, __u32 data_len)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        struct ptlrpc_client *cl;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        cl = &lock->l_resource->lr_namespace->ns_rpc_client;
        req = ptlrpc_prep_req(cl, lock->l_connection, LDLM_BL_CALLBACK, 1,
                              &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));
        memcpy(&body->lock_desc, desc, sizeof(*desc));

        LDLM_DEBUG(lock, "server preparing blocking AST");
        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        ptlrpc_free_req(req);

        RETURN(rc);
}

static int ldlm_server_completion_ast(struct ldlm_lock *lock, int flags)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        struct ptlrpc_client *cl;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        if (lock == NULL) {
                LBUG();
                RETURN(-EINVAL);
        }

        cl = &lock->l_resource->lr_namespace->ns_rpc_client;
        req = ptlrpc_prep_req(cl, lock->l_connection, LDLM_CP_CALLBACK, 1,
                              &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));
        body->lock_flags = flags;
        ldlm_lock2desc(lock, &body->lock_desc);

        LDLM_DEBUG(lock, "server preparing completion AST");
        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        ptlrpc_free_req(req);
        RETURN(rc);
}

int ldlm_handle_enqueue(struct ptlrpc_request *req)
{
        struct obd_device *obddev = req->rq_export->exp_obd;
        struct ldlm_reply *dlm_rep;
        struct ldlm_request *dlm_req;
        int rc, size = sizeof(*dlm_rep), cookielen = 0;
        __u32 flags;
        ldlm_error_t err;
        struct ldlm_lock *lock = NULL;
        void *cookie = NULL;
        ENTRY;

        LDLM_DEBUG_NOLOCK("server-side enqueue handler START");

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

        lock = ldlm_lock_create(obddev->obd_namespace,
                                &dlm_req->lock_handle2,
                                dlm_req->lock_desc.l_resource.lr_name,
                                dlm_req->lock_desc.l_resource.lr_type,
                                dlm_req->lock_desc.l_req_mode, NULL, 0);
        if (!lock)
                GOTO(out, err = -ENOMEM);

        memcpy(&lock->l_remote_handle, &dlm_req->lock_handle1,
               sizeof(lock->l_remote_handle));
        LDLM_DEBUG(lock, "server-side enqueue handler, new lock created");

        flags = dlm_req->lock_flags;
        err = ldlm_lock_enqueue(lock, cookie, cookielen, &flags,
                                ldlm_server_completion_ast,
                                ldlm_server_blocking_ast);
        if (err != ELDLM_OK)
                GOTO(out, err);

        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0);
        dlm_rep->lock_flags = flags;

        ldlm_lock2handle(lock, &dlm_rep->lock_handle);
        if (dlm_req->lock_desc.l_resource.lr_type == LDLM_EXTENT)
                memcpy(&dlm_rep->lock_extent, &lock->l_extent,
                       sizeof(lock->l_extent));
        if (dlm_rep->lock_flags & LDLM_FL_LOCK_CHANGED) {
                memcpy(dlm_rep->lock_resource_name, lock->l_resource->lr_name,
                       sizeof(dlm_rep->lock_resource_name));
                dlm_rep->lock_mode = lock->l_req_mode;
        }

        lock->l_connection = ptlrpc_connection_addref(req->rq_connection);
        EXIT;
 out:
        if (lock)
                LDLM_DEBUG(lock, "server-side enqueue handler, sending reply"
                           "(err=%d)", err);
        req->rq_status = err;

        if (ptlrpc_reply(req->rq_svc, req))
                LBUG();

        if (lock) {
                if (!err)
                        ldlm_reprocess_all(lock->l_resource);
                LDLM_LOCK_PUT(lock);
        }
        LDLM_DEBUG_NOLOCK("server-side enqueue handler END (lock %p)", lock);

        return 0;
}

int ldlm_handle_convert(struct ptlrpc_request *req)
{
        struct ldlm_request *dlm_req;
        struct ldlm_reply *dlm_rep;
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

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                req->rq_status = EINVAL;
        } else {
                LDLM_DEBUG(lock, "server-side convert handler START");
                ldlm_lock_convert(lock, dlm_req->lock_desc.l_req_mode,
                                  &dlm_rep->lock_flags);
                req->rq_status = 0;
        }
        if (ptlrpc_reply(req->rq_svc, req) != 0)
                LBUG();

        if (lock) {
                ldlm_reprocess_all(lock->l_resource);
                LDLM_DEBUG(lock, "server-side convert handler END");
                LDLM_LOCK_PUT(lock);
        } else
                LDLM_DEBUG_NOLOCK("server-side convert handler END");

        RETURN(0);
}

int ldlm_handle_cancel(struct ptlrpc_request *req)
{
        struct ldlm_request *dlm_req;
        struct ldlm_lock *lock;
        int rc;
        ENTRY;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("out of memory\n");
                RETURN(-ENOMEM);
        }
        dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                LDLM_DEBUG_NOLOCK("server-side cancel handler stale lock (lock "
                                  "%p)", (void *)(unsigned long)
                                  dlm_req->lock_handle1.addr);
                req->rq_status = ESTALE;
        } else {
                LDLM_DEBUG(lock, "server-side cancel handler START");
                ldlm_lock_cancel(lock);
                req->rq_status = 0;
        }

        if (ptlrpc_reply(req->rq_svc, req) != 0)
                LBUG();

        if (lock) {
                ldlm_reprocess_all(lock->l_resource);
                LDLM_DEBUG(lock, "server-side cancel handler END");
                LDLM_LOCK_PUT(lock);
        } 

        RETURN(0);
}

static int ldlm_handle_bl_callback(struct ptlrpc_request *req)
{
        struct ldlm_request *dlm_req;
        struct ldlm_lock *lock;
        int rc, do_ast;
        ENTRY;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(-ENOMEM);
        rc = ptlrpc_reply(req->rq_svc, req);
        if (rc)
                RETURN(rc);

        dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                CERROR("blocking callback on lock %Lx - lock disappeared\n",
                       dlm_req->lock_handle1.addr);
                RETURN(0);
        }

        LDLM_DEBUG(lock, "client blocking AST callback handler START");

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        lock->l_flags |= LDLM_FL_CBPENDING;
        do_ast = (!lock->l_readers && !lock->l_writers);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        if (do_ast) {
                LDLM_DEBUG(lock, "already unused, calling "
                           "callback (%p)", lock->l_blocking_ast);
                if (lock->l_blocking_ast != NULL) {
                        lock->l_blocking_ast(lock, &dlm_req->lock_desc,
                                             lock->l_data, lock->l_data_len);
                }
        } else
                LDLM_DEBUG(lock, "Lock still has references, will be"
                           " cancelled later");

        LDLM_DEBUG(lock, "client blocking callback handler END");
        LDLM_LOCK_PUT(lock);
        RETURN(0);
}

static int ldlm_handle_cp_callback(struct ptlrpc_request *req)
{
        struct list_head ast_list = LIST_HEAD_INIT(ast_list);
        struct ldlm_request *dlm_req;
        struct ldlm_lock *lock;
        int rc;
        ENTRY;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(-ENOMEM);
        rc = ptlrpc_reply(req->rq_svc, req);
        if (rc)
                RETURN(rc);

        dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                CERROR("completion callback on lock %Lx - lock disappeared\n",
                       dlm_req->lock_handle1.addr);
                RETURN(0);
        }

        LDLM_DEBUG(lock, "client completion callback handler START");

        l_lock(&lock->l_resource->lr_namespace->ns_lock);

        /* If we receive the completion AST before the actual enqueue returned,
         * then we might need to switch resources or lock modes. */
        if (dlm_req->lock_desc.l_granted_mode != lock->l_req_mode) {
                lock->l_req_mode = dlm_req->lock_desc.l_granted_mode;
                LDLM_DEBUG(lock, "completion AST, new lock mode");
        }
        ldlm_resource_unlink_lock(lock);
        if (memcmp(dlm_req->lock_desc.l_resource.lr_name,
                   lock->l_resource->lr_name,
                   sizeof(__u64) * RES_NAME_SIZE) != 0) {
                ldlm_lock_change_resource(lock, dlm_req->lock_desc.l_resource.lr_name);
                LDLM_DEBUG(lock, "completion AST, new resource");
        }
        lock->l_resource->lr_tmp = &ast_list;
        ldlm_grant_lock(lock);
        lock->l_resource->lr_tmp = NULL;
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        LDLM_DEBUG(lock, "callback handler finished, about to run_ast_work");
        LDLM_LOCK_PUT(lock);

        ldlm_run_ast_work(&ast_list);

        LDLM_DEBUG_NOLOCK("client completion callback handler END (lock %p)",
                          lock);
        RETURN(0);
}

static int ldlm_callback_handler(struct ptlrpc_request *req)
{
        int rc;
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
        switch (req->rq_reqmsg->opc) {
        case LDLM_BL_CALLBACK:
                CDEBUG(D_INODE, "blocking ast\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                rc = ldlm_handle_bl_callback(req);
                break;
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "completion ast\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CP_CALLBACK, 0);
                rc = ldlm_handle_cp_callback(req);
                break;

        default:
                rc = ptlrpc_error(req->rq_svc, req);
                RETURN(rc);
        }

        EXIT;
out:
        if (rc)
                RETURN(ptlrpc_error(req->rq_svc, req));
        return 0;
}


static int ldlm_iocontrol(long cmd, struct lustre_handle *conn, int len,
                          void *karg, void *uarg)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct ptlrpc_connection *connection;
        int err = 0;
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
        case IOC_LDLM_TEST:
                err = ldlm_test(obddev, conn);
                CERROR("-- done err %d\n", err);
                GOTO(out, err);
        case IOC_LDLM_DUMP:
                ldlm_dump_all_namespaces();
                GOTO(out, err);
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
        int rc, i;
        ENTRY;

        MOD_INC_USE_COUNT;
        rc = ldlm_proc_setup(obddev);
        if (rc != 0)
                GOTO(out_dec, rc);

        ldlm->ldlm_service = ptlrpc_init_svc(64 * 1024, LDLM_REQUEST_PORTAL,
                                             LDLM_REPLY_PORTAL, "self",
                                             ldlm_callback_handler);
        if (!ldlm->ldlm_service)
                GOTO(out_proc, rc = -ENOMEM);

        for (i = 0; i < LDLM_NUM_THREADS; i++) {
                char name[32];
                sprintf(name, "lustre_dlm_%02d", i);
                rc = ptlrpc_start_thread(obddev, ldlm->ldlm_service, name);
                if (rc) {
                        CERROR("cannot start LDLM thread #%d: rc %d\n", i, rc);
                        LBUG();
                        GOTO(out_thread, rc);
                }
        }

        RETURN(0);

 out_thread:
        ptlrpc_stop_all_threads(ldlm->ldlm_service);
        ptlrpc_unregister_service(ldlm->ldlm_service);
 out_proc:
        ldlm_proc_cleanup(obddev);
 out_dec:
        MOD_DEC_USE_COUNT;
        return rc;
}

static int ldlm_cleanup(struct obd_device *obddev)
{
        struct ldlm_obd *ldlm = &obddev->u.ldlm;
        ENTRY;

        if (!list_empty(&ldlm_namespace_list)) {
                CERROR("ldlm still has namespaces; clean these up first.\n");
                RETURN(-EBUSY);
        }

        ptlrpc_stop_all_threads(ldlm->ldlm_service);
        ptlrpc_unregister_service(ldlm->ldlm_service);
        ldlm_proc_cleanup(obddev);

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

struct obd_ops ldlm_obd_ops = {
        o_iocontrol:   ldlm_iocontrol,
        o_setup:       ldlm_setup,
        o_cleanup:     ldlm_cleanup,
        o_connect:     class_connect,
        o_disconnect:  class_disconnect
};

static int __init ldlm_init(void)
{
        int rc = class_register_type(&ldlm_obd_ops, OBD_LDLM_DEVICENAME);
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
        class_unregister_type(OBD_LDLM_DEVICENAME);
        if (kmem_cache_destroy(ldlm_resource_slab) != 0)
                CERROR("couldn't free ldlm resource slab\n");
        if (kmem_cache_destroy(ldlm_lock_slab) != 0)
                CERROR("couldn't free ldlm lock slab\n");
}

EXPORT_SYMBOL(ldlm_completion_ast);
EXPORT_SYMBOL(ldlm_handle_enqueue);
EXPORT_SYMBOL(ldlm_handle_cancel);
EXPORT_SYMBOL(ldlm_handle_convert);
EXPORT_SYMBOL(ldlm_register_intent);
EXPORT_SYMBOL(ldlm_unregister_intent); 
EXPORT_SYMBOL(ldlm_lockname);
EXPORT_SYMBOL(ldlm_typename);
EXPORT_SYMBOL(ldlm_handle2lock);
EXPORT_SYMBOL(ldlm_lock2handle);
EXPORT_SYMBOL(ldlm_lock_match);
EXPORT_SYMBOL(ldlm_lock_addref);
EXPORT_SYMBOL(ldlm_lock_decref);
EXPORT_SYMBOL(ldlm_lock_change_resource);
EXPORT_SYMBOL(ldlm_cli_convert);
EXPORT_SYMBOL(ldlm_cli_enqueue);
EXPORT_SYMBOL(ldlm_cli_cancel);
EXPORT_SYMBOL(ldlm_match_or_enqueue);
EXPORT_SYMBOL(ldlm_it2str);
EXPORT_SYMBOL(ldlm_test);
EXPORT_SYMBOL(ldlm_regression_start);
EXPORT_SYMBOL(ldlm_regression_stop);
EXPORT_SYMBOL(ldlm_lock_dump);
EXPORT_SYMBOL(ldlm_namespace_new);
EXPORT_SYMBOL(ldlm_namespace_free);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lock Management Module v0.1");
MODULE_LICENSE("GPL");

module_init(ldlm_init);
module_exit(ldlm_exit);
