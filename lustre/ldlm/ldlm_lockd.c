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
#include <linux/obd_class.h>

extern kmem_cache_t *ldlm_resource_slab;
extern kmem_cache_t *ldlm_lock_slab;
extern struct lustre_lock ldlm_handle_lock;
extern struct list_head ldlm_namespace_list;
extern int (*mds_reint_p)(int offset, struct ptlrpc_request *req);
extern int (*mds_getattr_name_p)(int offset, struct ptlrpc_request *req);

inline unsigned long round_timeout(unsigned long timeout)
{
        return ((timeout / HZ) + 1) * HZ;
}

static struct list_head waiting_locks_list;
static spinlock_t waiting_locks_spinlock;
static struct timer_list waiting_locks_timer;
static int ldlm_already_setup = 0;

static void waiting_locks_callback(unsigned long unused)
{
        struct list_head *liter, *n;

        spin_lock_bh(&waiting_locks_spinlock);
        list_for_each_safe(liter, n, &waiting_locks_list) {
                struct ldlm_lock *l = list_entry(liter, struct ldlm_lock,
                                                 l_pending_chain);
                if (l->l_callback_timeout > jiffies)
                        break;
                LDLM_DEBUG(l, "timer expired, recovering exp %p on conn %p",
                           l->l_export, l->l_export->exp_connection);
                recovd_conn_fail(l->l_export->exp_connection);
        }
        spin_unlock_bh(&waiting_locks_spinlock);
}

/*
 * Indicate that we're waiting for a client to call us back cancelling a given
 * lock.  We add it to the pending-callback chain, and schedule the lock-timeout
 * timer to fire appropriately.  (We round up to the next second, to avoid
 * floods of timer firings during periods of high lock contention and traffic).
 */
static int ldlm_add_waiting_lock(struct ldlm_lock *lock)
{
        unsigned long timeout_rounded;
        ENTRY;

        LASSERT(list_empty(&lock->l_pending_chain));

        spin_lock_bh(&waiting_locks_spinlock);
        lock->l_callback_timeout = jiffies + (obd_timeout * HZ / 2);

        timeout_rounded = round_timeout(lock->l_callback_timeout);

        if (timeout_rounded < waiting_locks_timer.expires ||
            !timer_pending(&waiting_locks_timer)) {
                mod_timer(&waiting_locks_timer, timeout_rounded);
        }
        list_add_tail(&lock->l_pending_chain, &waiting_locks_list); /* FIFO */
        spin_unlock_bh(&waiting_locks_spinlock);
        RETURN(1);
}

/*
 * Remove a lock from the pending list, likely because it had its cancellation
 * callback arrive without incident.  This adjusts the lock-timeout timer if
 * needed.  Returns 0 if the lock wasn't pending after all, 1 if it was.
 */
int ldlm_del_waiting_lock(struct ldlm_lock *lock)
{
        struct list_head *list_next;

        ENTRY;

        spin_lock_bh(&waiting_locks_spinlock);

        if (list_empty(&lock->l_pending_chain)) {
                spin_unlock_bh(&waiting_locks_spinlock);
                RETURN(0);
        }

        list_next = lock->l_pending_chain.next;
        if (lock->l_pending_chain.prev == &waiting_locks_list) {
                /* Removing the head of the list, adjust timer. */
                if (list_next == &waiting_locks_list) {
                        /* No more, just cancel. */
                        del_timer(&waiting_locks_timer);
                } else {
                        struct ldlm_lock *next;
                        next = list_entry(list_next, struct ldlm_lock,
                                          l_pending_chain);
                        mod_timer(&waiting_locks_timer,
                                  round_timeout(next->l_callback_timeout));
                }
        }
        list_del_init(&lock->l_pending_chain);
        spin_unlock_bh(&waiting_locks_spinlock);
        RETURN(1);
}

static int ldlm_server_blocking_ast(struct ldlm_lock *lock,
                                    struct ldlm_lock_desc *desc,
                                    void *data, __u32 data_len, int flag)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        if (flag == LDLM_CB_CANCELING) {
                /* Don't need to do anything here. */
                RETURN(0);
        }

        LASSERT(lock);

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (lock->l_destroyed) {
                /* What's the point? */
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

        req = ptlrpc_prep_req(&lock->l_export->exp_ldlm_data.led_import,
                              LDLM_BL_CALLBACK, 1, &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));
        memcpy(&body->lock_desc, desc, sizeof(*desc));

        LDLM_DEBUG(lock, "server preparing blocking AST");
        req->rq_replen = 0; /* no reply needed */

        ldlm_add_waiting_lock(lock);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        (void)ptl_send_rpc(req);

        /* not waiting for reply */
        ptlrpc_req_finished(req);

        RETURN(rc);
}

static int ldlm_server_completion_ast(struct ldlm_lock *lock, int flags)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        if (lock == NULL) {
                LBUG();
                RETURN(-EINVAL);
        }

        req = ptlrpc_prep_req(&lock->l_export->exp_ldlm_data.led_import,
                              LDLM_CP_CALLBACK, 1, &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));
        body->lock_flags = flags;
        ldlm_lock2desc(lock, &body->lock_desc);

        LDLM_DEBUG(lock, "server preparing completion AST");
        req->rq_replen = 0; /* no reply needed */

        (void)ptl_send_rpc(req);

        /* not waiting for reply */
        ptlrpc_req_finished(req);

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
        flags = dlm_req->lock_flags;
        if (dlm_req->lock_desc.l_resource.lr_type == LDLM_PLAIN &&
            (flags & LDLM_FL_HAS_INTENT)) {
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

        /* XXX notice that this lock has no callback data: of course the
           export would be exactly what we may want to use here... */
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

        LASSERT(req->rq_export);
        lock->l_export = req->rq_export;
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        list_add(&lock->l_export_chain,
                 &lock->l_export->exp_ldlm_data.led_held_locks);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

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

        EXIT;
 out:
        if (lock)
                LDLM_DEBUG(lock, "server-side enqueue handler, sending reply"
                           "(err=%d)", err);
        req->rq_status = err;

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
                if (ldlm_del_waiting_lock(lock))
                        CDEBUG(D_DLMTRACE, "converted waiting lock %p\n", lock);
                req->rq_status = 0;
        }

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
        if (!dlm_req) {
                CERROR("bad request buffer for cancel\n");
                RETURN(-EINVAL);
        }

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                LDLM_DEBUG_NOLOCK("server-side cancel handler stale lock (lock "
                                  "%p)", (void *)(unsigned long)
                                  dlm_req->lock_handle1.addr);
                req->rq_status = ESTALE;
        } else {
                LDLM_DEBUG(lock, "server-side cancel handler START");
                ldlm_lock_cancel(lock);
                if (ldlm_del_waiting_lock(lock))
                        CDEBUG(D_DLMTRACE, "cancelled waiting lock %p\n", lock);
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
        int do_ast;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_OSC_LOCK_BL_AST, 0);

        dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                CERROR("blocking callback on lock "LPX64" - lock disappeared\n",
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
                                             lock->l_data, lock->l_data_len,
                                             LDLM_CB_BLOCKING);
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
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_OSC_LOCK_CP_AST, 0);

        dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                CERROR("completion callback on lock "LPX64" - lock "
                       "disappeared\n", dlm_req->lock_handle1.addr);
                RETURN(0);
        }

        LDLM_DEBUG(lock, "client completion callback handler START");

        l_lock(&lock->l_resource->lr_namespace->ns_lock);

        /* If we receive the completion AST before the actual enqueue returned,
         * then we might need to switch lock modes, resources, or extents. */
        if (dlm_req->lock_desc.l_granted_mode != lock->l_req_mode) {
                lock->l_req_mode = dlm_req->lock_desc.l_granted_mode;
                LDLM_DEBUG(lock, "completion AST, new lock mode");
        }
        if (lock->l_resource->lr_type == LDLM_EXTENT)
                memcpy(&lock->l_extent, &dlm_req->lock_desc.l_extent,
                       sizeof(lock->l_extent));
        ldlm_resource_unlink_lock(lock);
        if (memcmp(dlm_req->lock_desc.l_resource.lr_name,
                   lock->l_resource->lr_name,
                   sizeof(__u64) * RES_NAME_SIZE) != 0) {
                ldlm_lock_change_resource(lock,
                                         dlm_req->lock_desc.l_resource.lr_name);
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
                CERROR("lustre_ldlm: Invalid request: %d\n", rc);
                RETURN(rc);
        }

        if (req->rq_export == NULL) {
                struct ldlm_request *dlm_req;

                CERROR("operation %d with bad export (ptl req %d/rep %d)\n",
                       req->rq_reqmsg->opc, req->rq_request_portal,
                       req->rq_reply_portal);
                CERROR("--> export addr: "LPX64", cookie: "LPX64"\n",
                       req->rq_reqmsg->addr, req->rq_reqmsg->cookie);
                dlm_req = lustre_msg_buf(req->rq_reqmsg, 0);
                CERROR("--> lock addr: "LPX64", cookie: "LPX64"\n",
                       dlm_req->lock_handle1.addr,dlm_req->lock_handle1.cookie);
                CERROR("--> ignoring this error as a temporary workaround!  "
                       "beware!\n");
                //RETURN(-ENOTCONN);
        }

        switch (req->rq_reqmsg->opc) {
        case LDLM_BL_CALLBACK:
                CDEBUG(D_INODE, "blocking ast\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                rc = ldlm_handle_bl_callback(req);
                RETURN(rc);
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "completion ast\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CP_CALLBACK, 0);
                rc = ldlm_handle_cp_callback(req);
                RETURN(rc);

        default:
                CERROR("invalid opcode %d\n", req->rq_reqmsg->opc);
                RETURN(-EINVAL);
        }

        RETURN(0);
}


static int ldlm_cancel_handler(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc) {
                CERROR("lustre_ldlm: Invalid request: %d\n", rc);
                RETURN(rc);
        }

        if (req->rq_export == NULL) {
                CERROR("operation %d with bad export (ptl req %d/rep %d)\n",
                       req->rq_reqmsg->opc, req->rq_request_portal,
                       req->rq_reply_portal);
                CERROR("--> export addr: "LPX64", cookie: "LPX64"\n",
                       req->rq_reqmsg->addr, req->rq_reqmsg->cookie);
                CERROR("--> ignoring this error as a temporary workaround!  "
                       "beware!\n");
                //RETURN(-ENOTCONN);
        }

        switch (req->rq_reqmsg->opc) {

        /* XXX FIXME move this back to mds/handler.c, bug 625069 */
        case LDLM_CANCEL:
                CDEBUG(D_INODE, "cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CANCEL, 0);
                rc = ldlm_handle_cancel(req);
                if (rc)
                        break;
                RETURN(0);

        default:
                CERROR("invalid opcode %d\n", req->rq_reqmsg->opc);
                RETURN(-EINVAL);
        }

        RETURN(0);
}


static int ldlm_iocontrol(unsigned int cmd, struct lustre_handle *conn, int len,
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

static int ldlm_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct ldlm_obd *ldlm = &obddev->u.ldlm;
        int rc, i;
        ENTRY;

        if (ldlm_already_setup)
                RETURN(-EALREADY);

        MOD_INC_USE_COUNT;

        rc = ldlm_proc_setup(obddev);
        if (rc != 0)
                GOTO(out_dec, rc);

        ldlm->ldlm_cb_service =
                ptlrpc_init_svc(LDLM_NEVENTS, LDLM_NBUFS, LDLM_BUFSIZE,
                                LDLM_MAXREQSIZE, LDLM_CB_REQUEST_PORTAL,
                                LDLM_CB_REPLY_PORTAL, "self",
                                ldlm_callback_handler, "ldlm_cbd");

        if (!ldlm->ldlm_cb_service) {
                CERROR("failed to start service\n");
                GOTO(out_proc, rc = -ENOMEM);
        }

        ldlm->ldlm_cancel_service =
                ptlrpc_init_svc(LDLM_NEVENTS, LDLM_NBUFS, LDLM_BUFSIZE,
                                LDLM_MAXREQSIZE, LDLM_CANCEL_REQUEST_PORTAL,
                                LDLM_CANCEL_REPLY_PORTAL, "self",
                                ldlm_cancel_handler, "ldlm_canceld");

        if (!ldlm->ldlm_cancel_service) {
                CERROR("failed to start service\n");
                GOTO(out_proc, rc = -ENOMEM);
        }

        for (i = 0; i < LDLM_NUM_THREADS; i++) {
                char name[32];
                sprintf(name, "ldlm_cn_%02d", i);
                rc = ptlrpc_start_thread(obddev, ldlm->ldlm_cancel_service,
                                         name);
                if (rc) {
                        CERROR("cannot start LDLM thread #%d: rc %d\n", i, rc);
                        LBUG();
                        GOTO(out_thread, rc);
                }
        }

        for (i = 0; i < LDLM_NUM_THREADS; i++) {
                char name[32];
                sprintf(name, "ldlm_cb_%02d", i);
                rc = ptlrpc_start_thread(obddev, ldlm->ldlm_cb_service, name);
                if (rc) {
                        CERROR("cannot start LDLM thread #%d: rc %d\n", i, rc);
                        LBUG();
                        GOTO(out_thread, rc);
                }
        }

        INIT_LIST_HEAD(&waiting_locks_list);
        spin_lock_init(&waiting_locks_spinlock);
        waiting_locks_timer.function = waiting_locks_callback;
        waiting_locks_timer.data = 0;
        init_timer(&waiting_locks_timer);

        ldlm_already_setup = 1;

        RETURN(0);

 out_thread:
        ptlrpc_stop_all_threads(ldlm->ldlm_cancel_service);
        ptlrpc_unregister_service(ldlm->ldlm_cancel_service);
        ptlrpc_stop_all_threads(ldlm->ldlm_cb_service);
        ptlrpc_unregister_service(ldlm->ldlm_cb_service);

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

        ptlrpc_stop_all_threads(ldlm->ldlm_cb_service);
        ptlrpc_unregister_service(ldlm->ldlm_cb_service);
        ptlrpc_stop_all_threads(ldlm->ldlm_cancel_service);
        ptlrpc_unregister_service(ldlm->ldlm_cancel_service);
        ldlm_proc_cleanup(obddev);

        ldlm_already_setup = 0;
        MOD_DEC_USE_COUNT;
        RETURN(0);
}

static int ldlm_connect(struct lustre_handle *conn, struct obd_device *src,
                        obd_uuid_t cluuid, struct recovd_obd *recovd,
                        ptlrpc_recovery_cb_t recover)
{
        return class_connect(conn, src, cluuid);
}

struct obd_ops ldlm_obd_ops = {
        o_iocontrol:   ldlm_iocontrol,
        o_setup:       ldlm_setup,
        o_cleanup:     ldlm_cleanup,
        o_connect:     ldlm_connect,
        o_disconnect:  class_disconnect
};

static int __init ldlm_init(void)
{
        int rc = class_register_type(&ldlm_obd_ops, 0, OBD_LDLM_DEVICENAME);
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

        l_lock_init(&ldlm_handle_lock);

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
EXPORT_SYMBOL(__ldlm_handle2lock);
EXPORT_SYMBOL(ldlm_lock2handle);
EXPORT_SYMBOL(ldlm_lock_put);
EXPORT_SYMBOL(ldlm_lock_match);
EXPORT_SYMBOL(ldlm_lock_addref);
EXPORT_SYMBOL(ldlm_lock_decref);
EXPORT_SYMBOL(ldlm_lock_change_resource);
EXPORT_SYMBOL(ldlm_lock_set_data);
EXPORT_SYMBOL(ldlm_cli_convert);
EXPORT_SYMBOL(ldlm_cli_enqueue);
EXPORT_SYMBOL(ldlm_cli_cancel);
EXPORT_SYMBOL(ldlm_cli_cancel_unused);
EXPORT_SYMBOL(ldlm_match_or_enqueue);
EXPORT_SYMBOL(ldlm_it2str);
EXPORT_SYMBOL(ldlm_test);
EXPORT_SYMBOL(ldlm_regression_start);
EXPORT_SYMBOL(ldlm_regression_stop);
EXPORT_SYMBOL(ldlm_lock_dump);
EXPORT_SYMBOL(ldlm_namespace_new);
EXPORT_SYMBOL(ldlm_namespace_cleanup);
EXPORT_SYMBOL(ldlm_namespace_free);
EXPORT_SYMBOL(ldlm_namespace_dump);
EXPORT_SYMBOL(ldlm_cancel_locks_for_export);
EXPORT_SYMBOL(ldlm_replay_locks);
EXPORT_SYMBOL(ldlm_resource_foreach);
EXPORT_SYMBOL(ldlm_namespace_foreach);
EXPORT_SYMBOL(l_lock);
EXPORT_SYMBOL(l_unlock);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lock Management Module v0.1");
MODULE_LICENSE("GPL");

module_init(ldlm_init);
module_exit(ldlm_exit);
