/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/slab.h>
# include <linux/init.h>
# include <linux/wait.h>
#else
# include <liblustre.h>
#endif

#include <linux/lustre_dlm.h>
#include <linux/obd_class.h>
extern kmem_cache_t *ldlm_resource_slab;
extern kmem_cache_t *ldlm_lock_slab;
extern struct lustre_lock ldlm_handle_lock;
extern struct list_head ldlm_namespace_list;
extern int (*mds_reint_p)(int offset, struct ptlrpc_request *req);
extern int (*mds_getattr_name_p)(int offset, struct ptlrpc_request *req);

static int ldlm_already_setup = 0;

#ifdef __KERNEL__

inline unsigned long round_timeout(unsigned long timeout)
{
        return ((timeout / HZ) + 1) * HZ;
}

/* XXX should this be per-ldlm? */
static struct list_head waiting_locks_list;
static spinlock_t waiting_locks_spinlock;
static struct timer_list waiting_locks_timer;

static struct expired_lock_thread {
        wait_queue_head_t         elt_waitq;
        int                       elt_state;
        struct list_head          elt_expired_locks;
        spinlock_t                elt_lock;
} expired_lock_thread;

#define ELT_STOPPED   0
#define ELT_READY     1
#define ELT_TERMINATE 2

static inline int have_expired_locks(void)
{
        int need_to_run;

        spin_lock_bh(&expired_lock_thread.elt_lock);
        need_to_run = !list_empty(&expired_lock_thread.elt_expired_locks);
        spin_unlock_bh(&expired_lock_thread.elt_lock);

        RETURN(need_to_run);
}

static int expired_lock_main(void *arg)
{
        struct list_head *expired = &expired_lock_thread.elt_expired_locks;
        struct l_wait_info lwi = { 0 };
        unsigned long flags;

        ENTRY;
        lock_kernel();
        kportal_daemonize("ldlm_elt");
        
        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
        
        unlock_kernel();
        
        expired_lock_thread.elt_state = ELT_READY;
        wake_up(&expired_lock_thread.elt_waitq);
        
        while (1) {
                l_wait_event(expired_lock_thread.elt_waitq,
                             have_expired_locks() ||
                             expired_lock_thread.elt_state == ELT_TERMINATE,
                             &lwi);

                spin_lock_bh(&expired_lock_thread.elt_lock);
                while (!list_empty(expired)) {
                        struct ldlm_lock *lock = list_entry(expired->next,
                                                            struct ldlm_lock,
                                                            l_pending_chain);
                        spin_unlock_bh(&expired_lock_thread.elt_lock);
                        
                        ptlrpc_fail_export(lock->l_export);

                        spin_lock_bh(&expired_lock_thread.elt_lock);
                }
                spin_unlock_bh(&expired_lock_thread.elt_lock);

                if (expired_lock_thread.elt_state == ELT_TERMINATE)
                        break;
        }

        expired_lock_thread.elt_state = ELT_STOPPED;
        wake_up(&expired_lock_thread.elt_waitq);
        RETURN(0);
}

static void waiting_locks_callback(unsigned long unused)
{
        struct ldlm_lock *lock;

        spin_lock_bh(&waiting_locks_spinlock);
        while (!list_empty(&waiting_locks_list)) {
                lock = list_entry(waiting_locks_list.next, struct ldlm_lock,
                                  l_pending_chain);

                if (lock->l_callback_timeout > jiffies)
                        break;

                LDLM_ERROR(lock, "lock callback timer expired: evicting client "
                           "%s@%s nid "LPU64,
                           lock->l_export->exp_client_uuid.uuid,
                           lock->l_export->exp_connection->c_remote_uuid.uuid,
                           lock->l_export->exp_connection->c_peer.peer_nid);

                spin_lock_bh(&expired_lock_thread.elt_lock);
                list_del(&lock->l_pending_chain);
                list_add(&lock->l_pending_chain,
                         &expired_lock_thread.elt_expired_locks);
                spin_unlock_bh(&expired_lock_thread.elt_lock);
                wake_up(&expired_lock_thread.elt_waitq);
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

        LDLM_DEBUG(lock, "adding to wait list");
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
        /* We drop this ref when we get removed from the list. */
        class_export_get(lock->l_export);
        return 1;
}

/*
 * Remove a lock from the pending list, likely because it had its cancellation
 * callback arrive without incident.  This adjusts the lock-timeout timer if
 * needed.  Returns 0 if the lock wasn't pending after all, 1 if it was.
 */
int ldlm_del_waiting_lock(struct ldlm_lock *lock)
{
        struct list_head *list_next;

        if (lock->l_export == NULL) {
                /* We don't have a "waiting locks list" on clients. */
                LDLM_DEBUG(lock, "client lock: no-op");
                return 0;
        }

        spin_lock_bh(&waiting_locks_spinlock);

        if (list_empty(&lock->l_pending_chain)) {
                spin_unlock_bh(&waiting_locks_spinlock);
                LDLM_DEBUG(lock, "wasn't waiting");
                return 0;
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
        /* We got this ref when we were added to the list. */
        class_export_put(lock->l_export);
        LDLM_DEBUG(lock, "removed");
        return 1;
}

#else /* !__KERNEL__ */

static int ldlm_add_waiting_lock(struct ldlm_lock *lock)
{
        RETURN(1);
}

int ldlm_del_waiting_lock(struct ldlm_lock *lock)
{
        RETURN(0);
}

#endif /* __KERNEL__ */

static inline void ldlm_failed_ast(struct ldlm_lock *lock, int rc,
                                   char *ast_type)
{
        CERROR("%s AST failed (%d) for res "LPU64"/"LPU64
               ", mode %s: evicting client %s@%s NID "LPU64"\n",
               ast_type, rc,
               lock->l_resource->lr_name.name[0],
               lock->l_resource->lr_name.name[1],
               ldlm_lockname[lock->l_granted_mode],
               lock->l_export->exp_client_uuid.uuid,
               lock->l_export->exp_connection->c_remote_uuid.uuid,
               lock->l_export->exp_connection->c_peer.peer_nid);
        ptlrpc_fail_export(lock->l_export);
}

int ldlm_server_blocking_ast(struct ldlm_lock *lock,
                             struct ldlm_lock_desc *desc,
                             void *data, int flag)
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
        /* XXX This is necessary because, with the lock re-tasking, we actually
         * _can_ get called in here twice.  (bug 830) */
        if (!list_empty(&lock->l_pending_chain)) {
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

        if (lock->l_destroyed) {
                /* What's the point? */
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

#if 0
        if (LTIME_S(CURRENT_TIME) - lock->l_export->exp_last_request_time > 30){
                ldlm_failed_ast(lock, -ETIMEDOUT, "Not-attempted blocking");
                RETURN(-ETIMEDOUT);
        }
#endif

        req = ptlrpc_prep_req(lock->l_export->exp_ldlm_data.led_import,
                              LDLM_BL_CALLBACK, 1, &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));
        memcpy(&body->lock_desc, desc, sizeof(*desc));

        LDLM_DEBUG(lock, "server preparing blocking AST");
        req->rq_replen = lustre_msg_size(0, NULL);

        ldlm_add_waiting_lock(lock);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        req->rq_level = LUSTRE_CONN_RECOVD;
        req->rq_timeout = 2; /* 2 second timeout for initial AST reply */
        rc = ptlrpc_queue_wait(req);
        if (rc == -ETIMEDOUT || rc == -EINTR) {
                ldlm_del_waiting_lock(lock);
                ldlm_failed_ast(lock, rc, "blocking");
        } else if (rc) {
                if (rc == -EINVAL)
                        CDEBUG(D_DLMTRACE, "client (nid "LPU64") returned %d "
                               "from blocking AST for lock %p--normal race\n",
                               req->rq_connection->c_peer.peer_nid,
                               req->rq_repmsg->status, lock);
                else if (rc == -ENOTCONN)
                        CDEBUG(D_DLMTRACE, "client (nid "LPU64") returned %d "
                               "from blocking AST for lock %p--this client was "
                               "probably rebooted while it held a lock, nothing"
                               " serious\n",req->rq_connection->c_peer.peer_nid,
                               req->rq_repmsg->status, lock);
                else
                        CDEBUG(D_ERROR, "client (nid "LPU64") returned %d "
                               "from blocking AST for lock %p\n",
                               req->rq_connection->c_peer.peer_nid,
                               req->rq_repmsg->status, lock);
                LDLM_DEBUG(lock, "client returned error %d from blocking AST",
                           req->rq_status);
                ldlm_lock_cancel(lock);
                /* Server-side AST functions are called from ldlm_reprocess_all,
                 * which needs to be told to please restart its reprocessing. */
                rc = -ERESTART;
        }

        ptlrpc_req_finished(req);

        RETURN(rc);
}

int ldlm_server_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        if (lock == NULL) {
                LBUG();
                RETURN(-EINVAL);
        }

        req = ptlrpc_prep_req(lock->l_export->exp_ldlm_data.led_import,
                              LDLM_CP_CALLBACK, 1, &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));
        body->lock_flags = flags;
        ldlm_lock2desc(lock, &body->lock_desc);

        LDLM_DEBUG(lock, "server preparing completion AST");
        req->rq_replen = lustre_msg_size(0, NULL);

        req->rq_level = LUSTRE_CONN_RECOVD;
        req->rq_timeout = 2; /* 2 second timeout for initial AST reply */
        rc = ptlrpc_queue_wait(req);
        if (rc == -ETIMEDOUT || rc == -EINTR) {
                ldlm_del_waiting_lock(lock);
                ldlm_failed_ast(lock, rc, "completion");
        } else if (rc) {
                CERROR("client returned %d from completion AST for lock %p\n",
                       req->rq_status, lock);
                LDLM_DEBUG(lock, "client returned error %d from completion AST",
                           req->rq_status);
                ldlm_lock_cancel(lock);
                /* Server-side AST functions are called from ldlm_reprocess_all,
                 * which needs to be told to please restart its reprocessing. */
                rc = -ERESTART;
        }
        ptlrpc_req_finished(req);

        RETURN(rc);
}

int ldlm_handle_enqueue(struct ptlrpc_request *req,
                        ldlm_completion_callback completion_callback,
                        ldlm_blocking_callback blocking_callback)
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

        dlm_req = lustre_swab_reqbuf (req, 0, sizeof (*dlm_req),
                                      lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR ("Can't unpack dlm_req\n");
                RETURN (-EFAULT);
        }
        
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

        /* The lock's callback data might be set in the policy function */
        lock = ldlm_lock_create(obddev->obd_namespace,
                                &dlm_req->lock_handle2,
                                dlm_req->lock_desc.l_resource.lr_name,
                                dlm_req->lock_desc.l_resource.lr_type,
                                dlm_req->lock_desc.l_req_mode,
                                blocking_callback, NULL);
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

        err = ldlm_lock_enqueue(obddev->obd_namespace, &lock, cookie, cookielen,
                                &flags, completion_callback);
        if (err)
                GOTO(out, err);

        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*dlm_rep));
        dlm_rep->lock_flags = flags;

        ldlm_lock2handle(lock, &dlm_rep->lock_handle);
        if (dlm_req->lock_desc.l_resource.lr_type == LDLM_EXTENT)
                memcpy(&dlm_rep->lock_extent, &lock->l_extent,
                       sizeof(lock->l_extent));
        if (dlm_rep->lock_flags & LDLM_FL_LOCK_CHANGED) {
                memcpy(&dlm_rep->lock_resource_name, &lock->l_resource->lr_name,
                       sizeof(dlm_rep->lock_resource_name));
                dlm_rep->lock_mode = lock->l_req_mode;
        }

        EXIT;
 out:
        if (lock)
                LDLM_DEBUG(lock, "server-side enqueue handler, sending reply"
                           "(err=%d)", err);
        req->rq_status = err;

        /* The LOCK_CHANGED code in ldlm_lock_enqueue depends on this
         * ldlm_reprocess_all.  If this moves, revisit that code. -phil */
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

        dlm_req = lustre_swab_reqbuf (req, 0, sizeof (*dlm_req),
                                      lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR ("Can't unpack dlm_req\n");
                RETURN (-EFAULT);
        }
        
        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("out of memory\n");
                RETURN(-ENOMEM);
        }
        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*dlm_rep));
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

        dlm_req = lustre_swab_reqbuf (req, 0, sizeof (*dlm_req),
                                      lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR("bad request buffer for cancel\n");
                RETURN(-EFAULT);
        }

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("out of memory\n");
                RETURN(-ENOMEM);
        }

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                CERROR("received cancel for unknown lock cookie "LPX64
                       " from nid "LPU64"\n", dlm_req->lock_handle1.cookie,
                       req->rq_connection->c_peer.peer_nid);
                LDLM_DEBUG_NOLOCK("server-side cancel handler stale lock "
                                  "(cookie "LPU64")",
                                  dlm_req->lock_handle1.cookie);
                req->rq_status = ESTALE;
        } else {
                LDLM_DEBUG(lock, "server-side cancel handler START");
                ldlm_lock_cancel(lock);
                if (ldlm_del_waiting_lock(lock))
                        CDEBUG(D_DLMTRACE, "cancelled waiting lock %p\n", lock);
                req->rq_status = 0;
        }

        if (ptlrpc_reply(req) != 0)
                LBUG();

        if (lock) {
                ldlm_reprocess_all(lock->l_resource);
                LDLM_DEBUG(lock, "server-side cancel handler END");
                LDLM_LOCK_PUT(lock);
        }

        RETURN(0);
}

static void ldlm_handle_bl_callback(struct ptlrpc_request *req,
                                    struct ldlm_namespace *ns,
                                    struct ldlm_request *dlm_req,
                                    struct ldlm_lock *lock)
{
        int do_ast;
        ENTRY;

        l_lock(&ns->ns_lock);
        LDLM_DEBUG(lock, "client blocking AST callback handler START");

        lock->l_flags |= LDLM_FL_CBPENDING;
        do_ast = (!lock->l_readers && !lock->l_writers);

        if (do_ast) {
                LDLM_DEBUG(lock, "already unused, calling "
                           "callback (%p)", lock->l_blocking_ast);
                if (lock->l_blocking_ast != NULL) {
                        l_unlock(&ns->ns_lock);
                        lock->l_blocking_ast(lock, &dlm_req->lock_desc,
                                             lock->l_data, LDLM_CB_BLOCKING);
                        l_lock(&ns->ns_lock);
                }
        } else {
                LDLM_DEBUG(lock, "Lock still has references, will be"
                           " cancelled later");
        }

        LDLM_DEBUG(lock, "client blocking callback handler END");
        l_unlock(&ns->ns_lock);
        LDLM_LOCK_PUT(lock);
        EXIT;
}

static void ldlm_handle_cp_callback(struct ptlrpc_request *req,
                                    struct ldlm_namespace *ns,
                                    struct ldlm_request *dlm_req,
                                    struct ldlm_lock *lock)
{
        LIST_HEAD(ast_list);
        ENTRY;

        l_lock(&ns->ns_lock);
        LDLM_DEBUG(lock, "client completion callback handler START");

        /* If we receive the completion AST before the actual enqueue returned,
         * then we might need to switch lock modes, resources, or extents. */
        if (dlm_req->lock_desc.l_granted_mode != lock->l_req_mode) {
                lock->l_req_mode = dlm_req->lock_desc.l_granted_mode;
                LDLM_DEBUG(lock, "completion AST, new lock mode");
        }
        if (lock->l_resource->lr_type == LDLM_EXTENT) {
                memcpy(&lock->l_extent, &dlm_req->lock_desc.l_extent,
                       sizeof(lock->l_extent));

                if ((lock->l_extent.end & ~PAGE_MASK) != ~PAGE_MASK) {
                        /* XXX Old versions of BA OST code have a fencepost bug
                         * which will cause them to grant a lock that's one
                         * byte too large.  This can be safely removed after BA
                         * ships their next release -phik (02 Apr 2003) */
                        lock->l_extent.end--;
                } else if ((lock->l_extent.start & ~PAGE_MASK) ==
                           ~PAGE_MASK) {
                        lock->l_extent.start++;
                }
        }

        ldlm_resource_unlink_lock(lock);
        if (memcmp(&dlm_req->lock_desc.l_resource.lr_name,
                   &lock->l_resource->lr_name,
                   sizeof(lock->l_resource->lr_name)) != 0) {
                ldlm_lock_change_resource(ns, lock,
                                         dlm_req->lock_desc.l_resource.lr_name);
                LDLM_DEBUG(lock, "completion AST, new resource");
        }
        lock->l_resource->lr_tmp = &ast_list;
        ldlm_grant_lock(lock, req, sizeof(*req));
        lock->l_resource->lr_tmp = NULL;
        LDLM_DEBUG(lock, "callback handler finished, about to run_ast_work");
        l_unlock(&ns->ns_lock);
        LDLM_LOCK_PUT(lock);

        ldlm_run_ast_work(&ast_list);

        LDLM_DEBUG_NOLOCK("client completion callback handler END (lock %p)",
                          lock);
        EXIT;
}

static int ldlm_callback_reply(struct ptlrpc_request *req, int rc)
{
        req->rq_status = rc;
        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen,
                             &req->rq_repmsg);
        if (rc)
                return rc;
        return ptlrpc_reply(req);
}

static int ldlm_callback_handler(struct ptlrpc_request *req)
{
        struct ldlm_namespace *ns;
        struct ldlm_request *dlm_req;
        struct ldlm_lock *lock;
        ENTRY;

        /* Requests arrive in sender's byte order.  The ptlrpc service
         * handler has already checked and, if necessary, byte-swapped the
         * incoming request message body, but I am responsible for the
         * message buffers. */

        if (req->rq_export == NULL) {
                struct ldlm_request *dlm_req;

                CDEBUG(D_RPCTRACE, "operation %d from nid "LPU64" with bad "
                       "export cookie "LPX64" (ptl req %d/rep %d); this is "
                       "normal if this node rebooted with a lock held\n",
                       req->rq_reqmsg->opc, req->rq_connection->c_peer.peer_nid,
                       req->rq_reqmsg->handle.cookie,
                       req->rq_request_portal, req->rq_reply_portal);

                dlm_req = lustre_swab_reqbuf(req, 0, sizeof (*dlm_req),
                                             lustre_swab_ldlm_request);
                if (dlm_req != NULL)
                        CDEBUG(D_RPCTRACE, "--> lock cookie: "LPX64"\n",
                               dlm_req->lock_handle1.cookie);

                ldlm_callback_reply(req, -ENOTCONN);
                RETURN(0);
        }

        if (req->rq_reqmsg->opc == LDLM_BL_CALLBACK) {
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
        } else if (req->rq_reqmsg->opc == LDLM_CP_CALLBACK) {
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CP_CALLBACK, 0);
        } else {
                ldlm_callback_reply(req, -EPROTO);
                RETURN(0);
        }

        LASSERT(req->rq_export != NULL);
        LASSERT(req->rq_export->exp_obd != NULL);
        ns = req->rq_export->exp_obd->obd_namespace;
        LASSERT(ns != NULL);

        dlm_req = lustre_swab_reqbuf (req, 0, sizeof (*dlm_req),
                                      lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR ("can't unpack dlm_req\n");
                ldlm_callback_reply (req, -EPROTO);
                RETURN (0);
        }
        
        lock = ldlm_handle2lock_ns(ns, &dlm_req->lock_handle1);
        if (!lock) {
                CDEBUG(D_INODE, "callback on lock "LPX64" - lock disappeared\n",
                       dlm_req->lock_handle1.cookie);
                ldlm_callback_reply(req, -EINVAL);
                RETURN(0);
        }

        /* we want the ost thread to get this reply so that it can respond
         * to ost requests (write cache writeback) that might be triggered
         * in the callback */
        ldlm_callback_reply(req, 0);

        switch (req->rq_reqmsg->opc) {
        case LDLM_BL_CALLBACK:
                CDEBUG(D_INODE, "blocking ast\n");
                ldlm_handle_bl_callback(req, ns, dlm_req, lock);
                break;
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "completion ast\n");
                ldlm_handle_cp_callback(req, ns, dlm_req, lock);
                break;
        default:
                LBUG();                         /* checked above */
        }

        RETURN(0);
}

static int ldlm_cancel_handler(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        /* Requests arrive in sender's byte order.  The ptlrpc service
         * handler has already checked and, if necessary, byte-swapped the
         * incoming request message body, but I am responsible for the
         * message buffers. */

        if (req->rq_export == NULL) {
                struct ldlm_request *dlm_req;
                CERROR("operation %d with bad export (ptl req %d/rep %d)\n",
                       req->rq_reqmsg->opc, req->rq_request_portal,
                       req->rq_reply_portal);
                CERROR("--> export cookie: "LPX64"\n",
                       req->rq_reqmsg->handle.cookie);
                dlm_req = lustre_swab_reqbuf(req, 0, sizeof (*dlm_req),
                                             lustre_swab_ldlm_request);
                if (dlm_req != NULL)
                        ldlm_lock_dump_handle(D_ERROR, &dlm_req->lock_handle1);
                RETURN(-ENOTCONN);
        }

        switch (req->rq_reqmsg->opc) {

        /* XXX FIXME move this back to mds/handler.c, bug 249 */
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
        struct obd_uuid uuid = { "ldlm" };
        int err = 0;
        ENTRY;

        if (_IOC_TYPE(cmd) != IOC_LDLM_TYPE || _IOC_NR(cmd) < IOC_LDLM_MIN_NR ||
            _IOC_NR(cmd) > IOC_LDLM_MAX_NR) {
                CDEBUG(D_IOCTL, "invalid ioctl (type %d, nr %d, size %d)\n",
                       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
                RETURN(-EINVAL);
        }

        OBD_ALLOC(obddev->u.ldlm.ldlm_client,
                  sizeof(*obddev->u.ldlm.ldlm_client));
        connection = ptlrpc_uuid_to_connection(&uuid);
        if (!connection)
                CERROR("No LDLM UUID found: assuming ldlm is local.\n");

        switch (cmd) {
        case IOC_LDLM_TEST:
                //err = ldlm_test(obddev, conn);
                err = 0;
                CERROR("-- NO TESTS WERE RUN done err %d\n", err);
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

        rc = ldlm_proc_setup(obddev);
        if (rc != 0)
                RETURN(rc);

#ifdef __KERNEL__
        inter_module_register("ldlm_cli_cancel_unused", THIS_MODULE,
                              ldlm_cli_cancel_unused);
        inter_module_register("ldlm_namespace_cleanup", THIS_MODULE,
                              ldlm_namespace_cleanup);
        inter_module_register("ldlm_replay_locks", THIS_MODULE,
                              ldlm_replay_locks);

        ldlm->ldlm_cb_service =
                ptlrpc_init_svc(LDLM_NEVENTS, LDLM_NBUFS, LDLM_BUFSIZE,
                                LDLM_MAXREQSIZE, LDLM_CB_REQUEST_PORTAL,
                                LDLM_CB_REPLY_PORTAL,
                                ldlm_callback_handler, "ldlm_cbd", obddev);

        if (!ldlm->ldlm_cb_service) {
                CERROR("failed to start service\n");
                GOTO(out_proc, rc = -ENOMEM);
        }

        ldlm->ldlm_cancel_service =
                ptlrpc_init_svc(LDLM_NEVENTS, LDLM_NBUFS, LDLM_BUFSIZE,
                                LDLM_MAXREQSIZE, LDLM_CANCEL_REQUEST_PORTAL,
                                LDLM_CANCEL_REPLY_PORTAL,
                                ldlm_cancel_handler, "ldlm_canceld", obddev);

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

        INIT_LIST_HEAD(&expired_lock_thread.elt_expired_locks);
        spin_lock_init(&expired_lock_thread.elt_lock);
        expired_lock_thread.elt_state = ELT_STOPPED;
        init_waitqueue_head(&expired_lock_thread.elt_waitq);

        rc = kernel_thread(expired_lock_main, NULL, CLONE_VM | CLONE_FS);
        if (rc < 0) {
                CERROR("Cannot start ldlm expired-lock thread: %d\n", rc);
                GOTO(out_thread, rc);
        }

        wait_event(expired_lock_thread.elt_waitq,
                   expired_lock_thread.elt_state == ELT_READY);

        INIT_LIST_HEAD(&waiting_locks_list);
        spin_lock_init(&waiting_locks_spinlock);
        waiting_locks_timer.function = waiting_locks_callback;
        waiting_locks_timer.data = 0;
        init_timer(&waiting_locks_timer);
#endif

        ldlm_already_setup = 1;

        RETURN(0);

 out_thread:
#ifdef __KERNEL__
        ptlrpc_stop_all_threads(ldlm->ldlm_cancel_service);
        ptlrpc_unregister_service(ldlm->ldlm_cancel_service);
        ptlrpc_stop_all_threads(ldlm->ldlm_cb_service);
        ptlrpc_unregister_service(ldlm->ldlm_cb_service);
#endif
 out_proc:
        ldlm_proc_cleanup(obddev);

        return rc;
}

static int ldlm_cleanup(struct obd_device *obddev, int force, int failover)
{
        struct ldlm_obd *ldlm = &obddev->u.ldlm;
        ENTRY;

        if (!list_empty(&ldlm_namespace_list)) {
                CERROR("ldlm still has namespaces; clean these up first.\n");
                ldlm_dump_all_namespaces();
                RETURN(-EBUSY);
        }

#ifdef __KERNEL__
        if (force) {
                ptlrpc_put_ldlm_hooks();
        } else if (ptlrpc_ldlm_hooks_referenced()) {
                CERROR("Some connections weren't cleaned up; run lconf with "
                       "--force to forcibly unload.\n");
                ptlrpc_dump_connections();
                RETURN(-EBUSY);
        }

        ptlrpc_stop_all_threads(ldlm->ldlm_cb_service);
        ptlrpc_unregister_service(ldlm->ldlm_cb_service);
        ptlrpc_stop_all_threads(ldlm->ldlm_cancel_service);
        ptlrpc_unregister_service(ldlm->ldlm_cancel_service);
        ldlm_proc_cleanup(obddev);

        expired_lock_thread.elt_state = ELT_TERMINATE;
        wake_up(&expired_lock_thread.elt_waitq);
        wait_event(expired_lock_thread.elt_waitq,
                   expired_lock_thread.elt_state == ELT_STOPPED);

        inter_module_unregister("ldlm_namespace_cleanup");
        inter_module_unregister("ldlm_cli_cancel_unused");
        inter_module_unregister("ldlm_replay_locks");
#endif

        ldlm_already_setup = 0;
        RETURN(0);
}

static int ldlm_connect(struct lustre_handle *conn, struct obd_device *src,
                        struct obd_uuid *cluuid)
{
        return class_connect(conn, src, cluuid);
}

struct obd_ops ldlm_obd_ops = {
        o_owner:       THIS_MODULE,
        o_iocontrol:   ldlm_iocontrol,
        o_setup:       ldlm_setup,
        o_cleanup:     ldlm_cleanup,
        o_connect:     ldlm_connect,
        o_disconnect:  class_disconnect
};

int __init ldlm_init(void)
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

/* ldlm_lock.c */
EXPORT_SYMBOL(ldlm_lock2desc);
EXPORT_SYMBOL(ldlm_register_intent);
EXPORT_SYMBOL(ldlm_unregister_intent);
EXPORT_SYMBOL(ldlm_lockname);
EXPORT_SYMBOL(ldlm_typename);
EXPORT_SYMBOL(ldlm_lock2handle);
EXPORT_SYMBOL(__ldlm_handle2lock);
EXPORT_SYMBOL(ldlm_lock_put);
EXPORT_SYMBOL(ldlm_lock_match);
EXPORT_SYMBOL(ldlm_lock_cancel);
EXPORT_SYMBOL(ldlm_lock_addref);
EXPORT_SYMBOL(ldlm_lock_decref);
EXPORT_SYMBOL(ldlm_lock_decref_and_cancel);
EXPORT_SYMBOL(ldlm_lock_change_resource);
EXPORT_SYMBOL(ldlm_lock_set_data);
EXPORT_SYMBOL(ldlm_it2str);
EXPORT_SYMBOL(ldlm_lock_dump);
EXPORT_SYMBOL(ldlm_lock_dump_handle);
EXPORT_SYMBOL(ldlm_cancel_locks_for_export);
EXPORT_SYMBOL(ldlm_reprocess_all_ns);

/* ldlm_request.c */
EXPORT_SYMBOL(ldlm_completion_ast);
EXPORT_SYMBOL(ldlm_expired_completion_wait);
EXPORT_SYMBOL(ldlm_cli_convert);
EXPORT_SYMBOL(ldlm_cli_enqueue);
EXPORT_SYMBOL(ldlm_cli_cancel);
EXPORT_SYMBOL(ldlm_cli_cancel_unused);
EXPORT_SYMBOL(ldlm_replay_locks);
EXPORT_SYMBOL(ldlm_resource_foreach);
EXPORT_SYMBOL(ldlm_namespace_foreach);
EXPORT_SYMBOL(ldlm_namespace_foreach_res);

/* ldlm_lockd.c */
EXPORT_SYMBOL(ldlm_server_blocking_ast);
EXPORT_SYMBOL(ldlm_server_completion_ast);
EXPORT_SYMBOL(ldlm_handle_enqueue);
EXPORT_SYMBOL(ldlm_handle_cancel);
EXPORT_SYMBOL(ldlm_handle_convert);
EXPORT_SYMBOL(ldlm_del_waiting_lock);

#if 0
/* ldlm_test.c */
EXPORT_SYMBOL(ldlm_test);
EXPORT_SYMBOL(ldlm_regression_start);
EXPORT_SYMBOL(ldlm_regression_stop);
#endif

/* ldlm_resource.c */
EXPORT_SYMBOL(ldlm_namespace_new);
EXPORT_SYMBOL(ldlm_namespace_cleanup);
EXPORT_SYMBOL(ldlm_namespace_free);
EXPORT_SYMBOL(ldlm_namespace_dump);

/* l_lock.c */
EXPORT_SYMBOL(l_lock);
EXPORT_SYMBOL(l_unlock);

/* ldlm_lib.c */
EXPORT_SYMBOL(client_import_connect);
EXPORT_SYMBOL(client_import_disconnect);
EXPORT_SYMBOL(target_abort_recovery);
EXPORT_SYMBOL(target_handle_connect);
EXPORT_SYMBOL(target_cancel_recovery_timer);
EXPORT_SYMBOL(target_send_reply);
EXPORT_SYMBOL(target_queue_recovery_request);
EXPORT_SYMBOL(target_handle_ping);
EXPORT_SYMBOL(target_handle_disconnect);
EXPORT_SYMBOL(target_queue_final_reply);

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lock Management Module v0.1");
MODULE_LICENSE("GPL");

module_init(ldlm_init);
module_exit(ldlm_exit);
#endif
