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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
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
#include <portals/list.h>
#include "ldlm_internal.h"

extern kmem_cache_t *ldlm_resource_slab;
extern kmem_cache_t *ldlm_lock_slab;
extern struct lustre_lock ldlm_handle_lock;
extern struct list_head ldlm_namespace_list;
extern int (*mds_reint_p)(int offset, struct ptlrpc_request *req);
extern int (*mds_getattr_name_p)(int offset, struct ptlrpc_request *req);

static DECLARE_MUTEX(ldlm_ref_sem);
static int ldlm_refcount = 0;

/* LDLM state */

static struct ldlm_state *ldlm_state;

inline unsigned long round_timeout(unsigned long timeout)
{
        return ((timeout / HZ) + 1) * HZ;
}

#ifdef __KERNEL__
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
#endif

#define ELT_STOPPED   0
#define ELT_READY     1
#define ELT_TERMINATE 2

struct ldlm_bl_pool {
        spinlock_t              blp_lock;
        struct list_head        blp_list;
        wait_queue_head_t       blp_waitq;
        atomic_t                blp_num_threads;
        struct completion       blp_comp;
};

struct ldlm_bl_work_item {
        struct list_head        blwi_entry;
        struct ldlm_namespace   *blwi_ns;
        struct ldlm_lock_desc   blwi_ld;
        struct ldlm_lock        *blwi_lock;
};

#ifdef __KERNEL__

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
                        struct obd_export *export;
                        struct ldlm_lock *lock;

                        lock = list_entry(expired->next, struct ldlm_lock,
                                          l_pending_chain);
                        if ((void *)lock < LP_POISON + PAGE_SIZE &&
                            (void *)lock >= LP_POISON) {
                                CERROR("free lock on elt list %p\n", lock);
                                LBUG();
                        }
                        list_del_init(&lock->l_pending_chain);
                        if ((void *)lock->l_export < LP_POISON + PAGE_SIZE &&
                            (void *)lock->l_export >= LP_POISON + PAGE_SIZE) {
                                CERROR("lock with free export on elt list %p\n",
                                       export);
                                lock->l_export = NULL;
                                LDLM_ERROR(lock, "free export\n");
                                continue;
                        }
                        export = class_export_get(lock->l_export);
                        spin_unlock_bh(&expired_lock_thread.elt_lock);

                        ptlrpc_fail_export(export);
                        class_export_put(export);
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
        char str[PTL_NALFMT_SIZE];

        spin_lock_bh(&waiting_locks_spinlock);
        while (!list_empty(&waiting_locks_list)) {
                lock = list_entry(waiting_locks_list.next, struct ldlm_lock,
                                  l_pending_chain);

                if ((lock->l_callback_timeout > jiffies) ||
                    (lock->l_req_mode == LCK_GROUP))
                        break;

                LDLM_ERROR(lock, "lock callback timer expired: evicting client "
                           "%s@%s nid "LPX64" (%s) ",
                           lock->l_export->exp_client_uuid.uuid,
                           lock->l_export->exp_connection->c_remote_uuid.uuid,
                           lock->l_export->exp_connection->c_peer.peer_nid,
                           portals_nid2str(lock->l_export->exp_connection->c_peer.peer_ni->pni_number,
                                           lock->l_export->exp_connection->c_peer.peer_nid,
                                           str));

                spin_lock_bh(&expired_lock_thread.elt_lock);
                list_del(&lock->l_pending_chain);
                list_add(&lock->l_pending_chain,
                         &expired_lock_thread.elt_expired_locks);
                spin_unlock_bh(&expired_lock_thread.elt_lock);
                wake_up(&expired_lock_thread.elt_waitq);
        }

        /*
         * Make sure the timer will fire again if we have any locks
         * left.
         */
        if (!list_empty(&waiting_locks_list)) {
                unsigned long timeout_rounded;
                lock = list_entry(waiting_locks_list.next, struct ldlm_lock,
                                  l_pending_chain);
                timeout_rounded = round_timeout(lock->l_callback_timeout);
                mod_timer(&waiting_locks_timer, timeout_rounded);
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

        spin_lock_bh(&waiting_locks_spinlock);
        if (!list_empty(&lock->l_pending_chain)) {
                LDLM_DEBUG(lock, "not re-adding to wait list");
                spin_unlock_bh(&waiting_locks_spinlock);
                return 0;
        }
        LDLM_DEBUG(lock, "adding to wait list");

        lock->l_callback_timeout = jiffies + (obd_timeout * HZ / 2);

        timeout_rounded = round_timeout(lock->l_callback_timeout);

        if (timeout_rounded < waiting_locks_timer.expires ||
            !timer_pending(&waiting_locks_timer)) {
                mod_timer(&waiting_locks_timer, timeout_rounded);
        }
        list_add_tail(&lock->l_pending_chain, &waiting_locks_list); /* FIFO */
        spin_unlock_bh(&waiting_locks_spinlock);
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

        spin_lock_bh(&expired_lock_thread.elt_lock);
        list_del_init(&lock->l_pending_chain);
        spin_unlock_bh(&expired_lock_thread.elt_lock);

        spin_unlock_bh(&waiting_locks_spinlock);
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

static void ldlm_failed_ast(struct ldlm_lock *lock, int rc, char *ast_type)
{
        const struct ptlrpc_connection *conn = lock->l_export->exp_connection;
        char str[PTL_NALFMT_SIZE];

        CERROR("%s AST failed (%d) for res "LPU64"/"LPU64
               ", mode %s: evicting client %s@%s NID "LPX64" (%s)\n",
               ast_type, rc,
               lock->l_resource->lr_name.name[0],
               lock->l_resource->lr_name.name[1],
               ldlm_lockname[lock->l_granted_mode],
               lock->l_export->exp_client_uuid.uuid,
               conn->c_remote_uuid.uuid, conn->c_peer.peer_nid,
               portals_nid2str(conn->c_peer.peer_ni->pni_number,
                               conn->c_peer.peer_nid, str));
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
        if (lock->l_granted_mode != lock->l_req_mode) {
                /* this blocking AST will be communicated as part of the
                 * completion AST instead */
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                LDLM_DEBUG(lock, "lock not granted, not sending blocking AST");                 RETURN(0);
        }

        if (lock->l_destroyed) {
                /* What's the point? */
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

#if 0
        if (LTIME_S(CURRENT_TIME) - lock->l_export->exp_last_request_time > 30){
                ldlm_failed_ast(lock, -ETIMEDOUT, "Not-attempted blocking");
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(-ETIMEDOUT);
        }
#endif

        req = ptlrpc_prep_req(lock->l_export->exp_imp_reverse,
                              LDLM_BL_CALLBACK, 1, &size, NULL);
        if (req == NULL) {
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(-ENOMEM);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));
        memcpy(&body->lock_desc, desc, sizeof(*desc));
        body->lock_flags |= (lock->l_flags & LDLM_AST_FLAGS);

        LDLM_DEBUG(lock, "server preparing blocking AST");
        req->rq_replen = lustre_msg_size(0, NULL);

        if (lock->l_granted_mode == lock->l_req_mode)
                ldlm_add_waiting_lock(lock);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        req->rq_send_state = LUSTRE_IMP_FULL;
        req->rq_timeout = 2; /* 2 second timeout for initial AST reply */
        rc = ptlrpc_queue_wait(req);
        if (rc == -ETIMEDOUT || rc == -EINTR || rc == -ENOTCONN) {
                LASSERT(lock->l_export);
                if (lock->l_export->exp_libclient) {
                        CDEBUG(D_HA, "BLOCKING AST to liblustre client (nid "
                               LPU64") timeout, simply cancel lock 0x%p\n",
                               req->rq_peer.peer_nid, lock);
                        ldlm_lock_cancel(lock);
                        rc = -ERESTART;
                } else {
                        ldlm_del_waiting_lock(lock);
                        ldlm_failed_ast(lock, rc, "blocking");
                }
        } else if (rc) {
                if (rc == -EINVAL)
                        CDEBUG(D_DLMTRACE, "client (nid "LPU64") returned %d "
                               "from blocking AST for lock %p--normal race\n",
                               req->rq_peer.peer_nid,
                               req->rq_repmsg->status, lock);
                else if (rc == -ENOTCONN)
                        CDEBUG(D_DLMTRACE, "client (nid "LPU64") returned %d "
                               "from blocking AST for lock %p--this client was "
                               "probably rebooted while it held a lock, nothing"
                               " serious\n",req->rq_peer.peer_nid,
                               req->rq_repmsg->status, lock);
                else
                        CDEBUG(D_ERROR, "client (nid "LPU64") returned %d "
                               "from blocking AST for lock %p\n",
                               req->rq_peer.peer_nid,
                               (req->rq_repmsg != NULL)?
                               req->rq_repmsg->status : 0,
                               lock);
                LDLM_DEBUG(lock, "client sent rc %d rq_status %d from blocking "
                           "AST", rc, req->rq_status);
                ldlm_lock_cancel(lock);
                /* Server-side AST functions are called from ldlm_reprocess_all,
                 * which needs to be told to please restart its reprocessing. */
                rc = -ERESTART;
        }

        ptlrpc_req_finished(req);

        RETURN(rc);
}

/* XXX copied from ptlrpc/service.c */
static long timeval_sub(struct timeval *large, struct timeval *small)
{
        return (large->tv_sec - small->tv_sec) * 1000000 +
                (large->tv_usec - small->tv_usec);
}

int ldlm_server_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        struct timeval granted_time;
        long total_enqueue_wait;
        int rc = 0, size[2] = {sizeof(*body)}, buffers = 1;
        ENTRY;

        LASSERT(lock != NULL);

        do_gettimeofday(&granted_time);
        total_enqueue_wait = timeval_sub(&granted_time, &lock->l_enqueued_time);

        if (total_enqueue_wait / 1000000 > obd_timeout)
                LDLM_ERROR(lock, "enqueue wait took %ldus", total_enqueue_wait);

        if (lock->l_resource->lr_lvb_len) {
                buffers = 2;
                size[1] = lock->l_resource->lr_lvb_len;
        }

        req = ptlrpc_prep_req(lock->l_export->exp_imp_reverse,
                              LDLM_CP_CALLBACK, buffers, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));
        body->lock_flags = flags;
        ldlm_lock2desc(lock, &body->lock_desc);

        if (buffers == 2) {
                void *lvb = lustre_msg_buf(req->rq_reqmsg, 1,
                                           lock->l_resource->lr_lvb_len);
                memcpy(lvb, lock->l_resource->lr_lvb_data,
                       lock->l_resource->lr_lvb_len);
        }

        LDLM_DEBUG(lock, "server preparing completion AST (after %ldus wait)",
                   total_enqueue_wait);
        req->rq_replen = lustre_msg_size(0, NULL);

        req->rq_send_state = LUSTRE_IMP_FULL;
        req->rq_timeout = 2; /* 2 second timeout for initial AST reply */

        /* We only send real blocking ASTs after the lock is granted */
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (lock->l_flags & LDLM_FL_AST_SENT) {
                body->lock_flags |= LDLM_FL_AST_SENT;
                ldlm_add_waiting_lock(lock); /* start the lock-timeout clock */
        }
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        rc = ptlrpc_queue_wait(req);
        if ((rc == -ETIMEDOUT || rc == -EINTR || rc == -ENOTCONN) &&
             !lock->l_export->exp_libclient) {
                ldlm_del_waiting_lock(lock);
                ldlm_failed_ast(lock, rc, "completion");
        } else if (rc == -EINVAL) {
                LDLM_DEBUG(lock, "lost the race -- client no longer has this "
                           "lock");
        } else if (rc) {
                LDLM_ERROR(lock, "client sent rc %d rq_status %d from "
                           "completion AST", rc, req->rq_status);
                ldlm_lock_cancel(lock);
                /* Server-side AST functions are called from ldlm_reprocess_all,
                 * which needs to be told to please restart its reprocessing. */
                rc = -ERESTART;
        }
        ptlrpc_req_finished(req);

        RETURN(rc);
}

int ldlm_server_glimpse_ast(struct ldlm_lock *lock, void *data)
{
        struct ldlm_resource *res = lock->l_resource;
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        LASSERT(lock != NULL);

        req = ptlrpc_prep_req(lock->l_export->exp_imp_reverse,
                              LDLM_GL_CALLBACK, 1, &size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*body));
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));
        ldlm_lock2desc(lock, &body->lock_desc);

        size = lock->l_resource->lr_lvb_len;
        req->rq_replen = lustre_msg_size(1, &size);

        req->rq_send_state = LUSTRE_IMP_FULL;
        req->rq_timeout = 2; /* 2 second timeout for initial AST reply */

        rc = ptlrpc_queue_wait(req);
        if ((rc == -ETIMEDOUT || rc == -EINTR || rc == -ENOTCONN) &&
            !lock->l_export->exp_libclient) {
                ldlm_del_waiting_lock(lock);
                ldlm_failed_ast(lock, rc, "glimpse");
        } else if (rc == -EINVAL) {
                LDLM_DEBUG(lock, "lost the race -- client no longer has this "
                           "lock");
        } else if (rc == -ELDLM_NO_LOCK_DATA) {
                LDLM_DEBUG(lock, "lost a race -- client has a lock, but no "
                           "inode");
        } else if (rc) {
                LDLM_ERROR(lock, "client sent rc %d rq_status %d from "
                           "glimpse AST", rc, req->rq_status);
        } else {
                rc = res->lr_namespace->ns_lvbo->lvbo_update
                        (res, req->rq_repmsg, 0, 1);
        }
        ptlrpc_req_finished(req);
        RETURN(rc);
}

int ldlm_handle_enqueue(struct ptlrpc_request *req,
                        ldlm_completion_callback completion_callback,
                        ldlm_blocking_callback blocking_callback,
                        ldlm_glimpse_callback glimpse_callback)
{
        struct obd_device *obddev = req->rq_export->exp_obd;
        struct ldlm_reply *dlm_rep;
        struct ldlm_request *dlm_req;
        int rc = 0, size[2] = {sizeof(*dlm_rep)};
        __u32 flags;
        ldlm_error_t err = ELDLM_OK;
        struct ldlm_lock *lock = NULL;
        void *cookie = NULL;
        ENTRY;

        LDLM_DEBUG_NOLOCK("server-side enqueue handler START");

        dlm_req = lustre_swab_reqbuf (req, 0, sizeof (*dlm_req),
                                      lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR ("Can't unpack dlm_req\n");
                GOTO(out, rc = -EFAULT);
        }

        flags = dlm_req->lock_flags;

        /* The lock's callback data might be set in the policy function */
        lock = ldlm_lock_create(obddev->obd_namespace, &dlm_req->lock_handle2,
                                dlm_req->lock_desc.l_resource.lr_name,
                                dlm_req->lock_desc.l_resource.lr_type,
                                dlm_req->lock_desc.l_req_mode,
                                blocking_callback, completion_callback,
                                glimpse_callback, NULL, 0);
        if (!lock)
                GOTO(out, rc = -ENOMEM);

        do_gettimeofday(&lock->l_enqueued_time);
        memcpy(&lock->l_remote_handle, &dlm_req->lock_handle1,
               sizeof(lock->l_remote_handle));
        LDLM_DEBUG(lock, "server-side enqueue handler, new lock created");

        LASSERT(req->rq_export);
        lock->l_export = class_export_get(req->rq_export);
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        list_add(&lock->l_export_chain,
                 &lock->l_export->exp_ldlm_data.led_held_locks);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        if (flags & LDLM_FL_HAS_INTENT) {
                /* In this case, the reply buffer is allocated deep in
                 * local_lock_enqueue by the policy function. */
                cookie = req;
        } else {
                int buffers = 1;
                if (lock->l_resource->lr_lvb_len) {
                        size[1] = lock->l_resource->lr_lvb_len;
                        buffers = 2;
                }

                rc = lustre_pack_reply(req, buffers, size, NULL);
                if (rc)
                        GOTO(out, rc);
        }

        if (dlm_req->lock_desc.l_resource.lr_type != LDLM_PLAIN)
                memcpy(&lock->l_policy_data, &dlm_req->lock_desc.l_policy_data,
                       sizeof(ldlm_policy_data_t));
        if (dlm_req->lock_desc.l_resource.lr_type == LDLM_EXTENT)
                memcpy(&lock->l_req_extent, &lock->l_policy_data.l_extent,
                       sizeof(lock->l_req_extent));

        err = ldlm_lock_enqueue(obddev->obd_namespace, &lock, cookie, &flags);
        if (err)
                GOTO(out, err);

        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*dlm_rep));
        dlm_rep->lock_flags = flags;

        ldlm_lock2desc(lock, &dlm_rep->lock_desc);
        ldlm_lock2handle(lock, &dlm_rep->lock_handle);

        /* We never send a blocking AST until the lock is granted, but
         * we can tell it right now */
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (lock->l_flags & LDLM_FL_AST_SENT) {
                dlm_rep->lock_flags |= LDLM_FL_AST_SENT;
                if (lock->l_granted_mode == lock->l_req_mode)
                        ldlm_add_waiting_lock(lock);
        }
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        EXIT;
 out:
        req->rq_status = err;
        if (req->rq_reply_state == NULL) {
                err = lustre_pack_reply(req, 0, NULL, NULL);
                if (rc == 0)
                        rc = err;
        }

        /* The LOCK_CHANGED code in ldlm_lock_enqueue depends on this
         * ldlm_reprocess_all.  If this moves, revisit that code. -phil */
        if (lock) {
                LDLM_DEBUG(lock, "server-side enqueue handler, sending reply"
                           "(err=%d, rc=%d)", err, rc);

                if (lock->l_resource->lr_lvb_len > 0) {
                        void *lvb = lustre_msg_buf(req->rq_repmsg, 1,
                                                  lock->l_resource->lr_lvb_len);
                        memcpy(lvb, lock->l_resource->lr_lvb_data,
                               lock->l_resource->lr_lvb_len);
                }

                if (!err && dlm_req->lock_desc.l_resource.lr_type != LDLM_FLOCK)
                        ldlm_reprocess_all(lock->l_resource);
                LDLM_LOCK_PUT(lock);
        }
        LDLM_DEBUG_NOLOCK("server-side enqueue handler END (lock %p, rc %d)",
                          lock, rc);

        return rc;
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

        rc = lustre_pack_reply(req, 1, &size, NULL);
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
        struct ldlm_resource *res;
        char str[PTL_NALFMT_SIZE];
        int rc;
        ENTRY;

        dlm_req = lustre_swab_reqbuf(req, 0, sizeof (*dlm_req),
                                      lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR("bad request buffer for cancel\n");
                RETURN(-EFAULT);
        }

        rc = lustre_pack_reply(req, 0, NULL, NULL);
        if (rc) {
                CERROR("out of memory\n");
                RETURN(-ENOMEM);
        }

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                CERROR("received cancel for unknown lock cookie "LPX64
                       " from client %s nid "LPX64" (%s)\n",
                       dlm_req->lock_handle1.cookie,
                       req->rq_export->exp_client_uuid.uuid,
                       req->rq_peer.peer_nid,
                       portals_nid2str(req->rq_peer.peer_ni->pni_number,
                                       req->rq_peer.peer_nid, str));
                LDLM_DEBUG_NOLOCK("server-side cancel handler stale lock "
                                  "(cookie "LPU64")",
                                  dlm_req->lock_handle1.cookie);
                req->rq_status = ESTALE;
        } else {
                LDLM_DEBUG(lock, "server-side cancel handler START");
                res = lock->l_resource;
                if (res && res->lr_namespace->ns_lvbo &&
                    res->lr_namespace->ns_lvbo->lvbo_update) {
                        (void)res->lr_namespace->ns_lvbo->lvbo_update
                                (res, NULL, 0, 0);
                                //(res, req->rq_reqmsg, 1);
                }

                ldlm_lock_cancel(lock);
                if (ldlm_del_waiting_lock(lock))
                        CDEBUG(D_DLMTRACE, "cancelled waiting lock %p\n", lock);
                req->rq_status = rc;
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

void ldlm_handle_bl_callback(struct ldlm_namespace *ns,
                             struct ldlm_lock_desc *ld, struct ldlm_lock *lock)
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
                        l_check_no_ns_lock(ns);
                        lock->l_blocking_ast(lock, ld, lock->l_ast_data,
                                             LDLM_CB_BLOCKING);
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

        if (lock->l_resource->lr_type != LDLM_PLAIN) {
                memcpy(&lock->l_policy_data, &dlm_req->lock_desc.l_policy_data,
                       sizeof(lock->l_policy_data));
                LDLM_DEBUG(lock, "completion AST, new policy data");
        }

        ldlm_resource_unlink_lock(lock);
        if (memcmp(&dlm_req->lock_desc.l_resource.lr_name,
                   &lock->l_resource->lr_name,
                   sizeof(lock->l_resource->lr_name)) != 0) {
                ldlm_lock_change_resource(ns, lock,
                                         dlm_req->lock_desc.l_resource.lr_name);
                LDLM_DEBUG(lock, "completion AST, new resource");
        }

        if (dlm_req->lock_flags & LDLM_FL_AST_SENT) {
                lock->l_flags |= LDLM_FL_CBPENDING;
                LDLM_DEBUG(lock, "completion AST includes blocking AST");
        }

        if (lock->l_lvb_len) {
                void *lvb;
                lvb = lustre_swab_reqbuf(req, 1, lock->l_lvb_len,
                                         lock->l_lvb_swabber);
                if (lvb == NULL) {
                        LDLM_ERROR(lock, "completion AST did not contain "
                                   "expected LVB!");
                } else {
                        memcpy(lock->l_lvb_data, lvb, lock->l_lvb_len);
                }
        }

        lock->l_resource->lr_tmp = &ast_list;
        ldlm_grant_lock(lock, req, sizeof(*req), 1);
        lock->l_resource->lr_tmp = NULL;
        LDLM_DEBUG(lock, "callback handler finished, about to run_ast_work");
        l_unlock(&ns->ns_lock);
        LDLM_LOCK_PUT(lock);

        ldlm_run_ast_work(ns, &ast_list);

        LDLM_DEBUG_NOLOCK("client completion callback handler END (lock %p)",
                          lock);
        EXIT;
}

static void ldlm_handle_gl_callback(struct ptlrpc_request *req,
                                    struct ldlm_namespace *ns,
                                    struct ldlm_request *dlm_req,
                                    struct ldlm_lock *lock)
{
        int rc = -ENOSYS;
        ENTRY;

        l_lock(&ns->ns_lock);
        LDLM_DEBUG(lock, "client glimpse AST callback handler");

        if (lock->l_glimpse_ast != NULL) {
                l_unlock(&ns->ns_lock);
                l_check_no_ns_lock(ns);
                rc = lock->l_glimpse_ast(lock, req);
                l_lock(&ns->ns_lock);
        }

        if (req->rq_repmsg != NULL) {
                ptlrpc_reply(req);
        } else {
                req->rq_status = rc;
                ptlrpc_error(req);
        }

        if (lock->l_granted_mode == LCK_PW &&
            !lock->l_readers && !lock->l_writers &&
            time_after(jiffies, lock->l_last_used + 10 * HZ)) {
                l_unlock(&ns->ns_lock);
                ldlm_handle_bl_callback(ns, NULL, lock);
                EXIT;
                return;
        }

        l_unlock(&ns->ns_lock);
        LDLM_LOCK_PUT(lock);
        EXIT;
}

static int ldlm_callback_reply(struct ptlrpc_request *req, int rc)
{
        req->rq_status = rc;
        if (req->rq_reply_state == NULL) {
                rc = lustre_pack_reply(req, 0, NULL, NULL);
                if (rc)
                        return rc;
        }
        return ptlrpc_reply(req);
}

int ldlm_bl_to_thread(struct ldlm_namespace *ns, struct ldlm_lock_desc *ld,
                      struct ldlm_lock *lock)
{
#ifdef __KERNEL__
        struct ldlm_bl_pool *blp = ldlm_state->ldlm_bl_pool;
        struct ldlm_bl_work_item *blwi;
        ENTRY;

        OBD_ALLOC(blwi, sizeof(*blwi));
        if (blwi == NULL)
                RETURN(-ENOMEM);

        blwi->blwi_ns = ns;
        if (ld != NULL)
                blwi->blwi_ld = *ld;
        blwi->blwi_lock = lock;

        spin_lock(&blp->blp_lock);
        list_add_tail(&blwi->blwi_entry, &blp->blp_list);
        wake_up(&blp->blp_waitq);
        spin_unlock(&blp->blp_lock);
#else
        LBUG();
#endif

        RETURN(0);
}

static int ldlm_callback_handler(struct ptlrpc_request *req)
{
        struct ldlm_namespace *ns;
        struct ldlm_request *dlm_req;
        struct ldlm_lock *lock;
        char str[PTL_NALFMT_SIZE];
        int rc;
        ENTRY;

        /* Requests arrive in sender's byte order.  The ptlrpc service
         * handler has already checked and, if necessary, byte-swapped the
         * incoming request message body, but I am responsible for the
         * message buffers. */

        if (req->rq_export == NULL) {
                struct ldlm_request *dlm_req;

                CDEBUG(D_RPCTRACE, "operation %d from nid "LPX64" (%s) with bad "
                       "export cookie "LPX64" (ptl req %d/rep %d); this is "
                       "normal if this node rebooted with a lock held\n",
                       req->rq_reqmsg->opc, req->rq_peer.peer_nid,
                       portals_nid2str(req->rq_peer.peer_ni->pni_number,
                                       req->rq_peer.peer_nid, str),
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

        LASSERT(req->rq_export != NULL);
        LASSERT(req->rq_export->exp_obd != NULL);

        switch(req->rq_reqmsg->opc) {
        case LDLM_BL_CALLBACK:
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                break;
        case LDLM_CP_CALLBACK:
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CP_CALLBACK, 0);
                break;
        case LDLM_GL_CALLBACK:
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_GL_CALLBACK, 0);
                break;
        case OBD_LOG_CANCEL:
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOG_CANCEL_NET, 0);
                rc = llog_origin_handle_cancel(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case LLOG_ORIGIN_HANDLE_CREATE:
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_create(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_next_block(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_read_header(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case LLOG_ORIGIN_HANDLE_CLOSE:
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_close(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        default:
                CERROR("unknown opcode %u\n", req->rq_reqmsg->opc);
                ldlm_callback_reply(req, -EPROTO);
                RETURN(0);
        }

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

        /* Copy hints/flags (e.g. LDLM_FL_DISCARD_DATA) from AST. */
        lock->l_flags |= (dlm_req->lock_flags & LDLM_AST_FLAGS);

        /* We want the ost thread to get this reply so that it can respond
         * to ost requests (write cache writeback) that might be triggered
         * in the callback.
         *
         * But we'd also like to be able to indicate in the reply that we're
         * cancelling right now, because it's unused, or have an intent result
         * in the reply, so we might have to push the responsibility for sending
         * the reply down into the AST handlers, alas. */

        switch (req->rq_reqmsg->opc) {
        case LDLM_BL_CALLBACK:
                CDEBUG(D_INODE, "blocking ast\n");
#ifdef __KERNEL__
                rc = ldlm_bl_to_thread(ns, &dlm_req->lock_desc, lock);
                ldlm_callback_reply(req, rc);
#else
                rc = 0;
                ldlm_callback_reply(req, rc);
                ldlm_handle_bl_callback(ns, &dlm_req->lock_desc, lock);
#endif
                break;
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "completion ast\n");
                ldlm_callback_reply(req, 0);
                ldlm_handle_cp_callback(req, ns, dlm_req, lock);
                break;
        case LDLM_GL_CALLBACK:
                CDEBUG(D_INODE, "glimpse ast\n");
                ldlm_handle_gl_callback(req, ns, dlm_req, lock);
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

#ifdef __KERNEL__
static struct ldlm_bl_work_item *ldlm_bl_get_work(struct ldlm_bl_pool *blp)
{
        struct ldlm_bl_work_item *blwi = NULL;

        spin_lock(&blp->blp_lock);
        if (!list_empty(&blp->blp_list)) {
                blwi = list_entry(blp->blp_list.next, struct ldlm_bl_work_item,
                                  blwi_entry);
                list_del(&blwi->blwi_entry);
        }
        spin_unlock(&blp->blp_lock);

        return blwi;
}

struct ldlm_bl_thread_data {
        int                     bltd_num;
        struct ldlm_bl_pool     *bltd_blp;
};

static int ldlm_bl_thread_main(void *arg)
{
        struct ldlm_bl_thread_data *bltd = arg;
        struct ldlm_bl_pool *blp = bltd->bltd_blp;
        unsigned long flags;
        ENTRY;

        /* XXX boiler-plate */
        {
                char name[sizeof(current->comm)];
                snprintf(name, sizeof(name) - 1, "ldlm_bl_%02d",
                         bltd->bltd_num);
                kportal_daemonize(name);
        }
        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        atomic_inc(&blp->blp_num_threads);
        complete(&blp->blp_comp);

        while(1) {
                struct l_wait_info lwi = { 0 };
                struct ldlm_bl_work_item *blwi = NULL;

                l_wait_event_exclusive(blp->blp_waitq,
                                       (blwi = ldlm_bl_get_work(blp)) != NULL,
                                       &lwi);

                if (blwi->blwi_ns == NULL)
                        break;

                ldlm_handle_bl_callback(blwi->blwi_ns, &blwi->blwi_ld,
                                        blwi->blwi_lock);
                OBD_FREE(blwi, sizeof(*blwi));
        }

        atomic_dec(&blp->blp_num_threads);
        complete(&blp->blp_comp);
        RETURN(0);
}

#endif

static int ldlm_setup(void);
static int ldlm_cleanup(int force);

int ldlm_get_ref(void)
{
        int rc = 0;
        down(&ldlm_ref_sem);
        if (++ldlm_refcount == 1) {
                rc = ldlm_setup();
                if (rc)
                        ldlm_refcount--;
        }
        up(&ldlm_ref_sem);

        RETURN(rc);
}

void ldlm_put_ref(int force)
{
        down(&ldlm_ref_sem);
        if (ldlm_refcount == 1) {
                int rc = ldlm_cleanup(force);
                if (rc)
                        CERROR("ldlm_cleanup failed: %d\n", rc);
                else
                        ldlm_refcount--;
        } else {
                ldlm_refcount--;
        }
        up(&ldlm_ref_sem);

        EXIT;
}

static int ldlm_setup(void)
{
        struct ldlm_bl_pool *blp;
        int rc = 0;
#ifdef __KERNEL__
        int i;
#endif
        ENTRY;

        if (ldlm_state != NULL)
                RETURN(-EALREADY);

        OBD_ALLOC(ldlm_state, sizeof(*ldlm_state));
        if (ldlm_state == NULL)
                RETURN(-ENOMEM);

#ifdef __KERNEL__
        rc = ldlm_proc_setup();
        if (rc != 0)
                GOTO(out_free, rc);
#endif

        ldlm_state->ldlm_cb_service =
                ptlrpc_init_svc(LDLM_NBUFS, LDLM_BUFSIZE, LDLM_MAXREQSIZE,
                                LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                                ldlm_callback_handler, "ldlm_cbd",
                                ldlm_svc_proc_dir);

        if (!ldlm_state->ldlm_cb_service) {
                CERROR("failed to start service\n");
                GOTO(out_proc, rc = -ENOMEM);
        }

        ldlm_state->ldlm_cancel_service =
                ptlrpc_init_svc(LDLM_NBUFS, LDLM_BUFSIZE, LDLM_MAXREQSIZE,
                                LDLM_CANCEL_REQUEST_PORTAL,
                                LDLM_CANCEL_REPLY_PORTAL,
                                ldlm_cancel_handler, "ldlm_canceld",
                                ldlm_svc_proc_dir);

        if (!ldlm_state->ldlm_cancel_service) {
                CERROR("failed to start service\n");
                GOTO(out_proc, rc = -ENOMEM);
        }

        OBD_ALLOC(blp, sizeof(*blp));
        if (blp == NULL)
                GOTO(out_proc, rc = -ENOMEM);
        ldlm_state->ldlm_bl_pool = blp;

        atomic_set(&blp->blp_num_threads, 0);
        init_waitqueue_head(&blp->blp_waitq);
        spin_lock_init(&blp->blp_lock);

        INIT_LIST_HEAD(&blp->blp_list);

#ifdef __KERNEL__
        for (i = 0; i < LDLM_NUM_THREADS; i++) {
                struct ldlm_bl_thread_data bltd = {
                        .bltd_num = i,
                        .bltd_blp = blp,
                };
                init_completion(&blp->blp_comp);
                rc = kernel_thread(ldlm_bl_thread_main, &bltd, 0);
                if (rc < 0) {
                        CERROR("cannot start LDLM thread #%d: rc %d\n", i, rc);
                        LBUG();
                        GOTO(out_thread, rc);
                }
                wait_for_completion(&blp->blp_comp);
        }

        rc = ptlrpc_start_n_threads(NULL, ldlm_state->ldlm_cancel_service,
                                    LDLM_NUM_THREADS, "ldlm_cn");
        if (rc) {
                LBUG();
                GOTO(out_thread, rc);
        }

        rc = ptlrpc_start_n_threads(NULL, ldlm_state->ldlm_cb_service,
                                    LDLM_NUM_THREADS, "ldlm_cb");
        if (rc) {
                LBUG();
                GOTO(out_thread, rc);
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

        RETURN(0);

#ifdef __KERNEL__
 out_thread:
        ptlrpc_unregister_service(ldlm_state->ldlm_cancel_service);
        ptlrpc_unregister_service(ldlm_state->ldlm_cb_service);
#endif

 out_proc:
#ifdef __KERNEL__
        ldlm_proc_cleanup();
 out_free:
#endif
        OBD_FREE(ldlm_state, sizeof(*ldlm_state));
        ldlm_state = NULL;
        return rc;
}

static int ldlm_cleanup(int force)
{
#ifdef __KERNEL__
        struct ldlm_bl_pool *blp = ldlm_state->ldlm_bl_pool;
#endif
        ENTRY;

        if (!list_empty(&ldlm_namespace_list)) {
                CERROR("ldlm still has namespaces; clean these up first.\n");
                ldlm_dump_all_namespaces();
                RETURN(-EBUSY);
        }

#ifdef __KERNEL__
        while (atomic_read(&blp->blp_num_threads) > 0) {
                struct ldlm_bl_work_item blwi = { .blwi_ns = NULL };

                init_completion(&blp->blp_comp);

                spin_lock(&blp->blp_lock);
                list_add_tail(&blwi.blwi_entry, &blp->blp_list);
                wake_up(&blp->blp_waitq);
                spin_unlock(&blp->blp_lock);

                wait_for_completion(&blp->blp_comp);
        }
        OBD_FREE(blp, sizeof(*blp));

        ptlrpc_stop_all_threads(ldlm_state->ldlm_cb_service);
        ptlrpc_unregister_service(ldlm_state->ldlm_cb_service);
        ptlrpc_stop_all_threads(ldlm_state->ldlm_cancel_service);
        ptlrpc_unregister_service(ldlm_state->ldlm_cancel_service);
        ldlm_proc_cleanup();

        expired_lock_thread.elt_state = ELT_TERMINATE;
        wake_up(&expired_lock_thread.elt_waitq);
        wait_event(expired_lock_thread.elt_waitq,
                   expired_lock_thread.elt_state == ELT_STOPPED);

#endif

        OBD_FREE(ldlm_state, sizeof(*ldlm_state));
        ldlm_state = NULL;

        RETURN(0);
}

int __init ldlm_init(void)
{
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

void __exit ldlm_exit(void)
{
        if ( ldlm_refcount )
                CERROR("ldlm_refcount is %d in ldlm_exit!\n", ldlm_refcount);
        if (kmem_cache_destroy(ldlm_resource_slab) != 0)
                CERROR("couldn't free ldlm resource slab\n");
        if (kmem_cache_destroy(ldlm_lock_slab) != 0)
                CERROR("couldn't free ldlm lock slab\n");
}

/* ldlm_flock.c */
EXPORT_SYMBOL(ldlm_flock_completion_ast);

/* ldlm_extent.c */
EXPORT_SYMBOL(ldlm_extent_shift_kms);

/* ldlm_lock.c */
EXPORT_SYMBOL(ldlm_get_processing_policy);
EXPORT_SYMBOL(ldlm_lock2desc);
EXPORT_SYMBOL(ldlm_register_intent);
EXPORT_SYMBOL(ldlm_lockname);
EXPORT_SYMBOL(ldlm_typename);
EXPORT_SYMBOL(ldlm_lock2handle);
EXPORT_SYMBOL(__ldlm_handle2lock);
EXPORT_SYMBOL(ldlm_lock_get);
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
EXPORT_SYMBOL(ldlm_lock_allow_match);

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
EXPORT_SYMBOL(ldlm_change_cbdata);

/* ldlm_lockd.c */
EXPORT_SYMBOL(ldlm_server_blocking_ast);
EXPORT_SYMBOL(ldlm_server_completion_ast);
EXPORT_SYMBOL(ldlm_server_glimpse_ast);
EXPORT_SYMBOL(ldlm_handle_enqueue);
EXPORT_SYMBOL(ldlm_handle_cancel);
EXPORT_SYMBOL(ldlm_handle_convert);
EXPORT_SYMBOL(ldlm_del_waiting_lock);
EXPORT_SYMBOL(ldlm_get_ref);
EXPORT_SYMBOL(ldlm_put_ref);

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
EXPORT_SYMBOL(ldlm_dump_all_namespaces);
EXPORT_SYMBOL(ldlm_resource_get);
EXPORT_SYMBOL(ldlm_resource_putref);

/* l_lock.c */
EXPORT_SYMBOL(l_lock);
EXPORT_SYMBOL(l_unlock);

/* ldlm_lib.c */
EXPORT_SYMBOL(client_obd_setup);
EXPORT_SYMBOL(client_obd_cleanup);
EXPORT_SYMBOL(client_connect_import);
EXPORT_SYMBOL(client_disconnect_export);
EXPORT_SYMBOL(target_abort_recovery);
EXPORT_SYMBOL(target_handle_connect);
EXPORT_SYMBOL(target_destroy_export);
EXPORT_SYMBOL(target_cancel_recovery_timer);
EXPORT_SYMBOL(target_send_reply);
EXPORT_SYMBOL(target_queue_recovery_request);
EXPORT_SYMBOL(target_handle_ping);
EXPORT_SYMBOL(target_handle_disconnect);
EXPORT_SYMBOL(target_queue_final_reply);
