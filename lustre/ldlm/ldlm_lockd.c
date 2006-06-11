/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002-2004 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LDLM

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else
# include <liblustre.h>
#endif

#include <lustre_dlm.h>
#include <obd_class.h>
#include <libcfs/list.h>
#include "ldlm_internal.h"

extern cfs_mem_cache_t *ldlm_resource_slab;
extern cfs_mem_cache_t *ldlm_lock_slab;
extern struct lustre_lock ldlm_handle_lock;
extern struct list_head ldlm_namespace_list;

extern struct semaphore ldlm_namespace_lock;
static struct semaphore ldlm_ref_sem;
static int ldlm_refcount;

/* LDLM state */

static struct ldlm_state *ldlm_state;

inline cfs_time_t round_timeout(cfs_time_t timeout)
{
        return cfs_time_seconds((int)cfs_duration_sec(cfs_time_sub(timeout, 0)) + 1);
}

/* timeout for initial callback (AST) reply */
static inline unsigned int ldlm_get_rq_timeout(unsigned int ldlm_timeout, unsigned int obd_timeout)
{
        return max(min(ldlm_timeout, obd_timeout / 3), 1U);
}

#ifdef __KERNEL__
/* w_l_spinlock protects both waiting_locks_list and expired_lock_thread */
static spinlock_t waiting_locks_spinlock;
static struct list_head waiting_locks_list;
static cfs_timer_t waiting_locks_timer;

static struct expired_lock_thread {
        cfs_waitq_t               elt_waitq;
        int                       elt_state;
        int                       elt_dump;
        struct list_head          elt_expired_locks;
} expired_lock_thread;
#endif

#define ELT_STOPPED   0
#define ELT_READY     1
#define ELT_TERMINATE 2

struct ldlm_bl_pool {
        spinlock_t              blp_lock;
        struct list_head        blp_list;
        cfs_waitq_t             blp_waitq;
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

        ENTRY;
        spin_lock_bh(&waiting_locks_spinlock);
        need_to_run = !list_empty(&expired_lock_thread.elt_expired_locks);
        spin_unlock_bh(&waiting_locks_spinlock);

        RETURN(need_to_run);
}

static int expired_lock_main(void *arg)
{
        struct list_head *expired = &expired_lock_thread.elt_expired_locks;
        struct l_wait_info lwi = { 0 };

        ENTRY;
        cfs_daemonize("ldlm_elt");

        expired_lock_thread.elt_state = ELT_READY;
        cfs_waitq_signal(&expired_lock_thread.elt_waitq);

        while (1) {
                l_wait_event(expired_lock_thread.elt_waitq,
                             have_expired_locks() ||
                             expired_lock_thread.elt_state == ELT_TERMINATE,
                             &lwi);

                spin_lock_bh(&waiting_locks_spinlock);
                if (expired_lock_thread.elt_dump) {
                        spin_unlock_bh(&waiting_locks_spinlock);

                        /* from waiting_locks_callback, but not in timer */
                        libcfs_debug_dumplog();
                        libcfs_run_lbug_upcall(__FILE__,
                                                "waiting_locks_callback",
                                                expired_lock_thread.elt_dump);

                        spin_lock_bh(&waiting_locks_spinlock);
                        expired_lock_thread.elt_dump = 0;
                }

                while (!list_empty(expired)) {
                        struct obd_export *export;
                        struct ldlm_lock *lock;

                        lock = list_entry(expired->next, struct ldlm_lock,
                                          l_pending_chain);
                        if ((void *)lock < LP_POISON + PAGE_SIZE &&
                            (void *)lock >= LP_POISON) {
                                spin_unlock_bh(&waiting_locks_spinlock);
                                CERROR("free lock on elt list %p\n", lock);
                                LBUG();
                        }
                        list_del_init(&lock->l_pending_chain);
                        if ((void *)lock->l_export < LP_POISON + PAGE_SIZE &&
                            (void *)lock->l_export >= LP_POISON) {
                                CERROR("lock with free export on elt list %p\n",
                                       lock->l_export);
                                lock->l_export = NULL;
                                LDLM_ERROR(lock, "free export");
                                continue;
                        }
                        export = class_export_get(lock->l_export);
                        spin_unlock_bh(&waiting_locks_spinlock);

                        class_fail_export(export);
                        class_export_put(export);
                        spin_lock_bh(&waiting_locks_spinlock);
                }
                spin_unlock_bh(&waiting_locks_spinlock);

                if (expired_lock_thread.elt_state == ELT_TERMINATE)
                        break;
        }

        expired_lock_thread.elt_state = ELT_STOPPED;
        cfs_waitq_signal(&expired_lock_thread.elt_waitq);
        RETURN(0);
}

/* This is called from within a timer interrupt and cannot schedule */
static void waiting_locks_callback(unsigned long unused)
{
        struct ldlm_lock *lock, *last = NULL;

        spin_lock_bh(&waiting_locks_spinlock);
        while (!list_empty(&waiting_locks_list)) {
                lock = list_entry(waiting_locks_list.next, struct ldlm_lock,
                                  l_pending_chain);

                if (cfs_time_after(lock->l_callback_timeout, cfs_time_current()) ||
                    (lock->l_req_mode == LCK_GROUP))
                        break;

                LDLM_ERROR(lock, "lock callback timer expired: evicting client "
                           "%s@%s nid %s ",lock->l_export->exp_client_uuid.uuid,
                           lock->l_export->exp_connection->c_remote_uuid.uuid,
                           libcfs_nid2str(lock->l_export->exp_connection->c_peer.nid));

                if (lock == last) {
                        LDLM_ERROR(lock, "waiting on lock multiple times");
                        CERROR("wll %p n/p %p/%p, l_pending %p n/p %p/%p\n",
                               &waiting_locks_list,
                               waiting_locks_list.next, waiting_locks_list.prev,
                               &lock->l_pending_chain,
                               lock->l_pending_chain.next,
                               lock->l_pending_chain.prev);

                        CFS_INIT_LIST_HEAD(&waiting_locks_list);    /* HACK */
                        expired_lock_thread.elt_dump = __LINE__;

                        /* LBUG(); */
                        CEMERG("would be an LBUG, but isn't (bug 5653)\n");
                        libcfs_debug_dumpstack(NULL);
                        /*blocks* libcfs_debug_dumplog(); */
                        /*blocks* libcfs_run_lbug_upcall(file, func, line); */
                        break;
                }
                last = lock;

                list_del(&lock->l_pending_chain);
                list_add(&lock->l_pending_chain,
                         &expired_lock_thread.elt_expired_locks);
        }

        if (!list_empty(&expired_lock_thread.elt_expired_locks)) {
                if (obd_dump_on_timeout)
                        expired_lock_thread.elt_dump = __LINE__;

                cfs_waitq_signal(&expired_lock_thread.elt_waitq);
        }

        /*
         * Make sure the timer will fire again if we have any locks
         * left.
         */
        if (!list_empty(&waiting_locks_list)) {
                cfs_time_t timeout_rounded;
                lock = list_entry(waiting_locks_list.next, struct ldlm_lock,
                                  l_pending_chain);
                timeout_rounded = (cfs_time_t)round_timeout(lock->l_callback_timeout);
                cfs_timer_arm(&waiting_locks_timer, timeout_rounded);
        }
        spin_unlock_bh(&waiting_locks_spinlock);
}

/*
 * Indicate that we're waiting for a client to call us back cancelling a given
 * lock.  We add it to the pending-callback chain, and schedule the lock-timeout
 * timer to fire appropriately.  (We round up to the next second, to avoid
 * floods of timer firings during periods of high lock contention and traffic).
 *
 * Called with the namespace lock held.
 */
static int __ldlm_add_waiting_lock(struct ldlm_lock *lock)
{
        cfs_time_t timeout_rounded;

        if (!list_empty(&lock->l_pending_chain))
                return 0;

        lock->l_callback_timeout =cfs_time_add(cfs_time_current(),
                                               cfs_time_seconds(obd_timeout)/2);

        timeout_rounded = round_timeout(lock->l_callback_timeout);

        if (cfs_time_before(timeout_rounded, cfs_timer_deadline(&waiting_locks_timer)) ||
            !cfs_timer_is_armed(&waiting_locks_timer)) {
                cfs_timer_arm(&waiting_locks_timer, timeout_rounded);

        }
        list_add_tail(&lock->l_pending_chain, &waiting_locks_list); /* FIFO */
        return 1;
}

static int ldlm_add_waiting_lock(struct ldlm_lock *lock)
{
        int ret;

        l_check_ns_lock(lock->l_resource->lr_namespace);
        LASSERT(!(lock->l_flags & LDLM_FL_CANCEL_ON_BLOCK));

        spin_lock_bh(&waiting_locks_spinlock);
        if (lock->l_destroyed) {
                static cfs_time_t next;
                spin_unlock_bh(&waiting_locks_spinlock);
                LDLM_ERROR(lock, "not waiting on destroyed lock (bug 5653)");
                if (cfs_time_after(cfs_time_current(), next)) {
                        next = cfs_time_shift(14400);
                        libcfs_debug_dumpstack(NULL);
                }
                return 0;
        }

        ret = __ldlm_add_waiting_lock(lock);
        spin_unlock_bh(&waiting_locks_spinlock);

        LDLM_DEBUG(lock, "%sadding to wait list",
                   ret == 0 ? "not re-" : "");
        return ret;
}

/*
 * Remove a lock from the pending list, likely because it had its cancellation
 * callback arrive without incident.  This adjusts the lock-timeout timer if
 * needed.  Returns 0 if the lock wasn't pending after all, 1 if it was.
 *
 * Called with namespace lock held.
 */
int __ldlm_del_waiting_lock(struct ldlm_lock *lock)
{
        struct list_head *list_next;

        if (list_empty(&lock->l_pending_chain))
                return 0;

        list_next = lock->l_pending_chain.next;
        if (lock->l_pending_chain.prev == &waiting_locks_list) {
                /* Removing the head of the list, adjust timer. */
                if (list_next == &waiting_locks_list) {
                        /* No more, just cancel. */
                        cfs_timer_disarm(&waiting_locks_timer);
                } else {
                        struct ldlm_lock *next;
                        next = list_entry(list_next, struct ldlm_lock,
                                          l_pending_chain);
                        cfs_timer_arm(&waiting_locks_timer,
                                      round_timeout(next->l_callback_timeout));
                }
        }
        list_del_init(&lock->l_pending_chain);

        return 1;
}

int ldlm_del_waiting_lock(struct ldlm_lock *lock)
{
        int ret;

        l_check_ns_lock(lock->l_resource->lr_namespace);

        if (lock->l_export == NULL) {
                /* We don't have a "waiting locks list" on clients. */
                LDLM_DEBUG(lock, "client lock: no-op");
                return 0;
        }

        spin_lock_bh(&waiting_locks_spinlock);
        ret = __ldlm_del_waiting_lock(lock);
        spin_unlock_bh(&waiting_locks_spinlock);

        LDLM_DEBUG(lock, "%s", ret == 0 ? "wasn't waiting" : "removed");
        return ret;
}

/*
 * Prolong the lock
 * 
 * Called with namespace lock held.
 */
int ldlm_refresh_waiting_lock(struct ldlm_lock *lock)
{
        l_check_ns_lock(lock->l_resource->lr_namespace);

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

        __ldlm_del_waiting_lock(lock);
        __ldlm_add_waiting_lock(lock);
        spin_unlock_bh(&waiting_locks_spinlock);

        LDLM_DEBUG(lock, "refreshed");
        return 1;
}

#else /* !__KERNEL__ */

static int ldlm_add_waiting_lock(struct ldlm_lock *lock)
{
        LASSERT(!(lock->l_flags & LDLM_FL_CANCEL_ON_BLOCK));
        RETURN(1);
}

int ldlm_del_waiting_lock(struct ldlm_lock *lock)
{
        RETURN(0);
}

int ldlm_refresh_waiting_lock(struct ldlm_lock *lock)
{
        RETURN(0);
}
#endif /* __KERNEL__ */

static void ldlm_failed_ast(struct ldlm_lock *lock, int rc,
                            const char *ast_type)
{
        struct ptlrpc_connection *conn = lock->l_export->exp_connection;
        char                     *str = libcfs_nid2str(conn->c_peer.nid);

        LCONSOLE_ERROR("A client on nid %s was evicted from service %s.\n",
                       str, lock->l_export->exp_obd->obd_name);

        LDLM_ERROR(lock, "%s AST failed (%d): evicting client %s@%s NID %s"
                   " (%s)", ast_type, rc, lock->l_export->exp_client_uuid.uuid,
                   conn->c_remote_uuid.uuid, libcfs_nid2str(conn->c_peer.nid),
                   str);

        if (obd_dump_on_timeout)
                libcfs_debug_dumplog();
        class_fail_export(lock->l_export);
}

static int ldlm_handle_ast_error(struct ldlm_lock *lock,
                                 struct ptlrpc_request *req, int rc,
                                 const char *ast_type)
{
        lnet_process_id_t peer = req->rq_import->imp_connection->c_peer;

        if (rc == -ETIMEDOUT || rc == -EINTR || rc == -ENOTCONN) {
                LASSERT(lock->l_export);
                if (lock->l_export->exp_libclient) {
                        LDLM_DEBUG(lock, "%s AST to liblustre client (nid %s)"
                                   " timeout, just cancelling lock", ast_type,
                                   libcfs_nid2str(peer.nid));
                        ldlm_lock_cancel(lock);
                        rc = -ERESTART;
                } else if (lock->l_flags & LDLM_FL_CANCEL) {
                        LDLM_DEBUG(lock, "%s AST timeout from nid %s, but "
                                   "cancel was received (AST reply lost?)",
                                   ast_type, libcfs_nid2str(peer.nid));
                        ldlm_lock_cancel(lock);
                        rc = -ERESTART;
                } else {
                        l_lock(&lock->l_resource->lr_namespace->ns_lock);
                        ldlm_del_waiting_lock(lock);
                        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                        ldlm_failed_ast(lock, rc, ast_type);
                }
        } else if (rc) {
                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                if (rc == -EINVAL)
                        LDLM_DEBUG(lock, "client (nid %s) returned %d"
                                   " from %s AST - normal race",
                                   libcfs_nid2str(peer.nid),
                                   lustre_msg_get_status(req->rq_repmsg),
                                   ast_type);
                else
                        LDLM_ERROR(lock, "client (nid %s) returned %d "
                                   "from %s AST", libcfs_nid2str(peer.nid),
                                   (req->rq_repmsg != NULL) ?
                                   lustre_msg_get_status(req->rq_repmsg) : 0,
                                   ast_type);
                ldlm_lock_cancel(lock);
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                /* Server-side AST functions are called from ldlm_reprocess_all,
                 * which needs to be told to please restart its reprocessing. */
                rc = -ERESTART;
        }

        return rc;
}

int ldlm_server_blocking_ast(struct ldlm_lock *lock,
                             struct ldlm_lock_desc *desc,
                             void *data, int flag)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        int size[] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                       [DLM_LOCKREQ_OFF]     = sizeof(*body) };
        int instant_cancel = 0, rc = 0;
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
                LDLM_DEBUG(lock, "lock not granted, not sending blocking AST");
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

        if (lock->l_destroyed) {
                /* What's the point? */
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

#if 0
        if (CURRENT_SECONDS - lock->l_export->exp_last_request_time > 30){
                ldlm_failed_ast(lock, -ETIMEDOUT, "Not-attempted blocking");
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(-ETIMEDOUT);
        }
#endif

        if (lock->l_flags & LDLM_FL_CANCEL_ON_BLOCK)
                instant_cancel = 1;

        req = ptlrpc_prep_req(lock->l_export->exp_imp_reverse,
                              LUSTRE_DLM_VERSION, LDLM_BL_CALLBACK, 2, size,
                              NULL);
        if (req == NULL) {
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(-ENOMEM);
        }

        body = lustre_msg_buf(req->rq_reqmsg, DLM_LOCKREQ_OFF, sizeof(*body));
        body->lock_handle1 = lock->l_remote_handle;
        body->lock_desc = *desc;
        body->lock_flags |= (lock->l_flags & LDLM_AST_FLAGS);

        LDLM_DEBUG(lock, "server preparing blocking AST");
        ptlrpc_req_set_repsize(req, 1, NULL);
        if (instant_cancel)
                ldlm_lock_cancel(lock);
        else if (lock->l_granted_mode == lock->l_req_mode)
                ldlm_add_waiting_lock(lock);

        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        req->rq_send_state = LUSTRE_IMP_FULL;
        req->rq_timeout = ldlm_get_rq_timeout(ldlm_timeout, obd_timeout); /* timeout for initial AST reply */
        if (unlikely(instant_cancel)) {
                rc = ptl_send_rpc(req, 1);
        } else {
                rc = ptlrpc_queue_wait(req);
        }
        if (rc != 0)
                rc = ldlm_handle_ast_error(lock, req, rc, "blocking");

        ptlrpc_req_finished(req);

        /* If we cancelled the lock, we need to restart ldlm_reprocess_queue */
        if (!rc && instant_cancel)
                rc = -ERESTART;

        RETURN(rc);
}

int ldlm_server_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        struct timeval granted_time;
        long total_enqueue_wait;
        int size[3] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREQ_OFF]     = sizeof(*body) };
        int rc = 0, buffers = 2, instant_cancel = 0;
        ENTRY;

        LASSERT(lock != NULL);

        do_gettimeofday(&granted_time);
        total_enqueue_wait = cfs_timeval_sub(&granted_time,
                                             &lock->l_enqueued_time, NULL);

        if (total_enqueue_wait / 1000000 > obd_timeout)
                LDLM_ERROR(lock, "enqueue wait took %luus from %lu",
                           total_enqueue_wait, lock->l_enqueued_time.tv_sec);

        mutex_down(&lock->l_resource->lr_lvb_sem);
        if (lock->l_resource->lr_lvb_len) {
                size[DLM_REQ_REC_OFF] = lock->l_resource->lr_lvb_len;
                buffers = 3;
        }
        mutex_up(&lock->l_resource->lr_lvb_sem);

        req = ptlrpc_prep_req(lock->l_export->exp_imp_reverse,
                              LUSTRE_DLM_VERSION, LDLM_CP_CALLBACK, buffers,
                              size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, DLM_LOCKREQ_OFF, sizeof(*body));
        body->lock_handle1 = lock->l_remote_handle;
        body->lock_flags = flags;
        ldlm_lock2desc(lock, &body->lock_desc);

        if (buffers == 3) {
                void *lvb;

                mutex_down(&lock->l_resource->lr_lvb_sem);
                lvb = lustre_msg_buf(req->rq_reqmsg, DLM_REQ_REC_OFF,
                                     lock->l_resource->lr_lvb_len);
                memcpy(lvb, lock->l_resource->lr_lvb_data,
                       lock->l_resource->lr_lvb_len);
                mutex_up(&lock->l_resource->lr_lvb_sem);
        }

        LDLM_DEBUG(lock, "server preparing completion AST (after %ldus wait)",
                   total_enqueue_wait);
        ptlrpc_req_set_repsize(req, 1, NULL);

        req->rq_send_state = LUSTRE_IMP_FULL;
        req->rq_timeout = ldlm_get_rq_timeout(ldlm_timeout, obd_timeout); /* timeout for initial AST reply */

        /* We only send real blocking ASTs after the lock is granted */
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (lock->l_flags & LDLM_FL_AST_SENT) {
                body->lock_flags |= LDLM_FL_AST_SENT;

                /* We might get here prior to ldlm_handle_enqueue setting
                 * LDLM_FL_CANCEL_ON_BLOCK flag. Then we will put this lock
                 * into waiting list, but this is safe and similar code in
                 * ldlm_handle_enqueue will call ldlm_lock_cancel() still,
                 * that would not only cancel the lock, but will also remove
                 * it from waiting list */
                if (lock->l_flags & LDLM_FL_CANCEL_ON_BLOCK) {
                        ldlm_lock_cancel(lock);
                        instant_cancel = 1;
                } else {
                        ldlm_add_waiting_lock(lock); /* start the lock-timeout
                                                         clock */
                }
        }
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        rc = ptlrpc_queue_wait(req);
        if (rc != 0)
                rc = ldlm_handle_ast_error(lock, req, rc, "completion");

        ptlrpc_req_finished(req);

        /* If we cancelled the lock, we need to restart ldlm_reprocess_queue */
        if (!rc && instant_cancel)
                rc = -ERESTART;

        RETURN(rc);
}

int ldlm_server_glimpse_ast(struct ldlm_lock *lock, void *data)
{
        struct ldlm_resource *res = lock->l_resource;
        struct ldlm_request *body;
        struct ptlrpc_request *req;
        int size[] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                       [DLM_LOCKREQ_OFF]     = sizeof(*body) };
        int rc = 0;
        ENTRY;

        LASSERT(lock != NULL);

        req = ptlrpc_prep_req(lock->l_export->exp_imp_reverse,
                              LUSTRE_DLM_VERSION, LDLM_GL_CALLBACK, 2, size,
                              NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, DLM_LOCKREQ_OFF, sizeof(*body));
        body->lock_handle1 = lock->l_remote_handle;
        ldlm_lock2desc(lock, &body->lock_desc);

        mutex_down(&lock->l_resource->lr_lvb_sem);
        size[REPLY_REC_OFF] = lock->l_resource->lr_lvb_len;
        mutex_up(&lock->l_resource->lr_lvb_sem);
        ptlrpc_req_set_repsize(req, 2, size);

        req->rq_send_state = LUSTRE_IMP_FULL;
        req->rq_timeout = ldlm_get_rq_timeout(ldlm_timeout, obd_timeout); /* timeout for initial AST reply */

        rc = ptlrpc_queue_wait(req);
        if (rc == -ELDLM_NO_LOCK_DATA)
                LDLM_DEBUG(lock, "lost race - client has a lock but no inode");
        else if (rc != 0)
                rc = ldlm_handle_ast_error(lock, req, rc, "glimpse");
        else
                rc = res->lr_namespace->ns_lvbo->lvbo_update
                        (res, req->rq_repmsg, REPLY_REC_OFF, 1);
        ptlrpc_req_finished(req);
        RETURN(rc);
}

static struct ldlm_lock *
find_existing_lock(struct obd_export *exp, struct lustre_handle *remote_hdl)
{
        struct obd_device *obd = exp->exp_obd;
        struct list_head *iter;

        l_lock(&obd->obd_namespace->ns_lock);
        list_for_each(iter, &exp->exp_ldlm_data.led_held_locks) {
                struct ldlm_lock *lock;
                lock = list_entry(iter, struct ldlm_lock, l_export_chain);
                if (lock->l_remote_handle.cookie == remote_hdl->cookie) {
                        LDLM_LOCK_GET(lock);
                        l_unlock(&obd->obd_namespace->ns_lock);
                        return lock;
                }
        }
        l_unlock(&obd->obd_namespace->ns_lock);
        return NULL;
}


/*
 * Main server-side entry point into LDLM. This is called by ptlrpc service
 * threads to carry out client lock enqueueing requests.
 */
int ldlm_handle_enqueue(struct ptlrpc_request *req,
                        ldlm_completion_callback completion_callback,
                        ldlm_blocking_callback blocking_callback,
                        ldlm_glimpse_callback glimpse_callback)
{
        struct obd_device *obddev = req->rq_export->exp_obd;
        struct ldlm_reply *dlm_rep;
        struct ldlm_request *dlm_req;
        int size[3] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREPLY_OFF]   = sizeof(*dlm_rep) };
        int rc = 0;
        __u32 flags;
        ldlm_error_t err = ELDLM_OK;
        struct ldlm_lock *lock = NULL;
        void *cookie = NULL;
        ENTRY;

        LDLM_DEBUG_NOLOCK("server-side enqueue handler START");

        dlm_req = lustre_swab_reqbuf(req, DLM_LOCKREQ_OFF, sizeof(*dlm_req),
                                     lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR ("Can't unpack dlm_req\n");
                GOTO(out, rc = -EFAULT);
        }

        flags = dlm_req->lock_flags;

        LASSERT(req->rq_export);

        if (dlm_req->lock_desc.l_resource.lr_type < LDLM_MIN_TYPE ||
            dlm_req->lock_desc.l_resource.lr_type >= LDLM_MAX_TYPE) {
                DEBUG_REQ(D_ERROR, req, "invalid lock request type %d\n",
                          dlm_req->lock_desc.l_resource.lr_type);
                GOTO(out, rc = -EFAULT);
        }

        if (dlm_req->lock_desc.l_req_mode <= LCK_MINMODE ||
            dlm_req->lock_desc.l_req_mode >= LCK_MAXMODE ||
            dlm_req->lock_desc.l_req_mode & (dlm_req->lock_desc.l_req_mode-1)) {
                DEBUG_REQ(D_ERROR, req, "invalid lock request mode %d\n",
                          dlm_req->lock_desc.l_req_mode);
                GOTO(out, rc = -EFAULT);
        }

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_IBITS) {
                if (dlm_req->lock_desc.l_resource.lr_type == LDLM_PLAIN) {
                        DEBUG_REQ(D_ERROR, req,
                                  "PLAIN lock request from IBITS client?\n");
                        GOTO(out, rc = -EPROTO);
                }
        } else if (dlm_req->lock_desc.l_resource.lr_type == LDLM_IBITS) {
                DEBUG_REQ(D_ERROR, req,
                          "IBITS lock request from unaware client?\n");
                GOTO(out, rc = -EPROTO);
        }

#if 0
        /* FIXME this makes it impossible to use LDLM_PLAIN locks -- check 
           against server's _CONNECT_SUPPORTED flags? (I don't want to use
           ibits for mgc/mgs) */

        /* INODEBITS_INTEROP: Perform conversion from plain lock to
         * inodebits lock if client does not support them. */
        if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_IBITS) &&
            (dlm_req->lock_desc.l_resource.lr_type == LDLM_PLAIN)) {
                dlm_req->lock_desc.l_resource.lr_type = LDLM_IBITS;
                dlm_req->lock_desc.l_policy_data.l_inodebits.bits =
                        MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE;
                if (dlm_req->lock_desc.l_req_mode == LCK_PR)
                        dlm_req->lock_desc.l_req_mode = LCK_CR;
        }
#endif

        if (flags & LDLM_FL_REPLAY) {
                lock = find_existing_lock(req->rq_export,
                                          &dlm_req->lock_handle1);
                if (lock != NULL) {
                        DEBUG_REQ(D_HA, req, "found existing lock cookie "LPX64,
                                  lock->l_handle.h_cookie);
                        GOTO(existing_lock, rc = 0);
                }
        }

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
        lock->l_remote_handle = dlm_req->lock_handle1;
        LDLM_DEBUG(lock, "server-side enqueue handler, new lock created");

        OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_ENQUEUE_BLOCKED, obd_timeout * 2);
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        /* Don't enqueue a lock onto the export if it has already
         * been evicted.  Cancel it now instead. (bug 3822) */
        if (req->rq_export->exp_failed) {
                LDLM_ERROR(lock, "lock on destroyed export %p", req->rq_export);
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                GOTO(out, rc = -ENOTCONN);
        }
        lock->l_export = class_export_get(req->rq_export);
        list_add(&lock->l_export_chain,
                 &lock->l_export->exp_ldlm_data.led_held_locks);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

existing_lock:

        if (flags & LDLM_FL_HAS_INTENT) {
                /* In this case, the reply buffer is allocated deep in
                 * local_lock_enqueue by the policy function. */
                cookie = req;
        } else {
                int buffers = 2;

                mutex_down(&lock->l_resource->lr_lvb_sem);
                if (lock->l_resource->lr_lvb_len) {
                        size[DLM_REPLY_REC_OFF] = lock->l_resource->lr_lvb_len;
                        buffers = 3;
                }
                mutex_up(&lock->l_resource->lr_lvb_sem);

                if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_LDLM_ENQUEUE_EXTENT_ERR))
                        GOTO(out, rc = -ENOMEM);

                rc = lustre_pack_reply(req, buffers, size, NULL);
                if (rc)
                        GOTO(out, rc);
        }

        if (dlm_req->lock_desc.l_resource.lr_type != LDLM_PLAIN)
                lock->l_policy_data = dlm_req->lock_desc.l_policy_data;
        if (dlm_req->lock_desc.l_resource.lr_type == LDLM_EXTENT)
                lock->l_req_extent = lock->l_policy_data.l_extent;

        err = ldlm_lock_enqueue(obddev->obd_namespace, &lock, cookie, &flags);
        if (err)
                GOTO(out, err);

        dlm_rep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF,
                                 sizeof(*dlm_rep));
        dlm_rep->lock_flags = flags;

        ldlm_lock2desc(lock, &dlm_rep->lock_desc);
        ldlm_lock2handle(lock, &dlm_rep->lock_handle);

        /* We never send a blocking AST until the lock is granted, but
         * we can tell it right now */
        l_lock(&lock->l_resource->lr_namespace->ns_lock);

        /* Now take into account flags to be inherited from original lock
           request both in reply to client and in our own lock flags. */
        dlm_rep->lock_flags |= dlm_req->lock_flags & LDLM_INHERIT_FLAGS;
        lock->l_flags |= dlm_req->lock_flags & LDLM_INHERIT_FLAGS;

        /* Don't move a pending lock onto the export if it has already
         * been evicted.  Cancel it now instead. (bug 5683) */
        if (req->rq_export->exp_failed ||
            OBD_FAIL_CHECK_ONCE(OBD_FAIL_LDLM_ENQUEUE_OLD_EXPORT)) {
                LDLM_ERROR(lock, "lock on destroyed export %p", req->rq_export);
                rc = -ENOTCONN;
        } else if (lock->l_flags & LDLM_FL_AST_SENT) {
                dlm_rep->lock_flags |= LDLM_FL_AST_SENT;
                if (dlm_rep->lock_flags & LDLM_FL_CANCEL_ON_BLOCK)
                        ldlm_lock_cancel(lock);
                else if (lock->l_granted_mode == lock->l_req_mode)
                        ldlm_add_waiting_lock(lock);
        }
        /* Make sure we never ever grant usual metadata locks to liblustre
           clients */
        if ((dlm_req->lock_desc.l_resource.lr_type == LDLM_PLAIN ||
            dlm_req->lock_desc.l_resource.lr_type == LDLM_IBITS) &&
             req->rq_export->exp_libclient) {
                if (!(lock->l_flags & LDLM_FL_CANCEL_ON_BLOCK) ||
                    !(dlm_rep->lock_flags & LDLM_FL_CANCEL_ON_BLOCK)) {
                        CERROR("Granting sync lock to libclient. "
                               "req fl %d, rep fl %d, lock fl %d\n",
                               dlm_req->lock_flags, dlm_rep->lock_flags,
                               lock->l_flags);
                        LDLM_ERROR(lock, "sync lock");
                        if (dlm_req->lock_flags & LDLM_FL_HAS_INTENT) {
                                struct ldlm_intent *it;
                                it = lustre_msg_buf(req->rq_reqmsg,
                                                    DLM_INTENT_IT_OFF,
                                                    sizeof(*it));
                                if (it != NULL) {
                                        CERROR("This is intent %s ("LPU64")\n",
                                               ldlm_it2str(it->opc), it->opc);
                                }
                        }
                }
        }

        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        EXIT;
 out:
        req->rq_status = err;
        if (req->rq_reply_state == NULL) {
                err = lustre_pack_reply(req, 1, NULL, NULL);
                if (rc == 0)
                        rc = err;
                req->rq_status = rc;
        }

        /* The LOCK_CHANGED code in ldlm_lock_enqueue depends on this
         * ldlm_reprocess_all.  If this moves, revisit that code. -phil */
        if (lock) {
                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                LDLM_DEBUG(lock, "server-side enqueue handler, sending reply"
                           "(err=%d, rc=%d)", err, rc);
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);

                if (rc == 0) {
                        mutex_down(&lock->l_resource->lr_lvb_sem);
                        size[DLM_REPLY_REC_OFF] = lock->l_resource->lr_lvb_len;
                        if (size[DLM_REPLY_REC_OFF] > 0) {
                                void *lvb = lustre_msg_buf(req->rq_repmsg,
                                                       DLM_REPLY_REC_OFF,
                                                       size[DLM_REPLY_REC_OFF]);
                                LASSERTF(lvb != NULL, "req %p, lock %p\n",
                                         req, lock);

                                memcpy(lvb, lock->l_resource->lr_lvb_data,
                                       size[DLM_REPLY_REC_OFF]);
                        }
                        mutex_up(&lock->l_resource->lr_lvb_sem);
                } else {
                        ldlm_resource_unlink_lock(lock);
                        ldlm_lock_destroy(lock);
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
        int rc;
        int size[2] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREPLY_OFF]   = sizeof(*dlm_rep) };
        ENTRY;

        dlm_req = lustre_swab_reqbuf(req, DLM_LOCKREQ_OFF, sizeof(*dlm_req),
                                     lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR ("Can't unpack dlm_req\n");
                RETURN (-EFAULT);
        }

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc) {
                CERROR("out of memory\n");
                RETURN(-ENOMEM);
        }
        dlm_rep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF,
                                 sizeof(*dlm_rep));
        dlm_rep->lock_flags = dlm_req->lock_flags;

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                req->rq_status = EINVAL;
        } else {
                void *res;
                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                LDLM_DEBUG(lock, "server-side convert handler START");
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                do_gettimeofday(&lock->l_enqueued_time);
                res = ldlm_lock_convert(lock, dlm_req->lock_desc.l_req_mode,
                                        &dlm_rep->lock_flags);
                if (res) {
                        l_lock(&lock->l_resource->lr_namespace->ns_lock);
                        if (ldlm_del_waiting_lock(lock))
                                CDEBUG(D_DLMTRACE,"converted waiting lock %p\n",
                                       lock);
                        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                        req->rq_status = 0;
                } else {
                        req->rq_status = EDEADLOCK;
                }
        }

        if (lock) {
                if (!req->rq_status)
                        ldlm_reprocess_all(lock->l_resource);
                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                LDLM_DEBUG(lock, "server-side convert handler END");
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
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
        int rc;
        ENTRY;

        dlm_req = lustre_swab_reqbuf(req, DLM_LOCKREQ_OFF, sizeof(*dlm_req),
                                     lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR("bad request buffer for cancel\n");
                RETURN(-EFAULT);
        }

        rc = lustre_pack_reply(req, 1, NULL, NULL);
        if (rc) {
                CERROR("out of memory\n");
                RETURN(-ENOMEM);
        }

        lock = ldlm_handle2lock(&dlm_req->lock_handle1);
        if (!lock) {
                CERROR("received cancel for unknown lock cookie "LPX64
                       " from client %s id %s\n",
                       dlm_req->lock_handle1.cookie,
                       req->rq_export->exp_client_uuid.uuid,
                       libcfs_id2str(req->rq_peer));
                LDLM_DEBUG_NOLOCK("server-side cancel handler stale lock "
                                  "(cookie "LPU64")",
                                  dlm_req->lock_handle1.cookie);
                req->rq_status = ESTALE;
        } else {
                res = lock->l_resource;
                l_lock(&res->lr_namespace->ns_lock);
                LDLM_DEBUG(lock, "server-side cancel handler START");
                l_unlock(&res->lr_namespace->ns_lock);
                if (res && res->lr_namespace->ns_lvbo &&
                    res->lr_namespace->ns_lvbo->lvbo_update) {
                        (void)res->lr_namespace->ns_lvbo->lvbo_update
                                (res, NULL, 0, 0);
                                //(res, req->rq_reqmsg, 1);
                }

                l_lock(&res->lr_namespace->ns_lock);
                ldlm_lock_cancel(lock);
                if (ldlm_del_waiting_lock(lock))
                        CDEBUG(D_DLMTRACE, "cancelled waiting lock %p\n", lock);
                l_unlock(&res->lr_namespace->ns_lock);
                req->rq_status = rc;
        }

        if (ptlrpc_reply(req) != 0)
                LBUG();

        if (lock) {
                ldlm_reprocess_all(lock->l_resource);
                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                LDLM_DEBUG(lock, "server-side cancel handler END");
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
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

        if (lock->l_flags & LDLM_FL_CANCEL_ON_BLOCK)
                lock->l_flags |= LDLM_FL_CANCEL;

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
        CFS_LIST_HEAD(ast_list);
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
                lock->l_policy_data = dlm_req->lock_desc.l_policy_data;
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
                lvb = lustre_swab_reqbuf(req, DLM_REQ_REC_OFF, lock->l_lvb_len,
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

        l_unlock(&ns->ns_lock);
        if (lock->l_granted_mode == LCK_PW &&
            !lock->l_readers && !lock->l_writers &&
            cfs_time_after(cfs_time_current(), 
                           cfs_time_add(lock->l_last_used, cfs_time_seconds(10)))) {
                if (ldlm_bl_to_thread(ns, NULL, lock))
                        ldlm_handle_bl_callback(ns, NULL, lock);
                EXIT;
                return;
        }

        LDLM_LOCK_PUT(lock);
        EXIT;
}

static int ldlm_callback_reply(struct ptlrpc_request *req, int rc)
{
        req->rq_status = rc;
        if (req->rq_reply_state == NULL) {
                rc = lustre_pack_reply(req, 1, NULL, NULL);
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
        cfs_waitq_signal(&blp->blp_waitq);
        spin_unlock(&blp->blp_lock);

        RETURN(0);
#else
        RETURN(-ENOSYS);
#endif
}

static int ldlm_callback_handler(struct ptlrpc_request *req)
{
        struct ldlm_namespace *ns;
        struct ldlm_request *dlm_req;
        struct ldlm_lock *lock;
        int rc;
        ENTRY;

        /* Requests arrive in sender's byte order.  The ptlrpc service
         * handler has already checked and, if necessary, byte-swapped the
         * incoming request message body, but I am responsible for the
         * message buffers. */

        if (req->rq_export == NULL) {
                struct ldlm_request *dlm_req;

                CDEBUG(D_RPCTRACE, "operation %d from %s with bad "
                       "export cookie "LPX64"; this is "
                       "normal if this node rebooted with a lock held\n",
                       lustre_msg_get_opc(req->rq_reqmsg),
                       libcfs_id2str(req->rq_peer),
                       lustre_msg_get_handle(req->rq_reqmsg)->cookie);

                dlm_req = lustre_swab_reqbuf(req, DLM_LOCKREQ_OFF,
                                             sizeof(*dlm_req),
                                             lustre_swab_ldlm_request);
                if (dlm_req != NULL)
                        CDEBUG(D_RPCTRACE, "--> lock cookie: "LPX64"\n",
                               dlm_req->lock_handle1.cookie);

                ldlm_callback_reply(req, -ENOTCONN);
                RETURN(0);
        }

        LASSERT(req->rq_export != NULL);
        LASSERT(req->rq_export->exp_obd != NULL);

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case LDLM_BL_CALLBACK:
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                break;
        case LDLM_CP_CALLBACK:
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CP_CALLBACK, 0);
                break;
        case LDLM_GL_CALLBACK:
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_GL_CALLBACK, 0);
                break;
        case OBD_LOG_CANCEL: /* remove this eventually - for 1.4.0 compat */
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOG_CANCEL_NET, 0);
                rc = llog_origin_handle_cancel(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case OBD_QC_CALLBACK:
                OBD_FAIL_RETURN(OBD_FAIL_OBD_QC_CALLBACK_NET, 0);
                rc = target_handle_qc_callback(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case QUOTA_DQACQ:
        case QUOTA_DQREL:
                /* reply in handler */
                rc = target_handle_dqacq_callback(req);
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
                CERROR("unknown opcode %u\n",
                       lustre_msg_get_opc(req->rq_reqmsg));
                ldlm_callback_reply(req, -EPROTO);
                RETURN(0);
        }

        ns = req->rq_export->exp_obd->obd_namespace;
        LASSERT(ns != NULL);

        dlm_req = lustre_swab_reqbuf(req, DLM_LOCKREQ_OFF, sizeof(*dlm_req),
                                     lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR ("can't unpack dlm_req\n");
                ldlm_callback_reply(req, -EPROTO);
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

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case LDLM_BL_CALLBACK:
                CDEBUG(D_INODE, "blocking ast\n");
                if (!(lock->l_flags & LDLM_FL_CANCEL_ON_BLOCK))
                        ldlm_callback_reply(req, 0);
                if (ldlm_bl_to_thread(ns, &dlm_req->lock_desc, lock))
                        ldlm_handle_bl_callback(ns, &dlm_req->lock_desc, lock);
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

                CERROR("operation %d from %s with bad export cookie "LPU64"\n",
                       lustre_msg_get_opc(req->rq_reqmsg),
                       libcfs_id2str(req->rq_peer),
                       lustre_msg_get_handle(req->rq_reqmsg)->cookie);

                dlm_req = lustre_swab_reqbuf(req, DLM_LOCKREQ_OFF,
                                             sizeof(*dlm_req),
                                             lustre_swab_ldlm_request);
                if (dlm_req != NULL)
                        ldlm_lock_dump_handle(D_ERROR, &dlm_req->lock_handle1);

                ldlm_callback_reply(req, -ENOTCONN);
                RETURN(0);
        }

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {

        /* XXX FIXME move this back to mds/handler.c, bug 249 */
        case LDLM_CANCEL:
                CDEBUG(D_INODE, "cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CANCEL, 0);
                rc = ldlm_handle_cancel(req);
                if (rc)
                        break;
                RETURN(0);
        case OBD_LOG_CANCEL:
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOG_CANCEL_NET, 0);
                rc = llog_origin_handle_cancel(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        default:
                CERROR("invalid opcode %d\n",
                       lustre_msg_get_opc(req->rq_reqmsg));
                ldlm_callback_reply(req, -EINVAL);
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
        ENTRY;

        {
                char name[CFS_CURPROC_COMM_MAX];
                snprintf(name, sizeof(name) - 1, "ldlm_bl_%02d",
                         bltd->bltd_num);
                cfs_daemonize(name);
        }

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
        ENTRY;
        mutex_down(&ldlm_ref_sem);
        if (++ldlm_refcount == 1) {
                rc = ldlm_setup();
                if (rc)
                        ldlm_refcount--;
        }
        mutex_up(&ldlm_ref_sem);

        RETURN(rc);
}

void ldlm_put_ref(int force)
{
        ENTRY;
        mutex_down(&ldlm_ref_sem);
        if (ldlm_refcount == 1) {
                int rc = ldlm_cleanup(force);
                if (rc)
                        CERROR("ldlm_cleanup failed: %d\n", rc);
                else
                        ldlm_refcount--;
        } else {
                ldlm_refcount--;
        }
        mutex_up(&ldlm_ref_sem);

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

#ifdef LPROCFS
        rc = ldlm_proc_setup();
        if (rc != 0)
                GOTO(out_free, rc);
#endif

        ldlm_state->ldlm_cb_service =
                ptlrpc_init_svc(LDLM_NBUFS, LDLM_BUFSIZE, LDLM_MAXREQSIZE,
                                LDLM_MAXREPSIZE, LDLM_CB_REQUEST_PORTAL,
                                LDLM_CB_REPLY_PORTAL, ldlm_timeout * 900,
                                ldlm_callback_handler, "ldlm_cbd",
                                ldlm_svc_proc_dir, NULL, LDLM_NUM_THREADS);

        if (!ldlm_state->ldlm_cb_service) {
                CERROR("failed to start service\n");
                GOTO(out_proc, rc = -ENOMEM);
        }

        ldlm_state->ldlm_cancel_service =
                ptlrpc_init_svc(LDLM_NBUFS, LDLM_BUFSIZE, LDLM_MAXREQSIZE,
                                LDLM_MAXREPSIZE, LDLM_CANCEL_REQUEST_PORTAL,
                                LDLM_CANCEL_REPLY_PORTAL, 30000,
                                ldlm_cancel_handler, "ldlm_canceld",
                                ldlm_svc_proc_dir, NULL, LDLM_NUM_THREADS);

        if (!ldlm_state->ldlm_cancel_service) {
                CERROR("failed to start service\n");
                GOTO(out_proc, rc = -ENOMEM);
        }

        OBD_ALLOC(blp, sizeof(*blp));
        if (blp == NULL)
                GOTO(out_proc, rc = -ENOMEM);
        ldlm_state->ldlm_bl_pool = blp;

        atomic_set(&blp->blp_num_threads, 0);
        cfs_waitq_init(&blp->blp_waitq);
        spin_lock_init(&blp->blp_lock);

        CFS_INIT_LIST_HEAD(&blp->blp_list);

#ifdef __KERNEL__
        for (i = 0; i < LDLM_NUM_THREADS; i++) {
                struct ldlm_bl_thread_data bltd = {
                        .bltd_num = i,
                        .bltd_blp = blp,
                };
                init_completion(&blp->blp_comp);
                rc = cfs_kernel_thread(ldlm_bl_thread_main, &bltd, 0);
                if (rc < 0) {
                        CERROR("cannot start LDLM thread #%d: rc %d\n", i, rc);
                        GOTO(out_thread, rc);
                }
                wait_for_completion(&blp->blp_comp);
        }

        rc = ptlrpc_start_threads(NULL, ldlm_state->ldlm_cancel_service,
                                  "ldlm_cn");
        if (rc)
                GOTO(out_thread, rc);

        rc = ptlrpc_start_threads(NULL, ldlm_state->ldlm_cb_service,
                                  "ldlm_cb");
        if (rc)
                GOTO(out_thread, rc);

        CFS_INIT_LIST_HEAD(&expired_lock_thread.elt_expired_locks);
        expired_lock_thread.elt_state = ELT_STOPPED;
        cfs_waitq_init(&expired_lock_thread.elt_waitq);

        CFS_INIT_LIST_HEAD(&waiting_locks_list);
        spin_lock_init(&waiting_locks_spinlock);
        cfs_timer_init(&waiting_locks_timer, waiting_locks_callback, 0);

        rc = cfs_kernel_thread(expired_lock_main, NULL, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("Cannot start ldlm expired-lock thread: %d\n", rc);
                GOTO(out_thread, rc);
        }

        wait_event(expired_lock_thread.elt_waitq,
                   expired_lock_thread.elt_state == ELT_READY);
#endif

        RETURN(0);

#ifdef __KERNEL__
 out_thread:
        ptlrpc_unregister_service(ldlm_state->ldlm_cancel_service);
        ptlrpc_unregister_service(ldlm_state->ldlm_cb_service);
#endif

 out_proc:
#ifdef LPROCFS
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
                ldlm_dump_all_namespaces(D_DLMTRACE);
                RETURN(-EBUSY);
        }

#ifdef __KERNEL__
        while (atomic_read(&blp->blp_num_threads) > 0) {
                struct ldlm_bl_work_item blwi = { .blwi_ns = NULL };

                init_completion(&blp->blp_comp);

                spin_lock(&blp->blp_lock);
                list_add_tail(&blwi.blwi_entry, &blp->blp_list);
                cfs_waitq_signal(&blp->blp_waitq);
                spin_unlock(&blp->blp_lock);

                wait_for_completion(&blp->blp_comp);
        }
        OBD_FREE(blp, sizeof(*blp));

        ptlrpc_unregister_service(ldlm_state->ldlm_cb_service);
        ptlrpc_unregister_service(ldlm_state->ldlm_cancel_service);
        ldlm_proc_cleanup();

        expired_lock_thread.elt_state = ELT_TERMINATE;
        cfs_waitq_signal(&expired_lock_thread.elt_waitq);
        wait_event(expired_lock_thread.elt_waitq,
                   expired_lock_thread.elt_state == ELT_STOPPED);
#else
        ptlrpc_unregister_service(ldlm_state->ldlm_cb_service);
        ptlrpc_unregister_service(ldlm_state->ldlm_cancel_service);
#endif

        OBD_FREE(ldlm_state, sizeof(*ldlm_state));
        ldlm_state = NULL;

        RETURN(0);
}

int __init ldlm_init(void)
{
        init_mutex(&ldlm_ref_sem);
        init_mutex(&ldlm_namespace_lock);
        ldlm_resource_slab = cfs_mem_cache_create("ldlm_resources",
                                               sizeof(struct ldlm_resource), 0,
                                               SLAB_HWCACHE_ALIGN);
        if (ldlm_resource_slab == NULL)
                return -ENOMEM;

        ldlm_lock_slab = cfs_mem_cache_create("ldlm_locks",
                                           sizeof(struct ldlm_lock), 0,
                                           SLAB_HWCACHE_ALIGN);
        if (ldlm_lock_slab == NULL) {
                cfs_mem_cache_destroy(ldlm_resource_slab);
                return -ENOMEM;
        }

        l_lock_init(&ldlm_handle_lock);

        return 0;
}

void __exit ldlm_exit(void)
{
        int rc;

        if (ldlm_refcount)
                CERROR("ldlm_refcount is %d in ldlm_exit!\n", ldlm_refcount);
        rc = cfs_mem_cache_destroy(ldlm_resource_slab);
        LASSERTF(rc == 0, "couldn't free ldlm resource slab\n");
        rc = cfs_mem_cache_destroy(ldlm_lock_slab);
        LASSERTF(rc == 0, "couldn't free ldlm lock slab\n");
}

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
EXPORT_SYMBOL(ldlm_blocking_ast);
EXPORT_SYMBOL(ldlm_glimpse_ast);
EXPORT_SYMBOL(ldlm_expired_completion_wait);
EXPORT_SYMBOL(ldlm_cli_convert);
EXPORT_SYMBOL(ldlm_cli_enqueue);
EXPORT_SYMBOL(ldlm_cli_enqueue_fini);
EXPORT_SYMBOL(ldlm_cli_enqueue_local);
EXPORT_SYMBOL(ldlm_cli_cancel);
EXPORT_SYMBOL(ldlm_cli_cancel_unused);
EXPORT_SYMBOL(ldlm_cli_join_lru);
EXPORT_SYMBOL(ldlm_replay_locks);
EXPORT_SYMBOL(ldlm_resource_foreach);
EXPORT_SYMBOL(ldlm_namespace_foreach);
EXPORT_SYMBOL(ldlm_namespace_foreach_res);
EXPORT_SYMBOL(ldlm_resource_iterate);

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
EXPORT_SYMBOL(ldlm_refresh_waiting_lock);

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
EXPORT_SYMBOL(client_import_add_conn);
EXPORT_SYMBOL(client_import_del_conn);
EXPORT_SYMBOL(client_obd_setup);
EXPORT_SYMBOL(client_obd_cleanup);
EXPORT_SYMBOL(client_connect_import);
EXPORT_SYMBOL(client_disconnect_export);
EXPORT_SYMBOL(target_abort_recovery);
EXPORT_SYMBOL(target_cleanup_recovery);
EXPORT_SYMBOL(target_handle_connect);
EXPORT_SYMBOL(target_destroy_export);
EXPORT_SYMBOL(target_cancel_recovery_timer);
EXPORT_SYMBOL(target_send_reply);
EXPORT_SYMBOL(target_queue_recovery_request);
EXPORT_SYMBOL(target_handle_ping);
EXPORT_SYMBOL(target_handle_disconnect);
EXPORT_SYMBOL(target_queue_final_reply);
