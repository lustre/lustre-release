/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_lockd.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/kthread.h>
#include <linux/list.h>
#include <libcfs/libcfs.h>
#include <lustre/lustre_errno.h>
#include <lustre_dlm.h>
#include <obd_class.h>
#include "ldlm_internal.h"

static int ldlm_num_threads;
module_param(ldlm_num_threads, int, 0444);
MODULE_PARM_DESC(ldlm_num_threads, "number of DLM service threads to start");

static char *ldlm_cpts;
module_param(ldlm_cpts, charp, 0444);
MODULE_PARM_DESC(ldlm_cpts, "CPU partitions ldlm threads should run on");

static DEFINE_MUTEX(ldlm_ref_mutex);
static int ldlm_refcount;

struct kobject *ldlm_kobj;
struct kset *ldlm_ns_kset;
struct kset *ldlm_svc_kset;

/* LDLM state */

static struct ldlm_state *ldlm_state;

static inline cfs_time_t round_timeout(cfs_time_t timeout)
{
        return cfs_time_seconds((int)cfs_duration_sec(cfs_time_sub(timeout, 0)) + 1);
}

/* timeout for initial callback (AST) reply (bz10399) */
static inline unsigned int ldlm_get_rq_timeout(void)
{
        /* Non-AT value */
        unsigned int timeout = min(ldlm_timeout, obd_timeout / 3);

        return timeout < 1 ? 1 : timeout;
}

struct ldlm_bl_pool {
	spinlock_t		blp_lock;

	/*
	 * blp_prio_list is used for callbacks that should be handled
	 * as a priority. It is used for LDLM_FL_DISCARD_DATA requests.
	 * see bug 13843
	 */
	struct list_head              blp_prio_list;

	/*
	 * blp_list is used for all other callbacks which are likely
	 * to take longer to process.
	 */
	struct list_head              blp_list;

	wait_queue_head_t       blp_waitq;
	struct completion       blp_comp;
	atomic_t            blp_num_threads;
	atomic_t            blp_busy_threads;
	int                     blp_min_threads;
	int                     blp_max_threads;
};

struct ldlm_bl_work_item {
	struct list_head	blwi_entry;
	struct ldlm_namespace	*blwi_ns;
	struct ldlm_lock_desc	blwi_ld;
	struct ldlm_lock	*blwi_lock;
	struct list_head	blwi_head;
	int			blwi_count;
	struct completion	blwi_comp;
	enum ldlm_cancel_flags	blwi_flags;
	int			blwi_mem_pressure;
};

#ifdef HAVE_SERVER_SUPPORT

/**
 * Protects both waiting_locks_list and expired_lock_thread.
 */
static DEFINE_SPINLOCK(waiting_locks_spinlock); /* BH lock (timer) */

/**
 * List for contended locks.
 *
 * As soon as a lock is contended, it gets placed on this list and
 * expected time to get a response is filled in the lock. A special
 * thread walks the list looking for locks that should be released and
 * schedules client evictions for those that have not been released in
 * time.
 *
 * All access to it should be under waiting_locks_spinlock.
 */
static LIST_HEAD(waiting_locks_list);
static void waiting_locks_callback(unsigned long unused);
static DEFINE_TIMER(waiting_locks_timer, waiting_locks_callback, 0, 0);

enum elt_state {
	ELT_STOPPED,
	ELT_READY,
	ELT_TERMINATE,
};

static DECLARE_WAIT_QUEUE_HEAD(expired_lock_wait_queue);
static enum elt_state expired_lock_thread_state = ELT_STOPPED;
static int expired_lock_dump;
static LIST_HEAD(expired_lock_list);

static inline int have_expired_locks(void)
{
	int need_to_run;

	ENTRY;
	spin_lock_bh(&waiting_locks_spinlock);
	need_to_run = !list_empty(&expired_lock_list);
	spin_unlock_bh(&waiting_locks_spinlock);

	RETURN(need_to_run);
}

/**
 * Check expired lock list for expired locks and time them out.
 */
static int expired_lock_main(void *arg)
{
	struct list_head *expired = &expired_lock_list;
	struct l_wait_info lwi = { 0 };
	int do_dump;

	ENTRY;

	expired_lock_thread_state = ELT_READY;
	wake_up(&expired_lock_wait_queue);

	while (1) {
		l_wait_event(expired_lock_wait_queue,
			     have_expired_locks() ||
			     expired_lock_thread_state == ELT_TERMINATE,
			     &lwi);

		spin_lock_bh(&waiting_locks_spinlock);
		if (expired_lock_dump) {
			spin_unlock_bh(&waiting_locks_spinlock);

			/* from waiting_locks_callback, but not in timer */
			libcfs_debug_dumplog();

			spin_lock_bh(&waiting_locks_spinlock);
			expired_lock_dump = 0;
		}

		do_dump = 0;

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
			if ((void *)lock->l_export <
			     LP_POISON + PAGE_SIZE &&
			    (void *)lock->l_export >= LP_POISON) {
				CERROR("lock with free export on elt list %p\n",
				       lock->l_export);
				lock->l_export = NULL;
				LDLM_ERROR(lock, "free export");
				/* release extra ref grabbed by
				 * ldlm_add_waiting_lock() or
				 * ldlm_failed_ast() */
				LDLM_LOCK_RELEASE(lock);
				continue;
			}

			if (ldlm_is_destroyed(lock)) {
				/* release the lock refcount where
				 * waiting_locks_callback() founds */
				LDLM_LOCK_RELEASE(lock);
				continue;
			}
			export = class_export_lock_get(lock->l_export, lock);
			spin_unlock_bh(&waiting_locks_spinlock);

			spin_lock_bh(&export->exp_bl_list_lock);
			list_del_init(&lock->l_exp_list);
			spin_unlock_bh(&export->exp_bl_list_lock);

			do_dump++;
			class_fail_export(export);
			class_export_lock_put(export, lock);

			/* release extra ref grabbed by ldlm_add_waiting_lock()
			 * or ldlm_failed_ast() */
			LDLM_LOCK_RELEASE(lock);

			spin_lock_bh(&waiting_locks_spinlock);
		}
		spin_unlock_bh(&waiting_locks_spinlock);

		if (do_dump && obd_dump_on_eviction) {
			CERROR("dump the log upon eviction\n");
			libcfs_debug_dumplog();
		}

		if (expired_lock_thread_state == ELT_TERMINATE)
			break;
	}

	expired_lock_thread_state = ELT_STOPPED;
	wake_up(&expired_lock_wait_queue);
	RETURN(0);
}

static int ldlm_add_waiting_lock(struct ldlm_lock *lock);
static int __ldlm_add_waiting_lock(struct ldlm_lock *lock, int seconds);

/**
 * Check if there is a request in the export request list
 * which prevents the lock canceling.
 */
static int ldlm_lock_busy(struct ldlm_lock *lock)
{
	struct ptlrpc_request *req;
	int match = 0;
	ENTRY;

	if (lock->l_export == NULL)
		return 0;

	spin_lock_bh(&lock->l_export->exp_rpc_lock);
	list_for_each_entry(req, &lock->l_export->exp_hp_rpcs,
				rq_exp_list) {
		if (req->rq_ops->hpreq_lock_match) {
			match = req->rq_ops->hpreq_lock_match(req, lock);
			if (match)
				break;
		}
	}
	spin_unlock_bh(&lock->l_export->exp_rpc_lock);
	RETURN(match);
}

/* This is called from within a timer interrupt and cannot schedule */
static void waiting_locks_callback(unsigned long unused)
{
	struct ldlm_lock	*lock;
	int			need_dump = 0;

	spin_lock_bh(&waiting_locks_spinlock);
	while (!list_empty(&waiting_locks_list)) {
		lock = list_entry(waiting_locks_list.next, struct ldlm_lock,
                                      l_pending_chain);
                if (cfs_time_after(lock->l_callback_timeout,
                                   cfs_time_current()) ||
                    (lock->l_req_mode == LCK_GROUP))
                        break;

                /* Check if we need to prolong timeout */
                if (!OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_HPREQ_TIMEOUT) &&
                    ldlm_lock_busy(lock)) {
                        int cont = 1;

                        if (lock->l_pending_chain.next == &waiting_locks_list)
                                cont = 0;

                        LDLM_LOCK_GET(lock);

			spin_unlock_bh(&waiting_locks_spinlock);
			LDLM_DEBUG(lock, "prolong the busy lock");
			ldlm_refresh_waiting_lock(lock,
						  ldlm_bl_timeout(lock) >> 1);
			spin_lock_bh(&waiting_locks_spinlock);

                        if (!cont) {
                                LDLM_LOCK_RELEASE(lock);
                                break;
                        }

                        LDLM_LOCK_RELEASE(lock);
                        continue;
                }
                ldlm_lock_to_ns(lock)->ns_timeouts++;
		LDLM_ERROR(lock, "lock callback timer expired after %llds: "
                           "evicting client at %s ",
			   ktime_get_real_seconds() - lock->l_last_activity,
                           libcfs_nid2str(
                                   lock->l_export->exp_connection->c_peer.nid));

                /* no needs to take an extra ref on the lock since it was in
                 * the waiting_locks_list and ldlm_add_waiting_lock()
                 * already grabbed a ref */
		list_del(&lock->l_pending_chain);
		list_add(&lock->l_pending_chain, &expired_lock_list);
		need_dump = 1;
	}

	if (!list_empty(&expired_lock_list)) {
		if (obd_dump_on_timeout && need_dump)
			expired_lock_dump = __LINE__;

		wake_up(&expired_lock_wait_queue);
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
		mod_timer(&waiting_locks_timer, timeout_rounded);
        }
	spin_unlock_bh(&waiting_locks_spinlock);
}

/**
 * Add lock to the list of contended locks.
 *
 * Indicate that we're waiting for a client to call us back cancelling a given
 * lock.  We add it to the pending-callback chain, and schedule the lock-timeout
 * timer to fire appropriately.  (We round up to the next second, to avoid
 * floods of timer firings during periods of high lock contention and traffic).
 * As done by ldlm_add_waiting_lock(), the caller must grab a lock reference
 * if it has been added to the waiting list (1 is returned).
 *
 * Called with the namespace lock held.
 */
static int __ldlm_add_waiting_lock(struct ldlm_lock *lock, int seconds)
{
        cfs_time_t timeout;
        cfs_time_t timeout_rounded;

	if (!list_empty(&lock->l_pending_chain))
                return 0;

        if (OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_HPREQ_NOTIMEOUT) ||
            OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_HPREQ_TIMEOUT))
                seconds = 1;

        timeout = cfs_time_shift(seconds);
        if (likely(cfs_time_after(timeout, lock->l_callback_timeout)))
                lock->l_callback_timeout = timeout;

        timeout_rounded = round_timeout(lock->l_callback_timeout);

	if (cfs_time_before(timeout_rounded, waiting_locks_timer.expires) ||
	    !timer_pending(&waiting_locks_timer)) {
		mod_timer(&waiting_locks_timer, timeout_rounded);
        }
        /* if the new lock has a shorter timeout than something earlier on
           the list, we'll wait the longer amount of time; no big deal. */
        /* FIFO */
	list_add_tail(&lock->l_pending_chain, &waiting_locks_list);
        return 1;
}

static void ldlm_add_blocked_lock(struct ldlm_lock *lock)
{
	spin_lock_bh(&lock->l_export->exp_bl_list_lock);
	if (list_empty(&lock->l_exp_list)) {
		if (lock->l_granted_mode != lock->l_req_mode)
			list_add_tail(&lock->l_exp_list,
				      &lock->l_export->exp_bl_list);
		else
			list_add(&lock->l_exp_list,
				 &lock->l_export->exp_bl_list);
	}
	spin_unlock_bh(&lock->l_export->exp_bl_list_lock);

	/* A blocked lock is added. Adjust the position in
	 * the stale list if the export is in the list.
	 * If export is stale and not in the list - it is being
	 * processed and will be placed on the right position
	 * on obd_stale_export_put(). */
	if (!list_empty(&lock->l_export->exp_stale_list))
		obd_stale_export_adjust(lock->l_export);
}

static int ldlm_add_waiting_lock(struct ldlm_lock *lock)
{
	int ret;
	int timeout = ldlm_bl_timeout(lock);

	/* NB: must be called with hold of lock_res_and_lock() */
	LASSERT(ldlm_is_res_locked(lock));
	LASSERT(!ldlm_is_cancel_on_block(lock));

	/* Do not put cross-MDT lock in the waiting list, since we
	 * will not evict it due to timeout for now */
	if (lock->l_export != NULL &&
	    (exp_connect_flags(lock->l_export) & OBD_CONNECT_MDS_MDS))
		return 0;

	spin_lock_bh(&waiting_locks_spinlock);
	if (ldlm_is_cancel(lock)) {
		spin_unlock_bh(&waiting_locks_spinlock);
		return 0;
	}

	if (ldlm_is_destroyed(lock)) {
		static cfs_time_t next;

		spin_unlock_bh(&waiting_locks_spinlock);
		LDLM_ERROR(lock, "not waiting on destroyed lock (bug 5653)");
		if (cfs_time_after(cfs_time_current(), next)) {
			next = cfs_time_shift(14400);
			libcfs_debug_dumpstack(NULL);
		}
		return 0;
	}

	ldlm_set_waited(lock);
	lock->l_last_activity = ktime_get_real_seconds();
	ret = __ldlm_add_waiting_lock(lock, timeout);
	if (ret) {
		/* grab ref on the lock if it has been added to the
		 * waiting list */
		LDLM_LOCK_GET(lock);
	}
	spin_unlock_bh(&waiting_locks_spinlock);

	if (ret)
		ldlm_add_blocked_lock(lock);

	LDLM_DEBUG(lock, "%sadding to wait list(timeout: %d, AT: %s)",
		   ret == 0 ? "not re-" : "", timeout,
		   AT_OFF ? "off" : "on");
	return ret;
}

/**
 * Remove a lock from the pending list, likely because it had its cancellation
 * callback arrive without incident.  This adjusts the lock-timeout timer if
 * needed.  Returns 0 if the lock wasn't pending after all, 1 if it was.
 * As done by ldlm_del_waiting_lock(), the caller must release the lock
 * reference when the lock is removed from any list (1 is returned).
 *
 * Called with namespace lock held.
 */
static int __ldlm_del_waiting_lock(struct ldlm_lock *lock)
{
	struct list_head *list_next;

	if (list_empty(&lock->l_pending_chain))
                return 0;

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

        return 1;
}

int ldlm_del_waiting_lock(struct ldlm_lock *lock)
{
        int ret;

        if (lock->l_export == NULL) {
                /* We don't have a "waiting locks list" on clients. */
                CDEBUG(D_DLMTRACE, "Client lock %p : no-op\n", lock);
                return 0;
        }

	spin_lock_bh(&waiting_locks_spinlock);
	ret = __ldlm_del_waiting_lock(lock);
	ldlm_clear_waited(lock);
	spin_unlock_bh(&waiting_locks_spinlock);

	/* remove the lock out of export blocking list */
	spin_lock_bh(&lock->l_export->exp_bl_list_lock);
	list_del_init(&lock->l_exp_list);
	spin_unlock_bh(&lock->l_export->exp_bl_list_lock);

        if (ret) {
                /* release lock ref if it has indeed been removed
                 * from a list */
                LDLM_LOCK_RELEASE(lock);
        }

        LDLM_DEBUG(lock, "%s", ret == 0 ? "wasn't waiting" : "removed");
        return ret;
}

/**
 * Prolong the contended lock waiting time.
 *
 * Called with namespace lock held.
 */
int ldlm_refresh_waiting_lock(struct ldlm_lock *lock, int timeout)
{
	if (lock->l_export == NULL) {
		/* We don't have a "waiting locks list" on clients. */
		LDLM_DEBUG(lock, "client lock: no-op");
		return 0;
	}

	if (exp_connect_flags(lock->l_export) & OBD_CONNECT_MDS_MDS) {
		/* We don't have a "waiting locks list" on OSP. */
		LDLM_DEBUG(lock, "MDS-MDS lock: no-op");
		return 0;
	}

	spin_lock_bh(&waiting_locks_spinlock);

	if (list_empty(&lock->l_pending_chain)) {
		spin_unlock_bh(&waiting_locks_spinlock);
		LDLM_DEBUG(lock, "wasn't waiting");
		return 0;
	}

	/* we remove/add the lock to the waiting list, so no needs to
	 * release/take a lock reference */
	__ldlm_del_waiting_lock(lock);
	__ldlm_add_waiting_lock(lock, timeout);
	spin_unlock_bh(&waiting_locks_spinlock);

	LDLM_DEBUG(lock, "refreshed");
	return 1;
}
EXPORT_SYMBOL(ldlm_refresh_waiting_lock);

#else /* HAVE_SERVER_SUPPORT */

int ldlm_del_waiting_lock(struct ldlm_lock *lock)
{
        RETURN(0);
}

int ldlm_refresh_waiting_lock(struct ldlm_lock *lock, int timeout)
{
        RETURN(0);
}

#endif /* !HAVE_SERVER_SUPPORT */

#ifdef HAVE_SERVER_SUPPORT

/**
 * Calculate the per-export Blocking timeout (covering BL AST, data flush,
 * lock cancel, and their replies). Used for lock callback timeout and AST
 * re-send period.
 *
 * \param[in] lock        lock which is getting the blocking callback
 *
 * \retval            timeout in seconds to wait for the client reply
 */
unsigned int ldlm_bl_timeout(struct ldlm_lock *lock)
{
	unsigned int timeout;

	if (AT_OFF)
		return obd_timeout / 2;

	/* Since these are non-updating timeouts, we should be conservative.
	 * Take more than usually, 150%
	 * It would be nice to have some kind of "early reply" mechanism for
	 * lock callbacks too... */
	timeout = at_get(&lock->l_export->exp_bl_lock_at);
	return max(timeout + (timeout >> 1), ldlm_enqueue_min);
}
EXPORT_SYMBOL(ldlm_bl_timeout);

/**
 * Perform lock cleanup if AST sending failed.
 */
static void ldlm_failed_ast(struct ldlm_lock *lock, int rc,
                            const char *ast_type)
{
        LCONSOLE_ERROR_MSG(0x138, "%s: A client on nid %s was evicted due "
                           "to a lock %s callback time out: rc %d\n",
                           lock->l_export->exp_obd->obd_name,
                           obd_export_nid2str(lock->l_export), ast_type, rc);

        if (obd_dump_on_timeout)
                libcfs_debug_dumplog();
	spin_lock_bh(&waiting_locks_spinlock);
	if (__ldlm_del_waiting_lock(lock) == 0)
		/* the lock was not in any list, grab an extra ref before adding
		 * the lock to the expired list */
		LDLM_LOCK_GET(lock);
	list_add(&lock->l_pending_chain, &expired_lock_list);
	wake_up(&expired_lock_wait_queue);
	spin_unlock_bh(&waiting_locks_spinlock);
}

/**
 * Perform lock cleanup if AST reply came with error.
 */
static int ldlm_handle_ast_error(struct ldlm_lock *lock,
				 struct ptlrpc_request *req, int rc,
				 const char *ast_type)
{
	struct lnet_process_id peer = req->rq_import->imp_connection->c_peer;

	if (!req->rq_replied || (rc && rc != -EINVAL)) {
		if (lock->l_export && lock->l_export->exp_libclient) {
			LDLM_DEBUG(lock,
				   "%s AST (req@%p x%llu) to liblustre client (nid %s) timeout, just cancelling lock",
				   ast_type, req, req->rq_xid,
				   libcfs_nid2str(peer.nid));
			ldlm_lock_cancel(lock);
			rc = -ERESTART;
		} else if (ldlm_is_cancel(lock)) {
			LDLM_DEBUG(lock,
				   "%s AST (req@%p x%llu) timeout from nid %s, but cancel was received (AST reply lost?)",
				   ast_type, req, req->rq_xid,
				   libcfs_nid2str(peer.nid));
			ldlm_lock_cancel(lock);
			rc = -ERESTART;
		} else if (rc == -ENODEV || rc == -ESHUTDOWN ||
			   (rc == -EIO &&
			    req->rq_import->imp_state == LUSTRE_IMP_CLOSED)) {
			/* Upon umount process the AST fails because cannot be
			 * sent. This shouldn't lead to the client eviction.
			 * -ENODEV error is returned by ptl_send_rpc() for
			 *  new request in such import.
			 * -SHUTDOWN is returned by ptlrpc_import_delay_req()
			 *  if imp_invalid is set or obd_no_recov.
			 * Meanwhile there is also check for LUSTRE_IMP_CLOSED
			 * in ptlrpc_import_delay_req() as well with -EIO code.
			 * In all such cases errors are ignored.
			 */
			LDLM_DEBUG(lock, "%s AST can't be sent due to a server"
					 " %s failure or umount process: rc = %d\n",
					 ast_type,
					 req->rq_import->imp_obd->obd_name, rc);
		} else {
			LDLM_ERROR(lock,
				   "client (nid %s) %s %s AST (req@%p x%llu status %d rc %d), evict it",
				   libcfs_nid2str(peer.nid),
				   req->rq_replied ? "returned error from" :
				   "failed to reply to",
				   ast_type, req, req->rq_xid,
				   (req->rq_repmsg != NULL) ?
				   lustre_msg_get_status(req->rq_repmsg) : 0,
				   rc);
			ldlm_failed_ast(lock, rc, ast_type);
		}
		return rc;
	}

	if (rc == -EINVAL) {
		struct ldlm_resource *res = lock->l_resource;

		LDLM_DEBUG(lock,
			   "client (nid %s) returned %d from %s AST (req@%p x%llu) - normal race",
			   libcfs_nid2str(peer.nid),
			   req->rq_repmsg ?
			   lustre_msg_get_status(req->rq_repmsg) : -1,
			   ast_type, req, req->rq_xid);
		if (res) {
			/* update lvbo to return proper attributes.
			 * see bug 23174 */
			ldlm_resource_getref(res);
			ldlm_res_lvbo_update(res, NULL, 1);
			ldlm_resource_putref(res);
		}
		ldlm_lock_cancel(lock);
		rc = -ERESTART;
	}

	return rc;
}

static int ldlm_cb_interpret(const struct lu_env *env,
                             struct ptlrpc_request *req, void *data, int rc)
{
        struct ldlm_cb_async_args *ca   = data;
        struct ldlm_lock          *lock = ca->ca_lock;
        struct ldlm_cb_set_arg    *arg  = ca->ca_set_arg;
        ENTRY;

        LASSERT(lock != NULL);

	switch (arg->type) {
	case LDLM_GL_CALLBACK:
		/* Update the LVB from disk if the AST failed
		 * (this is a legal race)
		 *
		 * - Glimpse callback of local lock just returns
		 *   -ELDLM_NO_LOCK_DATA.
		 * - Glimpse callback of remote lock might return
		 *   -ELDLM_NO_LOCK_DATA when inode is cleared. LU-274
		 */
		if (unlikely(arg->gl_interpret_reply)) {
			rc = arg->gl_interpret_reply(env, req, data, rc);
		} else if (rc == -ELDLM_NO_LOCK_DATA) {
			LDLM_DEBUG(lock, "lost race - client has a lock but no "
				   "inode");
			ldlm_res_lvbo_update(lock->l_resource, NULL, 1);
		} else if (rc != 0) {
			rc = ldlm_handle_ast_error(lock, req, rc, "glimpse");
		} else {
			rc = ldlm_res_lvbo_update(lock->l_resource, req, 1);
		}
		break;
	case LDLM_BL_CALLBACK:
		if (rc != 0)
			rc = ldlm_handle_ast_error(lock, req, rc, "blocking");
		break;
	case LDLM_CP_CALLBACK:
		if (rc != 0)
			rc = ldlm_handle_ast_error(lock, req, rc, "completion");
		break;
	default:
		LDLM_ERROR(lock, "invalid opcode for lock callback %d",
			   arg->type);
		LBUG();
	}

	/* release extra reference taken in ldlm_ast_fini() */
        LDLM_LOCK_RELEASE(lock);

	if (rc == -ERESTART)
		atomic_inc(&arg->restart);

	RETURN(0);
}

static void ldlm_update_resend(struct ptlrpc_request *req, void *data)
{
	struct ldlm_cb_async_args *ca   = data;
	struct ldlm_lock          *lock = ca->ca_lock;

	ldlm_refresh_waiting_lock(lock, ldlm_bl_timeout(lock));
}

static inline int ldlm_ast_fini(struct ptlrpc_request *req,
				struct ldlm_cb_set_arg *arg,
				struct ldlm_lock *lock,
				int instant_cancel)
{
	int rc = 0;
	ENTRY;

	if (unlikely(instant_cancel)) {
		rc = ptl_send_rpc(req, 1);
		ptlrpc_req_finished(req);
		if (rc == 0)
			atomic_inc(&arg->restart);
	} else {
		LDLM_LOCK_GET(lock);
		ptlrpc_set_add_req(arg->set, req);
	}

	RETURN(rc);
}

/**
 * Check if there are requests in the export request list which prevent
 * the lock canceling and make these requests high priority ones.
 */
static void ldlm_lock_reorder_req(struct ldlm_lock *lock)
{
	struct ptlrpc_request *req;
	ENTRY;

	if (lock->l_export == NULL) {
		LDLM_DEBUG(lock, "client lock: no-op");
		RETURN_EXIT;
	}

	spin_lock_bh(&lock->l_export->exp_rpc_lock);
	list_for_each_entry(req, &lock->l_export->exp_hp_rpcs,
			    rq_exp_list) {
		/* Do not process requests that were not yet added to there
		 * incoming queue or were already removed from there for
		 * processing. We evaluate ptlrpc_nrs_req_can_move() without
		 * holding svcpt->scp_req_lock, and then redo the check with
		 * the lock held once we need to obtain a reliable result.
		 */
		if (ptlrpc_nrs_req_can_move(req) &&
		    req->rq_ops->hpreq_lock_match &&
		    req->rq_ops->hpreq_lock_match(req, lock))
			ptlrpc_nrs_req_hp_move(req);
	}
	spin_unlock_bh(&lock->l_export->exp_rpc_lock);
	EXIT;
}

/**
 * ->l_blocking_ast() method for server-side locks. This is invoked when newly
 * enqueued server lock conflicts with given one.
 *
 * Sends blocking AST RPC to the client owning that lock; arms timeout timer
 * to wait for client response.
 */
int ldlm_server_blocking_ast(struct ldlm_lock *lock,
                             struct ldlm_lock_desc *desc,
                             void *data, int flag)
{
        struct ldlm_cb_async_args *ca;
        struct ldlm_cb_set_arg *arg = data;
        struct ldlm_request    *body;
        struct ptlrpc_request  *req;
        int                     instant_cancel = 0;
        int                     rc = 0;
        ENTRY;

        if (flag == LDLM_CB_CANCELING)
                /* Don't need to do anything here. */
                RETURN(0);

	if (OBD_FAIL_PRECHECK(OBD_FAIL_LDLM_SRV_BL_AST)) {
		LDLM_DEBUG(lock, "dropping BL AST");
		RETURN(0);
	}

        LASSERT(lock);
        LASSERT(data != NULL);
        if (lock->l_export->exp_obd->obd_recovering != 0)
                LDLM_ERROR(lock, "BUG 6063: lock collide during recovery");

        ldlm_lock_reorder_req(lock);

        req = ptlrpc_request_alloc_pack(lock->l_export->exp_imp_reverse,
                                        &RQF_LDLM_BL_CALLBACK,
                                        LUSTRE_DLM_VERSION, LDLM_BL_CALLBACK);
        if (req == NULL)
                RETURN(-ENOMEM);

        CLASSERT(sizeof(*ca) <= sizeof(req->rq_async_args));
        ca = ptlrpc_req_async_args(req);
        ca->ca_set_arg = arg;
        ca->ca_lock = lock;

        req->rq_interpret_reply = ldlm_cb_interpret;

	lock_res_and_lock(lock);
	if (ldlm_is_destroyed(lock)) {
		/* What's the point? */
		unlock_res_and_lock(lock);
		ptlrpc_req_finished(req);
		RETURN(0);
	}

	if (lock->l_granted_mode != lock->l_req_mode) {
		/* this blocking AST will be communicated as part of the
		 * completion AST instead */
		ldlm_add_blocked_lock(lock);
		ldlm_set_waited(lock);
		unlock_res_and_lock(lock);

		ptlrpc_req_finished(req);
		LDLM_DEBUG(lock, "lock not granted, not sending blocking AST");
		RETURN(0);
	}

	if (ldlm_is_cancel_on_block(lock))
                instant_cancel = 1;

        body = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        body->lock_handle[0] = lock->l_remote_handle;
        body->lock_desc = *desc;
	body->lock_flags |= ldlm_flags_to_wire(lock->l_flags & LDLM_FL_AST_MASK);

        LDLM_DEBUG(lock, "server preparing blocking AST");

        ptlrpc_request_set_replen(req);
	ldlm_set_cbpending(lock);
	if (instant_cancel) {
		unlock_res_and_lock(lock);
		ldlm_lock_cancel(lock);

		req->rq_no_resend = 1;
	} else {
		LASSERT(lock->l_granted_mode == lock->l_req_mode);
		ldlm_add_waiting_lock(lock);
		unlock_res_and_lock(lock);

		/* Do not resend after lock callback timeout */
		req->rq_delay_limit = ldlm_bl_timeout(lock);
		req->rq_resend_cb = ldlm_update_resend;
	}

        req->rq_send_state = LUSTRE_IMP_FULL;
        /* ptlrpc_request_alloc_pack already set timeout */
        if (AT_OFF)
                req->rq_timeout = ldlm_get_rq_timeout();

	lock->l_last_activity = ktime_get_real_seconds();

        if (lock->l_export && lock->l_export->exp_nid_stats &&
            lock->l_export->exp_nid_stats->nid_ldlm_stats)
                lprocfs_counter_incr(lock->l_export->exp_nid_stats->nid_ldlm_stats,
                                     LDLM_BL_CALLBACK - LDLM_FIRST_OPC);

	rc = ldlm_ast_fini(req, arg, lock, instant_cancel);

        RETURN(rc);
}

/**
 * ->l_completion_ast callback for a remote lock in server namespace.
 *
 *  Sends AST to the client notifying it of lock granting.  If initial
 *  lock response was not sent yet, instead of sending another RPC, just
 *  mark the lock as granted and client will understand
 */
int ldlm_server_completion_ast(struct ldlm_lock *lock, __u64 flags, void *data)
{
        struct ldlm_cb_set_arg *arg = data;
        struct ldlm_request    *body;
        struct ptlrpc_request  *req;
        struct ldlm_cb_async_args *ca;
        int                     instant_cancel = 0;
        int                     rc = 0;
	int			lvb_len;
        ENTRY;

        LASSERT(lock != NULL);
        LASSERT(data != NULL);

	if (OBD_FAIL_PRECHECK(OBD_FAIL_LDLM_SRV_CP_AST)) {
		LDLM_DEBUG(lock, "dropping CP AST");
		RETURN(0);
	}

        req = ptlrpc_request_alloc(lock->l_export->exp_imp_reverse,
                                    &RQF_LDLM_CP_CALLBACK);
        if (req == NULL)
                RETURN(-ENOMEM);

	/* server namespace, doesn't need lock */
	lvb_len = ldlm_lvbo_size(lock);
	/* LU-3124 & LU-2187: to not return layout in completion AST because
	 * it may deadlock for LU-2187, or client may not have enough space
	 * for large layout. The layout will be returned to client with an
	 * extra RPC to fetch xattr.lov */
	if (ldlm_has_layout(lock))
		lvb_len = 0;

	req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_CLIENT, lvb_len);
        rc = ptlrpc_request_pack(req, LUSTRE_DLM_VERSION, LDLM_CP_CALLBACK);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        CLASSERT(sizeof(*ca) <= sizeof(req->rq_async_args));
        ca = ptlrpc_req_async_args(req);
        ca->ca_set_arg = arg;
        ca->ca_lock = lock;

        req->rq_interpret_reply = ldlm_cb_interpret;
        body = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);

        body->lock_handle[0] = lock->l_remote_handle;
	body->lock_flags = ldlm_flags_to_wire(flags);
        ldlm_lock2desc(lock, &body->lock_desc);
	if (lvb_len > 0) {
		void *lvb = req_capsule_client_get(&req->rq_pill, &RMF_DLM_LVB);

		lvb_len = ldlm_lvbo_fill(lock, lvb, lvb_len);
		if (lvb_len < 0) {
			/* We still need to send the RPC to wake up the blocked
			 * enqueue thread on the client.
			 *
			 * Consider old client, there is no better way to notify
			 * the failure, just zero-sized the LVB, then the client
			 * will fail out as "-EPROTO". */
			req_capsule_shrink(&req->rq_pill, &RMF_DLM_LVB, 0,
					   RCL_CLIENT);
			instant_cancel = 1;
		} else {
			req_capsule_shrink(&req->rq_pill, &RMF_DLM_LVB, lvb_len,
					   RCL_CLIENT);
		}
        }

	lock->l_last_activity = ktime_get_real_seconds();

	LDLM_DEBUG(lock, "server preparing completion AST");

        ptlrpc_request_set_replen(req);

        req->rq_send_state = LUSTRE_IMP_FULL;
        /* ptlrpc_request_pack already set timeout */
        if (AT_OFF)
                req->rq_timeout = ldlm_get_rq_timeout();

        /* We only send real blocking ASTs after the lock is granted */
        lock_res_and_lock(lock);
	if (ldlm_is_ast_sent(lock)) {
		body->lock_flags |= ldlm_flags_to_wire(LDLM_FL_AST_SENT);
		/* Copy AST flags like LDLM_FL_DISCARD_DATA. */
		body->lock_flags |= ldlm_flags_to_wire(lock->l_flags &
						       LDLM_FL_AST_MASK);

                /* We might get here prior to ldlm_handle_enqueue setting
                 * LDLM_FL_CANCEL_ON_BLOCK flag. Then we will put this lock
                 * into waiting list, but this is safe and similar code in
                 * ldlm_handle_enqueue will call ldlm_lock_cancel() still,
                 * that would not only cancel the lock, but will also remove
                 * it from waiting list */
		if (ldlm_is_cancel_on_block(lock)) {
			unlock_res_and_lock(lock);
			ldlm_lock_cancel(lock);

			instant_cancel = 1;
			req->rq_no_resend = 1;

			lock_res_and_lock(lock);
		} else {
			/* start the lock-timeout clock */
			ldlm_add_waiting_lock(lock);
			/* Do not resend after lock callback timeout */
			req->rq_delay_limit = ldlm_bl_timeout(lock);
			req->rq_resend_cb = ldlm_update_resend;
		}
        }
        unlock_res_and_lock(lock);

        if (lock->l_export && lock->l_export->exp_nid_stats &&
            lock->l_export->exp_nid_stats->nid_ldlm_stats)
                lprocfs_counter_incr(lock->l_export->exp_nid_stats->nid_ldlm_stats,
                                     LDLM_CP_CALLBACK - LDLM_FIRST_OPC);

	rc = ldlm_ast_fini(req, arg, lock, instant_cancel);

	RETURN(lvb_len < 0 ? lvb_len : rc);
}

/**
 * Server side ->l_glimpse_ast handler for client locks.
 *
 * Sends glimpse AST to the client and waits for reply. Then updates
 * lvbo with the result.
 */
int ldlm_server_glimpse_ast(struct ldlm_lock *lock, void *data)
{
	struct ldlm_cb_set_arg		*arg = data;
	struct ldlm_request		*body;
	struct ptlrpc_request		*req;
	struct ldlm_cb_async_args	*ca;
	int				 rc;
	struct req_format		*req_fmt;
        ENTRY;

        LASSERT(lock != NULL);

	if (arg->gl_desc != NULL)
		/* There is a glimpse descriptor to pack */
		req_fmt = &RQF_LDLM_GL_DESC_CALLBACK;
	else
		req_fmt = &RQF_LDLM_GL_CALLBACK;

        req = ptlrpc_request_alloc_pack(lock->l_export->exp_imp_reverse,
					req_fmt, LUSTRE_DLM_VERSION,
					LDLM_GL_CALLBACK);

        if (req == NULL)
                RETURN(-ENOMEM);

	if (arg->gl_desc != NULL) {
		/* copy the GL descriptor */
		union ldlm_gl_desc	*desc;
		desc = req_capsule_client_get(&req->rq_pill, &RMF_DLM_GL_DESC);
		*desc = *arg->gl_desc;
	}

        body = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        body->lock_handle[0] = lock->l_remote_handle;
        ldlm_lock2desc(lock, &body->lock_desc);

	CLASSERT(sizeof(*ca) <= sizeof(req->rq_async_args));
	ca = ptlrpc_req_async_args(req);
	ca->ca_set_arg = arg;
	ca->ca_lock = lock;

        /* server namespace, doesn't need lock */
        req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
                             ldlm_lvbo_size(lock));
        ptlrpc_request_set_replen(req);

        req->rq_send_state = LUSTRE_IMP_FULL;
        /* ptlrpc_request_alloc_pack already set timeout */
        if (AT_OFF)
                req->rq_timeout = ldlm_get_rq_timeout();

	lock->l_last_activity = ktime_get_real_seconds();

	req->rq_interpret_reply = ldlm_cb_interpret;

        if (lock->l_export && lock->l_export->exp_nid_stats &&
            lock->l_export->exp_nid_stats->nid_ldlm_stats)
                lprocfs_counter_incr(lock->l_export->exp_nid_stats->nid_ldlm_stats,
                                     LDLM_GL_CALLBACK - LDLM_FIRST_OPC);

	rc = ldlm_ast_fini(req, arg, lock, 0);

	RETURN(rc);
}

int ldlm_glimpse_locks(struct ldlm_resource *res,
		       struct list_head *gl_work_list)
{
	int	rc;
	ENTRY;

	rc = ldlm_run_ast_work(ldlm_res_to_ns(res), gl_work_list,
			       LDLM_WORK_GL_AST);
	if (rc == -ERESTART)
		ldlm_reprocess_all(res);

	RETURN(rc);
}
EXPORT_SYMBOL(ldlm_glimpse_locks);

/* return LDLM lock associated with a lock callback request */
struct ldlm_lock *ldlm_request_lock(struct ptlrpc_request *req)
{
	struct ldlm_cb_async_args	*ca;
	struct ldlm_lock		*lock;
	ENTRY;

	ca = ptlrpc_req_async_args(req);
	lock = ca->ca_lock;
	if (lock == NULL)
		RETURN(ERR_PTR(-EFAULT));

	RETURN(lock);
}
EXPORT_SYMBOL(ldlm_request_lock);

static void ldlm_svc_get_eopc(const struct ldlm_request *dlm_req,
                       struct lprocfs_stats *srv_stats)
{
        int lock_type = 0, op = 0;

        lock_type = dlm_req->lock_desc.l_resource.lr_type;

        switch (lock_type) {
        case LDLM_PLAIN:
                op = PTLRPC_LAST_CNTR + LDLM_PLAIN_ENQUEUE;
                break;
        case LDLM_EXTENT:
                if (dlm_req->lock_flags & LDLM_FL_HAS_INTENT)
                        op = PTLRPC_LAST_CNTR + LDLM_GLIMPSE_ENQUEUE;
                else
                        op = PTLRPC_LAST_CNTR + LDLM_EXTENT_ENQUEUE;
                break;
        case LDLM_FLOCK:
                op = PTLRPC_LAST_CNTR + LDLM_FLOCK_ENQUEUE;
                break;
        case LDLM_IBITS:
                op = PTLRPC_LAST_CNTR + LDLM_IBITS_ENQUEUE;
                break;
        default:
                op = 0;
                break;
        }

        if (op)
                lprocfs_counter_incr(srv_stats, op);

        return;
}

/**
 * Main server-side entry point into LDLM for enqueue. This is called by ptlrpc
 * service threads to carry out client lock enqueueing requests.
 */
int ldlm_handle_enqueue0(struct ldlm_namespace *ns,
			 struct ptlrpc_request *req,
			 const struct ldlm_request *dlm_req,
			 const struct ldlm_callback_suite *cbs)
{
	struct ldlm_reply *dlm_rep;
	__u64 flags;
	enum ldlm_error err = ELDLM_OK;
	struct ldlm_lock *lock = NULL;
	void *cookie = NULL;
	int rc = 0;
	struct ldlm_resource *res = NULL;
	ENTRY;

	LDLM_DEBUG_NOLOCK("server-side enqueue handler START");

	ldlm_request_cancel(req, dlm_req, LDLM_ENQUEUE_CANCEL_OFF, LATF_SKIP);
	flags = ldlm_flags_from_wire(dlm_req->lock_flags);

	LASSERT(req->rq_export);

	if (ptlrpc_req2svc(req)->srv_stats != NULL)
		ldlm_svc_get_eopc(dlm_req, ptlrpc_req2svc(req)->srv_stats);

        if (req->rq_export && req->rq_export->exp_nid_stats &&
            req->rq_export->exp_nid_stats->nid_ldlm_stats)
                lprocfs_counter_incr(req->rq_export->exp_nid_stats->nid_ldlm_stats,
                                     LDLM_ENQUEUE - LDLM_FIRST_OPC);

        if (unlikely(dlm_req->lock_desc.l_resource.lr_type < LDLM_MIN_TYPE ||
                     dlm_req->lock_desc.l_resource.lr_type >= LDLM_MAX_TYPE)) {
                DEBUG_REQ(D_ERROR, req, "invalid lock request type %d",
                          dlm_req->lock_desc.l_resource.lr_type);
                GOTO(out, rc = -EFAULT);
        }

        if (unlikely(dlm_req->lock_desc.l_req_mode <= LCK_MINMODE ||
                     dlm_req->lock_desc.l_req_mode >= LCK_MAXMODE ||
                     dlm_req->lock_desc.l_req_mode &
                     (dlm_req->lock_desc.l_req_mode-1))) {
                DEBUG_REQ(D_ERROR, req, "invalid lock request mode %d",
                          dlm_req->lock_desc.l_req_mode);
                GOTO(out, rc = -EFAULT);
        }

	if (exp_connect_flags(req->rq_export) & OBD_CONNECT_IBITS) {
                if (unlikely(dlm_req->lock_desc.l_resource.lr_type ==
                             LDLM_PLAIN)) {
                        DEBUG_REQ(D_ERROR, req,
                                  "PLAIN lock request from IBITS client?");
                        GOTO(out, rc = -EPROTO);
                }
        } else if (unlikely(dlm_req->lock_desc.l_resource.lr_type ==
                            LDLM_IBITS)) {
                DEBUG_REQ(D_ERROR, req,
                          "IBITS lock request from unaware client?");
                GOTO(out, rc = -EPROTO);
        }

	if (unlikely((flags & LDLM_FL_REPLAY) ||
		     (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT))) {
                /* Find an existing lock in the per-export lock hash */
		/* In the function below, .hs_keycmp resolves to
		 * ldlm_export_lock_keycmp() */
		/* coverity[overrun-buffer-val] */
                lock = cfs_hash_lookup(req->rq_export->exp_lock_hash,
                                       (void *)&dlm_req->lock_handle[0]);
                if (lock != NULL) {
			DEBUG_REQ(D_DLMTRACE, req, "found existing lock cookie %#llx",
				  lock->l_handle.h_cookie);
			flags |= LDLM_FL_RESENT;
                        GOTO(existing_lock, rc = 0);
		}
	} else {
		if (ldlm_reclaim_full()) {
			DEBUG_REQ(D_DLMTRACE, req, "Too many granted locks, "
				  "reject current enqueue request and let the "
				  "client retry later.\n");
			GOTO(out, rc = -EINPROGRESS);
		}
	}

	/* The lock's callback data might be set in the policy function */
	lock = ldlm_lock_create(ns, &dlm_req->lock_desc.l_resource.lr_name,
				dlm_req->lock_desc.l_resource.lr_type,
				dlm_req->lock_desc.l_req_mode,
				cbs, NULL, 0, LVB_T_NONE);
	if (IS_ERR(lock)) {
		rc = PTR_ERR(lock);
		lock = NULL;
		GOTO(out, rc);
	}

        lock->l_remote_handle = dlm_req->lock_handle[0];
        LDLM_DEBUG(lock, "server-side enqueue handler, new lock created");

	/* Initialize resource lvb but not for a lock being replayed since
	 * Client already got lvb sent in this case.
	 * This must occur early since some policy methods assume resource
	 * lvb is available (lr_lvb_data != NULL).
	 */
	res = lock->l_resource;
	if (!(flags & LDLM_FL_REPLAY)) {
		/* non-replayed lock, delayed lvb init may need to be done */
		rc = ldlm_lvbo_init(res);
		if (rc < 0) {
			LDLM_DEBUG(lock, "delayed lvb init failed (rc %d)", rc);
			GOTO(out, rc);
		}
	}

        OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_ENQUEUE_BLOCKED, obd_timeout * 2);
        /* Don't enqueue a lock onto the export if it is been disonnected
         * due to eviction (bug 3822) or server umount (bug 24324).
         * Cancel it now instead. */
        if (req->rq_export->exp_disconnected) {
                LDLM_ERROR(lock, "lock on disconnected export %p",
                           req->rq_export);
                GOTO(out, rc = -ENOTCONN);
        }

        lock->l_export = class_export_lock_get(req->rq_export, lock);
        if (lock->l_export->exp_lock_hash)
                cfs_hash_add(lock->l_export->exp_lock_hash,
                             &lock->l_remote_handle,
                             &lock->l_exp_hash);

	/* Inherit the enqueue flags before the operation, because we do not
	 * keep the res lock on return and next operations (BL AST) may proceed
	 * without them. */
	lock->l_flags |= ldlm_flags_from_wire(dlm_req->lock_flags &
					      LDLM_FL_INHERIT_MASK);

	ldlm_convert_policy_to_local(req->rq_export,
				     dlm_req->lock_desc.l_resource.lr_type,
				     &dlm_req->lock_desc.l_policy_data,
				     &lock->l_policy_data);
	if (dlm_req->lock_desc.l_resource.lr_type == LDLM_EXTENT)
		lock->l_req_extent = lock->l_policy_data.l_extent;

existing_lock:

        if (flags & LDLM_FL_HAS_INTENT) {
                /* In this case, the reply buffer is allocated deep in
                 * local_lock_enqueue by the policy function. */
                cookie = req;
        } else {
                /* based on the assumption that lvb size never changes during
                 * resource life time otherwise it need resource->lr_lock's
                 * protection */
		req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB,
				     RCL_SERVER, ldlm_lvbo_size(lock));

                if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_ENQUEUE_EXTENT_ERR))
                        GOTO(out, rc = -ENOMEM);

                rc = req_capsule_server_pack(&req->rq_pill);
                if (rc)
                        GOTO(out, rc);
        }

	err = ldlm_lock_enqueue(ns, &lock, cookie, &flags);
	if (err) {
		if ((int)err < 0)
			rc = (int)err;
		GOTO(out, err);
	}

        dlm_rep = req_capsule_server_get(&req->rq_pill, &RMF_DLM_REP);

        ldlm_lock2desc(lock, &dlm_rep->lock_desc);
        ldlm_lock2handle(lock, &dlm_rep->lock_handle);

	if (lock && lock->l_resource->lr_type == LDLM_EXTENT)
		OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_BL_EVICT, 6);

        /* We never send a blocking AST until the lock is granted, but
         * we can tell it right now */
        lock_res_and_lock(lock);

        /* Now take into account flags to be inherited from original lock
           request both in reply to client and in our own lock flags. */
	dlm_rep->lock_flags = ldlm_flags_to_wire(flags);
	lock->l_flags |= flags & LDLM_FL_INHERIT_MASK;

        /* Don't move a pending lock onto the export if it has already been
         * disconnected due to eviction (bug 5683) or server umount (bug 24324).
         * Cancel it now instead. */
        if (unlikely(req->rq_export->exp_disconnected ||
                     OBD_FAIL_CHECK(OBD_FAIL_LDLM_ENQUEUE_OLD_EXPORT))) {
                LDLM_ERROR(lock, "lock on destroyed export %p", req->rq_export);
                rc = -ENOTCONN;
	} else if (ldlm_is_ast_sent(lock)) {
		dlm_rep->lock_flags |= ldlm_flags_to_wire(LDLM_FL_AST_SENT);
                if (lock->l_granted_mode == lock->l_req_mode) {
                        /*
                         * Only cancel lock if it was granted, because it would
                         * be destroyed immediately and would never be granted
                         * in the future, causing timeouts on client.  Not
                         * granted lock will be cancelled immediately after
                         * sending completion AST.
                         */
                        if (dlm_rep->lock_flags & LDLM_FL_CANCEL_ON_BLOCK) {
                                unlock_res_and_lock(lock);
                                ldlm_lock_cancel(lock);
                                lock_res_and_lock(lock);
                        } else
                                ldlm_add_waiting_lock(lock);
                }
        }
        /* Make sure we never ever grant usual metadata locks to liblustre
           clients */
        if ((dlm_req->lock_desc.l_resource.lr_type == LDLM_PLAIN ||
            dlm_req->lock_desc.l_resource.lr_type == LDLM_IBITS) &&
             req->rq_export->exp_libclient) {
		if (unlikely(!ldlm_is_cancel_on_block(lock) ||
                             !(dlm_rep->lock_flags & LDLM_FL_CANCEL_ON_BLOCK))){
                        CERROR("Granting sync lock to libclient. "
			       "req fl %d, rep fl %d, lock fl %#llx\n",
                               dlm_req->lock_flags, dlm_rep->lock_flags,
                               lock->l_flags);
                        LDLM_ERROR(lock, "sync lock");
			if (dlm_req->lock_flags & LDLM_FL_HAS_INTENT) {
				struct ldlm_intent *it;

				it = req_capsule_client_get(&req->rq_pill,
							    &RMF_LDLM_INTENT);
				if (it != NULL) {
					CERROR("This is intent %s (%llu)\n",
					       ldlm_it2str(it->opc), it->opc);
				}
			}
                }
        }

        unlock_res_and_lock(lock);

        EXIT;
 out:
        req->rq_status = rc ?: err; /* return either error - bug 11190 */
        if (!req->rq_packed_final) {
                err = lustre_pack_reply(req, 1, NULL, NULL);
                if (rc == 0)
                        rc = err;
        }

        /* The LOCK_CHANGED code in ldlm_lock_enqueue depends on this
         * ldlm_reprocess_all.  If this moves, revisit that code. -phil */
	if (lock != NULL) {
		LDLM_DEBUG(lock, "server-side enqueue handler, sending reply"
			   "(err=%d, rc=%d)", err, rc);

		if (rc == 0) {
			if (req_capsule_has_field(&req->rq_pill, &RMF_DLM_LVB,
						  RCL_SERVER) &&
			    ldlm_lvbo_size(lock) > 0) {
				void *buf;
				int buflen;

				buf = req_capsule_server_get(&req->rq_pill,
							     &RMF_DLM_LVB);
				LASSERTF(buf != NULL, "req %p, lock %p\n",
					 req, lock);
				buflen = req_capsule_get_size(&req->rq_pill,
						&RMF_DLM_LVB, RCL_SERVER);
				/* non-replayed lock, delayed lvb init may
				 * need to be occur now */
				if ((buflen > 0) && !(flags & LDLM_FL_REPLAY)) {
					buflen = ldlm_lvbo_fill(lock, buf,
								buflen);
					if (buflen >= 0)
						req_capsule_shrink(
							&req->rq_pill,
							&RMF_DLM_LVB,
							buflen, RCL_SERVER);
					else
						rc = buflen;
				} else if (flags & LDLM_FL_REPLAY) {
					/* no LVB resend upon replay */
					if (buflen > 0)
						req_capsule_shrink(
							&req->rq_pill,
							&RMF_DLM_LVB,
							0, RCL_SERVER);
					else
						rc = buflen;
				} else {
					rc = buflen;
				}
			}
		}

		if (rc != 0 && !(flags & LDLM_FL_RESENT)) {
			if (lock->l_export) {
				ldlm_lock_cancel(lock);
			} else {
				lock_res_and_lock(lock);
				ldlm_resource_unlink_lock(lock);
				ldlm_lock_destroy_nolock(lock);
				unlock_res_and_lock(lock);

			}
		}

                if (!err && dlm_req->lock_desc.l_resource.lr_type != LDLM_FLOCK)
                        ldlm_reprocess_all(lock->l_resource);

                LDLM_LOCK_RELEASE(lock);
        }

        LDLM_DEBUG_NOLOCK("server-side enqueue handler END (lock %p, rc %d)",
                          lock, rc);

        return rc;
}

/**
 * Old-style LDLM main entry point for server code enqueue.
 */
int ldlm_handle_enqueue(struct ptlrpc_request *req,
                        ldlm_completion_callback completion_callback,
                        ldlm_blocking_callback blocking_callback,
                        ldlm_glimpse_callback glimpse_callback)
{
        struct ldlm_request *dlm_req;
        struct ldlm_callback_suite cbs = {
                .lcs_completion = completion_callback,
                .lcs_blocking   = blocking_callback,
                .lcs_glimpse    = glimpse_callback
        };
        int rc;

        dlm_req = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        if (dlm_req != NULL) {
                rc = ldlm_handle_enqueue0(req->rq_export->exp_obd->obd_namespace,
                                          req, dlm_req, &cbs);
        } else {
                rc = -EFAULT;
        }
        return rc;
}

/**
 * Main LDLM entry point for server code to process lock conversion requests.
 */
int ldlm_handle_convert0(struct ptlrpc_request *req,
                         const struct ldlm_request *dlm_req)
{
        struct ldlm_reply *dlm_rep;
        struct ldlm_lock *lock;
        int rc;
        ENTRY;

        if (req->rq_export && req->rq_export->exp_nid_stats &&
            req->rq_export->exp_nid_stats->nid_ldlm_stats)
                lprocfs_counter_incr(req->rq_export->exp_nid_stats->nid_ldlm_stats,
                                     LDLM_CONVERT - LDLM_FIRST_OPC);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        dlm_rep = req_capsule_server_get(&req->rq_pill, &RMF_DLM_REP);
        dlm_rep->lock_flags = dlm_req->lock_flags;

        lock = ldlm_handle2lock(&dlm_req->lock_handle[0]);
        if (!lock) {
		req->rq_status = LUSTRE_EINVAL;
        } else {
                void *res = NULL;

                LDLM_DEBUG(lock, "server-side convert handler START");

                res = ldlm_lock_convert(lock, dlm_req->lock_desc.l_req_mode,
                                        &dlm_rep->lock_flags);
                if (res) {
                        if (ldlm_del_waiting_lock(lock))
                                LDLM_DEBUG(lock, "converted waiting lock");
                        req->rq_status = 0;
                } else {
			req->rq_status = LUSTRE_EDEADLK;
                }
        }

        if (lock) {
                if (!req->rq_status)
                        ldlm_reprocess_all(lock->l_resource);
                LDLM_DEBUG(lock, "server-side convert handler END");
                LDLM_LOCK_PUT(lock);
        } else
                LDLM_DEBUG_NOLOCK("server-side convert handler END");

        RETURN(0);
}

/**
 * Old-style main LDLM entry point for server code to process lock conversion
 * requests.
 */
int ldlm_handle_convert(struct ptlrpc_request *req)
{
        int rc;
        struct ldlm_request *dlm_req;

        dlm_req = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        if (dlm_req != NULL) {
                rc = ldlm_handle_convert0(req, dlm_req);
        } else {
                CERROR ("Can't unpack dlm_req\n");
                rc = -EFAULT;
        }
        return rc;
}

/**
 * Cancel all the locks whose handles are packed into ldlm_request
 *
 * Called by server code expecting such combined cancel activity
 * requests.
 */
int ldlm_request_cancel(struct ptlrpc_request *req,
			const struct ldlm_request *dlm_req,
			int first, enum lustre_at_flags flags)
{
        struct ldlm_resource *res, *pres = NULL;
        struct ldlm_lock *lock;
        int i, count, done = 0;
        ENTRY;

        count = dlm_req->lock_count ? dlm_req->lock_count : 1;
        if (first >= count)
                RETURN(0);

	if (count == 1 && dlm_req->lock_handle[0].cookie == 0)
		RETURN(0);

        /* There is no lock on the server at the replay time,
         * skip lock cancelling to make replay tests to pass. */
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY)
                RETURN(0);

        LDLM_DEBUG_NOLOCK("server-side cancel handler START: %d locks, "
                          "starting at %d", count, first);

        for (i = first; i < count; i++) {
                lock = ldlm_handle2lock(&dlm_req->lock_handle[i]);
                if (!lock) {
                        LDLM_DEBUG_NOLOCK("server-side cancel handler stale "
					  "lock (cookie %llu)",
                                          dlm_req->lock_handle[i].cookie);
                        continue;
                }

                res = lock->l_resource;
                done++;

		/* This code is an optimization to only attempt lock
		 * granting on the resource (that could be CPU-expensive)
		 * after we are done cancelling lock in that resource. */
                if (res != pres) {
                        if (pres != NULL) {
                                ldlm_reprocess_all(pres);
                                LDLM_RESOURCE_DELREF(pres);
                                ldlm_resource_putref(pres);
                        }
                        if (res != NULL) {
                                ldlm_resource_getref(res);
                                LDLM_RESOURCE_ADDREF(res);
                                ldlm_res_lvbo_update(res, NULL, 1);
                        }
                        pres = res;
                }

		if ((flags & LATF_STATS) && ldlm_is_ast_sent(lock)) {
			time64_t delay = ktime_get_real_seconds() -
					 lock->l_last_activity;
			LDLM_DEBUG(lock, "server cancels blocked lock after %llds",
				   (s64)delay);
			at_measured(&lock->l_export->exp_bl_lock_at, delay);
		}
                ldlm_lock_cancel(lock);
                LDLM_LOCK_PUT(lock);
        }
        if (pres != NULL) {
                ldlm_reprocess_all(pres);
                LDLM_RESOURCE_DELREF(pres);
                ldlm_resource_putref(pres);
        }
        LDLM_DEBUG_NOLOCK("server-side cancel handler END");
        RETURN(done);
}
EXPORT_SYMBOL(ldlm_request_cancel);

/**
 * Main LDLM entry point for server code to cancel locks.
 *
 * Typically gets called from service handler on LDLM_CANCEL opc.
 */
int ldlm_handle_cancel(struct ptlrpc_request *req)
{
        struct ldlm_request *dlm_req;
        int rc;
        ENTRY;

        dlm_req = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        if (dlm_req == NULL) {
                CDEBUG(D_INFO, "bad request buffer for cancel\n");
                RETURN(-EFAULT);
        }

        if (req->rq_export && req->rq_export->exp_nid_stats &&
            req->rq_export->exp_nid_stats->nid_ldlm_stats)
                lprocfs_counter_incr(req->rq_export->exp_nid_stats->nid_ldlm_stats,
                                     LDLM_CANCEL - LDLM_FIRST_OPC);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

	if (!ldlm_request_cancel(req, dlm_req, 0, LATF_STATS))
		req->rq_status = LUSTRE_ESTALE;

        RETURN(ptlrpc_reply(req));
}
#endif /* HAVE_SERVER_SUPPORT */

/**
 * Callback handler for receiving incoming blocking ASTs.
 *
 * This can only happen on client side.
 */
void ldlm_handle_bl_callback(struct ldlm_namespace *ns,
                             struct ldlm_lock_desc *ld, struct ldlm_lock *lock)
{
        int do_ast;
        ENTRY;

        LDLM_DEBUG(lock, "client blocking AST callback handler");

        lock_res_and_lock(lock);
	ldlm_set_cbpending(lock);

	if (ldlm_is_cancel_on_block(lock))
		ldlm_set_cancel(lock);

        do_ast = (!lock->l_readers && !lock->l_writers);
        unlock_res_and_lock(lock);

        if (do_ast) {
                CDEBUG(D_DLMTRACE, "Lock %p already unused, calling callback (%p)\n",
                       lock, lock->l_blocking_ast);
                if (lock->l_blocking_ast != NULL)
                        lock->l_blocking_ast(lock, ld, lock->l_ast_data,
                                             LDLM_CB_BLOCKING);
        } else {
                CDEBUG(D_DLMTRACE, "Lock %p is referenced, will be cancelled later\n",
                       lock);
        }

        LDLM_DEBUG(lock, "client blocking callback handler END");
        LDLM_LOCK_RELEASE(lock);
        EXIT;
}

/**
 * Callback handler for receiving incoming completion ASTs.
 *
 * This only can happen on client side.
 */
static void ldlm_handle_cp_callback(struct ptlrpc_request *req,
                                    struct ldlm_namespace *ns,
                                    struct ldlm_request *dlm_req,
                                    struct ldlm_lock *lock)
{
	struct list_head ast_list;
	int lvb_len;
	int rc = 0;
	ENTRY;

	LDLM_DEBUG(lock, "client completion callback handler START");

	INIT_LIST_HEAD(&ast_list);
	if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_BL_CB_RACE)) {
		int to = cfs_time_seconds(1);
		while (to > 0) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(to);
			if (lock->l_granted_mode == lock->l_req_mode ||
			    ldlm_is_destroyed(lock))
				break;
		}
	}

	lvb_len = req_capsule_get_size(&req->rq_pill, &RMF_DLM_LVB, RCL_CLIENT);
	if (lvb_len < 0) {
		LDLM_ERROR(lock, "Fail to get lvb_len, rc = %d", lvb_len);
		GOTO(out, rc = lvb_len);
	} else if (lvb_len > 0) {
		if (lock->l_lvb_len > 0) {
			/* for extent lock, lvb contains ost_lvb{}. */
			LASSERT(lock->l_lvb_data != NULL);

			if (unlikely(lock->l_lvb_len < lvb_len)) {
				LDLM_ERROR(lock, "Replied LVB is larger than "
					   "expectation, expected = %d, "
					   "replied = %d",
					   lock->l_lvb_len, lvb_len);
				GOTO(out, rc = -EINVAL);
			}
		}
	}

	lock_res_and_lock(lock);
	if (ldlm_is_destroyed(lock) ||
	    lock->l_granted_mode == lock->l_req_mode) {
		/* bug 11300: the lock has already been granted */
		unlock_res_and_lock(lock);
		LDLM_DEBUG(lock, "Double grant race happened");
		GOTO(out, rc = 0);
	}

	/* If we receive the completion AST before the actual enqueue returned,
	 * then we might need to switch lock modes, resources, or extents. */
	if (dlm_req->lock_desc.l_granted_mode != lock->l_req_mode) {
		lock->l_req_mode = dlm_req->lock_desc.l_granted_mode;
		LDLM_DEBUG(lock, "completion AST, new lock mode");
	}

	if (lock->l_resource->lr_type != LDLM_PLAIN) {
		ldlm_convert_policy_to_local(req->rq_export,
					  dlm_req->lock_desc.l_resource.lr_type,
					  &dlm_req->lock_desc.l_policy_data,
					  &lock->l_policy_data);
		LDLM_DEBUG(lock, "completion AST, new policy data");
	}

        ldlm_resource_unlink_lock(lock);
        if (memcmp(&dlm_req->lock_desc.l_resource.lr_name,
                   &lock->l_resource->lr_name,
                   sizeof(lock->l_resource->lr_name)) != 0) {
                unlock_res_and_lock(lock);
		rc = ldlm_lock_change_resource(ns, lock,
				&dlm_req->lock_desc.l_resource.lr_name);
		if (rc < 0) {
			LDLM_ERROR(lock, "Failed to allocate resource");
			GOTO(out, rc);
		}
                LDLM_DEBUG(lock, "completion AST, new resource");
                CERROR("change resource!\n");
                lock_res_and_lock(lock);
        }

        if (dlm_req->lock_flags & LDLM_FL_AST_SENT) {
		/* BL_AST locks are not needed in LRU.
		 * Let ldlm_cancel_lru() be fast. */
                ldlm_lock_remove_from_lru(lock);
		lock->l_flags |= LDLM_FL_CBPENDING | LDLM_FL_BL_AST;
                LDLM_DEBUG(lock, "completion AST includes blocking AST");
        }

	if (lock->l_lvb_len > 0) {
		rc = ldlm_fill_lvb(lock, &req->rq_pill, RCL_CLIENT,
				   lock->l_lvb_data, lvb_len);
		if (rc < 0) {
			unlock_res_and_lock(lock);
			GOTO(out, rc);
		}
	}

        ldlm_grant_lock(lock, &ast_list);
        unlock_res_and_lock(lock);

        LDLM_DEBUG(lock, "callback handler finished, about to run_ast_work");

        /* Let Enqueue to call osc_lock_upcall() and initialize
         * l_ast_data */
        OBD_FAIL_TIMEOUT(OBD_FAIL_OSC_CP_ENQ_RACE, 2);

        ldlm_run_ast_work(ns, &ast_list, LDLM_WORK_CP_AST);

        LDLM_DEBUG_NOLOCK("client completion callback handler END (lock %p)",
                          lock);
	GOTO(out, rc);

out:
	if (rc < 0) {
		lock_res_and_lock(lock);
		ldlm_set_failed(lock);
		unlock_res_and_lock(lock);
		wake_up(&lock->l_waitq);
	}
	LDLM_LOCK_RELEASE(lock);
}

/**
 * Callback handler for receiving incoming glimpse ASTs.
 *
 * This only can happen on client side.  After handling the glimpse AST
 * we also consider dropping the lock here if it is unused locally for a
 * long time.
 */
static void ldlm_handle_gl_callback(struct ptlrpc_request *req,
                                    struct ldlm_namespace *ns,
                                    struct ldlm_request *dlm_req,
                                    struct ldlm_lock *lock)
{
        int rc = -ENOSYS;
        ENTRY;

        LDLM_DEBUG(lock, "client glimpse AST callback handler");

        if (lock->l_glimpse_ast != NULL)
                rc = lock->l_glimpse_ast(lock, req);

        if (req->rq_repmsg != NULL) {
                ptlrpc_reply(req);
        } else {
                req->rq_status = rc;
                ptlrpc_error(req);
        }

        lock_res_and_lock(lock);
        if (lock->l_granted_mode == LCK_PW &&
            !lock->l_readers && !lock->l_writers &&
	    ktime_after(ktime_get(),
			ktime_add(lock->l_last_used,
				  ktime_set(10, 0)))) {
                unlock_res_and_lock(lock);
                if (ldlm_bl_to_thread_lock(ns, NULL, lock))
                        ldlm_handle_bl_callback(ns, NULL, lock);

                EXIT;
                return;
        }
        unlock_res_and_lock(lock);
        LDLM_LOCK_RELEASE(lock);
        EXIT;
}

static int ldlm_callback_reply(struct ptlrpc_request *req, int rc)
{
        if (req->rq_no_reply)
                return 0;

        req->rq_status = rc;
        if (!req->rq_packed_final) {
                rc = lustre_pack_reply(req, 1, NULL, NULL);
                if (rc)
                        return rc;
        }
        return ptlrpc_reply(req);
}

static int __ldlm_bl_to_thread(struct ldlm_bl_work_item *blwi,
			       enum ldlm_cancel_flags cancel_flags)
{
	struct ldlm_bl_pool *blp = ldlm_state->ldlm_bl_pool;
	ENTRY;

	spin_lock(&blp->blp_lock);
	if (blwi->blwi_lock &&
	    ldlm_is_discard_data(blwi->blwi_lock)) {
		/* add LDLM_FL_DISCARD_DATA requests to the priority list */
		list_add_tail(&blwi->blwi_entry, &blp->blp_prio_list);
	} else {
		/* other blocking callbacks are added to the regular list */
		list_add_tail(&blwi->blwi_entry, &blp->blp_list);
	}
	spin_unlock(&blp->blp_lock);

	wake_up(&blp->blp_waitq);

	/* can not check blwi->blwi_flags as blwi could be already freed in
	   LCF_ASYNC mode */
	if (!(cancel_flags & LCF_ASYNC))
		wait_for_completion(&blwi->blwi_comp);

	RETURN(0);
}

static inline void init_blwi(struct ldlm_bl_work_item *blwi,
			     struct ldlm_namespace *ns,
			     struct ldlm_lock_desc *ld,
			     struct list_head *cancels, int count,
			     struct ldlm_lock *lock,
			     enum ldlm_cancel_flags cancel_flags)
{
	init_completion(&blwi->blwi_comp);
	INIT_LIST_HEAD(&blwi->blwi_head);

	if (memory_pressure_get())
                blwi->blwi_mem_pressure = 1;

        blwi->blwi_ns = ns;
	blwi->blwi_flags = cancel_flags;
        if (ld != NULL)
                blwi->blwi_ld = *ld;
        if (count) {
		list_add(&blwi->blwi_head, cancels);
		list_del_init(cancels);
                blwi->blwi_count = count;
        } else {
                blwi->blwi_lock = lock;
        }
}

/**
 * Queues a list of locks \a cancels containing \a count locks
 * for later processing by a blocking thread.  If \a count is zero,
 * then the lock referenced as \a lock is queued instead.
 *
 * The blocking thread would then call ->l_blocking_ast callback in the lock.
 * If list addition fails an error is returned and caller is supposed to
 * call ->l_blocking_ast itself.
 */
static int ldlm_bl_to_thread(struct ldlm_namespace *ns,
			     struct ldlm_lock_desc *ld,
			     struct ldlm_lock *lock,
			     struct list_head *cancels, int count,
			     enum ldlm_cancel_flags cancel_flags)
{
	ENTRY;

	if (cancels && count == 0)
		RETURN(0);

	if (cancel_flags & LCF_ASYNC) {
		struct ldlm_bl_work_item *blwi;

		OBD_ALLOC(blwi, sizeof(*blwi));
		if (blwi == NULL)
			RETURN(-ENOMEM);
		init_blwi(blwi, ns, ld, cancels, count, lock, cancel_flags);

		RETURN(__ldlm_bl_to_thread(blwi, cancel_flags));
	} else {
		/* if it is synchronous call do minimum mem alloc, as it could
		 * be triggered from kernel shrinker
		 */
		struct ldlm_bl_work_item blwi;

		memset(&blwi, 0, sizeof(blwi));
		init_blwi(&blwi, ns, ld, cancels, count, lock, cancel_flags);
		RETURN(__ldlm_bl_to_thread(&blwi, cancel_flags));
	}
}


int ldlm_bl_to_thread_lock(struct ldlm_namespace *ns, struct ldlm_lock_desc *ld,
			   struct ldlm_lock *lock)
{
	return ldlm_bl_to_thread(ns, ld, lock, NULL, 0, LCF_ASYNC);
}

int ldlm_bl_to_thread_list(struct ldlm_namespace *ns, struct ldlm_lock_desc *ld,
			   struct list_head *cancels, int count,
			   enum ldlm_cancel_flags cancel_flags)
{
	return ldlm_bl_to_thread(ns, ld, NULL, cancels, count, cancel_flags);
}

int ldlm_bl_thread_wakeup(void)
{
	wake_up(&ldlm_state->ldlm_bl_pool->blp_waitq);
	return 0;
}

/* Setinfo coming from Server (eg MDT) to Client (eg MDC)! */
static int ldlm_handle_setinfo(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        char *key;
        void *val;
        int keylen, vallen;
        int rc = -ENOSYS;
        ENTRY;

        DEBUG_REQ(D_HSM, req, "%s: handle setinfo\n", obd->obd_name);

        req_capsule_set(&req->rq_pill, &RQF_OBD_SET_INFO);

        key = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_KEY);
        if (key == NULL) {
                DEBUG_REQ(D_IOCTL, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = req_capsule_get_size(&req->rq_pill, &RMF_SETINFO_KEY,
                                      RCL_CLIENT);
        val = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_VAL);
        if (val == NULL) {
                DEBUG_REQ(D_IOCTL, req, "no set_info val");
                RETURN(-EFAULT);
        }
        vallen = req_capsule_get_size(&req->rq_pill, &RMF_SETINFO_VAL,
                                      RCL_CLIENT);

        /* We are responsible for swabbing contents of val */

        if (KEY_IS(KEY_HSM_COPYTOOL_SEND))
                /* Pass it on to mdc (the "export" in this case) */
                rc = obd_set_info_async(req->rq_svc_thread->t_env,
                                        req->rq_export,
                                        sizeof(KEY_HSM_COPYTOOL_SEND),
                                        KEY_HSM_COPYTOOL_SEND,
                                        vallen, val, NULL);
        else
                DEBUG_REQ(D_WARNING, req, "ignoring unknown key %s", key);

        return rc;
}

static inline void ldlm_callback_errmsg(struct ptlrpc_request *req,
					const char *msg, int rc,
					const struct lustre_handle *handle)
{
        DEBUG_REQ((req->rq_no_reply || rc) ? D_WARNING : D_DLMTRACE, req,
		  "%s: [nid %s] [rc %d] [lock %#llx]",
                  msg, libcfs_id2str(req->rq_peer), rc,
                  handle ? handle->cookie : 0);
        if (req->rq_no_reply)
                CWARN("No reply was sent, maybe cause bug 21636.\n");
        else if (rc)
                CWARN("Send reply failed, maybe cause bug 21636.\n");
}

/* TODO: handle requests in a similar way as MDT: see mdt_handle_common() */
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

        /* do nothing for sec context finalize */
        if (lustre_msg_get_opc(req->rq_reqmsg) == SEC_CTX_FINI)
                RETURN(0);

        req_capsule_init(&req->rq_pill, req, RCL_SERVER);

        if (req->rq_export == NULL) {
                rc = ldlm_callback_reply(req, -ENOTCONN);
                ldlm_callback_errmsg(req, "Operate on unconnected server",
                                     rc, NULL);
                RETURN(0);
        }

        LASSERT(req->rq_export != NULL);
        LASSERT(req->rq_export->exp_obd != NULL);

	switch (lustre_msg_get_opc(req->rq_reqmsg)) {
	case LDLM_BL_CALLBACK:
		if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_BL_CALLBACK_NET)) {
			if (cfs_fail_err)
				ldlm_callback_reply(req, -(int)cfs_fail_err);
			RETURN(0);
		}
		break;
	case LDLM_CP_CALLBACK:
		if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_CP_CALLBACK_NET))
			RETURN(0);
		break;
	case LDLM_GL_CALLBACK:
		if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_GL_CALLBACK_NET))
			RETURN(0);
		break;
        case LDLM_SET_INFO:
                rc = ldlm_handle_setinfo(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case LLOG_ORIGIN_HANDLE_CREATE:
                req_capsule_set(&req->rq_pill, &RQF_LLOG_ORIGIN_HANDLE_CREATE);
                if (OBD_FAIL_CHECK(OBD_FAIL_OBD_LOGD_NET))
                        RETURN(0);
		rc = llog_origin_handle_open(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
                req_capsule_set(&req->rq_pill,
                                &RQF_LLOG_ORIGIN_HANDLE_NEXT_BLOCK);
                if (OBD_FAIL_CHECK(OBD_FAIL_OBD_LOGD_NET))
                        RETURN(0);
                rc = llog_origin_handle_next_block(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
                req_capsule_set(&req->rq_pill,
                                &RQF_LLOG_ORIGIN_HANDLE_READ_HEADER);
                if (OBD_FAIL_CHECK(OBD_FAIL_OBD_LOGD_NET))
                        RETURN(0);
                rc = llog_origin_handle_read_header(req);
                ldlm_callback_reply(req, rc);
                RETURN(0);
        case LLOG_ORIGIN_HANDLE_CLOSE:
                if (OBD_FAIL_CHECK(OBD_FAIL_OBD_LOGD_NET))
                        RETURN(0);
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

        req_capsule_set(&req->rq_pill, &RQF_LDLM_CALLBACK);

        dlm_req = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        if (dlm_req == NULL) {
                rc = ldlm_callback_reply(req, -EPROTO);
                ldlm_callback_errmsg(req, "Operate without parameter", rc,
                                     NULL);
                RETURN(0);
        }

        /* Force a known safe race, send a cancel to the server for a lock
         * which the server has already started a blocking callback on. */
        if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_BL_CB_RACE) &&
            lustre_msg_get_opc(req->rq_reqmsg) == LDLM_BL_CALLBACK) {
		rc = ldlm_cli_cancel(&dlm_req->lock_handle[0], 0);
                if (rc < 0)
                        CERROR("ldlm_cli_cancel: %d\n", rc);
        }

        lock = ldlm_handle2lock_long(&dlm_req->lock_handle[0], 0);
        if (!lock) {
		CDEBUG(D_DLMTRACE, "callback on lock %#llx - lock "
                       "disappeared\n", dlm_req->lock_handle[0].cookie);
                rc = ldlm_callback_reply(req, -EINVAL);
                ldlm_callback_errmsg(req, "Operate with invalid parameter", rc,
                                     &dlm_req->lock_handle[0]);
                RETURN(0);
        }

	if (ldlm_is_fail_loc(lock) &&
            lustre_msg_get_opc(req->rq_reqmsg) == LDLM_BL_CALLBACK)
                OBD_RACE(OBD_FAIL_LDLM_CP_BL_RACE);

        /* Copy hints/flags (e.g. LDLM_FL_DISCARD_DATA) from AST. */
        lock_res_and_lock(lock);
	lock->l_flags |= ldlm_flags_from_wire(dlm_req->lock_flags &
					      LDLM_FL_AST_MASK);
	if (lustre_msg_get_opc(req->rq_reqmsg) == LDLM_BL_CALLBACK) {
		/* If somebody cancels lock and cache is already dropped,
		 * or lock is failed before cp_ast received on client,
		 * we can tell the server we have no lock. Otherwise, we
		 * should send cancel after dropping the cache. */
		if ((ldlm_is_canceling(lock) && ldlm_is_bl_done(lock)) ||
		     ldlm_is_failed(lock)) {
			LDLM_DEBUG(lock, "callback on lock %llx - lock disappeared",
				   dlm_req->lock_handle[0].cookie);
			unlock_res_and_lock(lock);
			LDLM_LOCK_RELEASE(lock);
			rc = ldlm_callback_reply(req, -EINVAL);
			ldlm_callback_errmsg(req, "Operate on stale lock", rc,
					     &dlm_req->lock_handle[0]);
			RETURN(0);
		}
		/* BL_AST locks are not needed in LRU.
		 * Let ldlm_cancel_lru() be fast. */
		ldlm_lock_remove_from_lru(lock);
		ldlm_set_bl_ast(lock);
	}
        unlock_res_and_lock(lock);

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
                req_capsule_extend(&req->rq_pill, &RQF_LDLM_BL_CALLBACK);
		if (!ldlm_is_cancel_on_block(lock)) {
                        rc = ldlm_callback_reply(req, 0);
                        if (req->rq_no_reply || rc)
                                ldlm_callback_errmsg(req, "Normal process", rc,
                                                     &dlm_req->lock_handle[0]);
                }
                if (ldlm_bl_to_thread_lock(ns, &dlm_req->lock_desc, lock))
                        ldlm_handle_bl_callback(ns, &dlm_req->lock_desc, lock);
                break;
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "completion ast\n");
                req_capsule_extend(&req->rq_pill, &RQF_LDLM_CP_CALLBACK);
                ldlm_callback_reply(req, 0);
                ldlm_handle_cp_callback(req, ns, dlm_req, lock);
                break;
        case LDLM_GL_CALLBACK:
                CDEBUG(D_INODE, "glimpse ast\n");
                req_capsule_extend(&req->rq_pill, &RQF_LDLM_GL_CALLBACK);
                ldlm_handle_gl_callback(req, ns, dlm_req, lock);
                break;
        default:
                LBUG();                         /* checked above */
        }

        RETURN(0);
}

#ifdef HAVE_SERVER_SUPPORT
/**
 * Main handler for canceld thread.
 *
 * Separated into its own thread to avoid deadlocks.
 */
static int ldlm_cancel_handler(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        /* Requests arrive in sender's byte order.  The ptlrpc service
         * handler has already checked and, if necessary, byte-swapped the
         * incoming request message body, but I am responsible for the
         * message buffers. */

        req_capsule_init(&req->rq_pill, req, RCL_SERVER);

        if (req->rq_export == NULL) {
                struct ldlm_request *dlm_req;

                CERROR("%s from %s arrived at %lu with bad export cookie "
		       "%llu\n",
                       ll_opcode2str(lustre_msg_get_opc(req->rq_reqmsg)),
                       libcfs_nid2str(req->rq_peer.nid),
                       req->rq_arrival_time.tv_sec,
                       lustre_msg_get_handle(req->rq_reqmsg)->cookie);

                if (lustre_msg_get_opc(req->rq_reqmsg) == LDLM_CANCEL) {
                        req_capsule_set(&req->rq_pill, &RQF_LDLM_CALLBACK);
                        dlm_req = req_capsule_client_get(&req->rq_pill,
                                                         &RMF_DLM_REQ);
                        if (dlm_req != NULL)
                                ldlm_lock_dump_handle(D_ERROR,
                                                      &dlm_req->lock_handle[0]);
                }
                ldlm_callback_reply(req, -ENOTCONN);
                RETURN(0);
        }

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {

        /* XXX FIXME move this back to mds/handler.c, bug 249 */
        case LDLM_CANCEL:
                req_capsule_set(&req->rq_pill, &RQF_LDLM_CANCEL);
                CDEBUG(D_INODE, "cancel\n");
		if (CFS_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_NET) ||
		    CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_CANCEL_RESEND) ||
		    CFS_FAIL_CHECK(OBD_FAIL_LDLM_BL_EVICT))
			RETURN(0);
                rc = ldlm_handle_cancel(req);
                if (rc)
                        break;
                RETURN(0);
        default:
                CERROR("invalid opcode %d\n",
                       lustre_msg_get_opc(req->rq_reqmsg));
                req_capsule_set(&req->rq_pill, &RQF_LDLM_CALLBACK);
                ldlm_callback_reply(req, -EINVAL);
        }

        RETURN(0);
}

static int ldlm_cancel_hpreq_lock_match(struct ptlrpc_request *req,
                                        struct ldlm_lock *lock)
{
        struct ldlm_request *dlm_req;
        struct lustre_handle lockh;
        int rc = 0;
        int i;
        ENTRY;

        dlm_req = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        if (dlm_req == NULL)
                RETURN(0);

        ldlm_lock2handle(lock, &lockh);
        for (i = 0; i < dlm_req->lock_count; i++) {
                if (lustre_handle_equal(&dlm_req->lock_handle[i],
                                        &lockh)) {
                        DEBUG_REQ(D_RPCTRACE, req,
				  "Prio raised by lock %#llx.", lockh.cookie);

                        rc = 1;
                        break;
                }
        }

        RETURN(rc);

}

static int ldlm_cancel_hpreq_check(struct ptlrpc_request *req)
{
        struct ldlm_request *dlm_req;
        int rc = 0;
        int i;
        ENTRY;

        /* no prolong in recovery */
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY)
                RETURN(0);

        dlm_req = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        if (dlm_req == NULL)
                RETURN(-EFAULT);

        for (i = 0; i < dlm_req->lock_count; i++) {
                struct ldlm_lock *lock;

                lock = ldlm_handle2lock(&dlm_req->lock_handle[i]);
                if (lock == NULL)
                        continue;

		rc = ldlm_is_ast_sent(lock) ? 1 : 0;
                if (rc)
                        LDLM_DEBUG(lock, "hpreq cancel lock");
                LDLM_LOCK_PUT(lock);

                if (rc)
                        break;
        }

        RETURN(rc);
}

static struct ptlrpc_hpreq_ops ldlm_cancel_hpreq_ops = {
        .hpreq_lock_match = ldlm_cancel_hpreq_lock_match,
	.hpreq_check      = ldlm_cancel_hpreq_check,
	.hpreq_fini       = NULL,
};

static int ldlm_hpreq_handler(struct ptlrpc_request *req)
{
        ENTRY;

        req_capsule_init(&req->rq_pill, req, RCL_SERVER);

        if (req->rq_export == NULL)
                RETURN(0);

        if (LDLM_CANCEL == lustre_msg_get_opc(req->rq_reqmsg)) {
                req_capsule_set(&req->rq_pill, &RQF_LDLM_CANCEL);
                req->rq_ops = &ldlm_cancel_hpreq_ops;
        }
        RETURN(0);
}

static int ldlm_revoke_lock_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			       struct hlist_node *hnode, void *data)

{
	struct list_head         *rpc_list = data;
        struct ldlm_lock   *lock = cfs_hash_object(hs, hnode);

        lock_res_and_lock(lock);

        if (lock->l_req_mode != lock->l_granted_mode) {
                unlock_res_and_lock(lock);
                return 0;
        }

        LASSERT(lock->l_resource);
        if (lock->l_resource->lr_type != LDLM_IBITS &&
            lock->l_resource->lr_type != LDLM_PLAIN) {
                unlock_res_and_lock(lock);
                return 0;
        }

	if (ldlm_is_ast_sent(lock)) {
                unlock_res_and_lock(lock);
                return 0;
        }

        LASSERT(lock->l_blocking_ast);
        LASSERT(!lock->l_blocking_lock);

	ldlm_set_ast_sent(lock);
        if (lock->l_export && lock->l_export->exp_lock_hash) {
		/* NB: it's safe to call cfs_hash_del() even lock isn't
		 * in exp_lock_hash. */
		/* In the function below, .hs_keycmp resolves to
		 * ldlm_export_lock_keycmp() */
		/* coverity[overrun-buffer-val] */
		cfs_hash_del(lock->l_export->exp_lock_hash,
			     &lock->l_remote_handle, &lock->l_exp_hash);
	}

	list_add_tail(&lock->l_rk_ast, rpc_list);
        LDLM_LOCK_GET(lock);

        unlock_res_and_lock(lock);
        return 0;
}

void ldlm_revoke_export_locks(struct obd_export *exp)
{
	struct list_head  rpc_list;
	ENTRY;

	INIT_LIST_HEAD(&rpc_list);
	cfs_hash_for_each_nolock(exp->exp_lock_hash,
				 ldlm_revoke_lock_cb, &rpc_list, 0);
	ldlm_run_ast_work(exp->exp_obd->obd_namespace, &rpc_list,
			  LDLM_WORK_REVOKE_AST);

	EXIT;
}
EXPORT_SYMBOL(ldlm_revoke_export_locks);
#endif /* HAVE_SERVER_SUPPORT */

static int ldlm_bl_get_work(struct ldlm_bl_pool *blp,
			    struct ldlm_bl_work_item **p_blwi,
			    struct obd_export **p_exp)
{
	struct ldlm_bl_work_item *blwi = NULL;
	static unsigned int num_bl = 0;
	static unsigned int num_stale;
	int num_th = atomic_read(&blp->blp_num_threads);

	*p_exp = obd_stale_export_get();

	spin_lock(&blp->blp_lock);
	if (*p_exp != NULL) {
		if (num_th == 1 || ++num_stale < num_th) {
			spin_unlock(&blp->blp_lock);
			return 1;
		} else {
			num_stale = 0;
		}
	}

	/* process a request from the blp_list at least every blp_num_threads */
	if (!list_empty(&blp->blp_list) &&
	    (list_empty(&blp->blp_prio_list) || num_bl == 0))
		blwi = list_entry(blp->blp_list.next,
				  struct ldlm_bl_work_item, blwi_entry);
	else
		if (!list_empty(&blp->blp_prio_list))
			blwi = list_entry(blp->blp_prio_list.next,
					  struct ldlm_bl_work_item,
					  blwi_entry);

	if (blwi) {
		if (++num_bl >= num_th)
			num_bl = 0;
		list_del(&blwi->blwi_entry);
	}
	spin_unlock(&blp->blp_lock);
	*p_blwi = blwi;

	if (*p_exp != NULL && *p_blwi != NULL) {
		obd_stale_export_put(*p_exp);
		*p_exp = NULL;
	}

	return (*p_blwi != NULL || *p_exp != NULL) ? 1 : 0;
}

/* This only contains temporary data until the thread starts */
struct ldlm_bl_thread_data {
	struct ldlm_bl_pool	*bltd_blp;
	struct completion	bltd_comp;
	int			bltd_num;
};

static int ldlm_bl_thread_main(void *arg);

static int ldlm_bl_thread_start(struct ldlm_bl_pool *blp, bool check_busy)
{
	struct ldlm_bl_thread_data bltd = { .bltd_blp = blp };
	struct task_struct *task;

	init_completion(&bltd.bltd_comp);

	bltd.bltd_num = atomic_inc_return(&blp->blp_num_threads);
	if (bltd.bltd_num >= blp->blp_max_threads) {
		atomic_dec(&blp->blp_num_threads);
		return 0;
	}

	LASSERTF(bltd.bltd_num > 0, "thread num:%d\n", bltd.bltd_num);
	if (check_busy &&
	    atomic_read(&blp->blp_busy_threads) < (bltd.bltd_num - 1)) {
		atomic_dec(&blp->blp_num_threads);
		return 0;
	}

	task = kthread_run(ldlm_bl_thread_main, &bltd, "ldlm_bl_%02d",
			   bltd.bltd_num);
	if (IS_ERR(task)) {
		CERROR("cannot start LDLM thread ldlm_bl_%02d: rc %ld\n",
		       bltd.bltd_num, PTR_ERR(task));
		atomic_dec(&blp->blp_num_threads);
		return PTR_ERR(task);
	}
	wait_for_completion(&bltd.bltd_comp);

	return 0;
}

/* Not fatal if racy and have a few too many threads */
static int ldlm_bl_thread_need_create(struct ldlm_bl_pool *blp,
				      struct ldlm_bl_work_item *blwi)
{
	if (atomic_read(&blp->blp_num_threads) >= blp->blp_max_threads)
		return 0;

	if (atomic_read(&blp->blp_busy_threads) <
	    atomic_read(&blp->blp_num_threads))
		return 0;

	if (blwi != NULL && (blwi->blwi_ns == NULL ||
			     blwi->blwi_mem_pressure))
		return 0;

	return 1;
}

static int ldlm_bl_thread_blwi(struct ldlm_bl_pool *blp,
			       struct ldlm_bl_work_item *blwi)
{
	ENTRY;

	if (blwi->blwi_ns == NULL)
		/* added by ldlm_cleanup() */
		RETURN(LDLM_ITER_STOP);

	if (blwi->blwi_mem_pressure)
		memory_pressure_set();

	OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_PAUSE_CANCEL2, 4);

	if (blwi->blwi_count) {
		int count;
		/* The special case when we cancel locks in lru
		 * asynchronously, we pass the list of locks here.
		 * Thus locks are marked LDLM_FL_CANCELING, but NOT
		 * canceled locally yet. */
		count = ldlm_cli_cancel_list_local(&blwi->blwi_head,
						   blwi->blwi_count,
						   LCF_BL_AST);
		ldlm_cli_cancel_list(&blwi->blwi_head, count, NULL,
				     blwi->blwi_flags);
	} else {
		ldlm_handle_bl_callback(blwi->blwi_ns, &blwi->blwi_ld,
					blwi->blwi_lock);
	}
	if (blwi->blwi_mem_pressure)
		memory_pressure_clr();

	if (blwi->blwi_flags & LCF_ASYNC)
		OBD_FREE(blwi, sizeof(*blwi));
	else
		complete(&blwi->blwi_comp);

	RETURN(0);
}

/**
 * Cancel stale locks on export. Cancel blocked locks first.
 * If the given export has blocked locks, the next in the list may have
 * them too, thus cancel not blocked locks only if the current export has
 * no blocked locks.
 **/
static int ldlm_bl_thread_exports(struct ldlm_bl_pool *blp,
				  struct obd_export *exp)
{
	int num;
	ENTRY;

	OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_BL_EVICT, 4);

	num = ldlm_export_cancel_blocked_locks(exp);
	if (num == 0)
		ldlm_export_cancel_locks(exp);

	obd_stale_export_put(exp);

	RETURN(0);
}


/**
 * Main blocking requests processing thread.
 *
 * Callers put locks into its queue by calling ldlm_bl_to_thread.
 * This thread in the end ends up doing actual call to ->l_blocking_ast
 * for queued locks.
 */
static int ldlm_bl_thread_main(void *arg)
{
        struct ldlm_bl_pool *blp;
	struct ldlm_bl_thread_data *bltd = arg;
        ENTRY;

	blp = bltd->bltd_blp;

	complete(&bltd->bltd_comp);
	/* cannot use bltd after this, it is only on caller's stack */

	while (1) {
		struct l_wait_info lwi = { 0 };
		struct ldlm_bl_work_item *blwi = NULL;
		struct obd_export *exp = NULL;
		int rc;

		rc = ldlm_bl_get_work(blp, &blwi, &exp);

		if (rc == 0)
			l_wait_event_exclusive(blp->blp_waitq,
					       ldlm_bl_get_work(blp, &blwi,
								&exp),
					       &lwi);
		atomic_inc(&blp->blp_busy_threads);

		if (ldlm_bl_thread_need_create(blp, blwi))
			/* discard the return value, we tried */
			ldlm_bl_thread_start(blp, true);

		if (exp)
			rc = ldlm_bl_thread_exports(blp, exp);
		else if (blwi)
			rc = ldlm_bl_thread_blwi(blp, blwi);

		atomic_dec(&blp->blp_busy_threads);

		if (rc == LDLM_ITER_STOP)
			break;

		/* If there are many namespaces, we will not sleep waiting for
		 * work, and must do a cond_resched to avoid holding the CPU
		 * for too long */
		cond_resched();
	}

	atomic_dec(&blp->blp_num_threads);
	complete(&blp->blp_comp);
	RETURN(0);
}


static int ldlm_setup(void);
static int ldlm_cleanup(void);

int ldlm_get_ref(void)
{
        int rc = 0;
        ENTRY;
	mutex_lock(&ldlm_ref_mutex);
        if (++ldlm_refcount == 1) {
                rc = ldlm_setup();
                if (rc)
                        ldlm_refcount--;
        }
	mutex_unlock(&ldlm_ref_mutex);

        RETURN(rc);
}

void ldlm_put_ref(void)
{
        ENTRY;
	mutex_lock(&ldlm_ref_mutex);
        if (ldlm_refcount == 1) {
                int rc = ldlm_cleanup();
                if (rc)
                        CERROR("ldlm_cleanup failed: %d\n", rc);
                else
                        ldlm_refcount--;
        } else {
                ldlm_refcount--;
        }
	mutex_unlock(&ldlm_ref_mutex);

        EXIT;
}

/*
 * Export handle<->lock hash operations.
 */
static unsigned
ldlm_export_lock_hash(struct cfs_hash *hs, const void *key, unsigned mask)
{
        return cfs_hash_u64_hash(((struct lustre_handle *)key)->cookie, mask);
}

static void *
ldlm_export_lock_key(struct hlist_node *hnode)
{
        struct ldlm_lock *lock;

	lock = hlist_entry(hnode, struct ldlm_lock, l_exp_hash);
        return &lock->l_remote_handle;
}

static void
ldlm_export_lock_keycpy(struct hlist_node *hnode, void *key)
{
        struct ldlm_lock     *lock;

	lock = hlist_entry(hnode, struct ldlm_lock, l_exp_hash);
        lock->l_remote_handle = *(struct lustre_handle *)key;
}

static int
ldlm_export_lock_keycmp(const void *key, struct hlist_node *hnode)
{
        return lustre_handle_equal(ldlm_export_lock_key(hnode), key);
}

static void *
ldlm_export_lock_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct ldlm_lock, l_exp_hash);
}

static void
ldlm_export_lock_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
        struct ldlm_lock *lock;

	lock = hlist_entry(hnode, struct ldlm_lock, l_exp_hash);
        LDLM_LOCK_GET(lock);
}

static void
ldlm_export_lock_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
        struct ldlm_lock *lock;

	lock = hlist_entry(hnode, struct ldlm_lock, l_exp_hash);
        LDLM_LOCK_RELEASE(lock);
}

static struct cfs_hash_ops ldlm_export_lock_ops = {
        .hs_hash        = ldlm_export_lock_hash,
        .hs_key         = ldlm_export_lock_key,
        .hs_keycmp      = ldlm_export_lock_keycmp,
        .hs_keycpy      = ldlm_export_lock_keycpy,
        .hs_object      = ldlm_export_lock_object,
        .hs_get         = ldlm_export_lock_get,
        .hs_put         = ldlm_export_lock_put,
        .hs_put_locked  = ldlm_export_lock_put,
};

int ldlm_init_export(struct obd_export *exp)
{
	int rc;
        ENTRY;

        exp->exp_lock_hash =
                cfs_hash_create(obd_uuid2str(&exp->exp_client_uuid),
                                HASH_EXP_LOCK_CUR_BITS,
                                HASH_EXP_LOCK_MAX_BITS,
                                HASH_EXP_LOCK_BKT_BITS, 0,
                                CFS_HASH_MIN_THETA, CFS_HASH_MAX_THETA,
                                &ldlm_export_lock_ops,
                                CFS_HASH_DEFAULT | CFS_HASH_REHASH_KEY |
                                CFS_HASH_NBLK_CHANGE);

        if (!exp->exp_lock_hash)
                RETURN(-ENOMEM);

	rc = ldlm_init_flock_export(exp);
	if (rc)
		GOTO(err, rc);

        RETURN(0);
err:
	ldlm_destroy_export(exp);
	RETURN(rc);
}
EXPORT_SYMBOL(ldlm_init_export);

void ldlm_destroy_export(struct obd_export *exp)
{
        ENTRY;
        cfs_hash_putref(exp->exp_lock_hash);
        exp->exp_lock_hash = NULL;

	ldlm_destroy_flock_export(exp);
        EXIT;
}
EXPORT_SYMBOL(ldlm_destroy_export);

static ssize_t cancel_unused_locks_before_replay_show(struct kobject *kobj,
						      struct attribute *attr,
						      char *buf)
{
	return sprintf(buf, "%d\n", ldlm_cancel_unused_locks_before_replay);
}

static ssize_t cancel_unused_locks_before_replay_store(struct kobject *kobj,
						       struct attribute *attr,
						       const char *buffer,
						       size_t count)
{
	int rc;
	unsigned long val;

	rc = kstrtoul(buffer, 10, &val);
	if (rc)
		return rc;

	ldlm_cancel_unused_locks_before_replay = val;

	return count;
}
LUSTRE_RW_ATTR(cancel_unused_locks_before_replay);

static struct attribute *ldlm_attrs[] = {
	&lustre_attr_cancel_unused_locks_before_replay.attr,
	NULL,
};

static struct attribute_group ldlm_attr_group = {
	.attrs = ldlm_attrs,
};

static int ldlm_setup(void)
{
	static struct ptlrpc_service_conf	conf;
	struct ldlm_bl_pool		       *blp = NULL;
#ifdef HAVE_SERVER_SUPPORT
	struct task_struct *task;
#endif /* HAVE_SERVER_SUPPORT */
	int i;
	int rc = 0;

        ENTRY;

        if (ldlm_state != NULL)
                RETURN(-EALREADY);

        OBD_ALLOC(ldlm_state, sizeof(*ldlm_state));
        if (ldlm_state == NULL)
                RETURN(-ENOMEM);

	ldlm_kobj = kobject_create_and_add("ldlm", lustre_kobj);
	if (!ldlm_kobj)
		GOTO(out, -ENOMEM);

	rc = sysfs_create_group(ldlm_kobj, &ldlm_attr_group);
	if (rc)
		GOTO(out, rc);

	ldlm_ns_kset = kset_create_and_add("namespaces", NULL, ldlm_kobj);
	if (!ldlm_ns_kset)
		GOTO(out, -ENOMEM);

	ldlm_svc_kset = kset_create_and_add("services", NULL, ldlm_kobj);
	if (!ldlm_svc_kset)
		GOTO(out, -ENOMEM);

#ifdef CONFIG_PROC_FS
	rc = ldlm_proc_setup();
	if (rc != 0)
		GOTO(out, rc);
#endif /* CONFIG_PROC_FS */

	memset(&conf, 0, sizeof(conf));
	conf = (typeof(conf)) {
		.psc_name		= "ldlm_cbd",
		.psc_watchdog_factor	= 2,
		.psc_buf		= {
			.bc_nbufs		= LDLM_CLIENT_NBUFS,
			.bc_buf_size		= LDLM_BUFSIZE,
			.bc_req_max_size	= LDLM_MAXREQSIZE,
			.bc_rep_max_size	= LDLM_MAXREPSIZE,
			.bc_req_portal		= LDLM_CB_REQUEST_PORTAL,
			.bc_rep_portal		= LDLM_CB_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ldlm_cb",
			.tc_thr_factor		= LDLM_THR_FACTOR,
			.tc_nthrs_init		= LDLM_NTHRS_INIT,
			.tc_nthrs_base		= LDLM_NTHRS_BASE,
			.tc_nthrs_max		= LDLM_NTHRS_MAX,
			.tc_nthrs_user		= ldlm_num_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_MD_THREAD | LCT_DT_THREAD,
		},
		.psc_cpt		= {
			.cc_pattern		= ldlm_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= ldlm_callback_handler,
		},
	};
	ldlm_state->ldlm_cb_service = \
			ptlrpc_register_service(&conf, ldlm_svc_proc_dir);
	if (IS_ERR(ldlm_state->ldlm_cb_service)) {
		CERROR("failed to start service\n");
		rc = PTR_ERR(ldlm_state->ldlm_cb_service);
		ldlm_state->ldlm_cb_service = NULL;
		GOTO(out, rc);
	}

#ifdef HAVE_SERVER_SUPPORT
	memset(&conf, 0, sizeof(conf));
	conf = (typeof(conf)) {
		.psc_name		= "ldlm_canceld",
		.psc_watchdog_factor	= 6,
		.psc_buf		= {
			.bc_nbufs		= LDLM_SERVER_NBUFS,
			.bc_buf_size		= LDLM_BUFSIZE,
			.bc_req_max_size	= LDLM_MAXREQSIZE,
			.bc_rep_max_size	= LDLM_MAXREPSIZE,
			.bc_req_portal		= LDLM_CANCEL_REQUEST_PORTAL,
			.bc_rep_portal		= LDLM_CANCEL_REPLY_PORTAL,

		},
		.psc_thr		= {
			.tc_thr_name		= "ldlm_cn",
			.tc_thr_factor		= LDLM_THR_FACTOR,
			.tc_nthrs_init		= LDLM_NTHRS_INIT,
			.tc_nthrs_base		= LDLM_NTHRS_BASE,
			.tc_nthrs_max		= LDLM_NTHRS_MAX,
			.tc_nthrs_user		= ldlm_num_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_MD_THREAD | \
						  LCT_DT_THREAD | \
						  LCT_CL_THREAD,
		},
		.psc_cpt		= {
			.cc_pattern		= ldlm_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= ldlm_cancel_handler,
			.so_hpreq_handler	= ldlm_hpreq_handler,
		},
	};
	ldlm_state->ldlm_cancel_service = \
			ptlrpc_register_service(&conf, ldlm_svc_proc_dir);
	if (IS_ERR(ldlm_state->ldlm_cancel_service)) {
		CERROR("failed to start service\n");
		rc = PTR_ERR(ldlm_state->ldlm_cancel_service);
		ldlm_state->ldlm_cancel_service = NULL;
		GOTO(out, rc);
	}
#endif /* HAVE_SERVER_SUPPORT */

	OBD_ALLOC(blp, sizeof(*blp));
	if (blp == NULL)
		GOTO(out, rc = -ENOMEM);
	ldlm_state->ldlm_bl_pool = blp;

	spin_lock_init(&blp->blp_lock);
	INIT_LIST_HEAD(&blp->blp_list);
	INIT_LIST_HEAD(&blp->blp_prio_list);
	init_waitqueue_head(&blp->blp_waitq);
	atomic_set(&blp->blp_num_threads, 0);
	atomic_set(&blp->blp_busy_threads, 0);

	if (ldlm_num_threads == 0) {
		blp->blp_min_threads = LDLM_NTHRS_INIT;
		blp->blp_max_threads = LDLM_NTHRS_MAX;
	} else {
		blp->blp_min_threads = blp->blp_max_threads = \
			min_t(int, LDLM_NTHRS_MAX, max_t(int, LDLM_NTHRS_INIT,
							 ldlm_num_threads));
	}

	for (i = 0; i < blp->blp_min_threads; i++) {
		rc = ldlm_bl_thread_start(blp, false);
		if (rc < 0)
			GOTO(out, rc);
	}

#ifdef HAVE_SERVER_SUPPORT
	task = kthread_run(expired_lock_main, NULL, "ldlm_elt");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("Cannot start ldlm expired-lock thread: %d\n", rc);
		GOTO(out, rc);
	}

	wait_event(expired_lock_wait_queue,
		   expired_lock_thread_state == ELT_READY);
#endif /* HAVE_SERVER_SUPPORT */

	rc = ldlm_pools_init();
	if (rc) {
		CERROR("Failed to initialize LDLM pools: %d\n", rc);
		GOTO(out, rc);
	}

	rc = ldlm_reclaim_setup();
	if (rc) {
		CERROR("Failed to setup reclaim thread: rc = %d\n", rc);
		GOTO(out, rc);
	}
	RETURN(0);

 out:
	ldlm_cleanup();
	RETURN(rc);
}

static int ldlm_cleanup(void)
{
        ENTRY;

	if (!list_empty(ldlm_namespace_list(LDLM_NAMESPACE_SERVER)) ||
	    !list_empty(ldlm_namespace_list(LDLM_NAMESPACE_CLIENT))) {
                CERROR("ldlm still has namespaces; clean these up first.\n");
                ldlm_dump_all_namespaces(LDLM_NAMESPACE_SERVER, D_DLMTRACE);
                ldlm_dump_all_namespaces(LDLM_NAMESPACE_CLIENT, D_DLMTRACE);
                RETURN(-EBUSY);
        }

	ldlm_reclaim_cleanup();
	ldlm_pools_fini();

	if (ldlm_state->ldlm_bl_pool != NULL) {
		struct ldlm_bl_pool *blp = ldlm_state->ldlm_bl_pool;

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
	}

	if (ldlm_state->ldlm_cb_service != NULL)
		ptlrpc_unregister_service(ldlm_state->ldlm_cb_service);
#ifdef HAVE_SERVER_SUPPORT
	if (ldlm_state->ldlm_cancel_service != NULL)
		ptlrpc_unregister_service(ldlm_state->ldlm_cancel_service);
#endif

	if (ldlm_ns_kset)
		kset_unregister(ldlm_ns_kset);
	if (ldlm_svc_kset)
		kset_unregister(ldlm_svc_kset);
	if (ldlm_kobj)
		kobject_put(ldlm_kobj);

	ldlm_proc_cleanup();

#ifdef HAVE_SERVER_SUPPORT
	if (expired_lock_thread_state != ELT_STOPPED) {
		expired_lock_thread_state = ELT_TERMINATE;
		wake_up(&expired_lock_wait_queue);
		wait_event(expired_lock_wait_queue,
			   expired_lock_thread_state == ELT_STOPPED);
	}
#endif

        OBD_FREE(ldlm_state, sizeof(*ldlm_state));
        ldlm_state = NULL;

        RETURN(0);
}

int ldlm_init(void)
{
	ldlm_resource_slab = kmem_cache_create("ldlm_resources",
					       sizeof(struct ldlm_resource), 0,
					       SLAB_HWCACHE_ALIGN, NULL);
	if (ldlm_resource_slab == NULL)
		return -ENOMEM;

	ldlm_lock_slab = kmem_cache_create("ldlm_locks",
			      sizeof(struct ldlm_lock), 0,
			      SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU, NULL);
	if (ldlm_lock_slab == NULL)
		goto out_resource;

	ldlm_interval_slab = kmem_cache_create("interval_node",
                                        sizeof(struct ldlm_interval),
					0, SLAB_HWCACHE_ALIGN, NULL);
	if (ldlm_interval_slab == NULL)
		goto out_lock;

	ldlm_interval_tree_slab = kmem_cache_create("interval_tree",
			sizeof(struct ldlm_interval_tree) * LCK_MODE_NUM,
			0, SLAB_HWCACHE_ALIGN, NULL);
	if (ldlm_interval_tree_slab == NULL)
		goto out_interval;

#if LUSTRE_TRACKS_LOCK_EXP_REFS
	class_export_dump_hook = ldlm_dump_export_locks;
#endif
	return 0;

out_interval:
	kmem_cache_destroy(ldlm_interval_slab);
out_lock:
	kmem_cache_destroy(ldlm_lock_slab);
out_resource:
	kmem_cache_destroy(ldlm_resource_slab);

	return -ENOMEM;
}

void ldlm_exit(void)
{
	if (ldlm_refcount)
		CERROR("ldlm_refcount is %d in ldlm_exit!\n", ldlm_refcount);
	kmem_cache_destroy(ldlm_resource_slab);
	/* ldlm_lock_put() use RCU to call ldlm_lock_free, so need call
	 * synchronize_rcu() to wait a grace period elapsed, so that
	 * ldlm_lock_free() get a chance to be called. */
	synchronize_rcu();
	kmem_cache_destroy(ldlm_lock_slab);
	kmem_cache_destroy(ldlm_interval_slab);
	kmem_cache_destroy(ldlm_interval_tree_slab);
}
