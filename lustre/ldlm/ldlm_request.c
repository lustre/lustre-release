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
 */
/**
 * This file contains Asynchronous System Trap (AST) handlers and related
 * LDLM request-processing routines.
 *
 * An AST is a callback issued on a lock when its state is changed. There are
 * several different types of ASTs (callbacks) registered for each lock:
 *
 * - completion AST: when a lock is enqueued by some process, but cannot be
 *   granted immediately due to other conflicting locks on the same resource,
 *   the completion AST is sent to notify the caller when the lock is
 *   eventually granted
 *
 * - blocking AST: when a lock is granted to some process, if another process
 *   enqueues a conflicting (blocking) lock on a resource, a blocking AST is
 *   sent to notify the holder(s) of the lock(s) of the conflicting lock
 *   request. The lock holder(s) must release their lock(s) on that resource in
 *   a timely manner or be evicted by the server.
 *
 * - glimpse AST: this is used when a process wants information about a lock
 *   (i.e. the lock value block (LVB)) but does not necessarily require holding
 *   the lock. If the resource is locked, the lock holder(s) are sent glimpse
 *   ASTs and the LVB is returned to the caller, and lock holder(s) may CANCEL
 *   their lock(s) if they are idle. If the resource is not locked, the server
 *   may grant the lock.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <lustre/lustre_errno.h>

#include <lustre_dlm.h>
#include <obd_class.h>
#include <obd.h>

#include "ldlm_internal.h"

unsigned int ldlm_enqueue_min = OBD_TIMEOUT_DEFAULT;
module_param(ldlm_enqueue_min, uint, 0644);
MODULE_PARM_DESC(ldlm_enqueue_min, "lock enqueue timeout minimum");

/* in client side, whether the cached locks will be canceled before replay */
unsigned int ldlm_cancel_unused_locks_before_replay = 1;

static void interrupted_completion_wait(void *data)
{
}

struct lock_wait_data {
        struct ldlm_lock *lwd_lock;
        __u32             lwd_conn_cnt;
};

struct ldlm_async_args {
        struct lustre_handle lock_handle;
};

/**
 * ldlm_request_bufsize
 *
 * If opcode=LDLM_ENQUEUE, 1 slot is already occupied,
 * LDLM_LOCKREQ_HANDLE -1 slots are available.
 * Otherwise, LDLM_LOCKREQ_HANDLE slots are available.
 *
 * \param[in] count
 * \param[in] type
 *
 * \retval size of the request buffer
 */

int ldlm_request_bufsize(int count, int type)
{
	int avail = LDLM_LOCKREQ_HANDLES;
	if (type == LDLM_ENQUEUE)
		avail -= LDLM_ENQUEUE_CANCEL_OFF;

	if (count > avail)
		avail = (count - avail) * sizeof(struct lustre_handle);
	else
		avail = 0;

	return sizeof(struct ldlm_request) + avail;
}

int ldlm_expired_completion_wait(void *data)
{
        struct lock_wait_data *lwd = data;
        struct ldlm_lock *lock = lwd->lwd_lock;
        struct obd_import *imp;
        struct obd_device *obd;

        ENTRY;
        if (lock->l_conn_export == NULL) {
                static cfs_time_t next_dump = 0, last_dump = 0;

		LDLM_ERROR(lock, "lock timed out (enqueued at %lld, %llds ago); "
			   "not entering recovery in server code, just going back to sleep",
			   (s64)lock->l_activity,
			   (s64)(ktime_get_real_seconds() -
				 lock->l_activity));
                if (cfs_time_after(cfs_time_current(), next_dump)) {
                        last_dump = next_dump;
                        next_dump = cfs_time_shift(300);
                        ldlm_namespace_dump(D_DLMTRACE,
                                            ldlm_lock_to_ns(lock));
                        if (last_dump == 0)
                                libcfs_debug_dumplog();
                }
                RETURN(0);
        }

        obd = lock->l_conn_export->exp_obd;
        imp = obd->u.cli.cl_import;
        ptlrpc_fail_import(imp, lwd->lwd_conn_cnt);
	LDLM_ERROR(lock, "lock timed out (enqueued at %lld, %llds ago), entering recovery for %s@%s",
		  (s64)lock->l_activity,
		  (s64)(ktime_get_real_seconds() - lock->l_activity),
                  obd2cli_tgt(obd), imp->imp_connection->c_remote_uuid.uuid);

        RETURN(0);
}

/**
 * Calculate the Completion timeout (covering enqueue, BL AST, data flush,
 * lock cancel, and their replies). Used for lock completion timeout on the
 * client side.
 *
 * \param[in] lock        lock which is waiting the completion callback
 *
 * \retval            timeout in seconds to wait for the server reply
 */

/* We use the same basis for both server side and client side functions
   from a single node. */
static unsigned int ldlm_cp_timeout(struct ldlm_lock *lock)
{
	unsigned int timeout;

	if (AT_OFF)
		return obd_timeout;

	/* Wait a long time for enqueue - server may have to callback a
	 * lock from another client.  Server will evict the other client if it
	 * doesn't respond reasonably, and then give us the lock. */
	timeout = at_get(ldlm_lock_to_ns_at(lock));
	return max(3 * timeout, ldlm_enqueue_min);
}

/**
 * Helper function for ldlm_completion_ast(), updating timings when lock is
 * actually granted.
 */
static int ldlm_completion_tail(struct ldlm_lock *lock, void *data)
{
	time64_t delay;
	int result = 0;

	if (ldlm_is_destroyed(lock) || ldlm_is_failed(lock)) {
		LDLM_DEBUG(lock, "client-side enqueue: destroyed");
		result = -EIO;
	} else if (data == NULL) {
		LDLM_DEBUG(lock, "client-side enqueue: granted");
	} else {
		/* Take into AT only CP RPC, not immediately granted locks */
		delay = ktime_get_real_seconds() - lock->l_activity;
		LDLM_DEBUG(lock, "client-side enqueue: granted after %llds",
			   (s64)delay);

		/* Update our time estimate */
		at_measured(ldlm_lock_to_ns_at(lock), delay);
	}
	return result;
}

/**
 * Implementation of ->l_completion_ast() for a client, that doesn't wait
 * until lock is granted. Suitable for locks enqueued through ptlrpcd, of
 * other threads that cannot block for long.
 */
int ldlm_completion_ast_async(struct ldlm_lock *lock, __u64 flags, void *data)
{
	ENTRY;

	if (flags == LDLM_FL_WAIT_NOREPROC) {
		LDLM_DEBUG(lock, "client-side enqueue waiting on pending lock");
		RETURN(0);
	}

	if (!(flags & LDLM_FL_BLOCKED_MASK)) {
		wake_up(&lock->l_waitq);
		RETURN(ldlm_completion_tail(lock, data));
	}

	LDLM_DEBUG(lock, "client-side enqueue returned a blocked lock, "
		   "going forward");
	ldlm_reprocess_all(lock->l_resource);
	RETURN(0);
}
EXPORT_SYMBOL(ldlm_completion_ast_async);

/**
 * Generic LDLM "completion" AST. This is called in several cases:
 *
 *     - when a reply to an ENQUEUE RPC is received from the server
 *       (ldlm_cli_enqueue_fini()). Lock might be granted or not granted at
 *       this point (determined by flags);
 *
 *     - when LDLM_CP_CALLBACK RPC comes to client to notify it that lock has
 *       been granted;
 *
 *     - when ldlm_lock_match(LDLM_FL_LVB_READY) is about to wait until lock
 *       gets correct lvb;
 *
 *     - to force all locks when resource is destroyed (cleanup_resource());
 *
 *     - during lock conversion (not used currently).
 *
 * If lock is not granted in the first case, this function waits until second
 * or penultimate cases happen in some other thread.
 *
 */
int ldlm_completion_ast(struct ldlm_lock *lock, __u64 flags, void *data)
{
        /* XXX ALLOCATE - 160 bytes */
        struct lock_wait_data lwd;
        struct obd_device *obd;
        struct obd_import *imp = NULL;
        struct l_wait_info lwi;
        __u32 timeout;
        int rc = 0;
        ENTRY;

        if (flags == LDLM_FL_WAIT_NOREPROC) {
                LDLM_DEBUG(lock, "client-side enqueue waiting on pending lock");
                goto noreproc;
        }

	if (!(flags & LDLM_FL_BLOCKED_MASK)) {
		wake_up(&lock->l_waitq);
		RETURN(0);
	}

        LDLM_DEBUG(lock, "client-side enqueue returned a blocked lock, "
                   "sleeping");

noreproc:

        obd = class_exp2obd(lock->l_conn_export);

        /* if this is a local lock, then there is no import */
        if (obd != NULL) {
                imp = obd->u.cli.cl_import;
        }

	timeout = ldlm_cp_timeout(lock);

	lwd.lwd_lock = lock;
	lock->l_activity = cfs_time_current_sec();

	if (ldlm_is_no_timeout(lock)) {
                LDLM_DEBUG(lock, "waiting indefinitely because of NO_TIMEOUT");
                lwi = LWI_INTR(interrupted_completion_wait, &lwd);
        } else {
                lwi = LWI_TIMEOUT_INTR(cfs_time_seconds(timeout),
                                       ldlm_expired_completion_wait,
                                       interrupted_completion_wait, &lwd);
        }

	if (imp != NULL) {
		spin_lock(&imp->imp_lock);
		lwd.lwd_conn_cnt = imp->imp_conn_cnt;
		spin_unlock(&imp->imp_lock);
	}

        if (ns_is_client(ldlm_lock_to_ns(lock)) &&
            OBD_FAIL_CHECK_RESET(OBD_FAIL_LDLM_INTR_CP_AST,
                                 OBD_FAIL_LDLM_CP_BL_RACE | OBD_FAIL_ONCE)) {
		ldlm_set_fail_loc(lock);
                rc = -EINTR;
        } else {
                /* Go to sleep until the lock is granted or cancelled. */
                rc = l_wait_event(lock->l_waitq,
                                  is_granted_or_cancelled(lock), &lwi);
        }

        if (rc) {
                LDLM_DEBUG(lock, "client-side enqueue waking up: failed (%d)",
                           rc);
                RETURN(rc);
	}

	RETURN(ldlm_completion_tail(lock, data));
}
EXPORT_SYMBOL(ldlm_completion_ast);

/**
 * A helper to build a blocking AST function
 *
 * Perform a common operation for blocking ASTs:
 * defferred lock cancellation.
 *
 * \param lock the lock blocking or canceling AST was called on
 * \retval 0
 * \see mdt_blocking_ast
 * \see ldlm_blocking_ast
 */
int ldlm_blocking_ast_nocheck(struct ldlm_lock *lock)
{
        int do_ast;
        ENTRY;

	ldlm_set_cbpending(lock);
        do_ast = (!lock->l_readers && !lock->l_writers);
        unlock_res_and_lock(lock);

        if (do_ast) {
                struct lustre_handle lockh;
                int rc;

                LDLM_DEBUG(lock, "already unused, calling ldlm_cli_cancel");
                ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
                if (rc < 0)
                        CERROR("ldlm_cli_cancel: %d\n", rc);
        } else {
                LDLM_DEBUG(lock, "Lock still has references, will be "
                           "cancelled later");
        }
        RETURN(0);
}
EXPORT_SYMBOL(ldlm_blocking_ast_nocheck);

/**
 * Server blocking AST
 *
 * ->l_blocking_ast() callback for LDLM locks acquired by server-side
 * OBDs.
 *
 * \param lock the lock which blocks a request or cancelling lock
 * \param desc unused
 * \param data unused
 * \param flag indicates whether this cancelling or blocking callback
 * \retval 0
 * \see ldlm_blocking_ast_nocheck
 */
int ldlm_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                      void *data, int flag)
{
        ENTRY;

        if (flag == LDLM_CB_CANCELING) {
                /* Don't need to do anything here. */
                RETURN(0);
        }

        lock_res_and_lock(lock);
        /* Get this: if ldlm_blocking_ast is racing with intent_policy, such
         * that ldlm_blocking_ast is called just before intent_policy method
         * takes the lr_lock, then by the time we get the lock, we might not
         * be the correct blocking function anymore.  So check, and return
         * early, if so. */
        if (lock->l_blocking_ast != ldlm_blocking_ast) {
                unlock_res_and_lock(lock);
                RETURN(0);
        }
        RETURN(ldlm_blocking_ast_nocheck(lock));
}
EXPORT_SYMBOL(ldlm_blocking_ast);

/**
 * Implements ldlm_lock::l_glimpse_ast for extent locks acquired on the server.
 *
 * Returning -ELDLM_NO_LOCK_DATA actually works, but the reason for that is
 * rather subtle: with OST-side locking, it may so happen that _all_ extent
 * locks are held by the OST. If client wants to obtain the current file size
 * it calls ll_glimpse_size(), and (as all locks are held only on the server),
 * this dummy glimpse callback fires and does nothing. The client still
 * receives the correct file size due to the following fragment of code in
 * ldlm_cb_interpret():
 *
 *	if (rc == -ELDLM_NO_LOCK_DATA) {
 *		LDLM_DEBUG(lock, "lost race - client has a lock but no"
 *			   "inode");
 *		ldlm_res_lvbo_update(lock->l_resource, NULL, 1);
 *	}
 *
 * That is, after the glimpse returns this error, ofd_lvbo_update() is called
 * and returns the updated file attributes from the inode to the client.
 *
 * See also comment in ofd_intent_policy() on why servers must set a non-NULL
 * l_glimpse_ast when grabbing DLM locks.  Otherwise, the server will assume
 * that the object is in the process of being destroyed.
 *
 * \param[in] lock	DLM lock being glimpsed, unused
 * \param[in] reqp	pointer to ptlrpc_request, unused
 *
 * \retval		-ELDLM_NO_LOCK_DATA to get attributes from disk object
 */
int ldlm_glimpse_ast(struct ldlm_lock *lock, void *reqp)
{
        return -ELDLM_NO_LOCK_DATA;
}

/**
 * Enqueue a local lock (typically on a server).
 */
int ldlm_cli_enqueue_local(struct ldlm_namespace *ns,
			   const struct ldlm_res_id *res_id,
			   enum ldlm_type type, union ldlm_policy_data *policy,
			   enum ldlm_mode mode, __u64 *flags,
			   ldlm_blocking_callback blocking,
			   ldlm_completion_callback completion,
			   ldlm_glimpse_callback glimpse,
			   void *data, __u32 lvb_len, enum lvb_type lvb_type,
			   const __u64 *client_cookie,
			   struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        int err;
        const struct ldlm_callback_suite cbs = { .lcs_completion = completion,
                                                 .lcs_blocking   = blocking,
                                                 .lcs_glimpse    = glimpse,
        };
        ENTRY;

        LASSERT(!(*flags & LDLM_FL_REPLAY));
        if (unlikely(ns_is_client(ns))) {
                CERROR("Trying to enqueue local lock in a shadow namespace\n");
                LBUG();
        }

	lock = ldlm_lock_create(ns, res_id, type, mode, &cbs, data, lvb_len,
				lvb_type);
	if (IS_ERR(lock))
		GOTO(out_nolock, err = PTR_ERR(lock));

	err = ldlm_lvbo_init(lock->l_resource);
	if (err < 0) {
		LDLM_ERROR(lock, "delayed lvb init failed (rc %d)", err);
		GOTO(out, err);
	}

        ldlm_lock2handle(lock, lockh);

        /* NB: we don't have any lock now (lock_res_and_lock)
         * because it's a new lock */
        ldlm_lock_addref_internal_nolock(lock, mode);
	ldlm_set_local(lock);
        if (*flags & LDLM_FL_ATOMIC_CB)
		ldlm_set_atomic_cb(lock);

        if (policy != NULL)
                lock->l_policy_data = *policy;
        if (client_cookie != NULL)
                lock->l_client_cookie = *client_cookie;
	if (type == LDLM_EXTENT) {
		/* extent lock without policy is a bug */
		if (policy == NULL)
			LBUG();

		lock->l_req_extent = policy->l_extent;
	}

        err = ldlm_lock_enqueue(ns, &lock, policy, flags);
        if (unlikely(err != ELDLM_OK))
                GOTO(out, err);

        if (policy != NULL)
                *policy = lock->l_policy_data;

        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, *flags, NULL);

        LDLM_DEBUG(lock, "client-side local enqueue handler, new lock created");
        EXIT;
 out:
        LDLM_LOCK_RELEASE(lock);
 out_nolock:
        return err;
}
EXPORT_SYMBOL(ldlm_cli_enqueue_local);

static void failed_lock_cleanup(struct ldlm_namespace *ns,
                                struct ldlm_lock *lock, int mode)
{
        int need_cancel = 0;

        /* Set a flag to prevent us from sending a CANCEL (bug 407) */
        lock_res_and_lock(lock);
        /* Check that lock is not granted or failed, we might race. */
        if ((lock->l_req_mode != lock->l_granted_mode) &&
	    !ldlm_is_failed(lock)) {
		/* Make sure that this lock will not be found by raced
		 * bl_ast and -EINVAL reply is sent to server anyways.
		 * b=17645*/
		lock->l_flags |= LDLM_FL_LOCAL_ONLY | LDLM_FL_FAILED |
				 LDLM_FL_ATOMIC_CB | LDLM_FL_CBPENDING;
		need_cancel = 1;
        }
        unlock_res_and_lock(lock);

        if (need_cancel)
                LDLM_DEBUG(lock,
                           "setting FL_LOCAL_ONLY | LDLM_FL_FAILED | "
                           "LDLM_FL_ATOMIC_CB | LDLM_FL_CBPENDING");
        else
                LDLM_DEBUG(lock, "lock was granted or failed in race");

	/* XXX - HACK because we shouldn't call ldlm_lock_destroy()
	 *       from llite/file.c/ll_file_flock(). */
	/* This code makes for the fact that we do not have blocking handler on
	 * a client for flock locks. As such this is the place where we must
	 * completely kill failed locks. (interrupted and those that
	 * were waiting to be granted when server evicted us. */
	if (lock->l_resource->lr_type == LDLM_FLOCK) {
		lock_res_and_lock(lock);
		if (!ldlm_is_destroyed(lock)) {
			ldlm_resource_unlink_lock(lock);
			ldlm_lock_decref_internal_nolock(lock, mode);
			ldlm_lock_destroy_nolock(lock);
		}
		unlock_res_and_lock(lock);
	} else {
		ldlm_lock_decref_internal(lock, mode);
	}
}

/**
 * Finishing portion of client lock enqueue code.
 *
 * Called after receiving reply from server.
 */
int ldlm_cli_enqueue_fini(struct obd_export *exp, struct ptlrpc_request *req,
			  enum ldlm_type type, __u8 with_policy,
			  enum ldlm_mode mode, __u64 *flags, void *lvb,
			  __u32 lvb_len, const struct lustre_handle *lockh,
			  int rc)
{
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        int is_replay = *flags & LDLM_FL_REPLAY;
        struct ldlm_lock *lock;
        struct ldlm_reply *reply;
        int cleanup_phase = 1;
        ENTRY;

        lock = ldlm_handle2lock(lockh);
        /* ldlm_cli_enqueue is holding a reference on this lock. */
        if (!lock) {
                LASSERT(type == LDLM_FLOCK);
                RETURN(-ENOLCK);
        }

	LASSERTF(ergo(lvb_len != 0, lvb_len == lock->l_lvb_len),
		 "lvb_len = %d, l_lvb_len = %d\n", lvb_len, lock->l_lvb_len);

        if (rc != ELDLM_OK) {
                LASSERT(!is_replay);
                LDLM_DEBUG(lock, "client-side enqueue END (%s)",
                           rc == ELDLM_LOCK_ABORTED ? "ABORTED" : "FAILED");

		if (rc != ELDLM_LOCK_ABORTED)
			GOTO(cleanup, rc);
	}

	/* Before we return, swab the reply */
	reply = req_capsule_server_get(&req->rq_pill, &RMF_DLM_REP);
	if (reply == NULL)
		GOTO(cleanup, rc = -EPROTO);

	if (lvb_len > 0) {
		int size = 0;

		size = req_capsule_get_size(&req->rq_pill, &RMF_DLM_LVB,
					    RCL_SERVER);
		if (size < 0) {
			LDLM_ERROR(lock, "Fail to get lvb_len, rc = %d", size);
			GOTO(cleanup, rc = size);
		} else if (unlikely(size > lvb_len)) {
			LDLM_ERROR(lock, "Replied LVB is larger than "
				   "expectation, expected = %d, replied = %d",
				   lvb_len, size);
			GOTO(cleanup, rc = -EINVAL);
		}
		lvb_len = size;
	}

	if (rc == ELDLM_LOCK_ABORTED) {
		if (lvb_len > 0 && lvb != NULL)
			rc = ldlm_fill_lvb(lock, &req->rq_pill, RCL_SERVER,
					   lvb, lvb_len);
		GOTO(cleanup, rc = rc ? : ELDLM_LOCK_ABORTED);
	}

        /* lock enqueued on the server */
        cleanup_phase = 0;

        lock_res_and_lock(lock);
        /* Key change rehash lock in per-export hash with new key */
        if (exp->exp_lock_hash) {
		/* In the function below, .hs_keycmp resolves to
		 * ldlm_export_lock_keycmp() */
		/* coverity[overrun-buffer-val] */
                cfs_hash_rehash_key(exp->exp_lock_hash,
                                    &lock->l_remote_handle,
                                    &reply->lock_handle,
                                    &lock->l_exp_hash);
        } else {
                lock->l_remote_handle = reply->lock_handle;
        }

	*flags = ldlm_flags_from_wire(reply->lock_flags);
	lock->l_flags |= ldlm_flags_from_wire(reply->lock_flags &
					      LDLM_FL_INHERIT_MASK);
        unlock_res_and_lock(lock);

	CDEBUG(D_INFO, "local: %p, remote cookie: %#llx, flags: %#llx\n",
	       lock, reply->lock_handle.cookie, *flags);

	/* If enqueue returned a blocked lock but the completion handler has
	 * already run, then it fixed up the resource and we don't need to do it
	 * again. */
	if ((*flags) & LDLM_FL_LOCK_CHANGED) {
		int newmode = reply->lock_desc.l_req_mode;
		LASSERT(!is_replay);
		if (newmode && newmode != lock->l_req_mode) {
			LDLM_DEBUG(lock, "server returned different mode %s",
				   ldlm_lockname[newmode]);
			lock->l_req_mode = newmode;
		}

		if (!ldlm_res_eq(&reply->lock_desc.l_resource.lr_name,
				 &lock->l_resource->lr_name)) {
			CDEBUG(D_INFO, "remote intent success, locking "DLDLMRES
				       " instead of "DLDLMRES"\n",
			       PLDLMRES(&reply->lock_desc.l_resource),
			       PLDLMRES(lock->l_resource));

			rc = ldlm_lock_change_resource(ns, lock,
					&reply->lock_desc.l_resource.lr_name);
			if (rc || lock->l_resource == NULL)
				GOTO(cleanup, rc = -ENOMEM);
			LDLM_DEBUG(lock, "client-side enqueue, new resource");
		}

		if (with_policy) {
			/* We assume lock type cannot change on server*/
			ldlm_convert_policy_to_local(exp,
						lock->l_resource->lr_type,
						&reply->lock_desc.l_policy_data,
						&lock->l_policy_data);
		}

                if (type != LDLM_PLAIN)
                        LDLM_DEBUG(lock,"client-side enqueue, new policy data");
        }

	if ((*flags) & LDLM_FL_AST_SENT) {
                lock_res_and_lock(lock);
		lock->l_flags |= LDLM_FL_CBPENDING | LDLM_FL_BL_AST;
                unlock_res_and_lock(lock);
                LDLM_DEBUG(lock, "enqueue reply includes blocking AST");
        }

        /* If the lock has already been granted by a completion AST, don't
         * clobber the LVB with an older one. */
	if (lvb_len > 0) {
		/* We must lock or a racing completion might update lvb without
		 * letting us know and we'll clobber the correct value.
		 * Cannot unlock after the check either, a that still leaves
		 * a tiny window for completion to get in */
		lock_res_and_lock(lock);
		if (lock->l_req_mode != lock->l_granted_mode)
			rc = ldlm_fill_lvb(lock, &req->rq_pill, RCL_SERVER,
					   lock->l_lvb_data, lvb_len);
		unlock_res_and_lock(lock);
		if (rc < 0) {
			cleanup_phase = 1;
			GOTO(cleanup, rc);
		}
        }

        if (!is_replay) {
                rc = ldlm_lock_enqueue(ns, &lock, NULL, flags);
                if (lock->l_completion_ast != NULL) {
                        int err = lock->l_completion_ast(lock, *flags, NULL);
                        if (!rc)
                                rc = err;
                        if (rc)
                                cleanup_phase = 1;
                }
        }

	if (lvb_len > 0 && lvb != NULL) {
		/* Copy the LVB here, and not earlier, because the completion
		 * AST (if any) can override what we got in the reply */
		memcpy(lvb, lock->l_lvb_data, lvb_len);
	}

        LDLM_DEBUG(lock, "client-side enqueue END");
        EXIT;
cleanup:
        if (cleanup_phase == 1 && rc)
                failed_lock_cleanup(ns, lock, mode);
        /* Put lock 2 times, the second reference is held by ldlm_cli_enqueue */
        LDLM_LOCK_PUT(lock);
        LDLM_LOCK_RELEASE(lock);
        return rc;
}
EXPORT_SYMBOL(ldlm_cli_enqueue_fini);

/**
 * Estimate number of lock handles that would fit into request of given
 * size.  PAGE_SIZE-512 is to allow TCP/IP and LNET headers to fit into
 * a single page on the send/receive side. XXX: 512 should be changed to
 * more adequate value.
 */
static inline int ldlm_req_handles_avail(int req_size, int off)
{
        int avail;

	avail = min_t(int, LDLM_MAXREQSIZE, PAGE_SIZE - 512) - req_size;
        if (likely(avail >= 0))
                avail /= (int)sizeof(struct lustre_handle);
        else
                avail = 0;
        avail += LDLM_LOCKREQ_HANDLES - off;

        return avail;
}

static inline int ldlm_capsule_handles_avail(struct req_capsule *pill,
                                             enum req_location loc,
                                             int off)
{
	__u32 size = req_capsule_msg_size(pill, loc);
	return ldlm_req_handles_avail(size, off);
}

static inline int ldlm_format_handles_avail(struct obd_import *imp,
                                            const struct req_format *fmt,
                                            enum req_location loc, int off)
{
	__u32 size = req_capsule_fmt_size(imp->imp_msg_magic, fmt, loc);
	return ldlm_req_handles_avail(size, off);
}

/**
 * Cancel LRU locks and pack them into the enqueue request. Pack there the given
 * \a count locks in \a cancels.
 *
 * This is to be called by functions preparing their own requests that
 * might contain lists of locks to cancel in addition to actual operation
 * that needs to be performed.
 */
int ldlm_prep_elc_req(struct obd_export *exp, struct ptlrpc_request *req,
		      int version, int opc, int canceloff,
		      struct list_head *cancels, int count)
	{
	struct ldlm_namespace	*ns = exp->exp_obd->obd_namespace;
	struct req_capsule	*pill = &req->rq_pill;
	struct ldlm_request	*dlm = NULL;
	struct list_head	head = LIST_HEAD_INIT(head);
	enum ldlm_lru_flags lru_flags;
	int avail, to_free, pack = 0;
	int rc;
	ENTRY;

	if (cancels == NULL)
		cancels = &head;
	if (ns_connect_cancelset(ns)) {
		/* Estimate the amount of available space in the request. */
		req_capsule_filled_sizes(pill, RCL_CLIENT);
		avail = ldlm_capsule_handles_avail(pill, RCL_CLIENT, canceloff);

		lru_flags = LDLM_LRU_FLAG_NO_WAIT | (ns_connect_lru_resize(ns) ?
			LDLM_LRU_FLAG_LRUR : LDLM_LRU_FLAG_AGED);
		to_free = !ns_connect_lru_resize(ns) &&
			opc == LDLM_ENQUEUE ? 1 : 0;

		/* Cancel LRU locks here _only_ if the server supports
		 * EARLY_CANCEL. Otherwise we have to send extra CANCEL
		 * RPC, which will make us slower. */
		if (avail > count)
			count += ldlm_cancel_lru_local(ns, cancels, to_free,
						       avail - count, 0,
						       lru_flags);
		if (avail > count)
			pack = count;
		else
			pack = avail;
		req_capsule_set_size(pill, &RMF_DLM_REQ, RCL_CLIENT,
				     ldlm_request_bufsize(pack, opc));
	}

        rc = ptlrpc_request_pack(req, version, opc);
        if (rc) {
                ldlm_lock_list_put(cancels, l_bl_ast, count);
                RETURN(rc);
        }

	if (ns_connect_cancelset(ns)) {
                if (canceloff) {
                        dlm = req_capsule_client_get(pill, &RMF_DLM_REQ);
                        LASSERT(dlm);
                        /* Skip first lock handler in ldlm_request_pack(),
			 * this method will increment @lock_count according
                         * to the lock handle amount actually written to
                         * the buffer. */
                        dlm->lock_count = canceloff;
                }
                /* Pack into the request @pack lock handles. */
                ldlm_cli_cancel_list(cancels, pack, req, 0);
		/* Prepare and send separate cancel RPC for others. */
                ldlm_cli_cancel_list(cancels, count - pack, NULL, 0);
        } else {
                ldlm_lock_list_put(cancels, l_bl_ast, count);
        }
        RETURN(0);
}
EXPORT_SYMBOL(ldlm_prep_elc_req);

int ldlm_prep_enqueue_req(struct obd_export *exp, struct ptlrpc_request *req,
			  struct list_head *cancels, int count)
{
        return ldlm_prep_elc_req(exp, req, LUSTRE_DLM_VERSION, LDLM_ENQUEUE,
                                 LDLM_ENQUEUE_CANCEL_OFF, cancels, count);
}
EXPORT_SYMBOL(ldlm_prep_enqueue_req);

struct ptlrpc_request *ldlm_enqueue_pack(struct obd_export *exp, int lvb_len)
{
	struct ptlrpc_request *req;
	int rc;
	ENTRY;

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_LDLM_ENQUEUE);
	if (req == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	rc = ldlm_prep_enqueue_req(exp, req, NULL, 0);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(ERR_PTR(rc));
	}

	req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER, lvb_len);
	ptlrpc_request_set_replen(req);
	RETURN(req);
}
EXPORT_SYMBOL(ldlm_enqueue_pack);

/**
 * Client-side lock enqueue.
 *
 * If a request has some specific initialisation it is passed in \a reqp,
 * otherwise it is created in ldlm_cli_enqueue.
 *
 * Supports sync and async requests, pass \a async flag accordingly. If a
 * request was created in ldlm_cli_enqueue and it is the async request,
 * pass it to the caller in \a reqp.
 */
int ldlm_cli_enqueue(struct obd_export *exp, struct ptlrpc_request **reqp,
		     struct ldlm_enqueue_info *einfo,
		     const struct ldlm_res_id *res_id,
		     union ldlm_policy_data const *policy, __u64 *flags,
		     void *lvb, __u32 lvb_len, enum lvb_type lvb_type,
		     struct lustre_handle *lockh, int async)
{
	struct ldlm_namespace *ns;
        struct ldlm_lock      *lock;
        struct ldlm_request   *body;
        int                    is_replay = *flags & LDLM_FL_REPLAY;
        int                    req_passed_in = 1;
        int                    rc, err;
        struct ptlrpc_request *req;
        ENTRY;

        LASSERT(exp != NULL);

	ns = exp->exp_obd->obd_namespace;

        /* If we're replaying this lock, just check some invariants.
         * If we're creating a new lock, get everything all setup nice. */
        if (is_replay) {
                lock = ldlm_handle2lock_long(lockh, 0);
                LASSERT(lock != NULL);
                LDLM_DEBUG(lock, "client-side enqueue START");
                LASSERT(exp == lock->l_conn_export);
        } else {
		const struct ldlm_callback_suite cbs = {
			.lcs_completion = einfo->ei_cb_cp,
			.lcs_blocking	= einfo->ei_cb_bl,
			.lcs_glimpse	= einfo->ei_cb_gl
		};
		lock = ldlm_lock_create(ns, res_id, einfo->ei_type,
					einfo->ei_mode, &cbs, einfo->ei_cbdata,
					lvb_len, lvb_type);
		if (IS_ERR(lock))
			RETURN(PTR_ERR(lock));
                /* for the local lock, add the reference */
                ldlm_lock_addref_internal(lock, einfo->ei_mode);
                ldlm_lock2handle(lock, lockh);
		if (policy != NULL)
			lock->l_policy_data = *policy;

		if (einfo->ei_type == LDLM_EXTENT) {
			/* extent lock without policy is a bug */
			if (policy == NULL)
				LBUG();

			lock->l_req_extent = policy->l_extent;
		}
		LDLM_DEBUG(lock, "client-side enqueue START, flags %#llx",
			   *flags);
	}

	lock->l_conn_export = exp;
	lock->l_export = NULL;
	lock->l_blocking_ast = einfo->ei_cb_bl;
	lock->l_flags |= (*flags & (LDLM_FL_NO_LRU | LDLM_FL_EXCL));
        lock->l_activity = cfs_time_current_sec();

	/* lock not sent to server yet */
	if (reqp == NULL || *reqp == NULL) {
		req = ldlm_enqueue_pack(exp, lvb_len);
		if (IS_ERR(req)) {
			failed_lock_cleanup(ns, lock, einfo->ei_mode);
			LDLM_LOCK_RELEASE(lock);
			RETURN(PTR_ERR(req));
		}

		req_passed_in = 0;
		if (reqp)
			*reqp = req;
	} else {
		int len;

		req = *reqp;
		len = req_capsule_get_size(&req->rq_pill, &RMF_DLM_REQ,
					   RCL_CLIENT);
		LASSERTF(len >= sizeof(*body), "buflen[%d] = %d, not %d\n",
			 DLM_LOCKREQ_OFF, len, (int)sizeof(*body));
	}

	/* Dump lock data into the request buffer */
	body = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
	ldlm_lock2desc(lock, &body->lock_desc);
	body->lock_flags = ldlm_flags_to_wire(*flags);
	body->lock_handle[0] = *lockh;

	if (async) {
		LASSERT(reqp != NULL);
		RETURN(0);
	}

	LDLM_DEBUG(lock, "sending request");

	rc = ptlrpc_queue_wait(req);

	err = ldlm_cli_enqueue_fini(exp, req, einfo->ei_type, policy ? 1 : 0,
				    einfo->ei_mode, flags, lvb, lvb_len,
				    lockh, rc);

	/* If ldlm_cli_enqueue_fini did not find the lock, we need to free
	 * one reference that we took */
	if (err == -ENOLCK)
		LDLM_LOCK_RELEASE(lock);
	else
		rc = err;

	if (!req_passed_in && req != NULL) {
		ptlrpc_req_finished(req);
		if (reqp)
			*reqp = NULL;
	}

	RETURN(rc);
}
EXPORT_SYMBOL(ldlm_cli_enqueue);

static int ldlm_cli_convert_local(struct ldlm_lock *lock, int new_mode,
                                  __u32 *flags)
{
        struct ldlm_resource *res;
        int rc;
        ENTRY;
        if (ns_is_client(ldlm_lock_to_ns(lock))) {
                CERROR("Trying to cancel local lock\n");
                LBUG();
        }
        LDLM_DEBUG(lock, "client-side local convert");

        res = ldlm_lock_convert(lock, new_mode, flags);
        if (res) {
                ldlm_reprocess_all(res);
                rc = 0;
        } else {
		rc = LUSTRE_EDEADLK;
        }
        LDLM_DEBUG(lock, "client-side local convert handler END");
        LDLM_LOCK_PUT(lock);
        RETURN(rc);
}

/* FIXME: one of ldlm_cli_convert or the server side should reject attempted
 * conversion of locks which are on the waiting or converting queue */
/* Caller of this code is supposed to take care of lock readers/writers
   accounting */
int ldlm_cli_convert(const struct lustre_handle *lockh, int new_mode,
		     __u32 *flags)
{
        struct ldlm_request   *body;
        struct ldlm_reply     *reply;
        struct ldlm_lock      *lock;
        struct ldlm_resource  *res;
        struct ptlrpc_request *req;
        int                    rc;
        ENTRY;

        lock = ldlm_handle2lock(lockh);
        if (!lock) {
                LBUG();
                RETURN(-EINVAL);
        }
        *flags = 0;

        if (lock->l_conn_export == NULL)
                RETURN(ldlm_cli_convert_local(lock, new_mode, flags));

        LDLM_DEBUG(lock, "client-side convert");

        req = ptlrpc_request_alloc_pack(class_exp2cliimp(lock->l_conn_export),
                                        &RQF_LDLM_CONVERT, LUSTRE_DLM_VERSION,
                                        LDLM_CONVERT);
        if (req == NULL) {
                LDLM_LOCK_PUT(lock);
                RETURN(-ENOMEM);
        }

        body = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        body->lock_handle[0] = lock->l_remote_handle;

        body->lock_desc.l_req_mode = new_mode;
	body->lock_flags = ldlm_flags_to_wire(*flags);


        ptlrpc_request_set_replen(req);
        rc = ptlrpc_queue_wait(req);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        reply = req_capsule_server_get(&req->rq_pill, &RMF_DLM_REP);
        if (reply == NULL)
                GOTO(out, rc = -EPROTO);

        if (req->rq_status)
                GOTO(out, rc = req->rq_status);

        res = ldlm_lock_convert(lock, new_mode, &reply->lock_flags);
        if (res != NULL) {
                ldlm_reprocess_all(res);
                /* Go to sleep until the lock is granted. */
                /* FIXME: or cancelled. */
                if (lock->l_completion_ast) {
                        rc = lock->l_completion_ast(lock, LDLM_FL_WAIT_NOREPROC,
                                                    NULL);
                        if (rc)
                                GOTO(out, rc);
                }
        } else {
		rc = LUSTRE_EDEADLK;
        }
        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
        ptlrpc_req_finished(req);
        return rc;
}

/**
 * Cancel locks locally.
 * Returns:
 * \retval LDLM_FL_LOCAL_ONLY if there is no need for a CANCEL RPC to the server
 * \retval LDLM_FL_CANCELING otherwise;
 * \retval LDLM_FL_BL_AST if there is a need for a separate CANCEL RPC.
 */
static __u64 ldlm_cli_cancel_local(struct ldlm_lock *lock)
{
	__u64 rc = LDLM_FL_LOCAL_ONLY;
        ENTRY;

        if (lock->l_conn_export) {
                bool local_only;

                LDLM_DEBUG(lock, "client-side cancel");
                /* Set this flag to prevent others from getting new references*/
                lock_res_and_lock(lock);
		ldlm_set_cbpending(lock);
		local_only = !!(lock->l_flags &
				(LDLM_FL_LOCAL_ONLY|LDLM_FL_CANCEL_ON_BLOCK));
		ldlm_cancel_callback(lock);
		rc = (ldlm_is_bl_ast(lock)) ?
			LDLM_FL_BL_AST : LDLM_FL_CANCELING;
		unlock_res_and_lock(lock);

                if (local_only) {
                        CDEBUG(D_DLMTRACE, "not sending request (at caller's "
                               "instruction)\n");
                        rc = LDLM_FL_LOCAL_ONLY;
                }
                ldlm_lock_cancel(lock);
        } else {
                if (ns_is_client(ldlm_lock_to_ns(lock))) {
                        LDLM_ERROR(lock, "Trying to cancel local lock");
                        LBUG();
                }
                LDLM_DEBUG(lock, "server-side local cancel");
                ldlm_lock_cancel(lock);
                ldlm_reprocess_all(lock->l_resource);
        }

        RETURN(rc);
}

/**
 * Pack \a count locks in \a head into ldlm_request buffer of request \a req.
 */
static void ldlm_cancel_pack(struct ptlrpc_request *req,
			     struct list_head *head, int count)
{
        struct ldlm_request *dlm;
        struct ldlm_lock *lock;
        int max, packed = 0;
        ENTRY;

        dlm = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        LASSERT(dlm != NULL);

        /* Check the room in the request buffer. */
        max = req_capsule_get_size(&req->rq_pill, &RMF_DLM_REQ, RCL_CLIENT) -
                sizeof(struct ldlm_request);
        max /= sizeof(struct lustre_handle);
        max += LDLM_LOCKREQ_HANDLES;
        LASSERT(max >= dlm->lock_count + count);

        /* XXX: it would be better to pack lock handles grouped by resource.
         * so that the server cancel would call filter_lvbo_update() less
         * frequently. */
	list_for_each_entry(lock, head, l_bl_ast) {
                if (!count--)
                        break;
                LASSERT(lock->l_conn_export);
                /* Pack the lock handle to the given request buffer. */
                LDLM_DEBUG(lock, "packing");
                dlm->lock_handle[dlm->lock_count++] = lock->l_remote_handle;
                packed++;
        }
        CDEBUG(D_DLMTRACE, "%d locks packed\n", packed);
        EXIT;
}

/**
 * Prepare and send a batched cancel RPC. It will include \a count lock
 * handles of locks given in \a cancels list. */
int ldlm_cli_cancel_req(struct obd_export *exp, struct list_head *cancels,
			int count, enum ldlm_cancel_flags flags)
{
	struct ptlrpc_request *req = NULL;
	struct obd_import *imp;
	int free, sent = 0;
	int rc = 0;
	ENTRY;

        LASSERT(exp != NULL);
        LASSERT(count > 0);

        CFS_FAIL_TIMEOUT(OBD_FAIL_LDLM_PAUSE_CANCEL, cfs_fail_val);

        if (CFS_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_RACE))
                RETURN(count);

        free = ldlm_format_handles_avail(class_exp2cliimp(exp),
                                         &RQF_LDLM_CANCEL, RCL_CLIENT, 0);
        if (count > free)
                count = free;

        while (1) {
                imp = class_exp2cliimp(exp);
                if (imp == NULL || imp->imp_invalid) {
                        CDEBUG(D_DLMTRACE,
                               "skipping cancel on invalid import %p\n", imp);
                        RETURN(count);
                }

                req = ptlrpc_request_alloc(imp, &RQF_LDLM_CANCEL);
                if (req == NULL)
                        GOTO(out, rc = -ENOMEM);

                req_capsule_filled_sizes(&req->rq_pill, RCL_CLIENT);
                req_capsule_set_size(&req->rq_pill, &RMF_DLM_REQ, RCL_CLIENT,
                                     ldlm_request_bufsize(count, LDLM_CANCEL));

                rc = ptlrpc_request_pack(req, LUSTRE_DLM_VERSION, LDLM_CANCEL);
                if (rc) {
                        ptlrpc_request_free(req);
                        GOTO(out, rc);
                }

		/* If OSP want cancel cross-MDT lock, let's not block it in
		 * in recovery, otherwise the lock will not released, if
		 * the remote target is also in recovery, and it also need
		 * this lock, it might cause deadlock. */
		if (exp_connect_flags(exp) & OBD_CONNECT_MDS_MDS &&
		    exp->exp_obd->obd_lu_dev != NULL &&
		    exp->exp_obd->obd_lu_dev->ld_site != NULL) {
			struct lu_device *top_dev;

			top_dev = exp->exp_obd->obd_lu_dev->ld_site->ls_top_dev;
			if (top_dev != NULL &&
			    top_dev->ld_obd->obd_recovering)
				req->rq_allow_replay = 1;
		}

                req->rq_request_portal = LDLM_CANCEL_REQUEST_PORTAL;
                req->rq_reply_portal = LDLM_CANCEL_REPLY_PORTAL;
                ptlrpc_at_set_req_timeout(req);

                ldlm_cancel_pack(req, cancels, count);

		ptlrpc_request_set_replen(req);
		if (flags & LCF_ASYNC) {
			ptlrpcd_add_req(req);
			sent = count;
			GOTO(out, 0);
		}

		rc = ptlrpc_queue_wait(req);
		if (rc == LUSTRE_ESTALE) {
                        CDEBUG(D_DLMTRACE, "client/server (nid %s) "
                               "out of sync -- not fatal\n",
                               libcfs_nid2str(req->rq_import->
                                              imp_connection->c_peer.nid));
                        rc = 0;
                } else if (rc == -ETIMEDOUT && /* check there was no reconnect*/
                           req->rq_import_generation == imp->imp_generation) {
                        ptlrpc_req_finished(req);
                        continue;
                } else if (rc != ELDLM_OK) {
			/* -ESHUTDOWN is common on umount */
			CDEBUG_LIMIT(rc == -ESHUTDOWN ? D_DLMTRACE : D_ERROR,
				     "Got rc %d from cancel RPC: "
				     "canceling anyway\n", rc);
			break;
                }
                sent = count;
                break;
        }

        ptlrpc_req_finished(req);
        EXIT;
out:
        return sent ? sent : rc;
}

static inline struct ldlm_pool *ldlm_imp2pl(struct obd_import *imp)
{
        LASSERT(imp != NULL);
        return &imp->imp_obd->obd_namespace->ns_pool;
}

/**
 * Update client's OBD pool related fields with new SLV and Limit from \a req.
 */
int ldlm_cli_update_pool(struct ptlrpc_request *req)
{
        struct obd_device *obd;
        __u64 new_slv;
        __u32 new_limit;
        ENTRY;
        if (unlikely(!req->rq_import || !req->rq_import->imp_obd ||
                     !imp_connect_lru_resize(req->rq_import)))
        {
                /*
                 * Do nothing for corner cases.
                 */
                RETURN(0);
        }

	/* In some cases RPC may contain SLV and limit zeroed out. This
	 * is the case when server does not support LRU resize feature.
	 * This is also possible in some recovery cases when server-side
	 * reqs have no reference to the OBD export and thus access to
	 * server-side namespace is not possible. */
        if (lustre_msg_get_slv(req->rq_repmsg) == 0 ||
            lustre_msg_get_limit(req->rq_repmsg) == 0) {
                DEBUG_REQ(D_HA, req, "Zero SLV or Limit found "
			  "(SLV: %llu, Limit: %u)",
                          lustre_msg_get_slv(req->rq_repmsg),
                          lustre_msg_get_limit(req->rq_repmsg));
                RETURN(0);
        }

        new_limit = lustre_msg_get_limit(req->rq_repmsg);
        new_slv = lustre_msg_get_slv(req->rq_repmsg);
        obd = req->rq_import->imp_obd;

	/* Set new SLV and limit in OBD fields to make them accessible
	 * to the pool thread. We do not access obd_namespace and pool
	 * directly here as there is no reliable way to make sure that
	 * they are still alive at cleanup time. Evil races are possible
	 * which may cause Oops at that time. */
	write_lock(&obd->obd_pool_lock);
        obd->obd_pool_slv = new_slv;
        obd->obd_pool_limit = new_limit;
	write_unlock(&obd->obd_pool_lock);

        RETURN(0);
}

/**
 * Client side lock cancel.
 *
 * Lock must not have any readers or writers by this time.
 */
int ldlm_cli_cancel(const struct lustre_handle *lockh,
		    enum ldlm_cancel_flags cancel_flags)
{
	struct obd_export *exp;
	enum ldlm_lru_flags lru_flags;
	int avail, count = 1;
	__u64 rc = 0;
	struct ldlm_namespace *ns;
	struct ldlm_lock *lock;
	struct list_head cancels = LIST_HEAD_INIT(cancels);
	ENTRY;

	lock = ldlm_handle2lock_long(lockh, 0);
	if (lock == NULL) {
		LDLM_DEBUG_NOLOCK("lock is already being destroyed");
		RETURN(0);
	}

	lock_res_and_lock(lock);
	/* Lock is being canceled and the caller doesn't want to wait */
	if (ldlm_is_canceling(lock)) {
		if (cancel_flags & LCF_ASYNC) {
			unlock_res_and_lock(lock);
		} else {
			struct l_wait_info lwi = { 0 };

			unlock_res_and_lock(lock);
			l_wait_event(lock->l_waitq, is_bl_done(lock), &lwi);
		}
		LDLM_LOCK_RELEASE(lock);
		RETURN(0);
	}

	ldlm_set_canceling(lock);
	unlock_res_and_lock(lock);

	rc = ldlm_cli_cancel_local(lock);
	if (rc == LDLM_FL_LOCAL_ONLY || cancel_flags & LCF_LOCAL) {
		LDLM_LOCK_RELEASE(lock);
		RETURN(0);
	}
	/* Even if the lock is marked as LDLM_FL_BL_AST, this is a LDLM_CANCEL
	 * RPC which goes to canceld portal, so we can cancel other LRU locks
	 * here and send them all as one LDLM_CANCEL RPC. */
	LASSERT(list_empty(&lock->l_bl_ast));
	list_add(&lock->l_bl_ast, &cancels);

	exp = lock->l_conn_export;
	if (exp_connect_cancelset(exp)) {
		avail = ldlm_format_handles_avail(class_exp2cliimp(exp),
						  &RQF_LDLM_CANCEL,
						  RCL_CLIENT, 0);
		LASSERT(avail > 0);

		ns = ldlm_lock_to_ns(lock);
		lru_flags = ns_connect_lru_resize(ns) ?
			LDLM_LRU_FLAG_LRUR : LDLM_LRU_FLAG_AGED;
		count += ldlm_cancel_lru_local(ns, &cancels, 0, avail - 1,
					       LCF_BL_AST, lru_flags);
	}
	ldlm_cli_cancel_list(&cancels, count, NULL, cancel_flags);
	RETURN(0);
}
EXPORT_SYMBOL(ldlm_cli_cancel);

/**
 * Locally cancel up to \a count locks in list \a cancels.
 * Return the number of cancelled locks.
 */
int ldlm_cli_cancel_list_local(struct list_head *cancels, int count,
			       enum ldlm_cancel_flags cancel_flags)
{
	struct list_head head = LIST_HEAD_INIT(head);
	struct ldlm_lock *lock, *next;
	int left = 0, bl_ast = 0;
	__u64 rc;

	left = count;
	list_for_each_entry_safe(lock, next, cancels, l_bl_ast) {
		if (left-- == 0)
			break;

		if (cancel_flags & LCF_LOCAL) {
			rc = LDLM_FL_LOCAL_ONLY;
			ldlm_lock_cancel(lock);
		} else {
			rc = ldlm_cli_cancel_local(lock);
		}
		/* Until we have compound requests and can send LDLM_CANCEL
		 * requests batched with generic RPCs, we need to send cancels
		 * with the LDLM_FL_BL_AST flag in a separate RPC from
		 * the one being generated now. */
		if (!(cancel_flags & LCF_BL_AST) && (rc == LDLM_FL_BL_AST)) {
			LDLM_DEBUG(lock, "Cancel lock separately");
			list_del_init(&lock->l_bl_ast);
			list_add(&lock->l_bl_ast, &head);
			bl_ast++;
			continue;
		}
		if (rc == LDLM_FL_LOCAL_ONLY) {
			/* CANCEL RPC should not be sent to server. */
			list_del_init(&lock->l_bl_ast);
                        LDLM_LOCK_RELEASE(lock);
                        count--;
                }
        }
        if (bl_ast > 0) {
                count -= bl_ast;
                ldlm_cli_cancel_list(&head, bl_ast, NULL, 0);
        }

        RETURN(count);
}

/**
 * Cancel as many locks as possible w/o sending any RPCs (e.g. to write back
 * dirty data, to close a file, ...) or waiting for any RPCs in-flight (e.g.
 * readahead requests, ...)
 */
static enum ldlm_policy_res
ldlm_cancel_no_wait_policy(struct ldlm_namespace *ns, struct ldlm_lock *lock,
			   int unused, int added, int count)
{
	enum ldlm_policy_res result = LDLM_POLICY_CANCEL_LOCK;

	/* don't check added & count since we want to process all locks
	 * from unused list.
	 * It's fine to not take lock to access lock->l_resource since
	 * the lock has already been granted so it won't change. */
	switch (lock->l_resource->lr_type) {
		case LDLM_EXTENT:
		case LDLM_IBITS:
			if (ns->ns_cancel != NULL && ns->ns_cancel(lock) != 0)
				break;
		default:
			result = LDLM_POLICY_SKIP_LOCK;
			break;
	}

	RETURN(result);
}

/**
 * Callback function for LRU-resize policy. Decides whether to keep
 * \a lock in LRU for current \a LRU size \a unused, added in current
 * scan \a added and number of locks to be preferably canceled \a count.
 *
 * \retval LDLM_POLICY_KEEP_LOCK keep lock in LRU in stop scanning
 *
 * \retval LDLM_POLICY_CANCEL_LOCK cancel lock from LRU
 */
static enum ldlm_policy_res ldlm_cancel_lrur_policy(struct ldlm_namespace *ns,
						    struct ldlm_lock *lock,
						    int unused, int added,
						    int count)
{
	ktime_t cur = ktime_get();
	struct ldlm_pool *pl = &ns->ns_pool;
	u64 slv, lvf, lv;
	s64 la;

	/* Stop LRU processing when we reach past @count or have checked all
	 * locks in LRU. */
	if (count && added >= count)
		return LDLM_POLICY_KEEP_LOCK;

	/* Despite of the LV, It doesn't make sense to keep the lock which
	 * is unused for ns_max_age time.
	 */
	if (ktime_after(ktime_get(),
			ktime_add(lock->l_last_used, ns->ns_max_age)))
		return LDLM_POLICY_CANCEL_LOCK;

	slv = ldlm_pool_get_slv(pl);
	lvf = ldlm_pool_get_lvf(pl);
	la = ktime_to_ns(ktime_sub(cur, lock->l_last_used)) / NSEC_PER_SEC;
	lv = lvf * la * unused;

	/* Inform pool about current CLV to see it via proc. */
	ldlm_pool_set_clv(pl, lv);

	/* Stop when SLV is not yet come from server or lv is smaller than
	 * it is. */
	if (slv == 0 || lv < slv)
		return LDLM_POLICY_KEEP_LOCK;

	return LDLM_POLICY_CANCEL_LOCK;
}

static enum ldlm_policy_res
ldlm_cancel_lrur_no_wait_policy(struct ldlm_namespace *ns,
				struct ldlm_lock *lock,
				int unused, int added,
				int count)
{
	enum ldlm_policy_res result;

	result = ldlm_cancel_lrur_policy(ns, lock, unused, added, count);
	if (result == LDLM_POLICY_KEEP_LOCK)
		return result;

	return ldlm_cancel_no_wait_policy(ns, lock, unused, added, count);
}

/**
 * Callback function for proc used policy. Makes decision whether to keep
 * \a lock in LRU for current \a LRU size \a unused, added in current scan \a
 * added and number of locks to be preferably canceled \a count.
 *
 * \retval LDLM_POLICY_KEEP_LOCK keep lock in LRU in stop scanning
 *
 * \retval LDLM_POLICY_CANCEL_LOCK cancel lock from LRU
 */
static enum ldlm_policy_res ldlm_cancel_passed_policy(struct ldlm_namespace *ns,
						      struct ldlm_lock *lock,
						      int unused, int added,
						      int count)
{
	/* Stop LRU processing when we reach past @count or have checked all
	 * locks in LRU. */
	return (added >= count) ?
		LDLM_POLICY_KEEP_LOCK : LDLM_POLICY_CANCEL_LOCK;
}

/**
 * Callback function for aged policy. Makes decision whether to keep \a lock in
 * LRU for current LRU size \a unused, added in current scan \a added and
 * number of locks to be preferably canceled \a count.
 *
 * \retval LDLM_POLICY_KEEP_LOCK keep lock in LRU in stop scanning
 *
 * \retval LDLM_POLICY_CANCEL_LOCK cancel lock from LRU
 */
static enum ldlm_policy_res ldlm_cancel_aged_policy(struct ldlm_namespace *ns,
						    struct ldlm_lock *lock,
						    int unused, int added,
						    int count)
{
	if ((added >= count) &&
	    ktime_before(ktime_get(),
			 ktime_add(lock->l_last_used, ns->ns_max_age)))
		return LDLM_POLICY_KEEP_LOCK;

	return LDLM_POLICY_CANCEL_LOCK;
}

static enum ldlm_policy_res
ldlm_cancel_aged_no_wait_policy(struct ldlm_namespace *ns,
				struct ldlm_lock *lock,
				int unused, int added, int count)
{
	enum ldlm_policy_res result;

	result = ldlm_cancel_aged_policy(ns, lock, unused, added, count);
	if (result == LDLM_POLICY_KEEP_LOCK)
		return result;

	return ldlm_cancel_no_wait_policy(ns, lock, unused, added, count);
}

/**
 * Callback function for default policy. Makes decision whether to keep \a lock
 * in LRU for current LRU size \a unused, added in current scan \a added and
 * number of locks to be preferably canceled \a count.
 *
 * \retval LDLM_POLICY_KEEP_LOCK keep lock in LRU in stop scanning
 *
 * \retval LDLM_POLICY_CANCEL_LOCK cancel lock from LRU
 */
static
enum ldlm_policy_res ldlm_cancel_default_policy(struct ldlm_namespace *ns,
						struct ldlm_lock *lock,
						int unused, int added,
						int count)
{
	/* Stop LRU processing when we reach past count or have checked all
	 * locks in LRU. */
        return (added >= count) ?
                LDLM_POLICY_KEEP_LOCK : LDLM_POLICY_CANCEL_LOCK;
}

typedef enum ldlm_policy_res
(*ldlm_cancel_lru_policy_t)(struct ldlm_namespace *ns, struct ldlm_lock *lock,
			    int unused, int added, int count);

static ldlm_cancel_lru_policy_t
ldlm_cancel_lru_policy(struct ldlm_namespace *ns, enum ldlm_lru_flags lru_flags)
{
	if (ns_connect_lru_resize(ns)) {
		if (lru_flags & LDLM_LRU_FLAG_SHRINK)
			/* We kill passed number of old locks. */
			return ldlm_cancel_passed_policy;
		if (lru_flags & LDLM_LRU_FLAG_LRUR) {
			if (lru_flags & LDLM_LRU_FLAG_NO_WAIT)
				return ldlm_cancel_lrur_no_wait_policy;
			else
				return ldlm_cancel_lrur_policy;
		}
		if (lru_flags & LDLM_LRU_FLAG_PASSED)
			return ldlm_cancel_passed_policy;
	} else {
		if (lru_flags & LDLM_LRU_FLAG_AGED) {
			if (lru_flags & LDLM_LRU_FLAG_NO_WAIT)
				return ldlm_cancel_aged_no_wait_policy;
			else
				return ldlm_cancel_aged_policy;
		}
	}
	if (lru_flags & LDLM_LRU_FLAG_NO_WAIT)
		return ldlm_cancel_no_wait_policy;

	return ldlm_cancel_default_policy;
}

/**
 * - Free space in LRU for \a count new locks,
 *   redundant unused locks are canceled locally;
 * - also cancel locally unused aged locks;
 * - do not cancel more than \a max locks;
 * - GET the found locks and add them into the \a cancels list.
 *
 * A client lock can be added to the l_bl_ast list only when it is
 * marked LDLM_FL_CANCELING. Otherwise, somebody is already doing
 * CANCEL.  There are the following use cases:
 * ldlm_cancel_resource_local(), ldlm_cancel_lru_local() and
 * ldlm_cli_cancel(), which check and set this flag properly. As any
 * attempt to cancel a lock rely on this flag, l_bl_ast list is accessed
 * later without any special locking.
 *
 * Calling policies for enabled LRU resize:
 * ----------------------------------------
 * flags & LDLM_LRU_FLAG_LRUR - use LRU resize policy (SLV from server) to
 *				cancel not more than \a count locks;
 *
 * flags & LDLM_LRU_FLAG_PASSED - cancel \a count number of old locks (located
 *				at the beginning of LRU list);
 *
 * flags & LDLM_LRU_FLAG_SHRINK - cancel not more than \a count locks according
 *				to memory pressre policy function;
 *
 * flags & LDLM_LRU_FLAG_AGED - cancel \a count locks according to "aged policy"
 *
 * flags & LDLM_LRU_FLAG_NO_WAIT - cancel as many unused locks as possible
 *				(typically before replaying locks) w/o
 *				sending any RPCs or waiting for any
 *				outstanding RPC to complete.
 *
 * flags & LDLM_CANCEL_CLEANUP - when cancelling read locks, do not check for
 * 				other read locks covering the same pages, just
 * 				discard those pages.
 */
static int ldlm_prepare_lru_list(struct ldlm_namespace *ns,
				 struct list_head *cancels, int count, int max,
				 enum ldlm_lru_flags lru_flags)
{
	ldlm_cancel_lru_policy_t pf;
	int added = 0;
	int no_wait = lru_flags & LDLM_LRU_FLAG_NO_WAIT;

	ENTRY;

	if (!ns_connect_lru_resize(ns))
		count += ns->ns_nr_unused - ns->ns_max_unused;

	pf = ldlm_cancel_lru_policy(ns, lru_flags);
	LASSERT(pf != NULL);

	/* For any flags, stop scanning if @max is reached. */
	while (!list_empty(&ns->ns_unused_list) && (max == 0 || added < max)) {
		struct ldlm_lock *lock;
		struct list_head *item, *next;
		enum ldlm_policy_res result;
		ktime_t last_use = ktime_set(0, 0);

		spin_lock(&ns->ns_lock);
		item = no_wait ? ns->ns_last_pos : &ns->ns_unused_list;
		for (item = item->next, next = item->next;
		     item != &ns->ns_unused_list;
		     item = next, next = item->next) {
			lock = list_entry(item, struct ldlm_lock, l_lru);

			/* No locks which got blocking requests. */
			LASSERT(!ldlm_is_bl_ast(lock));

			if (!ldlm_is_canceling(lock))
				break;

			/* Somebody is already doing CANCEL. No need for this
			 * lock in LRU, do not traverse it again. */
			ldlm_lock_remove_from_lru_nolock(lock);
		}
		if (item == &ns->ns_unused_list) {
			spin_unlock(&ns->ns_lock);
			break;
		}

		last_use = lock->l_last_used;

		LDLM_LOCK_GET(lock);
		spin_unlock(&ns->ns_lock);
		lu_ref_add(&lock->l_reference, __FUNCTION__, current);

		/* Pass the lock through the policy filter and see if it
		 * should stay in LRU.
		 *
		 * Even for shrinker policy we stop scanning if
		 * we find a lock that should stay in the cache.
		 * We should take into account lock age anyway
		 * as a new lock is a valuable resource even if
		 * it has a low weight.
		 *
		 * That is, for shrinker policy we drop only
		 * old locks, but additionally choose them by
		 * their weight. Big extent locks will stay in
		 * the cache. */
		result = pf(ns, lock, ns->ns_nr_unused, added, count);
		if (result == LDLM_POLICY_KEEP_LOCK) {
			lu_ref_del(&lock->l_reference, __func__, current);
			LDLM_LOCK_RELEASE(lock);
			break;
		}

		if (result == LDLM_POLICY_SKIP_LOCK) {
			lu_ref_del(&lock->l_reference, __func__, current);
			LDLM_LOCK_RELEASE(lock);
			if (no_wait) {
				spin_lock(&ns->ns_lock);
				if (!list_empty(&lock->l_lru) &&
				    lock->l_lru.prev == ns->ns_last_pos)
					ns->ns_last_pos = &lock->l_lru;
				spin_unlock(&ns->ns_lock);
			}
			continue;
		}

		lock_res_and_lock(lock);
		/* Check flags again under the lock. */
		if (ldlm_is_canceling(lock) ||
		    ldlm_lock_remove_from_lru_check(lock, last_use) == 0) {
			/* Another thread is removing lock from LRU, or
			 * somebody is already doing CANCEL, or there
			 * is a blocking request which will send cancel
			 * by itself, or the lock is no longer unused or
			 * the lock has been used since the pf() call and
			 * pages could be put under it. */
			unlock_res_and_lock(lock);
			lu_ref_del(&lock->l_reference, __FUNCTION__, current);
			LDLM_LOCK_RELEASE(lock);
			continue;
		}
		LASSERT(!lock->l_readers && !lock->l_writers);

		/* If we have chosen to cancel this lock voluntarily, we
		 * better send cancel notification to server, so that it
		 * frees appropriate state. This might lead to a race
		 * where while we are doing cancel here, server is also
		 * silently cancelling this lock. */
		ldlm_clear_cancel_on_block(lock);

		/* Setting the CBPENDING flag is a little misleading,
		 * but prevents an important race; namely, once
		 * CBPENDING is set, the lock can accumulate no more
		 * readers/writers. Since readers and writers are
		 * already zero here, ldlm_lock_decref() won't see
		 * this flag and call l_blocking_ast */
		lock->l_flags |= LDLM_FL_CBPENDING | LDLM_FL_CANCELING;

		if ((lru_flags & LDLM_LRU_FLAG_CLEANUP) &&
		    lock->l_resource->lr_type == LDLM_EXTENT &&
		    lock->l_granted_mode == LCK_PR)
			ldlm_set_discard_data(lock);

		/* We can't re-add to l_lru as it confuses the
		 * refcounting in ldlm_lock_remove_from_lru() if an AST
		 * arrives after we drop lr_lock below. We use l_bl_ast
		 * and can't use l_pending_chain as it is used both on
		 * server and client nevertheless bug 5666 says it is
		 * used only on server */
		LASSERT(list_empty(&lock->l_bl_ast));
		list_add(&lock->l_bl_ast, cancels);
		unlock_res_and_lock(lock);
		lu_ref_del(&lock->l_reference, __FUNCTION__, current);
		added++;
	}
	RETURN(added);
}

int ldlm_cancel_lru_local(struct ldlm_namespace *ns, struct list_head *cancels,
			  int count, int max,
			  enum ldlm_cancel_flags cancel_flags,
			  enum ldlm_lru_flags lru_flags)
{
	int added;

	added = ldlm_prepare_lru_list(ns, cancels, count, max, lru_flags);
	if (added <= 0)
		return added;

	return ldlm_cli_cancel_list_local(cancels, added, cancel_flags);
}

/**
 * Cancel at least \a nr locks from given namespace LRU.
 *
 * When called with LCF_ASYNC the blocking callback will be handled
 * in a thread and this function will return after the thread has been
 * asked to call the callback.  When called with LCF_ASYNC the blocking
 * callback will be performed in this function.
 */
int ldlm_cancel_lru(struct ldlm_namespace *ns, int nr,
		    enum ldlm_cancel_flags cancel_flags,
		    enum ldlm_lru_flags lru_flags)
{
	struct list_head cancels = LIST_HEAD_INIT(cancels);
	int count, rc;
	ENTRY;

	/* Just prepare the list of locks, do not actually cancel them yet.
	 * Locks are cancelled later in a separate thread. */
	count = ldlm_prepare_lru_list(ns, &cancels, nr, 0, lru_flags);
	rc = ldlm_bl_to_thread_list(ns, NULL, &cancels, count, cancel_flags);
	if (rc == 0)
		RETURN(count);

	RETURN(0);
}

/**
 * Find and cancel locally unused locks found on resource, matched to the
 * given policy, mode. GET the found locks and add them into the \a cancels
 * list.
 */
int ldlm_cancel_resource_local(struct ldlm_resource *res,
			       struct list_head *cancels,
			       union ldlm_policy_data *policy,
			       enum ldlm_mode mode, __u64 lock_flags,
			       enum ldlm_cancel_flags cancel_flags,
			       void *opaque)
{
	struct ldlm_lock *lock;
	int count = 0;
	ENTRY;

	lock_res(res);
	list_for_each_entry(lock, &res->lr_granted, l_res_link) {
                if (opaque != NULL && lock->l_ast_data != opaque) {
                        LDLM_ERROR(lock, "data %p doesn't match opaque %p",
                                   lock->l_ast_data, opaque);
                        //LBUG();
                        continue;
                }

                if (lock->l_readers || lock->l_writers)
                        continue;

		/* If somebody is already doing CANCEL, or blocking AST came,
		 * skip this lock. */
		if (ldlm_is_bl_ast(lock) || ldlm_is_canceling(lock))
			continue;

                if (lockmode_compat(lock->l_granted_mode, mode))
                        continue;

                /* If policy is given and this is IBITS lock, add to list only
                 * those locks that match by policy. */
                if (policy && (lock->l_resource->lr_type == LDLM_IBITS) &&
                    !(lock->l_policy_data.l_inodebits.bits &
                      policy->l_inodebits.bits))
                        continue;

		/* See CBPENDING comment in ldlm_cancel_lru */
		lock->l_flags |= LDLM_FL_CBPENDING | LDLM_FL_CANCELING |
				 lock_flags;

		LASSERT(list_empty(&lock->l_bl_ast));
		list_add(&lock->l_bl_ast, cancels);
                LDLM_LOCK_GET(lock);
                count++;
        }
        unlock_res(res);

        RETURN(ldlm_cli_cancel_list_local(cancels, count, cancel_flags));
}
EXPORT_SYMBOL(ldlm_cancel_resource_local);

/**
 * Cancel client-side locks from a list and send/prepare cancel RPCs to the
 * server.
 * If \a req is NULL, send CANCEL request to server with handles of locks
 * in the \a cancels. If EARLY_CANCEL is not supported, send CANCEL requests
 * separately per lock.
 * If \a req is not NULL, put handles of locks in \a cancels into the request
 * buffer at the offset \a off.
 * Destroy \a cancels at the end.
 */
int ldlm_cli_cancel_list(struct list_head *cancels, int count,
			 struct ptlrpc_request *req,
			 enum ldlm_cancel_flags flags)
{
	struct ldlm_lock *lock;
	int res = 0;
	ENTRY;

	if (list_empty(cancels) || count == 0)
                RETURN(0);

        /* XXX: requests (both batched and not) could be sent in parallel.
         * Usually it is enough to have just 1 RPC, but it is possible that
         * there are too many locks to be cancelled in LRU or on a resource.
         * It would also speed up the case when the server does not support
         * the feature. */
        while (count > 0) {
		LASSERT(!list_empty(cancels));
		lock = list_entry(cancels->next, struct ldlm_lock,
                                      l_bl_ast);
                LASSERT(lock->l_conn_export);

                if (exp_connect_cancelset(lock->l_conn_export)) {
                        res = count;
                        if (req)
                                ldlm_cancel_pack(req, cancels, count);
                        else
                                res = ldlm_cli_cancel_req(lock->l_conn_export,
                                                          cancels, count,
                                                          flags);
                } else {
                        res = ldlm_cli_cancel_req(lock->l_conn_export,
                                                  cancels, 1, flags);
                }

		if (res < 0) {
			CDEBUG_LIMIT(res == -ESHUTDOWN ? D_DLMTRACE : D_ERROR,
				     "ldlm_cli_cancel_list: %d\n", res);
			res = count;
		}

                count -= res;
                ldlm_lock_list_put(cancels, l_bl_ast, res);
        }
        LASSERT(count == 0);
        RETURN(0);
}
EXPORT_SYMBOL(ldlm_cli_cancel_list);

/**
 * Cancel all locks on a resource that have 0 readers/writers.
 *
 * If flags & LDLM_FL_LOCAL_ONLY, throw the locks away without trying
 * to notify the server. */
int ldlm_cli_cancel_unused_resource(struct ldlm_namespace *ns,
				    const struct ldlm_res_id *res_id,
				    union ldlm_policy_data *policy,
				    enum ldlm_mode mode,
				    enum ldlm_cancel_flags flags, void *opaque)
{
	struct ldlm_resource *res;
	struct list_head cancels = LIST_HEAD_INIT(cancels);
	int count;
	int rc;
	ENTRY;

	res = ldlm_resource_get(ns, NULL, res_id, 0, 0);
	if (IS_ERR(res)) {
		/* This is not a problem. */
		CDEBUG(D_INFO, "No resource %llu\n", res_id->name[0]);
		RETURN(0);
	}

	LDLM_RESOURCE_ADDREF(res);
	count = ldlm_cancel_resource_local(res, &cancels, policy, mode,
					   0, flags | LCF_BL_AST, opaque);
	rc = ldlm_cli_cancel_list(&cancels, count, NULL, flags);
	if (rc != ELDLM_OK)
		CERROR("canceling unused lock "DLDLMRES": rc = %d\n",
		       PLDLMRES(res), rc);

	LDLM_RESOURCE_DELREF(res);
	ldlm_resource_putref(res);
	RETURN(0);
}
EXPORT_SYMBOL(ldlm_cli_cancel_unused_resource);

struct ldlm_cli_cancel_arg {
        int     lc_flags;
        void   *lc_opaque;
};

static int
ldlm_cli_hash_cancel_unused(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			    struct hlist_node *hnode, void *arg)
{
	struct ldlm_resource           *res = cfs_hash_object(hs, hnode);
	struct ldlm_cli_cancel_arg     *lc = arg;

	ldlm_cli_cancel_unused_resource(ldlm_res_to_ns(res), &res->lr_name,
					NULL, LCK_MINMODE, lc->lc_flags,
					lc->lc_opaque);
	/* must return 0 for hash iteration */
	return 0;
}

/**
 * Cancel all locks on a namespace (or a specific resource, if given)
 * that have 0 readers/writers.
 *
 * If flags & LCF_LOCAL, throw the locks away without trying
 * to notify the server. */
int ldlm_cli_cancel_unused(struct ldlm_namespace *ns,
			   const struct ldlm_res_id *res_id,
			   enum ldlm_cancel_flags flags, void *opaque)
{
        struct ldlm_cli_cancel_arg arg = {
                .lc_flags       = flags,
                .lc_opaque      = opaque,
        };

        ENTRY;

        if (ns == NULL)
                RETURN(ELDLM_OK);

        if (res_id != NULL) {
                RETURN(ldlm_cli_cancel_unused_resource(ns, res_id, NULL,
                                                       LCK_MINMODE, flags,
                                                       opaque));
	} else {
		cfs_hash_for_each_nolock(ns->ns_rs_hash,
					 ldlm_cli_hash_cancel_unused, &arg, 0);
		RETURN(ELDLM_OK);
	}
}

/* Lock iterators. */

int ldlm_resource_foreach(struct ldlm_resource *res, ldlm_iterator_t iter,
                          void *closure)
{
	struct list_head *tmp, *next;
        struct ldlm_lock *lock;
        int rc = LDLM_ITER_CONTINUE;

        ENTRY;

        if (!res)
                RETURN(LDLM_ITER_CONTINUE);

        lock_res(res);
	list_for_each_safe(tmp, next, &res->lr_granted) {
		lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (iter(lock, closure) == LDLM_ITER_STOP)
                        GOTO(out, rc = LDLM_ITER_STOP);
        }

	list_for_each_safe(tmp, next, &res->lr_converting) {
		lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (iter(lock, closure) == LDLM_ITER_STOP)
                        GOTO(out, rc = LDLM_ITER_STOP);
        }

	list_for_each_safe(tmp, next, &res->lr_waiting) {
		lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (iter(lock, closure) == LDLM_ITER_STOP)
                        GOTO(out, rc = LDLM_ITER_STOP);
        }
 out:
        unlock_res(res);
        RETURN(rc);
}

struct iter_helper_data {
        ldlm_iterator_t iter;
        void *closure;
};

static int ldlm_iter_helper(struct ldlm_lock *lock, void *closure)
{
        struct iter_helper_data *helper = closure;
        return helper->iter(lock, helper->closure);
}

static int ldlm_res_iter_helper(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				struct hlist_node *hnode, void *arg)

{
        struct ldlm_resource *res = cfs_hash_object(hs, hnode);

        return ldlm_resource_foreach(res, ldlm_iter_helper, arg) ==
               LDLM_ITER_STOP;
}

void ldlm_namespace_foreach(struct ldlm_namespace *ns,
                            ldlm_iterator_t iter, void *closure)

{
	struct iter_helper_data helper = { .iter = iter, .closure = closure };

	cfs_hash_for_each_nolock(ns->ns_rs_hash,
				 ldlm_res_iter_helper, &helper, 0);

}

/* non-blocking function to manipulate a lock whose cb_data is being put away.
 * return  0:  find no resource
 *       > 0:  must be LDLM_ITER_STOP/LDLM_ITER_CONTINUE.
 *       < 0:  errors
 */
int ldlm_resource_iterate(struct ldlm_namespace *ns,
			  const struct ldlm_res_id *res_id,
			  ldlm_iterator_t iter, void *data)
{
	struct ldlm_resource *res;
	int rc;
	ENTRY;

	LASSERTF(ns != NULL, "must pass in namespace\n");

	res = ldlm_resource_get(ns, NULL, res_id, 0, 0);
	if (IS_ERR(res))
		RETURN(0);

	LDLM_RESOURCE_ADDREF(res);
	rc = ldlm_resource_foreach(res, iter, data);
	LDLM_RESOURCE_DELREF(res);
	ldlm_resource_putref(res);
	RETURN(rc);
}
EXPORT_SYMBOL(ldlm_resource_iterate);

/* Lock replay */

static int ldlm_chain_lock_for_replay(struct ldlm_lock *lock, void *closure)
{
	struct list_head *list = closure;

        /* we use l_pending_chain here, because it's unused on clients. */
	LASSERTF(list_empty(&lock->l_pending_chain),
                 "lock %p next %p prev %p\n",
                 lock, &lock->l_pending_chain.next,&lock->l_pending_chain.prev);
        /* bug 9573: don't replay locks left after eviction, or
         * bug 17614: locks being actively cancelled. Get a reference
         * on a lock so that it does not disapear under us (e.g. due to cancel)
         */
	if (!(lock->l_flags & (LDLM_FL_FAILED|LDLM_FL_BL_DONE))) {
		list_add(&lock->l_pending_chain, list);
                LDLM_LOCK_GET(lock);
        }

        return LDLM_ITER_CONTINUE;
}

static int replay_lock_interpret(const struct lu_env *env,
				 struct ptlrpc_request *req,
				 struct ldlm_async_args *aa, int rc)
{
	struct ldlm_lock     *lock;
	struct ldlm_reply    *reply;
	struct obd_export    *exp;

	ENTRY;
	atomic_dec(&req->rq_import->imp_replay_inflight);
	if (rc != ELDLM_OK)
		GOTO(out, rc);

        reply = req_capsule_server_get(&req->rq_pill, &RMF_DLM_REP);
        if (reply == NULL)
                GOTO(out, rc = -EPROTO);

        lock = ldlm_handle2lock(&aa->lock_handle);
        if (!lock) {
		CERROR("received replay ack for unknown local cookie %#llx"
		       " remote cookie %#llx from server %s id %s\n",
                       aa->lock_handle.cookie, reply->lock_handle.cookie,
                       req->rq_export->exp_client_uuid.uuid,
                       libcfs_id2str(req->rq_peer));
                GOTO(out, rc = -ESTALE);
        }

        /* Key change rehash lock in per-export hash with new key */
        exp = req->rq_export;
        if (exp && exp->exp_lock_hash) {
		/* In the function below, .hs_keycmp resolves to
		 * ldlm_export_lock_keycmp() */
		/* coverity[overrun-buffer-val] */
                cfs_hash_rehash_key(exp->exp_lock_hash,
                                    &lock->l_remote_handle,
                                    &reply->lock_handle,
                                    &lock->l_exp_hash);
        } else {
                lock->l_remote_handle = reply->lock_handle;
        }

        LDLM_DEBUG(lock, "replayed lock:");
        ptlrpc_import_recovery_state_machine(req->rq_import);
        LDLM_LOCK_PUT(lock);
out:
        if (rc != ELDLM_OK)
                ptlrpc_connect_import(req->rq_import);

        RETURN(rc);
}

static int replay_one_lock(struct obd_import *imp, struct ldlm_lock *lock)
{
        struct ptlrpc_request *req;
        struct ldlm_async_args *aa;
        struct ldlm_request   *body;
        int flags;
        ENTRY;


        /* Bug 11974: Do not replay a lock which is actively being canceled */
	if (ldlm_is_bl_done(lock)) {
                LDLM_DEBUG(lock, "Not replaying canceled lock:");
                RETURN(0);
        }

        /* If this is reply-less callback lock, we cannot replay it, since
         * server might have long dropped it, but notification of that event was
         * lost by network. (and server granted conflicting lock already) */
	if (ldlm_is_cancel_on_block(lock)) {
                LDLM_DEBUG(lock, "Not replaying reply-less lock:");
                ldlm_lock_cancel(lock);
                RETURN(0);
        }

        /*
         * If granted mode matches the requested mode, this lock is granted.
         *
         * If they differ, but we have a granted mode, then we were granted
         * one mode and now want another: ergo, converting.
         *
         * If we haven't been granted anything and are on a resource list,
         * then we're blocked/waiting.
         *
         * If we haven't been granted anything and we're NOT on a resource list,
         * then we haven't got a reply yet and don't have a known disposition.
         * This happens whenever a lock enqueue is the request that triggers
         * recovery.
         */
        if (lock->l_granted_mode == lock->l_req_mode)
                flags = LDLM_FL_REPLAY | LDLM_FL_BLOCK_GRANTED;
        else if (lock->l_granted_mode)
                flags = LDLM_FL_REPLAY | LDLM_FL_BLOCK_CONV;
	else if (!list_empty(&lock->l_res_link))
                flags = LDLM_FL_REPLAY | LDLM_FL_BLOCK_WAIT;
        else
                flags = LDLM_FL_REPLAY;

        req = ptlrpc_request_alloc_pack(imp, &RQF_LDLM_ENQUEUE,
                                        LUSTRE_DLM_VERSION, LDLM_ENQUEUE);
        if (req == NULL)
                RETURN(-ENOMEM);

        /* We're part of recovery, so don't wait for it. */
        req->rq_send_state = LUSTRE_IMP_REPLAY_LOCKS;

        body = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
        ldlm_lock2desc(lock, &body->lock_desc);
	body->lock_flags = ldlm_flags_to_wire(flags);

        ldlm_lock2handle(lock, &body->lock_handle[0]);
	if (lock->l_lvb_len > 0)
		req_capsule_extend(&req->rq_pill, &RQF_LDLM_ENQUEUE_LVB);
	req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
			     lock->l_lvb_len);
        ptlrpc_request_set_replen(req);
        /* notify the server we've replayed all requests.
         * also, we mark the request to be put on a dedicated
         * queue to be processed after all request replayes.
         * bug 6063 */
	lustre_msg_set_flags(req->rq_reqmsg, MSG_REQ_REPLAY_DONE);

	LDLM_DEBUG(lock, "replaying lock:");

	atomic_inc(&req->rq_import->imp_replay_inflight);
	CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
	aa = ptlrpc_req_async_args(req);
	aa->lock_handle = body->lock_handle[0];
	req->rq_interpret_reply = (ptlrpc_interpterer_t)replay_lock_interpret;
	ptlrpcd_add_req(req);

	RETURN(0);
}

/**
 * Cancel as many unused locks as possible before replay. since we are
 * in recovery, we can't wait for any outstanding RPCs to send any RPC
 * to the server.
 *
 * Called only in recovery before replaying locks. there is no need to
 * replay locks that are unused. since the clients may hold thousands of
 * cached unused locks, dropping the unused locks can greatly reduce the
 * load on the servers at recovery time.
 */
static void ldlm_cancel_unused_locks_for_replay(struct ldlm_namespace *ns)
{
	int canceled;
	struct list_head cancels = LIST_HEAD_INIT(cancels);

	CDEBUG(D_DLMTRACE, "Dropping as many unused locks as possible before"
			   "replay for namespace %s (%d)\n",
			   ldlm_ns_name(ns), ns->ns_nr_unused);

	/* We don't need to care whether or not LRU resize is enabled
	 * because the LDLM_LRU_FLAG_NO_WAIT policy doesn't use the
	 * count parameter */
	canceled = ldlm_cancel_lru_local(ns, &cancels, ns->ns_nr_unused, 0,
					 LCF_LOCAL, LDLM_LRU_FLAG_NO_WAIT);

	CDEBUG(D_DLMTRACE, "Canceled %d unused locks from namespace %s\n",
			   canceled, ldlm_ns_name(ns));
}

int ldlm_replay_locks(struct obd_import *imp)
{
	struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
	struct list_head list = LIST_HEAD_INIT(list);
	struct ldlm_lock *lock, *next;
	int rc = 0;

	ENTRY;

	LASSERT(atomic_read(&imp->imp_replay_inflight) == 0);

	/* don't replay locks if import failed recovery */
	if (imp->imp_vbr_failed)
		RETURN(0);

	/* ensure this doesn't fall to 0 before all have been queued */
	atomic_inc(&imp->imp_replay_inflight);

	if (ldlm_cancel_unused_locks_before_replay)
		ldlm_cancel_unused_locks_for_replay(ns);

	ldlm_namespace_foreach(ns, ldlm_chain_lock_for_replay, &list);

	list_for_each_entry_safe(lock, next, &list, l_pending_chain) {
		list_del_init(&lock->l_pending_chain);
		if (rc) {
			LDLM_LOCK_RELEASE(lock);
			continue; /* or try to do the rest? */
		}
		rc = replay_one_lock(imp, lock);
		LDLM_LOCK_RELEASE(lock);
	}

	atomic_dec(&imp->imp_replay_inflight);

	RETURN(rc);
}
