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
 * Copyright (c) 2003 Hewlett-Packard Development Company LP.
 * Developed under the sponsorship of the US Government under
 * Subcontract No. B514193
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

/**
 * This file implements POSIX lock type for Lustre.
 * Its policy properties are start and end of extent and PID.
 *
 * These locks are only done through MDS due to POSIX semantics requiring
 * e.g. that locks could be only partially released and as such split into
 * two parts, and also that two adjacent locks from the same process may be
 * merged into a single wider lock.
 *
 * Lock modes are mapped like this:
 * PR and PW for READ and WRITE locks
 * NL to request a releasing of a portion of the lock
 *
 * These flock locks never timeout.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/list.h>
#include <lustre_dlm.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_lib.h>

#include "ldlm_internal.h"

int ldlm_flock_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
			    void *data, int flag);

/**
 * list_for_remaining_safe - iterate over the remaining entries in a list
 *              and safeguard against removal of a list entry.
 * \param pos   the &struct list_head to use as a loop counter. pos MUST
 *              have been initialized prior to using it in this macro.
 * \param n     another &struct list_head to use as temporary storage
 * \param head  the head for your list.
 */
#define list_for_remaining_safe(pos, n, head) \
	for (n = pos->next; pos != (head); pos = n, n = pos->next)

static inline int
ldlm_same_flock_owner(struct ldlm_lock *lock, struct ldlm_lock *new)
{
	return ((new->l_policy_data.l_flock.owner ==
		 lock->l_policy_data.l_flock.owner) &&
		(new->l_export == lock->l_export));
}

static inline int
ldlm_flocks_overlap(struct ldlm_lock *lock, struct ldlm_lock *new)
{
	return ((new->l_policy_data.l_flock.start <=
		 lock->l_policy_data.l_flock.end) &&
		(new->l_policy_data.l_flock.end >=
		 lock->l_policy_data.l_flock.start));
}

static inline void ldlm_flock_blocking_link(struct ldlm_lock *req,
					    struct ldlm_lock *lock)
{
	/* For server only */
	if (req->l_export == NULL)
		return;

	LASSERT(hlist_unhashed(&req->l_exp_flock_hash));

	req->l_policy_data.l_flock.blocking_owner =
		lock->l_policy_data.l_flock.owner;
	req->l_policy_data.l_flock.blocking_export =
		lock->l_export;
	atomic_set(&req->l_policy_data.l_flock.blocking_refs, 0);

	cfs_hash_add(req->l_export->exp_flock_hash,
		     &req->l_policy_data.l_flock.owner,
		     &req->l_exp_flock_hash);
}

static inline void ldlm_flock_blocking_unlink(struct ldlm_lock *req)
{
	/* For server only */
	if (req->l_export == NULL)
		return;

	check_res_locked(req->l_resource);
	if (req->l_export->exp_flock_hash != NULL &&
	    !hlist_unhashed(&req->l_exp_flock_hash))
		cfs_hash_del(req->l_export->exp_flock_hash,
			     &req->l_policy_data.l_flock.owner,
			     &req->l_exp_flock_hash);
}

static inline void
ldlm_flock_destroy(struct ldlm_lock *lock, enum ldlm_mode mode, __u64 flags)
{
	ENTRY;

	LDLM_DEBUG(lock, "ldlm_flock_destroy(mode: %d, flags: %#llx)",
		   mode, flags);

	/* Safe to not lock here, since it should be empty anyway */
	LASSERT(hlist_unhashed(&lock->l_exp_flock_hash));

	list_del_init(&lock->l_res_link);
	if (flags == LDLM_FL_WAIT_NOREPROC) {
		/* client side - set a flag to prevent sending a CANCEL */
		lock->l_flags |= LDLM_FL_LOCAL_ONLY | LDLM_FL_CBPENDING;

		/* when reaching here, it is under lock_res_and_lock(). Thus,
		 * need call the nolock version of ldlm_lock_decref_internal
		 */
		ldlm_lock_decref_internal_nolock(lock, mode);
	}

	ldlm_lock_destroy_nolock(lock);
	EXIT;
}

#ifdef HAVE_SERVER_SUPPORT
/**
 * POSIX locks deadlock detection code.
 *
 * Given a new lock \a req and an existing lock \a bl_lock it conflicts
 * with, we need to iterate through all blocked POSIX locks for this
 * export and see if there is a deadlock condition arising. (i.e. when
 * one client holds a lock on something and want a lock on something
 * else and at the same time another client has the opposite situation).
 */

struct ldlm_flock_lookup_cb_data {
	__u64 *bl_owner;
	struct ldlm_lock *lock;
	struct obd_export *exp;
};

static int ldlm_flock_lookup_cb(struct obd_export *exp, void *data)
{
	struct ldlm_flock_lookup_cb_data *cb_data = data;
	struct ldlm_lock *lock;

	if (exp->exp_failed)
		return 0;

	lock = cfs_hash_lookup(exp->exp_flock_hash, cb_data->bl_owner);
	if (lock == NULL)
		return 0;

	/* Stop on first found lock. Same process can't sleep twice */
	cb_data->lock = lock;
	cb_data->exp = class_export_get(exp);

	return 1;
}

static int
ldlm_flock_deadlock(struct ldlm_lock *req, struct ldlm_lock *bl_lock)
{
	struct obd_export *req_exp = req->l_export;
	struct obd_export *bl_exp = bl_lock->l_export;
	__u64 req_owner = req->l_policy_data.l_flock.owner;
	__u64 bl_owner = bl_lock->l_policy_data.l_flock.owner;

	/* For server only */
	if (req_exp == NULL)
		return 0;

	class_export_get(bl_exp);
	while (1) {
		struct ldlm_flock_lookup_cb_data cb_data = {
			.bl_owner = &bl_owner,
			.lock = NULL,
			.exp = NULL,
		};
		struct ptlrpc_connection *bl_exp_conn;
		struct obd_export *bl_exp_new;
		struct ldlm_lock *lock = NULL;
		struct ldlm_flock *flock;

		bl_exp_conn = bl_exp->exp_connection;
		if (bl_exp->exp_flock_hash != NULL) {
			int found;

			found = obd_nid_export_for_each(bl_exp->exp_obd,
							bl_exp_conn->c_peer.nid,
							ldlm_flock_lookup_cb,
							&cb_data);
			if (found)
				lock = cb_data.lock;
		}
		if (lock == NULL)
			break;

		class_export_put(bl_exp);
		bl_exp = cb_data.exp;

		LASSERT(req != lock);
		flock = &lock->l_policy_data.l_flock;
		LASSERT(flock->owner == bl_owner);
		bl_owner = flock->blocking_owner;
		bl_exp_new = class_export_get(flock->blocking_export);
		class_export_put(bl_exp);

		cfs_hash_put(bl_exp->exp_flock_hash, &lock->l_exp_flock_hash);
		bl_exp = bl_exp_new;

		if (bl_exp->exp_failed)
			break;

		if (bl_owner == req_owner &&
		    (bl_exp_conn->c_peer.nid ==
		     req_exp->exp_connection->c_peer.nid)) {
			class_export_put(bl_exp);
			return 1;
		}
	}
	class_export_put(bl_exp);

	return 0;
}

static void ldlm_flock_cancel_on_deadlock(struct ldlm_lock *lock,
					  struct list_head *work_list)
{
	CDEBUG(D_INFO, "reprocess deadlock req=%p\n", lock);

	if ((exp_connect_flags(lock->l_export) &
	     OBD_CONNECT_FLOCK_DEAD) == 0) {
		CERROR("deadlock found, but client doesn't support flock canceliation\n");
	} else {
		LASSERT(lock->l_completion_ast);
		LASSERT(!ldlm_is_ast_sent(lock));
		lock->l_flags |= (LDLM_FL_AST_SENT | LDLM_FL_CANCEL_ON_BLOCK |
				  LDLM_FL_FLOCK_DEADLOCK);
		ldlm_flock_blocking_unlink(lock);
		ldlm_resource_unlink_lock(lock);
		ldlm_add_ast_work_item(lock, NULL, work_list);
	}
}
#endif /* HAVE_SERVER_SUPPORT */

/**
 * Process a granting attempt for flock lock.
 * Must be called under ns lock held.
 *
 * This function looks for any conflicts for \a lock in the granted or
 * waiting queues. The lock is granted if no conflicts are found in
 * either queue.
 */
int
ldlm_process_flock_lock(struct ldlm_lock *req, __u64 *flags,
			enum ldlm_process_intention intention,
			enum ldlm_error *err, struct list_head *work_list)
{
	struct ldlm_resource *res = req->l_resource;
	struct ldlm_namespace *ns = ldlm_res_to_ns(res);
	struct list_head *tmp;
	struct list_head *ownlocks = NULL;
	struct ldlm_lock *lock = NULL;
	struct ldlm_lock *new = req;
	struct ldlm_lock *new2 = NULL;
	enum ldlm_mode mode = req->l_req_mode;
	int local = ns_is_client(ns);
	int added = (mode == LCK_NL);
	int overlaps = 0;
	int splitted = 0;
	const struct ldlm_callback_suite null_cbs = { NULL };
#ifdef HAVE_SERVER_SUPPORT
	struct list_head *grant_work = (intention == LDLM_PROCESS_ENQUEUE ?
					NULL : work_list);
#endif
	ENTRY;

	CDEBUG(D_DLMTRACE, "flags %#llx owner %llu pid %u mode %u start "
	       "%llu end %llu\n", *flags,
	       new->l_policy_data.l_flock.owner,
	       new->l_policy_data.l_flock.pid, mode,
	       req->l_policy_data.l_flock.start,
	       req->l_policy_data.l_flock.end);

	*err = ELDLM_OK;

	if (local) {
		/* No blocking ASTs are sent to the clients for
		 * Posix file & record locks
		 */
		req->l_blocking_ast = NULL;
	} else {
		/* Called on the server for lock cancels. */
		req->l_blocking_ast = ldlm_flock_blocking_ast;
	}

reprocess:
	if ((*flags == LDLM_FL_WAIT_NOREPROC) || (mode == LCK_NL)) {
		/* This loop determines where this processes locks start
		 * in the resource lr_granted list.
		 */
		list_for_each(tmp, &res->lr_granted) {
			lock = list_entry(tmp, struct ldlm_lock,
					  l_res_link);
			if (ldlm_same_flock_owner(lock, req)) {
				ownlocks = tmp;
				break;
			}
		}
	}
#ifdef HAVE_SERVER_SUPPORT
	else {
		int reprocess_failed = 0;
		lockmode_verify(mode);

		/* This loop determines if there are existing locks
		 * that conflict with the new lock request.
		 */
		list_for_each(tmp, &res->lr_granted) {
			lock = list_entry(tmp, struct ldlm_lock,
					  l_res_link);

			if (ldlm_same_flock_owner(lock, req)) {
				if (!ownlocks)
					ownlocks = tmp;
				continue;
			}

			/* locks are compatible, overlap doesn't matter */
			if (lockmode_compat(lock->l_granted_mode, mode))
				continue;

			if (!ldlm_flocks_overlap(lock, req))
				continue;

			if (intention != LDLM_PROCESS_ENQUEUE) {
				if (ldlm_flock_deadlock(req, lock)) {
					ldlm_flock_cancel_on_deadlock(
						req, grant_work);
					RETURN(LDLM_ITER_CONTINUE);
				}
				reprocess_failed = 1;
				break;
			}

			if (*flags & LDLM_FL_BLOCK_NOWAIT) {
				ldlm_flock_destroy(req, mode, *flags);
				*err = -EAGAIN;
				RETURN(LDLM_ITER_STOP);
			}

			if (*flags & LDLM_FL_TEST_LOCK) {
				ldlm_flock_destroy(req, mode, *flags);
				req->l_req_mode = lock->l_granted_mode;
				req->l_policy_data.l_flock.pid =
					lock->l_policy_data.l_flock.pid;
				req->l_policy_data.l_flock.start =
					lock->l_policy_data.l_flock.start;
				req->l_policy_data.l_flock.end =
					lock->l_policy_data.l_flock.end;
				*flags |= LDLM_FL_LOCK_CHANGED;
				RETURN(LDLM_ITER_STOP);
			}

			/* add lock to blocking list before deadlock
			 * check to prevent race
			 */
			ldlm_flock_blocking_link(req, lock);

			if (ldlm_flock_deadlock(req, lock)) {
				ldlm_flock_blocking_unlink(req);
				ldlm_flock_destroy(req, mode, *flags);
				*err = -EDEADLK;
				RETURN(LDLM_ITER_STOP);
			}

			ldlm_resource_add_lock(res, &res->lr_waiting, req);
			*flags |= LDLM_FL_BLOCK_GRANTED;
			RETURN(LDLM_ITER_STOP);
		}
		if (reprocess_failed)
			RETURN(LDLM_ITER_CONTINUE);
	}

	if (*flags & LDLM_FL_TEST_LOCK) {
		ldlm_flock_destroy(req, mode, *flags);
		req->l_req_mode = LCK_NL;
		*flags |= LDLM_FL_LOCK_CHANGED;
		RETURN(LDLM_ITER_STOP);
	}

	/* In case we had slept on this lock request take it off of the
	 * deadlock detection hash list.
	 */
	ldlm_flock_blocking_unlink(req);
#endif /* HAVE_SERVER_SUPPORT */

	/* Scan the locks owned by this process that overlap this request.
	 * We may have to merge or split existing locks.
	 */
	if (!ownlocks)
		ownlocks = &res->lr_granted;

	list_for_remaining_safe(ownlocks, tmp, &res->lr_granted) {
		lock = list_entry(ownlocks, struct ldlm_lock, l_res_link);

		if (!ldlm_same_flock_owner(lock, new))
			break;

		if (lock->l_granted_mode == mode) {
			/* If the modes are the same then we need to process
			 * locks that overlap OR adjoin the new lock. The extra
			 * logic condition is necessary to deal with arithmetic
			 * overflow and underflow.
			 */
			if ((new->l_policy_data.l_flock.start >
			     (lock->l_policy_data.l_flock.end + 1))
			    && (lock->l_policy_data.l_flock.end !=
				OBD_OBJECT_EOF))
				continue;

			if ((new->l_policy_data.l_flock.end <
			     (lock->l_policy_data.l_flock.start - 1))
			    && (lock->l_policy_data.l_flock.start != 0))
				break;

			if (new->l_policy_data.l_flock.start <
			    lock->l_policy_data.l_flock.start) {
				lock->l_policy_data.l_flock.start =
					new->l_policy_data.l_flock.start;
			} else {
				new->l_policy_data.l_flock.start =
					lock->l_policy_data.l_flock.start;
			}

			if (new->l_policy_data.l_flock.end >
			    lock->l_policy_data.l_flock.end) {
				lock->l_policy_data.l_flock.end =
					new->l_policy_data.l_flock.end;
			} else {
				new->l_policy_data.l_flock.end =
					lock->l_policy_data.l_flock.end;
			}

			if (added) {
				ldlm_flock_destroy(lock, mode, *flags);
			} else {
				new = lock;
				added = 1;
			}
			continue;
		}

		if (new->l_policy_data.l_flock.start >
		    lock->l_policy_data.l_flock.end)
			continue;

		if (new->l_policy_data.l_flock.end <
		    lock->l_policy_data.l_flock.start)
			break;

		++overlaps;

		if (new->l_policy_data.l_flock.start <=
		    lock->l_policy_data.l_flock.start) {
			if (new->l_policy_data.l_flock.end <
			    lock->l_policy_data.l_flock.end) {
				lock->l_policy_data.l_flock.start =
					new->l_policy_data.l_flock.end + 1;
				break;
			}
			ldlm_flock_destroy(lock, lock->l_req_mode, *flags);
			continue;
		}
		if (new->l_policy_data.l_flock.end >=
		    lock->l_policy_data.l_flock.end) {
			lock->l_policy_data.l_flock.end =
				new->l_policy_data.l_flock.start - 1;
			continue;
		}

		/* split the existing lock into two locks */

		/* if this is an F_UNLCK operation then we could avoid
		 * allocating a new lock and use the req lock passed in
		 * with the request but this would complicate the reply
		 * processing since updates to req get reflected in the
		 * reply. The client side replays the lock request so
		 * it must see the original lock data in the reply.
		 */

		/* XXX - if ldlm_lock_new() can sleep we should
		 * release the lr_lock, allocate the new lock,
		 * and restart processing this lock.
		 */
		if (new2 == NULL) {
			unlock_res_and_lock(req);
			new2 = ldlm_lock_create(ns, &res->lr_name, LDLM_FLOCK,
						lock->l_granted_mode, &null_cbs,
						NULL, 0, LVB_T_NONE);
			lock_res_and_lock(req);
			if (IS_ERR(new2)) {
				ldlm_flock_destroy(req, lock->l_granted_mode,
						   *flags);
				*err = PTR_ERR(new2);
				RETURN(LDLM_ITER_STOP);
			}
			goto reprocess;
		}

		splitted = 1;

		new2->l_granted_mode = lock->l_granted_mode;
		new2->l_policy_data.l_flock.pid =
			new->l_policy_data.l_flock.pid;
		new2->l_policy_data.l_flock.owner =
			new->l_policy_data.l_flock.owner;
		new2->l_policy_data.l_flock.start =
			lock->l_policy_data.l_flock.start;
		new2->l_policy_data.l_flock.end =
			new->l_policy_data.l_flock.start - 1;
		lock->l_policy_data.l_flock.start =
			new->l_policy_data.l_flock.end + 1;
		new2->l_conn_export = lock->l_conn_export;
		if (lock->l_export != NULL) {
			new2->l_export = class_export_lock_get(lock->l_export,
							       new2);
			if (new2->l_export->exp_lock_hash &&
			    hlist_unhashed(&new2->l_exp_hash))
				cfs_hash_add(new2->l_export->exp_lock_hash,
					     &new2->l_remote_handle,
					     &new2->l_exp_hash);
		}
		if (*flags == LDLM_FL_WAIT_NOREPROC)
			ldlm_lock_addref_internal_nolock(new2,
							 lock->l_granted_mode);

		/* insert new2 at lock */
		ldlm_resource_add_lock(res, ownlocks, new2);
		LDLM_LOCK_RELEASE(new2);
		break;
	}

	/* if new2 is created but never used, destroy it*/
	if (splitted == 0 && new2 != NULL)
		ldlm_lock_destroy_nolock(new2);

	/* At this point we're granting the lock request. */
	req->l_granted_mode = req->l_req_mode;

	/* Add req to the granted queue before calling ldlm_reprocess_all(). */
	if (!added) {
		list_del_init(&req->l_res_link);
		/* insert new lock before ownlocks in list. */
		ldlm_resource_add_lock(res, ownlocks, req);
	}

	if (*flags != LDLM_FL_WAIT_NOREPROC) {
#ifdef HAVE_SERVER_SUPPORT
		if (intention == LDLM_PROCESS_ENQUEUE) {
			/* If this is an unlock, reprocess the waitq and
			 * send completions ASTs for locks that can now be
			 * granted. The only problem with doing this
			 * reprocessing here is that the completion ASTs for
			 * newly granted locks will be sent before the unlock
			 * completion is sent. It shouldn't be an issue. Also
			 * note that ldlm_process_flock_lock() will recurse,
			 * but only once because 'intention' won't be
			 * LDLM_PROCESS_ENQUEUE from ldlm_reprocess_queue.
			 */
			if ((mode == LCK_NL) && overlaps) {
				LIST_HEAD(rpc_list);
				int rc;

restart:
				ldlm_reprocess_queue(res, &res->lr_waiting,
						     &rpc_list,
						     LDLM_PROCESS_RESCAN, NULL);

				unlock_res_and_lock(req);
				rc = ldlm_run_ast_work(ns, &rpc_list,
						       LDLM_WORK_CP_AST);
				lock_res_and_lock(req);
				if (rc == -ERESTART)
					GOTO(restart, rc);
			}
		} else {
			LASSERT(req->l_completion_ast);
			ldlm_add_ast_work_item(req, NULL, grant_work);
		}
#else /* !HAVE_SERVER_SUPPORT */
		/* The only one possible case for client-side calls flock
		 * policy function is ldlm_flock_completion_ast inside which
		 * carries LDLM_FL_WAIT_NOREPROC flag.
		 */
		CERROR("Illegal parameter for client-side-only module.\n");
		LBUG();
#endif /* HAVE_SERVER_SUPPORT */
	}

	/* In case we're reprocessing the requested lock we can't destroy
	 * it until after calling ldlm_add_ast_work_item() above so that laawi()
	 * can bump the reference count on \a req. Otherwise \a req
	 * could be freed before the completion AST can be sent.
	 */
	if (added)
		ldlm_flock_destroy(req, mode, *flags);

	ldlm_resource_dump(D_INFO, res);
	RETURN(LDLM_ITER_CONTINUE);
}

/**
 * Flock completion callback function.
 *
 * \param lock [in,out]: A lock to be handled
 * \param flags    [in]: flags
 * \param *data    [in]: ldlm_work_cp_ast_lock() will use ldlm_cb_set_arg
 *
 * \retval 0    : success
 * \retval <0   : failure
 */
int
ldlm_flock_completion_ast(struct ldlm_lock *lock, __u64 flags, void *data)
{
	struct file_lock *getlk = lock->l_ast_data;
	struct obd_device *obd;
	enum ldlm_error err;
	int rc = 0;
	ENTRY;

	OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_CP_CB_WAIT2, 4);
	if (OBD_FAIL_PRECHECK(OBD_FAIL_LDLM_CP_CB_WAIT3)) {
		lock_res_and_lock(lock);
		lock->l_flags |= LDLM_FL_FAIL_LOC;
		unlock_res_and_lock(lock);
		OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_CP_CB_WAIT3, 4);
	}
	CDEBUG(D_DLMTRACE, "flags: %#llx data: %p getlk: %p\n",
	       flags, data, getlk);

	LASSERT(flags != LDLM_FL_WAIT_NOREPROC);

	if (flags & LDLM_FL_FAILED)
		goto granted;

	if (!(flags & LDLM_FL_BLOCKED_MASK)) {
		if (NULL == data)
			/* mds granted the lock in the reply */
			goto granted;
		/* CP AST RPC: lock get granted, wake it up */
		wake_up(&lock->l_waitq);
		RETURN(0);
	}

	LDLM_DEBUG(lock,
		   "client-side enqueue returned a blocked lock, sleeping");
	obd = class_exp2obd(lock->l_conn_export);

	/* Go to sleep until the lock is granted. */
	rc = l_wait_event_abortable(lock->l_waitq,
				    is_granted_or_cancelled(lock));
	if (rc < 0) {
		/* take lock off the deadlock detection hash list. */
		lock_res_and_lock(lock);
		ldlm_flock_blocking_unlink(lock);

		/* client side - set flag to prevent lock from being
		 * put on LRU list
		 */
		ldlm_set_cbpending(lock);
		unlock_res_and_lock(lock);

		LDLM_DEBUG(lock, "client-side enqueue waking up: failed (%d)",
			   rc);
		RETURN(rc);
	}

granted:
	OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_CP_CB_WAIT, 10);

	if (OBD_FAIL_PRECHECK(OBD_FAIL_LDLM_CP_CB_WAIT4)) {
		lock_res_and_lock(lock);
		/* DEADLOCK is always set with CBPENDING */
		lock->l_flags |= LDLM_FL_FLOCK_DEADLOCK | LDLM_FL_CBPENDING;
		unlock_res_and_lock(lock);
		OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_CP_CB_WAIT4, 4);
	}
	if (OBD_FAIL_PRECHECK(OBD_FAIL_LDLM_CP_CB_WAIT5)) {
		lock_res_and_lock(lock);
		/* DEADLOCK is always set with CBPENDING */
		lock->l_flags |= (LDLM_FL_FAIL_LOC |
				  LDLM_FL_FLOCK_DEADLOCK | LDLM_FL_CBPENDING);
		unlock_res_and_lock(lock);
		OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_CP_CB_WAIT5, 4);
	}

	lock_res_and_lock(lock);


	/* Protect against race where lock could have been just destroyed
	 * due to overlap in ldlm_process_flock_lock().
	 */
	if (ldlm_is_destroyed(lock)) {
		unlock_res_and_lock(lock);
		LDLM_DEBUG(lock, "client-side enqueue waking up: destroyed");

		/* An error is still to be returned, to propagate it up to
		 * ldlm_cli_enqueue_fini() caller. */
		RETURN(-EIO);
	}

	/* ldlm_lock_enqueue() has already placed lock on the granted list. */
	ldlm_resource_unlink_lock(lock);

	/* Import invalidation. We need to actually release the lock
	 * references being held, so that it can go away. No point in
	 * holding the lock even if app still believes it has it, since
	 * server already dropped it anyway. Only for granted locks too.
	 */
	/* Do the same for DEADLOCK'ed locks. */
	if (ldlm_is_failed(lock) || ldlm_is_flock_deadlock(lock)) {
		int mode;

		if (flags & LDLM_FL_TEST_LOCK)
			LASSERT(ldlm_is_test_lock(lock));

		if (ldlm_is_test_lock(lock) || ldlm_is_flock_deadlock(lock))
			mode = getlk->fl_type;
		else
			mode = lock->l_req_mode;

		if (ldlm_is_flock_deadlock(lock)) {
			LDLM_DEBUG(lock, "client-side enqueue deadlock "
				   "received");
			rc = -EDEADLK;
		}
		ldlm_flock_destroy(lock, mode, LDLM_FL_WAIT_NOREPROC);
		unlock_res_and_lock(lock);

		/* Need to wake up the waiter if we were evicted */
		wake_up(&lock->l_waitq);

		/* An error is still to be returned, to propagate it up to
		 * ldlm_cli_enqueue_fini() caller.
		 */
		RETURN(rc ? : -EIO);
	}

	LDLM_DEBUG(lock, "client-side enqueue granted");

	if (flags & LDLM_FL_TEST_LOCK) {
		/*
		 * fcntl(F_GETLK) request
		 * The old mode was saved in getlk->fl_type so that if the mode
		 * in the lock changes we can decref the appropriate refcount.
		 */
		LASSERT(ldlm_is_test_lock(lock));
		ldlm_flock_destroy(lock, getlk->fl_type, LDLM_FL_WAIT_NOREPROC);
		switch (lock->l_granted_mode) {
		case LCK_PR:
			getlk->fl_type = F_RDLCK;
			break;
		case LCK_PW:
			getlk->fl_type = F_WRLCK;
			break;
		default:
			getlk->fl_type = F_UNLCK;
		}
		getlk->fl_pid = (pid_t)lock->l_policy_data.l_flock.pid;
		getlk->fl_start = (loff_t)lock->l_policy_data.l_flock.start;
		getlk->fl_end = (loff_t)lock->l_policy_data.l_flock.end;
	} else {
		__u64 noreproc = LDLM_FL_WAIT_NOREPROC;

		/* We need to reprocess the lock to do merges or splits
		 * with existing locks owned by this process.
		 */
		ldlm_process_flock_lock(lock, &noreproc, 1, &err, NULL);
	}
	unlock_res_and_lock(lock);
	RETURN(rc);
}
EXPORT_SYMBOL(ldlm_flock_completion_ast);

int ldlm_flock_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
			    void *data, int flag)
{
	ENTRY;

	LASSERT(lock);
	LASSERT(flag == LDLM_CB_CANCELING);

	/* take lock off the deadlock detection hash list. */
	lock_res_and_lock(lock);
	ldlm_flock_blocking_unlink(lock);
	unlock_res_and_lock(lock);
	RETURN(0);
}

void ldlm_flock_policy_wire_to_local(const union ldlm_wire_policy_data *wpolicy,
				     union ldlm_policy_data *lpolicy)
{
	lpolicy->l_flock.start = wpolicy->l_flock.lfw_start;
	lpolicy->l_flock.end = wpolicy->l_flock.lfw_end;
	lpolicy->l_flock.pid = wpolicy->l_flock.lfw_pid;
	lpolicy->l_flock.owner = wpolicy->l_flock.lfw_owner;
}

void ldlm_flock_policy_local_to_wire(const union ldlm_policy_data *lpolicy,
				     union ldlm_wire_policy_data *wpolicy)
{
	memset(wpolicy, 0, sizeof(*wpolicy));
	wpolicy->l_flock.lfw_start = lpolicy->l_flock.start;
	wpolicy->l_flock.lfw_end = lpolicy->l_flock.end;
	wpolicy->l_flock.lfw_pid = lpolicy->l_flock.pid;
	wpolicy->l_flock.lfw_owner = lpolicy->l_flock.owner;
}

/*
 * Export handle<->flock hash operations.
 */
static unsigned
ldlm_export_flock_hash(struct cfs_hash *hs, const void *key, unsigned mask)
{
	return cfs_hash_u64_hash(*(__u64 *)key, mask);
}

static void *
ldlm_export_flock_key(struct hlist_node *hnode)
{
	struct ldlm_lock *lock;

	lock = hlist_entry(hnode, struct ldlm_lock, l_exp_flock_hash);
	return &lock->l_policy_data.l_flock.owner;
}

static int
ldlm_export_flock_keycmp(const void *key, struct hlist_node *hnode)
{
	return !memcmp(ldlm_export_flock_key(hnode), key, sizeof(__u64));
}

static void *
ldlm_export_flock_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct ldlm_lock, l_exp_flock_hash);
}

static void
ldlm_export_flock_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct ldlm_lock *lock;
	struct ldlm_flock *flock;

	lock = hlist_entry(hnode, struct ldlm_lock, l_exp_flock_hash);
	LDLM_LOCK_GET(lock);

	flock = &lock->l_policy_data.l_flock;
	LASSERT(flock->blocking_export != NULL);
	class_export_get(flock->blocking_export);
	atomic_inc(&flock->blocking_refs);
}

static void
ldlm_export_flock_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct ldlm_lock *lock;
	struct ldlm_flock *flock;

	lock = hlist_entry(hnode, struct ldlm_lock, l_exp_flock_hash);

	flock = &lock->l_policy_data.l_flock;
	LASSERT(flock->blocking_export != NULL);
	class_export_put(flock->blocking_export);
	if (atomic_dec_and_test(&flock->blocking_refs)) {
		flock->blocking_owner = 0;
		flock->blocking_export = NULL;
	}
	LDLM_LOCK_RELEASE(lock);
}

static struct cfs_hash_ops ldlm_export_flock_ops = {
	.hs_hash        = ldlm_export_flock_hash,
	.hs_key         = ldlm_export_flock_key,
	.hs_keycmp      = ldlm_export_flock_keycmp,
	.hs_object      = ldlm_export_flock_object,
	.hs_get         = ldlm_export_flock_get,
	.hs_put         = ldlm_export_flock_put,
	.hs_put_locked  = ldlm_export_flock_put,
};

int ldlm_init_flock_export(struct obd_export *exp)
{
	if( strcmp(exp->exp_obd->obd_type->typ_name, LUSTRE_MDT_NAME) != 0)
		RETURN(0);

	exp->exp_flock_hash =
		cfs_hash_create(obd_uuid2str(&exp->exp_client_uuid),
				HASH_EXP_LOCK_CUR_BITS,
				HASH_EXP_LOCK_MAX_BITS,
				HASH_EXP_LOCK_BKT_BITS, 0,
				CFS_HASH_MIN_THETA, CFS_HASH_MAX_THETA,
				&ldlm_export_flock_ops,
				CFS_HASH_DEFAULT | CFS_HASH_NBLK_CHANGE);
	if (!exp->exp_flock_hash)
		RETURN(-ENOMEM);

	RETURN(0);
}

void ldlm_destroy_flock_export(struct obd_export *exp)
{
	ENTRY;
	if (exp->exp_flock_hash) {
		cfs_hash_putref(exp->exp_flock_hash);
		exp->exp_flock_hash = NULL;
	}
	EXIT;
}
