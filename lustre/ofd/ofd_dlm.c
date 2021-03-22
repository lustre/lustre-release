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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ofd/ofd_dlm.c
 *
 * This file contains OBD Filter Device (OFD) LDLM-related code which is just
 * intent handling for glimpse lock.
 *
 * Author: Andreas Dilger <andreas.dilger@intel.com>
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

struct ofd_intent_args {
	struct list_head	gl_list;
	__u64			 size;
	bool			no_glimpse_ast;
	int			error;
};

/**
 * OFD interval callback.
 *
 * The interval_callback_t is part of interval_iterate_reverse() and is called
 * for each interval in tree. The OFD interval callback searches for locks
 * covering extents beyond the given args->size. This is used to decide if the
 * size is too small and needs to be updated.  Note that we are only interested
 * in growing the size, as truncate is the only operation which can shrink it,
 * and it is handled differently.  This is why we only look at locks beyond the
 * current size.
 *
 * It finds the highest lock (by starting point) in this interval, and adds it
 * to the list of locks to glimpse.  We must glimpse a list of locks - rather
 * than only the highest lock on the file - because lockahead creates extent
 * locks in advance of IO, and so breaks the assumption that the holder of the
 * highest lock knows the current file size.
 *
 * This assumption is normally true because locks which are created as part of
 * IO - rather than in advance of it - are guaranteed to be 'active', i.e.,
 * involved in IO, and the holder of the highest 'active' lock always knows the
 * current file size, because the size is either not changing or the holder of
 * that lock is responsible for updating it.
 *
 * So we need only glimpse until we find the first client with an 'active'
 * lock.
 *
 * Unfortunately, there is no way to know if a manually requested/speculative
 * lock is 'active' from the server side.  So when we see a potentially
 * speculative lock, we must send a glimpse for that lock unless we have
 * already sent a glimpse to the holder of that lock.
 *
 * However, *all* non-speculative locks are active.  So we can stop glimpsing
 * as soon as we find a non-speculative lock.  Currently, all speculative PW
 * locks have LDLM_FL_NO_EXPANSION set, and we use this to identify them.  This
 * is enforced by an assertion in osc_lock_init, which references this comment.
 *
 * If that ever changes, we will either need to find a new way to identify
 * active locks or we will need to consider all PW locks (we will still only
 * glimpse one per client).
 *
 * Note that it is safe to glimpse only the 'top' lock from each interval
 * because ofd_intent_cb is only called for PW extent locks, and for PW locks,
 * there is only one lock per interval.
 *
 * \param[in] n		interval node
 * \param[in,out] args	intent arguments, gl work list for identified locks
 *
 * \retval		INTERVAL_ITER_STOP if the interval is lower than
 *			file size, caller stops execution
 * \retval		INTERVAL_ITER_CONT if callback finished successfully
 *			and caller may continue execution
 */
static enum interval_iter ofd_intent_cb(struct interval_node *n, void *args)
{
	struct ldlm_interval	 *node = (struct ldlm_interval *)n;
	struct ofd_intent_args	 *arg = args;
	__u64			  size = arg->size;
	struct ldlm_lock	 *victim_lock = NULL;
	struct ldlm_lock	 *lck;
	struct ldlm_glimpse_work *gl_work = NULL;
	int rc = 0;

	/* If the interval is lower than the current file size, just break. */
	if (interval_high(n) <= size)
		GOTO(out, rc = INTERVAL_ITER_STOP);

	/* Find the 'victim' lock from this interval */
	list_for_each_entry(lck, &node->li_group, l_sl_policy) {
		victim_lock = LDLM_LOCK_GET(lck);

		/* the same policy group - every lock has the
		 * same extent, so needn't do it any more */
		break;
	}

	/* l_export can be null in race with eviction - In that case, we will
	 * not find any locks in this interval */
	if (!victim_lock)
		GOTO(out, rc = INTERVAL_ITER_CONT);

	/*
	 * This check is for lock taken in ofd_destroy_by_fid() that does
	 * not have l_glimpse_ast set. So the logic is: if there is a lock
	 * with no l_glimpse_ast set, this object is being destroyed already.
	 * Hence, if you are grabbing DLM locks on the server, always set
	 * non-NULL glimpse_ast (e.g., ldlm_request.c::ldlm_glimpse_ast()).
	 */
	if (victim_lock->l_glimpse_ast == NULL) {
		LDLM_DEBUG(victim_lock, "no l_glimpse_ast");
		arg->no_glimpse_ast = true;
		GOTO(out_release, rc = INTERVAL_ITER_STOP);
	}

	/* If NO_EXPANSION is not set, this is an active lock, and we don't need
	 * to glimpse any further once we've glimpsed the client holding this
	 * lock.  So set us up to stop.  See comment above this function. */
	if (!(victim_lock->l_flags & LDLM_FL_NO_EXPANSION))
		rc = INTERVAL_ITER_STOP;
	else
		rc = INTERVAL_ITER_CONT;

	/* Check to see if we're already set up to send a glimpse to this
	 * client; if so, don't add this lock to the glimpse list - We need
	 * only glimpse each client once. (And if we know that client holds
	 * an active lock, we can stop glimpsing.  So keep the rc set in the
	 * check above.) */
	list_for_each_entry(gl_work, &arg->gl_list, gl_list) {
		if (gl_work->gl_lock->l_export == victim_lock->l_export)
			GOTO(out_release, rc);
	}

	if (!OBD_FAIL_CHECK(OBD_FAIL_OST_GL_WORK_ALLOC))
		OBD_SLAB_ALLOC_PTR_GFP(gl_work, ldlm_glimpse_work_kmem,
				       GFP_ATOMIC);

	if (!gl_work) {
		arg->error = -ENOMEM;
		GOTO(out_release, rc = INTERVAL_ITER_STOP);
	}

	/* Populate the gl_work structure. */
	gl_work->gl_lock = victim_lock;
	list_add_tail(&gl_work->gl_list, &arg->gl_list);
	/* There is actually no need for a glimpse descriptor when glimpsing
	 * extent locks */
	gl_work->gl_desc = NULL;
	/* This tells ldlm_work_gl_ast_lock this was allocated from a slab and
	 * must be freed in a slab-aware manner. */
	gl_work->gl_flags = LDLM_GL_WORK_SLAB_ALLOCATED;

	GOTO(out, rc);

out_release:
	/* If the victim doesn't go on the glimpse list, we must release it */
	LDLM_LOCK_RELEASE(victim_lock);

out:
	return rc;
}
/**
 * OFD lock intent policy
 *
 * This defines ldlm_namespace::ns_policy interface for OFD.
 * Intent policy is called when lock has an intent, for OFD that
 * means glimpse lock and policy fills Lock Value Block (LVB).
 *
 * If already granted lock is found it will be placed in \a lockp and
 * returned back to caller function.
 *
 * \param[in] ns	 namespace
 * \param[in,out] lockp	 pointer to the lock
 * \param[in] req_cookie incoming request
 * \param[in] mode	 LDLM mode
 * \param[in] flags	 LDLM flags
 * \param[in] data	 opaque data, not used in OFD policy
 *
 * \retval		ELDLM_LOCK_REPLACED if already granted lock was found
 *			and placed in \a lockp
 * \retval		ELDLM_LOCK_ABORTED in other cases except error
 * \retval		negative errno on error
 */
int ofd_intent_policy(const struct lu_env *env, struct ldlm_namespace *ns,
		      struct ldlm_lock **lockp, void *req_cookie,
		      enum ldlm_mode mode, __u64 flags, void *data)
{
	struct ptlrpc_request *req = req_cookie;
	struct ldlm_lock *lock = *lockp;
	struct ldlm_resource *res = lock->l_resource;
	ldlm_processing_policy policy;
	struct ost_lvb *res_lvb, *reply_lvb;
	struct ldlm_reply *rep;
	enum ldlm_error err;
	int idx, rc;
	struct ldlm_interval_tree *tree;
	struct ofd_intent_args arg;
	__u32 repsize[3] = {
		[MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
		[DLM_LOCKREPLY_OFF]   = sizeof(*rep),
		[DLM_REPLY_REC_OFF]   = sizeof(*reply_lvb)
	};
	struct ldlm_glimpse_work *pos, *tmp;
	ENTRY;

	/* update stats for intent in intent policy */
	if (ptlrpc_req2svc(req)->srv_stats != NULL)
		lprocfs_counter_incr(ptlrpc_req2svc(req)->srv_stats,
				     PTLRPC_LAST_CNTR + LDLM_GLIMPSE_ENQUEUE);

	INIT_LIST_HEAD(&arg.gl_list);
	arg.no_glimpse_ast = false;
	arg.error = 0;
	lock->l_lvb_type = LVB_T_OST;
	policy = ldlm_get_processing_policy(res);
	LASSERT(policy != NULL);
	LASSERT(req != NULL);

	rc = lustre_pack_reply(req, 3, repsize, NULL);
	if (rc)
		RETURN(req->rq_status = rc);

	rep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF, sizeof(*rep));
	LASSERT(rep != NULL);

	reply_lvb = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF,
				   sizeof(*reply_lvb));
	LASSERT(reply_lvb != NULL);

	/* Call the extent policy function to see if our request can be
	 * granted, or is blocked.
	 * If the OST lock has LDLM_FL_HAS_INTENT set, it means a glimpse
	 * lock, and should not be granted if the lock will be blocked.
	 */

	if (flags & LDLM_FL_BLOCK_NOWAIT) {
		OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_AGL_DELAY, 5);

		if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_AGL_NOLOCK))
			RETURN(ELDLM_LOCK_ABORTED);
	}

	LASSERT(ns == ldlm_res_to_ns(res));
	lock_res(res);

	/* Check if this is a resend case (MSG_RESENT is set on RPC) and a
	 * lock was found by ldlm_handle_enqueue(); if so no need to grant
	 * it again. */
	if (flags & LDLM_FL_RESENT) {
		rc = LDLM_ITER_CONTINUE;
	} else {
		__u64 tmpflags = 0;
		rc = policy(lock, &tmpflags, LDLM_PROCESS_RESCAN, &err, NULL);
		check_res_locked(res);
	}

	/* The lock met with no resistance; we're finished. */
	if (rc == LDLM_ITER_CONTINUE) {
		if (OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_GLIMPSE, 2)) {
			ldlm_resource_unlink_lock(lock);
			err = ELDLM_LOCK_ABORTED;
		} else {
			err = ELDLM_LOCK_REPLACED;
		}
		unlock_res(res);
		RETURN(err);
	} else if (flags & LDLM_FL_BLOCK_NOWAIT) {
		/* LDLM_FL_BLOCK_NOWAIT means it is for AGL. Do not send glimpse
		 * callback for glimpse size. The real size user will trigger
		 * the glimpse callback when necessary. */
		unlock_res(res);
		RETURN(ELDLM_LOCK_ABORTED);
	}

	/* Do not grant any lock, but instead send GL callbacks.  The extent
	 * policy nicely created a list of all PW locks for us.  We will choose
	 * the highest of those which are larger than the size in the LVB, if
	 * any, and perform a glimpse callback. */
	res_lvb = res->lr_lvb_data;
	LASSERT(res_lvb != NULL);
	*reply_lvb = *res_lvb;

	/*
	 * ->ns_lock guarantees that no new locks are granted, and,
	 *  therefore, that res->lr_lvb_data cannot increase beyond the
	 *  end of already granted lock. As a result, it is safe to
	 *  check against "stale" reply_lvb->lvb_size value without
	 *  res->lr_lvb_sem.
	 */
	arg.size = reply_lvb->lvb_size;

	/* Check for PW locks beyond the size in the LVB, build the list
	 * of locks to glimpse (arg.gl_list) */
	for (idx = 0; idx < LCK_MODE_NUM; idx++) {
		tree = &res->lr_itree[idx];
		if (tree->lit_mode == LCK_PR)
			continue;

		interval_iterate_reverse(tree->lit_root, ofd_intent_cb, &arg);
		if (arg.error) {
			unlock_res(res);
			GOTO(out, rc = arg.error);
		}
	}
	unlock_res(res);

	/* There were no PW locks beyond the size in the LVB; finished. */
	if (list_empty(&arg.gl_list))
		RETURN(ELDLM_LOCK_ABORTED);

	if (arg.no_glimpse_ast) {
		/* We are racing with unlink(); just return -ENOENT */
		rep->lock_policy_res1 = ptlrpc_status_hton(-ENOENT);
		GOTO(out, ELDLM_LOCK_ABORTED);
	}

	/* this will update the LVB */
	ldlm_glimpse_locks(res, &arg.gl_list);

	lock_res(res);
	*reply_lvb = *res_lvb;
	unlock_res(res);

out:
	/* If the list is not empty, we failed to glimpse some locks and
	 * must clean up.  Usually due to a race with unlink.*/
	list_for_each_entry_safe(pos, tmp, &arg.gl_list, gl_list) {
		list_del(&pos->gl_list);
		LDLM_LOCK_RELEASE(pos->gl_lock);
		OBD_SLAB_FREE_PTR(pos, ldlm_glimpse_work_kmem);
	}

	RETURN(rc < 0 ? rc : ELDLM_LOCK_ABORTED);
}

