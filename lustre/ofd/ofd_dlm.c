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
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
	struct ldlm_lock	**victim;
	__u64			 size;
	int			*liblustre;
};

/**
 * OFD interval callback.
 *
 * The interval_callback_t is part of interval_iterate_reverse() and is called
 * for each interval in tree. The OFD interval callback searches for locks
 * covering extents beyond the given args->size. This is used to decide if LVB
 * data is outdated.
 *
 * \param[in] n		interval node
 * \param[in] args	intent arguments
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
	struct ldlm_lock	**v = arg->victim;
	struct ldlm_lock	 *lck;

	/* If the interval is lower than the current file size, just break. */
	if (interval_high(n) <= size)
		return INTERVAL_ITER_STOP;

	list_for_each_entry(lck, &node->li_group, l_sl_policy) {
		/* Don't send glimpse ASTs to liblustre clients.
		 * They aren't listening for them, and they do
		 * entirely synchronous I/O anyways. */
		if (lck->l_export == NULL || lck->l_export->exp_libclient)
			continue;

		if (*arg->liblustre)
			*arg->liblustre = 0;

		if (*v == NULL) {
			*v = LDLM_LOCK_GET(lck);
		} else if ((*v)->l_policy_data.l_extent.start <
			   lck->l_policy_data.l_extent.start) {
			LDLM_LOCK_RELEASE(*v);
			*v = LDLM_LOCK_GET(lck);
		}

		/* the same policy group - every lock has the
		 * same extent, so needn't do it any more */
		break;
	}

	return INTERVAL_ITER_CONT;
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
 * \retval		negative value on error
 */
int ofd_intent_policy(struct ldlm_namespace *ns, struct ldlm_lock **lockp,
		      void *req_cookie, enum ldlm_mode mode, __u64 flags,
		      void *data)
{
	struct ptlrpc_request *req = req_cookie;
	struct ldlm_lock *lock = *lockp, *l = NULL;
	struct ldlm_resource *res = lock->l_resource;
	ldlm_processing_policy policy;
	struct ost_lvb *res_lvb, *reply_lvb;
	struct ldlm_reply *rep;
	enum ldlm_error err;
	int idx, rc, only_liblustre = 1;
	struct ldlm_interval_tree *tree;
	struct ofd_intent_args arg;
	__u32 repsize[3] = {
		[MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
		[DLM_LOCKREPLY_OFF]   = sizeof(*rep),
		[DLM_REPLY_REC_OFF]   = sizeof(*reply_lvb)
	};
	struct ldlm_glimpse_work gl_work = {};
	struct list_head gl_list;
	ENTRY;

	INIT_LIST_HEAD(&gl_list);
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
		/* do not grant locks to the liblustre clients: they cannot
		 * handle ASTs robustly.  We need to do this while still
		 * holding ns_lock to avoid the lock remaining on the res_link
		 * list (and potentially being added to l_pending_list by an
		 * AST) when we are going to drop this lock ASAP. */
		if (lock->l_export->exp_libclient ||
		    OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_GLIMPSE, 2)) {
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
	arg.victim = &l;
	arg.liblustre = &only_liblustre;

	for (idx = 0; idx < LCK_MODE_NUM; idx++) {
		tree = &res->lr_itree[idx];
		if (tree->lit_mode == LCK_PR)
			continue;

		interval_iterate_reverse(tree->lit_root, ofd_intent_cb, &arg);
	}
	unlock_res(res);

	/* There were no PW locks beyond the size in the LVB; finished. */
	if (l == NULL) {
		if (only_liblustre) {
			/* If we discovered a liblustre client with a PW lock,
			 * however, the LVB may be out of date!  The LVB is
			 * updated only on glimpse (which we don't do for
			 * liblustre clients) and cancel (which the client
			 * obviously has not yet done).  So if it has written
			 * data but kept the lock, the LVB is stale and needs
			 * to be updated from disk.
			 *
			 * Of course, this will all disappear when we switch to
			 * taking liblustre locks on the OST. */
			ldlm_res_lvbo_update(res, NULL, 1);
		}
		RETURN(ELDLM_LOCK_ABORTED);
	}

	/*
	 * This check is for lock taken in ofd_destroy_by_fid() that does
	 * not have l_glimpse_ast set. So the logic is: if there is a lock
	 * with no l_glimpse_ast set, this object is being destroyed already.
	 * Hence, if you are grabbing DLM locks on the server, always set
	 * non-NULL glimpse_ast (e.g., ldlm_request.c::ldlm_glimpse_ast()).
	 */
	if (l->l_glimpse_ast == NULL) {
		/* We are racing with unlink(); just return -ENOENT */
		rep->lock_policy_res1 = ptlrpc_status_hton(-ENOENT);
		goto out;
	}

	/* Populate the gl_work structure.
	 * Grab additional reference on the lock which will be released in
	 * ldlm_work_gl_ast_lock() */
	gl_work.gl_lock = LDLM_LOCK_GET(l);
	/* The glimpse callback is sent to one single extent lock. As a result,
	 * the gl_work list is just composed of one element */
	list_add_tail(&gl_work.gl_list, &gl_list);
	/* There is actually no need for a glimpse descriptor when glimpsing
	 * extent locks */
	gl_work.gl_desc = NULL;
	/* the ldlm_glimpse_work structure is allocated on the stack */
	gl_work.gl_flags = LDLM_GL_WORK_NOFREE;

	rc = ldlm_glimpse_locks(res, &gl_list); /* this will update the LVB */

	if (!list_empty(&gl_list))
		LDLM_LOCK_RELEASE(l);

	lock_res(res);
	*reply_lvb = *res_lvb;
	unlock_res(res);

out:
	LDLM_LOCK_RELEASE(l);

	RETURN(ELDLM_LOCK_ABORTED);
}

