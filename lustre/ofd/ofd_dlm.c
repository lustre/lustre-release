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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_dlm.c
 *
 * Author: Mike Pershin <tappro@whamcloud.com>
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

struct ofd_intent_args {
	struct ldlm_lock	**victim;
	__u64			 size;
	int			*liblustre;
};

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

	cfs_list_for_each_entry(lck, &node->li_group, l_sl_policy) {
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

int ofd_intent_policy(struct ldlm_namespace *ns, struct ldlm_lock **lockp,
		      void *req_cookie, ldlm_mode_t mode, __u64 flags,
		      void *data)
{
	struct ptlrpc_request		*req = req_cookie;
	struct ldlm_lock		*lock = *lockp, *l = NULL;
	struct ldlm_resource		*res = lock->l_resource;
	ldlm_processing_policy		 policy;
	struct ost_lvb			*res_lvb, *reply_lvb;
	struct ldlm_reply		*rep;
	ldlm_error_t			 err;
	int				 idx, rc, only_liblustre = 1;
	struct ldlm_interval_tree	*tree;
	struct ofd_intent_args		 arg;
	__u32				 repsize[3] = {
		[MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
		[DLM_LOCKREPLY_OFF]   = sizeof(*rep),
		[DLM_REPLY_REC_OFF]   = sizeof(*reply_lvb)
	};
	struct ldlm_glimpse_work	 gl_work;
	CFS_LIST_HEAD(gl_list);
	ENTRY;

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
		rc = policy(lock, &tmpflags, 0, &err, NULL);
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
	 * This check is for lock taken in ofd_prepare_destroy() that does
	 * not have l_glimpse_ast set. So the logic is: if there is a lock
	 * with no l_glimpse_ast set, this object is being destroyed already.
	 * Hence, if you are grabbing DLM locks on the server, always set
	 * non-NULL glimpse_ast (e.g., ldlm_request.c:ldlm_glimpse_ast()).
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
	cfs_list_add_tail(&gl_work.gl_list, &gl_list);
	/* There is actually no need for a glimpse descriptor when glimpsing
	 * extent locks */
	gl_work.gl_desc = NULL;
	/* the ldlm_glimpse_work structure is allocated on the stack */
	gl_work.gl_flags = LDLM_GL_WORK_NOFREE;

	rc = ldlm_glimpse_locks(res, &gl_list); /* this will update the LVB */

	if (!cfs_list_empty(&gl_list))
		LDLM_LOCK_RELEASE(l);

	lock_res(res);
	*reply_lvb = *res_lvb;
	unlock_res(res);

out:
	LDLM_LOCK_RELEASE(l);

	RETURN(ELDLM_LOCK_ABORTED);
}

