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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_inodebits.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

/**
 * This file contains implementation of IBITS lock type
 *
 * IBITS lock type contains a bit mask determining various properties of an
 * object. The meanings of specific bits are specific to the caller and are
 * opaque to LDLM code.
 *
 * Locks with intersecting bitmasks and conflicting lock modes (e.g.  LCK_PW)
 * are considered conflicting.  See the lock mode compatibility matrix
 * in lustre_dlm.h.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <lustre_dlm.h>
#include <obd_support.h>
#include <lustre_lib.h>
#include <obd_class.h>

#include "ldlm_internal.h"

#ifdef HAVE_SERVER_SUPPORT
/**
 * Determine if the lock is compatible with all locks on the queue.
 *
 * If \a work_list is provided, conflicting locks are linked there.
 * If \a work_list is not provided, we exit this function on first conflict.
 *
 * \retval 0 if there are conflicting locks in the \a queue
 * \retval 1 if the lock is compatible to all locks in \a queue
 *
 * IBITS locks in granted queue are organized in bunches of
 * same-mode/same-bits locks called "skip lists". The First lock in the
 * bunch contains a pointer to the end of the bunch.  This allows us to
 * skip an entire bunch when iterating the list in search for conflicting
 * locks if first lock of the bunch is not conflicting with us.
 */
static int
ldlm_inodebits_compat_queue(struct list_head *queue, struct ldlm_lock *req,
			    struct list_head *work_list)
{
	struct list_head *tmp;
	struct ldlm_lock *lock;
	__u64 req_bits = req->l_policy_data.l_inodebits.bits;
	int compat = 1;
	ENTRY;

	/* There is no sense in lock with no bits set, I think.
	 * Also, such a lock would be compatible with any other bit lock */
	LASSERT(req_bits != 0);

	list_for_each(tmp, queue) {
		struct list_head *mode_tail;

		lock = list_entry(tmp, struct ldlm_lock, l_res_link);

		/* We stop walking the queue if we hit ourselves so we don't
		 * take conflicting locks enqueued after us into account,
		 * or we'd wait forever. */
		if (req == lock)
			RETURN(compat);

		/* last lock in mode group */
		LASSERT(lock->l_sl_mode.prev != NULL);
		mode_tail = &list_entry(lock->l_sl_mode.prev,
					struct ldlm_lock,
					l_sl_mode)->l_res_link;

		/* if reqest lock is not COS_INCOMPAT and COS is disabled,
		 * they are compatible, IOW this request is from a local
		 * transaction on a DNE system. */
		if (lock->l_req_mode == LCK_COS && !ldlm_is_cos_incompat(req) &&
		    !ldlm_is_cos_enabled(req)) {
			/* jump to last lock in mode group */
			tmp = mode_tail;
			continue;
		}

		/* locks' mode are compatible, bits don't matter */
		if (lockmode_compat(lock->l_req_mode, req->l_req_mode)) {
			/* jump to last lock in mode group */
			tmp = mode_tail;
			continue;
		}

		for (;;) {
			struct list_head *head;

			/* Advance loop cursor to last lock in policy group. */
			tmp = &list_entry(lock->l_sl_policy.prev,
					      struct ldlm_lock,
					      l_sl_policy)->l_res_link;

			/* Locks with overlapping bits conflict. */
			if (lock->l_policy_data.l_inodebits.bits & req_bits) {
				/* COS lock mode has a special compatibility
				 * requirement: it is only compatible with
				 * locks from the same client. */
				if (lock->l_req_mode == LCK_COS &&
				    !ldlm_is_cos_incompat(req) &&
				    ldlm_is_cos_enabled(req) &&
				    lock->l_client_cookie == req->l_client_cookie)
					goto not_conflicting;
				/* Found a conflicting policy group. */
				if (!work_list)
					RETURN(0);

				compat = 0;

				/* Add locks of the policy group to @work_list
				 * as blocking locks for @req */
                                if (lock->l_blocking_ast)
                                        ldlm_add_ast_work_item(lock, req,
                                                               work_list);
                                head = &lock->l_sl_policy;
				list_for_each_entry(lock, head, l_sl_policy)
                                        if (lock->l_blocking_ast)
                                                ldlm_add_ast_work_item(lock, req,
                                                                       work_list);
                        }
                not_conflicting:
                        if (tmp == mode_tail)
                                break;

                        tmp = tmp->next;
			lock = list_entry(tmp, struct ldlm_lock,
                                              l_res_link);
		} /* Loop over policy groups within one mode group. */
	} /* Loop over mode groups within @queue. */

	RETURN(compat);
}

/**
 * Process a granting attempt for IBITS lock.
 * Must be called with ns lock held
 *
 * This function looks for any conflicts for \a lock in the granted or
 * waiting queues. The lock is granted if no conflicts are found in
 * either queue.
 */
int ldlm_process_inodebits_lock(struct ldlm_lock *lock, __u64 *flags,
				enum ldlm_process_intention intention,
				enum ldlm_error *err,
				struct list_head *work_list)
{
	struct ldlm_resource *res = lock->l_resource;
	struct list_head rpc_list;
	int rc;
	ENTRY;

	LASSERT(lock->l_granted_mode != lock->l_req_mode);
	LASSERT(list_empty(&res->lr_converting));
	INIT_LIST_HEAD(&rpc_list);
	check_res_locked(res);

	/* (*flags & LDLM_FL_BLOCK_NOWAIT) is for layout lock right now. */
	if (intention == LDLM_PROCESS_RESCAN ||
	    (*flags & LDLM_FL_BLOCK_NOWAIT)) {
		*err = ELDLM_LOCK_ABORTED;
		if (*flags & LDLM_FL_BLOCK_NOWAIT)
			*err = ELDLM_LOCK_WOULDBLOCK;

                rc = ldlm_inodebits_compat_queue(&res->lr_granted, lock, NULL);
                if (!rc)
                        RETURN(LDLM_ITER_STOP);
                rc = ldlm_inodebits_compat_queue(&res->lr_waiting, lock, NULL);
                if (!rc)
                        RETURN(LDLM_ITER_STOP);

                ldlm_resource_unlink_lock(lock);
                ldlm_grant_lock(lock, work_list);

		*err = ELDLM_OK;
		RETURN(LDLM_ITER_CONTINUE);
	}

	LASSERT((intention == LDLM_PROCESS_ENQUEUE && work_list == NULL) ||
		(intention == LDLM_PROCESS_RECOVERY && work_list != NULL));
 restart:
        rc = ldlm_inodebits_compat_queue(&res->lr_granted, lock, &rpc_list);
        rc += ldlm_inodebits_compat_queue(&res->lr_waiting, lock, &rpc_list);

        if (rc != 2) {
		rc = ldlm_handle_conflict_lock(lock, flags, &rpc_list, 0);
		if (rc == -ERESTART)
			GOTO(restart, rc);
		*err = rc;
	} else {
		ldlm_resource_unlink_lock(lock);
		ldlm_grant_lock(lock, work_list);
		rc = 0;
	}

	if (!list_empty(&rpc_list))
		ldlm_discard_bl_list(&rpc_list);

	RETURN(rc);
}
#endif /* HAVE_SERVER_SUPPORT */

void ldlm_ibits_policy_wire_to_local(const union ldlm_wire_policy_data *wpolicy,
				     union ldlm_policy_data *lpolicy)
{
	lpolicy->l_inodebits.bits = wpolicy->l_inodebits.bits;
}

void ldlm_ibits_policy_local_to_wire(const union ldlm_policy_data *lpolicy,
				     union ldlm_wire_policy_data *wpolicy)
{
	memset(wpolicy, 0, sizeof(*wpolicy));
	wpolicy->l_inodebits.bits = lpolicy->l_inodebits.bits;
}
