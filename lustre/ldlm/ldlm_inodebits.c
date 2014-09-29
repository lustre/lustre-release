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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
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
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <lustre_dlm.h>
#include <obd_support.h>
#include <lustre_lib.h>

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
ldlm_inodebits_compat_queue(cfs_list_t *queue, struct ldlm_lock *req,
                            cfs_list_t *work_list)
{
        cfs_list_t *tmp;
        struct ldlm_lock *lock;
        ldlm_mode_t req_mode = req->l_req_mode;
        __u64 req_bits = req->l_policy_data.l_inodebits.bits;
        int compat = 1;
        ENTRY;

        LASSERT(req_bits); /* There is no sense in lock with no bits set,
                              I think. Also such a lock would be compatible
                               with any other bit lock */

        cfs_list_for_each(tmp, queue) {
                cfs_list_t *mode_tail;

                lock = cfs_list_entry(tmp, struct ldlm_lock, l_res_link);

		/* We stop walking the queue if we hit ourselves so we don't
		 * take conflicting locks enqueued after us into account,
		 * or we'd wait forever. */
                if (req == lock)
                        RETURN(compat);

                /* last lock in mode group */
                LASSERT(lock->l_sl_mode.prev != NULL);
                mode_tail = &cfs_list_entry(lock->l_sl_mode.prev,
                                            struct ldlm_lock,
                                            l_sl_mode)->l_res_link;

                /* locks are compatible, bits don't matter */
                if (lockmode_compat(lock->l_req_mode, req_mode)) {
                        /* jump to last lock in mode group */
                        tmp = mode_tail;
                        continue;
                }

                for (;;) {
                        cfs_list_t *head;

			/* Advance loop cursor to last lock in policy group. */
			tmp = &cfs_list_entry(lock->l_sl_policy.prev,
					      struct ldlm_lock,
					      l_sl_policy)->l_res_link;

			/* Locks with overlapping bits conflict. */
			if (lock->l_policy_data.l_inodebits.bits & req_bits) {
				/* COS lock mode has a special compatibility
				 * requirement: it is only compatible with
				 * locks from the same client. */
				if (lock->l_req_mode == LCK_COS &&
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
                                cfs_list_for_each_entry(lock, head, l_sl_policy)
                                        if (lock->l_blocking_ast)
                                                ldlm_add_ast_work_item(lock, req,
                                                                       work_list);
                        }
                not_conflicting:
                        if (tmp == mode_tail)
                                break;

                        tmp = tmp->next;
                        lock = cfs_list_entry(tmp, struct ldlm_lock,
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
 *
 * If \a first_enq is 0 (ie, called from ldlm_reprocess_queue):
 *   - blocking ASTs have already been sent
 *
 * If \a first_enq is 1 (ie, called from ldlm_lock_enqueue):
 *   - blocking ASTs have not been sent yet, so list of conflicting locks
 *     would be collected and ASTs sent.
 */
int ldlm_process_inodebits_lock(struct ldlm_lock *lock, __u64 *flags,
                                int first_enq, ldlm_error_t *err,
                                cfs_list_t *work_list)
{
        struct ldlm_resource *res = lock->l_resource;
        CFS_LIST_HEAD(rpc_list);
        int rc;
        ENTRY;

	LASSERT(lock->l_granted_mode != lock->l_req_mode);
	LASSERT(cfs_list_empty(&res->lr_converting));
	check_res_locked(res);

	/* (*flags & LDLM_FL_BLOCK_NOWAIT) is for layout lock right now. */
        if (!first_enq || (*flags & LDLM_FL_BLOCK_NOWAIT)) {
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

 restart:
        rc = ldlm_inodebits_compat_queue(&res->lr_granted, lock, &rpc_list);
        rc += ldlm_inodebits_compat_queue(&res->lr_waiting, lock, &rpc_list);

        if (rc != 2) {
                /* If either of the compat_queue()s returned 0, then we
                 * have ASTs to send and must go onto the waiting list.
                 *
                 * bug 2322: we used to unlink and re-add here, which was a
                 * terrible folly -- if we goto restart, we could get
                 * re-ordered!  Causes deadlock, because ASTs aren't sent! */
                if (cfs_list_empty(&lock->l_res_link))
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                unlock_res(res);
                rc = ldlm_run_ast_work(ldlm_res_to_ns(res), &rpc_list,
                                       LDLM_WORK_BL_AST);
                lock_res(res);
                if (rc == -ERESTART)
                        GOTO(restart, -ERESTART);
                *flags |= LDLM_FL_BLOCK_GRANTED;
        } else {
                ldlm_resource_unlink_lock(lock);
                ldlm_grant_lock(lock, NULL);
        }
        RETURN(0);
}
#endif /* HAVE_SERVER_SUPPORT */

void ldlm_ibits_policy_wire_to_local(const ldlm_wire_policy_data_t *wpolicy,
                                     ldlm_policy_data_t *lpolicy)
{
        memset(lpolicy, 0, sizeof(*lpolicy));
        lpolicy->l_inodebits.bits = wpolicy->l_inodebits.bits;
}

void ldlm_ibits_policy_local_to_wire(const ldlm_policy_data_t *lpolicy,
                                     ldlm_wire_policy_data_t *wpolicy)
{
        memset(wpolicy, 0, sizeof(*wpolicy));
        wpolicy->l_inodebits.bits = lpolicy->l_inodebits.bits;
}
