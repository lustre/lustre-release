/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_LDLM

#ifdef __KERNEL__
#include <linux/lustre_dlm.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#else
#include <liblustre.h>
#endif

static inline int
ldlm_same_flock_owner(struct ldlm_lock *lock, struct ldlm_lock *new)
{
        if ((new->l_data.l_flock.pid == lock->l_data.l_flock.pid) &&
            (new->l_export == lock->l_export))
                return 1;
        else
                return 0;
}

static inline int
ldlm_flocks_overlap(struct ldlm_lock *lock, struct ldlm_lock *new)
{
        if ((new->l_data.l_flock.start <= lock->l_data.l_flock.end) &&
            (new->l_data.l_flock.end >= lock->l_data.l_flock.start))
                return 1;
        else
                return 0;
}

static inline void
ldlm_flock_destroy(struct ldlm_lock *lock, int flags)
{
        ENTRY;

        list_del_init(&lock->l_res_link);
        if (flags == LDLM_FL_WAIT_NOREPROC) {
                /* client side */
                struct lustre_handle lockh;

                /* Set a flag to prevent us from sending a CANCEL */
                lock->l_flags |= LDLM_FL_LOCAL_ONLY;

                ldlm_lock2handle(lock, &lockh);
                ldlm_lock_decref_and_cancel(&lockh, lock->l_granted_mode);
        }

        ldlm_lock_destroy(lock);
        EXIT;
}

int
ldlm_flock_enqueue(struct ldlm_lock **reqp, void *req_cookie, int *flags,
                   int first_enq, ldlm_error_t *err)
{
        struct ldlm_lock *req = *reqp;
        struct ldlm_lock *new = req;
        struct ldlm_lock *new2 = NULL;
        struct ldlm_lock *lock = NULL;
        struct ldlm_resource *res = req->l_resource;
        struct ldlm_namespace *ns = res->lr_namespace;
        struct list_head *tmp;
        struct list_head *ownlocks;
        ldlm_mode_t mode = req->l_req_mode;
        int added = 0;
        int overlaps = 0;
        ENTRY;

        CDEBUG(D_DLMTRACE, "flags: 0x%x pid: %d mode: %d start: %llu "
               "end: %llu\n", *flags, new->l_data.l_flock.pid, mode,
               req->l_data.l_flock.start, req->l_data.l_flock.end);

        *err = ELDLM_OK;

        /* No blocking ASTs are sent for record locks */
        req->l_blocking_ast = NULL;

        ownlocks = NULL;
	if ((*flags == LDLM_FL_WAIT_NOREPROC) || (mode == LCK_NL)) {
                list_for_each(tmp, &res->lr_granted) {
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                        if (ldlm_same_flock_owner(lock, req)) {
                                ownlocks = tmp;
                                break;
                        }
                }
        } else {
                list_for_each(tmp, &res->lr_granted) {
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);

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

                        if (*flags & LDLM_FL_BLOCK_NOWAIT) {
                                ldlm_flock_destroy(req, *flags);
                                *err = ELDLM_LOCK_ABORTED;
                                RETURN(LDLM_ITER_STOP);
                        }

                        if (*flags & LDLM_FL_TEST_LOCK) {
                                req->l_granted_mode = lock->l_granted_mode;
                                req->l_data.l_flock.pid =
                                        lock->l_data.l_flock.pid;
                                req->l_data.l_flock.start =
                                        lock->l_data.l_flock.start;
                                req->l_data.l_flock.end =
                                        lock->l_data.l_flock.end;
                                ldlm_flock_destroy(req, *flags);
                                RETURN(LDLM_ITER_STOP);
                        }

                        if (first_enq) {
                                /* XXX - add deadlock detection check here */
                        }

                        *flags |= LDLM_FL_BLOCK_GRANTED;
                        RETURN(LDLM_ITER_CONTINUE);
                }
        }

        if (*flags & LDLM_FL_TEST_LOCK) {
                LASSERT(first_enq);
                req->l_granted_mode = req->l_req_mode;
                RETURN(LDLM_ITER_STOP);
        }

        added = (mode == LCK_NL);

        /* Insert the new lock into the list */

        if (!ownlocks)
                ownlocks = &res->lr_granted;

        for (tmp = ownlocks->next; ownlocks != &res->lr_granted;
             ownlocks = tmp, tmp = ownlocks->next) {
                lock = list_entry(ownlocks, struct ldlm_lock, l_res_link);

                if (!ldlm_same_flock_owner(lock, new))
                        break;

		if (lock->l_granted_mode == mode) {
			if (lock->l_data.l_flock.end <
                            (new->l_data.l_flock.start - 1))
				continue;

			if (lock->l_data.l_flock.start >
                            (new->l_data.l_flock.end + 1))
				break;

			if (lock->l_data.l_flock.start >
                            new->l_data.l_flock.start)
				lock->l_data.l_flock.start =
                                        new->l_data.l_flock.start;
			else
				new->l_data.l_flock.start =
                                        lock->l_data.l_flock.start;

			if (lock->l_data.l_flock.end <
                            new->l_data.l_flock.end)
				lock->l_data.l_flock.end =
                                        new->l_data.l_flock.end;
			else
				new->l_data.l_flock.end =
                                        lock->l_data.l_flock.end;

			if (added) {
                                ldlm_flock_destroy(lock, *flags);
			} else {
                                new = lock;
                                added = 1;
                        }
                        continue;
		}

                if (lock->l_data.l_flock.end < new->l_data.l_flock.start)
                        continue;
                if (lock->l_data.l_flock.start > new->l_data.l_flock.end)
                        break;

                ++overlaps;

                if (new->l_data.l_flock.start <=
                    lock->l_data.l_flock.start) {
                        if (new->l_data.l_flock.end <
                            lock->l_data.l_flock.end) {
                                lock->l_data.l_flock.start =
                                        new->l_data.l_flock.end + 1;
                                break;
                        } else if (added) {
                                ldlm_flock_destroy(lock, *flags);
                        } else {
                                lock->l_data.l_flock.start =
                                        new->l_data.l_flock.start;
                                lock->l_data.l_flock.end =
                                        new->l_data.l_flock.end;
                                new = lock;
                                added = 1;
                        }
                        continue;
                }
                if (new->l_data.l_flock.end >= lock->l_data.l_flock.end) {
                        lock->l_data.l_flock.end =
                                new->l_data.l_flock.start - 1;
                        continue;
                }

                /* split the existing lock into two locks */

                /* if this is an F_UNLCK operation then we could avoid
                 * allocating a new lock and use the req lock passed in
                 * with the request but this would complicate the reply
                 * processing since updates to req get reflected in the
                 * reply. The client side must see the original lock data
                 * so that it can process the unlock properly. */

                /* XXX - if ldlm_lock_new() can sleep we have to
                 * release the ns_lock, allocate the new lock, and
                 * restart processing this lock. */
                new2 = ldlm_lock_create(ns, NULL, res->lr_name, LDLM_FLOCK,
                                        lock->l_granted_mode, NULL, NULL);
                if (!new2) {
                        /* LBUG for now */
                        LASSERT(0);
                        RETURN(ENOMEM);
                }

                new2->l_granted_mode = lock->l_granted_mode;
                new2->l_data.l_flock.pid = new->l_data.l_flock.pid;
                new2->l_data.l_flock.start = lock->l_data.l_flock.start;
                new2->l_data.l_flock.end = new->l_data.l_flock.start - 1;
                lock->l_data.l_flock.start = new->l_data.l_flock.end + 1;
                new2->l_connh = lock->l_connh;
                if ((new2->l_export = lock->l_export) != NULL) {
                        list_add(&new2->l_export_chain,
                                 &new2->l_export->
                                 exp_ldlm_data.led_held_locks);
                }
                if (*flags == LDLM_FL_WAIT_NOREPROC) {
                        /* client side */
                        ldlm_lock_addref_internal(new2, lock->l_granted_mode);
                }

                /* insert new2 at lock */
                list_add_tail(&new2->l_res_link, ownlocks);
                LDLM_LOCK_PUT(new2);
                break;
        }

        if (added) {
                ldlm_flock_destroy(req, *flags);
        } else {
                /* insert new at ownlocks */
                new->l_granted_mode = new->l_req_mode;
                list_del_init(&new->l_res_link);
                list_add_tail(&new->l_res_link, ownlocks);
        }

	if (*flags != LDLM_FL_WAIT_NOREPROC) {
                if (req->l_completion_ast)
                        ldlm_add_ast_work_item(req, NULL, NULL, 0);

                /* The only problem with doing the reprocessing here is that
                 * the completion ASTs for newly granted locks will be sent
                 * before the unlock completion is sent. It shouldn't be an
                 * issue. Also note that ldlm_flock_enqueue() will recurse,
                 * but only once because there can't be unlock requests on
                 * the wait queue. */
                if ((mode == LCK_NL) && overlaps)
                        ldlm_reprocess_queue(res, &res->lr_waiting);
        }

        ldlm_resource_dump(res);

	RETURN(LDLM_ITER_CONTINUE);
}

static void interrupted_flock_completion_wait(void *data)
{
}

struct flock_wait_data {
        struct ldlm_lock *fwd_lock;
        int               fwd_generation;
};

int
ldlm_flock_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        struct ldlm_namespace *ns;
        struct file_lock *getlk = data;
        struct flock_wait_data fwd;
        unsigned long irqflags;
        struct obd_device *obd;
        struct obd_import *imp = NULL;
        ldlm_error_t err;
        int rc = 0;
        struct l_wait_info lwi;
        ENTRY;

        LASSERT(flags != LDLM_FL_WAIT_NOREPROC);

        if (flags == 0) {
                wake_up(&lock->l_waitq);
                RETURN(0);
        }

        if (!(flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                       LDLM_FL_BLOCK_CONV)))
                goto  granted;

        LDLM_DEBUG(lock, "client-side enqueue returned a blocked lock, "
                   "sleeping");

        ldlm_lock_dump(D_OTHER, lock);

        fwd.fwd_lock = lock;
        obd = class_conn2obd(lock->l_connh);

        /* if this is a local lock, then there is no import */
        if (obd != NULL)
                imp = obd->u.cli.cl_import;

        if (imp != NULL) {
                spin_lock_irqsave(&imp->imp_lock, irqflags);
                fwd.fwd_generation = imp->imp_generation;
                spin_unlock_irqrestore(&imp->imp_lock, irqflags);
        }

        lwi = LWI_TIMEOUT_INTR(0, NULL, interrupted_flock_completion_wait,
                               &fwd);

        /* Go to sleep until the lock is granted. */
        rc = l_wait_event(lock->l_waitq,
                          ((lock->l_req_mode == lock->l_granted_mode) ||
                           lock->l_destroyed), &lwi);

        LASSERT(!(lock->l_destroyed));

        if (rc) {
                LDLM_DEBUG(lock, "client-side enqueue waking up: failed (%d)",
                           rc);
                RETURN(rc);
        }

granted:

        LDLM_DEBUG(lock, "client-side enqueue waking up");
        ns = lock->l_resource->lr_namespace;
        l_lock(&ns->ns_lock);

        /* ldlm_lock_enqueue() has already placed lock on the granted list. */
        list_del_init(&lock->l_res_link);

        if (getlk) {
                /* fcntl(F_GETLK) request */
                if (lock->l_granted_mode == LCK_PR)
                        getlk->fl_type = F_RDLCK;
                else if (lock->l_granted_mode == LCK_PW)
                        getlk->fl_type = F_WRLCK;
                else
                        getlk->fl_type = F_UNLCK;
                getlk->fl_pid = lock->l_data.l_flock.pid;
                getlk->fl_start = lock->l_data.l_flock.start;
                getlk->fl_end = lock->l_data.l_flock.end;
                /* ldlm_flock_destroy(lock); */
        } else {
                flags = LDLM_FL_WAIT_NOREPROC;
                /* We need to reprocess the lock to do merges or split */
                ldlm_flock_enqueue(&lock, NULL, &flags, 1, &err);
        }
        l_unlock(&ns->ns_lock);
        RETURN(0);
}

/* This function is only called on the client when a lock is aborted. */
int
ldlm_flock_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *ld,
                        void *data, int flag)
{
        ENTRY;
        ldlm_lock_destroy(lock);
        RETURN(0);
}
