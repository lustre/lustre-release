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

/*
 * 2003 - 2005 Copyright, Hewlett-Packard Development Compnay, LP.
 *
 * Developed under the sponsorship of the U.S. Government
 *     under Subcontract No. B514193
 */

#define DEBUG_SUBSYSTEM S_LDLM

#ifdef __KERNEL__
#include <linux/lustre_dlm.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <libcfs/list.h>
#else
#include <liblustre.h>
#endif

#include "ldlm_internal.h"

static struct list_head ldlm_flock_waitq = LIST_HEAD_INIT(ldlm_flock_waitq);
static int ldlm_deadlock_timeout = 30 * HZ;

/**
 * list_for_remaining_safe - iterate over the remaining entries in a list
 *              and safeguard against removal of a list entry.
 * @pos:        the &struct list_head to use as a loop counter. pos MUST
 *              have been initialized prior to using it in this macro.
 * @n:          another &struct list_head to use as temporary storage
 * @head:       the head for your list.
 */
#define list_for_remaining_safe(pos, n, head) \
        for (n = pos->next; pos != (head); pos = n, n = pos->next)

static inline int
ldlm_same_flock_owner(struct ldlm_lock *lock, struct ldlm_lock *new)
{
        return((new->l_policy_data.l_flock.pid ==
                lock->l_policy_data.l_flock.pid) &&
               (new->l_policy_data.l_flock.nid ==
                lock->l_policy_data.l_flock.nid));
}

static inline int
ldlm_flocks_overlap(struct ldlm_lock *lock, struct ldlm_lock *new)
{
        return((new->l_policy_data.l_flock.start <=
                lock->l_policy_data.l_flock.end) &&
               (new->l_policy_data.l_flock.end >=
                lock->l_policy_data.l_flock.start));
}

static inline void
ldlm_flock_destroy(struct ldlm_lock *lock, ldlm_mode_t mode, int flags)
{
        ENTRY;

        LDLM_DEBUG(lock, "ldlm_flock_destroy(mode: %d, flags: 0x%x)",
                   mode, flags);

        /* don't need to take the locks here because the lock
         * is on a local destroy list, not the resource list. */
        list_del_init(&lock->l_res_link);

        if (flags == LDLM_FL_WAIT_NOREPROC) {
                /* client side - set flags to prevent sending a CANCEL */
                lock->l_flags |= LDLM_FL_LOCAL_ONLY | LDLM_FL_CBPENDING;
                ldlm_lock_decref_internal(lock, mode);
        }

        ldlm_lock_destroy(lock);
        EXIT;
}

int
ldlm_process_flock_lock(struct ldlm_lock *req, int *flags, int first_enq,
                        ldlm_error_t *err, struct list_head *work_list)
{
        struct list_head destroy_list = LIST_HEAD_INIT(destroy_list);
        struct ldlm_resource *res = req->l_resource;
        struct ldlm_namespace *ns = res->lr_namespace;
        struct list_head *pos;
        struct list_head *tmp = NULL;
        struct ldlm_lock *lock;
        struct ldlm_lock *new = req;
        struct ldlm_lock *new2;
        ldlm_mode_t mode = req->l_req_mode;
        int added = (mode == LCK_NL);
        int overlaps = 0;
        int rc = LDLM_ITER_CONTINUE;
        int i = 0;
        ENTRY;

        CDEBUG(D_DLMTRACE, "flags %#x mode %u pid "LPU64" nid "LPU64" "
               "start "LPU64" end "LPU64"\n", *flags, mode,
               req->l_policy_data.l_flock.pid, 
               req->l_policy_data.l_flock.nid, 
	       req->l_policy_data.l_flock.start,
               req->l_policy_data.l_flock.end);

        *err = ELDLM_OK;

        /* No blocking ASTs are sent for Posix file & record locks */
        req->l_blocking_ast = NULL;

        if ((*flags == LDLM_FL_WAIT_NOREPROC) || (mode == LCK_NL)) {
                /* This loop determines where this processes locks start
                 * in the resource lr_granted list. */
                list_for_each(pos, &res->lr_granted) {
                        lock = list_entry(pos, struct ldlm_lock, l_res_link);
                        if (ldlm_same_flock_owner(lock, req)) {
                                tmp = pos;
                                break;
                        }
                }
        } else {
                lockmode_verify(mode);

                /* This loop determines if there are existing locks
                 * that conflict with the new lock request. */
                list_for_each(pos, &res->lr_granted) {
                        lock = list_entry(pos, struct ldlm_lock, l_res_link);

                        if (ldlm_same_flock_owner(lock, req)) {
                                if (!tmp)
                                        tmp = pos;
                                continue;
                        }

                        /* locks are compatible, overlap doesn't matter */
                        if (lockmode_compat(lock->l_granted_mode, mode))
                                continue;

                        if (!ldlm_flocks_overlap(lock, req))
                                continue;

                        /* deadlock detection will be done will be postponed
                         * until ldlm_flock_completion_ast(). */

                        *flags |= LDLM_FL_LOCK_CHANGED;

                        req->l_policy_data.l_flock.blocking_pid =
                                lock->l_policy_data.l_flock.pid;
                        req->l_policy_data.l_flock.blocking_nid =
                                lock->l_policy_data.l_flock.nid;

                        if (!first_enq)
                                RETURN(LDLM_ITER_CONTINUE);

                        if (*flags & LDLM_FL_BLOCK_NOWAIT) {
                                list_move(&req->l_res_link, &destroy_list);
                                *err = -EAGAIN;
                                GOTO(out, rc = LDLM_ITER_STOP);
                        }

                        if (*flags & LDLM_FL_TEST_LOCK) {
                                req->l_req_mode = lock->l_granted_mode;
                                req->l_policy_data.l_flock.pid =
                                        lock->l_policy_data.l_flock.pid;
                                req->l_policy_data.l_flock.nid =
                                        lock->l_policy_data.l_flock.nid;
                                req->l_policy_data.l_flock.start =
                                        lock->l_policy_data.l_flock.start;
                                req->l_policy_data.l_flock.end =
                                        lock->l_policy_data.l_flock.end;
                                list_move(&req->l_res_link, &destroy_list);
                                GOTO(out, rc = LDLM_ITER_STOP);
                        }

                        ldlm_resource_add_lock(res, &res->lr_waiting, req);
                        *flags |= LDLM_FL_BLOCK_GRANTED;
                        RETURN(LDLM_ITER_STOP);
                }
        }

        if (*flags & LDLM_FL_TEST_LOCK) {
                req->l_req_mode = LCK_NL;
                *flags |= LDLM_FL_LOCK_CHANGED;
                list_move(&req->l_res_link, &destroy_list);
                GOTO(out, rc = LDLM_ITER_STOP);
        }

        /* Scan the locks owned by this process that overlap this request.
         * We may have to merge or split existing locks. */
        pos = (tmp != NULL) ? tmp : &res->lr_granted;

        list_for_remaining_safe(pos, tmp, &res->lr_granted) {
                lock = list_entry(pos, struct ldlm_lock, l_res_link);

                if (!ldlm_same_flock_owner(lock, new))
                        break;

                if (lock->l_granted_mode == mode) {
                        /* If the modes are the same then we need to process
                         * locks that overlap OR adjoin the new lock. The extra
                         * logic condition is necessary to deal with arithmetic
                         * overflow and underflow. */
                        if ((new->l_policy_data.l_flock.start >
                             (lock->l_policy_data.l_flock.end + 1))
                            && (lock->l_policy_data.l_flock.end != ~0))
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
                                list_move(&lock->l_res_link, &destroy_list);
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
                        list_move(&lock->l_res_link, &destroy_list);
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
                 * it must see the original lock data in the reply. */

                /* XXX - if ldlm_lock_new() can sleep we should
                 * release the ns_lock, allocate the new lock,
                 * and restart processing this lock. */
                new2 = ldlm_lock_create(ns, NULL, res->lr_name, LDLM_FLOCK,
                                        lock->l_granted_mode, NULL, NULL, NULL,
                                        NULL, 0);
                if (!new2) {
                        list_move(&req->l_res_link, &destroy_list);
                        *err = -ENOLCK;
                        GOTO(out, rc = LDLM_ITER_STOP);
                }

                new2->l_granted_mode = lock->l_granted_mode;
                new2->l_policy_data.l_flock.pid =
                        new->l_policy_data.l_flock.pid;
                new2->l_policy_data.l_flock.nid =
                        new->l_policy_data.l_flock.nid;
                new2->l_policy_data.l_flock.start =
                        lock->l_policy_data.l_flock.start;
                new2->l_policy_data.l_flock.end =
                        new->l_policy_data.l_flock.start - 1;
                lock->l_policy_data.l_flock.start =
                        new->l_policy_data.l_flock.end + 1;
                new2->l_conn_export = lock->l_conn_export;
                if (lock->l_export != NULL) {
                        new2->l_export = class_export_get(lock->l_export);
                        list_add(&new2->l_export_chain,
                                 &new2->l_export->exp_ldlm_data.led_held_locks);
                }
                if (*flags == LDLM_FL_WAIT_NOREPROC)
                        ldlm_lock_addref_internal_nolock(new2,
                                                         lock->l_granted_mode);

                /* insert new2 at lock */
                ldlm_resource_add_lock(res, pos, new2);
                LDLM_LOCK_PUT(new2);
                break;
        }

        /* At this point we're granting the lock request. */
        req->l_granted_mode = req->l_req_mode;

        if (added) {
                list_move(&req->l_res_link, &destroy_list);
        } else {
                /* Add req to the granted queue before calling
                 * ldlm_reprocess_all() below. */
                list_del_init(&req->l_res_link);
                /* insert new lock before pos in the list. */
                ldlm_resource_add_lock(res, pos, req);
        }

        if (*flags != LDLM_FL_WAIT_NOREPROC) {
                if (first_enq) {
                        /* If this is an unlock, reprocess the waitq and
                         * send completions ASTs for locks that can now be 
                         * granted. The only problem with doing this
                         * reprocessing here is that the completion ASTs for
                         * newly granted locks will be sent before the unlock
                         * completion is sent. It shouldn't be an issue. Also
                         * note that ldlm_process_flock_lock() will recurse,
                         * but only once because first_enq will be false from
                         * ldlm_reprocess_queue. */
                        if ((mode == LCK_NL) && overlaps) {
                                struct list_head rpc_list =
                                                     LIST_HEAD_INIT(rpc_list);
                                int rc;
 restart:
                                ldlm_reprocess_queue(res, &res->lr_waiting,
                                                     &rpc_list);
                                unlock_res(res);
                                rc = ldlm_run_cp_ast_work(&rpc_list);
                                lock_res(res);
                                if (rc == -ERESTART)
                                        GOTO(restart, -ERESTART);
                       }
                } else {
                        LASSERT(req->l_completion_ast);
                        ldlm_add_ast_work_item(req, NULL, work_list);
                }
        }

 out:
        if (!list_empty(&destroy_list)) {
                /* FIXME: major hack. when called from ldlm_lock_enqueue()
                 * the res and the lock are locked. When called from
                 * ldlm_reprocess_queue() the res is locked but the lock
                 * is not. */
                if (added && first_enq && res->lr_namespace->ns_client)
                        unlock_bitlock(req);

                unlock_res(res);

                CDEBUG(D_DLMTRACE, "Destroy locks:\n");

                list_for_each_safe(pos, tmp, &destroy_list) {
                        lock = list_entry(pos, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(D_DLMTRACE, lock, ++i);
                        ldlm_flock_destroy(lock, lock->l_req_mode, *flags);
                }

                if (added && first_enq && res->lr_namespace->ns_client)
                        lock_bitlock(req);

                lock_res(res);
        }

        RETURN(rc);
}

struct ldlm_sleep_flock {
        __u64 lsf_pid;
        __u64 lsf_nid;
        __u64 lsf_blocking_pid;
        __u64 lsf_blocking_nid;
        struct list_head lsf_list;
};

int
ldlm_handle_flock_deadlock_check(struct ptlrpc_request *req)
{
        struct ldlm_request *dlm_req;
        struct ldlm_sleep_flock *lsf;
        struct list_head *pos;
        __u64 pid, nid, blocking_pid, blocking_nid;
        unsigned int flags;
        int rc = 0;
        ENTRY;

        req->rq_status = 0;

        dlm_req = lustre_swab_reqbuf(req, 0, sizeof (*dlm_req),
                                      lustre_swab_ldlm_request);
        if (dlm_req == NULL) {
                CERROR("bad request buffer for flock deadlock check\n");
                RETURN(-EFAULT);
        }

        flags = dlm_req->lock_flags;
        pid = dlm_req->lock_desc.l_policy_data.l_flock.pid;
        nid = dlm_req->lock_desc.l_policy_data.l_flock.nid;
        blocking_pid = dlm_req->lock_desc.l_policy_data.l_flock.blocking_pid;
        blocking_nid = dlm_req->lock_desc.l_policy_data.l_flock.blocking_nid;

        CDEBUG(D_DLMTRACE, "flags: 0x%x req: pid: "LPU64" nid "LPU64" "
               "blk: pid: "LPU64" nid: "LPU64"\n",
               dlm_req->lock_flags, pid, nid, blocking_pid, blocking_nid);

        if (flags & LDLM_FL_GET_BLOCKING) {
                struct ldlm_lock *lock;
                struct ldlm_reply *dlm_rep;
                int size = sizeof(*dlm_rep);
                
                lock = ldlm_handle2lock(&dlm_req->lock_handle1);
                if (!lock) {
                        CERROR("received deadlock check for unknown lock "
                               "cookie "LPX64" from client %s id %s\n",
                               dlm_req->lock_handle1.cookie,
                               req->rq_export->exp_client_uuid.uuid,
                               req->rq_peerstr);
                        req->rq_status = -ESTALE;
                        RETURN(0);
                }

                lock_res_and_lock(lock);
                blocking_pid = lock->l_policy_data.l_flock.blocking_pid;
                blocking_nid = lock->l_policy_data.l_flock.blocking_nid;
                unlock_res_and_lock(lock);

                rc = lustre_pack_reply(req, 1, &size, NULL);
                if (rc) {
                        CERROR("lustre_pack_reply failed: rc = %d\n", rc);
                        req->rq_status = rc;
                        RETURN(0);
                }

                dlm_rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*dlm_rep));
                dlm_rep->lock_desc.l_policy_data.l_flock.blocking_pid =
                        blocking_pid;
                dlm_rep->lock_desc.l_policy_data.l_flock.blocking_nid =
                        blocking_nid;
        } else {
                rc = lustre_pack_reply(req, 0, NULL, NULL);
        }

        if (flags & LDLM_FL_DEADLOCK_CHK) {
                __u64 orig_blocking_pid = blocking_pid;
                __u64 orig_blocking_nid = blocking_nid;
 restart:
                list_for_each(pos, &ldlm_flock_waitq) {
                        lsf = list_entry(pos,struct ldlm_sleep_flock,lsf_list);

                        /* We want to return a deadlock condition for the
                         * last lock on the waitq that created the deadlock
                         * situation. Posix verification suites expect this
                         * behavior. We'll stop if we haven't found a deadlock
                         * up to the point where the current process is queued
                         * to let the last lock on the queue that's in the
                         * deadlock loop detect the deadlock. In this case
                         * just update the blocking info.*/
                        if ((lsf->lsf_pid == pid) && (lsf->lsf_nid == nid)) {
                                lsf->lsf_blocking_pid = blocking_pid;
                                lsf->lsf_blocking_nid = blocking_nid;
                                break;
                        }

                        if ((lsf->lsf_pid != blocking_pid) ||
                            (lsf->lsf_nid != blocking_nid))
                                continue;

                        blocking_pid = lsf->lsf_blocking_pid;
                        blocking_nid = lsf->lsf_blocking_nid;

                        if (blocking_pid == pid && blocking_nid == nid){
                                req->rq_status = -EDEADLOCK;
                                flags |= LDLM_FL_DEADLOCK_DEL;
                                break;
                        }

                        goto restart;
                }

                /* If we got all the way thru the list then we're not on it. */
                if (pos == &ldlm_flock_waitq) {
                        OBD_ALLOC(lsf, sizeof(*lsf));
                        if (!lsf)
                                RETURN(-ENOSPC);

                        lsf->lsf_pid = pid;
                        lsf->lsf_nid = nid;
                        lsf->lsf_blocking_pid = orig_blocking_pid;
                        lsf->lsf_blocking_nid = orig_blocking_nid;
                        list_add_tail(&lsf->lsf_list, &ldlm_flock_waitq);
                }
        }
        
        if (flags & LDLM_FL_DEADLOCK_DEL) {
                list_for_each_entry(lsf, &ldlm_flock_waitq, lsf_list) {
                        if ((lsf->lsf_pid == pid) && (lsf->lsf_nid == nid)) {
                                list_del_init(&lsf->lsf_list);
                                OBD_FREE(lsf, sizeof(*lsf));
                                break;
                        }
                }
        }

        RETURN(rc);
}

int
ldlm_send_flock_deadlock_check(struct obd_device *obd, struct ldlm_lock *lock,
                               unsigned int flags)
{
        struct obd_import *imp;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        struct ptlrpc_request *req;
        int rc, size = sizeof(*body);
        ENTRY;

        CDEBUG(D_DLMTRACE, "obd: %p flags: 0x%x\n", obd, flags);

        imp = obd->u.cli.cl_import;
        req = ptlrpc_prep_req(imp, LUSTRE_DLM_VERSION, LDLM_FLK_DEADLOCK_CHK, 1,
                              &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        body->lock_flags = flags;
        ldlm_lock2desc(lock, &body->lock_desc);
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));

        if (flags & LDLM_FL_GET_BLOCKING) {
                size = sizeof(*reply);
                req->rq_replen = lustre_msg_size(1, &size);
        } else {
                req->rq_replen = lustre_msg_size(0, NULL);
        }

        rc = ptlrpc_queue_wait(req);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        if (flags & LDLM_FL_GET_BLOCKING) {
                reply = lustre_swab_repbuf(req, 0, sizeof (*reply),
                                           lustre_swab_ldlm_reply);
                if (reply == NULL) {
                        CERROR ("Can't unpack ldlm_reply\n");
                        GOTO (out, rc = -EPROTO);
                }

                lock->l_policy_data.l_flock.blocking_pid =
                        reply->lock_desc.l_policy_data.l_flock.blocking_pid;
                lock->l_policy_data.l_flock.blocking_nid =
                        reply->lock_desc.l_policy_data.l_flock.blocking_nid;

                CDEBUG(D_DLMTRACE, "LDLM_FL_GET_BLOCKING: pid: "LPU64" "
                       "nid: "LPU64" blk: pid: "LPU64" nid: "LPU64"\n",
                       lock->l_policy_data.l_flock.pid,
                       lock->l_policy_data.l_flock.nid,
                       lock->l_policy_data.l_flock.blocking_pid,
                       lock->l_policy_data.l_flock.blocking_nid);
        }

        rc = req->rq_status;
 out:
        ptlrpc_req_finished(req);
        RETURN(rc);
}

int
ldlm_flock_deadlock_check(struct obd_device *master_obd, struct obd_device *obd,
                          struct ldlm_lock *lock)
{
        unsigned int flags = 0;
        int rc;
        ENTRY;

        if (obd == NULL) {
                /* Delete this process from the sleeplock list. */
                flags = LDLM_FL_DEADLOCK_DEL;
                rc = ldlm_send_flock_deadlock_check(master_obd, lock, flags);
                RETURN(rc);
        }

        flags = LDLM_FL_GET_BLOCKING;
        if (obd == master_obd)
                flags |= LDLM_FL_DEADLOCK_CHK;

        rc = ldlm_send_flock_deadlock_check(obd, lock, flags);
        CDEBUG(D_DLMTRACE, "1st check: rc: %d flags: 0x%x\n", rc, flags);
        if (rc || (flags & LDLM_FL_DEADLOCK_CHK))
                RETURN(rc);

        CDEBUG(D_DLMTRACE, "about to send 2nd check: master: %p.\n",
                master_obd);

        flags = LDLM_FL_DEADLOCK_CHK;

        rc = ldlm_send_flock_deadlock_check(master_obd, lock, flags);

        CDEBUG(D_DLMTRACE, "2nd check: rc: %d flags: 0x%x\n", rc, flags);

        RETURN(rc);
}

struct ldlm_flock_wait_data {
        struct ldlm_lock *fwd_lock;
        int               fwd_generation;
};

static void
ldlm_flock_interrupted_wait(void *data)
{
        struct ldlm_lock *lock;
        struct lustre_handle lockh;
        ENTRY;

        lock = ((struct ldlm_flock_wait_data *)data)->fwd_lock;

        /* client side - set flag to prevent lock from being put on lru list */
        lock_res_and_lock(lock);
        lock->l_flags |= LDLM_FL_CBPENDING;
        unlock_res_and_lock(lock);

        ldlm_lock_decref_internal(lock, lock->l_req_mode);
        ldlm_lock2handle(lock, &lockh);
        ldlm_cli_cancel(&lockh);
        EXIT;
}

int
ldlm_flock_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        struct ldlm_flock_wait_data fwd;
        unsigned long irqflags;
        struct obd_device *obd;
        struct obd_device *master_obd = (struct obd_device *)lock->l_ast_data;
        struct obd_import *imp = NULL;
        ldlm_error_t err;
        int deadlock_checked = 0;
        int rc = 0;
        struct l_wait_info lwi;
        ENTRY;

        LASSERT(flags != LDLM_FL_WAIT_NOREPROC);

        if (!(flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                       LDLM_FL_BLOCK_CONV)))
                goto  granted;

        LDLM_DEBUG(lock, "client-side enqueue returned a blocked lock, "
                   "sleeping");

        ldlm_lock_dump(D_DLMTRACE, lock, 0);
        fwd.fwd_lock = lock;
        obd = class_exp2obd(lock->l_conn_export);

        CDEBUG(D_DLMTRACE, "flags: 0x%x master: %p obd: %p\n",
               flags, master_obd, obd);

        /* if this is a local lock, then there is no import */
        if (obd != NULL)
                imp = obd->u.cli.cl_import;

        if (imp != NULL) {
                spin_lock_irqsave(&imp->imp_lock, irqflags);
                fwd.fwd_generation = imp->imp_generation;
                spin_unlock_irqrestore(&imp->imp_lock, irqflags);
        }

        lwi = LWI_TIMEOUT_INTR(ldlm_deadlock_timeout, NULL,
                               ldlm_flock_interrupted_wait, &fwd);

 restart:
        rc = l_wait_event(lock->l_waitq,
                          ((lock->l_req_mode == lock->l_granted_mode) ||
                           lock->l_destroyed), &lwi);

        if (rc == -ETIMEDOUT) {
                deadlock_checked = 1;
                rc = ldlm_flock_deadlock_check(master_obd, obd, lock);
                if (rc == -EDEADLK)
                        ldlm_flock_interrupted_wait(&fwd);
                else {
                        CDEBUG(D_DLMTRACE, "lock: %p going back to sleep,\n",
                               lock);
                        goto restart;
                }
        } else {
                if (deadlock_checked)
                        ldlm_flock_deadlock_check(master_obd, NULL, lock);
        }

        LDLM_DEBUG(lock, "client-side enqueue waking up: rc = %d", rc);
        RETURN(rc);
 
 granted:
        LDLM_DEBUG(lock, "client-side enqueue granted");
        lock_res_and_lock(lock);

        /* ldlm_lock_enqueue() has already placed lock on the granted list. */
        list_del_init(&lock->l_res_link);

        if (flags & LDLM_FL_TEST_LOCK) {
                /* client side - set flag to prevent sending a CANCEL */
                lock->l_flags |= LDLM_FL_LOCAL_ONLY | LDLM_FL_CBPENDING;
        } else {
                int noreproc = LDLM_FL_WAIT_NOREPROC;

                /* We need to reprocess the lock to do merges or splits
                 * with existing locks owned by this process. */
                ldlm_process_flock_lock(lock, &noreproc, 1, &err, NULL);
                if (flags == 0)
                        wake_up(&lock->l_waitq);
        }

        unlock_res_and_lock(lock);
        RETURN(0);
}
