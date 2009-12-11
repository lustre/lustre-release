/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ptlrpc/ptlrpcd.c
 */

#define DEBUG_SUBSYSTEM S_RPC

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else /* __KERNEL__ */
# include <liblustre.h>
# include <ctype.h>
#endif

#include <libcfs/kp30.h>
#include <lustre_net.h>
# include <lustre_lib.h>

#include <lustre_ha.h>
#include <obd_class.h>   /* for obd_zombie */
#include <obd_support.h> /* for OBD_FAIL_CHECK */
#include <lprocfs_status.h>

static struct ptlrpcd_ctl ptlrpcd_pc;
static struct ptlrpcd_ctl ptlrpcd_recovery_pc;

struct semaphore ptlrpcd_sem;
static int ptlrpcd_users = 0;

void ptlrpcd_wake(struct ptlrpc_request *req)
{
        struct ptlrpc_request_set *rq_set = req->rq_set;

        LASSERT(rq_set != NULL);

        cfs_waitq_signal(&rq_set->set_waitq);
}

/* 
 * Requests that are added to the ptlrpcd queue are sent via
 * ptlrpcd_check->ptlrpc_check_set().
 */
void ptlrpcd_add_req(struct ptlrpc_request *req)
{
        struct ptlrpcd_ctl *pc;
        int rc;

        if (req->rq_send_state == LUSTRE_IMP_FULL)
                pc = &ptlrpcd_pc;
        else
                pc = &ptlrpcd_recovery_pc;
        rc = ptlrpc_set_add_new_req(pc, req);
        if (rc) {
                int (*interpreter)(struct ptlrpc_request *,
                                   void *, int);
                                
                interpreter = req->rq_interpret_reply;

                /*
                 * Thread is probably in stop now so we need to
                 * kill this rpc as it was not added. Let's call
                 * interpret for it to let know we're killing it
                 * so that higher levels might free assosiated
                 * resources.
                */
                req->rq_status = -EBADR;
                interpreter(req, &req->rq_async_args,
                            req->rq_status);
                req->rq_set = NULL;
                ptlrpc_req_finished(req);
        }
}

static int ptlrpcd_check(struct ptlrpcd_ctl *pc)
{
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        int rc = 0;
        ENTRY;

        spin_lock(&pc->pc_set->set_new_req_lock);
        list_for_each_safe(pos, tmp, &pc->pc_set->set_new_requests) {
                req = list_entry(pos, struct ptlrpc_request, rq_set_chain);
                list_del_init(&req->rq_set_chain);
                ptlrpc_set_add_req(pc->pc_set, req);
                /* 
                 * Need to calculate its timeout. 
                 */
                rc = 1;
        }
        spin_unlock(&pc->pc_set->set_new_req_lock);

        if (pc->pc_set->set_remaining) {
                rc = rc | ptlrpc_check_set(pc->pc_set);

                /* 
                 * XXX: our set never completes, so we prune the completed
                 * reqs after each iteration. boy could this be smarter. 
                 */
                list_for_each_safe(pos, tmp, &pc->pc_set->set_requests) {
                        req = list_entry(pos, struct ptlrpc_request,
                                         rq_set_chain);
                        if (req->rq_phase != RQ_PHASE_COMPLETE)
                                continue;

                        list_del_init(&req->rq_set_chain);
                        req->rq_set = NULL;
                        ptlrpc_req_finished (req);
                }
        }

        if (rc == 0) {
                /* 
                 * If new requests have been added, make sure to wake up. 
                 */
                spin_lock(&pc->pc_set->set_new_req_lock);
                rc = !list_empty(&pc->pc_set->set_new_requests);
                spin_unlock(&pc->pc_set->set_new_req_lock);
        }

        RETURN(rc);
}

#ifdef __KERNEL__
/* 
 * ptlrpc's code paths like to execute in process context, so we have this
 * thread which spins on a set which contains the io rpcs. llite specifies
 * ptlrpcd's set when it pushes pages down into the oscs.
 */
static int ptlrpcd(void *arg)
{
        struct ptlrpcd_ctl *pc = arg;
        int rc, exit = 0;
        ENTRY;

        if ((rc = cfs_daemonize_ctxt(pc->pc_name))) {
                complete(&pc->pc_starting);
                goto out;
        }

        complete(&pc->pc_starting);

        /* 
         * This mainloop strongly resembles ptlrpc_set_wait() except that our
         * set never completes.  ptlrpcd_check() calls ptlrpc_check_set() when
         * there are requests in the set. New requests come in on the set's 
         * new_req_list and ptlrpcd_check() moves them into the set. 
         */
        do {
                struct l_wait_info lwi;
                int timeout;

                timeout = ptlrpc_set_next_timeout(pc->pc_set);
                lwi = LWI_TIMEOUT(cfs_time_seconds(timeout ? timeout : 1), 
                                  ptlrpc_expired_set, pc->pc_set);

                l_wait_event(pc->pc_set->set_waitq, ptlrpcd_check(pc), &lwi);

                /*
                 * Abort inflight rpcs for forced stop case.
                 */
                if (test_bit(LIOD_STOP, &pc->pc_flags)) {
                        if (test_bit(LIOD_FORCE, &pc->pc_flags))
                                ptlrpc_abort_set(pc->pc_set);
                        exit++;
                }

                /* 
                 * Let's make one more loop to make sure that ptlrpcd_check()
                 * copied all raced new rpcs into the set so we can kill them.
                 */
        } while (exit < 2);

        /* 
         * Wait for inflight requests to drain. 
         */
        if (!list_empty(&pc->pc_set->set_requests))
                ptlrpc_set_wait(pc->pc_set);

        complete(&pc->pc_finishing);
out:
        clear_bit(LIOD_START, &pc->pc_flags);
        clear_bit(LIOD_STOP, &pc->pc_flags);
        clear_bit(LIOD_FORCE, &pc->pc_flags);
        return 0;
}

#else

int ptlrpcd_check_async_rpcs(void *arg)
{
        struct ptlrpcd_ctl *pc = arg;
        int                  rc = 0;

        /* 
         * Single threaded!! 
         */
        pc->pc_recurred++;

        if (pc->pc_recurred == 1) {
                rc = ptlrpcd_check(pc);
                if (!rc)
                        ptlrpc_expired_set(pc->pc_set);
                /* 
                 * XXX: send replay requests. 
                 */
                if (pc == &ptlrpcd_recovery_pc)
                        rc = ptlrpcd_check(pc);
        }

        pc->pc_recurred--;
        return rc;
}

int ptlrpcd_idle(void *arg)
{
        struct ptlrpcd_ctl *pc = arg;

        return (list_empty(&pc->pc_set->set_new_requests) &&
                pc->pc_set->set_remaining == 0);
}

#endif

int ptlrpcd_start(char *name, struct ptlrpcd_ctl *pc)
{
        int rc = 0;
        ENTRY;
 
        /* 
         * Do not allow start second thread for one pc. 
         */
        if (test_bit(LIOD_START, &pc->pc_flags)) {
                CERROR("Starting second thread (%s) for same pc %p\n",
                       name, pc);
                RETURN(-EALREADY);
        }

        set_bit(LIOD_START, &pc->pc_flags);
        init_completion(&pc->pc_starting);
        init_completion(&pc->pc_finishing);
        spin_lock_init(&pc->pc_lock);
        snprintf (pc->pc_name, sizeof (pc->pc_name), name);

        pc->pc_set = ptlrpc_prep_set();
        if (pc->pc_set == NULL)
                GOTO(out, rc = -ENOMEM);

#ifdef __KERNEL__
        rc = cfs_kernel_thread(ptlrpcd, pc, 0);
        if (rc < 0)  {
                ptlrpc_set_destroy(pc->pc_set);
                GOTO(out, rc);
        }
        rc = 0;
        wait_for_completion(&pc->pc_starting);
#else
        pc->pc_wait_callback =
                liblustre_register_wait_callback("ptlrpcd_check_async_rpcs",
                                                 &ptlrpcd_check_async_rpcs, pc);
        pc->pc_idle_callback =
                liblustre_register_idle_callback("ptlrpcd_check_idle_rpcs",
                                                 &ptlrpcd_idle, pc);
#endif
out:
        if (rc)
                clear_bit(LIOD_START, &pc->pc_flags);
        RETURN(rc);
}

void ptlrpcd_stop(struct ptlrpcd_ctl *pc, int force)
{
        if (!test_bit(LIOD_START, &pc->pc_flags)) {
                CERROR("Thread for pc %p was not started\n", pc);
                return;
        }

        set_bit(LIOD_STOP, &pc->pc_flags);
        if (force)
                set_bit(LIOD_FORCE, &pc->pc_flags);
        cfs_waitq_signal(&pc->pc_set->set_waitq);
#ifdef __KERNEL__
        wait_for_completion(&pc->pc_finishing);
#else
        liblustre_deregister_wait_callback(pc->pc_wait_callback);
        liblustre_deregister_idle_callback(pc->pc_idle_callback);
#endif
        ptlrpc_set_destroy(pc->pc_set);
}

int ptlrpcd_addref(void)
{
        int rc = 0;
        ENTRY;

        mutex_down(&ptlrpcd_sem);
        if (++ptlrpcd_users != 1)
                GOTO(out, rc);

        rc = ptlrpcd_start("ptlrpcd", &ptlrpcd_pc);
        if (rc) {
                --ptlrpcd_users;
                GOTO(out, rc);
        }

        rc = ptlrpcd_start("ptlrpcd-recov", &ptlrpcd_recovery_pc);
        if (rc) {
                ptlrpcd_stop(&ptlrpcd_pc, 0);
                --ptlrpcd_users;
                GOTO(out, rc);
        }
out:
        mutex_up(&ptlrpcd_sem);
        RETURN(rc);
}

void ptlrpcd_decref(void)
{
        mutex_down(&ptlrpcd_sem);
        if (--ptlrpcd_users == 0) {
                ptlrpcd_stop(&ptlrpcd_pc, 0);
                ptlrpcd_stop(&ptlrpcd_recovery_pc, 0);
        }
        mutex_up(&ptlrpcd_sem);
}
