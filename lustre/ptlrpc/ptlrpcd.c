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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ptlrpc/ptlrpcd.c
 */

/** \defgroup ptlrpcd PortalRPC daemon
 *
 * ptlrpcd is a special thread with its own set where other user might add
 * requests when they don't want to wait for their completion.
 * PtlRPCD will take care of sending such requests and then processing their
 * replies and calling completion callbacks as necessary.
 * The callbacks are called directly from ptlrpcd context.
 * It is important to never significantly block (esp. on RPCs!) within such
 * completion handler or a deadlock might occur where ptlrpcd enters some
 * callback that attempts to send another RPC and wait for it to return,
 * during which time ptlrpcd is completely blocked, so e.g. if import
 * fails, recovery cannot progress because connection requests are also
 * sent by ptlrpcd.
 *
 * @{
 */

#define DEBUG_SUBSYSTEM S_RPC

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else /* __KERNEL__ */
# include <liblustre.h>
# include <ctype.h>
#endif

#include <lustre_net.h>
# include <lustre_lib.h>

#include <lustre_ha.h>
#include <obd_class.h>   /* for obd_zombie */
#include <obd_support.h> /* for OBD_FAIL_CHECK */
#include <cl_object.h> /* cl_env_{get,put}() */
#include <lprocfs_status.h>

enum pscope_thread {
        PT_NORMAL,
        PT_RECOVERY,
        PT_NR
};

struct ptlrpcd_scope_ctl {
        struct ptlrpcd_thread {
                const char        *pt_name;
                struct ptlrpcd_ctl pt_ctl;
        } pscope_thread[PT_NR];
};

static struct ptlrpcd_scope_ctl ptlrpcd_scopes[PSCOPE_NR] = {
        [PSCOPE_BRW] = {
                .pscope_thread = {
                        [PT_NORMAL] = {
                                .pt_name = "ptlrpcd-brw"
                        },
                        [PT_RECOVERY] = {
                                .pt_name = "ptlrpcd-brw-rcv"
                        }
                }
        },
        [PSCOPE_OTHER] = {
                .pscope_thread = {
                        [PT_NORMAL] = {
                                .pt_name = "ptlrpcd"
                        },
                        [PT_RECOVERY] = {
                                .pt_name = "ptlrpcd-rcv"
                        }
                }
        }
};

cfs_semaphore_t ptlrpcd_sem;
static int ptlrpcd_users = 0;

void ptlrpcd_wake(struct ptlrpc_request *req)
{
        struct ptlrpc_request_set *rq_set = req->rq_set;

        LASSERT(rq_set != NULL);

        cfs_waitq_signal(&rq_set->set_waitq);
}

/**
 * Move all request from an existing request set to the ptlrpcd queue.
 * All requests from the set must be in phase RQ_PHASE_NEW.
 */
void ptlrpcd_add_rqset(struct ptlrpc_request_set *set)
{
        cfs_list_t *tmp, *pos;

        cfs_list_for_each_safe(pos, tmp, &set->set_requests) {
                struct ptlrpc_request *req =
                        cfs_list_entry(pos, struct ptlrpc_request,
                                       rq_set_chain);

                LASSERT(req->rq_phase == RQ_PHASE_NEW);
                cfs_list_del_init(&req->rq_set_chain);
                req->rq_set = NULL;
                ptlrpcd_add_req(req, PSCOPE_OTHER);
                cfs_atomic_dec(&set->set_remaining);
        }
        LASSERT(cfs_atomic_read(&set->set_remaining) == 0);
}
EXPORT_SYMBOL(ptlrpcd_add_rqset);

/**
 * Requests that are added to the ptlrpcd queue are sent via
 * ptlrpcd_check->ptlrpc_check_set().
 */
int ptlrpcd_add_req(struct ptlrpc_request *req, enum ptlrpcd_scope scope)
{
        struct ptlrpcd_ctl *pc;
        enum pscope_thread  pt;
        int rc;

        LASSERT(scope < PSCOPE_NR);
        
        cfs_spin_lock(&req->rq_lock);
        if (req->rq_invalid_rqset) {
                cfs_duration_t timeout;
                struct l_wait_info lwi;

                req->rq_invalid_rqset = 0;
                cfs_spin_unlock(&req->rq_lock);

                timeout = cfs_time_seconds(5);
                lwi = LWI_TIMEOUT(timeout, back_to_sleep, NULL);
                l_wait_event(req->rq_set_waitq, (req->rq_set == NULL), &lwi);
        } else if (req->rq_set) {
                LASSERT(req->rq_phase == RQ_PHASE_NEW);
                LASSERT(req->rq_send_state == LUSTRE_IMP_REPLAY);

                /* ptlrpc_check_set will decrease the count */
                cfs_atomic_inc(&req->rq_set->set_remaining);
                cfs_spin_unlock(&req->rq_lock);

                cfs_waitq_signal(&req->rq_set->set_waitq);
        } else {
                cfs_spin_unlock(&req->rq_lock);
        }

        pt = req->rq_send_state == LUSTRE_IMP_FULL ? PT_NORMAL : PT_RECOVERY;
        pc = &ptlrpcd_scopes[scope].pscope_thread[pt].pt_ctl;
        rc = ptlrpc_set_add_new_req(pc, req);
        /*
         * XXX disable this for CLIO: environment is needed for interpreter.
         *     add debug temporary to check rc.
         */
        LASSERTF(rc == 0, "ptlrpcd_add_req failed (rc = %d)\n", rc);
        if (rc && 0) {
                /*
                 * Thread is probably in stop now so we need to
                 * kill this rpc as it was not added. Let's call
                 * interpret for it to let know we're killing it
                 * so that higher levels might free associated
                 * resources.
                 */
                ptlrpc_req_interpret(NULL, req, -EBADR);
                req->rq_set = NULL;
                ptlrpc_req_finished(req);
        } else if (req->rq_send_state == LUSTRE_IMP_CONNECTING) {
                /*
                 * The request is for recovery, should be sent ASAP.
                 */
                cfs_waitq_signal(&pc->pc_set->set_waitq);
        }

        return rc;
}

/**
 * Check if there is more work to do on ptlrpcd set.
 * Returns 1 if yes.
 */
static int ptlrpcd_check(const struct lu_env *env, struct ptlrpcd_ctl *pc)
{
        cfs_list_t *tmp, *pos;
        struct ptlrpc_request *req;
        int rc = 0;
        ENTRY;

        cfs_spin_lock(&pc->pc_set->set_new_req_lock);
        cfs_list_for_each_safe(pos, tmp, &pc->pc_set->set_new_requests) {
                req = cfs_list_entry(pos, struct ptlrpc_request, rq_set_chain);
                cfs_list_del_init(&req->rq_set_chain);
                ptlrpc_set_add_req(pc->pc_set, req);
                /*
                 * Need to calculate its timeout.
                 */
                rc = 1;
        }
        cfs_spin_unlock(&pc->pc_set->set_new_req_lock);

        if (cfs_atomic_read(&pc->pc_set->set_remaining)) {
                rc = rc | ptlrpc_check_set(env, pc->pc_set);

                /*
                 * XXX: our set never completes, so we prune the completed
                 * reqs after each iteration. boy could this be smarter.
                 */
                cfs_list_for_each_safe(pos, tmp, &pc->pc_set->set_requests) {
                        req = cfs_list_entry(pos, struct ptlrpc_request,
                                         rq_set_chain);
                        if (req->rq_phase != RQ_PHASE_COMPLETE)
                                continue;

                        cfs_list_del_init(&req->rq_set_chain);
                        req->rq_set = NULL;
                        ptlrpc_req_finished (req);
                }
        }

        if (rc == 0) {
                /*
                 * If new requests have been added, make sure to wake up.
                 */
                cfs_spin_lock(&pc->pc_set->set_new_req_lock);
                rc = !cfs_list_empty(&pc->pc_set->set_new_requests);
                cfs_spin_unlock(&pc->pc_set->set_new_req_lock);
        }

        RETURN(rc);
}

#ifdef __KERNEL__
/**
 * Main ptlrpcd thread.
 * ptlrpc's code paths like to execute in process context, so we have this
 * thread which spins on a set which contains the rpcs and sends them.
 *
 */
static int ptlrpcd(void *arg)
{
        struct ptlrpcd_ctl *pc = arg;
        struct lu_env env = { .le_ses = NULL };
        int rc, exit = 0;
        ENTRY;

        rc = cfs_daemonize_ctxt(pc->pc_name);
        if (rc == 0) {
                /*
                 * XXX So far only "client" ptlrpcd uses an environment. In
                 * the future, ptlrpcd thread (or a thread-set) has to given
                 * an argument, describing its "scope".
                 */
                rc = lu_context_init(&env.le_ctx,
                                     LCT_CL_THREAD|LCT_REMEMBER|LCT_NOREF);
        }

        cfs_complete(&pc->pc_starting);

        if (rc != 0)
                RETURN(rc);
        env.le_ctx.lc_cookie = 0x7;

        /*
         * This mainloop strongly resembles ptlrpc_set_wait() except that our
         * set never completes.  ptlrpcd_check() calls ptlrpc_check_set() when
         * there are requests in the set. New requests come in on the set's
         * new_req_list and ptlrpcd_check() moves them into the set.
         */
        do {
                struct l_wait_info lwi;
                int timeout;

                rc = lu_env_refill(&env);
                if (rc != 0) {
                        /*
                         * XXX This is very awkward situation, because
                         * execution can neither continue (request
                         * interpreters assume that env is set up), nor repeat
                         * the loop (as this potentially results in a tight
                         * loop of -ENOMEM's).
                         *
                         * Fortunately, refill only ever does something when
                         * new modules are loaded, i.e., early during boot up.
                         */
                        CERROR("Failure to refill session: %d\n", rc);
                        continue;
                }

                timeout = ptlrpc_set_next_timeout(pc->pc_set);
                lwi = LWI_TIMEOUT(cfs_time_seconds(timeout ? timeout : 1),
                                  ptlrpc_expired_set, pc->pc_set);

                lu_context_enter(&env.le_ctx);
                l_wait_event(pc->pc_set->set_waitq,
                             ptlrpcd_check(&env, pc), &lwi);
                lu_context_exit(&env.le_ctx);

                /*
                 * Abort inflight rpcs for forced stop case.
                 */
                if (cfs_test_bit(LIOD_STOP, &pc->pc_flags)) {
                        if (cfs_test_bit(LIOD_FORCE, &pc->pc_flags))
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
        if (!cfs_list_empty(&pc->pc_set->set_requests))
                ptlrpc_set_wait(pc->pc_set);
        lu_context_fini(&env.le_ctx);
        cfs_complete(&pc->pc_finishing);

        cfs_clear_bit(LIOD_START, &pc->pc_flags);
        cfs_clear_bit(LIOD_STOP, &pc->pc_flags);
        cfs_clear_bit(LIOD_FORCE, &pc->pc_flags);
        return 0;
}

#else /* !__KERNEL__ */

/**
 * In liblustre we do not have separate threads, so this function
 * is called from time to time all across common code to see
 * if something needs to be processed on ptlrpcd set.
 */
int ptlrpcd_check_async_rpcs(void *arg)
{
        struct ptlrpcd_ctl *pc = arg;
        int                 rc = 0;

        /*
         * Single threaded!!
         */
        pc->pc_recurred++;

        if (pc->pc_recurred == 1) {
                rc = lu_env_refill(&pc->pc_env);
                if (rc == 0) {
                        lu_context_enter(&pc->pc_env.le_ctx);
                        rc = ptlrpcd_check(&pc->pc_env, pc);
                        lu_context_exit(&pc->pc_env.le_ctx);
                        if (!rc)
                                ptlrpc_expired_set(pc->pc_set);
                        /*
                         * XXX: send replay requests.
                         */
                        if (cfs_test_bit(LIOD_RECOVERY, &pc->pc_flags))
                                rc = ptlrpcd_check(&pc->pc_env, pc);
                }
        }

        pc->pc_recurred--;
        return rc;
}

int ptlrpcd_idle(void *arg)
{
        struct ptlrpcd_ctl *pc = arg;

        return (cfs_list_empty(&pc->pc_set->set_new_requests) &&
                cfs_atomic_read(&pc->pc_set->set_remaining) == 0);
}

#endif

int ptlrpcd_start(const char *name, struct ptlrpcd_ctl *pc)
{
        int rc;
        ENTRY;

        /*
         * Do not allow start second thread for one pc.
         */
        if (cfs_test_and_set_bit(LIOD_START, &pc->pc_flags)) {
                CERROR("Starting second thread (%s) for same pc %p\n",
                       name, pc);
                RETURN(-EALREADY);
        }

        cfs_init_completion(&pc->pc_starting);
        cfs_init_completion(&pc->pc_finishing);
        cfs_spin_lock_init(&pc->pc_lock);
        strncpy(pc->pc_name, name, sizeof(pc->pc_name) - 1);
        pc->pc_set = ptlrpc_prep_set();
        if (pc->pc_set == NULL)
                GOTO(out, rc = -ENOMEM);
        /*
         * So far only "client" ptlrpcd uses an environment. In the future,
         * ptlrpcd thread (or a thread-set) has to be given an argument,
         * describing its "scope".
         */
        rc = lu_context_init(&pc->pc_env.le_ctx, LCT_CL_THREAD|LCT_REMEMBER);
        if (rc != 0) {
                ptlrpc_set_destroy(pc->pc_set);
                GOTO(out, rc);
        }

#ifdef __KERNEL__
        rc = cfs_create_thread(ptlrpcd, pc, 0);
        if (rc < 0)  {
                lu_context_fini(&pc->pc_env.le_ctx);
                ptlrpc_set_destroy(pc->pc_set);
                GOTO(out, rc);
        }
        rc = 0;
        cfs_wait_for_completion(&pc->pc_starting);
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
                cfs_clear_bit(LIOD_START, &pc->pc_flags);
        RETURN(rc);
}

void ptlrpcd_stop(struct ptlrpcd_ctl *pc, int force)
{
        if (!cfs_test_bit(LIOD_START, &pc->pc_flags)) {
                CERROR("Thread for pc %p was not started\n", pc);
                return;
        }

        cfs_set_bit(LIOD_STOP, &pc->pc_flags);
        if (force)
                cfs_set_bit(LIOD_FORCE, &pc->pc_flags);
        cfs_waitq_signal(&pc->pc_set->set_waitq);
#ifdef __KERNEL__
        cfs_wait_for_completion(&pc->pc_finishing);
#else
        liblustre_deregister_wait_callback(pc->pc_wait_callback);
        liblustre_deregister_idle_callback(pc->pc_idle_callback);
#endif
        lu_context_fini(&pc->pc_env.le_ctx);
        ptlrpc_set_destroy(pc->pc_set);
}

void ptlrpcd_fini(void)
{
        int i;
        int j;

        ENTRY;

        for (i = 0; i < PSCOPE_NR; ++i) {
                for (j = 0; j < PT_NR; ++j) {
                        struct ptlrpcd_ctl *pc;

                        pc = &ptlrpcd_scopes[i].pscope_thread[j].pt_ctl;

                        if (cfs_test_bit(LIOD_START, &pc->pc_flags))
                                ptlrpcd_stop(pc, 0);
                }
        }
        EXIT;
}

int ptlrpcd_addref(void)
{
        int rc = 0;
        int i;
        int j;
        ENTRY;

        cfs_mutex_down(&ptlrpcd_sem);
        if (++ptlrpcd_users == 1) {
                for (i = 0; rc == 0 && i < PSCOPE_NR; ++i) {
                        for (j = 0; rc == 0 && j < PT_NR; ++j) {
                                struct ptlrpcd_thread *pt;
                                struct ptlrpcd_ctl    *pc;

                                pt = &ptlrpcd_scopes[i].pscope_thread[j];
                                pc = &pt->pt_ctl;
                                if (j == PT_RECOVERY)
                                        cfs_set_bit(LIOD_RECOVERY, &pc->pc_flags);
                                rc = ptlrpcd_start(pt->pt_name, pc);
                        }
                }
                if (rc != 0) {
                        --ptlrpcd_users;
                        ptlrpcd_fini();
                }
        }
        cfs_mutex_up(&ptlrpcd_sem);
        RETURN(rc);
}

void ptlrpcd_decref(void)
{
        cfs_mutex_down(&ptlrpcd_sem);
        if (--ptlrpcd_users == 0)
                ptlrpcd_fini();
        cfs_mutex_up(&ptlrpcd_sem);
}
/** @} ptlrpcd */
