/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author Peter Braam <braam@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
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

#define LIOD_STOP 0
struct ptlrpcd_ctl {
        unsigned long             pc_flags;
        spinlock_t                pc_lock;
        struct completion         pc_starting;
        struct completion         pc_finishing;
        struct ptlrpc_request_set *pc_set;
        char                      pc_name[16];
#ifndef __KERNEL__
        int                       pc_recurred;
        void                     *pc_callback;
        void                     *pc_wait_callback;
        void                     *pc_idle_callback;
#endif
};

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

/* requests that are added to the ptlrpcd queue are sent via
 * ptlrpcd_check->ptlrpc_check_set() */
void ptlrpcd_add_req(struct ptlrpc_request *req)
{
        struct ptlrpcd_ctl *pc;

        if (req->rq_send_state == LUSTRE_IMP_FULL)
                pc = &ptlrpcd_pc;
        else
                pc = &ptlrpcd_recovery_pc;

        ptlrpc_set_add_new_req(pc->pc_set, req);
        cfs_waitq_signal(&pc->pc_set->set_waitq);
}

static int ptlrpcd_check(struct ptlrpcd_ctl *pc)
{
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        int rc = 0;
        ENTRY;

        if (test_bit(LIOD_STOP, &pc->pc_flags))
                RETURN(1);

        spin_lock(&pc->pc_set->set_new_req_lock);
        list_for_each_safe(pos, tmp, &pc->pc_set->set_new_requests) {
                req = list_entry(pos, struct ptlrpc_request, rq_set_chain);
                list_del_init(&req->rq_set_chain);
                ptlrpc_set_add_req(pc->pc_set, req);
                rc = 1; /* need to calculate its timeout */
        }
        spin_unlock(&pc->pc_set->set_new_req_lock);

        if (pc->pc_set->set_remaining) {
                rc = rc | ptlrpc_check_set(pc->pc_set);

                /* XXX our set never completes, so we prune the completed
                 * reqs after each iteration. boy could this be smarter. */
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
                /* If new requests have been added, make sure to wake up */
                spin_lock(&pc->pc_set->set_new_req_lock);
                rc = !list_empty(&pc->pc_set->set_new_requests);
                spin_unlock(&pc->pc_set->set_new_req_lock);
        }

        RETURN(rc);
}

#ifdef __KERNEL__
/* ptlrpc's code paths like to execute in process context, so we have this
 * thread which spins on a set which contains the io rpcs.  llite specifies
 * ptlrpcd's set when it pushes pages down into the oscs */
static int ptlrpcd(void *arg)
{
        struct ptlrpcd_ctl *pc = arg;
        int rc;
        ENTRY;

        if ((rc = cfs_daemonize_ctxt(pc->pc_name))) {
                complete(&pc->pc_starting);
                return rc;
        }

        complete(&pc->pc_starting);

        /* this mainloop strongly resembles ptlrpc_set_wait except
         * that our set never completes.  ptlrpcd_check calls ptlrpc_check_set
         * when there are requests in the set.  new requests come in
         * on the set's new_req_list and ptlrpcd_check moves them into
         * the set. */
        while (1) {
                struct l_wait_info lwi;
                cfs_duration_t timeout;

                timeout = cfs_time_seconds(ptlrpc_set_next_timeout(pc->pc_set));
                lwi = LWI_TIMEOUT(timeout, ptlrpc_expired_set, pc->pc_set);

                l_wait_event(pc->pc_set->set_waitq, ptlrpcd_check(pc), &lwi);

                if (test_bit(LIOD_STOP, &pc->pc_flags))
                        break;
        }
        /* wait for inflight requests to drain */
        if (!list_empty(&pc->pc_set->set_requests))
                ptlrpc_set_wait(pc->pc_set);
        complete(&pc->pc_finishing);
        return 0;
}

#else

int ptlrpcd_check_async_rpcs(void *arg)
{
        struct ptlrpcd_ctl *pc = arg;
        int                  rc = 0;

        /* single threaded!! */
        pc->pc_recurred++;

        if (pc->pc_recurred == 1) {
                rc = ptlrpcd_check(pc);
                if (!rc)
                        ptlrpc_expired_set(pc->pc_set);
                /*XXX send replay requests */
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

static int ptlrpcd_start(char *name, struct ptlrpcd_ctl *pc)
{
        int rc;

        ENTRY;
        memset(pc, 0, sizeof(*pc));
        init_completion(&pc->pc_starting);
        init_completion(&pc->pc_finishing);
        pc->pc_flags = 0;
        spin_lock_init(&pc->pc_lock);
        snprintf (pc->pc_name, sizeof (pc->pc_name), name);

        pc->pc_set = ptlrpc_prep_set();
        if (pc->pc_set == NULL)
                RETURN(-ENOMEM);

#ifdef __KERNEL__
        rc = cfs_kernel_thread(ptlrpcd, pc, 0);
        if (rc < 0)  {
                ptlrpc_set_destroy(pc->pc_set);
                RETURN(rc);
        }

        wait_for_completion(&pc->pc_starting);
#else
        pc->pc_wait_callback =
                liblustre_register_wait_callback("ptlrpcd_check_async_rpcs",
                                                 &ptlrpcd_check_async_rpcs, pc);
        pc->pc_idle_callback =
                liblustre_register_idle_callback("ptlrpcd_check_idle_rpcs",
                                                 &ptlrpcd_idle, pc);
        (void)rc;
#endif
        RETURN(0);
}

static void ptlrpcd_stop(struct ptlrpcd_ctl *pc)
{
        set_bit(LIOD_STOP, &pc->pc_flags);
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
                ptlrpcd_stop(&ptlrpcd_pc);
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
                ptlrpcd_stop(&ptlrpcd_pc);
                ptlrpcd_stop(&ptlrpcd_recovery_pc);
        }
        mutex_up(&ptlrpcd_sem);
}
