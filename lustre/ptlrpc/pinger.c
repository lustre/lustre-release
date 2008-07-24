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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 * lustre/ptlrpc/pinger.c
 *
 * Portal-RPC reconnection and replay operations, for use in recovery.
 */

#ifndef __KERNEL__
#include <liblustre.h>
#else
#define DEBUG_SUBSYSTEM S_RPC
#endif

#include <obd_support.h>
#include <obd_class.h>
#include "ptlrpc_internal.h"

struct semaphore pinger_sem;
static struct list_head pinger_imports = CFS_LIST_HEAD_INIT(pinger_imports);

int ptlrpc_ping(struct obd_import *imp)
{
        struct ptlrpc_request *req;
        int rc = 0;
        ENTRY;

        req = ptlrpc_prep_req(imp, LUSTRE_OBD_VERSION, OBD_PING, 
                              1, NULL, NULL);
        if (req) {
                DEBUG_REQ(D_INFO, req, "pinging %s->%s",
                          imp->imp_obd->obd_uuid.uuid,
                          obd2cli_tgt(imp->imp_obd));
                req->rq_no_resend = req->rq_no_delay = 1;
                ptlrpc_req_set_repsize(req, 1, NULL);
                ptlrpcd_add_req(req);
        } else {
                CERROR("OOM trying to ping %s->%s\n",
                       imp->imp_obd->obd_uuid.uuid,
                       obd2cli_tgt(imp->imp_obd));
                rc = -ENOMEM;
        }

        RETURN(rc);
}

void ptlrpc_update_next_ping(struct obd_import *imp)
{
#ifdef ENABLE_PINGER
        int time = PING_INTERVAL;
        if (imp->imp_state == LUSTRE_IMP_DISCON) {
                int dtime = max_t(int, CONNECTION_SWITCH_MIN,
                                  AT_OFF ? 0 :
                                  at_get(&imp->imp_at.iat_net_latency));
                time = min(time, dtime);
        }
        imp->imp_next_ping = cfs_time_shift(time);
#endif /* ENABLE_PINGER */
}

void ptlrpc_ping_import_soon(struct obd_import *imp)
{
        imp->imp_next_ping = cfs_time_current();
}

#ifdef __KERNEL__
static int ptlrpc_pinger_main(void *arg)
{
        struct ptlrpc_svc_data *data = (struct ptlrpc_svc_data *)arg;
        struct ptlrpc_thread *thread = data->thread;
        ENTRY;

        cfs_daemonize(data->name);

        /* Record that the thread is running */
        thread->t_flags = SVC_RUNNING;
        cfs_waitq_signal(&thread->t_ctl_waitq);

        /* And now, loop forever, pinging as needed. */
        while (1) {
                cfs_time_t this_ping = cfs_time_current();
                struct l_wait_info lwi;
                cfs_duration_t time_to_next_ping;
                struct list_head *iter;

                mutex_down(&pinger_sem);
                list_for_each(iter, &pinger_imports) {
                        struct obd_import *imp =
                                list_entry(iter, struct obd_import,
                                           imp_pinger_chain);
                        int force, level;

                        spin_lock(&imp->imp_lock);
                        level = imp->imp_state;
                        force = imp->imp_force_verify;
                        imp->imp_force_verify = 0;
                        spin_unlock(&imp->imp_lock);

                        CDEBUG(level == LUSTRE_IMP_FULL ? D_INFO : D_RPCTRACE,
                               "level %s/%u force %u deactive %u pingable %u\n",
                               ptlrpc_import_state_name(level), level,
                               force, imp->imp_deactive, imp->imp_pingable);

                        if (force ||
                            /* if the next ping is within, say, 5 jiffies from
                               now, go ahead and ping. See note below. */
                            cfs_time_aftereq(this_ping, 
                                             imp->imp_next_ping - 5 * CFS_TICK)) {
                                if (level == LUSTRE_IMP_DISCON &&
                                    !imp->imp_deactive) {
                                        /* wait at least a timeout before
                                           trying recovery again. */
                                        imp->imp_next_ping = cfs_time_shift(obd_timeout);
                                        ptlrpc_initiate_recovery(imp);
                                } else if (level != LUSTRE_IMP_FULL ||
                                         imp->imp_obd->obd_no_recov ||
                                         imp->imp_deactive) {
                                        CDEBUG(D_HA, "not pinging %s "
                                               "(in recovery: %s or recovery "
                                               "disabled: %u/%u)\n",
                                               obd2cli_tgt(imp->imp_obd),
                                               ptlrpc_import_state_name(level),
                                               imp->imp_deactive,
                                               imp->imp_obd->obd_no_recov);
                                } else if (imp->imp_pingable || force) {
                                        ptlrpc_ping(imp);
                                }
                        } else {
                                if (!imp->imp_pingable)
                                        continue;
                                CDEBUG(D_INFO,
                                       "don't need to ping %s ("CFS_TIME_T
                                       " > "CFS_TIME_T")\n",
                                       obd2cli_tgt(imp->imp_obd),
                                       imp->imp_next_ping, this_ping);
                        }

                        /* obd_timeout might have changed */
                        if (cfs_time_after(imp->imp_next_ping,
                                           cfs_time_add(this_ping, 
                                                        cfs_time_seconds(PING_INTERVAL))))
                                ptlrpc_update_next_ping(imp);
                }
                mutex_up(&pinger_sem);
                /* update memory usage info */
                obd_update_maxusage();

                /* Wait until the next ping time, or until we're stopped. */
                time_to_next_ping = cfs_time_sub(cfs_time_add(this_ping, 
                                                              cfs_time_seconds(PING_INTERVAL)), 
                                                 cfs_time_current());

                /* The ping sent by ptlrpc_send_rpc may get sent out
                   say .01 second after this.
                   ptlrpc_pinger_eending_on_import will then set the
                   next ping time to next_ping + .01 sec, which means
                   we will SKIP the next ping at next_ping, and the
                   ping will get sent 2 timeouts from now!  Beware. */
                CDEBUG(D_INFO, "next ping in "CFS_DURATION_T" ("CFS_TIME_T")\n", 
                               time_to_next_ping, 
                               cfs_time_add(this_ping, cfs_time_seconds(PING_INTERVAL)));
                if (time_to_next_ping > 0) {
                        lwi = LWI_TIMEOUT(max_t(cfs_duration_t, time_to_next_ping, cfs_time_seconds(1)),
                                          NULL, NULL);
                        l_wait_event(thread->t_ctl_waitq,
                                     thread->t_flags & (SVC_STOPPING|SVC_EVENT),
                                     &lwi);
                        if (thread->t_flags & SVC_STOPPING) {
                                thread->t_flags &= ~SVC_STOPPING;
                                EXIT;
                                break;
                        } else if (thread->t_flags & SVC_EVENT) {
                                /* woken after adding import to reset timer */
                                thread->t_flags &= ~SVC_EVENT;
                        }
                }
        }

        thread->t_flags = SVC_STOPPED;
        cfs_waitq_signal(&thread->t_ctl_waitq);

        CDEBUG(D_NET, "pinger thread exiting, process %d\n", cfs_curproc_pid());
        return 0;
}

static struct ptlrpc_thread *pinger_thread = NULL;

int ptlrpc_start_pinger(void)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_svc_data d;
        int rc;
#ifndef ENABLE_PINGER
        return 0;
#endif
        ENTRY;

        if (pinger_thread != NULL)
                RETURN(-EALREADY);

        OBD_ALLOC(pinger_thread, sizeof(*pinger_thread));
        if (pinger_thread == NULL)
                RETURN(-ENOMEM);
        cfs_waitq_init(&pinger_thread->t_ctl_waitq);

        d.name = "ll_ping";
        d.thread = pinger_thread;

        /* CLONE_VM and CLONE_FILES just avoid a needless copy, because we
         * just drop the VM and FILES in ptlrpc_daemonize() right away. */
        rc = cfs_kernel_thread(ptlrpc_pinger_main, &d, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread: %d\n", rc);
                OBD_FREE(pinger_thread, sizeof(*pinger_thread));
                pinger_thread = NULL;
                RETURN(rc);
        }
        l_wait_event(pinger_thread->t_ctl_waitq,
                     pinger_thread->t_flags & SVC_RUNNING, &lwi);

        RETURN(0);
}

int ptlrpc_stop_pinger(void)
{
        struct l_wait_info lwi = { 0 };
        int rc = 0;
#ifndef ENABLE_PINGER
        return 0;
#endif
        ENTRY;

        if (pinger_thread == NULL)
                RETURN(-EALREADY);
        mutex_down(&pinger_sem);
        pinger_thread->t_flags = SVC_STOPPING;
        cfs_waitq_signal(&pinger_thread->t_ctl_waitq);
        mutex_up(&pinger_sem);

        l_wait_event(pinger_thread->t_ctl_waitq,
                     (pinger_thread->t_flags & SVC_STOPPED), &lwi);

        OBD_FREE(pinger_thread, sizeof(*pinger_thread));
        pinger_thread = NULL;
        RETURN(rc);
}

void ptlrpc_pinger_sending_on_import(struct obd_import *imp)
{
        ptlrpc_update_next_ping(imp);
}

int ptlrpc_pinger_add_import(struct obd_import *imp)
{
        ENTRY;
        if (!list_empty(&imp->imp_pinger_chain))
                RETURN(-EALREADY);

        mutex_down(&pinger_sem);
        CDEBUG(D_HA, "adding pingable import %s->%s\n",
               imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
        /* if we add to pinger we want recovery on this import */
        imp->imp_obd->obd_no_recov = 0;

        ptlrpc_update_next_ping(imp);
        /* XXX sort, blah blah */
        list_add_tail(&imp->imp_pinger_chain, &pinger_imports);
        class_import_get(imp);

        ptlrpc_pinger_wake_up();
        mutex_up(&pinger_sem);

        RETURN(0);
}

int ptlrpc_pinger_del_import(struct obd_import *imp)
{
        ENTRY;
        if (list_empty(&imp->imp_pinger_chain))
                RETURN(-ENOENT);

        mutex_down(&pinger_sem);
        list_del_init(&imp->imp_pinger_chain);
        CDEBUG(D_HA, "removing pingable import %s->%s\n",
               imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
        /* if we remove from pinger we don't want recovery on this import */
        imp->imp_obd->obd_no_recov = 1;
        class_import_put(imp);
        mutex_up(&pinger_sem);
        RETURN(0);
}

void ptlrpc_pinger_wake_up()
{
#ifdef ENABLE_PINGER
        pinger_thread->t_flags |= SVC_EVENT;
        cfs_waitq_signal(&pinger_thread->t_ctl_waitq);
#endif
}

/* Ping evictor thread */
#define PET_READY     1
#define PET_TERMINATE 2

static int               pet_refcount = 0;
static int               pet_state;
static wait_queue_head_t pet_waitq;
static struct obd_export *pet_exp = NULL;
static spinlock_t        pet_lock = SPIN_LOCK_UNLOCKED;

int ping_evictor_wake(struct obd_export *exp)
{
        spin_lock(&pet_lock);
        if (pet_exp || (pet_state != PET_READY)) {
                /* eventually the new obd will call here again. */
                spin_unlock(&pet_lock);
                return 1;
        }

        /* We have to make sure the obd isn't destroyed between now and when
         * the ping evictor runs.  We'll take a reference here, and drop it
         * when we finish in the evictor.  We don't really care about this
         * export in particular; we just need one to keep the obd alive. */
        pet_exp = class_export_get(exp);
        spin_unlock(&pet_lock);

        wake_up(&pet_waitq);
        return 0;
}

static int ping_evictor_main(void *arg)
{
        struct obd_device *obd;
        struct obd_export *exp;
        struct l_wait_info lwi = { 0 };
        time_t expire_time;
        ENTRY;

        ptlrpc_daemonize("ll_evictor");

        CDEBUG(D_HA, "Starting Ping Evictor\n");
        pet_exp = NULL;
        pet_state = PET_READY;
        while (1) {
                l_wait_event(pet_waitq, pet_exp ||
                             (pet_state == PET_TERMINATE), &lwi);
                if (pet_state == PET_TERMINATE)
                        break;

                /* we only get here if pet_exp != NULL, and the end of this
                 * loop is the only place which sets it NULL again, so lock
                 * is not strictly necessary. */
                spin_lock(&pet_lock);
                obd = pet_exp->exp_obd;
                spin_unlock(&pet_lock);

                expire_time = cfs_time_current_sec() - PING_EVICT_TIMEOUT;

                CDEBUG(D_HA, "evicting all exports of obd %s older than %ld\n",
                       obd->obd_name, expire_time);

                /* Exports can't be deleted out of the list while we hold
                 * the obd lock (class_unlink_export), which means we can't
                 * lose the last ref on the export.  If they've already been
                 * removed from the list, we won't find them here. */
                spin_lock(&obd->obd_dev_lock);
                while (!list_empty(&obd->obd_exports_timed)) {
                        exp = list_entry(obd->obd_exports_timed.next,
                                         struct obd_export,exp_obd_chain_timed);
                        if (expire_time > exp->exp_last_request_time) {
                                class_export_get(exp);
                                spin_unlock(&obd->obd_dev_lock);
                                LCONSOLE_WARN("%s: haven't heard from client %s"
                                              " (at %s) in %ld seconds. I think"
                                              " it's dead, and I am evicting"
                                              " it.\n", obd->obd_name,
                                              obd_uuid2str(&exp->exp_client_uuid),
                                              obd_export_nid2str(exp),
                                              (long)(cfs_time_current_sec() -
                                                     exp->exp_last_request_time));
                                CDEBUG(D_HA, "Last request was at %ld\n",
                                       exp->exp_last_request_time);
                                class_fail_export(exp);
                                class_export_put(exp);
                                spin_lock(&obd->obd_dev_lock);
                        } else {
                                /* List is sorted, so everyone below is ok */
                                break;
                        }
                }
                spin_unlock(&obd->obd_dev_lock);

                class_export_put(pet_exp);

                spin_lock(&pet_lock);
                pet_exp = NULL;
                spin_unlock(&pet_lock);
        }
        CDEBUG(D_HA, "Exiting Ping Evictor\n");

        RETURN(0);
}

void ping_evictor_start(void)
{
        int rc;

        if (++pet_refcount > 1)
                return;

        init_waitqueue_head(&pet_waitq);

        rc = cfs_kernel_thread(ping_evictor_main, NULL, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                pet_refcount--;
                CERROR("Cannot start ping evictor thread: %d\n", rc);
        }
}
EXPORT_SYMBOL(ping_evictor_start);

void ping_evictor_stop(void)
{
        if (--pet_refcount > 0)
                return;

        pet_state = PET_TERMINATE;
        wake_up(&pet_waitq);
}
EXPORT_SYMBOL(ping_evictor_stop);
#else /* !__KERNEL__ */

/* XXX
 * the current implementation of pinger in liblustre is not optimized
 */

#ifdef ENABLE_PINGER
static struct pinger_data {
        int             pd_recursion;
        cfs_time_t      pd_this_ping;   /* jiffies */
        cfs_time_t      pd_next_ping;   /* jiffies */
        struct ptlrpc_request_set *pd_set;
} pinger_args;

static int pinger_check_rpcs(void *arg)
{
        cfs_time_t curtime = cfs_time_current();
        struct ptlrpc_request *req;
        struct ptlrpc_request_set *set;
        struct list_head *iter;
        struct pinger_data *pd = &pinger_args;
        int rc;

        /* prevent recursion */
        if (pd->pd_recursion++) {
                CDEBUG(D_HA, "pinger: recursion! quit\n");
                LASSERT(pd->pd_set);
                pd->pd_recursion--;
                return 0;
        }

        /* have we reached ping point? */
        if (!pd->pd_set && time_before(curtime, pd->pd_next_ping)) {
                pd->pd_recursion--;
                return 0;
        }

        /* if we have rpc_set already, continue processing it */
        if (pd->pd_set) {
                LASSERT(pd->pd_this_ping);
                set = pd->pd_set;
                goto do_check_set;
        }

        pd->pd_this_ping = curtime;
        pd->pd_set = ptlrpc_prep_set();
        if (pd->pd_set == NULL)
                goto out;
        set = pd->pd_set;

        /* add rpcs into set */
        mutex_down(&pinger_sem);
        list_for_each(iter, &pinger_imports) {
                struct obd_import *imp =
                        list_entry(iter, struct obd_import, imp_pinger_chain);
                int generation, level;

                if (cfs_time_aftereq(pd->pd_this_ping, 
                                     imp->imp_next_ping - 5 * CFS_TICK)) {
                        /* Add a ping. */
                        spin_lock(&imp->imp_lock);
                        generation = imp->imp_generation;
                        level = imp->imp_state;
                        spin_unlock(&imp->imp_lock);

                        if (level != LUSTRE_IMP_FULL) {
                                CDEBUG(D_HA,
                                       "not pinging %s (in recovery)\n",
                                       obd2cli_tgt(imp->imp_obd));
                                continue;
                        }

                        req = ptlrpc_prep_req(imp, LUSTRE_OBD_VERSION, OBD_PING,
                                              1, NULL, NULL);
                        if (!req) {
                                CERROR("out of memory\n");
                                break;
                        }
                        req->rq_no_resend = 1;
                        ptlrpc_req_set_repsize(req, 1, NULL);
                        req->rq_send_state = LUSTRE_IMP_FULL;
                        req->rq_phase = RQ_PHASE_RPC;
                        req->rq_import_generation = generation;
                        ptlrpc_set_add_req(set, req);
                } else {
                        CDEBUG(D_INFO, "don't need to ping %s ("CFS_TIME_T
                               " > "CFS_TIME_T")\n", obd2cli_tgt(imp->imp_obd),
                               imp->imp_next_ping, pd->pd_this_ping);
                }
        }
        pd->pd_this_ping = curtime;
        mutex_up(&pinger_sem);

        /* Might be empty, that's OK. */
        if (set->set_remaining == 0)
                CDEBUG(D_RPCTRACE, "nothing to ping\n");

        list_for_each(iter, &set->set_requests) {
                struct ptlrpc_request *req =
                        list_entry(iter, struct ptlrpc_request,
                                   rq_set_chain);
                DEBUG_REQ(D_RPCTRACE, req, "pinging %s->%s",
                          req->rq_import->imp_obd->obd_uuid.uuid,
                          obd2cli_tgt(req->rq_import->imp_obd));
                (void)ptl_send_rpc(req, 0);
        }

do_check_set:
        rc = ptlrpc_check_set(set);

        /* not finished, and we are not expired, simply return */
        if (!rc && cfs_time_before(curtime, cfs_time_add(pd->pd_this_ping,
                                            cfs_time_seconds(PING_INTERVAL)))) {
                CDEBUG(D_RPCTRACE, "not finished, but also not expired\n");
                pd->pd_recursion--;
                return 0;
        }

        /* Expire all the requests that didn't come back. */
        mutex_down(&pinger_sem);
        list_for_each(iter, &set->set_requests) {
                req = list_entry(iter, struct ptlrpc_request,
                                 rq_set_chain);

                if (req->rq_phase == RQ_PHASE_COMPLETE)
                        continue;

                req->rq_phase = RQ_PHASE_COMPLETE;
                atomic_dec(&req->rq_import->imp_inflight);
                set->set_remaining--;
                /* If it was disconnected, don't sweat it. */
                if (list_empty(&req->rq_import->imp_pinger_chain)) {
                        ptlrpc_unregister_reply(req);
                        continue;
                }

                CDEBUG(D_RPCTRACE, "pinger initiate expire_one_request\n");
                ptlrpc_expire_one_request(req);
        }
        mutex_up(&pinger_sem);

        ptlrpc_set_destroy(set);
        pd->pd_set = NULL;

out:
        pd->pd_next_ping = cfs_time_add(pd->pd_this_ping,
                                        cfs_time_seconds(PING_INTERVAL));
        pd->pd_this_ping = 0; /* XXX for debug */

        CDEBUG(D_INFO, "finished a round ping\n");
        pd->pd_recursion--;
        return 0;
}

static void *pinger_callback = NULL;
#endif /* ENABLE_PINGER */

int ptlrpc_start_pinger(void)
{
#ifdef ENABLE_PINGER
        memset(&pinger_args, 0, sizeof(pinger_args));
        pinger_callback = liblustre_register_wait_callback("pinger_check_rpcs",
                                                           &pinger_check_rpcs,
                                                           &pinger_args);
#endif
        return 0;
}

int ptlrpc_stop_pinger(void)
{
#ifdef ENABLE_PINGER
        if (pinger_callback)
                liblustre_deregister_wait_callback(pinger_callback);
#endif
        return 0;
}

void ptlrpc_pinger_sending_on_import(struct obd_import *imp)
{
#ifdef ENABLE_PINGER
        mutex_down(&pinger_sem);
        ptlrpc_update_next_ping(imp);
        if (pinger_args.pd_set == NULL &&
            time_before(imp->imp_next_ping, pinger_args.pd_next_ping)) {
                CDEBUG(D_HA, "set next ping to "CFS_TIME_T"(cur "CFS_TIME_T")\n",
                        imp->imp_next_ping, cfs_time_current());
                pinger_args.pd_next_ping = imp->imp_next_ping;
        }
        mutex_up(&pinger_sem);
#endif
}

int ptlrpc_pinger_add_import(struct obd_import *imp)
{
        ENTRY;
        if (!list_empty(&imp->imp_pinger_chain))
                RETURN(-EALREADY);

        CDEBUG(D_HA, "adding pingable import %s->%s\n",
               imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
        ptlrpc_pinger_sending_on_import(imp);

        mutex_down(&pinger_sem);
        list_add_tail(&imp->imp_pinger_chain, &pinger_imports);
        class_import_get(imp);
        mutex_up(&pinger_sem);

        RETURN(0);
}

int ptlrpc_pinger_del_import(struct obd_import *imp)
{
        ENTRY;
        if (list_empty(&imp->imp_pinger_chain))
                RETURN(-ENOENT);

        mutex_down(&pinger_sem);
        list_del_init(&imp->imp_pinger_chain);
        CDEBUG(D_HA, "removing pingable import %s->%s\n",
               imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
        class_import_put(imp);
        mutex_up(&pinger_sem);
        RETURN(0);
}

void ptlrpc_pinger_wake_up()
{
#ifdef ENABLE_PINGER
        ENTRY;
        /* XXX force pinger to run, if needed */
        struct obd_import *imp;
        list_for_each_entry(imp, &pinger_imports, imp_pinger_chain) {
                CDEBUG(D_RPCTRACE, "checking import %s->%s\n",
                       imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
#ifdef ENABLE_LIBLUSTRE_RECOVERY
                if (imp->imp_state == LUSTRE_IMP_DISCON && !imp->imp_deactive)
#else
                /*XXX only recover for the initial connection */
                if (!lustre_handle_is_used(&imp->imp_remote_handle) &&
                    imp->imp_state == LUSTRE_IMP_DISCON && !imp->imp_deactive)
#endif
                        ptlrpc_initiate_recovery(imp);
                else if (imp->imp_state != LUSTRE_IMP_FULL)
                        CDEBUG(D_HA, "Refused to recover import %s->%s "
                                     "state %d, deactive %d\n",
                                     imp->imp_obd->obd_uuid.uuid,
                                     obd2cli_tgt(imp->imp_obd), imp->imp_state,
                                     imp->imp_deactive);
        }
#endif
        EXIT;
}
#endif /* !__KERNEL__ */
