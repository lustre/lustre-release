/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Portal-RPC reconnection and replay operations, for use in recovery.
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *   Authors: Phil Schwan <phil@clusterfs.com>
 *            Mike Shaver <shaver@clusterfs.com>
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

#include <linux/version.h>
#include <asm/semaphore.h>

#define DEBUG_SUBSYSTEM S_RPC
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include "ptlrpc_internal.h"

static struct ptlrpc_thread *pinger_thread = NULL;
static DECLARE_MUTEX(pinger_sem);
static struct list_head pinger_imports = LIST_HEAD_INIT(pinger_imports);

int ptlrpc_start_pinger(void);
int ptlrpc_stop_pinger(void);

void ptlrpc_pinger_sending_on_import(struct obd_import *imp)
{
        down(&pinger_sem);
        imp->imp_next_ping = jiffies + (obd_timeout * HZ);
        up(&pinger_sem);
}

int ptlrpc_pinger_add_import(struct obd_import *imp)
{
#ifndef ENABLE_PINGER
        return 0;
#else
        int rc;
        ENTRY;

        if (!list_empty(&imp->imp_pinger_chain))
                RETURN(-EALREADY);

        down(&pinger_sem);
        if (list_empty(&pinger_imports)) {
                up(&pinger_sem);
                rc = ptlrpc_start_pinger();
                if (rc < 0)
                        RETURN(rc);
                down(&pinger_sem);
        }
                
        CDEBUG(D_HA, "adding pingable import %s->%s\n",
               imp->imp_obd->obd_uuid.uuid, imp->imp_target_uuid.uuid);
        imp->imp_next_ping = jiffies + (obd_timeout * HZ);
        list_add_tail(&imp->imp_pinger_chain, &pinger_imports); /* XXX sort, blah blah */
        class_import_get(imp);
        up(&pinger_sem);
        RETURN(0);
#endif
}

int ptlrpc_pinger_del_import(struct obd_import *imp)
{
#ifndef ENABLE_PINGER
        return 0;
#else
        int rc;
        ENTRY;

        if (list_empty(&imp->imp_pinger_chain))
                RETURN(-ENOENT);

        down(&pinger_sem);
        list_del_init(&imp->imp_pinger_chain);
        CDEBUG(D_HA, "removing pingable import %s->%s\n",
               imp->imp_obd->obd_uuid.uuid, imp->imp_target_uuid.uuid);
        class_import_put(imp);
        if (list_empty(&pinger_imports)) {
                up(&pinger_sem);
                rc = ptlrpc_stop_pinger();
                if (rc)
                        RETURN(rc);
                down(&pinger_sem);
        }
        up(&pinger_sem);
        RETURN(0);
#endif
}

static int ptlrpc_pinger_main(void *arg)
{
        struct ptlrpc_svc_data *data = (struct ptlrpc_svc_data *)arg;
        struct ptlrpc_thread *thread = data->thread;
        unsigned long flags;
        ENTRY;

        lock_kernel();
        ptlrpc_daemonize();

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        THREAD_NAME(current->comm, "%s", data->name);
        unlock_kernel();

        /* Record that the thread is running */
        thread->t_flags = SVC_RUNNING;
        wake_up(&thread->t_ctl_waitq);

        /* And now, loop forever, pinging as needed. */
        while (1) {
                unsigned long this_ping = jiffies;
                long time_to_next_ping;
                struct l_wait_info lwi = LWI_TIMEOUT(10 * HZ, NULL, NULL);
                struct ptlrpc_request_set *set;
                struct ptlrpc_request *req;
                struct list_head *iter;
                wait_queue_t set_wait;
                int rc;

                set = ptlrpc_prep_set();
                down(&pinger_sem);
                list_for_each(iter, &pinger_imports) {
                        struct obd_import *imp =
                                list_entry(iter, struct obd_import,
                                           imp_pinger_chain);
                        int generation, level;
                        unsigned long flags;

                        if (imp->imp_next_ping <= this_ping) {
                                /* Add a ping. */
                                spin_lock_irqsave(&imp->imp_lock, flags);
                                generation = imp->imp_generation;
                                level = imp->imp_state;
                                spin_unlock_irqrestore(&imp->imp_lock, flags);

                                if (level != LUSTRE_IMP_FULL) {
                                        CDEBUG(D_HA,
                                               "not pinging %s (in recovery)\n",
                                               imp->imp_target_uuid.uuid);
                                        continue;
                                }

                                req = ptlrpc_prep_req(imp, OBD_PING, 0, NULL,
                                                      NULL);
                                if (!req) {
                                        CERROR("OOM trying to ping\n");
                                        break;
                                }
                                req->rq_no_resend = 1;
                                req->rq_replen = lustre_msg_size(0, NULL);
                                req->rq_send_state = LUSTRE_IMP_FULL;
                                req->rq_phase = RQ_PHASE_RPC;
                                req->rq_import_generation = generation;
                                ptlrpc_set_add_req(set, req);
                        } else {
                                CDEBUG(D_HA, "don't need to ping %s (%lu > %lu)\n",
                                       imp->imp_target_uuid.uuid, imp->imp_next_ping,
                                       this_ping);
                        }
                }
                up(&pinger_sem);

                /* Might be empty, that's OK. */
                if (set->set_remaining == 0)
                        CDEBUG(D_HA, "nothing to ping\n");
                list_for_each(iter, &set->set_requests) {
                        struct ptlrpc_request *req =
                                list_entry(iter, struct ptlrpc_request, rq_set_chain);
                        DEBUG_REQ(D_HA, req, "pinging %s->%s",
                                  req->rq_import->imp_obd->obd_uuid.uuid,
                                  req->rq_import->imp_target_uuid.uuid);
                        (void)ptl_send_rpc(req);
                }

                /* Have to wait on both the thread's queue and the set's. */
                init_waitqueue_entry(&set_wait, current);
                add_wait_queue(&set->set_waitq, &set_wait);
                rc = l_wait_event(thread->t_ctl_waitq,
                                  thread->t_flags & SVC_STOPPING || ptlrpc_check_set(set),
                                  &lwi);
                remove_wait_queue(&set->set_waitq, &set_wait);
                CDEBUG(D_HA, "ping complete (%lu)\n", jiffies);

                if (thread->t_flags & SVC_STOPPING) {
                        thread->t_flags &= ~SVC_STOPPING;
                        list_for_each(iter, &set->set_requests) {
                                req = list_entry(iter, struct ptlrpc_request,
                                                 rq_set_chain);
                                if (!req->rq_replied)
                                        ptlrpc_unregister_reply(req);
                        }
                        ptlrpc_set_destroy(set);
                        EXIT;
                        break;
                }

                /* Expire all the requests that didn't come back. */
                down(&pinger_sem);
                list_for_each(iter, &set->set_requests) {
                        req = list_entry(iter, struct ptlrpc_request, rq_set_chain);

                        if (req->rq_replied)
                                continue;

                        req->rq_phase = RQ_PHASE_COMPLETE;
                        set->set_remaining--;
                        /* If it was disconnected, don't sweat it. */
                        if (list_empty(&req->rq_import->imp_pinger_chain))
                                continue;

                        ptlrpc_expire_one_request(req);
                }
                up(&pinger_sem);
                ptlrpc_set_destroy(set);

                /* Wait until the next ping time, or until we're stopped. */
                time_to_next_ping = this_ping + (obd_timeout * HZ) - jiffies;
                CDEBUG(D_HA, "next ping in %lu (%lu)\n", time_to_next_ping,
                       this_ping + (obd_timeout * HZ));
                if (time_to_next_ping > 0) {
                        lwi = LWI_TIMEOUT(time_to_next_ping, NULL, NULL);
                        l_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_STOPPING,
                                     &lwi);
                        if (thread->t_flags & SVC_STOPPING) {
                                thread->t_flags &= ~SVC_STOPPING;
                                EXIT;
                                break;
                        }
                }
        }

        thread->t_flags = SVC_STOPPED;
        wake_up(&thread->t_ctl_waitq);

        CDEBUG(D_NET, "pinger thread exiting, process %d\n", current->pid);
        return 0;
}

int ptlrpc_start_pinger(void)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_svc_data d;
        int rc;
        ENTRY;

        down(&pinger_sem);
        if (pinger_thread != NULL)
                GOTO(out, rc = -EALREADY);

        OBD_ALLOC(pinger_thread, sizeof(*pinger_thread));
        if (pinger_thread == NULL)
                GOTO(out, rc = -ENOMEM);
        init_waitqueue_head(&pinger_thread->t_ctl_waitq);

        d.name = "ll_ping";
        d.thread = pinger_thread;

        /* CLONE_VM and CLONE_FILES just avoid a needless copy, because we
         * just drop the VM and FILES in ptlrpc_daemonize() right away. */
        rc = kernel_thread(ptlrpc_pinger_main, &d, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread: %d\n", rc);
                OBD_FREE(pinger_thread, sizeof(*pinger_thread));
                GOTO(out, rc);
        }
        l_wait_event(pinger_thread->t_ctl_waitq,
                     pinger_thread->t_flags & SVC_RUNNING, &lwi);

 out:
        up(&pinger_sem);
        RETURN(rc);
}

int ptlrpc_stop_pinger(void)
{
        struct l_wait_info lwi = { 0 };
        int rc = 0;
        ENTRY;

        down(&pinger_sem);
        if (pinger_thread == NULL)
                GOTO(out, rc = -EALREADY);

        pinger_thread->t_flags = SVC_STOPPING;
        wake_up(&pinger_thread->t_ctl_waitq);
        l_wait_event(pinger_thread->t_ctl_waitq,
                     (pinger_thread->t_flags & SVC_STOPPED), &lwi);

        OBD_FREE(pinger_thread, sizeof(*pinger_thread));

 out:
        up(&pinger_sem);
        RETURN(rc);
}
