/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Portal-RPC reconnection and replay operations, for use in recovery.
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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

#include <linux/version.h>

#define DEBUG_SUBSYSTEM S_RPC
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include "ptlrpc_internal.h"

static struct ptlrpc_thread *pinger_thread = NULL;
static spinlock_t pinger_lock = SPIN_LOCK_UNLOCKED;
static struct list_head pinger_imports = LIST_HEAD_INIT(pinger_imports);

int ptlrpc_pinger_add_import(struct obd_import *imp)
{
        ENTRY;
        if (!list_empty(&imp->imp_pinger_chain))
                RETURN(-EALREADY);

        spin_lock(&pinger_lock);
        list_add(&imp->imp_pinger_chain, &pinger_imports);
        spin_unlock(&pinger_lock);
        RETURN(0);
}

int ptlrpc_pinger_del_import(struct obd_import *imp)
{
        ENTRY;
        if (list_empty(&imp->imp_pinger_chain))
                RETURN(-EALREADY);

        spin_lock(&pinger_lock);
        list_del_init(&imp->imp_pinger_chain);
        spin_unlock(&pinger_lock);
        RETURN(0);
}

static void ptlrpc_pinger_do_stuff(void)
{



}

static int ptlrpc_pinger_main(void *arg)
{
        struct ptlrpc_svc_data *data = (struct ptlrpc_svc_data *)arg;
        struct ptlrpc_thread *thread = data->thread;
        unsigned long flags;
        int rc = 0;
        ENTRY;

        lock_kernel();
        ptlrpc_daemonize();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
        sigfillset(&current->blocked);
        recalc_sigpending();
#else
        spin_lock_irqsave(&current->sigmask_lock, flags);
        sigfillset(&current->blocked);
        recalc_sigpending(current);
        spin_unlock_irqrestore(&current->sigmask_lock, flags);
#endif

#ifdef __arch_um__
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        sprintf(current->comm, "%s|%d", data->name, current->thread.extern_pid);
#endif
#else
        strcpy(current->comm, data->name);
#endif
        unlock_kernel();

        /* Record that the thread is running */
        thread->t_flags = SVC_RUNNING;
        wake_up(&thread->t_ctl_waitq);

        /* And now, loop forever on requests */
        while (1) {
                struct l_wait_info lwi = LWI_TIMEOUT(5 * HZ, NULL, NULL);
                l_wait_event(thread->t_ctl_waitq,
                             thread->t_flags & SVC_STOPPING, &lwi);

                if (thread->t_flags & SVC_STOPPING) {
                        thread->t_flags &= ~SVC_STOPPING;
                        EXIT;
                        break;
                }
                ptlrpc_pinger_do_stuff();
        }

        thread->t_flags = SVC_STOPPED;
        wake_up(&thread->t_ctl_waitq);

        CDEBUG(D_NET, "pinger thread exiting, process %d: rc = %d\n",
               current->pid, rc);
        return rc;
}

int ptlrpc_pinger_start(void)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_svc_data d;
        int rc;
        ENTRY;

        spin_lock(&pinger_lock);
        if (pinger_thread != NULL)
                GOTO(out, rc = -EALREADY);

        OBD_ALLOC(pinger_thread, sizeof(*pinger_thread));
        if (pinger_thread == NULL)
                GOTO(out, rc = -ENOMEM);
        init_waitqueue_head(&pinger_thread->t_ctl_waitq);

        d.name = "Lustre pinger";
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
        spin_unlock(&pinger_lock);
        RETURN(rc);
}

int ptlrpc_stop_pinger(void)
{
        struct l_wait_info lwi = { 0 };
        int rc = 0;
        ENTRY;

        spin_lock(&pinger_lock);
        if (pinger_thread == NULL)
                GOTO(out, rc = -EALREADY);

        pinger_thread->t_flags = SVC_STOPPING;
        wake_up(&pinger_thread->t_ctl_waitq);
        l_wait_event(pinger_thread->t_ctl_waitq,
                     (pinger_thread->t_flags & SVC_STOPPED), &lwi);

        OBD_FREE(pinger_thread, sizeof(*pinger_thread));

 out:
        spin_unlock(&pinger_lock);
        RETURN(rc);
}
