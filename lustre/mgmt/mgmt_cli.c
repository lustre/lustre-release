/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Implementation of the management/health monitoring client.
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *   Author: Mike Shaver <shaver@clusterfs.com>
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MGMT
#include <linux/module.h>
#include <linux/init.h>

#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_net.h>
#include <linux/lustre_mgmt.h>

/*** Registration and service/thread management. ***/

/* An entry representing one obd which has registered for management events. */
struct mgmtcli_registrant {
        struct list_head   chain;
        struct obd_device *notify_obd;
        struct obd_uuid   *relevant_uuid;
};
 
static int mgmtcli_pinger_main(void *arg)
{
        struct ptlrpc_svc_data *data = (struct ptlrpc_svc_data *)arg;
        struct ptlrpc_thread *thread = data->thread;
        unsigned long flags;
        struct l_wait_info lwi = { 0 };
        ENTRY;

        lock_kernel();
        /* vv ptlrpc_daemonize(); vv */
        exit_mm(current);

        current->session = 1;
        current->pgrp = 1;
        current->tty = NULL;

        exit_files(current);
        reparent_to_init();
        /* ^^ ptlrpc_daemonize(); ^^ */

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20))
        sprintf(current->comm, "%s|%d", data->name,current->thread.extern_pid);
#elif defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        sprintf(current->comm, "%s|%d", data->name,
                current->thread.mode.tt.extern_pid);
#else
        strcpy(current->comm, data->name);
#endif
        unlock_kernel();

        /* Record that the thread is running */
        thread->t_flags = SVC_RUNNING;
        wake_up(&thread->t_ctl_waitq);

        /* And now, loop forever, pinging as needed. */
        l_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_STOPPING, &lwi);
        
        thread->t_flags = SVC_STOPPED;
        wake_up(&thread->t_ctl_waitq);

        CDEBUG(D_NET, "pinger thread exiting");
        return 0;
}

static int mgmtcli_connect_to_svc(struct obd_device *obd)
{
        int rc;
        struct mgmtcli_obd *mc = &obd->u.mgmtcli;
        struct ptlrpc_svc_data svc_data;
        struct ptlrpc_thread *thread;
        struct l_wait_info lwi = { 0 };
        ENTRY;

        /* Connect to ourselves, and thusly to the mgmt service. */
        rc = client_import_connect(&mc->mc_ping_handle, obd, &obd->obd_uuid);
        if (rc) {
                CERROR("failed to connect to mgmt svc: %d\n", rc);
                (void)client_obd_cleanup(obd, 0);
                RETURN(rc);
        }
        
        LASSERT(mc->mc_ping_thread == NULL);
        OBD_ALLOC(thread, sizeof (*thread));
        if (thread == NULL)
                RETURN(-ENOMEM);
        mc->mc_ping_thread = thread;
        init_waitqueue_head(&thread->t_ctl_waitq);

        svc_data.name = "mgmtcli";
        svc_data.thread = thread;

        rc = kernel_thread(mgmtcli_pinger_main, &svc_data, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("can't start thread to ping mgmt svc %s: %d\n",
                       mc->mc_import->imp_target_uuid.uuid, rc);
                OBD_FREE(mc->mc_ping_thread, sizeof (*mc->mc_ping_thread));
                (void)client_import_disconnect(&mc->mc_ping_handle, 0);
                RETURN(rc);
        }
        l_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_RUNNING, &lwi);
        
        RETURN(0);
}

static int mgmtcli_disconnect_from_svc(struct obd_device *obd)
{
        struct mgmtcli_obd *mc = &obd->u.mgmtcli;
        struct obd_import *imp = mc->mc_import;
        struct ptlrpc_thread *thread = mc->mc_ping_thread;
        struct l_wait_info lwi = { 0 };
        int rc;

        ENTRY;
        rc = client_import_disconnect(&mc->mc_ping_handle, 0);
        if (rc) {
                CERROR("can't disconnect from %s: %d (%s)\n",
                       imp->imp_target_uuid.uuid, rc,
                       (thread ? 
                        "stopping pinger thread anyway" :
                        "pinger thread already stopped"));
        }

        if (thread) {
                thread->t_flags = SVC_STOPPING;
                wake_up(&thread->t_ctl_waitq);
                l_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_STOPPED, &lwi);
                
                OBD_FREE(mc->mc_ping_thread, sizeof (*mc->mc_ping_thread));
        }

        RETURN(rc);
}

static int mgmtcli_register_for_events(struct obd_device *mgmt_obd,
                                       struct obd_device *notify_obd,
                                       struct obd_uuid *relevant_uuid)
{
        int start_thread;
        struct mgmtcli_registrant *reg;
        struct mgmtcli_obd *mcobd = &mgmt_obd->u.mgmtcli;

        ENTRY;
        if (strcmp(mgmt_obd->obd_type->typ_name, LUSTRE_MGMTCLI_NAME))
                RETURN(-EINVAL);

        OBD_ALLOC(reg, sizeof(*reg));
        if (reg == NULL)
                RETURN(-ENOMEM);

        reg->notify_obd = notify_obd;
        reg->relevant_uuid = relevant_uuid; /* XXX hash */

        spin_lock(&mgmt_obd->obd_dev_lock);
        start_thread = list_empty(&mcobd->mc_registered);
        list_add(&reg->chain, &mcobd->mc_registered);
        spin_unlock(&mgmt_obd->obd_dev_lock);

        if (start_thread)
                RETURN(mgmtcli_connect_to_svc(mgmt_obd));

        RETURN(0);
}

static int mgmtcli_deregister_for_events(struct obd_device *mgmt_obd,
                                         struct obd_device *notify_obd)
{
        int stop_thread, found = 0;
        struct mgmtcli_registrant *reg = NULL;
        struct list_head *tmp, *n;
        struct mgmtcli_obd *mc = &mgmt_obd->u.mgmtcli;

        ENTRY;
        if (strcmp(mgmt_obd->obd_type->typ_name, LUSTRE_MGMTCLI_NAME))
                RETURN(-EINVAL);

        spin_lock(&mgmt_obd->obd_dev_lock);
        list_for_each_safe(tmp, n, &mc->mc_registered) {
                reg = list_entry(tmp, struct mgmtcli_registrant, chain);
                if (reg->notify_obd == notify_obd) {
                        list_del(&reg->chain);
                        found = 1;
                        OBD_FREE(reg, sizeof(*reg));
                        break;
                }
        }
        spin_unlock(&mgmt_obd->obd_dev_lock);

        if (!found)
                RETURN(-ENOENT);
        RETURN(0);
}

/*** OBD scaffolding and module paraphernalia. ***/

static int mgmtcli_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct mgmtcli_obd *mc = &obd->u.mgmtcli;
        INIT_LIST_HEAD(&mc->mc_registered);
        
        /* Initialize our nested client_obd structure. */
        RETURN(client_obd_setup(obd, len, buf));
}

static int mgmtcli_cleanup(struct obd_device *obd, int flags)
{
        struct mgmtcli_obd *mc = &obd->u.mgmtcli;
        
        if (!list_empty(&mc->mc_registered))
                RETURN(-EBUSY);

        if (mc->mc_ping_thread) {
                rc = mgmtcli_disconnect_from_svc(obd);
                if (rc)
                        RETURN(rc);
        }

        RETURN(client_obd_cleanup(obd, flags);
}

static struct obd_ops mgmtcli_obd_ops = {
        o_owner:   THIS_MODULE,
        o_setup:   mgmtcli_setup,
        o_cleanup: client_obd_cleanup
};

static int __init mgmtcli_init(void)
{
        inter_module_register("mgmtcli_register_for_events", THIS_MODULE,
                              mgmtcli_register_for_events);
        inter_module_register("mgmtcli_deregister_for_events", THIS_MODULE,
                              mgmtcli_deregister_for_events);
        return class_register_type(&mgmtcli_obd_ops, 0, LUSTRE_MGMTCLI_NAME);
}

static void __exit mgmtcli_exit(void)
{
        class_unregister_type(LUSTRE_MGMTCLI_NAME);
        inter_module_unregister("mgmtcli_register_for_events");
        inter_module_unregister("mgmtcli_deregister_for_events");
}

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre monitoring client v0.1");
MODULE_LICENSE("GPL");

module_init(mgmtcli_init);
module_exit(mgmtcli_exit);
#endif
