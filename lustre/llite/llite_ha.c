/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/handler.c
 *
 *  Lustre High Availability Daemon
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  by Peter Braam <braam@clusterfs.com>
 *
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/kmod.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>

static int lustre_ha_check_event(struct lustre_ha_mgr *mgr)
{
        int rc = 0; 
        ENTRY;

        spin_lock(&mgr->mgr_lock); 
        if (!(mgr->mgr_flags & MGR_WORKING) && 
            !list_empty(&mgr->mgr_troubled_lh) ) {
                mgr->mgr_flags |= MGR_WORKING;
                mgr->mgr_waketime = CURRENT_TIME; 
                schedule_timeout(4*HZ); 
                CERROR("connection in trouble\n"); 
                rc = 1;
        }

        if (!mgr->mgr_flags & MGR_WORKING &&
            CURRENT_TIME >= mgr->mgr_waketime ) { 
                CERROR("woken up once more\n");
                mgr->mgr_waketime = CURRENT_TIME; 
                schedule_timeout(4*HZ); 
                rc = 1;
        }

        if (mgr->mgr_flags & MGR_STOPPING) { 
                CERROR("ha mgr stopping\n");
                rc = 1;
        }

        spin_unlock(&mgr->mgr_lock); 
        RETURN(rc);
}


static int llite_ha_upcall(void)
{
        char *argv[2];
        char *envp[3];

        argv[0] = "/usr/src/obd/utils/ha_assist.sh";
        argv[1] = NULL;

        envp [0] = "HOME=/";
        envp [1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp [2] = NULL;

        return call_usermodehelper(argv[0], argv, envp);
}

static int llite_ha_main(void *arg)
{
        struct lustre_ha_thread *data = (struct lustre_ha_thread *)arg;
        struct lustre_ha_mgr *mgr = data->mgr;

        ENTRY;

        lock_kernel();
        daemonize();
        spin_lock_irq(&current->sigmask_lock);
        sigfillset(&current->blocked);
        recalc_sigpending(current);
        spin_unlock_irq(&current->sigmask_lock);

        sprintf(current->comm, data->name);

        /* Record that the  thread is running */
        mgr->mgr_thread = current;
        mgr->mgr_flags = MGR_RUNNING;
        wake_up(&mgr->mgr_ctl_waitq);

        /* And now, loop forever on requests */
        while (1) {
                wait_event_interruptible(mgr->mgr_waitq, 
                                         lustre_ha_check_event(mgr));

                if (mgr->mgr_flags & MGR_STOPPING) {
                        spin_unlock(&mgr->mgr_lock);
                        CERROR("lustre_hamgr quitting\n"); 
                        EXIT;
                        break;
                }

                spin_lock(&mgr->mgr_lock);
                CERROR("lustre_hamgr woken up\n"); 
                llite_ha_upcall();
                schedule_timeout(5 * HZ);
                spin_unlock(&mgr->mgr_lock);
        }

        mgr->mgr_thread = NULL;
        mgr->mgr_flags = MGR_STOPPED;
        wake_up(&mgr->mgr_ctl_waitq);
        CDEBUG(D_NET, "mgr exiting process %d\n", current->pid);
        RETURN(0);
}

struct lustre_ha_mgr *llite_ha_setup(void)
{
        struct lustre_ha_thread d;
        struct lustre_ha_mgr *mgr;
        int rc;
        ENTRY;

        PORTAL_ALLOC(mgr, sizeof(*mgr));
        if (!mgr) { 
                CERROR("out of memory\n");
                LBUG();
                RETURN(NULL); 
        }
        INIT_LIST_HEAD(&mgr->mgr_connections_lh);
        INIT_LIST_HEAD(&mgr->mgr_troubled_lh);
        spin_lock_init(&mgr->mgr_lock); 

        d.mgr = mgr;
        d.name = "lustre_hamgr";

        init_waitqueue_head(&mgr->mgr_waitq);
        init_waitqueue_head(&mgr->mgr_ctl_waitq);

        rc = kernel_thread(llite_ha_main, (void *) &d,
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread\n");
                RETURN(NULL);
        }
        wait_event(mgr->mgr_ctl_waitq, mgr->mgr_flags & MGR_RUNNING);

        RETURN(mgr);
}


int llite_ha_cleanup(struct lustre_ha_mgr *mgr)
{
        mgr->mgr_flags = MGR_STOPPING;

        wake_up(&mgr->mgr_waitq);
        wait_event_interruptible(mgr->mgr_ctl_waitq,
                                 (mgr->mgr_flags & MGR_STOPPED));
        PORTAL_FREE(mgr, sizeof(*mgr));
        RETURN(0);
}
