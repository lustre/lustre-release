/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/handler.c
 *
 *  Lustre Metadata Server (mds) request handler
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  by Peter Braam <braam@clusterfs.com>
 *
 *  This server is single threaded at present (but can easily be multi threaded)
 *
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
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

        
        return 1;
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

                spin_lock(&mgr->mgr_lock);
                schedule_timeout(5 * HZ); 
                if (mgr->mgr_flags & MGR_SIGNAL) {
                        spin_unlock(&mgr->mgr_lock);
                        EXIT;
                        break;
                }

                if (mgr->mgr_flags & MGR_STOPPING) {
                        spin_unlock(&mgr->mgr_lock);
                        EXIT;
                        break;
                }

                if (mgr->mgr_flags & MGR_EVENT) {
                        mgr->mgr_flags = MGR_RUNNING;

                        /* FIXME: If we move to an event-driven model,
                         * we should put the request on the stack of
                         * mds_handle instead. */
                        CERROR("MGR event\n"); 
                        continue;
                }

                CERROR("unknown break in service");
                spin_unlock(&mgr->mgr_lock);
                EXIT;
                break;
        }

        mgr->mgr_thread = NULL;
        mgr->mgr_flags = MGR_STOPPED;
        wake_up(&mgr->mgr_ctl_waitq);
        CDEBUG(D_NET, "mgr exiting process %d\n", current->pid);
        return 0;
}


int llite_ha_setup(struct obd_device *dev, struct lustre_ha_mgr *mgr,
                   char *name)
{
        struct lustre_ha_thread d;
        int rc;
        ENTRY;

        d.dev = dev;
        d.mgr = mgr;
        d.name = name;

        init_waitqueue_head(&mgr->mgr_waitq);

        init_waitqueue_head(&mgr->mgr_ctl_waitq);
        rc = kernel_thread(llite_ha_main, (void *) &d,
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread\n");
                RETURN(-EINVAL);
        }
        wait_event(mgr->mgr_ctl_waitq, mgr->mgr_flags & MGR_RUNNING);

        RETURN(0);
}


int llite_ha_cleanup(struct lustre_ha_mgr *mgr)
{
        mgr->mgr_flags = MGR_STOPPING;

        wake_up(&mgr->mgr_waitq);
        wait_event_interruptible(mgr->mgr_ctl_waitq,
                                 (mgr->mgr_flags & MGR_STOPPED));
        return 0;
}
