/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  The daemon that causes completed but not committed transactions 
 *   on the MDS to be flushed periodically when they are committed.
 *   A gratuitous getattr RPC is made to the MDS to discover the 
 *   last committed record. 
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
#include <linux/lustre_lib.h>

static int ll_commitcbd_check_event(struct ll_sb_info *sbi)
{
        int rc = 0; 
        ENTRY;

        spin_lock(&sbi->ll_commitcbd_lock); 
        if (sbi->ll_commitcbd_flags & LL_COMMITCBD_STOPPING) { 
                GOTO(out, rc = 1);
        }

 out:
        spin_unlock(&sbi->ll_commitcbd_lock);
        RETURN(rc);
}

static int ll_commitcbd_main(void *arg)
{
        struct ll_sb_info *sbi = (struct ll_sb_info *)arg;

        ENTRY;

        lock_kernel();
        daemonize();
        spin_lock_irq(&current->sigmask_lock);
        sigfillset(&current->blocked);
        recalc_sigpending(current);
        spin_unlock_irq(&current->sigmask_lock);

        sprintf(current->comm, "lustre_commitcbd");

        /* Record that the  thread is running */
        sbi->ll_commitcbd_waketime = CURRENT_TIME;
        sbi->ll_commitcbd_timeout = 10 * HZ;
        sbi->ll_commitcbd_thread = current;
        sbi->ll_commitcbd_flags =  LL_COMMITCBD_RUNNING;
        wake_up(&sbi->ll_commitcbd_ctl_waitq);

        /* And now, loop forever on requests */
        while (1) {
                wait_event(sbi->ll_commitcbd_waitq, 
                           ll_commitcbd_check_event(sbi));

                spin_lock(&sbi->ll_commitcbd_lock);
                if (sbi->ll_commitcbd_flags & LL_COMMITCBD_STOPPING) {
                        spin_unlock(&sbi->ll_commitcbd_lock);
                        CERROR("lustre_commitd quitting\n"); 
                        EXIT;
                        break;
                }

                schedule_timeout(sbi->ll_commitcbd_timeout);
                CERROR("commit callback daemon woken up - FIXME\n"); 
                spin_unlock(&sbi->ll_commitcbd_lock);
        }

        sbi->ll_commitcbd_thread = NULL;
        sbi->ll_commitcbd_flags = LL_COMMITCBD_STOPPED;
        wake_up(&sbi->ll_commitcbd_ctl_waitq);
        CDEBUG(D_NET, "commit callback daemon exiting %d\n", current->pid);
        RETURN(0);
}



int ll_commitcbd_setup(struct ll_sb_info *sbi)
{
        int rc;
        ENTRY;

        rc = kernel_thread(ll_commitcbd_main, (void *) sbi,
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread\n");
                RETURN(rc);
        }
        wait_event(sbi->ll_commitcbd_ctl_waitq, 
                   sbi->ll_commitcbd_flags & LL_COMMITCBD_RUNNING);
        RETURN(0);
}


int ll_commitcbd_cleanup(struct ll_sb_info *sbi)
{
        sbi->ll_commitcbd_flags = LL_COMMITCBD_STOPPING;

        wake_up(&sbi->ll_commitcbd_waitq);
        wait_event(sbi->ll_commitcbd_ctl_waitq,
                   sbi->ll_commitcbd_flags & LL_COMMITCBD_STOPPED);
        RETURN(0);
}
