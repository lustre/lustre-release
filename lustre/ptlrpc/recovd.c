/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  obd/rpc/recovd.c
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

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/kmod.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/obd_support.h>

void recovd_conn_manage(struct recovd_obd *recovd,
                        struct ptlrpc_connection *conn)
{
        ENTRY;
        conn->c_recovd = recovd;
        spin_lock(&recovd->recovd_lock);
        list_add(&conn->c_recovd_data.rd_managed_chain,
                 &recovd->recovd_managed_items);
        spin_unlock(&recovd->recovd_lock);
        EXIT;
}

void recovd_conn_fail(struct ptlrpc_connection *conn)
{
        ENTRY;
        spin_lock(&conn->c_recovd->recovd_lock);
        conn->c_recovd->recovd_flags |= RECOVD_FAIL;
        conn->c_recovd->recovd_wakeup_flag = 1;
        list_del(&conn->c_recovd_data.rd_managed_chain);
        list_add(&conn->c_recovd_data.rd_managed_chain, 
                 &conn->c_recovd->recovd_troubled_items);
        spin_unlock(&conn->c_recovd->recovd_lock);
        wake_up(&conn->c_recovd->recovd_waitq);
        EXIT;
}

/* this function must be called with conn->c_lock held */
void recovd_conn_fixed(struct ptlrpc_connection *conn)
{
        ENTRY;
        list_del(&conn->c_recovd_data.rd_managed_chain);
        list_add(&conn->c_recovd_data.rd_managed_chain,
                 &conn->c_recovd->recovd_managed_items);
        EXIT;
}


static int recovd_upcall(void)
{
        char *argv[2];
        char *envp[3];

        argv[0] = obd_recovery_upcall;
        argv[1] = NULL;

        envp [0] = "HOME=/";
        envp [1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp [2] = NULL;

        return call_usermodehelper(argv[0], argv, envp);
}

static int recovd_check_event(struct recovd_obd *recovd)
{
        int rc = 0;
        ENTRY;

        spin_lock(&recovd->recovd_lock);

        recovd->recovd_waketime = CURRENT_TIME;
        if (recovd->recovd_timeout) 
                schedule_timeout(recovd->recovd_timeout);

        if (recovd->recovd_wakeup_flag) {
                CERROR("service woken\n"); 
                GOTO(out, rc = 1);
        }

        if (recovd->recovd_timeout && 
            CURRENT_TIME > recovd->recovd_waketime + recovd->recovd_timeout) {
                recovd->recovd_flags |= RECOVD_TIMEOUT;
                CERROR("timeout\n");
                GOTO(out, rc = 1);
        }

        if (recovd->recovd_flags & RECOVD_STOPPING) {
                CERROR("recovd stopping\n");
                rc = 1;
        }

 out:
        recovd->recovd_wakeup_flag = 0;
        spin_unlock(&recovd->recovd_lock);
        RETURN(rc);
}

static int recovd_handle_event(struct recovd_obd *recovd)
{
        ENTRY;

        if (!(recovd->recovd_flags & RECOVD_UPCALL_WAIT) &&
            recovd->recovd_flags & RECOVD_FAIL) { 

                CERROR("client in trouble: flags -> UPCALL_WAITING\n");
                recovd->recovd_flags |= RECOVD_UPCALL_WAIT;

                recovd_upcall();
                recovd->recovd_waketime = CURRENT_TIME;
                recovd->recovd_timeout = 10 * HZ;
                schedule_timeout(recovd->recovd_timeout);
        }

        if (recovd->recovd_flags & RECOVD_TIMEOUT) { 
                CERROR("timeout - no news from upcall?\n");
                recovd->recovd_flags &= ~RECOVD_TIMEOUT;
        }

        if (recovd->recovd_flags & RECOVD_UPCALL_ANSWER) { 
                CERROR("UPCALL_WAITING: upcall answer\n");

                while (!list_empty(&recovd->recovd_troubled_items)) {
                        struct recovd_data *rd =
                                list_entry(recovd->recovd_troubled_items.next,
                                           struct recovd_data, rd_managed_chain);

                        list_del(&rd->rd_managed_chain);
                        if (rd->rd_recover) {
                                spin_unlock(&recovd->recovd_lock);
                                rd->rd_recover(rd);
                                spin_lock(&recovd->recovd_lock);
                        }
                }

                recovd->recovd_timeout = 0;
                recovd->recovd_flags = RECOVD_IDLE; 
        }

        RETURN(0);
}

static int recovd_main(void *arg)
{
        struct recovd_obd *recovd = (struct recovd_obd *)arg;

        ENTRY;

        lock_kernel();
        daemonize();
        spin_lock_irq(&current->sigmask_lock);
        sigfillset(&current->blocked);
        recalc_sigpending(current);
        spin_unlock_irq(&current->sigmask_lock);

        sprintf(current->comm, "lustre_recovd");
        spin_unlock();

        /* Record that the  thread is running */
        recovd->recovd_thread = current;
        recovd->recovd_flags = RECOVD_IDLE;
        wake_up(&recovd->recovd_ctl_waitq);

        /* And now, loop forever on requests */
        while (1) {
                wait_event(recovd->recovd_waitq, recovd_check_event(recovd));

                spin_lock(&recovd->recovd_lock);
                if (recovd->recovd_flags & RECOVD_STOPPING) {
                        spin_unlock(&recovd->recovd_lock);
                        CERROR("lustre_recovd stopping\n");
                        EXIT;
                        break;
                }

                recovd_handle_event(recovd);
                spin_unlock(&recovd->recovd_lock);
        }

        recovd->recovd_thread = NULL;
        recovd->recovd_flags = RECOVD_STOPPED;
        wake_up(&recovd->recovd_ctl_waitq);
        CDEBUG(D_NET, "mgr exiting process %d\n", current->pid);
        RETURN(0);
}

int recovd_setup(struct recovd_obd *recovd)
{
        int rc;
        extern void (*class_signal_connection_failure)
                (struct ptlrpc_connection *);

        ENTRY;

        INIT_LIST_HEAD(&recovd->recovd_managed_items);
        INIT_LIST_HEAD(&recovd->recovd_troubled_items);
        spin_lock_init(&recovd->recovd_lock);

        init_waitqueue_head(&recovd->recovd_waitq);
        init_waitqueue_head(&recovd->recovd_recovery_waitq);
        init_waitqueue_head(&recovd->recovd_ctl_waitq);

        rc = kernel_thread(recovd_main, (void *)recovd,
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread\n");
                RETURN(-EINVAL);
        }
        wait_event(recovd->recovd_ctl_waitq, recovd->recovd_flags & RECOVD_IDLE);

        /* exported and called by obdclass timeout handlers */
        class_signal_connection_failure = recovd_conn_fail;

        RETURN(0);
}

int recovd_cleanup(struct recovd_obd *recovd)
{
        spin_lock(&recovd->recovd_lock);
        recovd->recovd_flags = RECOVD_STOPPING;
        wake_up(&recovd->recovd_waitq);
        spin_unlock(&recovd->recovd_lock);

        wait_event(recovd->recovd_ctl_waitq,
                   (recovd->recovd_flags & RECOVD_STOPPED));
        RETURN(0);
}
