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

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/obd_support.h>

void recovd_conn_manage(struct ptlrpc_connection *conn,
                        struct recovd_obd *recovd, ptlrpc_recovery_cb_t recover)
{
        struct recovd_data *rd = &conn->c_recovd_data;
        ENTRY;

        rd->rd_recovd = recovd;
        rd->rd_recover = recover;
        rd->rd_phase = RD_IDLE;
        rd->rd_next_phase = RD_TROUBLED;

        spin_lock(&recovd->recovd_lock);
        list_add(&rd->rd_managed_chain, &recovd->recovd_managed_items);
        spin_unlock(&recovd->recovd_lock);

        EXIT;
}

void recovd_conn_fail(struct ptlrpc_connection *conn)
{
        struct recovd_data *rd = &conn->c_recovd_data;
        struct recovd_obd *recovd = rd->rd_recovd;
        ENTRY;

        if (!recovd) {
                CERROR("no recovd for connection %p\n", conn);
                EXIT;
                return;
        }


        spin_lock(&recovd->recovd_lock);
        if (rd->rd_phase != RD_IDLE) {
                CERROR("connection %p to %s already in recovery\n",
                       conn, conn->c_remote_uuid);
                /* XXX need to distinguish from failure-in-recovery */
                spin_unlock(&recovd->recovd_lock);
                EXIT;
                return;
        }
                
        CERROR("connection %p to %s failed\n", conn, conn->c_remote_uuid);
        list_del(&rd->rd_managed_chain);
        list_add_tail(&rd->rd_managed_chain, &recovd->recovd_troubled_items);
        rd->rd_phase = RD_TROUBLED;
        spin_unlock(&recovd->recovd_lock);

        wake_up(&recovd->recovd_waitq);

        EXIT;
}

/* this function must be called with recovd->recovd_lock held */
void recovd_conn_fixed(struct ptlrpc_connection *conn)
{
        struct recovd_data *rd = &conn->c_recovd_data;
        ENTRY;

        spin_lock(&rd->rd_recovd->recovd_lock);
        list_del(&rd->rd_managed_chain);
        rd->rd_phase = RD_IDLE;
        rd->rd_next_phase = RD_TROUBLED;
        list_add(&rd->rd_managed_chain, &rd->rd_recovd->recovd_managed_items);
        spin_unlock(&rd->rd_recovd->recovd_lock);

        EXIT;
}


static int recovd_check_event(struct recovd_obd *recovd)
{
        int rc = 0;
        struct list_head *tmp;

        ENTRY;

        spin_lock(&recovd->recovd_lock);

        if (recovd->recovd_state == RECOVD_STOPPING)
                GOTO(out, rc = 1);

        list_for_each(tmp, &recovd->recovd_troubled_items) {

                struct recovd_data *rd = list_entry(tmp, struct recovd_data,
                                                    rd_managed_chain);

                if (rd->rd_phase == rd->rd_next_phase ||
                    rd->rd_phase == RD_FAILED)
                        GOTO(out, rc = 1);
        }

 out:
        spin_unlock(&recovd->recovd_lock);
        RETURN(rc);
}

static void dump_connection_list(struct list_head *head)
{
        struct list_head *tmp;

        list_for_each(tmp, head) {
                struct ptlrpc_connection *conn =
                        list_entry(tmp, struct ptlrpc_connection,
                                   c_recovd_data.rd_managed_chain);
                CERROR("   %p = %s (%d/%d)\n", conn, conn->c_remote_uuid,
                       conn->c_recovd_data.rd_phase,
                       conn->c_recovd_data.rd_next_phase);
        }
}

static int recovd_handle_event(struct recovd_obd *recovd)
{
        struct list_head *tmp, *n;
        int rc = 0;
        ENTRY;

        spin_lock(&recovd->recovd_lock);

        CERROR("managed: \n");
        dump_connection_list(&recovd->recovd_managed_items);
        CERROR("troubled: \n");
        dump_connection_list(&recovd->recovd_troubled_items);

        /*
         * We use _safe here because one of the callbacks, expecially
         * FAILURE or PREPARED, could move list items around.
         */
        list_for_each_safe(tmp, n, &recovd->recovd_troubled_items) {
                struct recovd_data *rd = list_entry(tmp, struct recovd_data,
                                                    rd_managed_chain);

                if (rd->rd_phase != RD_FAILED &&
                    rd->rd_phase != rd->rd_next_phase)
                        continue;

                switch (rd->rd_phase) {
                    case RD_FAILED:
                cb_failed: /* must always reach here with recovd_lock held! */
                        CERROR("recovery FAILED for rd %p (conn %p): %d\n",
                               rd, class_rd2conn(rd), rc);
                        
                        spin_unlock(&recovd->recovd_lock);
                        (void)rd->rd_recover(rd, PTLRPC_RECOVD_PHASE_FAILURE);
                        spin_lock(&recovd->recovd_lock);
                        break;
                        
                    case RD_TROUBLED:
                        if (!rd->rd_recover) {
                                CERROR("no rd_recover for rd %p (conn %p)\n",
                                       rd, class_rd2conn(rd));
                                rc = -EINVAL;
                                break;
                        }
                        CERROR("starting recovery for rd %p (conn %p)\n",
                               rd, class_rd2conn(rd));
                        rd->rd_phase = RD_PREPARING;
                        
                        spin_unlock(&recovd->recovd_lock);
                        rc = rd->rd_recover(rd, PTLRPC_RECOVD_PHASE_PREPARE);
                        spin_lock(&recovd->recovd_lock);
                        if (rc)
                                goto cb_failed;
                        
                        rd->rd_next_phase = RD_PREPARED;
                        break;
                        
                    case RD_PREPARED:
                        rd->rd_phase = RD_RECOVERING;
                        
                        CERROR("recovery prepared for rd %p (conn %p)\n",
                               rd, class_rd2conn(rd));
                        
                        spin_unlock(&recovd->recovd_lock);
                        rc = rd->rd_recover(rd, PTLRPC_RECOVD_PHASE_RECOVER);
                        spin_lock(&recovd->recovd_lock);
                        if (rc)
                                goto cb_failed;
                        
                        rd->rd_next_phase = RD_RECOVERED;
                        break;
                        
                    case RD_RECOVERED:
                        rd->rd_phase = RD_IDLE;
                        rd->rd_next_phase = RD_TROUBLED;
                        
                        CERROR("recovery complete for rd %p (conn %p)\n",
                               rd, class_rd2conn(rd));
                        break;
                        
                    default:
                        break;
                }
        }
        spin_unlock(&recovd->recovd_lock);
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
        unlock_kernel();

        /* Signal that the thread is running. */
        recovd->recovd_thread = current;
        recovd->recovd_state = RECOVD_READY;
        wake_up(&recovd->recovd_ctl_waitq);

        /* And now, loop forever on requests. */
        while (1) {
                wait_event(recovd->recovd_waitq, recovd_check_event(recovd));
                if (recovd->recovd_state == RECOVD_STOPPING)
                        break;
                recovd_handle_event(recovd);
        }

        recovd->recovd_thread = NULL;
        recovd->recovd_state = RECOVD_STOPPED;
        wake_up(&recovd->recovd_ctl_waitq);
        CDEBUG(D_NET, "mgr exiting process %d\n", current->pid);
        RETURN(0);
}

int recovd_setup(struct recovd_obd *recovd)
{
        int rc;

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
        wait_event(recovd->recovd_ctl_waitq,
                   recovd->recovd_state == RECOVD_READY);

        ptlrpc_recovd = recovd;

        RETURN(0);
}

int recovd_cleanup(struct recovd_obd *recovd)
{
        spin_lock(&recovd->recovd_lock);
        recovd->recovd_state = RECOVD_STOPPING;
        wake_up(&recovd->recovd_waitq);
        spin_unlock(&recovd->recovd_lock);

        wait_event(recovd->recovd_ctl_waitq,
                   (recovd->recovd_state == RECOVD_STOPPED));
        RETURN(0);
}

struct recovd_obd *ptlrpc_recovd;
