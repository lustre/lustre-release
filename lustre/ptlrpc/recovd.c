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
                return;
        }

        spin_lock(&recovd->recovd_lock);
        list_del(&rd->rd_managed_chain);
        list_add_tail(&rd->rd_managed_chain, &recovd->recovd_troubled_items);
        spin_unlock(&recovd->recovd_lock);

        wake_up(&recovd->recovd_waitq);

        EXIT;
}

/* this function must be called with conn->c_lock held */
void recovd_conn_fixed(struct ptlrpc_connection *conn)
{
        struct recovd_data *rd = &conn->c_recovd_data;
        ENTRY;

        list_del(&rd->rd_managed_chain);
        list_add(&rd->rd_managed_chain, &rd->rd_recovd->recovd_managed_items);

        EXIT;
}


static int recovd_check_event(struct recovd_obd *recovd)
{
        int rc = 0;
        ENTRY;

        spin_lock(&recovd->recovd_lock);

        if (recovd->recovd_phase == RECOVD_IDLE &&
            !list_empty(&recovd->recovd_troubled_items)) {
                GOTO(out, rc = 1);
        }

        if (recovd->recovd_flags & RECOVD_STOPPING)
                GOTO(out, rc = 1);

        if (recovd->recovd_flags & RECOVD_FAILED) {
                LASSERT(recovd->recovd_phase != RECOVD_IDLE && 
                        recovd->recovd_current_rd);
                GOTO(out, rc = 1);
        }

        if (recovd->recovd_phase == recovd->recovd_next_phase)
                GOTO(out, rc = 1);

 out:
        spin_unlock(&recovd->recovd_lock);
        RETURN(rc);
}

static int recovd_handle_event(struct recovd_obd *recovd)
{
        struct recovd_data *rd;
        int rc;
        ENTRY;

        if (recovd->recovd_flags & RECOVD_FAILED) {

                LASSERT(recovd->recovd_phase != RECOVD_IDLE && 
                        recovd->recovd_current_rd);

                rd = recovd->recovd_current_rd;
        cb_failed:
                CERROR("recovery FAILED for rd %p (conn %p), recovering\n",
                       rd, class_rd2conn(rd));

                list_add(&rd->rd_managed_chain, &recovd->recovd_managed_items);
                spin_unlock(&recovd->recovd_lock);
                rd->rd_recover(rd, PTLRPC_RECOVD_PHASE_FAILURE);
                spin_lock(&recovd->recovd_lock);
                recovd->recovd_phase = RECOVD_IDLE;
                recovd->recovd_next_phase = RECOVD_PREPARING;
                
                recovd->recovd_flags &= ~RECOVD_FAILED;

                RETURN(1);
        }

        switch (recovd->recovd_phase) {
            case RECOVD_IDLE:
                if (recovd->recovd_current_rd ||
                    list_empty(&recovd->recovd_troubled_items))
                        break;
                rd = list_entry(recovd->recovd_troubled_items.next,
                                struct recovd_data, rd_managed_chain);
                
                list_del(&rd->rd_managed_chain);
                if (!rd->rd_recover)
                        LBUG();

                CERROR("starting recovery for rd %p (conn %p)\n",
                       rd, class_rd2conn(rd));
                recovd->recovd_current_rd = rd;
                recovd->recovd_flags &= ~RECOVD_FAILED;
                recovd->recovd_phase = RECOVD_PREPARING;

                spin_unlock(&recovd->recovd_lock);
                rc = rd->rd_recover(rd, PTLRPC_RECOVD_PHASE_PREPARE);
                spin_lock(&recovd->recovd_lock);
                if (rc)
                        goto cb_failed;
                
                recovd->recovd_next_phase = RECOVD_PREPARED;
                break;

            case RECOVD_PREPARED:
                rd = recovd->recovd_current_rd;
                recovd->recovd_phase = RECOVD_RECOVERING;

                CERROR("recovery prepared for rd %p (conn %p), recovering\n",
                       rd, class_rd2conn(rd));

                spin_unlock(&recovd->recovd_lock);
                rc = rd->rd_recover(rd, PTLRPC_RECOVD_PHASE_RECOVER);
                spin_lock(&recovd->recovd_lock);
                if (rc)
                        goto cb_failed;
                
                recovd->recovd_next_phase = RECOVD_RECOVERED;
                break;

            case RECOVD_RECOVERED:
                rd = recovd->recovd_current_rd;
                recovd->recovd_phase = RECOVD_IDLE;
                recovd->recovd_next_phase = RECOVD_PREPARING;

                CERROR("recovery complete for rd %p (conn %p), recovering\n",
                       rd, class_rd2conn(rd));
                break;

            default:
                break;
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
        unlock_kernel();

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

        recovd->recovd_next_phase = RECOVD_PREPARING;
        
        rc = kernel_thread(recovd_main, (void *)recovd,
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread\n");
                RETURN(-EINVAL);
        }
        wait_event(recovd->recovd_ctl_waitq,
                   recovd->recovd_phase == RECOVD_IDLE);

        /* exported and called by obdclass timeout handlers */
        class_signal_connection_failure = recovd_conn_fail;
        ptlrpc_recovd = recovd;

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

struct recovd_obd *ptlrpc_recovd;
