/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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
 *
 * OST<->MDS recovery logging thread.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/fs.h>
#include <linux/obd_class.h>
#include <linux/lustre_commit_confd.h>
#include <portals/list.h>

/* Allocate new commit structs in case we do not have enough */
static int llcd_alloc(struct llog_commit_master *lcm)
{
        struct llog_commit_data *llcd;

        OBD_ALLOC(llcd, PAGE_SIZE);
        if (!llcd)
                return -ENOMEM;

        llcd->llcd_lcm = lcm;

        spin_lock(&lcm->lcm_llcd_lock);
        list_add(&llcd->llcd_list, &lcm->lcm_llcd_free);
        atomic_inc(&lcm->lcm_llcd_numfree);
        spin_unlock(&lcm->lcm_llcd_lock);

        return 0;
}

/* Get a free cookie struct from the list */
struct llog_commit_data *llcd_grab(struct llog_commit_master *lcm)
{
        struct llog_commit_data *llcd;

        spin_lock(&lcm->lcm_llcd_lock);
        if (list_empty(&lcm->lcm_llcd_free)) {
                spin_unlock(&lcm->lcm_llcd_lock);
                CERROR("no free log commit data structs!\n");
                llcd = kmalloc(GFP_ATOMIC, PAGE_SIZE);
                if (llcd)
                        llcd->llcd_lcm = lcm;
                return llcd;
        }

        llcd = list_entry(&lcm->lcm_llcd_free.next, typeof(*llcd), llcd_list);
        list_del(&llcd->llcd_list);
        atomic_dec(&lcm->lcm_llcd_numfree);
        spin_unlock(&lcm->lcm_llcd_lock);

        llcd->llcd_tries = 0;
        llcd->llcd_cookiebytes = 0;

        return llcd;
}
EXPORT_SYMBOL(llcd_grab);

static void llcd_put(struct llog_commit_master *lcm,
                     struct llog_commit_data *llcd)
{
        if (atomic_read(&lcm->lcm_llcd_numfree) >= lcm->lcm_llcd_maxfree) {
                OBD_FREE(llcd, PAGE_SIZE);
        } else {
                spin_lock(&lcm->lcm_llcd_lock);
                list_add(&llcd->llcd_list, &lcm->lcm_llcd_free);
                atomic_inc(&lcm->lcm_llcd_numfree);
                spin_unlock(&lcm->lcm_llcd_lock);
        }
}

/* Send some cookies to the appropriate target */
void llcd_send(struct llog_commit_data *llcd)
{
        spin_lock(&llcd->llcd_lcm->lcm_llcd_lock);
        list_add_tail(&llcd->llcd_list, &llcd->llcd_lcm->lcm_llcd_pending);
        spin_unlock(&llcd->llcd_lcm->lcm_llcd_lock);

        wake_up_nr(&llcd->llcd_lcm->lcm_waitq, 1);
}
EXPORT_SYMBOL(llcd_send);

static int log_commit_thread(void *arg)
{
        struct llog_commit_master *lcm = arg;
        struct llog_commit_daemon *lcd;
        struct llog_commit_data *llcd, *n;
        long flags;
        int rc;

        OBD_ALLOC(lcd, sizeof(*lcd));
        if (!lcd)
                RETURN(-ENOMEM);

        INIT_LIST_HEAD(&lcd->lcd_lcm_list);
        INIT_LIST_HEAD(&lcd->lcd_llcd_list);
        lcd->lcd_lcm = lcm;

        lock_kernel();
	daemonize(); /* thread never needs to do IO */

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        spin_lock(lcm->lcm_thread_lock);
	THREAD_NAME(current->comm, "ll_log_commit_%d", lcm->lcm_thread_total++);
        spin_unlock(lcm->lcm_thread_lock);
        unlock_kernel();

        CDEBUG(D_HA, "%s started\n", current->comm);
        do {
                struct ptlrpc_request *request;
                struct lustre_handle *conn;
                struct list_head *sending_list;

                /* If we do not have enough pages available, allocate some */
                while (atomic_read(&lcm->lcm_llcd_numfree) <
                       lcm->lcm_llcd_minfree) {
                        if (llcd_alloc(lcm) < 0)
                                break;
                }

                spin_lock(lcm->lcm_thread_lock);
                atomic_inc(&lcm->lcm_thread_numidle);
                list_move(&lcd->lcd_lcm_list, &lcm->lcm_thread_idle);
                spin_unlock(lcm->lcm_thread_lock);

                wait_event_interruptible(lcm->lcm_waitq,
                                         !list_empty(&lcm->lcm_llcd_pending) ||
                                         lcm->lcm_flags & LLOG_LCM_FL_EXIT);

                /* If we are the last available thread, start a new one in case
                 * we get blocked on an RPC (nobody else will start a new one).
                 */
                spin_lock(lcm->lcm_thread_lock);
                atomic_dec(&lcm->lcm_thread_numidle);
                list_move(&lcd->lcd_lcm_list, &lcm->lcm_thread_busy);
                spin_unlock(lcm->lcm_thread_lock);

                sending_list = &lcm->lcm_llcd_pending;
        resend:
                if (lcm->lcm_flags & LLOG_LCM_FL_EXIT) {
                        lcm->lcm_llcd_maxfree = 0;
                        lcm->lcm_llcd_minfree = 0;
                        lcm->lcm_thread_max = 0;

                        if (list_empty(&lcm->lcm_llcd_pending) ||
                            lcm->lcm_flags & LLOG_LCM_FL_EXIT_FORCE)
                                break;
                }

                if (atomic_read(&lcm->lcm_thread_numidle) <= 1 &&
                    atomic_read(&lcm->lcm_thread_numidle) <
                    lcm->lcm_thread_max) {
                        rc = llog_start_commit_thread(lcm);
                        if (rc < 0)
                                CERROR("error starting thread: rc %d\n", rc);
                }

                /* Move all of the pending cancels from the same OST off of
                 * the list, so we don't get multiple threads blocked and/or
                 * doing upcalls on the same OST in case failure.
                 */
                spin_lock(&lcm->lcm_llcd_lock);
                if (!list_empty(sending_list)) {
                        list_move(sending_list, &lcd->lcd_llcd_list);
                        llcd = list_entry(&lcd->lcd_llcd_list.next,
                                          typeof(*llcd), llcd_list);
                        conn = llcd->llcd_conn;
                }
                list_for_each_entry_safe(llcd, n, sending_list, llcd_list) {
                        if (conn == llcd->llcd_conn)
                                list_move_tail(&llcd->llcd_list, sending_list);
                }
                if (sending_list != &lcm->lcm_llcd_resend) {
                        list_for_each_entry_safe(llcd, n, &lcm->lcm_llcd_resend,
                                                 llcd_list) {
                                if (conn == llcd->llcd_conn)
                                        list_move_tail(&llcd->llcd_list,
                                                       &lcm->lcm_llcd_resend);
                        }
                }
                spin_unlock(&lcm->lcm_llcd_lock);

                /* We are the only one manipulating our local list - no lock */
                list_for_each_entry_safe(llcd,n, &lcd->lcd_llcd_list,llcd_list){
                        list_del(&llcd->llcd_list);

                        request = ptlrpc_prep_req(class_conn2cliimp(conn),
                                                  OST_LOG_CANCEL, 1,
                                                  &llcd->llcd_cookiebytes,
                                                  (char **)&llcd->llcd_cookies);
                        if (request == NULL) {
                                rc = -ENOMEM;
                                CERROR("error preparing commit: rc %d\n", rc);

                                spin_lock(&lcm->lcm_llcd_lock);
                                list_splice(&lcd->lcd_llcd_list,
                                            &lcm->lcm_llcd_resend);
                                spin_unlock(&lcm->lcm_llcd_lock);
                                break;
                        }

                        request->rq_replen = lustre_msg_size(0, NULL);
                        rc = ptlrpc_queue_wait(request);

                        /* If the RPC failed, we put this and the remaining
                         * messages onto the resend list for another time.
                         */
                        if (rc) {
                                spin_lock(&lcm->lcm_llcd_lock);
                                list_splice(&lcd->lcd_llcd_list,
                                            &lcm->lcm_llcd_resend);
                                if (++llcd->llcd_tries < 5) {
                                        CERROR("commit %p failed %dx: rc %d\n",
                                               llcd, llcd->llcd_tries, rc);

                                        list_add_tail(&llcd->llcd_list,
                                                      &lcm->lcm_llcd_resend);
                                        spin_unlock(&lcm->lcm_llcd_lock);
                                } else {
                                        spin_unlock(&lcm->lcm_llcd_lock);
                                        CERROR("commit %p dropped %d cookies: "
                                               "rc %d\n", llcd,
                                               llcd->llcd_cookiebytes /
                                               sizeof(*llcd->llcd_cookies), rc);
                                       llcd_put(lcm, llcd);
                                }
                                break;
                        } else
                                llcd_put(lcm, llcd);
                        ptlrpc_req_finished(request);
                }

                if (rc == 0) {
                        sending_list = &lcm->lcm_llcd_resend;
                        if (!list_empty(sending_list))
                                goto resend;
                }
        } while(1);

        /* If we are force exiting, just drop all of the cookies. */
        if (lcm->lcm_flags & LLOG_LCM_FL_EXIT_FORCE) {
                spin_lock(&lcm->lcm_llcd_lock);
                list_splice(&lcm->lcm_llcd_pending,&lcd->lcd_llcd_list);
                list_splice(&lcm->lcm_llcd_resend, &lcd->lcd_llcd_list);
                list_splice(&lcm->lcm_llcd_free, &lcd->lcd_llcd_list);
                spin_unlock(&lcm->lcm_llcd_lock);

                list_for_each_entry_safe(llcd, n, &lcd->lcd_llcd_list,llcd_list)
                        llcd_put(lcm, llcd);
        }

        CDEBUG(D_HA, "%s exiting\n", current->comm);
        OBD_FREE(lcd, sizeof(*lcd));
        return 0;
}

int llog_start_commit_thread(struct llog_commit_master *lcm)
{
        int rc;
        ENTRY;

	rc = kernel_thread(log_commit_thread, lcm, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("error starting thread #%d: %d\n", lcm->lcm_thread_total,
                       rc);
                RETURN(rc);
        }

        RETURN(0);
}
EXPORT_SYMBOL(llog_start_commit_thread);
