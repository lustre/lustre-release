/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2003 Cluster File Systems, Inc.
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
# define EXPORT_SYMTAB
#endif

#ifdef __KERNEL__
#include <linux/fs.h>
#else
# include <portals/list.h>
# include <liblustre.h>
#endif

#include <linux/kp30.h>
#include <linux/obd_class.h>
#include <linux/lustre_commit_confd.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <portals/types.h>
#include <portals/list.h>
#include <linux/lustre_log.h>
#include "ptlrpc_internal.h"

#ifdef __KERNEL__

static struct llog_commit_master lustre_lcm;
static struct llog_commit_master *lcm = &lustre_lcm;

/* Allocate new commit structs in case we do not have enough */
static int llcd_alloc(void)
{
        struct llog_canceld_ctxt *llcd;
        int offset = offsetof(struct llog_canceld_ctxt, llcd_cookies);

        OBD_ALLOC(llcd, PAGE_SIZE + offset);
        if (llcd == NULL)
                return -ENOMEM;

        llcd->llcd_lcm = lcm;

        spin_lock(&lcm->lcm_llcd_lock);
        list_add(&llcd->llcd_list, &lcm->lcm_llcd_free);
        atomic_inc(&lcm->lcm_llcd_numfree);
        spin_unlock(&lcm->lcm_llcd_lock);

        return 0;
}

/* Get a free cookie struct from the list */
struct llog_canceld_ctxt *llcd_grab(void)
{
        struct llog_canceld_ctxt *llcd;

        spin_lock(&lcm->lcm_llcd_lock);
        if (list_empty(&lcm->lcm_llcd_free)) {
                spin_unlock(&lcm->lcm_llcd_lock);
                if (llcd_alloc() < 0) {
                        CERROR("unable to allocate log commit data!\n");
                        return NULL;
                }
                spin_lock(&lcm->lcm_llcd_lock);
        }

        llcd = list_entry(lcm->lcm_llcd_free.next, typeof(*llcd), llcd_list);
        list_del(&llcd->llcd_list);
        atomic_dec(&lcm->lcm_llcd_numfree);
        spin_unlock(&lcm->lcm_llcd_lock);

        llcd->llcd_tries = 0;
        llcd->llcd_cookiebytes = 0;

        return llcd;
}
EXPORT_SYMBOL(llcd_grab);

static void llcd_put(struct llog_canceld_ctxt *llcd)
{
        int offset = offsetof(struct llog_canceld_ctxt, llcd_cookies);

        if (atomic_read(&lcm->lcm_llcd_numfree) >= lcm->lcm_llcd_maxfree) {
                OBD_FREE(llcd, PAGE_SIZE + offset);
        } else {
                spin_lock(&lcm->lcm_llcd_lock);
                list_add(&llcd->llcd_list, &lcm->lcm_llcd_free);
                atomic_inc(&lcm->lcm_llcd_numfree);
                spin_unlock(&lcm->lcm_llcd_lock);
        }
}

/* Send some cookies to the appropriate target */
void llcd_send(struct llog_canceld_ctxt *llcd)
{
        spin_lock(&llcd->llcd_lcm->lcm_llcd_lock);
        list_add_tail(&llcd->llcd_list, &llcd->llcd_lcm->lcm_llcd_pending);
        spin_unlock(&llcd->llcd_lcm->lcm_llcd_lock);

        wake_up_nr(&llcd->llcd_lcm->lcm_waitq, 1);
}
EXPORT_SYMBOL(llcd_send);

/* deleted objects have a commit callback that cancels the MDS
 * log record for the deletion.  The commit callback calls this 
 * function 
 */
int llog_obd_repl_cancel(struct llog_ctxt *ctxt,
                         struct lov_stripe_md *lsm, int count,
                         struct llog_cookie *cookies, int flags)
{
        struct llog_canceld_ctxt *llcd;
        int rc = 0;
        ENTRY;

        LASSERT(ctxt);

        if (count == 0 || cookies == NULL) {
                down(&ctxt->loc_sem);
                if (ctxt->loc_llcd == NULL || !(flags & OBD_LLOG_FL_SENDNOW))
                        GOTO(out, rc);

                llcd = ctxt->loc_llcd;
                GOTO(send_now, rc);
        }

        down(&ctxt->loc_sem);
        llcd = ctxt->loc_llcd;
        if (llcd == NULL) {
                llcd = llcd_grab();
                if (llcd == NULL) {
                        CERROR("couldn't get an llcd - dropped "LPX64":%x+%u\n",
                               cookies->lgc_lgl.lgl_oid,
                               cookies->lgc_lgl.lgl_ogen, cookies->lgc_index);
                        GOTO(out, rc = -ENOMEM);
                }
                llcd->llcd_import = ctxt->loc_imp;
                llcd->llcd_gen = ctxt->loc_gen;
                ctxt->loc_llcd = llcd;
        }

        memcpy((char *)llcd->llcd_cookies + llcd->llcd_cookiebytes, cookies,
               sizeof(*cookies));
        llcd->llcd_cookiebytes += sizeof(*cookies);

send_now:
        if ((PAGE_SIZE - llcd->llcd_cookiebytes < sizeof(*cookies) ||
             flags & OBD_LLOG_FL_SENDNOW)) {
                CDEBUG(D_HA, "send llcd: %p\n", llcd);
                ctxt->loc_llcd = NULL;
                llcd_send(llcd);
        }
out:
        up(&ctxt->loc_sem);
        return rc;
}
EXPORT_SYMBOL(llog_obd_repl_cancel);

static int log_commit_thread(void *arg)
{
        struct llog_commit_master *lcm = arg;
        struct llog_commit_daemon *lcd;
        struct llog_canceld_ctxt *llcd, *n;
        unsigned long flags;
        ENTRY;

        OBD_ALLOC(lcd, sizeof(*lcd));
        if (lcd == NULL)
                RETURN(-ENOMEM);

        lock_kernel();
        ptlrpc_daemonize(); /* thread never needs to do IO */

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        spin_lock(&lcm->lcm_thread_lock);
        THREAD_NAME(current->comm, "ll_log_commit_%d",
                    atomic_read(&lcm->lcm_thread_total));
        atomic_inc(&lcm->lcm_thread_total);
        spin_unlock(&lcm->lcm_thread_lock);
        unlock_kernel();

        INIT_LIST_HEAD(&lcd->lcd_lcm_list);
        INIT_LIST_HEAD(&lcd->lcd_llcd_list);
        lcd->lcd_lcm = lcm;

        CDEBUG(D_HA, "%s started\n", current->comm);
        do {
                struct ptlrpc_request *request;
                struct obd_import *import = NULL;
                struct list_head *sending_list;
                int rc = 0;

                /* If we do not have enough pages available, allocate some */
                while (atomic_read(&lcm->lcm_llcd_numfree) <
                       lcm->lcm_llcd_minfree) {
                        if (llcd_alloc() < 0)
                                break;
                }

                spin_lock(&lcm->lcm_thread_lock);
                atomic_inc(&lcm->lcm_thread_numidle);
                list_move(&lcd->lcd_lcm_list, &lcm->lcm_thread_idle);
                spin_unlock(&lcm->lcm_thread_lock);

                wait_event_interruptible(lcm->lcm_waitq,
                                         !list_empty(&lcm->lcm_llcd_pending) ||
                                         lcm->lcm_flags & LLOG_LCM_FL_EXIT);

                /* If we are the last available thread, start a new one in case
                 * we get blocked on an RPC (nobody else will start a new one)*/
                spin_lock(&lcm->lcm_thread_lock);
                atomic_dec(&lcm->lcm_thread_numidle);
                list_move(&lcd->lcd_lcm_list, &lcm->lcm_thread_busy);
                spin_unlock(&lcm->lcm_thread_lock);

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
                    atomic_read(&lcm->lcm_thread_total) < lcm->lcm_thread_max) {
                        rc = llog_start_commit_thread();
                        if (rc < 0)
                                CERROR("error starting thread: rc %d\n", rc);
                }

                /* Move all of the pending cancels from the same OST off of
                 * the list, so we don't get multiple threads blocked and/or
                 * doing upcalls on the same OST in case of failure. */
                spin_lock(&lcm->lcm_llcd_lock);
                if (!list_empty(sending_list)) {
                        list_move_tail(sending_list->next,
                                       &lcd->lcd_llcd_list);
                        llcd = list_entry(lcd->lcd_llcd_list.next,
                                          typeof(*llcd), llcd_list);
                        LASSERT(llcd->llcd_lcm == lcm);
                        import = llcd->llcd_import;
                }
                list_for_each_entry_safe(llcd, n, sending_list, llcd_list) {
                        LASSERT(llcd->llcd_lcm == lcm);
                        if (import == llcd->llcd_import)
                                list_move_tail(&llcd->llcd_list,
                                               &lcd->lcd_llcd_list);
                }
                if (sending_list != &lcm->lcm_llcd_resend) {
                        list_for_each_entry_safe(llcd, n, &lcm->lcm_llcd_resend,
                                                 llcd_list) {
                                LASSERT(llcd->llcd_lcm == lcm);
                                if (import == llcd->llcd_import)
                                        list_move_tail(&llcd->llcd_list,
                                                       &lcd->lcd_llcd_list);
                        }
                }
                spin_unlock(&lcm->lcm_llcd_lock);

                /* We are the only one manipulating our local list - no lock */
                list_for_each_entry_safe(llcd,n, &lcd->lcd_llcd_list,llcd_list){
                        char *bufs[1] = {(char *)llcd->llcd_cookies};
                        struct obd_device *obd = import->imp_obd;
                        struct llog_ctxt *ctxt;

                        list_del(&llcd->llcd_list);
                        if (llcd->llcd_cookiebytes == 0) {
                                CDEBUG(D_HA, "just put empty llcd %p\n", llcd);
                                llcd_put(llcd);
                                continue;
                        }
                        /* check whether the cookies are new. if new then send, otherwise
                         * just put llcd */
                        ctxt = llog_get_context(obd, llcd->llcd_cookies[0].lgc_subsys + 1);
                        LASSERT(ctxt != NULL);
                        down(&ctxt->loc_sem);
                        if (log_gen_lt(llcd->llcd_gen, ctxt->loc_gen)) {
                                up(&ctxt->loc_sem); 
                                CDEBUG(D_HA, "just put stale llcd %p\n", llcd);
                                llcd_put(llcd);
                                continue;
                        }
                        up(&ctxt->loc_sem); 

                        request = ptlrpc_prep_req(import, OBD_LOG_CANCEL, 1,
                                                  &llcd->llcd_cookiebytes,
                                                  bufs);
                        if (request == NULL) {
                                rc = -ENOMEM;
                                CERROR("error preparing commit: rc %d\n", rc);

                                spin_lock(&lcm->lcm_llcd_lock);
                                list_splice(&lcd->lcd_llcd_list,
                                            &lcm->lcm_llcd_resend);
                                INIT_LIST_HEAD(&lcd->lcd_llcd_list);
                                spin_unlock(&lcm->lcm_llcd_lock);
                                break;
                        }

                        request->rq_replen = lustre_msg_size(0, NULL);
                        rc = ptlrpc_queue_wait(request);
                        ptlrpc_req_finished(request);

                        /* If the RPC failed, we put this and the remaining
                         * messages onto the resend list for another time. */
                        if (rc == 0) {
                                llcd_put(llcd);
                                continue;
                        }

#if 0                   /* FIXME just put llcd, not send it again */
                        spin_lock(&lcm->lcm_llcd_lock);
                        list_splice(&lcd->lcd_llcd_list, &lcm->lcm_llcd_resend);
                        if (++llcd->llcd_tries < 5) {
                                CERROR("commit %p failed on attempt %d: rc %d\n",
                                       llcd, llcd->llcd_tries, rc);

                                list_add_tail(&llcd->llcd_list,
                                              &lcm->lcm_llcd_resend);
                                spin_unlock(&lcm->lcm_llcd_lock);
                        } else {
                                spin_unlock(&lcm->lcm_llcd_lock);
#endif
                                CERROR("commit %p dropped %d cookies: rc %d\n",
                                       llcd, (int)(llcd->llcd_cookiebytes /
                                                   sizeof(*llcd->llcd_cookies)),
                                       rc);
                                llcd_put(llcd);
//                        }
                        break;
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
                list_splice(&lcm->lcm_llcd_pending, &lcd->lcd_llcd_list);
                list_splice(&lcm->lcm_llcd_resend, &lcd->lcd_llcd_list);
                list_splice(&lcm->lcm_llcd_free, &lcd->lcd_llcd_list);
                spin_unlock(&lcm->lcm_llcd_lock);

                list_for_each_entry_safe(llcd, n, &lcd->lcd_llcd_list,llcd_list)
                        llcd_put(llcd);
        }

        spin_lock(&lcm->lcm_thread_lock);
        list_del(&lcd->lcd_lcm_list);
        spin_unlock(&lcm->lcm_thread_lock);
        OBD_FREE(lcd, sizeof(*lcd));

        spin_lock(&lcm->lcm_thread_lock);
        atomic_dec(&lcm->lcm_thread_total);
        spin_unlock(&lcm->lcm_thread_lock);
        wake_up(&lcm->lcm_waitq);

        CDEBUG(D_HA, "%s exiting\n", current->comm);
        return 0;
}

int llog_start_commit_thread(void)
{
        int rc;
        ENTRY;

        if (atomic_read(&lcm->lcm_thread_total) >= lcm->lcm_thread_max)
                RETURN(0);

        rc = kernel_thread(log_commit_thread, lcm, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("error starting thread #%d: %d\n",
                       atomic_read(&lcm->lcm_thread_total), rc);
                RETURN(rc);
        }

        RETURN(0);
}
EXPORT_SYMBOL(llog_start_commit_thread);

static struct llog_process_args {
        struct semaphore         llpa_sem; 
        struct llog_ctxt        *llpa_ctxt;
        void                    *llpa_cb;
        void                    *llpa_arg;
} llpa;
int llog_init_commit_master(void)
{
        INIT_LIST_HEAD(&lcm->lcm_thread_busy);
        INIT_LIST_HEAD(&lcm->lcm_thread_idle);
        spin_lock_init(&lcm->lcm_thread_lock);
        atomic_set(&lcm->lcm_thread_numidle, 0);
        init_waitqueue_head(&lcm->lcm_waitq);
        INIT_LIST_HEAD(&lcm->lcm_llcd_pending);
        INIT_LIST_HEAD(&lcm->lcm_llcd_resend);
        INIT_LIST_HEAD(&lcm->lcm_llcd_free);
        spin_lock_init(&lcm->lcm_llcd_lock);
        atomic_set(&lcm->lcm_llcd_numfree, 0);
        lcm->lcm_llcd_minfree = 0;
        lcm->lcm_thread_max = 5;
        /* FIXME initialize semaphore for llog_process_args */
        sema_init(&llpa.llpa_sem, 1);
        return 0;
}

int llog_cleanup_commit_master(int force)
{
        lcm->lcm_flags |= LLOG_LCM_FL_EXIT;
        if (force)
                lcm->lcm_flags |= LLOG_LCM_FL_EXIT_FORCE;
        wake_up(&lcm->lcm_waitq);

        wait_event_interruptible(lcm->lcm_waitq,
                                 atomic_read(&lcm->lcm_thread_total) == 0);
        return 0;
}


static int log_process_thread(void *args)
{
        struct llog_process_args *data = args;
        struct llog_ctxt *ctxt = data->llpa_ctxt;
        void   *cb = data->llpa_cb;
        struct llog_logid logid = *(struct llog_logid *)(data->llpa_arg);
        struct llog_handle *llh = NULL;
        unsigned long flags;
        int rc;
        ENTRY;
                                                                                                                             
        up(&data->llpa_sem);
        lock_kernel();
        ptlrpc_daemonize(); /* thread never needs to do IO */
                                                                                                                             
        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
        unlock_kernel();
                                                                                                                             
        rc = llog_create(ctxt, &llh, &logid, NULL);
        if (rc) {
                CERROR("llog_create failed %d\n", rc);
                RETURN(rc);
        }
        rc = llog_init_handle(llh, LLOG_F_IS_CAT, NULL);
        if (rc) {
                CERROR("llog_init_handle failed %d\n", rc);
                GOTO(out, rc);
        }
                                                                                                                             
        rc = llog_process(llh, cathandle_print_cb, NULL);
        if (rc) {
                CERROR("llog_process with cathandle_print_cb failed %d\n", rc);
                GOTO(out, rc);
        }
                                                                                                                             
        if (cb) {
                rc = llog_cat_process(llh, (llog_cb_t)cb, NULL);
                if (rc)
                        CERROR("llog_cat_process failed %d\n", rc);
        } else
                CERROR("no cb func for recovery\n");

        CDEBUG(D_HA, "send to llcd :%p forcibly\n", ctxt->loc_llcd);
        llog_cancel(ctxt, NULL, 0, NULL, OBD_LLOG_FL_SENDNOW);
out:
        rc = llog_cat_put(llh);
        if (rc)
                CERROR("llog_cat_put failed %d\n", rc);
                                                                                                                             
        RETURN(rc);
}
static int llog_recovery_generic(struct llog_ctxt *ctxt,
                                 void *handle,
                                 void *arg)
{
        int rc;
        ENTRY;

        down(&llpa.llpa_sem);
        llpa.llpa_ctxt = ctxt;
        llpa.llpa_cb = handle;
        llpa.llpa_arg = arg;

        rc = kernel_thread(log_process_thread, &llpa, CLONE_VM | CLONE_FILES);
        if (rc < 0)
                CERROR("error starting log_process_thread: %d\n", rc);
        else {
                CDEBUG(D_HA, "log_process_thread: %d\n", rc);
                rc = 0;
        }

        RETURN(rc);
}
int llog_repl_connect(struct llog_ctxt *ctxt, int count,
                      struct llog_logid *logid, struct llog_ctxt_gen *gen)
{
        struct llog_canceld_ctxt *llcd;
        int rc;
        ENTRY;
                                                                                                                             
        down(&ctxt->loc_sem);
        ctxt->loc_gen = *gen;
        llcd = ctxt->loc_llcd;
        if (llcd) {
                CDEBUG(D_HA, "put current llcd when new connection arrives\n");
                llcd_put(llcd);
        }
        llcd = llcd_grab();
        if (llcd == NULL) {
                CERROR("couldn't get an llcd\n");
                RETURN(-ENOMEM);
        }
        llcd->llcd_import = ctxt->loc_imp;
        llcd->llcd_gen = ctxt->loc_gen;
        ctxt->loc_llcd = llcd;
        up(&ctxt->loc_sem);

        rc = llog_recovery_generic(ctxt, ctxt->llog_proc_cb, logid); 
        if (rc != 0)
                CERROR("error recovery process: %d\n", rc);

        RETURN(rc);
}
EXPORT_SYMBOL(llog_repl_connect);

#else /* !__KERNEL__ */

int llog_obd_repl_cancel(struct llog_ctxt *ctxt,
                         struct lov_stripe_md *lsm, int count,
                         struct llog_cookie *cookies, int flags)
{
        return 0;
}
#endif
