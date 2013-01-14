/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ptlrpc/recov_thread.c
 *
 * OST<->MDS recovery logging thread.
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 *
 * Author: Andreas Dilger   <adilger@clusterfs.com>
 *         Yury Umanets     <yury.umanets@sun.com>
 *         Alexey Lyashkov  <alexey.lyashkov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else
# include <libcfs/list.h>
# include <liblustre.h>
#endif

#include <obd_class.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lnet/types.h>
#include <libcfs/list.h>
#include <lustre_log.h>
#include "ptlrpc_internal.h"

static atomic_t                   llcd_count = ATOMIC_INIT(0);
static cfs_mem_cache_t           *llcd_cache = NULL;

#ifdef __KERNEL__
enum {
        LLOG_LCM_FL_START       = 1 << 0,
        LLOG_LCM_FL_EXIT        = 1 << 1
};

struct llcd_async_args {
        struct llog_canceld_ctxt *la_ctxt;
};

static void llcd_print(struct llog_canceld_ctxt *llcd,
                       const char *func, int line)
{
        CDEBUG(D_RPCTRACE, "Llcd (%p) at %s:%d:\n", llcd, func, line);
        CDEBUG(D_RPCTRACE, "  size: %d\n", llcd->llcd_size);
        CDEBUG(D_RPCTRACE, "  ctxt: %p\n", llcd->llcd_ctxt);
        CDEBUG(D_RPCTRACE, "  lcm : %p\n", llcd->llcd_lcm);
        CDEBUG(D_RPCTRACE, "  cookiebytes : %d\n", llcd->llcd_cookiebytes);
}

/**
 * Allocate new llcd from cache, init it and return to caller.
 * Bumps number of objects allocated.
 */
static struct llog_canceld_ctxt *llcd_alloc(struct llog_commit_master *lcm)
{
        struct llog_canceld_ctxt *llcd;
        int size, overhead;

        LASSERT(lcm != NULL);

        /*
         * We want to send one page of cookies with rpc header. This buffer
         * will be assigned later to the rpc, this is why we preserve the
         * space for rpc header.
         */
        size = CFS_PAGE_SIZE - lustre_msg_size(LUSTRE_MSG_MAGIC_V2, 1, NULL);
        overhead =  offsetof(struct llog_canceld_ctxt, llcd_cookies);
        OBD_SLAB_ALLOC(llcd, llcd_cache, CFS_ALLOC_STD, size + overhead);
        if (!llcd)
                return NULL;

        CFS_INIT_LIST_HEAD(&llcd->llcd_list);
        llcd->llcd_cookiebytes = 0;
        llcd->llcd_size = size;

        spin_lock(&lcm->lcm_lock);
        llcd->llcd_lcm = lcm;
        atomic_inc(&lcm->lcm_count);
        list_add_tail(&llcd->llcd_list, &lcm->lcm_llcds);
        spin_unlock(&lcm->lcm_lock);
        atomic_inc(&llcd_count);

        CDEBUG(D_RPCTRACE, "Alloc llcd %p on lcm %p (%d)\n",
               llcd, lcm, atomic_read(&lcm->lcm_count));

        return llcd;
}

/**
 * Returns passed llcd to cache.
 */
static void llcd_free(struct llog_canceld_ctxt *llcd)
{
        struct llog_commit_master *lcm = llcd->llcd_lcm;
        int size;

        if (lcm) {
                if (atomic_read(&lcm->lcm_count) == 0) {
                        CERROR("Invalid llcd free %p\n", llcd);
                        llcd_print(llcd, __FUNCTION__, __LINE__);
                        LBUG();
                }
                spin_lock(&lcm->lcm_lock);
                LASSERT(!list_empty(&llcd->llcd_list));
                list_del_init(&llcd->llcd_list);
                atomic_dec(&lcm->lcm_count);
                spin_unlock(&lcm->lcm_lock);

                CDEBUG(D_RPCTRACE, "Free llcd %p on lcm %p (%d)\n",
                       llcd, lcm, atomic_read(&lcm->lcm_count));
        }

        LASSERT(atomic_read(&llcd_count) > 0);
        atomic_dec(&llcd_count);

        size = offsetof(struct llog_canceld_ctxt, llcd_cookies) +
            llcd->llcd_size;
        OBD_SLAB_FREE(llcd, llcd_cache, size);
}

/**
 * Checks if passed cookie fits into llcd free space buffer. Returns
 * 1 if yes and 0 otherwise.
 */
static inline int
llcd_fit(struct llog_canceld_ctxt *llcd, struct llog_cookie *cookies)
{
        return (llcd->llcd_size - llcd->llcd_cookiebytes >= sizeof(*cookies));
}

/**
 * Copy passed @cookies to @llcd.
 */
static inline void
llcd_copy(struct llog_canceld_ctxt *llcd, struct llog_cookie *cookies)
{
        LASSERT(llcd_fit(llcd, cookies));
        memcpy((char *)llcd->llcd_cookies + llcd->llcd_cookiebytes,
              cookies, sizeof(*cookies));
        llcd->llcd_cookiebytes += sizeof(*cookies);
}

/**
 * Llcd completion function. Called uppon llcd send finish regardless
 * sending result. Error is passed in @rc. Note, that this will be called
 * in cleanup time when all inflight rpcs aborted.
 */
static int
llcd_interpret(struct ptlrpc_request *req, void *args, int rc)
{
        struct llcd_async_args *la = args;
        struct llog_canceld_ctxt *llcd = la->la_ctxt;

        CDEBUG(D_RPCTRACE, "Sent llcd %p (%d) - killing it\n", llcd, rc);
        llcd_free(llcd);
        return 0;
}

/**
 * Send @llcd to remote node. Free llcd uppon completion or error. Sending
 * is performed in async style so this function will return asap without
 * blocking.
 */
static int llcd_send(struct llog_canceld_ctxt *llcd)
{
        int size[2] = { sizeof(struct ptlrpc_body),
                        llcd->llcd_cookiebytes };
        char *bufs[2] = { NULL, (char *)llcd->llcd_cookies };
        struct obd_import *import = NULL;
        struct llog_commit_master *lcm;
        struct llcd_async_args *la;
        struct ptlrpc_request *req;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        ctxt = llcd->llcd_ctxt;
        if (!ctxt) {
                CERROR("Invalid llcd with NULL ctxt found (%p)\n",
                       llcd);
                llcd_print(llcd, __FUNCTION__, __LINE__);
                LBUG();
        }
        LASSERT_SEM_LOCKED(&ctxt->loc_sem);

        if (llcd->llcd_cookiebytes == 0)
                GOTO(exit, rc = 0);

        lcm = llcd->llcd_lcm;

        /*
         * Check if we're in exit stage. Do not send llcd in
         * this case.
         */
        if (test_bit(LLOG_LCM_FL_EXIT, &lcm->lcm_flags))
                GOTO(exit, rc = -ENODEV);

        CDEBUG(D_RPCTRACE, "Sending llcd %p\n", llcd);

        import = llcd->llcd_ctxt->loc_imp;
        if (!import || (import == LP_POISON) ||
            (import->imp_client == LP_POISON)) {
                CERROR("Invalid import %p for llcd %p\n",
                       import, llcd);
                GOTO(exit, rc = -ENODEV);
        }

        OBD_FAIL_TIMEOUT(OBD_FAIL_PTLRPC_DELAY_RECOV, 10);

        /*
         * No need to get import here as it is already done in
         * llog_receptor_accept().
         */
        req = ptlrpc_prep_req(import, LUSTRE_LOG_VERSION,
                              OBD_LOG_CANCEL, 2, size, bufs);
        if (req == NULL) {
                CERROR("Can't allocate request for sending llcd %p\n",
                       llcd);
                GOTO(exit, rc = -ENOMEM);
        }

        /*
         * Check if we're in exit stage again. Do not send llcd in
         * this case.
         */
        if (test_bit(LLOG_LCM_FL_EXIT, &lcm->lcm_flags)) {
                ptlrpc_req_finished(req);
                GOTO(exit, rc = -ENODEV);
        }

        /* bug 5515 */
        req->rq_request_portal = LDLM_CANCEL_REQUEST_PORTAL;
        req->rq_reply_portal = LDLM_CANCEL_REPLY_PORTAL;
        ptlrpc_req_set_repsize(req, 1, NULL);
        ptlrpc_at_set_req_timeout(req);
        req->rq_interpret_reply = llcd_interpret;

        CLASSERT(sizeof(*la) <= sizeof(req->rq_async_args));
        la = ptlrpc_req_async_args(req);
        la->la_ctxt = llcd;

        /* llog cancels will be replayed after reconnect so this will do twice
         * first from replay llog, second for resended rpc */
        req->rq_no_delay = req->rq_no_resend = 1;

        rc = ptlrpc_set_add_new_req(&lcm->lcm_pc, req);
        if (rc) {
                ptlrpc_req_finished(req);
                GOTO(exit, rc);
        }
        RETURN(rc);
exit:
        CDEBUG(D_RPCTRACE, "Refused llcd %p\n", llcd);
        llcd_free(llcd);
        return rc;
}

/**
 * Attach @llcd to @ctxt. Establish llcd vs. ctxt reserve connection
 * so hat they can refer each other.
 */
static int
llcd_attach(struct llog_ctxt *ctxt, struct llog_canceld_ctxt *llcd)
{
        LASSERT(ctxt != NULL && llcd != NULL);
        LASSERT_SEM_LOCKED(&ctxt->loc_sem);
        LASSERT(ctxt->loc_llcd == NULL);
        llcd->llcd_ctxt = llog_ctxt_get(ctxt);
        ctxt->loc_llcd = llcd;

        CDEBUG(D_RPCTRACE, "Attach llcd %p to ctxt %p\n",
               llcd, ctxt);

        return 0;
}

/**
 * Opposite to llcd_attach(). Detaches llcd from its @ctxt. This makes
 * sure that this llcd will not be found another time we try to cancel.
 */
static struct llog_canceld_ctxt *llcd_detach(struct llog_ctxt *ctxt)
{
        struct llog_canceld_ctxt *llcd;

        LASSERT(ctxt != NULL);
        LASSERT_SEM_LOCKED(&ctxt->loc_sem);

        llcd = ctxt->loc_llcd;
        if (!llcd)
                return NULL;

        CDEBUG(D_RPCTRACE, "Detach llcd %p from ctxt %p\n",
               llcd, ctxt);

        ctxt->loc_llcd = NULL;
        llog_ctxt_put(ctxt);
        return llcd;
}

/**
 * Return @llcd cached in @ctxt. Allocate new one if required. Attach it
 * to ctxt so that it may be used for gathering cookies and sending.
 */
static struct llog_canceld_ctxt *llcd_get(struct llog_ctxt *ctxt)
{
        struct llog_canceld_ctxt *llcd;

        llcd = llcd_alloc(ctxt->loc_lcm);
        if (!llcd) {
                CERROR("Can't alloc an llcd for ctxt %p\n", ctxt);
                return NULL;
        }
        llcd_attach(ctxt, llcd);
        return llcd;
}

/**
 * Deatch llcd from its @ctxt. Free llcd.
 */
static void llcd_put(struct llog_ctxt *ctxt)
{
        struct llog_canceld_ctxt *llcd;

        llcd = llcd_detach(ctxt);
        if (llcd)
                llcd_free(llcd);
}

/**
 * Detach llcd from its @ctxt so that nobody will find it with try to
 * re-use. Send llcd to remote node.
 */
static int llcd_push(struct llog_ctxt *ctxt)
{
        struct llog_canceld_ctxt *llcd;
        int rc;

        /*
         * Make sure that this llcd will not be sent again as we detach
         * it from ctxt.
         */
        llcd = llcd_detach(ctxt);
        if (!llcd) {
                CERROR("Invalid detached llcd found %p\n", llcd);
                llcd_print(llcd, __FUNCTION__, __LINE__);
                LBUG();
        }

        rc = llcd_send(llcd);
        if (rc)
                CERROR("Couldn't send llcd %p (%d)\n", llcd, rc);
        return rc;
}

/**
 * Start recovery thread which actually deals llcd sending. This
 * is all ptlrpc standard thread based so there is not much of work
 * to do.
 */
int llog_recov_thread_start(struct llog_commit_master *lcm)
{
        int rc;
        ENTRY;

        rc = ptlrpcd_start(lcm->lcm_name, &lcm->lcm_pc);
        if (rc) {
                CERROR("Error %d while starting recovery thread %s\n",
                       rc, lcm->lcm_name);
                RETURN(rc);
        }
        RETURN(rc);
}
EXPORT_SYMBOL(llog_recov_thread_start);

/**
 * Stop recovery thread. Complement to llog_recov_thread_start().
 */
void llog_recov_thread_stop(struct llog_commit_master *lcm, int force)
{
        ENTRY;

        /*
         * Let all know that we're stopping. This will also make
         * llcd_send() refuse any new llcds.
         */
        set_bit(LLOG_LCM_FL_EXIT, &lcm->lcm_flags);

        /*
         * Stop processing thread. No new rpcs will be accepted for
         * for processing now.
         */
        ptlrpcd_stop(&lcm->lcm_pc, force);

        /*
         * By this point no alive inflight llcds should be left. Only
         * those forgotten in sync may still be attached to ctxt. Let's
         * print them.
         */
        if (atomic_read(&lcm->lcm_count) != 0) {
                struct llog_canceld_ctxt *llcd;
                struct list_head         *tmp;

                CERROR("Busy llcds found (%d) on lcm %p\n",
                       atomic_read(&lcm->lcm_count) == 0, lcm);

                spin_lock(&lcm->lcm_lock);
                list_for_each(tmp, &lcm->lcm_llcds) {
                        llcd = list_entry(tmp, struct llog_canceld_ctxt,
                                          llcd_list);
                        llcd_print(llcd, __FUNCTION__, __LINE__);
                }
                spin_unlock(&lcm->lcm_lock);

                /*
                 * No point to go further with busy llcds at this point
                 * as this is clear bug. It might mean we got hanging
                 * rpc which holds import ref and this means we will not
                 * be able to cleanup anyways.
                 *
                 * Or we just missed to kill them when they were not
                 * attached to ctxt. In this case our slab will remind
                 * us about this a bit later.
                 */
                LBUG();
        }
        EXIT;
}
EXPORT_SYMBOL(llog_recov_thread_stop);

/**
 * Initialize commit master structure and start recovery thread on it.
 */
struct llog_commit_master *llog_recov_thread_init(char *name)
{
        struct llog_commit_master *lcm;
        int rc;
        ENTRY;

        OBD_ALLOC_PTR(lcm);
        if (!lcm)
                RETURN(NULL);

        /*
         * Try to create threads with unique names.
         */
        snprintf(lcm->lcm_name, sizeof(lcm->lcm_name),
                 "lcm_%s", name);

        atomic_set(&lcm->lcm_count, 0);
        spin_lock_init(&lcm->lcm_lock);
        CFS_INIT_LIST_HEAD(&lcm->lcm_llcds);
        rc = llog_recov_thread_start(lcm);
        if (rc) {
                CERROR("Can't start commit thread, rc %d\n", rc);
                GOTO(out, rc);
        }
        RETURN(lcm);
out:
        OBD_FREE_PTR(lcm);
        return NULL;
}
EXPORT_SYMBOL(llog_recov_thread_init);

/**
 * Finalize commit master and its recovery thread.
 */
void llog_recov_thread_fini(struct llog_commit_master *lcm, int force)
{
        ENTRY;
        llog_recov_thread_stop(lcm, force);
        OBD_FREE_PTR(lcm);
        EXIT;
}
EXPORT_SYMBOL(llog_recov_thread_fini);

static int llog_recov_thread_replay(struct llog_ctxt *ctxt,
                                    void *cb, void *arg)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct llog_process_cat_args *lpca;
        int rc;
        ENTRY;

        if (obd->obd_stopping)
                RETURN(-ENODEV);

        /*
         * This will be balanced in llog_cat_process_thread()
         */
        OBD_ALLOC_PTR(lpca);
        if (!lpca)
                RETURN(-ENOMEM);

        lpca->lpca_cb = cb;
        lpca->lpca_arg = arg;

        /*
         * This will be balanced in llog_cat_process_thread()
         */
        lpca->lpca_ctxt = llog_ctxt_get(ctxt);
        if (!lpca->lpca_ctxt) {
                OBD_FREE_PTR(lpca);
                RETURN(-ENODEV);
        }
        rc = cfs_kernel_thread(llog_cat_process_thread, lpca,
                               CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("Error starting llog_cat_process_thread(): %d\n", rc);
                OBD_FREE_PTR(lpca);
                llog_ctxt_put(ctxt);
        } else {
                CDEBUG(D_HA, "Started llog_cat_process_thread(): %d\n", rc);
                rc = 0;
        }

        RETURN(rc);
}

int llog_obd_repl_connect(struct llog_ctxt *ctxt,
                          struct llog_logid *logid, struct llog_gen *gen,
                          struct obd_uuid *uuid)
{
        int rc;
        ENTRY;

        /*
         * Send back cached llcd from llog before recovery if we have any.
         * This is void is nothing cached is found there.
         */
        llog_sync(ctxt, NULL);

        /*
         * Start recovery in separate thread.
         */
        mutex_down(&ctxt->loc_sem);
        ctxt->loc_gen = *gen;
        rc = llog_recov_thread_replay(ctxt, ctxt->llog_proc_cb, logid);
        mutex_up(&ctxt->loc_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(llog_obd_repl_connect);

/**
 * Deleted objects have a commit callback that cancels the MDS
 * log record for the deletion. The commit callback calls this
 * function.
 */
int llog_obd_repl_cancel(struct llog_ctxt *ctxt,
                         struct lov_stripe_md *lsm, int count,
                         struct llog_cookie *cookies, int flags)
{
        struct llog_commit_master *lcm;
        struct llog_canceld_ctxt *llcd;
        int rc = 0;
        ENTRY;

        LASSERT(ctxt != NULL);

        mutex_down(&ctxt->loc_sem);
        lcm = ctxt->loc_lcm;
        CDEBUG(D_INFO, "cancel on lsm %p\n", lcm);

        /*
         * Let's check if we have all structures alive. We also check for
         * possible shutdown. Do nothing if we're stopping.
         */
        if (ctxt->loc_imp == NULL) {
                CDEBUG(D_RPCTRACE, "No import for ctxt %p\n", ctxt);
                GOTO(out, rc = -ENODEV);
        }

        if (test_bit(LLOG_LCM_FL_EXIT, &lcm->lcm_flags)) {
                CDEBUG(D_RPCTRACE, "Commit thread is stopping for ctxt %p\n",
                       ctxt);
                GOTO(out, rc = -ENODEV);
        }

        llcd = ctxt->loc_llcd;

        if (count > 0 && cookies != NULL) {
                /*
                 * Get new llcd from ctxt if required.
                 */
                if (!llcd) {
                        llcd = llcd_get(ctxt);
                        if (!llcd)
                                GOTO(out, rc = -ENOMEM);
                        /*
                         * Allocation is successful, let's check for stop
                         * flag again to fall back as soon as possible.
                         */
                        if (test_bit(LLOG_LCM_FL_EXIT, &lcm->lcm_flags))
                                GOTO(out, rc = -ENODEV);
                }

                /*
                 * Llcd does not have enough room for @cookies. Let's push
                 * it out and allocate new one.
                 */
                if (!llcd_fit(llcd, cookies)) {
                        rc = llcd_push(ctxt);
                        if (rc)
                                GOTO(out, rc);
                        llcd = llcd_get(ctxt);
                        if (!llcd)
                                GOTO(out, rc = -ENOMEM);
                        /*
                         * Allocation is successful, let's check for stop
                         * flag again to fall back as soon as possible.
                         */
                        if (test_bit(LLOG_LCM_FL_EXIT, &lcm->lcm_flags))
                                GOTO(out, rc = -ENODEV);
                }

                /*
                 * Copy cookies to @llcd, no matter old or new allocated
                 * one.
                 */
                llcd_copy(llcd, cookies);
        }

        /*
         * Let's check if we need to send copied @cookies asap. If yes
         * then do it.
         */
        if (llcd && (flags & OBD_LLOG_FL_SENDNOW)) {
                CDEBUG(D_RPCTRACE, "Sync llcd %p\n", llcd);
                rc = llcd_push(ctxt);
                if (rc)
                        GOTO(out, rc);
        }
        EXIT;
out:
        if (rc)
                llcd_put(ctxt);
        mutex_up(&ctxt->loc_sem);
        return rc;
}
EXPORT_SYMBOL(llog_obd_repl_cancel);

int llog_obd_repl_sync(struct llog_ctxt *ctxt, struct obd_export *exp)
{
        int rc = 0;
        ENTRY;

        /*
         * Flush any remaining llcd.
         */
        mutex_down(&ctxt->loc_sem);
        if (exp && (ctxt->loc_imp == exp->exp_imp_reverse)) {
                /*
                 * This is ost->mds connection, we can't be sure that mds
                 * can still receive cookies, let's killed the cached llcd.
                 */
                CDEBUG(D_RPCTRACE, "Kill cached llcd\n");
                llcd_put(ctxt);
                mutex_up(&ctxt->loc_sem);
        } else {
                /*
                 * This is either llog_sync() from generic llog code or sync
                 * on client disconnect. In either way let's do it and send
                 * llcds to the target with waiting for completion.
                 */
                CDEBUG(D_RPCTRACE, "Sync cached llcd\n");
                mutex_up(&ctxt->loc_sem);
                rc = llog_cancel(ctxt, NULL, 0, NULL, OBD_LLOG_FL_SENDNOW);
        }
        RETURN(rc);
}
EXPORT_SYMBOL(llog_obd_repl_sync);

#else /* !__KERNEL__ */

int llog_obd_repl_cancel(struct llog_ctxt *ctxt,
                         struct lov_stripe_md *lsm, int count,
                         struct llog_cookie *cookies, int flags)
{
        return 0;
}
#endif

/**
 * Module init time fucntion. Initializes slab for llcd objects.
 */
int llog_recov_init(void)
{
        int llcd_size;

        llcd_size = CFS_PAGE_SIZE -
                lustre_msg_size(LUSTRE_MSG_MAGIC_V2, 1, NULL);
        llcd_size += offsetof(struct llog_canceld_ctxt, llcd_cookies);
        llcd_cache = cfs_mem_cache_create("llcd_cache", llcd_size, 0, 0);
        if (!llcd_cache) {
                CERROR("Error allocating llcd cache\n");
                return -ENOMEM;
        }
        return 0;
}

/**
 * Module fini time fucntion. Releases slab for llcd objects.
 */
void llog_recov_fini(void)
{
        /*
         * Kill llcd cache when thread is stopped and we're sure no
         * llcd in use left.
         */
        if (llcd_cache) {
                /*
                 * In 2.6.22 cfs_mem_cache_destroy() will not return error
                 * for busy resources. Let's check it another way.
                 */
                LASSERTF(atomic_read(&llcd_count) == 0,
                         "Can't destroy llcd cache! Number of "
                         "busy llcds: %d\n", atomic_read(&llcd_count));
                cfs_mem_cache_destroy(llcd_cache);
                llcd_cache = NULL;
        }
}
