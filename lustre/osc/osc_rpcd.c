/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author Peter Braam <braam@clusterfs.com>
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
 *  For testing and management it is treated as an obd_device,
 *  although * it does not export a full OBD method table (the
 *  requests are coming * in over the wire, so object target modules
 *  do not have a full * method table.)
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
# include <linux/version.h>
# include <linux/module.h>
# include <linux/mm.h>
# include <linux/highmem.h>
# include <linux/lustre_dlm.h>
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  include <linux/workqueue.h>
#  include <linux/smp_lock.h>
# else
#  include <linux/locks.h>
# endif
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <linux/kp30.h>
#include <linux/lustre_mds.h> /* for mds_objid */
#include <linux/lustre_net.h>
#include <linux/obd_ost.h>
#include <linux/lustre_commit_confd.h>
#include <linux/obd_lov.h>

#ifndef  __CYGWIN__
# include <linux/ctype.h>
# include <linux/init.h>
#else
# include <ctype.h>
#endif

#include <linux/lustre_ha.h>
#include <linux/obd_support.h> /* for OBD_FAIL_CHECK */
#include <portals/lib-types.h> /* for PTL_MD_MAX_IOV */
#include <linux/lprocfs_status.h>

#define LIOD_STOP 0
static struct osc_rpcd_ctl {
        unsigned long             orc_flags;
        spinlock_t                orc_lock;
        struct completion         orc_starting;
        struct completion         orc_finishing;
        struct list_head          orc_req_list;
        wait_queue_head_t         orc_waitq;
        struct ptlrpc_request_set *orc_set;
} osc_orc;

static DECLARE_MUTEX(osc_rpcd_sem);
static int osc_rpcd_users = 0;

void osc_rpcd_add_req(struct ptlrpc_request *req)
{
        struct osc_rpcd_ctl *orc = &osc_orc;

        ptlrpc_set_add_new_req(orc->orc_set, req);
        wake_up(&orc->orc_waitq);
}

static int osc_rpcd_check(struct osc_rpcd_ctl *orc)
{
        struct list_head *tmp, *pos;
        struct ptlrpc_request *req;
        unsigned long flags;
        int rc = 0;
        ENTRY;

        if (test_bit(LIOD_STOP, &orc->orc_flags))
                RETURN(1);

        spin_lock_irqsave(&orc->orc_set->set_new_req_lock, flags);
        list_for_each_safe(pos, tmp, &orc->orc_set->set_new_requests) {
                req = list_entry(pos, struct ptlrpc_request, rq_set_chain);
                list_del_init(&req->rq_set_chain);
                ptlrpc_set_add_req(orc->orc_set, req);
        }
        spin_unlock_irqrestore(&orc->orc_set->set_new_req_lock, flags);

        if (orc->orc_set->set_remaining) {
                rc = ptlrpc_check_set(orc->orc_set);

                /* XXX our set never completes, so we prune the completed
                 * reqs after each iteration. boy could this be smarter. */
                list_for_each_safe(pos, tmp, &orc->orc_set->set_requests) {
                        req = list_entry(pos, struct ptlrpc_request, 
                                         rq_set_chain);
                        if (req->rq_phase != RQ_PHASE_COMPLETE)
                                continue;

                        list_del_init(&req->rq_set_chain);
                        req->rq_set = NULL;
                        ptlrpc_req_finished (req);
                }
        }

        RETURN(rc);
}
             
/* ptlrpc's code paths like to execute in process context, so we have this
 * thread which spins on a set which contains the io rpcs.  llite specifies
 * osc_rpcd's set when it pushes pages down into the oscs */
static int osc_rpcd(void *arg)
{
        struct osc_rpcd_ctl *orc = arg;
        unsigned long flags;
        ENTRY;

        kportal_daemonize("liod_writeback");

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        complete(&orc->orc_starting);

        /* like kswapd */
        current->flags |= PF_MEMALLOC;

        /* this mainloop strongly resembles ptlrpc_set_wait except
         * that our set never completes.  osc_rpcd_check calls ptlrpc_check_set
         * when there are requests in the set.  new requests come in
         * on the set's new_req_list and osc_rpcd_check moves them into
         * the set. */
        while (1) {
                wait_queue_t set_wait;
                struct l_wait_info lwi;
                int timeout;

                timeout = ptlrpc_set_next_timeout(orc->orc_set);
                /* XXX the interrupted thing isn't really functional. */
                lwi = LWI_TIMEOUT_INTR(timeout * HZ, ptlrpc_expired_set,
                                       ptlrpc_interrupted_set, orc->orc_set);

                /* ala the pinger, wait on orc's waitqueue and the set's */
                init_waitqueue_entry(&set_wait, current);
                add_wait_queue(&orc->orc_set->set_waitq, &set_wait);
                l_wait_event(orc->orc_waitq, osc_rpcd_check(orc), &lwi);
                remove_wait_queue(&orc->orc_set->set_waitq, &set_wait);

                if (test_bit(LIOD_STOP, &orc->orc_flags))
                        break;
        }
        /* XXX should be making sure we don't have anything in flight */
        complete(&orc->orc_finishing);
        return 0;
}

int osc_rpcd_addref(void)
{
        struct osc_rpcd_ctl *orc = &osc_orc;
        int rc = 0;
        ENTRY;

        down(&osc_rpcd_sem);
        if (++osc_rpcd_users != 1)
                GOTO(out, rc);

        memset(orc, 0, sizeof(*orc));
        init_completion(&orc->orc_starting);
        init_completion(&orc->orc_finishing);
        init_waitqueue_head(&orc->orc_waitq);
        orc->orc_flags = 0;
        spin_lock_init(&orc->orc_lock);
        INIT_LIST_HEAD(&orc->orc_req_list);

        orc->orc_set = ptlrpc_prep_set();
        if (orc->orc_set == NULL)
                GOTO(out, rc = -ENOMEM);

        if (kernel_thread(osc_rpcd, orc, 0) < 0)  {
                ptlrpc_set_destroy(orc->orc_set);
                GOTO(out, rc = -ECHILD);
        }

        wait_for_completion(&orc->orc_starting);
out:
        up(&osc_rpcd_sem);
        RETURN(rc);
}

void osc_rpcd_decref(void)
{
        struct osc_rpcd_ctl *orc = &osc_orc;

        down(&osc_rpcd_sem);
        if (--osc_rpcd_users == 0) {
                set_bit(LIOD_STOP, &orc->orc_flags);
                wake_up(&orc->orc_waitq);
                wait_for_completion(&orc->orc_finishing);
                ptlrpc_set_destroy(orc->orc_set);
        }
        up(&osc_rpcd_sem);
}
