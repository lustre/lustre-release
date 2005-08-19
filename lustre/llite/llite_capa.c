/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004, 2005 Cluster File Systems, Inc.
 *
 * Author: Lai Siyao <lsy@clusterfs.com>
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
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/fs.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/kmod.h>

#include <linux/lustre_lite.h>
#include "llite_internal.h"

static struct ptlrpc_thread ll_capa_thread;
static struct list_head *ll_capa_list = &capa_list[CLIENT_CAPA];
static struct thread_ctl {
        struct completion ctl_starting;
        struct completion ctl_finishing;
} ll_capa_ctl;

static inline int have_expired_capa(void)
{
        struct obd_capa *ocapa;
        int expired = 0;
        unsigned long expiry;
        ENTRY;

        spin_lock(&capa_lock);
        if (!list_empty(ll_capa_list)) {
                ocapa = list_entry(ll_capa_list->next, struct obd_capa, c_list);

                expired = __capa_is_to_expire(ocapa);
                if (!expired && !timer_pending(&ll_capa_timer)) {
                        /* the expired capa has been put, so set the timer to
                         * the expired of the next capa */
                        expiry = expiry_to_jiffies(ocapa->c_capa.lc_expiry);
                        mod_timer(&ll_capa_timer, expiry);
                        CDEBUG(D_INFO, "ll_capa_timer new expiry: %lu\n", expiry);
                }
        }
        spin_unlock(&capa_lock);

        RETURN(expired);
}

static int inline ll_capa_check_stop(void)
{
        return (ll_capa_thread.t_flags & SVC_STOPPING) ? 1: 0;
}

static int ll_renew_capa(struct obd_capa *ocapa)
{
        struct ptlrpc_request *req = NULL;
        /* no need to lock, no one else will touch it */
        struct inode *inode = ocapa->c_inode;
        struct obd_export *md_exp = ll_i2mdexp(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        __u64 valid = 0;
        int rc;
        ENTRY;

        valid |= OBD_MD_CAPA;

        rc = md_getattr(md_exp, &lli->lli_id, valid, NULL, NULL, 0,
                        0, ocapa, &req);
        if (rc < 0)
                CDEBUG(D_INFO, "md_getattr failed: rc = %d\n", rc);
        RETURN(rc);
}

static int ll_capa_thread_main(void *arg)
{
        struct thread_ctl *ctl = arg;
        unsigned long flags;
        ENTRY;

        {
                char name[sizeof(current->comm)];
                snprintf(name, sizeof(name) - 1, "ll_capa");
                kportal_daemonize(name);
        }

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        /*
         * letting starting function know, that we are ready and control may be
         * returned.
         */
        ll_capa_thread.t_flags = SVC_RUNNING;
        complete(&ctl->ctl_starting);

        while (1) {
                struct l_wait_info lwi = { 0 };
                struct obd_capa *ocapa, *next = NULL;
                unsigned long expiry, sleep = CAPA_PRE_EXPIRY;

                l_wait_event(ll_capa_thread.t_ctl_waitq,
                             (have_expired_capa() || ll_capa_check_stop()),
                             &lwi);

                spin_lock(&capa_lock);
                list_for_each_entry(ocapa, ll_capa_list, c_list) {
                        if (__capa_is_to_expire(ocapa)) {
                                /* get capa in case it's deleted */
                                __capa_get(ocapa);

                                spin_unlock(&capa_lock);
                                ll_renew_capa(ocapa);
                                capa_put(ocapa, CLIENT_CAPA);
                                spin_lock(&capa_lock);
                        } else {
                                next = ocapa;
                                break;
                        }
                }
                if (next) {
                        expiry = expiry_to_jiffies(next->c_capa.lc_expiry);
                        mod_timer(&ll_capa_timer, expiry);
                        CDEBUG(D_INFO, "ll_capa_timer new expiry: %lu\n", expiry);
                        if (next->c_capa.lc_flags & CAPA_FL_NOROUND)
                                sleep = CAPA_PRE_EXPIRY_NOROUND;
                }
                spin_unlock(&capa_lock);

                if (ll_capa_check_stop())
                        break;

                /* wait ll_renew_capa finish */
                set_current_state(TASK_INTERRUPTIBLE);
                schedule_timeout(sleep * HZ);
        }

        ll_capa_thread.t_flags = SVC_STOPPED;

        /* this is SMP-safe way to finish thread. */
        complete_and_exit(&ctl->ctl_finishing, 0);
        EXIT;
}

/* just wake up, others are handled by ll_capa_thread */
void ll_capa_timer_callback(unsigned long unused)
{
        ENTRY;
        wake_up(&ll_capa_thread.t_ctl_waitq);
        EXIT;
}

int ll_capa_start_thread(void)
{
        int rc;
        ENTRY;

        LASSERT(ll_capa_thread.t_flags == 0);
        init_completion(&ll_capa_ctl.ctl_starting);
        init_completion(&ll_capa_ctl.ctl_finishing);
        init_waitqueue_head(&ll_capa_thread.t_ctl_waitq);

        rc = kernel_thread(ll_capa_thread_main, &ll_capa_ctl,
                           (CLONE_VM | CLONE_FILES));
        if (rc < 0) {
                CERROR("cannot start expired capa thread, "
                       "err = %d\n", rc);
                RETURN(rc);
        }
        wait_for_completion(&ll_capa_ctl.ctl_starting);
        LASSERT(ll_capa_thread.t_flags == SVC_RUNNING);
        RETURN(0);
}

void ll_capa_stop_thread(void)
{
        ENTRY;

        ll_capa_thread.t_flags = SVC_STOPPING;
        wake_up(&ll_capa_thread.t_ctl_waitq);
        wait_for_completion(&ll_capa_ctl.ctl_finishing);
        LASSERT(ll_capa_thread.t_flags == SVC_STOPPED);
        ll_capa_thread.t_flags = 0;

        EXIT;
}

int ll_set_och_capa(struct inode *inode, struct lookup_intent *it,
            	    struct obd_client_handle *och)
{
        struct ptlrpc_request *req = LUSTRE_IT(it)->it_data;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct mds_body *body;
        struct lustre_capa *capa;
        __u64 mdsid = lli->lli_id.li_fid.lf_group;
        unsigned long ino = lli->lli_id.li_stc.u.e3s.l3s_ino;
        int capa_op = (it->it_flags & MAY_WRITE) ? MAY_WRITE : MAY_READ;
        unsigned long expiry;
        int rc = 0;
        ENTRY;

        body = lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));
        LASSERT(body != NULL);          /* reply already checked out */
        LASSERT_REPSWABBED(req, 1);     /* and swabbed down */

        capa = lustre_msg_buf(req->rq_repmsg, 7, sizeof (*capa));
        LASSERT(capa != NULL);          /* reply already checked out */
        LASSERT_REPSWABBED(req, 7);     /* and swabbed down */

        och->och_capa = capa_get(current->uid, capa_op, mdsid, ino,
                                 CLIENT_CAPA, capa, inode, &body->handle);
        if (!och->och_capa)
                rc = -ENOMEM;

        DEBUG_CAPA(D_INFO, capa, "ll_set_och_capa");

        expiry = expiry_to_jiffies(capa->lc_expiry - capa_pre_expiry(capa));

        spin_lock(&capa_lock);
        if (time_before(expiry, ll_capa_timer.expires) ||
            !timer_pending(&ll_capa_timer)) {
                mod_timer(&ll_capa_timer, expiry);
                CDEBUG(D_INFO, "ll_capa_timer new expiry: %lu\n", expiry);
        }
        spin_unlock(&capa_lock);

        RETURN(rc);
}

