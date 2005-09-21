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

static struct list_head *ll_capa_list = &capa_list[CLIENT_CAPA];
static struct ptlrpc_thread capa_thread;

static struct thread_ctl {
        struct completion ctl_starting;
        struct completion ctl_finishing;
} ll_capa_ctl;

static inline int have_expired_capa(void)
{
        struct obd_capa *ocapa;
        struct lustre_capa *capa;
        int expired = 0;
        unsigned long expiry;
        struct timeval tv;

        ENTRY;

        do_gettimeofday(&tv);
        spin_lock(&capa_lock);
        if (!list_empty(ll_capa_list)) {
                ocapa = list_entry(ll_capa_list->next, struct obd_capa, c_list);
                expired = __capa_is_to_expire(ocapa, &tv);
                if (!expired) {
                        capa = &ocapa->c_capa;
                        expiry = expiry_to_jiffies(capa->lc_expiry -
                                                   capa_pre_expiry(capa));
                        if (time_before(expiry, ll_capa_timer.expires) ||
                            !timer_pending(&ll_capa_timer)) {
                                mod_timer(&ll_capa_timer, expiry);
                                CDEBUG(D_INFO,"ll_capa_timer new expiry: %lu\n",
                                       expiry);
                        }
                }
        }
        spin_unlock(&capa_lock);

        RETURN(expired);
}

static int inline ll_capa_check_stop(void)
{
        return (capa_thread.t_flags & SVC_STOPPING) ? 1: 0;
}

static int ll_renew_capa(struct obd_capa *ocapa)
{
        struct ptlrpc_request *req = NULL;
        /* no need to lock, no one else will touch it */
        struct inode *inode = ocapa->c_inode;
        struct obd_export *md_exp = ll_i2mdexp(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        __u64 valid = OBD_MD_CAPA;
        int rc;
        ENTRY;

        rc = md_getattr(md_exp, &lli->lli_id, valid, NULL, NULL, 0,
                        0, ocapa, &req);
        RETURN(rc);
}

static int ll_capa_thread(void *arg)
{
        struct thread_ctl *ctl = arg;
        unsigned long flags;
        int rc;
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
        capa_thread.t_flags = SVC_RUNNING;
        complete(&ctl->ctl_starting);

        while (1) {
                struct l_wait_info lwi = { 0 };
                struct obd_capa *ocapa, tcapa, *tmp, *next = NULL;
                unsigned long expiry, sleep = CAPA_PRE_EXPIRY;
                struct inode *inode;
                struct timeval tv;

                l_wait_event(capa_thread.t_ctl_waitq,
                             (have_expired_capa() || ll_capa_check_stop()),
                             &lwi);

                if (ll_capa_check_stop())
                        break;

                do_gettimeofday(&tv);
                spin_lock(&capa_lock);
                list_for_each_entry_safe(ocapa, tmp, ll_capa_list, c_list) {
                        if (ocapa->c_capa.lc_flags & CAPA_FL_SHORT)
                                sleep = CAPA_PRE_EXPIRY_SHORT;

                        if (ocapa->c_capa.lc_op == CAPA_TRUNC)
                                continue;

                        if (capa_expired(&ocapa->c_capa)) {
                                capa_put_nolock(ocapa);
                                continue;
                        }

                        if (__capa_is_to_expire(ocapa, &tv)) {
                                inode = igrab(ocapa->c_inode);
                                if (inode == NULL) {
                                        DEBUG_CAPA(D_ERROR, &ocapa->c_capa,
                                                   "igrab failed for");
                                        continue;
                                }

                                tcapa = *ocapa;
                                spin_unlock(&capa_lock);

                                rc = ll_renew_capa(&tcapa);
                                iput(inode);

                                spin_lock(&capa_lock);
                        } else {
                                next = ocapa;
                                break;
                        }
                }

                if (next) {
                        struct lustre_capa *capa = &next->c_capa;

                        expiry = expiry_to_jiffies(capa->lc_expiry -
                                                   capa_pre_expiry(capa));
                        if (time_before(expiry, ll_capa_timer.expires) ||
                            !timer_pending(&ll_capa_timer)) {
                                mod_timer(&ll_capa_timer, expiry);
                                CDEBUG(D_INFO,"ll_capa_timer new expiry: %lu\n",
                                       expiry);
                        }
                }
                spin_unlock(&capa_lock);

                /* wait ll_renew_capa finish */
                set_current_state(TASK_INTERRUPTIBLE);
                schedule_timeout(sleep * HZ);
        }

        capa_thread.t_flags = SVC_STOPPED;

        /* this is SMP-safe way to finish thread. */
        complete_and_exit(&ctl->ctl_finishing, 0);
        EXIT;
}

/* just wake up, others are handled by ll_capa_thread */
void ll_capa_timer_callback(unsigned long unused)
{
        ENTRY;
        wake_up(&capa_thread.t_ctl_waitq);
        EXIT;
}

int ll_capa_thread_start(void)
{
        int rc;
        ENTRY;

        LASSERT(capa_thread.t_flags == 0);
        init_completion(&ll_capa_ctl.ctl_starting);
        init_completion(&ll_capa_ctl.ctl_finishing);
        init_waitqueue_head(&capa_thread.t_ctl_waitq);

        rc = kernel_thread(ll_capa_thread, &ll_capa_ctl,
                           (CLONE_VM | CLONE_FILES));
        if (rc < 0) {
                CERROR("cannot start expired capa thread, "
                       "err = %d\n", rc);
                RETURN(rc);
        }
        wait_for_completion(&ll_capa_ctl.ctl_starting);
        LASSERT(capa_thread.t_flags == SVC_RUNNING);
        RETURN(0);
}

void ll_capa_thread_stop(void)
{
        ENTRY;

        capa_thread.t_flags = SVC_STOPPING;
        wake_up(&capa_thread.t_ctl_waitq);
        wait_for_completion(&ll_capa_ctl.ctl_finishing);
        LASSERT(capa_thread.t_flags == SVC_STOPPED);
        capa_thread.t_flags = 0;

        EXIT;
}

int ll_set_capa(struct inode *inode, struct lookup_intent *it,
                struct obd_client_handle *och)
{
        struct ptlrpc_request *req = LUSTRE_IT(it)->it_data;
        struct mds_body *body;
        struct lustre_capa *capa;
        struct obd_capa *ocapa;
        struct ll_inode_info *lli = ll_i2info(inode);
        unsigned long expiry;

        if (!S_ISREG(inode->i_mode))
                return 0;

        /* GNS code path will have no req */
        if (!req)
                return 0;

        body = lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));
        LASSERT(body != NULL);          /* reply already checked out */
        LASSERT_REPSWABBED(req, 1);     /* and swabbed down */

        if (!(body->valid & OBD_MD_CAPA))
                return 0;

        ENTRY;

        capa = lustre_msg_buf(req->rq_repmsg, 7, sizeof (*capa));
        LASSERT(capa != NULL);          /* reply already checked out */
        LASSERT_REPSWABBED(req, 7);     /* and swabbed down */

        ocapa = capa_renew(capa, CLIENT_CAPA);
        if (!ocapa)
                RETURN(-ENOMEM);

        spin_lock(&capa_lock);
        ocapa->c_inode = inode;
        ocapa->c_handle = och->och_fh;
        spin_unlock(&capa_lock);

        spin_lock(&lli->lli_lock);
        /* in case it was linked to lli_capas already */
        if (list_empty(&ocapa->c_lli_list))
                list_add(&ocapa->c_lli_list, &lli->lli_capas);
        spin_unlock(&lli->lli_lock);

        expiry = expiry_to_jiffies(capa->lc_expiry - capa_pre_expiry(capa));

        spin_lock(&capa_lock);
        if (time_before(expiry, ll_capa_timer.expires) ||
            !timer_pending(&ll_capa_timer)) {
                mod_timer(&ll_capa_timer, expiry);
                CDEBUG(D_INFO, "ll_capa_timer new expiry: %lu\n", expiry);
        }
        spin_unlock(&capa_lock);

        RETURN(0);
}

int ll_set_trunc_capa(struct ptlrpc_request *req, int offset, struct inode *inode)
{
        struct mds_body *body;
        struct obd_capa *ocapa;
        struct lustre_capa *capa;
        struct ll_inode_info *lli = ll_i2info(inode);

        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof(*body));
        if (!body)
                return -ENOMEM;

        if (!(body->valid & OBD_MD_CAPA))
                return 0;

        ENTRY;
        capa = (struct lustre_capa *)lustre_swab_repbuf(req, offset + 1,
                                        sizeof(*capa), lustre_swab_lustre_capa);
        if (!capa)
                RETURN(-ENOMEM);        

        ocapa = capa_renew(capa, CLIENT_CAPA);
        if (!ocapa)
                RETURN(-ENOMEM);

        spin_lock(&lli->lli_lock);
        /* in case it was linked to lli_capas already */
        if (list_empty(&ocapa->c_lli_list))
                list_add(&ocapa->c_lli_list, &lli->lli_capas);
        spin_unlock(&lli->lli_lock);

        RETURN(0);
}

struct obd_capa *ll_get_capa(struct inode *inode, uid_t uid, int op)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *ocapa, *tmp;
        ENTRY;

        list_for_each_entry_safe(ocapa, tmp, &lli->lli_capas, c_lli_list) {
                if (ocapa->c_capa.lc_ruid != uid)
                        continue;
                if (ocapa->c_capa.lc_op != op)
                        continue;

                RETURN(ocapa);
        }

        if (atomic_read(&ll_capa_stat)) {
                CDEBUG(D_ERROR, "can't find capa for (uid %u, op %d, mdsid "
                       LPU64", ino %u igen %u) failed.\n",
                       (unsigned)uid, op, id_group(&lli->lli_id),
                       (unsigned)id_ino(&lli->lli_id), id_gen(&lli->lli_id));
                atomic_set(&ll_capa_stat, 0);
        }
        
        RETURN(NULL);
}
