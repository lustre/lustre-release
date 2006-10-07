/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
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

#include <lustre_lite.h>
#include "llite_internal.h"

/* for obd_capa.c_list, client capa might stay in three places:
 * 1. ll_capa_list.
 * 2. ll_idle_capas.
 * 3. stand alone: just allocated.
 */

/* capas for oss writeback and those failed to renew */
static LIST_HEAD(ll_idle_capas);
static struct ptlrpc_thread ll_capa_thread;
static struct list_head *ll_capa_list = &capa_list[CAPA_SITE_CLIENT];

/* llite capa renewal timer */
cfs_timer_t ll_capa_timer;
/* for debug: indicate whether capa on llite is enabled or not */
static atomic_t ll_capa_debug = ATOMIC_INIT(0);

static inline void update_capa_timer(struct obd_capa *ocapa, cfs_time_t expiry)
{
        if (cfs_time_before(expiry, cfs_timer_deadline(&ll_capa_timer)) ||
            !cfs_timer_is_armed(&ll_capa_timer)) {
                cfs_timer_arm(&ll_capa_timer, expiry);
                DEBUG_CAPA(D_SEC, &ocapa->c_capa,
                           "ll_capa_timer update: %lu/%lu by",
                           expiry, cfs_time_current());
        }
}

static inline int have_expired_capa(void)
{
        struct obd_capa *ocapa = NULL;
        int expired = 0;

        /* if ll_capa_list has client capa to expire or ll_idle_capas has
         * expired capa, return 1.
         */
        spin_lock(&capa_lock);
        if (!list_empty(ll_capa_list)) {
                ocapa = list_entry(ll_capa_list->next, struct obd_capa, c_list);
                expired = capa_is_to_expire(ocapa);
                if (!expired)
                        update_capa_timer(ocapa, capa_renewal_time(ocapa));
        } else if (!list_empty(&ll_idle_capas)) {
                ocapa = list_entry(ll_idle_capas.next, struct obd_capa, c_list);
                expired = capa_is_expired(ocapa);
                if (!expired)
                        update_capa_timer(ocapa, ocapa->c_expiry);
        }
        spin_unlock(&capa_lock);

        if (expired)
                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "expired");
        return expired;
}

static inline int ll_capa_check_stop(void)
{
        return (ll_capa_thread.t_flags & SVC_STOPPING) ? 1: 0;
}

static void sort_add_capa(struct obd_capa *ocapa, struct list_head *head)
{
        struct obd_capa *tmp;
        struct list_head *before = NULL;

        /* TODO: client capa is sorted by expiry, this could be optimized */
        list_for_each_entry_reverse(tmp, head, c_list) {
                if (cfs_time_after(ocapa->c_expiry, tmp->c_expiry)) {
                        before = &tmp->c_list;
                        break;
                }
        }

        LASSERT(&ocapa->c_list != before);
        list_add(&ocapa->c_list, before ?: head);
}

static int inode_have_md_lock(struct inode *inode, __u64 inodebits)
{
        struct obd_export *exp = ll_i2mdexp(inode);
        ldlm_policy_data_t policy = { .l_inodebits = {inodebits}};
        struct lustre_handle lockh;
        int flags = LDLM_FL_BLOCK_GRANTED|LDLM_FL_CBPENDING|LDLM_FL_TEST_LOCK;
        int rc;
        ENTRY;

        rc = md_lock_match(exp, flags, ll_inode2fid(inode),
                           LDLM_IBITS, &policy, LCK_CR|LCK_CW|LCK_PR, &lockh);
        RETURN(rc);
}

static void ll_delete_capa(struct obd_capa *ocapa)
{
        struct ll_inode_info *lli = ll_i2info(ocapa->u.cli.inode);

        if (capa_for_mds(&ocapa->c_capa)) {
                capa_put(ocapa);
                LASSERT(lli->lli_mds_capa == ocapa);
                lli->lli_mds_capa = NULL;
        } else if (capa_for_oss(&ocapa->c_capa)) {
                list_del_init(&ocapa->u.cli.lli_list);
        }

        DEBUG_CAPA(D_SEC, &ocapa->c_capa, "free client");
        list_del(&ocapa->c_list);
        free_capa(ocapa);
}

/* three places where client capa is deleted:
 * 1. capa_thread_main(), main place to delete expired capa.
 * 2. ll_clear_inode_capas() in ll_clear_inode().
 * 3. ll_truncate_free_capa() delete truncate capa explicitly in ll_truncate().
 */
static int capa_thread_main(void *unused)
{
        struct obd_capa *ocapa, *tmp, *next;
        struct inode *inode = NULL;
        struct l_wait_info lwi = { 0 };
        int rc;
        ENTRY;

        cfs_daemonize("ll_capa");

        ll_capa_thread.t_flags = SVC_RUNNING;
        wake_up(&ll_capa_thread.t_ctl_waitq);

        while (1) {
                l_wait_event(ll_capa_thread.t_ctl_waitq,
                             (ll_capa_check_stop() || have_expired_capa()),
                             &lwi);

                if (ll_capa_check_stop())
                        break;

                spin_lock(&capa_lock);
                next = NULL;
                list_for_each_entry_safe(ocapa, tmp, ll_capa_list, c_list) {
                        LASSERT(ocapa->c_capa.lc_opc != CAPA_OPC_OSS_TRUNC);

                        if (!capa_is_to_expire(ocapa)) {
                                next = ocapa;
                                break;
                        }

                        if (capa_for_mds(&ocapa->c_capa) &&
                            !ll_have_md_lock(ocapa->u.cli.inode,
                                             MDS_INODELOCK_LOOKUP) &&
                            !obd_capa_is_root(ocapa)) {
                                /* MDS capa without LOOKUP lock won't renew,
                                 * move to idle list (except root fid) */
                                DEBUG_CAPA(D_SEC, &ocapa->c_capa,
                                           "skip renewal for");
                                list_del_init(&ocapa->c_list);
                                sort_add_capa(ocapa, &ll_idle_capas);
                                continue;
                        }

                        if (capa_for_oss(&ocapa->c_capa) &&
                            atomic_read(&ocapa->u.cli.open_count) == 0) {
                                /* oss capa with open_count == 0 won't renew,
                                 * move to idle list */
                                list_del_init(&ocapa->c_list);
                                sort_add_capa(ocapa, &ll_idle_capas);
                                continue;
                        }

                        /* NB iput() is in ll_update_capa() */
                        inode = igrab(ocapa->u.cli.inode);
                        if (inode == NULL) {
                                DEBUG_CAPA(D_SEC, &ocapa->c_capa,
                                           "igrab failed for");
                                ll_delete_capa(ocapa);
                                continue;
                        }

                        list_del_init(&ocapa->c_list);
                        capa_get(ocapa);
                        spin_unlock(&capa_lock);

                        rc = md_renew_capa(ll_i2mdexp(inode), ocapa,
                                           ll_update_capa);
                        spin_lock(&capa_lock);
                        if (rc)
                                sort_add_capa(ocapa, &ll_idle_capas);
                }

                if (next)
                        update_capa_timer(next, capa_renewal_time(next));

                list_for_each_entry_safe(ocapa, tmp, &ll_idle_capas, c_list) {
                        LASSERT(atomic_read(&ocapa->u.cli.open_count) == 0);

                        if (!capa_is_expired(ocapa)) {
                                if (!next)
                                        update_capa_timer(ocapa, ocapa->c_expiry);
                                break;
                        }

                        if (atomic_read(&ocapa->c_refc)) {
                                DEBUG_CAPA(D_SEC, &ocapa->c_capa,
                                           "expired(c_refc %d), don't release",
                                           atomic_read(&ocapa->c_refc));
                                obd_capa_set_expired(ocapa);
                                /* don't try to renew any more */
                                list_del_init(&ocapa->c_list);
                                continue;
                        }

                        /* expired capa is released. */
                        DEBUG_CAPA(D_SEC, &ocapa->c_capa, "release expired");
                        ll_delete_capa(ocapa);
                }

                spin_unlock(&capa_lock);
        }

        ll_capa_thread.t_flags = SVC_STOPPED;
        wake_up(&ll_capa_thread.t_ctl_waitq);
        RETURN(0);
}

void ll_capa_timer_callback(unsigned long unused)
{
        wake_up(&ll_capa_thread.t_ctl_waitq);
}

int ll_capa_thread_start(void)
{
        int rc;
        ENTRY;

        init_waitqueue_head(&ll_capa_thread.t_ctl_waitq);

        rc = kernel_thread(capa_thread_main, NULL, 0);
        if (rc < 0) {
                CERROR("cannot start expired capa thread: rc %d\n", rc);
                RETURN(rc);
        }
        wait_event(ll_capa_thread.t_ctl_waitq,
                   ll_capa_thread.t_flags & SVC_RUNNING);

        RETURN(0);
}

void ll_capa_thread_stop(void)
{
        ll_capa_thread.t_flags = SVC_STOPPING;
        wake_up(&ll_capa_thread.t_ctl_waitq);
        wait_event(ll_capa_thread.t_ctl_waitq,
                   ll_capa_thread.t_flags & SVC_STOPPED);
}

static struct obd_capa *do_lookup_oss_capa(struct inode *inode, int opc)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *ocapa;

        /* inside capa_lock */
        list_for_each_entry(ocapa, &lli->lli_oss_capas, u.cli.lli_list) {
                if (!obd_capa_is_valid(ocapa))
                        continue;
                if ((capa_opc(&ocapa->c_capa) & opc) != opc)
                        continue;

                LASSERT(lu_fid_eq(capa_fid(&ocapa->c_capa),
                                  ll_inode2fid(inode)));
                LASSERT(ocapa->c_site == CAPA_SITE_CLIENT);

                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "found client");
                return ocapa;
        }

        return NULL;
}

struct obd_capa *ll_lookup_oss_capa(struct inode *inode, __u64 opc)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *ocapa;
        int found = 0;

        if ((ll_i2sbi(inode)->ll_flags & LL_SBI_OSS_CAPA) == 0)
                return NULL;
        ENTRY;

        LASSERT(opc == CAPA_OPC_OSS_WRITE ||
                opc == (CAPA_OPC_OSS_WRITE | CAPA_OPC_OSS_READ) ||
                opc == CAPA_OPC_OSS_TRUNC);

        spin_lock(&capa_lock);
        list_for_each_entry(ocapa, &lli->lli_oss_capas, u.cli.lli_list) {
                if (!obd_capa_is_valid(ocapa))
                        continue;
                if ((opc & CAPA_OPC_OSS_WRITE) &&
                    capa_opc_supported(&ocapa->c_capa, opc)) {
                        found = 1; break;
                } else if ((opc & CAPA_OPC_OSS_READ) &&
                           capa_opc_supported(&ocapa->c_capa, opc)) {
                        found = 1; break;
                } else if ((opc & CAPA_OPC_OSS_TRUNC) &&
                           capa_opc_supported(&ocapa->c_capa, opc)) {
                        found = 1; break;
                }
        }

        if (found) {
                LASSERT(lu_fid_eq(capa_fid(&ocapa->c_capa),
                                  ll_inode2fid(inode)));
                LASSERT(ocapa->c_site == CAPA_SITE_CLIENT);

                capa_get(ocapa);

                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "found client");
        } else {
                ocapa = NULL;

                if (atomic_read(&ll_capa_debug)) {
                        CERROR("no capability for "DFID" opc "LPX64"\n",
                               PFID(&lli->lli_fid), opc);
                        atomic_set(&ll_capa_debug, 0);
                }
        }
        spin_unlock(&capa_lock);

        RETURN(ocapa);
}

struct obd_capa *ll_i2mdscapa(struct inode *inode)
{
        struct obd_capa *ocapa;
        struct ll_inode_info *lli = ll_i2info(inode);

        LASSERT(inode);
        if ((ll_i2sbi(inode)->ll_flags & LL_SBI_MDS_CAPA) == 0)
                return NULL;
        ENTRY;

        spin_lock(&capa_lock);
        ocapa = capa_get(lli->lli_mds_capa);
        spin_unlock(&capa_lock);
        if (ocapa && !obd_capa_is_valid(ocapa)) {
                DEBUG_CAPA(D_ERROR, &ocapa->c_capa, "invalid");
                capa_put(ocapa);
                ocapa = NULL;
        }

        if (!ocapa && atomic_read(&ll_capa_debug)) {
                CDEBUG(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ?
                       D_ERROR : D_SEC, "no MDS capability for fid "DFID"\n",
                       PFID(ll_inode2fid(inode)));
                if (inode_have_md_lock(inode, MDS_INODELOCK_LOOKUP))
                        LBUG();
                atomic_set(&ll_capa_debug, 0);
        }

        RETURN(ocapa);
}

static inline int do_add_mds_capa(struct inode *inode, struct obd_capa **pcapa)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *old = lli->lli_mds_capa;
        struct obd_capa *ocapa = *pcapa;
        int rc = 0;

        if (!old) {
                ocapa->u.cli.inode = inode;
                lli->lli_mds_capa = capa_get(ocapa);
                obd_capa_clear_new(ocapa);
                obd_capa_set_valid(ocapa);

                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "add MDS");
        } else {
                if (ocapa->c_capa.lc_expiry == old->c_capa.lc_expiry) {
                        rc = -EEXIST;
                } else {
                        spin_lock(&old->c_lock);
                        old->c_capa = ocapa->c_capa;
                        obd_capa_set_valid(old);
                        spin_unlock(&old->c_lock);

                        DEBUG_CAPA(D_SEC, &old->c_capa, "update MDS");
                }

                free_capa(ocapa);
                *pcapa = old;
        }

        return rc;
}

static inline void inode_add_oss_capa(struct inode *inode,
                                      struct obd_capa *ocapa)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *tmp;
        struct list_head *next = NULL;

        /* capa is sorted in lli_oss_capas so lookup can always find the
         * latest one */
        list_for_each_entry(tmp, &lli->lli_oss_capas, u.cli.lli_list) {
                if (cfs_time_after(ocapa->c_expiry, tmp->c_expiry)) {
                        next = &tmp->u.cli.lli_list;
                        break;
                }
        }
        list_move_tail(&ocapa->u.cli.lli_list, next ?: &lli->lli_oss_capas);
}

static inline int do_add_oss_capa(struct inode *inode, struct obd_capa **pcapa)
{
        struct obd_capa *old, *ocapa = *pcapa;
        struct lustre_capa *capa = &ocapa->c_capa;
        int rc = 0;

        LASSERTF(S_ISREG(inode->i_mode),
                 "inode has oss capa, but not regular file, mode: %d\n",
                 inode->i_mode);

        /* FIXME: can't replace it so easily with fine-grained opc */
        old = do_lookup_oss_capa(inode, capa->lc_opc & CAPA_OPC_OSS_ONLY);
        if (!old) {
                ocapa->u.cli.inode = inode;
                atomic_set(&ocapa->u.cli.open_count, 0);
                INIT_LIST_HEAD(&ocapa->u.cli.lli_list);
                obd_capa_set_valid(ocapa);

                DEBUG_CAPA(D_SEC, capa, "add OSS");
        } else {
                if (old->c_capa.lc_expiry == capa->lc_expiry) {
                        rc = -EEXIST;
                } else {
                        spin_lock(&old->c_lock);
                        old->c_capa = *capa;
                        obd_capa_set_valid(old);
                        spin_unlock(&old->c_lock);

                        DEBUG_CAPA(D_SEC, capa, "update OSS");
                }

                free_capa(ocapa);
                *pcapa = old;
        }

        if (!rc)
                inode_add_oss_capa(inode, *pcapa);
        return rc;
}

struct obd_capa *ll_add_capa(struct inode *inode, struct obd_capa *ocapa)
{
        struct obd_capa **pcapa = &ocapa;
        int rc;

        spin_lock(&capa_lock);
        rc = capa_for_mds(&ocapa->c_capa) ?  do_add_mds_capa(inode, pcapa) :
                                             do_add_oss_capa(inode, pcapa);

        ocapa = *pcapa;
        /* truncate capa won't renew, or no existed capa changed, don't update
         * capa timer. */
        if (!rc && ocapa->c_capa.lc_opc != CAPA_OPC_OSS_TRUNC) {
                list_del_init(&ocapa->c_list);
                sort_add_capa(ocapa, ll_capa_list);

                spin_lock(&ocapa->c_lock);
                set_capa_expiry(ocapa);
                spin_unlock(&ocapa->c_lock);
                update_capa_timer(ocapa, capa_renewal_time(ocapa));
        }

        atomic_set(&ll_capa_debug, 1);
        spin_unlock(&capa_lock);

        return ocapa;
}


int ll_update_capa(struct obd_capa *ocapa, struct lustre_capa *capa)
{
        struct inode *inode = ocapa->u.cli.inode;
        cfs_time_t expiry;
        int rc = 0;

        LASSERT(ocapa);

        if (IS_ERR(capa)) {
                /* set error code */
                rc = PTR_ERR(capa);
                /* failed capa won't be renewed any longer, but if -EIO, client
                 * might be doing recovery, retry in 1 min. */
                spin_lock(&capa_lock);
                if (rc == -EIO) {
                        expiry = cfs_time_current() + cfs_time_seconds(60);
                        DEBUG_CAPA(D_SEC, &ocapa->c_capa,
                                   "renewal failed: -EIO, retry in 1 min");
                        goto retry;
                } else {
                        sort_add_capa(ocapa, &ll_idle_capas);
                }
                spin_unlock(&capa_lock);

                DEBUG_CAPA(rc == -ENOENT ? D_SEC : D_ERROR, &ocapa->c_capa,
                           "renewal failed(rc: %d) for", rc);
                goto out;
        }

        LASSERT(!memcmp(&ocapa->c_capa, capa,
                        offsetof(struct lustre_capa, lc_flags)));

        spin_lock(&ocapa->c_lock);
        ocapa->c_capa = *capa;
        set_capa_expiry(ocapa);
        spin_unlock(&ocapa->c_lock);

        spin_lock(&capa_lock);
        if (capa->lc_opc & (CAPA_OPC_OSS_READ | CAPA_OPC_OSS_WRITE))
                inode_add_oss_capa(inode, ocapa);
        DEBUG_CAPA(D_SEC, capa, "renew");

        expiry = capa_renewal_time(ocapa);
retry:
        sort_add_capa(ocapa, ll_capa_list);
        update_capa_timer(ocapa, expiry);
        spin_unlock(&capa_lock);

out:
        capa_put(ocapa);
        iput(inode);
        return rc;
}

void ll_oss_capa_open(struct inode *inode, struct file *file)
{
        struct obd_capa *ocapa;
        int opc = capa_open_opc(open_flags_to_accmode(file->f_flags));

        if ((ll_i2sbi(inode)->ll_flags & LL_SBI_OSS_CAPA) == 0)
                return;

        if (!S_ISREG(inode->i_mode))
                return;

        spin_lock(&capa_lock);
        ocapa = do_lookup_oss_capa(inode, opc);
        if (!ocapa) {
                if (atomic_read(&ll_capa_debug)) {
                        CDEBUG(D_ERROR, "no opc %x capability for fid "DFID"\n",
                               opc, PFID(ll_inode2fid(inode)));
                        atomic_set(&ll_capa_debug, 0);
                }
                spin_unlock(&capa_lock);
                return;
        }
        atomic_inc(&ocapa->u.cli.open_count);
        spin_unlock(&capa_lock);

        DEBUG_CAPA(D_SEC, &ocapa->c_capa, "open (count: %d)",
                   atomic_read(&ocapa->u.cli.open_count));
}

void ll_oss_capa_close(struct inode *inode, struct file *file)
{
        struct obd_capa *ocapa;
        int opc = capa_open_opc(open_flags_to_accmode(file->f_flags));

        if ((ll_i2sbi(inode)->ll_flags & LL_SBI_OSS_CAPA) == 0)
                return;

        if (!S_ISREG(inode->i_mode))
                return;

        spin_lock(&capa_lock);
        ocapa = do_lookup_oss_capa(inode, opc);
        if (!ocapa) {
                spin_unlock(&capa_lock);
                return;
        }
        atomic_dec(&ocapa->u.cli.open_count);
        spin_unlock(&capa_lock);

        DEBUG_CAPA(D_SEC, &ocapa->c_capa, "close (count: %d)",
                   atomic_read(&ocapa->u.cli.open_count));
}

/* delete CAPA_OPC_OSS_TRUNC only */
void ll_truncate_free_capa(struct obd_capa *ocapa)
{
        struct inode *inode;

        if (!ocapa)
                return;

        LASSERT(ocapa->c_capa.lc_opc & CAPA_OPC_OSS_TRUNC);
        DEBUG_CAPA(D_SEC, &ocapa->c_capa, "release truncate");

        inode = ocapa->u.cli.inode;

        spin_lock(&capa_lock);
        capa_put(ocapa);
        ll_delete_capa(ocapa);
        spin_unlock(&capa_lock);
}

void ll_clear_inode_capas(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct obd_capa *ocapa, *tmp;

        spin_lock(&capa_lock);
        ocapa = lli->lli_mds_capa;
        if (ocapa)
                ll_delete_capa(ocapa);
                
        list_for_each_entry_safe(ocapa, tmp, &lli->lli_oss_capas,
                                 u.cli.lli_list)
                ll_delete_capa(ocapa);
        spin_unlock(&capa_lock);
}
