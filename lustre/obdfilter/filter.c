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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdfilter/filter.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

/*
 * Invariant: Get O/R i_mutex for lookup, if needed, before any journal ops
 *            (which need to get journal_lock, may block if journal full).
 *
 * Invariant: Call filter_start_transno() before any journal ops to avoid the
 *            same deadlock problem.  We can (and want) to get rid of the
 *            transno sem in favour of the dir/inode i_mutex to avoid single
 *            threaded operation on the OST.
 */

#define DEBUG_SUBSYSTEM S_FILTER
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/buffer_head.h>

#include <obd_class.h>
#include <obd_lov.h>
#include <lustre_dlm.h>
#include <lustre_fsfilt.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include <libcfs/list.h>
#include <lustre_disk.h>
#include <lustre_quota.h>
#include <linux/slab.h>
#include <lustre_param.h>
#include <lustre/ll_fiemap.h>

#include "filter_internal.h"

static struct lvfs_callback_ops filter_lvfs_ops;
cfs_mem_cache_t *ll_fmd_cachep;

static void filter_commit_cb(struct obd_device *obd, __u64 transno,
                             void *cb_data, int error)
{
        struct obd_export *exp = cb_data;
        LASSERTF(exp->exp_obd == obd,
                 "%s: bad export (%p), obd (%p) != exp->exp_obd (%p)\n",
                 obd->obd_name, exp, obd, exp->exp_obd);
        obd_transno_commit_cb(obd, transno, exp, error);
        class_export_put(exp);
}

int filter_version_get_check(struct obd_export *exp,
                             struct obd_trans_info *oti, struct inode *inode)
{
        __u64 curr_version;

        if (inode == NULL || oti == NULL)
                RETURN(0);

        curr_version = fsfilt_get_version(exp->exp_obd, inode);
        if ((__s64)curr_version == -EOPNOTSUPP)
                RETURN(0);
        /* VBR: version is checked always because costs nothing */
        if (oti->oti_pre_version != 0 &&
            oti->oti_pre_version != curr_version) {
                CDEBUG(D_INODE, "Version mismatch "LPX64" != "LPX64"\n",
                       oti->oti_pre_version, curr_version);
                spin_lock(&exp->exp_lock);
                exp->exp_vbr_failed = 1;
                spin_unlock(&exp->exp_lock);
                RETURN (-EOVERFLOW);
        }
        oti->oti_pre_version = curr_version;
        RETURN(0);
}

/* Assumes caller has already pushed us into the kernel context. */
int filter_finish_transno(struct obd_export *exp, struct inode *inode,
                          struct obd_trans_info *oti,
                          int rc, int force_sync)
{
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct lr_server_data *lsd = filter->fo_fsd;
        struct lsd_client_data *lcd = fed->fed_lcd;
        __u64 last_rcvd;
        loff_t off;
        int err, log_pri = D_RPCTRACE;

        /* Propagate error code. */
        if (rc)
                RETURN(rc);

        if (!exp->exp_obd->obd_replayable || oti == NULL)
                RETURN(rc);

        /* we don't allocate new transnos for replayed requests */
        spin_lock(&filter->fo_translock);
        if (oti->oti_transno == 0) {
                last_rcvd = le64_to_cpu(lsd->lsd_last_transno) + 1;
                lsd->lsd_last_transno = cpu_to_le64(last_rcvd);
                LASSERT(last_rcvd >= le64_to_cpu(lcd->lcd_last_transno));
        } else {
                last_rcvd = oti->oti_transno;
                if (last_rcvd > le64_to_cpu(lsd->lsd_last_transno))
                        lsd->lsd_last_transno = cpu_to_le64(last_rcvd);
                if (unlikely(last_rcvd < le64_to_cpu(lcd->lcd_last_transno))) {
                        spin_lock(&exp->exp_lock);
                        exp->exp_vbr_failed = 1;
                        spin_unlock(&exp->exp_lock);
                        spin_unlock(&filter->fo_translock);
                        CERROR("last_rcvd ("LPU64") < lcd_last_transno "
                               "("LPU64")\n", last_rcvd,
                               le64_to_cpu(lcd->lcd_last_transno));
                        RETURN (-EOVERFLOW);
                }
        }
        oti->oti_transno = last_rcvd;
        lcd->lcd_last_transno = cpu_to_le64(last_rcvd);
        lcd->lcd_pre_versions[0] = cpu_to_le64(oti->oti_pre_version);
        lcd->lcd_last_xid = cpu_to_le64(oti->oti_xid);
        target_trans_table_update(exp, last_rcvd);

        spin_unlock(&filter->fo_translock);

        if (inode)
                fsfilt_set_version(exp->exp_obd, inode, last_rcvd);

        off = fed->fed_lr_off;
        if (off <= 0) {
                CERROR("%s: client idx %d is %lld\n", exp->exp_obd->obd_name,
                       fed->fed_lr_idx, fed->fed_lr_off);
                err = -EINVAL;
        } else {
                class_export_get(exp); /* released when the cb is called */
                if (!force_sync)
                        force_sync = fsfilt_add_journal_cb(exp->exp_obd,
                                                           last_rcvd,
                                                           oti->oti_handle,
                                                           filter_commit_cb,
                                                           exp);

                err = fsfilt_write_record(exp->exp_obd, filter->fo_rcvd_filp,
                                          lcd, sizeof(*lcd), &off,
                                          force_sync | exp->exp_need_sync);
                if (force_sync)
                        filter_commit_cb(exp->exp_obd, last_rcvd, exp, err);
        }
        if (err) {
                log_pri = D_ERROR;
                if (rc == 0)
                        rc = err;
        }

        CDEBUG(log_pri, "wrote trans "LPU64" for client %s at #%d: err = %d\n",
               last_rcvd, lcd->lcd_uuid, fed->fed_lr_idx, err);

        RETURN(rc);
}

void f_dput(struct dentry *dentry)
{
        /* Can't go inside filter_ddelete because it can block */
        CDEBUG(D_INODE, "putting %s: %p, count = %d\n",
               dentry->d_name.name, dentry, atomic_read(&dentry->d_count) - 1);
        LASSERT(atomic_read(&dentry->d_count) > 0);

        dput(dentry);
}

static void init_brw_stats(struct brw_stats *brw_stats)
{
        int i;
        for (i = 0; i < BRW_LAST; i++)
                spin_lock_init(&brw_stats->hist[i].oh_lock);
}

static int lprocfs_init_rw_stats(struct obd_device *obd,
                                 struct lprocfs_stats **stats)
{
        int num_stats;

        num_stats = (sizeof(*obd->obd_type->typ_ops) / sizeof(void *)) +
                                                        LPROC_FILTER_LAST - 1;
        *stats = lprocfs_alloc_stats(num_stats, LPROCFS_STATS_FLAG_NOPERCPU);
        if (*stats == NULL)
                return -ENOMEM;

        lprocfs_init_ops_stats(LPROC_FILTER_LAST, *stats);
        lprocfs_counter_init(*stats, LPROC_FILTER_READ_BYTES,
                             LPROCFS_CNTR_AVGMINMAX, "read_bytes", "bytes");
        lprocfs_counter_init(*stats, LPROC_FILTER_WRITE_BYTES,
                             LPROCFS_CNTR_AVGMINMAX, "write_bytes", "bytes");

        return(0);
}

/* brw_stats are 2128, ops are 3916, ldlm are 204, so 6248 bytes per client,
   plus the procfs overhead :( */
static int filter_export_stats_init(struct obd_device *obd,
                                    struct obd_export *exp,
                                    void *client_nid)
{
        struct proc_dir_entry *brw_entry;
        int rc, newnid = 0;
        ENTRY;

        if (obd_uuid_equals(&exp->exp_client_uuid, &obd->obd_uuid))
                /* Self-export gets no proc entry */
                RETURN(0);
        rc = lprocfs_exp_setup(exp, (lnet_nid_t *)client_nid, &newnid);
        if (rc) {
                /* Mask error for already created
                 * /proc entries */
                if (rc == -EALREADY)
                        rc = 0;

                RETURN(rc);
        }

        if (newnid) {
                struct nid_stat *tmp = exp->exp_nid_stats;
                LASSERT(tmp != NULL);

                OBD_ALLOC(tmp->nid_brw_stats, sizeof(struct brw_stats));
                if (tmp->nid_brw_stats == NULL)
                        RETURN(-ENOMEM);

                init_brw_stats(tmp->nid_brw_stats);

                brw_entry = create_proc_entry("brw_stats", 0644,
                                              exp->exp_nid_stats->nid_proc);
                if (brw_entry == NULL)
                       RETURN(-ENOMEM);

                brw_entry->proc_fops = &filter_per_nid_stats_fops;
                brw_entry->data = exp->exp_nid_stats;

                rc = lprocfs_init_rw_stats(obd, &exp->exp_nid_stats->nid_stats);
                if (rc)
                        RETURN(rc);

                rc = lprocfs_nid_ldlm_stats_init(tmp);
                if (rc)
                        RETURN(rc);
        }

        RETURN(0);
}

/* VBR: to determine the delayed client the lcd should be updated for each new
 * epoch */
static int filter_update_client_epoch(struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct lvfs_run_ctxt saved;
        loff_t off = fed->fed_lr_off;
        int rc = 0;

        /* VBR: set client last_epoch to current epoch */
        if (le32_to_cpu(fed->fed_lcd->lcd_last_epoch) >=
                        le32_to_cpu(filter->fo_fsd->lsd_start_epoch))
                return rc;
        fed->fed_lcd->lcd_last_epoch = filter->fo_fsd->lsd_start_epoch;
        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
        rc = fsfilt_write_record(exp->exp_obd, filter->fo_rcvd_filp,
                                 fed->fed_lcd, sizeof(*fed->fed_lcd), &off,
                                 exp->exp_delayed);
        pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);

        CDEBUG(D_INFO, "update client idx %u last_epoch %#x (%#x)\n",
               fed->fed_lr_idx, le32_to_cpu(fed->fed_lcd->lcd_last_epoch),
               le32_to_cpu(filter->fo_fsd->lsd_start_epoch));

        return rc;
}

/* Called after recovery is done on server */
static void filter_update_last_epoch(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        struct filter_obd *filter = &obd->u.filter;
        struct lr_server_data *fsd = filter->fo_fsd;
        __u32 start_epoch;

        /* Increase server epoch after recovery */
        spin_lock(&filter->fo_translock);
        /* VBR: increase the epoch and store it in lsd */
        start_epoch = lr_epoch(le64_to_cpu(fsd->lsd_last_transno)) + 1;
        fsd->lsd_last_transno = cpu_to_le64((__u64)start_epoch << LR_EPOCH_BITS);
        fsd->lsd_start_epoch = cpu_to_le32(start_epoch);
        spin_unlock(&filter->fo_translock);

        /* go through delayed reply queue to find all exports participate in
         * recovery and set new epoch for them */
        list_for_each_entry(req, &obd->obd_delayed_reply_queue, rq_list) {
                LASSERT(!req->rq_export->exp_delayed);
                filter_update_client_epoch(req->rq_export);
        }
        filter_update_server_data(obd, filter->fo_rcvd_filp, fsd, 1);
}

static int filter_postrecov(struct obd_device *obd)
{
        ENTRY;

        if (obd->obd_fail)
                RETURN(0);

        LASSERT(!obd->obd_recovering);
        /* VBR: update start_epoch on server */
        filter_update_last_epoch(obd);

        RETURN(0);
}

/* Add client data to the FILTER.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_idx is -1 (i.e. a new client).
 * Otherwise, we have just read the data from the last_rcvd file and
 * we know its offset. */
static int filter_client_add(struct obd_device *obd, struct obd_export *exp,
                             int cl_idx)
{
        struct filter_obd *filter = &obd->u.filter;
        struct filter_export_data *fed = &exp->exp_filter_data;
        unsigned long *bitmap = filter->fo_last_rcvd_slots;
        int new_client = (cl_idx == -1);

        ENTRY;

        LASSERT(bitmap != NULL);
        LASSERTF(cl_idx > -2, "%d\n", cl_idx);

        /* Self-export */
        if (strcmp(fed->fed_lcd->lcd_uuid, obd->obd_uuid.uuid) == 0)
                RETURN(0);

        /* VBR: remove expired exports before searching for free slot */
        if (new_client)
                class_disconnect_expired_exports(obd);

        /* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        if (new_client) {
                cl_idx = find_first_zero_bit(bitmap, LR_MAX_CLIENTS);
        repeat:
                if (cl_idx >= LR_MAX_CLIENTS) {
                        CERROR("no room for %u clients - fix LR_MAX_CLIENTS\n",
                               cl_idx);
                        RETURN(-EOVERFLOW);
                }
                if (test_and_set_bit(cl_idx, bitmap)) {
                        cl_idx = find_next_zero_bit(bitmap, LR_MAX_CLIENTS,
                                                    cl_idx);
                        goto repeat;
                }
        } else {
                if (test_and_set_bit(cl_idx, bitmap)) {
                        CERROR("FILTER client %d: bit already set in bitmap!\n",
                               cl_idx);
                        LBUG();
                }
        }

        fed->fed_lr_idx = cl_idx;
        fed->fed_lr_off = le32_to_cpu(filter->fo_fsd->lsd_client_start) +
                cl_idx * le16_to_cpu(filter->fo_fsd->lsd_client_size);
        LASSERTF(fed->fed_lr_off > 0, "fed_lr_off = %llu\n", fed->fed_lr_off);

        CDEBUG(D_INFO, "client at index %d (%llu) with UUID '%s' added\n",
               fed->fed_lr_idx, fed->fed_lr_off, fed->fed_lcd->lcd_uuid);

        if (new_client) {
                struct lvfs_run_ctxt saved;
                loff_t off = fed->fed_lr_off;
                void *handle;
                int rc;

                CDEBUG(D_INFO, "writing client lcd at idx %u (%llu) (len %u)\n",
                       fed->fed_lr_idx,off,(unsigned int)sizeof(*fed->fed_lcd));

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                /* Transaction needed to fix bug 1403 */
                handle = fsfilt_start(obd,
                                      filter->fo_rcvd_filp->f_dentry->d_inode,
                                      FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        CERROR("unable to start transaction: rc %d\n", rc);
                } else {
                        fed->fed_lcd->lcd_last_epoch =
                                              filter->fo_fsd->lsd_start_epoch;
                        exp->exp_last_request_time = cfs_time_current_sec();
                        rc = fsfilt_add_journal_cb(obd, 0, handle,
                                                   target_client_add_cb, exp);
                        if (rc == 0) {
                                spin_lock(&exp->exp_lock);
                                exp->exp_need_sync = 1;
                                spin_unlock(&exp->exp_lock);
                        }
                        rc = fsfilt_write_record(obd, filter->fo_rcvd_filp,
                                                 fed->fed_lcd,
                                                 sizeof(*fed->fed_lcd),
                                                 &off, rc /* sync if no cb */);
                        fsfilt_commit(obd,
                                      filter->fo_rcvd_filp->f_dentry->d_inode,
                                      handle, 0);
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                if (rc) {
                        CERROR("error writing %s client idx %u: rc %d\n",
                               LAST_RCVD, fed->fed_lr_idx, rc);
                        RETURN(rc);
                }
        }
        RETURN(0);
}

struct lsd_client_data zero_lcd; /* globals are implicitly zeroed */

static int filter_client_free(struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct obd_device *obd = exp->exp_obd;
        struct lvfs_run_ctxt saved;
        int rc;
        loff_t off;
        ENTRY;

        if (fed->fed_lcd == NULL)
                RETURN(0);

        /* Do not erase record for recoverable client. */
        if (obd->obd_fail && !exp->exp_failed)
                GOTO(free, 0);

        /* XXX if lcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (strcmp(fed->fed_lcd->lcd_uuid, obd->obd_uuid.uuid ) == 0)
                GOTO(free, 0);

        LASSERT(filter->fo_last_rcvd_slots != NULL);

        off = fed->fed_lr_off;

        CDEBUG(D_INFO, "freeing client at idx %u, offset %lld with UUID '%s'\n",
               fed->fed_lr_idx, fed->fed_lr_off, fed->fed_lcd->lcd_uuid);

        /* Don't clear fed_lr_idx here as it is likely also unset.  At worst
         * we leak a client slot that will be cleaned on the next recovery. */
        if (off <= 0) {
                CERROR("%s: client idx %d has med_off %lld\n",
                       obd->obd_name, fed->fed_lr_idx, off);
                GOTO(free, rc = -EINVAL);
        }

        /* Clear the bit _after_ zeroing out the client so we don't
           race with filter_client_add and zero out new clients.*/
        if (!test_bit(fed->fed_lr_idx, filter->fo_last_rcvd_slots)) {
                CERROR("FILTER client %u: bit already clear in bitmap!!\n",
                       fed->fed_lr_idx);
                LBUG();
        }

        if (!(exp->exp_flags & OBD_OPT_FAILOVER)) {
                /* Don't force sync on disconnect if aborting recovery,
                 * or it does num_clients * num_osts.  b=17194 */
                int need_sync = exp->exp_need_sync &&
                                !(exp->exp_flags&OBD_OPT_ABORT_RECOV);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_write_record(obd, filter->fo_rcvd_filp, &zero_lcd,
                                         sizeof(zero_lcd), &off, 0);

                /* Make sure the server's last_transno is up to date. Do this
                 * after the client is freed so we know all the client's
                 * transactions have been committed. */
                if (rc == 0)
                        filter_update_server_data(obd, filter->fo_rcvd_filp,
                                                  filter->fo_fsd, need_sync);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                CDEBUG(rc == 0 ? D_INFO : D_ERROR,
                       "zero out client %s at idx %u/%llu in %s %ssync rc %d\n",
                       fed->fed_lcd->lcd_uuid, fed->fed_lr_idx, fed->fed_lr_off,
                       LAST_RCVD, need_sync ? "" : "a", rc);
        }

        if (!test_and_clear_bit(fed->fed_lr_idx, filter->fo_last_rcvd_slots)) {
                CERROR("FILTER client %u: bit already clear in bitmap!!\n",
                       fed->fed_lr_idx);
                LBUG();
        }

        EXIT;
free:
        OBD_FREE_PTR(fed->fed_lcd);
        fed->fed_lcd = NULL;

        return 0;
}

/* drop fmd reference, free it if last ref. must be called with fed_lock held.*/
static inline void filter_fmd_put_nolock(struct filter_export_data *fed,
                                         struct filter_mod_data *fmd)
{
        LASSERT_SPIN_LOCKED(&fed->fed_lock);
        if (--fmd->fmd_refcount == 0) {
                /* XXX when we have persistent reservations and the handle
                 * is stored herein we need to drop it here. */
                fed->fed_mod_count--;
                list_del(&fmd->fmd_list);
                OBD_SLAB_FREE(fmd, ll_fmd_cachep, sizeof(*fmd));
        }
}

/* drop fmd reference, free it if last ref */
void filter_fmd_put(struct obd_export *exp, struct filter_mod_data *fmd)
{
        struct filter_export_data *fed;

        if (fmd == NULL)
                return;

        fed = &exp->exp_filter_data;
        spin_lock(&fed->fed_lock);
        filter_fmd_put_nolock(fed, fmd); /* caller reference */
        spin_unlock(&fed->fed_lock);
}

/* expire entries from the end of the list if there are too many
 * or they are too old */
static void filter_fmd_expire_nolock(struct filter_obd *filter,
                                     struct filter_export_data *fed,
                                     struct filter_mod_data *keep)
{
        struct filter_mod_data *fmd, *tmp;

        list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
                if (fmd == keep)
                        break;

                if (time_before(jiffies, fmd->fmd_expire) &&
                    fed->fed_mod_count < filter->fo_fmd_max_num)
                        break;

                list_del_init(&fmd->fmd_list);
                filter_fmd_put_nolock(fed, fmd); /* list reference */
        }
}

void filter_fmd_expire(struct obd_export *exp)
{
        spin_lock(&exp->exp_filter_data.fed_lock);
        filter_fmd_expire_nolock(&exp->exp_obd->u.filter,
                                 &exp->exp_filter_data, NULL);
        spin_unlock(&exp->exp_filter_data.fed_lock);
}

/* find specified objid, group in export fmd list.
 * caller must hold fed_lock and take fmd reference itself */
static struct filter_mod_data *filter_fmd_find_nolock(struct filter_obd *filter,
                                                struct filter_export_data *fed,
                                                obd_id objid, obd_gr group)
{
        struct filter_mod_data *found = NULL, *fmd;

        LASSERT_SPIN_LOCKED(&fed->fed_lock);

        list_for_each_entry_reverse(fmd, &fed->fed_mod_list, fmd_list) {
                if (fmd->fmd_id == objid && fmd->fmd_gr == group) {
                        found = fmd;
                        list_del(&fmd->fmd_list);
                        list_add_tail(&fmd->fmd_list, &fed->fed_mod_list);
                        fmd->fmd_expire = jiffies + filter->fo_fmd_max_age;
                        break;
                }
        }

        filter_fmd_expire_nolock(filter, fed, found);

        return found;
}

/* Find fmd based on objid and group, or return NULL if not found. */
struct filter_mod_data *filter_fmd_find(struct obd_export *exp,
                                        obd_id objid, obd_gr group)
{
        struct filter_mod_data *fmd;

        spin_lock(&exp->exp_filter_data.fed_lock);
        fmd = filter_fmd_find_nolock(&exp->exp_obd->u.filter,
                                     &exp->exp_filter_data, objid, group);
        if (fmd)
                fmd->fmd_refcount++;    /* caller reference */
        spin_unlock(&exp->exp_filter_data.fed_lock);

        return fmd;
}

/* Find fmd based on objid and group, or create a new one if none is found.
 * It is possible for this function to return NULL under memory pressure,
 * or if objid = 0 is passed (which will only cause old entries to expire).
 * Currently this is not fatal because any fmd state is transient and
 * may also be freed when it gets sufficiently old. */
struct filter_mod_data *filter_fmd_get(struct obd_export *exp,
                                       obd_id objid, obd_gr group)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_mod_data *found = NULL, *fmd_new = NULL;

        OBD_SLAB_ALLOC(fmd_new, ll_fmd_cachep, CFS_ALLOC_IO, sizeof(*fmd_new));

        spin_lock(&fed->fed_lock);
        found = filter_fmd_find_nolock(&exp->exp_obd->u.filter,fed,objid,group);
        if (fmd_new) {
                if (found == NULL) {
                        list_add_tail(&fmd_new->fmd_list, &fed->fed_mod_list);
                        fmd_new->fmd_id = objid;
                        fmd_new->fmd_gr = group;
                        fmd_new->fmd_refcount++;   /* list reference */
                        found = fmd_new;
                        fed->fed_mod_count++;
                } else {
                        OBD_SLAB_FREE(fmd_new, ll_fmd_cachep, sizeof(*fmd_new));
                }
        }
        if (found) {
                found->fmd_refcount++;          /* caller reference */
                found->fmd_expire = jiffies +
                        exp->exp_obd->u.filter.fo_fmd_max_age;
        }

        spin_unlock(&fed->fed_lock);

        return found;
}

#ifdef DO_FMD_DROP
/* drop fmd list reference so it will disappear when last reference is put.
 * This isn't so critical because it would in fact only affect the one client
 * that is doing the unlink and at worst we have an stale entry referencing
 * an object that should never be used again. */
static void filter_fmd_drop(struct obd_export *exp, obd_id objid, obd_gr group)
{
        struct filter_mod_data *found = NULL;

        spin_lock(&exp->exp_filter_data.fed_lock);
        found = filter_fmd_find_nolock(&exp->exp_filter_data, objid, group);
        if (found) {
                list_del_init(&found->fmd_list);
                filter_fmd_put_nolock(&exp->exp_filter_data, found);
        }
        spin_unlock(&exp->exp_filter_data.fed_lock);
}
#else
#define filter_fmd_drop(exp, objid, group)
#endif

/* remove all entries from fmd list */
static void filter_fmd_cleanup(struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_mod_data *fmd = NULL, *tmp;

        spin_lock(&fed->fed_lock);
        list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
                list_del_init(&fmd->fmd_list);
                filter_fmd_put_nolock(fed, fmd);
        }
        spin_unlock(&fed->fed_lock);
}

static int filter_init_export(struct obd_export *exp)
{
        spin_lock_init(&exp->exp_filter_data.fed_lock);
        INIT_LIST_HEAD(&exp->exp_filter_data.fed_mod_list);

        spin_lock(&exp->exp_lock);
        exp->exp_connecting = 1;
        spin_unlock(&exp->exp_lock);

        return ldlm_init_export(exp);
}

static int filter_free_server_data(struct filter_obd *filter)
{
        OBD_FREE(filter->fo_fsd, sizeof(*filter->fo_fsd));
        filter->fo_fsd = NULL;
        OBD_FREE(filter->fo_last_rcvd_slots, LR_MAX_CLIENTS / 8);
        filter->fo_last_rcvd_slots = NULL;
        return 0;
}

/* assumes caller is already in kernel ctxt */
int filter_update_server_data(struct obd_device *obd, struct file *filp,
                              struct lr_server_data *fsd, int force_sync)
{
        loff_t off = 0;
        int rc;
        ENTRY;

        CDEBUG(D_INODE, "server uuid      : %s\n", fsd->lsd_uuid);
        CDEBUG(D_INODE, "server last_rcvd : "LPU64"\n",
               le64_to_cpu(fsd->lsd_last_transno));
        CDEBUG(D_INODE, "server last_mount: "LPU64"\n",
               le64_to_cpu(fsd->lsd_mount_count));

        fsd->lsd_compat14 = fsd->lsd_last_transno;
        rc = fsfilt_write_record(obd, filp, fsd, sizeof(*fsd), &off,force_sync);
        if (rc)
                CERROR("error writing lr_server_data: rc = %d\n", rc);

        RETURN(rc);
}

int filter_update_last_objid(struct obd_device *obd, obd_gr group,
                             int force_sync)
{
        struct filter_obd *filter = &obd->u.filter;
        __u64 tmp;
        loff_t off = 0;
        int rc;
        ENTRY;

        if (filter->fo_last_objid_files[group] == NULL) {
                CERROR("Object group "LPU64" not fully setup; not updating "
                       "last_objid\n", group);
                RETURN(-EINVAL);
        }

        CDEBUG(D_INODE, "%s: server last_objid for group "LPU64": "LPU64"\n",
               obd->obd_name, group, filter->fo_last_objids[group]);

        tmp = cpu_to_le64(filter->fo_last_objids[group]);
        rc = fsfilt_write_record(obd, filter->fo_last_objid_files[group],
                                 &tmp, sizeof(tmp), &off, force_sync);
        if (rc)
                CERROR("error writing group "LPU64" last objid: rc = %d\n",
                       group, rc);
        RETURN(rc);
}

/* assumes caller has already in kernel ctxt */
static int filter_init_server_data(struct obd_device *obd, struct file * filp)
{
        struct filter_obd *filter = &obd->u.filter;
        struct lr_server_data *fsd;
        struct lsd_client_data *lcd = NULL;
        struct inode *inode = filp->f_dentry->d_inode;
        unsigned long last_rcvd_size = i_size_read(inode);
        struct lustre_mount_info *lmi;
        __u64 mount_count;
        __u32 start_epoch;
        int cl_idx;
        loff_t off = 0;
        int rc;

        /* ensure padding in the struct is the correct size */
        CLASSERT (offsetof(struct lr_server_data, lsd_padding) +
                 sizeof(fsd->lsd_padding) == LR_SERVER_SIZE);
        CLASSERT (offsetof(struct lsd_client_data, lcd_padding) +
                 sizeof(lcd->lcd_padding) == LR_CLIENT_SIZE);

        OBD_ALLOC(fsd, sizeof(*fsd));
        if (!fsd)
                RETURN(-ENOMEM);
        filter->fo_fsd = fsd;

        OBD_ALLOC(filter->fo_last_rcvd_slots, LR_MAX_CLIENTS / 8);
        if (filter->fo_last_rcvd_slots == NULL) {
                OBD_FREE(fsd, sizeof(*fsd));
                RETURN(-ENOMEM);
        }

        if (last_rcvd_size == 0) {
                LCONSOLE_WARN("%s: new disk, initializing\n", obd->obd_name);

                memcpy(fsd->lsd_uuid, obd->obd_uuid.uuid,sizeof(fsd->lsd_uuid));
                fsd->lsd_last_transno = 0;
                mount_count = fsd->lsd_mount_count = 0;
                fsd->lsd_server_size = cpu_to_le32(LR_SERVER_SIZE);
                fsd->lsd_client_start = cpu_to_le32(LR_CLIENT_START);
                fsd->lsd_client_size = cpu_to_le16(LR_CLIENT_SIZE);
                fsd->lsd_subdir_count = cpu_to_le16(FILTER_SUBDIR_COUNT);
                filter->fo_subdir_count = FILTER_SUBDIR_COUNT;
                fsd->lsd_feature_incompat = cpu_to_le32(OBD_INCOMPAT_OST);
        } else {
                rc = fsfilt_read_record(obd, filp, fsd, sizeof(*fsd), &off);
                if (rc) {
                        CDEBUG(D_INODE,"OBD filter: error reading %s: rc %d\n",
                               LAST_RCVD, rc);
                        GOTO(err_fsd, rc);
                }
                if (strcmp(fsd->lsd_uuid, obd->obd_uuid.uuid) != 0) {
                        LCONSOLE_ERROR_MSG(0x134, "Trying to start OBD %s using"
                                           " the wrong disk %s. Were the /dev/ "
                                           "assignments rearranged?\n",
                                           obd->obd_uuid.uuid, fsd->lsd_uuid);
                        GOTO(err_fsd, rc = -EINVAL);
                }
                mount_count = le64_to_cpu(fsd->lsd_mount_count);
                filter->fo_subdir_count = le16_to_cpu(fsd->lsd_subdir_count);
                /* COMPAT_146 */
                /* Assume old last_rcvd format unless I_C_LR is set */
                if (!(fsd->lsd_feature_incompat &
                      cpu_to_le32(OBD_INCOMPAT_COMMON_LR)))
                        fsd->lsd_last_transno = fsd->lsd_compat14;
                /* end COMPAT_146 */
        }

        if (fsd->lsd_feature_incompat & ~cpu_to_le32(FILTER_INCOMPAT_SUPP)) {
                CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
                       obd->obd_name, le32_to_cpu(fsd->lsd_feature_incompat) &
                       ~FILTER_INCOMPAT_SUPP);
                GOTO(err_fsd, rc = -EINVAL);
        }
        if (fsd->lsd_feature_rocompat & ~cpu_to_le32(FILTER_ROCOMPAT_SUPP)) {
                CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
                       obd->obd_name, le32_to_cpu(fsd->lsd_feature_rocompat) &
                       ~FILTER_ROCOMPAT_SUPP);
                /* Do something like remount filesystem read-only */
                GOTO(err_fsd, rc = -EINVAL);
        }

        target_trans_table_init(obd);
        start_epoch = le32_to_cpu(fsd->lsd_start_epoch);

        CDEBUG(D_INODE, "%s: server start_epoch : %#x\n",
               obd->obd_name, start_epoch);
        CDEBUG(D_INODE, "%s: server last_transno : "LPX64"\n",
               obd->obd_name, le64_to_cpu(fsd->lsd_last_transno));
        CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
               obd->obd_name, mount_count + 1);
        CDEBUG(D_INODE, "%s: server data size: %u\n",
               obd->obd_name, le32_to_cpu(fsd->lsd_server_size));
        CDEBUG(D_INODE, "%s: per-client data start: %u\n",
               obd->obd_name, le32_to_cpu(fsd->lsd_client_start));
        CDEBUG(D_INODE, "%s: per-client data size: %u\n",
               obd->obd_name, le32_to_cpu(fsd->lsd_client_size));
        CDEBUG(D_INODE, "%s: server subdir_count: %u\n",
               obd->obd_name, le16_to_cpu(fsd->lsd_subdir_count));
        CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", obd->obd_name,
               last_rcvd_size <= le32_to_cpu(fsd->lsd_client_start) ? 0 :
               (last_rcvd_size - le32_to_cpu(fsd->lsd_client_start)) /
                le16_to_cpu(fsd->lsd_client_size));

        if (!obd->obd_replayable) {
                CWARN("%s: recovery support OFF\n", obd->obd_name);
                GOTO(out, rc = 0);
        }

        for (cl_idx = 0, off = le32_to_cpu(fsd->lsd_client_start);
             off < last_rcvd_size; cl_idx++) {
                __u64 last_rcvd;
                struct obd_export *exp;
                struct filter_export_data *fed;

                if (!lcd) {
                        OBD_ALLOC_PTR(lcd);
                        if (!lcd)
                                GOTO(err_client, rc = -ENOMEM);
                }

                /* Don't assume off is incremented properly by
                 * fsfilt_read_record(), in case sizeof(*lcd)
                 * isn't the same as fsd->lsd_client_size.  */
                off = le32_to_cpu(fsd->lsd_client_start) +
                        cl_idx * le16_to_cpu(fsd->lsd_client_size);
                rc = fsfilt_read_record(obd, filp, lcd, sizeof(*lcd), &off);
                if (rc) {
                        CERROR("error reading FILT %s idx %d off %llu: rc %d\n",
                               LAST_RCVD, cl_idx, off, rc);
                        break; /* read error shouldn't cause startup to fail */
                }

                if (lcd->lcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_idx);
                        continue;
                }

                check_lcd(obd->obd_name, cl_idx, lcd);

                last_rcvd = le64_to_cpu(lcd->lcd_last_transno);

                /* These exports are cleaned up by filter_disconnect(), so they
                 * need to be set up like real exports as filter_connect() does.
                 */
                exp = class_new_export(obd, (struct obd_uuid *)lcd->lcd_uuid);
                CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                       " srv lr: "LPU64"\n", lcd->lcd_uuid, cl_idx,
                       last_rcvd, le64_to_cpu(fsd->lsd_last_transno));
                if (IS_ERR(exp)) {
                        if (PTR_ERR(exp) == -EALREADY) {
                                /* export already exists, zero out this one */
                                CERROR("Zeroing out duplicate export due to "
                                       "bug 10479.\n");
                                lcd->lcd_uuid[0] = '\0';
                        } else {
                                OBD_FREE_PTR(lcd);
                                GOTO(err_client, rc = PTR_ERR(exp));
                        }
                } else {
                        fed = &exp->exp_filter_data;
                        fed->fed_lcd = lcd;
                        filter_export_stats_init(obd, exp, NULL);
                        rc = filter_client_add(obd, exp, cl_idx);
                        /* can't fail for existing client */
                        LASSERTF(rc == 0, "rc = %d\n", rc);

                        /* VBR: set export last committed */
                        exp->exp_last_committed = last_rcvd;
                        /* read last time from disk */
                        exp->exp_last_request_time = target_trans_table_last_time(exp);

                        spin_lock(&exp->exp_lock);
                        exp->exp_replay_needed = 1;
                        exp->exp_connecting = 0;
                        exp->exp_in_recovery = 0;
                        spin_unlock(&exp->exp_lock);

                        spin_lock_bh(&obd->obd_processing_task_lock);
                        obd->obd_recoverable_clients++;
                        obd->obd_max_recoverable_clients++;
                        spin_unlock_bh(&obd->obd_processing_task_lock);

                        /* VBR: if epoch too old mark export as delayed,
                         * if epoch is zero then client is pre-vbr one */
                        if (start_epoch > le32_to_cpu(lcd->lcd_last_epoch) &&
                            le32_to_cpu(lcd->lcd_last_epoch) != 0)
                                class_set_export_delayed(exp);

                        lcd = NULL;
                        class_export_put(exp);
                }

                /* Need to check last_rcvd even for duplicated exports. */
                CDEBUG(D_OTHER, "client at idx %d has last_rcvd = "LPX64"\n",
                       cl_idx, last_rcvd);

                if (last_rcvd > le64_to_cpu(fsd->lsd_last_transno))
                        fsd->lsd_last_transno = cpu_to_le64(last_rcvd);
        }

        if (lcd)
                OBD_FREE_PTR(lcd);

        obd->obd_last_committed = le64_to_cpu(fsd->lsd_last_transno);

        if (obd->obd_recoverable_clients) {
                CWARN("RECOVERY: service %s, %d recoverable clients, "
                      "%d delayed clients, last_rcvd "LPU64"\n",
                      obd->obd_name, obd->obd_recoverable_clients,
                      obd->obd_delayed_clients,
                      le64_to_cpu(fsd->lsd_last_transno));
                obd->obd_next_recovery_transno = obd->obd_last_committed + 1;
                obd->obd_recovering = 1;
                obd->obd_recovery_start = 0;
                obd->obd_recovery_end = 0;
        } else {
                LASSERT(!obd->obd_recovering);
                /* VBR: update boot epoch after recovery */
                filter_update_last_epoch(obd);
        }

        obd->obd_recovery_timeout = OBD_RECOVERY_TIME_SOFT;
        obd->obd_recovery_time_hard = OBD_RECOVERY_TIME_HARD;

        lmi = server_find_mount_locked(obd->obd_name);
        if (lmi) {
                struct lustre_sb_info *lsi = s2lsi(lmi->lmi_sb);

                if (lsi->lsi_lmd && lsi->lsi_lmd->lmd_recovery_time_soft)
                        obd->obd_recovery_timeout =
                                lsi->lsi_lmd->lmd_recovery_time_soft;

                if (lsi->lsi_lmd && lsi->lsi_lmd->lmd_recovery_time_hard)
                        obd->obd_recovery_time_hard =
                                lsi->lsi_lmd->lmd_recovery_time_hard;
        }

out:
        filter->fo_mount_count = mount_count + 1;
        fsd->lsd_mount_count = cpu_to_le64(filter->fo_mount_count);

        /* save it, so mount count and last_transno is current */
        rc = filter_update_server_data(obd, filp, filter->fo_fsd, 1);
        if (rc)
                GOTO(err_client, rc);

        RETURN(0);

err_client:
        class_disconnect_exports(obd);
err_fsd:
        filter_free_server_data(filter);
        RETURN(rc);
}

static int filter_cleanup_groups(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct file *filp;
        struct dentry *dentry;
        int i;
        ENTRY;

        if (filter->fo_dentry_O_groups != NULL) {
                for (i = 0; i < FILTER_GROUPS; i++) {
                        dentry = filter->fo_dentry_O_groups[i];
                        if (dentry != NULL)
                                f_dput(dentry);
                }
                OBD_FREE(filter->fo_dentry_O_groups,
                         FILTER_GROUPS * sizeof(*filter->fo_dentry_O_groups));
                filter->fo_dentry_O_groups = NULL;
        }
        if (filter->fo_last_objid_files != NULL) {
                for (i = 0; i < FILTER_GROUPS; i++) {
                        filp = filter->fo_last_objid_files[i];
                        if (filp != NULL)
                                filp_close(filp, 0);
                }
                OBD_FREE(filter->fo_last_objid_files,
                         FILTER_GROUPS * sizeof(*filter->fo_last_objid_files));
                filter->fo_last_objid_files = NULL;
        }
        if (filter->fo_dentry_O_sub != NULL) {
                for (i = 0; i < filter->fo_subdir_count; i++) {
                        dentry = filter->fo_dentry_O_sub[i];
                        if (dentry != NULL)
                                f_dput(dentry);
                }
                OBD_FREE(filter->fo_dentry_O_sub,
                         filter->fo_subdir_count *
                         sizeof(*filter->fo_dentry_O_sub));
                filter->fo_dentry_O_sub = NULL;
        }
        if (filter->fo_last_objids != NULL) {
                OBD_FREE(filter->fo_last_objids,
                         FILTER_GROUPS * sizeof(*filter->fo_last_objids));
                filter->fo_last_objids = NULL;
        }
        if (filter->fo_dentry_O != NULL) {
                f_dput(filter->fo_dentry_O);
                filter->fo_dentry_O = NULL;
        }
        RETURN(0);
}

/* FIXME: object groups */
static int filter_prep_groups(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct dentry *dentry, *O_dentry;
        struct file *filp;
        int i, rc = 0, cleanup_phase = 0;
        ENTRY;

        O_dentry = simple_mkdir(cfs_fs_pwd(current->fs), filter->fo_vfsmnt,
                                "O", 0700, 1);
        CDEBUG(D_INODE, "got/created O: %p\n", O_dentry);
        if (IS_ERR(O_dentry)) {
                rc = PTR_ERR(O_dentry);
                CERROR("cannot open/create O: rc = %d\n", rc);
                GOTO(cleanup, rc);
        }
        filter->fo_dentry_O = O_dentry;
        cleanup_phase = 1; /* O_dentry */

        OBD_ALLOC(filter->fo_last_objids, FILTER_GROUPS * sizeof(__u64));
        if (filter->fo_last_objids == NULL)
                GOTO(cleanup, rc = -ENOMEM);
        cleanup_phase = 2; /* groups */

        OBD_ALLOC(filter->fo_dentry_O_groups, FILTER_GROUPS * sizeof(dentry));
        if (filter->fo_dentry_O_groups == NULL)
                GOTO(cleanup, rc = -ENOMEM);
        OBD_ALLOC(filter->fo_last_objid_files, FILTER_GROUPS * sizeof(filp));
        if (filter->fo_last_objid_files == NULL)
                GOTO(cleanup, rc = -ENOMEM);

        for (i = 0; i < FILTER_GROUPS; i++) {
                char name[25];
                loff_t off = 0;

                sprintf(name, "%d", i);
                dentry = simple_mkdir(O_dentry, filter->fo_vfsmnt,
                                      name, 0700, 1);
                CDEBUG(D_INODE, "got/created O/%s: %p\n", name, dentry);
                if (IS_ERR(dentry)) {
                        rc = PTR_ERR(dentry);
                        CERROR("cannot lookup/create O/%s: rc = %d\n",
                               name, rc);
                        GOTO(cleanup, rc);
                }
                filter->fo_dentry_O_groups[i] = dentry;

                sprintf(name, "O/%d/LAST_ID", i);
                filp = filp_open(name, O_CREAT | O_RDWR, 0700);
                if (IS_ERR(filp)) {
                        rc = PTR_ERR(filp);
                        CERROR("cannot create %s: rc = %d\n", name, rc);
                        GOTO(cleanup, rc);
                }
                filter->fo_last_objid_files[i] = filp;

                if (i_size_read(filp->f_dentry->d_inode) == 0) {
                        filter->fo_last_objids[i] = FILTER_INIT_OBJID;
                        rc = filter_update_last_objid(obd, i, 1);
                        if (rc)
                                GOTO(cleanup, rc);
                        continue;
                }

                rc = fsfilt_read_record(obd, filp, &filter->fo_last_objids[i],
                                        sizeof(__u64), &off);
                if (rc) {
                        CERROR("OBD filter: error reading %s: rc %d\n",
                               name, rc);
                        GOTO(cleanup, rc);
                }
                filter->fo_last_objids[i] =
                        le64_to_cpu(filter->fo_last_objids[i]);
                CDEBUG(D_HA, "%s: server last_objid group %d: "LPU64"\n",
                       obd->obd_name, i, filter->fo_last_objids[i]);
        }

        if (filter->fo_subdir_count) {
                O_dentry = filter->fo_dentry_O_groups[0];
                OBD_ALLOC(filter->fo_dentry_O_sub,
                          filter->fo_subdir_count * sizeof(dentry));
                if (filter->fo_dentry_O_sub == NULL)
                        GOTO(cleanup, rc = -ENOMEM);

                for (i = 0; i < filter->fo_subdir_count; i++) {
                        char dir[20];
                        snprintf(dir, sizeof(dir), "d%u", i);

                        dentry = simple_mkdir(O_dentry, filter->fo_vfsmnt,
                                              dir, 0700, 1);
                        CDEBUG(D_INODE, "got/created O/0/%s: %p\n", dir,dentry);
                        if (IS_ERR(dentry)) {
                                rc = PTR_ERR(dentry);
                                CERROR("can't lookup/create O/0/%s: rc = %d\n",
                                       dir, rc);
                                GOTO(cleanup, rc);
                        }
                        filter->fo_dentry_O_sub[i] = dentry;
                }
        }
        RETURN(0);

 cleanup:
        filter_cleanup_groups(obd);
        return rc;
}

/* setup the object store with correct subdirectories */
static int filter_prep(struct obd_device *obd)
{
        struct lvfs_run_ctxt saved;
        struct filter_obd *filter = &obd->u.filter;
        struct file *file;
        struct inode *inode;
        int rc = 0;
        ENTRY;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        file = filp_open(LAST_RCVD, O_RDWR | O_CREAT | O_LARGEFILE, 0700);
        if (!file || IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create %s: rc = %d\n",
                       LAST_RCVD, rc);
                GOTO(out, rc);
        }
        filter->fo_rcvd_filp = file;
        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LAST_RCVD,
                       file->f_dentry->d_inode->i_mode);
                GOTO(err_filp, rc = -ENOENT);
        }

        inode = file->f_dentry->d_parent->d_inode;
        /* We use i_op->unlink directly in filter_vfs_unlink() */
        if (!inode->i_op || !inode->i_op->create || !inode->i_op->unlink) {
                CERROR("%s: filesystem does not support create/unlink ops\n",
                       obd->obd_name);
                GOTO(err_filp, rc = -EOPNOTSUPP);
        }

        rc = filter_init_server_data(obd, file);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_filp, rc);
        }
        /* open and create health check io file*/
        file = filp_open(HEALTH_CHECK, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create %s rc = %d\n",
                       HEALTH_CHECK, rc);
                GOTO(err_filp, rc);
        }
        filter->fo_obt.obt_health_check_filp = file;
        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", HEALTH_CHECK,
                       file->f_dentry->d_inode->i_mode);
                GOTO(err_health_check, rc = -ENOENT);
        }
        rc = lvfs_check_io_health(obd, file);
        if (rc)
                GOTO(err_health_check, rc);

        rc = filter_prep_groups(obd);
        if (rc)
                GOTO(err_server_data, rc);
 out:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        return(rc);

 err_server_data:
        //class_disconnect_exports(obd, 0);
        filter_free_server_data(filter);
 err_health_check:
        if (filp_close(filter->fo_obt.obt_health_check_filp, 0))
                CERROR("can't close %s after error\n", HEALTH_CHECK);
        filter->fo_obt.obt_health_check_filp = NULL;
 err_filp:
        if (filp_close(filter->fo_rcvd_filp, 0))
                CERROR("can't close %s after error\n", LAST_RCVD);
        filter->fo_rcvd_filp = NULL;
        goto out;
}

/* cleanup the filter: write last used object id to status file */
static void filter_post(struct obd_device *obd)
{
        struct lvfs_run_ctxt saved;
        struct filter_obd *filter = &obd->u.filter;
        int rc, i;

        /* XXX: filter_update_lastobjid used to call fsync_dev.  It might be
         * best to start a transaction with h_sync, because we removed this
         * from lastobjid */

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = filter_update_server_data(obd, filter->fo_rcvd_filp,
                                       filter->fo_fsd, 0);
        if (rc)
                CERROR("error writing server data: rc = %d\n", rc);

        for (i = 0; i < FILTER_GROUPS; i++) {
                rc = filter_update_last_objid(obd, i, (i == FILTER_GROUPS - 1));
                if (rc)
                        CERROR("error writing group %d lastobjid: rc = %d\n",
                               i, rc);
        }

        rc = filp_close(filter->fo_rcvd_filp, 0);
        filter->fo_rcvd_filp = NULL;
        if (rc)
                CERROR("error closing %s: rc = %d\n", LAST_RCVD, rc);

        rc = filp_close(filter->fo_obt.obt_health_check_filp, 0);
        filter->fo_obt.obt_health_check_filp = NULL;
        if (rc)
                CERROR("error closing %s: rc = %d\n", HEALTH_CHECK, rc);

        filter_cleanup_groups(obd);
        filter_free_server_data(filter);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
}

static void filter_set_last_id(struct filter_obd *filter,
                               obd_id id, obd_gr group)
{
        LASSERT(filter->fo_fsd != NULL);
        LASSERT(group <= FILTER_GROUPS);

        spin_lock(&filter->fo_objidlock);
        filter->fo_last_objids[group] = id;
        spin_unlock(&filter->fo_objidlock);
}

obd_id filter_last_id(struct filter_obd *filter, obd_gr group)
{
        obd_id id;
        LASSERT(filter->fo_fsd != NULL);
        LASSERT(group <= FILTER_GROUPS);
        LASSERT(filter->fo_last_objids != NULL);

        /* FIXME: object groups */
        spin_lock(&filter->fo_objidlock);
        id = filter->fo_last_objids[group];
        spin_unlock(&filter->fo_objidlock);

        return id;
}

static int filter_lock_dentry(struct obd_device *obd, struct dentry *dparent)
{
        LOCK_INODE_MUTEX(dparent->d_inode);
        return 0;
}

/* We never dget the object parent, so DON'T dput it either */
struct dentry *filter_parent(struct obd_device *obd, obd_gr group, obd_id objid)
{
        struct filter_obd *filter = &obd->u.filter;

        if (group >= FILTER_GROUPS) /* FIXME: object groups */
		return ERR_PTR(-EBADF);

        if (group > 0 || filter->fo_subdir_count == 0)
                return filter->fo_dentry_O_groups[group];

        return filter->fo_dentry_O_sub[objid & (filter->fo_subdir_count - 1)];
}

/* We never dget the object parent, so DON'T dput it either */
struct dentry *filter_parent_lock(struct obd_device *obd, obd_gr group,
                                  obd_id objid)
{
        unsigned long now = jiffies;
        struct dentry *dparent = filter_parent(obd, group, objid);
        int rc;

        if (IS_ERR(dparent))
                return dparent;

        rc = filter_lock_dentry(obd, dparent);
        fsfilt_check_slow(obd, now, "parent lock");
        return rc ? ERR_PTR(rc) : dparent;
}

/* We never dget the object parent, so DON'T dput it either */
static void filter_parent_unlock(struct dentry *dparent)
{
        UNLOCK_INODE_MUTEX(dparent->d_inode);
}

/* How to get files, dentries, inodes from object id's.
 *
 * If dir_dentry is passed, the caller has already locked the parent
 * appropriately for this operation (normally a write lock).  If
 * dir_dentry is NULL, we do a read lock while we do the lookup to
 * avoid races with create/destroy and such changing the directory
 * internal to the filesystem code. */
struct dentry *filter_fid2dentry(struct obd_device *obd,
                                 struct dentry *dir_dentry,
                                 obd_gr group, obd_id id)
{
        struct dentry *dparent = dir_dentry;
        struct dentry *dchild;
        char name[32];
        int len;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT) &&
            !obd->u.filter.fo_destroy_in_progress) {
                /* don't fail lookups for orphan recovery, it causes
                 * later LBUGs when objects still exist during precreate */
                CDEBUG(D_INFO, "*** obd_fail_loc=%x ***\n",OBD_FAIL_OST_ENOENT);
                RETURN(ERR_PTR(-ENOENT));
        }

        if (id == 0) {
                CERROR("fatal: invalid object id 0\n");
                RETURN(ERR_PTR(-ESTALE));
        }

        len = sprintf(name, LPU64, id);
        if (dir_dentry == NULL) {
                dparent = filter_parent_lock(obd, group, id);
                if (IS_ERR(dparent)) {
                        CERROR("%s: error getting object "LPU64":"LPU64
                               " parent: rc %ld\n", obd->obd_name,
                               id, group, PTR_ERR(dparent));
                        RETURN(dparent);
                }
        }
        CDEBUG(D_INODE, "looking up object O/%.*s/%s\n",
               dparent->d_name.len, dparent->d_name.name, name);
        dchild = /*ll_*/lookup_one_len(name, dparent, len);
        if (dir_dentry == NULL)
                filter_parent_unlock(dparent);
        if (IS_ERR(dchild)) {
                CERROR("%s: object "LPU64":"LPU64" lookup error: rc %ld\n",
                       obd->obd_name, id, group, PTR_ERR(dchild));
                RETURN(dchild);
        }

        if (dchild->d_inode != NULL && is_bad_inode(dchild->d_inode)) {
                CERROR("%s: got bad object "LPU64" inode %lu\n",
                       obd->obd_name, id, dchild->d_inode->i_ino);
                f_dput(dchild);
                RETURN(ERR_PTR(-ENOENT));
        }

        CDEBUG(D_INODE, "got child objid %s: %p, count = %d\n",
               name, dchild, atomic_read(&dchild->d_count));

        LASSERT(atomic_read(&dchild->d_count) > 0);

        RETURN(dchild);
}

static int filter_prepare_destroy(struct obd_device *obd, obd_id objid,
                                  struct lustre_handle *lockh)
{
        int flags = LDLM_AST_DISCARD_DATA, rc;
        struct ldlm_res_id res_id = { .name = { objid } };
        ldlm_policy_data_t policy = { .l_extent = { 0, OBD_OBJECT_EOF } };

        ENTRY;
        /* Tell the clients that the object is gone now and that they should
         * throw away any cached pages. */
        rc = ldlm_cli_enqueue_local(obd->obd_namespace, &res_id, LDLM_EXTENT,
                                    &policy, LCK_PW, &flags, ldlm_blocking_ast,
                                    ldlm_completion_ast, NULL, NULL, 0, NULL,
                                    lockh);

        if (rc != ELDLM_OK) {
                lockh->cookie = 0;
                CERROR("%s: failed to get lock to destroy objid "LPU64" (%d)\n",
                       obd->obd_name, objid, rc);
        }
        RETURN(rc);
}

static void filter_fini_destroy(struct obd_device *obd,
                                struct lustre_handle *lockh)
{
        if (lustre_handle_is_used(lockh))
                ldlm_lock_decref(lockh, LCK_PW);
}

/* This is vfs_unlink() without down(i_sem).  If we call regular vfs_unlink()
 * we have 2.6 lock ordering issues with filter_commitrw_write() as it takes
 * i_sem before starting a handle, while filter_destroy() + vfs_unlink do the
 * reverse.  Caller must take i_sem before starting the transaction and we
 * drop it here before the inode is removed from the dentry.  bug 4180/6984 */
int filter_vfs_unlink(struct inode *dir, struct dentry *dentry,
                      struct vfsmount *mnt)
{
        int rc;
        ENTRY;

        /* don't need dir->i_zombie for 2.4, it is for rename/unlink of dir
         * itself we already hold dir->i_mutex for child create/unlink ops */
        LASSERT(dentry->d_inode != NULL);
        LASSERT(TRYLOCK_INODE_MUTEX(dir) == 0);
        LASSERT(TRYLOCK_INODE_MUTEX(dentry->d_inode) == 0);


        /* may_delete() */
        if (/*!dentry->d_inode ||*/dentry->d_parent->d_inode != dir)
                GOTO(out, rc = -ENOENT);

        rc = ll_permission(dir, MAY_WRITE | MAY_EXEC, NULL);
        if (rc)
                GOTO(out, rc);

        if (IS_APPEND(dir))
                GOTO(out, rc = -EPERM);

        /* check_sticky() */
        if ((dentry->d_inode->i_uid != current_fsuid() &&
             !cfs_capable(CFS_CAP_FOWNER)) || IS_APPEND(dentry->d_inode) ||
            IS_IMMUTABLE(dentry->d_inode))
                GOTO(out, rc = -EPERM);

        /* Locking order: i_mutex -> journal_lock -> dqptr_sem. LU-952 */
        ll_vfs_dq_init(dir);

        rc = ll_security_inode_unlink(dir, dentry, mnt);
        if (rc)
                GOTO(out, rc);
        rc = dir->i_op->unlink(dir, dentry);
out:
        /* need to drop i_mutex before we lose inode reference */
        UNLOCK_INODE_MUTEX(dentry->d_inode);
        if (rc == 0)
                d_delete(dentry);

        RETURN(rc);
}

/* Caller must hold LCK_PW on parent and push us into kernel context.
 * Caller must hold child i_mutex, we drop it always.
 * Caller is also required to ensure that dchild->d_inode exists. */
static int filter_destroy_internal(struct obd_device *obd, obd_id objid,
                                   obd_gr group, struct dentry *dparent,
                                   struct dentry *dchild)
{
        struct inode *inode = dchild->d_inode;
        struct filter_obd *filter = &obd->u.filter;
        int rc;

        /* There should be 2 references to the inode:
         *  1) taken by filter_prepare_destroy
         *  2) taken by filter_destroy */
        if (inode->i_nlink != 1 || atomic_read(&inode->i_count) != 2) {
                CERROR("destroying objid %.*s ino %lu nlink %lu count %d\n",
                       dchild->d_name.len, dchild->d_name.name, inode->i_ino,
                       (unsigned long)inode->i_nlink,
                       atomic_read(&inode->i_count));
        }

        rc = filter_vfs_unlink(dparent->d_inode, dchild, filter->fo_vfsmnt);
        if (rc)
                CERROR("error unlinking objid %.*s: rc %d\n",
                       dchild->d_name.len, dchild->d_name.name, rc);
        return(rc);
}

struct filter_intent_args {
        struct ldlm_lock **victim;
        __u64 size;
        int *liblustre;
};

static enum interval_iter filter_intent_cb(struct interval_node *n,
                                           void *args)
{
        struct ldlm_interval *node = (struct ldlm_interval *)n;
        struct filter_intent_args *arg = (struct filter_intent_args*)args;
        __u64 size = arg->size;
        struct ldlm_lock **v = arg->victim;
        struct ldlm_lock *lck;

        /* If the interval is lower than the current file size,
         * just break. */
        if (interval_high(n) <= size)
                return INTERVAL_ITER_STOP;

        list_for_each_entry(lck, &node->li_group, l_sl_policy) {
                /* Don't send glimpse ASTs to liblustre clients.
                 * They aren't listening for them, and they do
                 * entirely synchronous I/O anyways. */
                if (lck->l_export == NULL ||
                    lck->l_export->exp_libclient == 1)
                        continue;

                if (*arg->liblustre)
                        *arg->liblustre = 0;

                if (*v == NULL) {
                        *v = LDLM_LOCK_GET(lck);
                } else if ((*v)->l_policy_data.l_extent.start <
                           lck->l_policy_data.l_extent.start) {
                        LDLM_LOCK_PUT(*v);
                        *v = LDLM_LOCK_GET(lck);
                }

                /* the same policy group - every lock has the
                 * same extent, so needn't do it any more */
                break;
        }

        return INTERVAL_ITER_CONT;
}

static int filter_intent_policy(struct ldlm_namespace *ns,
                                struct ldlm_lock **lockp, void *req_cookie,
                                ldlm_mode_t mode, int flags, void *data)
{
        struct list_head rpc_list = LIST_HEAD_INIT(rpc_list);
        struct ptlrpc_request *req = req_cookie;
        struct ldlm_lock *lock = *lockp, *l = NULL;
        struct ldlm_resource *res = lock->l_resource;
        ldlm_processing_policy policy;
        struct ost_lvb *res_lvb, *reply_lvb;
        struct ldlm_reply *rep;
        ldlm_error_t err;
        int idx, rc, tmpflags = 0, only_liblustre = 1;
        struct ldlm_interval_tree *tree;
        struct filter_intent_args arg;
        __u32 repsize[3] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                           [DLM_LOCKREPLY_OFF]   = sizeof(*rep),
                           [DLM_REPLY_REC_OFF]   = sizeof(*reply_lvb) };
        ENTRY;

        policy = ldlm_get_processing_policy(res);
        LASSERT(policy != NULL);
        LASSERT(req != NULL);

        rc = lustre_pack_reply(req, 3, repsize, NULL);
        if (rc)
                RETURN(req->rq_status = rc);

        rep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF, sizeof(*rep));
        LASSERT(rep != NULL);

        reply_lvb = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF,
                                   sizeof(*reply_lvb));
        LASSERT(reply_lvb != NULL);

        //fixup_handle_for_resent_req(req, lock, &lockh);

        /* Call the extent policy function to see if our request can be
         * granted, or is blocked.
         * If the OST lock has LDLM_FL_HAS_INTENT set, it means a glimpse
         * lock, and should not be granted if the lock will be blocked.
         */

        LASSERT(ns == res->lr_namespace);
        lock_res(res);
        rc = policy(lock, &tmpflags, 0, &err, &rpc_list);
        check_res_locked(res);

        /* FIXME: we should change the policy function slightly, to not make
         * this list at all, since we just turn around and free it */
        while (!list_empty(&rpc_list)) {
                struct ldlm_lock *wlock =
                        list_entry(rpc_list.next, struct ldlm_lock, l_cp_ast);
                LASSERT((lock->l_flags & LDLM_FL_AST_SENT) == 0);
                LASSERT(lock->l_flags & LDLM_FL_CP_REQD);
                lock->l_flags &= ~LDLM_FL_CP_REQD;
                list_del_init(&wlock->l_cp_ast);
                LDLM_LOCK_PUT(wlock);
        }

        /* The lock met with no resistance; we're finished. */
        if (rc == LDLM_ITER_CONTINUE) {
                /* do not grant locks to the liblustre clients: they cannot
                 * handle ASTs robustly.  We need to do this while still
                 * holding ns_lock to avoid the lock remaining on the res_link
                 * list (and potentially being added to l_pending_list by an
                 * AST) when we are going to drop this lock ASAP. */
                if (lock->l_export->exp_libclient ||
                    OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_GLIMPSE, 2)) {
                        ldlm_resource_unlink_lock(lock);
                        err = ELDLM_LOCK_ABORTED;
                } else {
                        err = ELDLM_LOCK_REPLACED;
                }
                unlock_res(res);
                RETURN(err);
        }

        /* Do not grant any lock, but instead send GL callbacks.  The extent
         * policy nicely created a list of all PW locks for us.  We will choose
         * the highest of those which are larger than the size in the LVB, if
         * any, and perform a glimpse callback. */
        res_lvb = res->lr_lvb_data;
        LASSERT(res_lvb != NULL);
        *reply_lvb = *res_lvb;

        /*
         * ->ns_lock guarantees that no new locks are granted, and,
         * therefore, that res->lr_lvb_data cannot increase beyond the
         * end of already granted lock. As a result, it is safe to
         * check against "stale" reply_lvb->lvb_size value without
         * res->lr_lvb_sem.
         */
        arg.size = reply_lvb->lvb_size;
        arg.victim = &l;
        arg.liblustre = &only_liblustre;
        for (idx = 0; idx < LCK_MODE_NUM; idx++) {
                tree = &res->lr_itree[idx];
                if (tree->lit_mode == LCK_PR)
                        continue;

                interval_iterate_reverse(tree->lit_root,
                                         filter_intent_cb, &arg);
        }
        unlock_res(res);

        /* There were no PW locks beyond the size in the LVB; finished. */
        if (l == NULL) {
                if (only_liblustre) {
                        /* If we discovered a liblustre client with a PW lock,
                         * however, the LVB may be out of date!  The LVB is
                         * updated only on glimpse (which we don't do for
                         * liblustre clients) and cancel (which the client
                         * obviously has not yet done).  So if it has written
                         * data but kept the lock, the LVB is stale and needs
                         * to be updated from disk.
                         *
                         * Of course, this will all disappear when we switch to
                         * taking liblustre locks on the OST. */
                        ldlm_res_lvbo_update(res, NULL, 0, 1);
                }
                RETURN(ELDLM_LOCK_ABORTED);
        }

        /*
         * This check is for lock taken in filter_prepare_destroy() that does
         * not have l_glimpse_ast set. So the logic is: if there is a lock
         * with no l_glimpse_ast set, this object is being destroyed already.
         *
         * Hence, if you are grabbing DLM locks on the server, always set
         * non-NULL glimpse_ast (e.g., ldlm_request.c:ldlm_glimpse_ast()).
         */
        if (l->l_glimpse_ast == NULL) {
                /* We are racing with unlink(); just return -ENOENT */
                rep->lock_policy_res1 = -ENOENT;
                goto out;
        }

        LASSERTF(l->l_glimpse_ast != NULL, "l == %p", l);
        rc = l->l_glimpse_ast(l, NULL); /* this will update the LVB */
        /* Update the LVB from disk if the AST failed (this is a legal race) */
        /* Client might return -ELDLM_NO_LOCK_DATA if the inode has been cleared
         * in client cache, since the data must has been flushed to OST in such
         * case, we should update LVB from disk. LU-274 */
        if (rc != 0)
                ldlm_res_lvbo_update(res, NULL, 0, 1);


        lock_res(res);
        *reply_lvb = *res_lvb;
        unlock_res(res);

 out:
        LDLM_LOCK_PUT(l);

        RETURN(ELDLM_LOCK_ABORTED);
}

/*
 * per-obd_device iobuf pool.
 *
 * To avoid memory deadlocks in low-memory setups, amount of dynamic
 * allocations in write-path has to be minimized (see bug 5137).
 *
 * Pages, niobuf_local's and niobuf_remote's are pre-allocated and attached to
 * OST threads (see ost_thread_{init,done}()).
 *
 * "iobuf's" used by filter cannot be attached to OST thread, however, because
 * at the OST layer there are only (potentially) multiple obd_device of type
 * unknown at the time of OST thread creation.
 *
 * Instead array of iobuf's is attached to struct filter_obd (->fo_iobuf_pool
 * field). This array has size OST_MAX_THREADS, so that each OST thread uses
 * it's very own iobuf.
 *
 * Functions below
 *
 *     filter_kiobuf_pool_init()
 *
 *     filter_kiobuf_pool_done()
 *
 *     filter_iobuf_get()
 *
 * operate on this array. They are "generic" in a sense that they don't depend
 * on actual type of iobuf's (the latter depending on Linux kernel version).
 */

/*
 * destroy pool created by filter_iobuf_pool_init
 */
static void filter_iobuf_pool_done(struct filter_obd *filter)
{
        struct filter_iobuf **pool;
        int i;

        ENTRY;

        pool = filter->fo_iobuf_pool;
        if (pool != NULL) {
                for (i = 0; i < filter->fo_iobuf_count; ++ i) {
                        if (pool[i] != NULL)
                                filter_free_iobuf(pool[i]);
                }
                OBD_FREE(pool, filter->fo_iobuf_count * sizeof pool[0]);
                filter->fo_iobuf_pool = NULL;
        }
        EXIT;
}

/*
 * pre-allocate pool of iobuf's to be used by filter_{prep,commit}rw_write().
 */
static int filter_iobuf_pool_init(struct filter_obd *filter)
{
        void **pool;

        ENTRY;

        OBD_ALLOC_GFP(filter->fo_iobuf_pool, OSS_THREADS_MAX * sizeof(*pool),
                      GFP_KERNEL);
        if (filter->fo_iobuf_pool == NULL)
                RETURN(-ENOMEM);

        filter->fo_iobuf_count = OSS_THREADS_MAX;

        RETURN(0);
}

/* Return iobuf allocated for @thread_id.  We don't know in advance how
 * many threads there will be so we allocate a large empty array and only
 * fill in those slots that are actually in use.
 * If we haven't allocated a pool entry for this thread before, do so now. */
void *filter_iobuf_get(struct filter_obd *filter, struct obd_trans_info *oti)
{
        int thread_id                    = (oti && oti->oti_thread) ?
                                           oti->oti_thread->t_id : -1;
        struct filter_iobuf  *pool       = NULL;
        struct filter_iobuf **pool_place = NULL;

        if (thread_id >= 0) {
                LASSERT(thread_id < filter->fo_iobuf_count);
                pool = *(pool_place = &filter->fo_iobuf_pool[thread_id]);
        }

        if (unlikely(pool == NULL)) {
                pool = filter_alloc_iobuf(filter, OBD_BRW_WRITE,
                                          PTLRPC_MAX_BRW_PAGES);
                if (pool_place != NULL)
                        *pool_place = pool;
        }

        return pool;
}

/* mount the file system (secretly).  lustre_cfg parameters are:
 * 1 = device
 * 2 = fstype
 * 3 = flags: failover=f, failout=n
 * 4 = mount options
 */
int filter_common_setup(struct obd_device *obd, obd_count len, void *buf,
                        void *option)
{
        struct lustre_cfg* lcfg = buf;
        struct filter_obd *filter = &obd->u.filter;
        struct vfsmount *mnt;
        struct lustre_mount_info *lmi;
        struct obd_uuid uuid;
        __u8 *uuid_ptr;
        char *str, *label;
        char ns_name[48];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
        struct request_queue *q;
#endif
        int rc;
        ENTRY;

        if (lcfg->lcfg_bufcount < 3 ||
            LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
            LUSTRE_CFG_BUFLEN(lcfg, 2) < 1)
                RETURN(-EINVAL);

        lmi = server_get_mount(obd->obd_name);
        if (lmi) {
                /* We already mounted in lustre_fill_super.
                   lcfg bufs 1, 2, 4 (device, fstype, mount opts) are ignored.*/
                struct lustre_sb_info *lsi = s2lsi(lmi->lmi_sb);
                mnt = lmi->lmi_mnt;
                obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        } else {
                /* old path - used by lctl */
                CERROR("Using old MDS mount method\n");
                mnt = ll_kern_mount(lustre_cfg_string(lcfg, 2),
                                    MS_NOATIME|MS_NODIRATIME,
                                    lustre_cfg_string(lcfg, 1), option);
                if (IS_ERR(mnt)) {
                        rc = PTR_ERR(mnt);
                        LCONSOLE_ERROR_MSG(0x135, "Can't mount disk %s (%d)\n",
                                           lustre_cfg_string(lcfg, 1), rc);
                        RETURN(rc);
                }

                obd->obd_fsops = fsfilt_get_ops(lustre_cfg_string(lcfg, 2));
        }
        if (IS_ERR(obd->obd_fsops))
                GOTO(err_mntput, rc = PTR_ERR(obd->obd_fsops));

        rc = filter_iobuf_pool_init(filter);
        if (rc != 0)
                GOTO(err_ops, rc);

        if (lvfs_check_rdonly(lvfs_sbdev(mnt->mnt_sb))) {
                CERROR("%s: Underlying device is marked as read-only. "
                       "Setup failed\n", obd->obd_name);
                GOTO(err_ops, rc = -EROFS);
        }

        /* failover is the default */
        obd->obd_replayable = 1;

        if (lcfg->lcfg_bufcount > 3 && LUSTRE_CFG_BUFLEN(lcfg, 3) > 0) {
                str = lustre_cfg_string(lcfg, 3);
                if (strchr(str, 'n')) {
                        CWARN("%s: recovery disabled\n", obd->obd_name);
                        obd->obd_replayable = 0;
                }
        }

        filter->fo_vfsmnt = mnt;
        obd->u.obt.obt_sb = mnt->mnt_sb;
        obd->u.obt.obt_stale_export_age = STALE_EXPORT_MAXTIME_DEFAULT;
        spin_lock_init(&obd->u.obt.obt_trans_table_lock);

        filter->fo_fstype = mnt->mnt_sb->s_type->name;
        CDEBUG(D_SUPER, "%s: mnt = %p\n", filter->fo_fstype, mnt);

        rc = fsfilt_setup(obd, obd->u.obt.obt_sb);
        if (rc)
                GOTO(err_ops, rc);

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        obd->obd_lvfs_ctxt.cb_ops = filter_lvfs_ops;

        filter->fo_destroy_in_progress = 0;
        sema_init(&filter->fo_create_lock, 1);
        spin_lock_init(&filter->fo_translock);
        spin_lock_init(&filter->fo_objidlock);
        INIT_LIST_HEAD(&filter->fo_export_list);
        sema_init(&filter->fo_alloc_lock, 1);
        init_brw_stats(&filter->fo_filter_stats);
        filter->fo_read_cache = 1; /* enable read-only cache by default */
        filter->fo_writethrough_cache = 1; /* enable writethrough cache */
        filter->fo_readcache_max_filesize = FILTER_MAX_CACHE_SIZE;
        filter->fo_fmd_max_num = FILTER_FMD_MAX_NUM_DEFAULT;
        filter->fo_fmd_max_age = FILTER_FMD_MAX_AGE_DEFAULT;
        filter->fo_syncjournal = 1; /* Sync journals on i/o by default b=19128 */
        filter_slc_set(filter); /* initialize sync on lock cancel */

        rc = filter_prep(obd);
        if (rc)
                GOTO(err_ops, rc);

        sprintf(ns_name, "filter-%s", obd->obd_uuid.uuid);
        obd->obd_namespace = ldlm_namespace_new(obd, ns_name, LDLM_NAMESPACE_SERVER,
                                                LDLM_NAMESPACE_GREEDY);
        if (obd->obd_namespace == NULL)
                GOTO(err_post, rc = -ENOMEM);
        obd->obd_namespace->ns_lvbp = obd;
        obd->obd_namespace->ns_lvbo = &filter_lvbo;
        ldlm_register_intent(obd->obd_namespace, filter_intent_policy);

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "filter_ldlm_cb_client", &obd->obd_ldlm_client);

        rc = obd_llog_init(obd, obd, NULL);
        if (rc) {
                CERROR("failed to setup llogging subsystems\n");
                GOTO(err_post, rc);
        }

        rc = lquota_setup(filter_quota_interface_ref, obd);
        if (rc)
                GOTO(err_post, rc);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
        q = bdev_get_queue(mnt->mnt_sb->s_bdev);
        if (queue_max_sectors(q) < queue_max_hw_sectors(q) &&
            queue_max_sectors(q) < PTLRPC_MAX_BRW_SIZE >> 9)
                LCONSOLE_INFO("%s: underlying device %s should be tuned "
                              "for larger I/O requests: max_sectors = %u "
                              "could be up to max_hw_sectors=%u\n",
                              obd->obd_name, mnt->mnt_sb->s_id,
                              queue_max_sectors(q), queue_max_hw_sectors(q));
#endif

        uuid_ptr = fsfilt_uuid(obd, obd->u.obt.obt_sb);
        if (uuid_ptr != NULL) {
                class_uuid_unparse(uuid_ptr, &uuid);
                str = uuid.uuid;
        } else {
                str = "no UUID";
        }

        label = fsfilt_get_label(obd, obd->u.obt.obt_sb);
        LCONSOLE_INFO("%s: Now serving %s %s%s with recovery %s\n",
                      obd->obd_name, label ?: str, lmi ? "on " : "",
                      lmi ? s2lsi(lmi->lmi_sb)->lsi_lmd->lmd_dev : "",
                      obd->obd_replayable ? "enabled" : "disabled");

        if (obd->obd_recovering)
                LCONSOLE_WARN("%s: Will be in recovery for at least %d:%.02d, "
                              "or until %d client%s reconnect%s\n",
                              obd->obd_name,
                              obd->obd_recovery_timeout / 60,
                              obd->obd_recovery_timeout % 60,
                              obd->obd_recoverable_clients,
                              obd->obd_recoverable_clients == 1 ? "" : "s",
                              obd->obd_recoverable_clients == 1 ? "s": "");

        RETURN(0);

err_post:
        filter_post(obd);
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
        filter_iobuf_pool_done(filter);
err_mntput:
        server_put_mount(obd->obd_name, mnt);
        obd->u.obt.obt_sb = 0;
        return rc;
}

static int filter_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        struct lustre_cfg* lcfg = buf;
        unsigned long addr;
        struct page *page;
        int rc;

        CLASSERT(offsetof(struct obd_device, u.obt) ==
                 offsetof(struct obd_device, u.filter.fo_obt));

        if (!LUSTRE_CFG_BUFLEN(lcfg, 1) || !LUSTRE_CFG_BUFLEN(lcfg, 2))
                RETURN(-EINVAL);

        /* 2.6.9 selinux wants a full option page for do_kern_mount (bug6471) */
        OBD_PAGE_ALLOC(page, CFS_ALLOC_STD);
        if (!page)
                RETURN(-ENOMEM);
        addr = (unsigned long)cfs_page_address(page);
        clear_page((void *)addr);

        /* lprocfs must be setup before the filter so state can be safely added
         * to /proc incrementally as the filter is setup */
        lprocfs_filter_init_vars(&lvars);
        if (lprocfs_obd_setup(obd, lvars.obd_vars) == 0 &&
            lprocfs_alloc_obd_stats(obd, LPROC_FILTER_LAST) == 0) {
                /* Init obdfilter private stats here */
                lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_READ_BYTES,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "read_bytes", "bytes");
                lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_WRITE_BYTES,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "write_bytes", "bytes");
                lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_GET_PAGE,
                                     LPROCFS_CNTR_AVGMINMAX|LPROCFS_CNTR_STDDEV,
                                     "get_page", "usec");
                lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_NO_PAGE,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "get_page failures", "num");
                lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_CACHE_ACCESS,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "cache_access", "pages");
                lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_CACHE_HIT,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "cache_hit", "pages");
                lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_CACHE_MISS,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "cache_miss", "pages");
                lproc_filter_attach_seqstat(obd);
#ifdef HAVE_DELAYED_RECOVERY
                lprocfs_obd_attach_stale_exports(obd);
#endif
                obd->obd_proc_exports_entry = proc_mkdir("exports",
                                                         obd->obd_proc_entry);
        }
        if (obd->obd_proc_exports_entry)
                lprocfs_add_simple(obd->obd_proc_exports_entry, "clear",
                                   lprocfs_nid_stats_clear_read,
                                   lprocfs_nid_stats_clear_write, obd, NULL);

        memcpy((void *)addr, lustre_cfg_buf(lcfg, 4),
               LUSTRE_CFG_BUFLEN(lcfg, 4));
        rc = filter_common_setup(obd, len, buf, (void *)addr);
        OBD_PAGE_FREE(page);

        if (rc) {
                remove_proc_entry("clear", obd->obd_proc_exports_entry);
                lprocfs_free_per_client_stats(obd);
                lprocfs_free_obd_stats(obd);
                lprocfs_obd_cleanup(obd);
        }

        return rc;
}

static struct llog_operations filter_mds_ost_repl_logops /* initialized below*/;
static struct llog_operations filter_size_orig_logops = {
        lop_setup: llog_obd_origin_setup,
        lop_cleanup: llog_obd_origin_cleanup,
        lop_add: llog_obd_origin_add
};

static int filter_llog_init(struct obd_device *obd, struct obd_device *disk_obd,
                            int *index)
{
        struct filter_obd *filter = &obd->u.filter;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        filter->fo_lcm = llog_recov_thread_init(obd->obd_name);
        if (!filter->fo_lcm)
                RETURN(-ENOMEM);

        filter_mds_ost_repl_logops = llog_client_ops;
        filter_mds_ost_repl_logops.lop_cancel = llog_obd_repl_cancel;
        filter_mds_ost_repl_logops.lop_connect = llog_obd_repl_connect;
        filter_mds_ost_repl_logops.lop_sync = llog_obd_repl_sync;

        rc = llog_setup(obd, LLOG_MDS_OST_REPL_CTXT, disk_obd, 0, NULL,
                        &filter_mds_ost_repl_logops);
        if (rc)
                GOTO(cleanup_lcm, rc);

        /* FIXME - assign unlink_cb for filter's recovery */
        ctxt = llog_get_context(obd, LLOG_MDS_OST_REPL_CTXT);
        ctxt->llog_proc_cb = filter_recov_log_mds_ost_cb;
        ctxt->loc_lcm = filter->fo_lcm;
        llog_ctxt_put(ctxt);

        rc = llog_setup(obd, LLOG_SIZE_ORIG_CTXT, disk_obd, 0, NULL,
                        &filter_size_orig_logops);
        if (rc)
                GOTO(cleanup_ctxt, rc);
        RETURN(rc);
cleanup_ctxt:
        ctxt = llog_get_context(obd, LLOG_MDS_OST_REPL_CTXT);
        if (ctxt)
                llog_cleanup(ctxt);
cleanup_lcm:
        llog_recov_thread_fini(filter->fo_lcm, 1);
        filter->fo_lcm = NULL;
        return rc;
}

static int filter_llog_finish(struct obd_device *obd, int count)
{
        struct filter_obd *filter = &obd->u.filter;
        struct llog_ctxt *ctxt;
        int rc = 0, rc2 = 0;
        ENTRY;

        ctxt = llog_get_context(obd, LLOG_MDS_OST_REPL_CTXT);
        if (ctxt) {
                /*
                 * Make sure that no cached llcds left in recov_thread. We
                 * actually do sync in disconnect time, but disconnect may
                 * not come being marked rq_no_resend = 1.
                 */
                llog_sync(ctxt, NULL);

                /*
                 * Balance class_import_get() called in llog_receptor_accept().
                 * This is safe to do here, as llog is already synchronized and
                 * its import may go.
                 */
                mutex_down(&ctxt->loc_sem);
                if (ctxt->loc_imp) {
                        class_import_put(ctxt->loc_imp);
                        ctxt->loc_imp = NULL;
                }
                mutex_up(&ctxt->loc_sem);
        }

        if (filter->fo_lcm) {
                llog_recov_thread_fini(filter->fo_lcm, obd->obd_force);
                filter->fo_lcm = NULL;
        }

        if (ctxt)
                rc = llog_cleanup(ctxt);

        ctxt = llog_get_context(obd, LLOG_SIZE_ORIG_CTXT);
        if (ctxt)
                rc2 = llog_cleanup(ctxt);
        if (!rc)
                rc = rc2;

        RETURN(rc);
}

static int filter_llog_connect(struct obd_export *exp,
                               struct llogd_conn_body *body)
{
        struct obd_device *obd = exp->exp_obd;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        CDEBUG(D_OTHER, "%s: Recovery from log "LPX64"/"LPX64":%x\n",
               obd->obd_name, body->lgdc_logid.lgl_oid,
               body->lgdc_logid.lgl_ogr, body->lgdc_logid.lgl_ogen);

        spin_lock_bh(&obd->obd_processing_task_lock);
        obd->u.filter.fo_mds_ost_sync = 1;
        spin_unlock_bh(&obd->obd_processing_task_lock);

        ctxt = llog_get_context(obd, body->lgdc_ctxt_idx);
        if (ctxt == NULL) {
                CERROR("NULL ctxt at idx %d\n", body->lgdc_ctxt_idx);
                RETURN(-ENOENT);
        }

        rc = llog_connect(ctxt, &body->lgdc_logid, &body->lgdc_gen, NULL);
        llog_ctxt_put(ctxt);
        if (rc != 0)
                CERROR("%s: failed to connect rc %d idx %d\n", obd->obd_name,
                       rc, body->lgdc_ctxt_idx);

        RETURN(rc);
}

static int filter_precleanup(struct obd_device *obd,
                             enum obd_cleanup_stage stage)
{
        int rc = 0;
        ENTRY;

        switch(stage) {
        case OBD_CLEANUP_EARLY:
                break;
        case OBD_CLEANUP_EXPORTS:
                target_cleanup_recovery(obd);
                rc = filter_llog_finish(obd, 0);
                break;
        case OBD_CLEANUP_SELF_EXP:
                break;
        case OBD_CLEANUP_OBD:
                break;
        }
        RETURN(rc);
}

static int filter_cleanup(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        ENTRY;

        if (obd->obd_fail)
                LCONSOLE_WARN("%s: shutting down for failover; client state "
                              "will be preserved.\n", obd->obd_name);

        if (!list_empty(&obd->obd_exports)) {
                CERROR("%s: still has clients!\n", obd->obd_name);
                class_disconnect_exports(obd);
                if (!list_empty(&obd->obd_exports)) {
                        CERROR("still has exports after forced cleanup?\n");
                        RETURN(-EBUSY);
                }
        }

       /* some exports may still be in the zombie queue, so we make sure that
        * all the exports have been processed, otherwise the last_rcvd slot
        * may not be updated on time */
        obd_zombie_barrier();

        remove_proc_entry("clear", obd->obd_proc_exports_entry);
        lprocfs_free_per_client_stats(obd);
        lprocfs_free_obd_stats(obd);
        lprocfs_obd_cleanup(obd);

        lquota_cleanup(filter_quota_interface_ref, obd);

        ldlm_namespace_free(obd->obd_namespace, NULL, obd->obd_force);
        obd->obd_namespace = NULL;

        if (obd->u.obt.obt_sb == NULL)
                RETURN(0);

        filter_post(obd);

        LL_DQUOT_OFF(obd->u.obt.obt_sb, 0);
        shrink_dcache_sb(obd->u.obt.obt_sb);

        server_put_mount(obd->obd_name, filter->fo_vfsmnt);
        obd->u.obt.obt_sb = NULL;

        fsfilt_put_ops(obd->obd_fsops);

        filter_iobuf_pool_done(filter);

        LCONSOLE_INFO("OST %s has stopped.\n", obd->obd_name);

        RETURN(0);
}

static int filter_connect_internal(struct obd_export *exp,
                                   struct obd_connect_data *data,
                                   int reconnect)
{
        if (!data)
                RETURN(0);

        CDEBUG(D_RPCTRACE, "%s: cli %s/%p ocd_connect_flags: "LPX64
               " ocd_version: %x ocd_grant: %d ocd_index: %u\n",
               exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
               data->ocd_connect_flags, data->ocd_version,
               data->ocd_grant, data->ocd_index);

        data->ocd_connect_flags &= OST_CONNECT_SUPPORTED;
        exp->exp_connect_flags = data->ocd_connect_flags;
        data->ocd_version = LUSTRE_VERSION_CODE;

        /* Kindly make sure the SKIP_ORPHAN flag is from MDS. */
        if (!ergo(data->ocd_connect_flags & OBD_CONNECT_SKIP_ORPHAN,
                  data->ocd_connect_flags & OBD_CONNECT_MDS))
                RETURN(-EPROTO);

        if (exp->exp_connect_flags & OBD_CONNECT_GRANT) {
                struct filter_obd *filter = &exp->exp_obd->u.filter;
                struct filter_export_data *fed = &exp->exp_filter_data;
                obd_size left, want;

                spin_lock(&exp->exp_obd->obd_osfs_lock);
                left = filter_grant_space_left(exp);
                want = data->ocd_grant;
                filter_grant(exp, fed->fed_grant, want, left, (reconnect == 0));
                data->ocd_grant = fed->fed_grant;
                spin_unlock(&exp->exp_obd->obd_osfs_lock);

                CDEBUG(D_CACHE, "%s: cli %s/%p ocd_grant: %d want: "
                       LPU64" left: "LPU64"\n", exp->exp_obd->obd_name,
                       exp->exp_client_uuid.uuid, exp,
                       data->ocd_grant, want, left);

                filter->fo_tot_granted_clients ++;
        }

        if (data->ocd_connect_flags & OBD_CONNECT_INDEX) {
                struct filter_obd *filter = &exp->exp_obd->u.filter;
                struct lr_server_data *lsd = filter->fo_fsd;
                int index = le32_to_cpu(lsd->lsd_ost_index);

                if (!(lsd->lsd_feature_compat &
                      cpu_to_le32(OBD_COMPAT_OST))) {
                        /* this will only happen on the first connect */
                        lsd->lsd_ost_index = cpu_to_le32(data->ocd_index);
                        lsd->lsd_feature_compat |= cpu_to_le32(OBD_COMPAT_OST);
                        filter_update_server_data(exp->exp_obd,
                                                  filter->fo_rcvd_filp, lsd, 1);
                } else if (index != data->ocd_index) {
                        LCONSOLE_ERROR_MSG(0x136, "Connection from %s to index "
                                           "%u doesn't match actual OST index "
                                           "%u in last_rcvd file, bad "
                                           "configuration?\n",
                                           obd_export_nid2str(exp), index,
                                           data->ocd_index);
                        RETURN(-EBADF);
                }
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_SIZE)) {
                data->ocd_brw_size = 65536;
        } else if (data->ocd_connect_flags & OBD_CONNECT_BRW_SIZE) {
                data->ocd_brw_size = min(data->ocd_brw_size,
                                         (__u32)(PTLRPC_MAX_BRW_PAGES <<
                                                 CFS_PAGE_SHIFT));
                if (data->ocd_brw_size == 0) {
                        CERROR("%s: cli %s/%p ocd_connect_flags: "LPX64
                               " ocd_version: %x ocd_grant: %d ocd_index: %u "
                               "ocd_brw_size is unexpectedly zero, "
                               "network data corruption?"
                               "Refusing connection of this client\n",
                                exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
                                exp, data->ocd_connect_flags, data->ocd_version,
                                data->ocd_grant, data->ocd_index);
                        RETURN(-EPROTO);
                }
        }

        if (data->ocd_connect_flags & OBD_CONNECT_CKSUM) {
                __u32 cksum_types = data->ocd_cksum_types;

                /* The client set in ocd_cksum_types the checksum types it
                 * supports. We have to mask off the algorithms that we don't
                 * support */
                if (cksum_types & OBD_CKSUM_ALL)
                        data->ocd_cksum_types &= OBD_CKSUM_ALL;
                else
                        data->ocd_cksum_types = OBD_CKSUM_CRC32;

                CDEBUG(D_RPCTRACE, "%s: cli %s supports cksum type %x, return "
                                   "%x\n", exp->exp_obd->obd_name,
                                   obd_export_nid2str(exp), cksum_types,
                                   data->ocd_cksum_types);
        } else {
                /* This client does not support OBD_CONNECT_CKSUM
                 * fall back to CRC32 */
                CDEBUG(D_RPCTRACE, "%s: cli %s does not support "
                                   "OBD_CONNECT_CKSUM, CRC32 will be used\n",
                                   exp->exp_obd->obd_name,
                                   obd_export_nid2str(exp));
        }

        /* FIXME: Do the same with the MDS UUID and fsd_peeruuid.
         * FIXME: We don't strictly need the COMPAT flag for that,
         * FIXME: as fsd_peeruuid[0] will tell us if that is set.
         * FIXME: We needed it for the index, as index 0 is valid. */

        RETURN(0);
}

static int filter_reconnect(struct obd_export *exp, struct obd_device *obd,
                            struct obd_uuid *cluuid,
                            struct obd_connect_data *data,
                            void *localdata)
{
        int rc;
        ENTRY;

        if (exp == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        rc = filter_connect_internal(exp, data, 1);
        if (rc == 0)
                filter_export_stats_init(obd, exp, localdata);

        RETURN(rc);
}

/* nearly identical to mds_connect */
static int filter_connect(struct lustre_handle *conn, struct obd_device *obd,
                          struct obd_uuid *cluuid,
                          struct obd_connect_data *data,
                          void *localdata)
{
        struct obd_export *exp;
        struct filter_export_data *fed;
        struct lsd_client_data *lcd = NULL;
        int rc;
        ENTRY;

        if (conn == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        /* Check for aborted recovery. */
        target_recovery_check_and_stop(obd);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        LASSERT(exp != NULL);

        fed = &exp->exp_filter_data;

        rc = filter_connect_internal(exp, data,0);
        if (rc)
                GOTO(cleanup, rc);

        filter_export_stats_init(obd, exp, localdata);

        if (!obd->obd_replayable)
                GOTO(cleanup, rc = 0);

        OBD_ALLOC_PTR(lcd);
        if (!lcd) {
                CERROR("filter: out of memory for client data\n");
                GOTO(cleanup, rc = -ENOMEM);
        }

        memcpy(lcd->lcd_uuid, cluuid, sizeof(lcd->lcd_uuid));
        fed->fed_lcd = lcd;

        rc = filter_client_add(obd, exp, -1);

        GOTO(cleanup, rc);

cleanup:
        if (rc) {
                if (lcd) {
                        OBD_FREE_PTR(lcd);
                        fed->fed_lcd = NULL;
                }
                class_disconnect(exp);
        } else {
                class_export_put(exp);
        }

        RETURN(rc);
}

/* Do extra sanity checks for grant accounting.  We do this at connect,
 * disconnect, and statfs RPC time, so it shouldn't be too bad.  We can
 * always get rid of it or turn it off when we know accounting is good. */
static void filter_grant_sanity_check(struct obd_device *obd, const char *func)
{
        struct filter_export_data *fed;
        struct obd_export *exp;
        obd_size maxsize = obd->obd_osfs.os_blocks * obd->obd_osfs.os_bsize;
        obd_size tot_dirty = 0, tot_pending = 0, tot_granted = 0;
        obd_size fo_tot_dirty, fo_tot_pending, fo_tot_granted;

        if (list_empty(&obd->obd_exports))
                return;

        /* We don't want to do this for large machines that do lots of
           mounts or unmounts.  It burns... */
        if (obd->obd_num_exports > 100)
                return;

        spin_lock(&obd->obd_osfs_lock);
        spin_lock(&obd->obd_dev_lock);
        list_for_each_entry(exp, &obd->obd_exports, exp_obd_chain) {
                int error = 0;
                fed = &exp->exp_filter_data;
                if (fed->fed_grant < 0 || fed->fed_pending < 0 ||
                    fed->fed_dirty < 0)
                        error = 1;
                if (maxsize > 0) { /* we may not have done a statfs yet */
                        LASSERTF(fed->fed_grant + fed->fed_pending <= maxsize,
                                 "%s: cli %s/%p %ld+%ld > "LPU64"\n", func,
                                 exp->exp_client_uuid.uuid, exp,
                                 fed->fed_grant, fed->fed_pending, maxsize);
                        LASSERTF(fed->fed_dirty <= maxsize,
                                 "%s: cli %s/%p %ld > "LPU64"\n", func,
                                 exp->exp_client_uuid.uuid, exp,
                                 fed->fed_dirty, maxsize);
                }
                if (error)
                        CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
                               obd->obd_name, exp->exp_client_uuid.uuid, exp,
                               fed->fed_dirty, fed->fed_pending,fed->fed_grant);
                else
                        CDEBUG(D_CACHE, "%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
                               obd->obd_name, exp->exp_client_uuid.uuid, exp,
                               fed->fed_dirty, fed->fed_pending,fed->fed_grant);
                tot_granted += fed->fed_grant + fed->fed_pending;
                tot_pending += fed->fed_pending;
                tot_dirty += fed->fed_dirty;
        }
        fo_tot_granted = obd->u.filter.fo_tot_granted;
        fo_tot_pending = obd->u.filter.fo_tot_pending;
        fo_tot_dirty = obd->u.filter.fo_tot_dirty;
        spin_unlock(&obd->obd_dev_lock);
        spin_unlock(&obd->obd_osfs_lock);

        /* Do these assertions outside the spinlocks so we don't kill system */
        if (tot_granted != fo_tot_granted)
                CERROR("%s: tot_granted "LPU64" != fo_tot_granted "LPU64"\n",
                       func, tot_granted, fo_tot_granted);
        if (tot_pending != fo_tot_pending)
                CERROR("%s: tot_pending "LPU64" != fo_tot_pending "LPU64"\n",
                       func, tot_pending, fo_tot_pending);
        if (tot_dirty != fo_tot_dirty)
                CERROR("%s: tot_dirty "LPU64" != fo_tot_dirty "LPU64"\n",
                       func, tot_dirty, fo_tot_dirty);
        if (tot_pending > tot_granted)
                CERROR("%s: tot_pending "LPU64" > tot_granted "LPU64"\n",
                       func, tot_pending, tot_granted);
        if (tot_granted > maxsize)
                CERROR("%s: tot_granted "LPU64" > maxsize "LPU64"\n",
                       func, tot_granted, maxsize);
        if (tot_dirty > maxsize)
                CERROR("%s: tot_dirty "LPU64" > maxsize "LPU64"\n",
                       func, tot_dirty, maxsize);
}

/* Remove this client from the grant accounting totals.  We also remove
 * the export from the obd device under the osfs and dev locks to ensure
 * that the filter_grant_sanity_check() calculations are always valid.
 * The client should do something similar when it invalidates its import. */
static void filter_grant_discard(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        struct filter_export_data *fed = &exp->exp_filter_data;

        spin_lock(&obd->obd_osfs_lock);
        spin_lock(&obd->obd_dev_lock);
        list_del_init(&exp->exp_obd_chain);
        spin_unlock(&obd->obd_dev_lock);

        LASSERTF(filter->fo_tot_granted >= fed->fed_grant,
                 "%s: tot_granted "LPU64" cli %s/%p fed_grant %ld\n",
                 obd->obd_name, filter->fo_tot_granted,
                 exp->exp_client_uuid.uuid, exp, fed->fed_grant);
        filter->fo_tot_granted -= fed->fed_grant;
        LASSERTF(filter->fo_tot_pending >= fed->fed_pending,
                 "%s: tot_pending "LPU64" cli %s/%p fed_pending %ld\n",
                 obd->obd_name, filter->fo_tot_pending,
                 exp->exp_client_uuid.uuid, exp, fed->fed_pending);
        /* fo_tot_pending is handled in filter_grant_commit as bulk finishes */
        LASSERTF(filter->fo_tot_dirty >= fed->fed_dirty,
                 "%s: tot_dirty "LPU64" cli %s/%p fed_dirty %ld\n",
                 obd->obd_name, filter->fo_tot_dirty,
                 exp->exp_client_uuid.uuid, exp, fed->fed_dirty);
        filter->fo_tot_dirty -= fed->fed_dirty;
        fed->fed_dirty = 0;
        fed->fed_grant = 0;

        spin_unlock(&obd->obd_osfs_lock);
}

static int filter_destroy_export(struct obd_export *exp)
{
        ENTRY;

        if (exp->exp_filter_data.fed_pending)
                CERROR("%s: cli %s/%p has %lu pending on destroyed export\n",
                       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
                       exp, exp->exp_filter_data.fed_pending);

        lquota_clearinfo(filter_quota_interface_ref, exp, exp->exp_obd);

        target_destroy_export(exp);
        ldlm_destroy_export(exp);

        if (obd_uuid_equals(&exp->exp_client_uuid, &exp->exp_obd->obd_uuid))
                RETURN(0);


        if (exp->exp_obd->obd_replayable)
                filter_client_free(exp);
        else
                fsfilt_sync(exp->exp_obd, exp->exp_obd->u.obt.obt_sb);

        filter_grant_discard(exp);
        filter_fmd_cleanup(exp);

        if (!(exp->exp_flags & OBD_OPT_FORCE))
                filter_grant_sanity_check(exp->exp_obd, __FUNCTION__);

        RETURN(0);
}

/* also incredibly similar to mds_disconnect */
static int filter_disconnect(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        /* Flush any remaining cancel messages out to the target */
        ctxt = llog_get_context(obd, LLOG_MDS_OST_REPL_CTXT);
        if (ctxt) {
                if (ctxt->loc_imp == exp->exp_imp_reverse)
                        CDEBUG(D_RPCTRACE, "Reverse import disconnect\n");
                llog_sync(ctxt, exp);
                llog_ctxt_put(ctxt);
        }

        if (exp->exp_connect_flags & OBD_CONNECT_GRANT_SHRINK) {
                struct filter_obd *filter = &exp->exp_obd->u.filter;
                if (filter->fo_tot_granted_clients > 0)
                        filter->fo_tot_granted_clients --;
        }

        if (!(exp->exp_flags & OBD_OPT_FORCE))
                filter_grant_sanity_check(obd, __FUNCTION__);
        filter_grant_discard(exp);

        lquota_clearinfo(filter_quota_interface_ref, exp, exp->exp_obd);

        rc = server_disconnect_export(exp);

        class_export_put(exp);
        RETURN(rc);
}

static int filter_ping(struct obd_export *exp)
{
        filter_fmd_expire(exp);

        if (exp->exp_delayed)
                filter_update_client_epoch(exp);

        return 0;
}

struct dentry *__filter_oa2dentry(struct obd_device *obd, struct obdo *oa,
                                  const char *what, int quiet)
{
        struct dentry *dchild = NULL;

        if (!(oa->o_valid & OBD_MD_FLGROUP))
                oa->o_gr = 0;

        dchild = filter_fid2dentry(obd, NULL, oa->o_gr, oa->o_id);

        if (IS_ERR(dchild)) {
                CERROR("%s error looking up object: "LPU64"\n",
                       what, oa->o_id);
                RETURN(dchild);
        }

        if (dchild->d_inode == NULL) {
                if (!quiet)
                        CERROR("%s: %s on non-existent object: "LPU64"\n",
                               obd->obd_name, what, oa->o_id);
                f_dput(dchild);
                RETURN(ERR_PTR(-ENOENT));
        }

        return dchild;
}

static int filter_getattr(struct obd_export *exp, struct obd_info *oinfo)
{
        struct dentry *dentry = NULL;
        struct obd_device *obd;
        int rc = 0;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client export %p\n", exp);
                RETURN(-EINVAL);
        }

        dentry = filter_oa2dentry(obd, oinfo->oi_oa);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        /* Limit the valid bits in the return data to what we actually use */
        oinfo->oi_oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oinfo->oi_oa, dentry->d_inode, FILTER_VALID_FLAGS);

        f_dput(dentry);
        RETURN(rc);
}

/* this should be enabled/disabled in condition to enabled/disabled large
 * inodes (fast EAs) in backing store FS. */
int filter_update_fidea(struct obd_export *exp, struct inode *inode,
                        void *handle, struct obdo *oa)
{
        struct obd_device *obd = exp->exp_obd;
        int rc = 0;
        ENTRY;

        if (oa->o_valid & OBD_MD_FLFID) {
                struct filter_fid ff;

                if (!(oa->o_valid & OBD_MD_FLGROUP))
                        oa->o_gr = 0;

                /* packing fid and converting it to LE for storing into EA.
                 * Here ->o_stripe_idx should be filled by LOV and rest of
                 * fields - by client. */
                ff.ff_fid.id = cpu_to_le64(oa->o_fid);
                ff.ff_fid.f_type = cpu_to_le32(oa->o_stripe_idx);
                ff.ff_fid.generation = cpu_to_le32(oa->o_generation);
                ff.ff_objid = cpu_to_le64(oa->o_id);
                ff.ff_group = cpu_to_le64(oa->o_gr);

                CDEBUG(D_INODE, "storing filter fid EA ("LPU64"/%u/%u"
                       LPU64"/"LPU64")\n", oa->o_fid, oa->o_stripe_idx,
                       oa->o_generation, oa->o_id, oa->o_gr);

                rc = fsfilt_set_md(obd, inode, handle, &ff, sizeof(ff), "fid");
                if (rc)
                        CERROR("store fid in object failed! rc: %d\n", rc);
        } else {
                CDEBUG(D_HA, "OSS object without fid info!\n");
        }

        RETURN(rc);
}

/* this is called from filter_truncate() until we have filter_punch() */
int filter_setattr_internal(struct obd_export *exp, struct dentry *dentry,
                            struct obdo *oa, struct obd_trans_info *oti)
{
        unsigned int orig_ids[MAXQUOTAS] = {0, 0};
        struct llog_cookie *fcc = NULL;
        struct filter_obd *filter;
        int rc, err, sync = 0;
        loff_t old_size = 0;
        unsigned int ia_valid;
        struct inode *inode;
        struct page *page = NULL;
        struct iattr iattr;
        void *handle;
        ENTRY;

        LASSERT(dentry != NULL);
        LASSERT(!IS_ERR(dentry));

        inode = dentry->d_inode;
        LASSERT(inode != NULL);

        filter = &exp->exp_obd->u.filter;
        iattr_from_obdo(&iattr, oa, oa->o_valid);
        ia_valid = iattr.ia_valid;

        if (oa->o_valid & OBD_MD_FLCOOKIE) {
                OBD_ALLOC(fcc, sizeof(*fcc));
                if (fcc != NULL)
                        *fcc = oa->o_lcookie;
        }
        if (ia_valid & (ATTR_SIZE | ATTR_UID | ATTR_GID)) {
                /* Filter truncates and writes are serialized by
                 * i_alloc_sem, see the comment in
                 * filter_preprw_write.*/
                if (ia_valid & ATTR_SIZE)
                        down_write(&inode->i_alloc_sem);
                LOCK_INODE_MUTEX(inode);
                old_size = i_size_read(inode);
        }

        /* VBR: version recovery check */
        rc = filter_version_get_check(exp, oti, inode);
        if (rc)
                GOTO(out_unlock, rc);

        /* Let's pin the last page so that ldiskfs_truncate
         * should not start GFP_FS allocation (20008). */
        if (ia_valid & ATTR_SIZE) {
                page = grab_cache_page(inode->i_mapping,
                                       iattr.ia_size >> PAGE_CACHE_SHIFT);
                if (page == NULL)
                        GOTO(out_unlock, rc = -ENOMEM);

                unlock_page(page);
        }

        /* If the inode still has SUID+SGID bits set (see filter_precreate())
         * then we will accept the UID+GID sent by the client during write for
         * initializing the ownership of this inode.  We only allow this to
         * happen once so clear these bits in setattr. In 2.6 kernels it is
         * possible to get ATTR_UID and ATTR_GID separately, so we only clear
         * the flags that are actually being set. */
        if (ia_valid & (ATTR_UID | ATTR_GID)) {
                CDEBUG(D_INODE, "update UID/GID to %lu/%lu\n",
                       (unsigned long)oa->o_uid, (unsigned long)oa->o_gid);

                if ((inode->i_mode & S_ISUID) && (ia_valid & ATTR_UID)) {
                        if (!(ia_valid & ATTR_MODE)) {
                                iattr.ia_mode = inode->i_mode;
                                iattr.ia_valid |= ATTR_MODE;
                        }
                        iattr.ia_mode &= ~S_ISUID;
                }
                if ((inode->i_mode & S_ISGID) && (ia_valid & ATTR_GID)) {
                        if (!(iattr.ia_valid & ATTR_MODE)) {
                                iattr.ia_mode = inode->i_mode;
                                iattr.ia_valid |= ATTR_MODE;
                        }
                        iattr.ia_mode &= ~S_ISGID;
                }

                orig_ids[USRQUOTA] = inode->i_uid;
                orig_ids[GRPQUOTA] = inode->i_gid;
                handle = fsfilt_start_log(exp->exp_obd, inode,
                                          FSFILT_OP_SETATTR, oti, 1);

                if (IS_ERR(handle))
                        GOTO(out_unlock, rc = PTR_ERR(handle));

                /* update inode EA only once when inode is suid bit marked. As
                 * on 2.6.x UID and GID may be set separately, we check here
                 * only one of them to avoid double setting. */
                if (inode->i_mode & S_ISUID)
                        filter_update_fidea(exp, inode, handle, oa);
        } else {
                handle = fsfilt_start(exp->exp_obd, inode,
                                      FSFILT_OP_SETATTR, oti);

                if (IS_ERR(handle))
                        GOTO(out_unlock, rc = PTR_ERR(handle));
        }

        /* Locking order: i_mutex -> journal_lock -> dqptr_sem. LU-952 */
        if (ia_valid & (ATTR_SIZE | ATTR_UID | ATTR_GID))
                ll_vfs_dq_init(inode);

        if (oa->o_valid & OBD_MD_FLFLAGS) {
                rc = fsfilt_iocontrol(exp->exp_obd, dentry,
                                      FSFILT_IOC_SETFLAGS, (long)&oa->o_flags);
        } else {
                rc = fsfilt_setattr(exp->exp_obd, dentry, handle, &iattr, 1);
                if (fcc != NULL)
                        /* set cancel cookie callback function */
                        sync = fsfilt_add_journal_cb(exp->exp_obd, 0, handle,
                                                     filter_cancel_cookies_cb,
                                                     fcc);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_SETATTR_CREDITS))
                fsfilt_extend(exp->exp_obd, inode, 0, handle);

        /* The truncate might have used up our transaction credits.  Make sure
         * we have two left for the last_rcvd and VBR inode version updates. */
        err = fsfilt_extend(exp->exp_obd, inode, 2, handle);
        rc = filter_finish_transno(exp, inode, oti, rc, sync);
        if (sync) {
                filter_cancel_cookies_cb(exp->exp_obd, 0, fcc, rc);
                fcc = NULL;
        }

        err = fsfilt_commit(exp->exp_obd, inode, handle, 0);
        if (err) {
                CERROR("error on commit, err = %d\n", err);
                if (!rc)
                        rc = err;
        } else {
                fcc = NULL;
        }

        /* For a partial-page truncate flush the page to disk immediately
         * to avoid data corruption during direct disk write. b=17397 */
        if (!sync && (iattr.ia_valid & ATTR_SIZE) &&
            old_size != iattr.ia_size && (iattr.ia_size & ~CFS_PAGE_MASK)) {
                err = filemap_fdatawrite_range(inode->i_mapping, iattr.ia_size,
                                               iattr.ia_size + 1);
                if (!rc)
                        rc = err;
        }

        EXIT;

out_unlock:
        if (page)
                page_cache_release(page);

        if (ia_valid & (ATTR_SIZE | ATTR_UID | ATTR_GID))
                UNLOCK_INODE_MUTEX(inode);
        if (ia_valid & ATTR_SIZE)
                up_write(&inode->i_alloc_sem);
        if (fcc)
                OBD_FREE(fcc, sizeof(*fcc));

        /* trigger quota release */
        if (ia_valid & (ATTR_SIZE | ATTR_UID | ATTR_GID)) {
                unsigned int cur_ids[MAXQUOTAS] = {oa->o_uid, oa->o_gid};
                int rc2 = lquota_adjust(filter_quota_interface_ref,exp->exp_obd,
                                        cur_ids, orig_ids,rc,FSFILT_OP_SETATTR);
                CDEBUG(rc2 ? D_ERROR : D_QUOTA,
                       "filter adjust qunit. (rc:%d)\n", rc2);
        }
        return rc;
}

/* this is called from filter_truncate() until we have filter_punch() */
int filter_setattr(struct obd_export *exp, struct obd_info *oinfo,
                   struct obd_trans_info *oti)
{
        struct ldlm_res_id res_id = { .name = { oinfo->oi_oa->o_id } };
        struct filter_mod_data *fmd;
        struct lvfs_run_ctxt saved;
        struct filter_obd *filter;
        struct ldlm_resource *res;
        struct dentry *dentry;
        int rc = 0;
        ENTRY;

        dentry = __filter_oa2dentry(exp->exp_obd, oinfo->oi_oa,
                                    __FUNCTION__, 1);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        filter = &exp->exp_obd->u.filter;
        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);

        /*
         * We need to be atomic against a concurrent write
         * (which takes the semaphore for reading). fmd_mactime_xid
         * checks will have no effect if a write request with lower
         * xid starts just before a setattr and finishes later than
         * the setattr (see bug 21489, comment 27).
         */
        if (oinfo->oi_oa->o_valid &
            (OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME)) {
                down_write(&dentry->d_inode->i_alloc_sem);
                fmd = filter_fmd_get(exp,oinfo->oi_oa->o_id,oinfo->oi_oa->o_gr);
                if (fmd && fmd->fmd_mactime_xid < oti->oti_xid)
                        fmd->fmd_mactime_xid = oti->oti_xid;
                filter_fmd_put(exp, fmd);
                up_write(&dentry->d_inode->i_alloc_sem);
        }

        /* setting objects attributes (including owner/group) */
        rc = filter_setattr_internal(exp, dentry, oinfo->oi_oa, oti);
        if (rc)
                GOTO(out_unlock, rc);

        res = ldlm_resource_get(exp->exp_obd->obd_namespace, NULL,
                                res_id, LDLM_EXTENT, 0);

        if (res != NULL) {
                rc = ldlm_res_lvbo_update(res, NULL, 0, 0);
                ldlm_resource_putref(res);
        }

        oinfo->oi_oa->o_valid = OBD_MD_FLID;

        /* Quota release need uid/gid info */
        obdo_from_inode(oinfo->oi_oa, dentry->d_inode,
                        FILTER_VALID_FLAGS | OBD_MD_FLUID | OBD_MD_FLGID);

        EXIT;
out_unlock:
        f_dput(dentry);
        pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
        return rc;
}

/* XXX identical to osc_unpackmd */
static int filter_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsmp,
                           struct lov_mds_md *lmm, int lmm_bytes)
{
        int lsm_size;
        ENTRY;

        if (lmm != NULL) {
                if (lmm_bytes < sizeof (*lmm)) {
                        CERROR("lov_mds_md too small: %d, need %d\n",
                               lmm_bytes, (int)sizeof(*lmm));
                        RETURN(-EINVAL);
                }
                /* XXX LOV_MAGIC etc check? */

                if (lmm->lmm_object_id == cpu_to_le64(0)) {
                        CERROR("lov_mds_md: zero lmm_object_id\n");
                        RETURN(-EINVAL);
                }
        }

        lsm_size = lov_stripe_md_size(1);
        if (lsmp == NULL)
                RETURN(lsm_size);

        if (*lsmp != NULL && lmm == NULL) {
                OBD_FREE((*lsmp)->lsm_oinfo[0], sizeof(struct lov_oinfo));
                OBD_FREE(*lsmp, lsm_size);
                *lsmp = NULL;
                RETURN(0);
        }

        if (*lsmp == NULL) {
                OBD_ALLOC(*lsmp, lsm_size);
                if (*lsmp == NULL)
                        RETURN(-ENOMEM);
                OBD_ALLOC((*lsmp)->lsm_oinfo[0], sizeof(struct lov_oinfo));
                if ((*lsmp)->lsm_oinfo[0] == NULL) {
                        OBD_FREE(*lsmp, lsm_size);
                        RETURN(-ENOMEM);
                }
                loi_init((*lsmp)->lsm_oinfo[0]);
        }

        if (lmm != NULL) {
                /* XXX zero *lsmp? */
                (*lsmp)->lsm_object_id = le64_to_cpu (lmm->lmm_object_id);
                LASSERT((*lsmp)->lsm_object_id);
        }

        (*lsmp)->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES;

        RETURN(lsm_size);
}

/* caller must hold fo_create_lock */
static int filter_destroy_precreated(struct obd_export *exp, struct obdo *oa,
                                     struct filter_obd *filter)
{
        struct obdo doa = { 0 }; /* XXX obdo on stack */
        obd_id last, id;
        int rc = 0;
        int skip_orphan;
        ENTRY;

        LASSERT(oa);
        LASSERT(down_trylock(&filter->fo_create_lock) != 0);

        memset(&doa, 0, sizeof(doa));
        if (oa->o_valid & OBD_MD_FLGROUP) {
                doa.o_valid |= OBD_MD_FLGROUP;
                doa.o_gr = oa->o_gr;
        } else {
                doa.o_gr = 0;
        }
        doa.o_mode = S_IFREG;

        if (!filter->fo_destroy_in_progress) {
                CERROR("%s: destroy_in_progress already cleared\n",
                        exp->exp_obd->obd_name);
                RETURN(0);
        }

        last = filter_last_id(filter, doa.o_gr);
        skip_orphan = !!(exp->exp_connect_flags & OBD_CONNECT_SKIP_ORPHAN);

        CWARN("%s: deleting orphan objects from "LPU64" to "LPU64"%s\n",
               exp->exp_obd->obd_name, oa->o_id + 1, last,
               skip_orphan ? ", orphan objids won't be reused any more." : ".");

        for (id = last; id > oa->o_id; id--) {
                doa.o_id = id;
                rc = filter_destroy(exp, &doa, NULL, NULL, NULL);
                if (rc && rc != -ENOENT) /* this is pretty fatal... */
                        CEMERG("error destroying precreate objid "LPU64": %d\n",
                               id, rc);
                /* update last_id on disk periodically so that if we restart
                 * we don't need to re-scan all of the just-deleted objects. */
                if ((id & 511) == 0 && !skip_orphan) {
                        filter_set_last_id(filter, id - 1, doa.o_gr);
                        filter_update_last_objid(exp->exp_obd, doa.o_gr, 0);
                }
        }

        CDEBUG(D_HA, "%s: after destroy: set last_objids["LPU64"] = "LPU64"\n",
               exp->exp_obd->obd_name, doa.o_gr, oa->o_id);

        if (!skip_orphan) {
                filter_set_last_id(filter, id, doa.o_gr);
                rc = filter_update_last_objid(exp->exp_obd, doa.o_gr, 1);
        } else {
                /*
                 * We have destroyed orphan objects, but don't want to reuse
                 * them. Therefore we don't reset last_id to the last created
                 * objects. Instead, we report back to the MDS the object id
                 * of the last orphan, so that the MDS can restart allocating
                 * objects from this id + 1 and thus skip the whole orphan
                 * object id range
                 */
                oa->o_id = last;
                rc = 0;
        }
        filter->fo_destroy_in_progress = 0;

        RETURN(rc);
}

static int filter_precreate(struct obd_device *obd, struct obdo *oa,
                            obd_gr group, int *num);
/* returns a negative error or a nonnegative number of files to create */
static int filter_handle_precreate(struct obd_export *exp, struct obdo *oa,
                                   obd_gr group, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        int diff, rc;
        ENTRY;

        /* delete orphans request */
        if ((oa->o_valid & OBD_MD_FLFLAGS) && (oa->o_flags & OBD_FL_DELORPHAN)){
                if (oti->oti_conn_cnt < exp->exp_conn_cnt) {
                        CERROR("%s: dropping old orphan cleanup request\n",
                               obd->obd_name);
                        RETURN(0);
                }

                /* This causes inflight precreates to abort and drop lock */
                filter->fo_destroy_in_progress = 1;
                down(&filter->fo_create_lock);
                diff = oa->o_id - filter_last_id(filter, group);
                CDEBUG(D_HA, "filter_last_id() = "LPU64" -> diff = %d\n",
                       filter_last_id(filter, group), diff);

                if (-diff > OST_MAX_PRECREATE) {
                        CERROR("%s: ignoring bogus orphan destroy request: "
                               "obdid "LPU64" last_id "LPU64"\n", obd->obd_name,
                               oa->o_id, filter_last_id(filter, group));
                        /* FIXME: should reset precreate_next_id on MDS */
                        GOTO(out, rc = -EINVAL);
                }
                if (diff < 0) {
                        rc = filter_destroy_precreated(exp, oa, filter);
                        if (rc)
                                CERROR("%s: unable to write lastobjid, but "
                                       "orphans were deleted\n", obd->obd_name);
                        GOTO(out, rc);
                } else {
                        /*XXX used by MDS for the first time! */
                        filter->fo_destroy_in_progress = 0;
                }
        } else {
                down(&filter->fo_create_lock);
                if (oti->oti_conn_cnt < exp->exp_conn_cnt) {
                        CERROR("%s: dropping old precreate request\n",
                               obd->obd_name);
                        GOTO(out, rc = 0);
                }
                /* only precreate if group == 0 and o_id is specfied */
                if (group != 0 || oa->o_id == 0)
                        diff = 1;
                else
                        diff = oa->o_id - filter_last_id(filter, group);
                CDEBUG(D_RPCTRACE, "filter_last_id() = "LPU64" -> diff = %d\n",
                       filter_last_id(filter, group), diff);

		/*
		 * Check obd->obd_recovering to handle the race condition
		 * while recreating missing precreated objects through
		 * filter_preprw_write() and mds_lov_clear_orphans()
		 * at the same time.
		 */
		LASSERTF(ergo(!obd->obd_recovering, diff >= 0),
			 "%s: "LPU64" - "LPU64" = %d\n", obd->obd_name,
			 oa->o_id, filter_last_id(filter, group), diff);
        }

        if (diff > 0) {
                oa->o_id = filter_last_id(&obd->u.filter, group);
                rc = filter_precreate(obd, oa, group, &diff);
                oa->o_id = filter_last_id(&obd->u.filter, group);
                oa->o_valid = OBD_MD_FLID;
                GOTO(out, rc);
        }
        /* else diff == 0 */
        GOTO(out, rc = 0);
out:
        up(&filter->fo_create_lock);
        return rc;
}

static int filter_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                         __u64 max_age, __u32 flags)
{
        struct filter_obd *filter = &obd->u.filter;
        int blockbits = obd->u.obt.obt_sb->s_blocksize_bits;
        int rc;
        ENTRY;

        /* at least try to account for cached pages.  its still racey and
         * might be under-reporting if clients haven't announced their
         * caches with brw recently */
        spin_lock(&obd->obd_osfs_lock);
        rc = fsfilt_statfs(obd, obd->u.obt.obt_sb, max_age);
        memcpy(osfs, &obd->obd_osfs, sizeof(*osfs));
        spin_unlock(&obd->obd_osfs_lock);

        CDEBUG(D_SUPER | D_CACHE, "blocks cached "LPU64" granted "LPU64
               " pending "LPU64" free "LPU64" avail "LPU64"\n",
               filter->fo_tot_dirty, filter->fo_tot_granted,
               filter->fo_tot_pending,
               osfs->os_bfree << blockbits, osfs->os_bavail << blockbits);

        filter_grant_sanity_check(obd, __FUNCTION__);

        osfs->os_bavail -= min(osfs->os_bavail, GRANT_FOR_LLOG(obd) +
                               ((filter->fo_tot_dirty + filter->fo_tot_pending +
                                 osfs->os_bsize - 1) >> blockbits));

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOSPC)) {
                struct lr_server_data *lsd = filter->fo_fsd;
                int index = le32_to_cpu(lsd->lsd_ost_index);

                if (obd_fail_val == -1 ||
                    index == obd_fail_val)
                        osfs->os_bfree = osfs->os_bavail = 2;
                else if (obd_fail_loc & OBD_FAIL_ONCE)
                        obd_fail_loc &= ~OBD_FAILED; /* reset flag */
        }

        /* set EROFS to state field if FS is mounted as RDONLY. The goal is to
         * stop creating files on MDS if OST is not good shape to create
         * objects.*/
        osfs->os_state = 0;

        if (filter->fo_obt.obt_sb->s_flags & MS_RDONLY)
                osfs->os_state = OS_STATE_READONLY;

        if (filter->fo_raid_degraded)
                osfs->os_state |= OS_STATE_DEGRADED;
        RETURN(rc);
}

static int filter_use_existing_obj(struct obd_device *obd,
                                   struct dentry *dchild, void **handle,
                                   int *cleanup_phase)
{
        struct inode *inode = dchild->d_inode;
        struct iattr iattr;
        int rc;

        if ((inode->i_mode & (S_ISUID | S_ISGID)) == (S_ISUID|S_ISGID))
                return 0;

        *handle = fsfilt_start_log(obd, inode, FSFILT_OP_SETATTR, NULL, 1);
        if (IS_ERR(*handle))
                return PTR_ERR(*handle);

        iattr.ia_valid = ATTR_MODE;
        iattr.ia_mode = S_ISUID | S_ISGID |0666;
        rc = fsfilt_setattr(obd, dchild, *handle, &iattr, 1);
        if (rc == 0)
                *cleanup_phase = 3;

        return rc;
}


/* We rely on the fact that only one thread will be creating files in a given
 * group at a time, which is why we don't need an atomic filter_get_new_id.
 * Even if we had that atomic function, the following race would exist:
 *
 * thread 1: gets id x from filter_next_id
 * thread 2: gets id (x + 1) from filter_next_id
 * thread 2: creates object (x + 1)
 * thread 1: tries to create object x, gets -ENOSPC
 *
 * Caller must hold fo_create_lock
 */
static int filter_precreate(struct obd_device *obd, struct obdo *oa,
                            obd_gr group, int *num)
{
        struct dentry *dchild = NULL, *dparent = NULL;
        struct filter_obd *filter;
        int err = 0, rc = 0, recreate_obj = 0, i;
        cfs_time_t enough_time = cfs_time_shift(DISK_TIMEOUT/2);
        obd_id next_id;
        void *handle = NULL;
        ENTRY;

        filter = &obd->u.filter;

        LASSERT(down_trylock(&filter->fo_create_lock) != 0);

        OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_DELAY_PRECREATE, obd_timeout / 2);

        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            (oa->o_flags & OBD_FL_RECREATE_OBJS)) {
                recreate_obj = 1;
        } else {
                struct obd_statfs *osfs;

                OBD_ALLOC(osfs, sizeof(*osfs));
                if (osfs == NULL)
                        RETURN(-ENOMEM);
                rc = filter_statfs(obd, osfs,
                                   cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
                                   0);
                if (rc == 0 && osfs->os_bavail < (osfs->os_blocks >> 10)) {
                        CDEBUG(D_RPCTRACE,"%s: not enough space for create "
                               LPU64"\n", obd->obd_name, osfs->os_bavail <<
                               filter->fo_vfsmnt->mnt_sb->s_blocksize_bits);
                        *num = 0;
                        rc = -ENOSPC;
                }
                OBD_FREE(osfs, sizeof(*osfs));
                if (rc)
                        RETURN(rc);
        }

        CDEBUG(D_RPCTRACE, "%s: precreating %d objects in group "LPU64
               " at "LPU64"\n", obd->obd_name, *num, group, oa->o_id);

        for (i = 0; i < *num && err == 0; i++) {
                int cleanup_phase = 0;

                if (recreate_obj) {
                        __u64 last_id;
                        next_id = oa->o_id;
                        last_id = filter_last_id(filter, group);
                        if (next_id > last_id) {
                                CERROR("%s: trying to recreate obj greater"
                                       "than last id "LPD64" > "LPD64"\n",
                                       obd->obd_name, next_id, last_id);
                                GOTO(cleanup, rc = -EINVAL);
                        }
                } else if (filter->fo_destroy_in_progress) {
                        CWARN("%s: precreate aborted by destroy\n",
                              obd->obd_name);
                        rc = -EAGAIN;
                        break;
                } else
                        next_id = filter_last_id(filter, group) + 1;

                dparent = filter_parent_lock(obd, group, next_id);
                if (IS_ERR(dparent))
                        GOTO(cleanup, rc = PTR_ERR(dparent));
                cleanup_phase = 1;      /* filter_parent_unlock(dparent) */

                dchild = filter_fid2dentry(obd, dparent, group, next_id);
                if (IS_ERR(dchild))
                        GOTO(cleanup, rc = PTR_ERR(dchild));
                cleanup_phase = 2;      /* f_dput(dchild) */

                if (dchild->d_inode != NULL) {
                        /* This would only happen if lastobjid was bad on disk*/
                        /* Could also happen if recreating missing obj but it
                         * already exists. */
                        if (recreate_obj) {
                                CERROR("%s: recreating existing object %.*s?\n",
                                       obd->obd_name, dchild->d_name.len,
                                       dchild->d_name.name);
                        } else {
                                /* Use these existing objects if they are
                                 * zero length. */
                                if (dchild->d_inode->i_size == 0) {
                                        rc = filter_use_existing_obj(obd,dchild,
                                                      &handle, &cleanup_phase);
                                        if (rc == 0)
                                                goto set_last_id;
                                        else
                                                GOTO(cleanup, rc);
                                }

                                CERROR("%s: Serious error: objid %.*s already "
                                       "exists; is this filesystem corrupt?\n",
                                       obd->obd_name, dchild->d_name.len,
                                       dchild->d_name.name);
                                LBUG();
                        }
                        GOTO(cleanup, rc = -EEXIST);
                }

                handle = fsfilt_start_log(obd, dparent->d_inode,
                                          FSFILT_OP_CREATE, NULL, 1);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                cleanup_phase = 3;

                CDEBUG(D_INODE, "%s: filter_precreate(od->o_gr="LPU64
                       ",od->o_id="LPU64")\n", obd->obd_name, group,
                       next_id);

                /* We mark object SUID+SGID to flag it for accepting UID+GID
                 * from client on first write.  Currently the permission bits
                 * on the OST are never used, so this is OK. */
                rc = ll_vfs_create(dparent->d_inode, dchild,
                                   S_IFREG |  S_ISUID | S_ISGID | 0666, NULL);
                if (rc) {
                        CERROR("create failed rc = %d\n", rc);
                        GOTO(cleanup, rc);
                }
                if (dchild->d_inode)
                        CDEBUG(D_INFO, "objid "LPU64" got inum %lu\n", next_id,
                                       dchild->d_inode->i_ino);

set_last_id:
                if (!recreate_obj) {
                        filter_set_last_id(filter, next_id, group);
                        err = filter_update_last_objid(obd, group, 0);
                        if (err)
                                CERROR("unable to write lastobjid "
                                       "but file created\n");
                }

        cleanup:
                switch(cleanup_phase) {
                case 3:
                        err = fsfilt_commit(obd, dparent->d_inode, handle, 0);
                        if (err) {
                                CERROR("error on commit, err = %d\n", err);
                                if (!rc)
                                        rc = err;
                        }
                case 2:
                        f_dput(dchild);
                case 1:
                        filter_parent_unlock(dparent);
                case 0:
                        break;
                }

                if (rc)
                        break;
                if (cfs_time_after(cfs_time_current(), enough_time)) {
                        i++;
                        CDEBUG(D_RPCTRACE,
                               "%s: precreate slow - want %d got %d \n",
                               obd->obd_name, *num, i);
                        break;
                }
        }
        *num = i;

        CDEBUG(D_RPCTRACE,
               "%s: created %d objects for group "LPU64": "LPU64" rc %d\n",
               obd->obd_name, i, group, filter->fo_last_objids[group], rc);

        RETURN(rc);
}

int filter_recreate(struct obd_device *obd, struct obdo *oa)
{
        struct ldlm_res_id res_id = { .name = { oa->o_id } };
        struct ldlm_valblock_ops *ns_lvbo;
        struct ldlm_resource *res;
        obd_valid old_valid = oa->o_valid;
        obd_flag old_flags = oa->o_flags;
        int diff = 1, rc;
        ENTRY;

        if (oa->o_id > filter_last_id(&obd->u.filter, oa->o_gr)) {
                if (!obd->obd_recovering ||
                    oa->o_id > filter_last_id(&obd->u.filter, oa->o_gr) +
                    OST_MAX_PRECREATE) {
                        CERROR("recreate objid "LPU64" > last id "LPU64"\n",
                               oa->o_id, filter_last_id(&obd->u.filter,
                               oa->o_gr));
                        RETURN(-EINVAL);
                }
                diff = oa->o_id - filter_last_id(&obd->u.filter, oa->o_gr);
        } else {
                if ((oa->o_valid & OBD_MD_FLFLAGS) == 0) {
                        oa->o_valid |= OBD_MD_FLFLAGS;
                        oa->o_flags = OBD_FL_RECREATE_OBJS;
                } else {
                        oa->o_flags |= OBD_FL_RECREATE_OBJS;
                }
        }

        down(&obd->u.filter.fo_create_lock);
        rc = filter_precreate(obd, oa, oa->o_gr, &diff);
        up(&obd->u.filter.fo_create_lock);

        res = ldlm_resource_get(obd->obd_namespace, NULL,
                                res_id, LDLM_EXTENT, 0);
        if (res != NULL) {
                /* Update lvb->lvb_blocks for the recreated object */
                ns_lvbo = res->lr_namespace->ns_lvbo;
                if (ns_lvbo && ns_lvbo->lvbo_update) {
                        rc = ns_lvbo->lvbo_update(res, NULL, 0, 1);
                        if (rc)
                                RETURN(rc);
                }
                ldlm_resource_putref(res);
        }

        if (rc == 0)
                CWARN("%s: recreated missing object "LPU64"/"LPU64"\n",
                      obd->obd_name, oa->o_id, oa->o_gr);

        oa->o_valid = old_valid;
        oa->o_flags = old_flags;
        RETURN(rc);
}

static int filter_create(struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct lvfs_run_ctxt saved;
        struct lov_stripe_md *lsm = NULL;
        struct ldlm_res_id res_id = { .name = { oa->o_id } };
        ldlm_policy_data_t policy = { .l_extent = { 0, OBD_OBJECT_EOF } };
        struct lustre_handle lockh;
        int flags = 0;
        int rc = 0;
        ENTRY;

        CDEBUG(D_INODE, "%s: filter_create(od->o_gr="LPU64",od->o_id="
               LPU64")\n", obd->obd_name, oa->o_gr, oa->o_id);

        if (!(oa->o_valid & OBD_MD_FLGROUP))
                oa->o_gr = 0;

        CDEBUG(D_INFO, "object "LPU64"/"LPU64"\n", oa->o_id, oa->o_gr);
        if (ea != NULL) {
                lsm = *ea;
                if (lsm == NULL) {
                        rc = obd_alloc_memmd(exp, &lsm);
                        if (rc < 0)
                                RETURN(rc);
                }
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            (oa->o_flags & OBD_FL_RECREATE_OBJS)) {
                /* Cancel all conflicting extent locks on recreating object,
                 * thus object's metadata will be updated on the clients */
                rc = ldlm_cli_enqueue_local(obd->obd_namespace, &res_id,
                                            LDLM_EXTENT, &policy, LCK_PW,
                                            &flags, ldlm_blocking_ast,
                                            ldlm_completion_ast,
                                            ldlm_glimpse_ast, NULL, 0,
                                            NULL, &lockh);
                rc = filter_recreate(obd, oa);
                ldlm_lock_decref(&lockh, LCK_PW);
        } else {
                rc = filter_handle_precreate(exp, oa, oa->o_gr, oti);
        }

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (rc && ea != NULL && *ea != lsm) {
                obd_free_memmd(exp, &lsm);
        } else if (rc == 0 && ea != NULL) {
                /* XXX LOV STACKING: the lsm that is passed to us from
                 * LOV does not have valid lsm_oinfo data structs, so
                 * don't go touching that.  This needs to be fixed in a
                 * big way. */
                lsm->lsm_object_id = oa->o_id;
                *ea = lsm;
        }

        RETURN(rc);
}

int filter_destroy(struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md *md, struct obd_trans_info *oti,
                   struct obd_export *md_exp)
{
        unsigned int qcids[MAXQUOTAS] = {0, 0};
        struct obd_device *obd;
        struct filter_obd *filter;
        struct dentry *dchild = NULL, *dparent = NULL;
        struct lustre_handle lockh = { 0 };
        struct lvfs_run_ctxt saved;
        void *handle = NULL;
        struct llog_cookie *fcc = NULL;
        int rc, rc2, cleanup_phase = 0, sync = 0;
        struct iattr iattr;
        ENTRY;

        if (!(oa->o_valid & OBD_MD_FLGROUP))
                oa->o_gr = 0;

        obd = exp->exp_obd;
        filter = &obd->u.filter;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        cleanup_phase = 1;

        CDEBUG(D_INODE, "%s: filter_destroy(od->o_gr="LPU64",od->o_id="
               LPU64")\n", obd->obd_name, oa->o_gr, oa->o_id);

        dchild = filter_fid2dentry(obd, NULL, oa->o_gr, oa->o_id);
        if (IS_ERR(dchild))
                GOTO(cleanup, rc = PTR_ERR(dchild));
        cleanup_phase = 2;

        if (dchild->d_inode == NULL) {
                CDEBUG(D_INODE, "destroying non-existent object "LPU64"\n",
                       oa->o_id);
                /* If object already gone, cancel cookie right now */
                if (oa->o_valid & OBD_MD_FLCOOKIE) {
                        struct llog_ctxt *ctxt;
                        fcc = &oa->o_lcookie;
                        ctxt = llog_get_context(obd, fcc->lgc_subsys + 1);
                        llog_cancel(ctxt, NULL, 1, fcc, 0);
                        llog_ctxt_put(ctxt);
                        fcc = NULL; /* we didn't allocate fcc, don't free it */
                }
                GOTO(cleanup, rc = -ENOENT);
        }

        rc = filter_prepare_destroy(obd, oa->o_id, &lockh);
        if (rc)
                GOTO(cleanup, rc);

        /* Our MDC connection is established by the MDS to us */
        if (oa->o_valid & OBD_MD_FLCOOKIE) {
                OBD_ALLOC(fcc, sizeof(*fcc));
                if (fcc != NULL)
                        *fcc = oa->o_lcookie;
        }

        /* we're gonna truncate it first in order to avoid possible deadlock:
         *      P1                      P2
         * open trasaction      open transaction
         * down(i_zombie)       down(i_zombie)
         *                      restart transaction
         * (see BUG 4180) -bzzz
         *
         * take i_alloc_sem too to prevent other threads from writing to the
         * file while we are truncating it. This can cause lock ordering issue
         * between page lock, i_mutex & starting new journal handle.
         * (see bug 20321) -johann
         */
        down_write(&dchild->d_inode->i_alloc_sem);
        LOCK_INODE_MUTEX(dchild->d_inode);

        /* VBR: version recovery check */
        rc = filter_version_get_check(exp, oti, dchild->d_inode);
        if (rc) {
                UNLOCK_INODE_MUTEX(dchild->d_inode);
                up_write(&dchild->d_inode->i_alloc_sem);
                GOTO(cleanup, rc);
        }

        handle = fsfilt_start_log(obd, dchild->d_inode, FSFILT_OP_SETATTR,
                                  NULL, 1);
        if (IS_ERR(handle)) {
                UNLOCK_INODE_MUTEX(dchild->d_inode);
                up_write(&dchild->d_inode->i_alloc_sem);
                GOTO(cleanup, rc = PTR_ERR(handle));
        }

        /* Locking order: i_mutex -> journal_lock -> dqptr_sem. LU-952 */
        ll_vfs_dq_init(dchild->d_inode);

        iattr.ia_valid = ATTR_SIZE;
        iattr.ia_size = 0;
        rc = fsfilt_setattr(obd, dchild, handle, &iattr, 1);
        rc2 = fsfilt_commit(obd, dchild->d_inode, handle, 0);
        UNLOCK_INODE_MUTEX(dchild->d_inode);
        up_write(&dchild->d_inode->i_alloc_sem);
        if (rc)
                GOTO(cleanup, rc);
        if (rc2)
                GOTO(cleanup, rc = rc2);

        /* We don't actually need to lock the parent until we are unlinking
         * here, and not while truncating above.  That avoids holding the
         * parent lock for a long time during truncate, which can block other
         * threads from doing anything to objects in that directory. bug 7171 */
        dparent = filter_parent_lock(obd, oa->o_gr, oa->o_id);
        if (IS_ERR(dparent))
                GOTO(cleanup, rc = PTR_ERR(dparent));
        cleanup_phase = 3; /* filter_parent_unlock */

        LOCK_INODE_MUTEX(dchild->d_inode);
        handle = fsfilt_start_log(obd, dparent->d_inode,FSFILT_OP_UNLINK,oti,1);
        if (IS_ERR(handle)) {
                UNLOCK_INODE_MUTEX(dchild->d_inode);
                GOTO(cleanup, rc = PTR_ERR(handle));
        }
        cleanup_phase = 4; /* fsfilt_commit */

        /* Quota release need uid/gid of inode */
        obdo_from_inode(oa, dchild->d_inode, OBD_MD_FLUID|OBD_MD_FLGID);

        filter_fmd_drop(exp, oa->o_id, oa->o_gr);

        /* this drops dchild->d_inode->i_mutex unconditionally */
        rc = filter_destroy_internal(obd, oa->o_id, oa->o_gr, dparent, dchild);

        EXIT;
cleanup:
        switch(cleanup_phase) {
        case 4:
                if (fcc != NULL)
                        sync = fsfilt_add_journal_cb(obd, 0, oti ?
                                                     oti->oti_handle : handle,
                                                     filter_cancel_cookies_cb,
                                                     fcc);
                /* If add_journal_cb failed, then filter_finish_transno
                 * will commit the handle and we will do a sync
                 * on commit. then we call callback directly to free
                 * the fcc.
                 */
                rc = filter_finish_transno(exp, NULL, oti, rc, sync);
                if (sync) {
                        filter_cancel_cookies_cb(obd, 0, fcc, rc);
                        fcc = NULL;
                }
                rc2 = fsfilt_commit(obd, dparent->d_inode, handle, 0);
                if (rc2) {
                        CERROR("error on commit, err = %d\n", rc2);
                        if (!rc)
                                rc = rc2;
                } else {
                        fcc = NULL;
                }
        case 3:
                filter_parent_unlock(dparent);
        case 2:
                filter_fini_destroy(obd, &lockh);

                f_dput(dchild);
                if (fcc != NULL)
                        OBD_FREE(fcc, sizeof(*fcc));
        case 1:
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }

        /* trigger quota release */
        qcids[USRQUOTA] = oa->o_uid;
        qcids[GRPQUOTA] = oa->o_gid;
        rc2 = lquota_adjust(filter_quota_interface_ref, obd, qcids, NULL, rc,
                            FSFILT_OP_UNLINK);
        if (rc2)
                CERROR("filter adjust qunit! (rc:%d)\n", rc2);
        return rc;
}

/* NB start and end are used for punch, but not truncate */
static int filter_truncate(struct obd_export *exp, struct obd_info *oinfo,
                           struct obd_trans_info *oti,
                           struct ptlrpc_request_set *rqset)
{
        int rc;
        ENTRY;

        if (oinfo->oi_policy.l_extent.end != OBD_OBJECT_EOF) {
                CERROR("PUNCH not supported, only truncate: end = "LPX64"\n",
                       oinfo->oi_policy.l_extent.end);
                RETURN(-EFAULT);
        }

        CDEBUG(D_INODE, "calling truncate for object "LPU64", valid = "LPX64
               ", o_size = "LPD64"\n", oinfo->oi_oa->o_id,
               oinfo->oi_oa->o_valid, oinfo->oi_policy.l_extent.start);

        oinfo->oi_oa->o_size = oinfo->oi_policy.l_extent.start;
        rc = filter_setattr(exp, oinfo, oti);

        RETURN(rc);
}

static int filter_sync(struct obd_export *exp, struct obd_info *oinfo,
                       obd_off start, obd_off end,
                       struct ptlrpc_request_set *set)
{
        struct lvfs_run_ctxt saved;
        struct filter_obd *filter;
        struct dentry *dentry;
        struct llog_ctxt *ctxt;
        int rc, rc2;
        ENTRY;

        filter = &exp->exp_obd->u.filter;

        /* An objid of zero is taken to mean "sync whole filesystem" */
        if (!oinfo->oi_oa || !(oinfo->oi_oa->o_valid & OBD_MD_FLID)) {
                rc = fsfilt_sync(exp->exp_obd, filter->fo_obt.obt_sb);

                /* Flush any remaining cancel messages out to the target */
                ctxt = llog_get_context(exp->exp_obd, LLOG_MDS_OST_REPL_CTXT);
                if (ctxt) {
                        llog_sync(ctxt, exp);
                        llog_ctxt_put(ctxt);
                } else {
                        CERROR("No LLOG_MDS_OST_REPL_CTXT found in obd %p\n",
                               exp->exp_obd);
                }
                RETURN(rc);
        }

        dentry = filter_oa2dentry(exp->exp_obd, oinfo->oi_oa);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);

        LOCK_INODE_MUTEX(dentry->d_inode);

        rc = filemap_fdatawrite(dentry->d_inode->i_mapping);
        if (rc == 0) {
                /* just any file to grab fsync method - "file" arg unused */
                struct file *file = filter->fo_rcvd_filp;

                if (file->f_op && file->f_op->fsync)
                        rc = file->f_op->fsync(NULL, dentry, 1);

                rc2 = filemap_fdatawait(dentry->d_inode->i_mapping);
                if (!rc)
                        rc = rc2;
        }
        UNLOCK_INODE_MUTEX(dentry->d_inode);

        oinfo->oi_oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oinfo->oi_oa, dentry->d_inode, FILTER_VALID_FLAGS);

        pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);

        f_dput(dentry);
        RETURN(rc);
}

static int filter_get_info(struct obd_export *exp, __u32 keylen,
                           void *key, __u32 *vallen, void *val,
                           struct lov_stripe_md *lsm)
{
        struct obd_device *obd;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client export %p\n", exp);
                RETURN(-EINVAL);
        }

        if (KEY_IS(KEY_BLOCKSIZE)) {
                __u32 *blocksize = val;
                if (blocksize) {
                        if (*vallen < sizeof(*blocksize))
                                RETURN(-EOVERFLOW);
                        *blocksize = obd->u.obt.obt_sb->s_blocksize;
                }
                *vallen = sizeof(*blocksize);
                RETURN(0);
        }

        if (KEY_IS(KEY_BLOCKSIZE_BITS)) {
                __u32 *blocksize_bits = val;
                if (blocksize_bits) {
                        if (*vallen < sizeof(*blocksize_bits))
                                RETURN(-EOVERFLOW);
                        *blocksize_bits = obd->u.obt.obt_sb->s_blocksize_bits;
                }
                *vallen = sizeof(*blocksize_bits);
                RETURN(0);
        }

        if (KEY_IS(KEY_LAST_ID)) {
                obd_id *last_id = val;
                /* FIXME: object groups */
                if (last_id) {
                        if (*vallen < sizeof(*last_id))
                                RETURN(-EOVERFLOW);
                        *last_id = filter_last_id(&obd->u.filter, 0);
                }
                *vallen = sizeof(*last_id);
                RETURN(0);
        }

        if (KEY_IS(KEY_FIEMAP)) {
                struct ll_fiemap_info_key *fm_key = key;
                struct dentry *dentry;
                struct ll_user_fiemap *fiemap = val;
                struct lvfs_run_ctxt saved;
                int rc;

                if (fiemap == NULL) {
                        *vallen = fiemap_count_to_size(
                                                fm_key->fiemap.fm_extent_count);
                        RETURN(0);
                }

                dentry = __filter_oa2dentry(exp->exp_obd, &fm_key->oa,
                                            __FUNCTION__, 1);
                if (IS_ERR(dentry))
                        RETURN(PTR_ERR(dentry));

                memcpy(fiemap, &fm_key->fiemap, sizeof(*fiemap));
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                rc = fsfilt_iocontrol(obd, dentry, FSFILT_IOC_FIEMAP,
                                      (long)fiemap);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                f_dput(dentry);
                RETURN(rc);
        }

        if (KEY_IS(KEY_SYNC_LOCK_CANCEL)) {
                *((__u32 *) val) = obd->u.filter.fo_sync_lock_cancel;
                *vallen = sizeof(__u32);
                RETURN(0);
        }

        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
}

static int filter_set_info_async(struct obd_export *exp, __u32 keylen,
                                 void *key, __u32 vallen, void *val,
                                 struct ptlrpc_request_set *set)
{
        struct obd_device *obd;
        struct llog_ctxt *ctxt;
        int rc = 0;
        ENTRY;

        obd = exp->exp_obd;
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid export %p\n", exp);
                RETURN(-EINVAL);
        }

	if (KEY_IS(KEY_GRANT_SHRINK)) {
                struct ost_body *body = (struct ost_body *)val;
                /* handle shrink grant */
                spin_lock(&exp->exp_obd->obd_osfs_lock);
                filter_grant_incoming(exp, &body->oa);
                spin_unlock(&exp->exp_obd->obd_osfs_lock);
                RETURN(rc);
        }

        if (KEY_IS(KEY_CAPA_KEY)) {
                RETURN(0);
        }

        if (!KEY_IS(KEY_MDS_CONN))
                RETURN(-EINVAL);

        LCONSOLE_WARN("%s: received MDS connection from %s\n", obd->obd_name,
                      obd_export_nid2str(exp));
        obd->u.filter.fo_mdc_conn.cookie = exp->exp_handle.h_cookie;

        /* setup llog imports */
        ctxt = llog_get_context(obd, LLOG_MDS_OST_REPL_CTXT);
        rc = llog_receptor_accept(ctxt, exp->exp_imp_reverse);
        llog_ctxt_put(ctxt);

        lquota_setinfo(filter_quota_interface_ref, exp, obd);

        RETURN(rc);
}

int filter_iocontrol(unsigned int cmd, struct obd_export *exp,
                     int len, void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_ioctl_data *data = karg;
        int rc = 0;

        switch (cmd) {
        case OBD_IOC_ABORT_RECOVERY: {
                CERROR("aborting recovery for device %s\n", obd->obd_name);
                target_abort_recovery(obd);
                RETURN(0);
        }

        case OBD_IOC_SYNC: {
                CDEBUG(D_RPCTRACE, "syncing ost %s\n", obd->obd_name);
                rc = fsfilt_sync(obd, obd->u.obt.obt_sb);
                RETURN(rc);
        }

        case OBD_IOC_SET_READONLY: {
                void *handle;
                struct super_block *sb = obd->u.obt.obt_sb;
                struct inode *inode = sb->s_root->d_inode;
                LCONSOLE_WARN("*** setting obd %s device '%s' read-only ***\n",
                              obd->obd_name, sb->s_id);

                handle = fsfilt_start(obd, inode, FSFILT_OP_MKNOD, NULL);
                if (!IS_ERR(handle))
                        rc = fsfilt_commit(obd, inode, handle, 1);

                CDEBUG(D_HA, "syncing ost %s\n", obd->obd_name);
                rc = fsfilt_sync(obd, obd->u.obt.obt_sb);

                lvfs_set_rdonly(obd, obd->u.obt.obt_sb);
                RETURN(0);
        }

        case OBD_IOC_CATLOGLIST: {
                rc = llog_catalog_list(obd, 1, data);
                RETURN(rc);
        }

        case OBD_IOC_LLOG_CANCEL:
        case OBD_IOC_LLOG_REMOVE:
        case OBD_IOC_LLOG_INFO:
        case OBD_IOC_LLOG_PRINT: {
                /* FIXME to be finished */
                RETURN(-EOPNOTSUPP);
/*
                struct llog_ctxt *ctxt = NULL;

                push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                rc = llog_ioctl(ctxt, cmd, data);
                pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);

                RETURN(rc);
*/
        }
        default:
                RETURN(-EINVAL);
        }
        RETURN(0);
}

static int filter_health_check(struct obd_device *obd)
{
#ifdef USE_HEALTH_CHECK_WRITE
        struct filter_obd *filter = &obd->u.filter;
#endif
        int rc = 0;

        /*
         * health_check to return 0 on healthy
         * and 1 on unhealthy.
         */
        if (obd->u.obt.obt_sb->s_flags & MS_RDONLY)
                rc = 1;

#ifdef USE_HEALTH_CHECK_WRITE
        LASSERT(filter->fo_obt.obt_health_check_filp != NULL);
        rc |= !!lvfs_check_io_health(obd, filter->fo_obt.obt_health_check_filp);
#endif

        return rc;
}

static struct dentry *filter_lvfs_fid2dentry(__u64 id, __u32 gen, __u64 gr,
                                             void *data)
{
        return filter_fid2dentry(data, NULL, gr, id);
}

static int filter_process_config(struct obd_device *obd,obd_count len,void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct lprocfs_static_vars lvars;
        int rc = 0;

        lprocfs_filter_init_vars(&lvars);

        rc = class_process_proc_param(PARAM_OST, lvars.obd_vars, lcfg, obd);

        return(rc);
}

static struct lvfs_callback_ops filter_lvfs_ops = {
        l_fid2dentry:     filter_lvfs_fid2dentry,
};

static int filter_notify(struct obd_device *obd, struct obd_device *watched,
                         enum obd_notify_event ev, void *data)
{
        ENTRY;

        CDEBUG(D_CONFIG, "notify %s ev=%d\n", watched->obd_name, ev);

        switch (ev) {
        case OBD_NOTIFY_CONFIG:
                /* call this only when config is processed and stale_export_age
                 * value is configured */
                class_disconnect_expired_exports(obd);
        default:
                RETURN(0);
        }
}

static struct obd_ops filter_obd_ops = {
        .o_owner          = THIS_MODULE,
        .o_get_info       = filter_get_info,
        .o_set_info_async = filter_set_info_async,
        .o_setup          = filter_setup,
        .o_precleanup     = filter_precleanup,
        .o_cleanup        = filter_cleanup,
        .o_connect        = filter_connect,
        .o_reconnect      = filter_reconnect,
        .o_disconnect     = filter_disconnect,
        .o_ping           = filter_ping,
        .o_init_export    = filter_init_export,
        .o_destroy_export = filter_destroy_export,
        .o_statfs         = filter_statfs,
        .o_getattr        = filter_getattr,
        .o_unpackmd       = filter_unpackmd,
        .o_create         = filter_create,
        .o_setattr        = filter_setattr,
        .o_destroy        = filter_destroy,
        .o_brw            = filter_brw,
        .o_punch          = filter_truncate,
        .o_sync           = filter_sync,
        .o_preprw         = filter_preprw,
        .o_commitrw       = filter_commitrw,
        .o_llog_init      = filter_llog_init,
        .o_llog_connect   = filter_llog_connect,
        .o_llog_finish    = filter_llog_finish,
        .o_iocontrol      = filter_iocontrol,
        .o_health_check   = filter_health_check,
        .o_process_config = filter_process_config,
        .o_postrecov      = filter_postrecov,
        .o_notify         = filter_notify,
};

quota_interface_t *filter_quota_interface_ref;
extern quota_interface_t filter_quota_interface;

static int __init obdfilter_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        printk(KERN_INFO "Lustre: Filtering OBD driver; http://wiki.whamcloud.com/\n");

        lprocfs_filter_init_vars(&lvars);

        request_module("lquota");
        OBD_ALLOC(obdfilter_created_scratchpad,
                  OBDFILTER_CREATED_SCRATCHPAD_ENTRIES *
                  sizeof(*obdfilter_created_scratchpad));
        if (obdfilter_created_scratchpad == NULL)
                return -ENOMEM;

        ll_fmd_cachep = cfs_mem_cache_create("ll_fmd_cache",
                                             sizeof(struct filter_mod_data),
                                             0, 0);
        if (!ll_fmd_cachep)
                GOTO(out, rc = -ENOMEM);

        filter_quota_interface_ref = PORTAL_SYMBOL_GET(filter_quota_interface);
        init_obd_quota_ops(filter_quota_interface_ref, &filter_obd_ops);

        rc = class_register_type(&filter_obd_ops, lvars.module_vars,
                                 LUSTRE_OST_NAME);
        if (rc) {
                int err;

                err = cfs_mem_cache_destroy(ll_fmd_cachep);
                LASSERTF(err == 0, "Cannot destroy ll_fmd_cachep: rc %d\n",err);
                ll_fmd_cachep = NULL;
out:
                if (filter_quota_interface_ref)
                        PORTAL_SYMBOL_PUT(filter_quota_interface);

                OBD_FREE(obdfilter_created_scratchpad,
                         OBDFILTER_CREATED_SCRATCHPAD_ENTRIES *
                         sizeof(*obdfilter_created_scratchpad));
        }

        return rc;
}

static void __exit obdfilter_exit(void)
{
        if (filter_quota_interface_ref)
                PORTAL_SYMBOL_PUT(filter_quota_interface);

        if (ll_fmd_cachep) {
                int rc = cfs_mem_cache_destroy(ll_fmd_cachep);
                LASSERTF(rc == 0, "Cannot destroy ll_fmd_cachep: rc %d\n", rc);
                ll_fmd_cachep = NULL;
        }

        class_unregister_type(LUSTRE_OST_NAME);
        OBD_FREE(obdfilter_created_scratchpad,
                 OBDFILTER_CREATED_SCRATCHPAD_ENTRIES *
                 sizeof(*obdfilter_created_scratchpad));
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Filtering OBD driver");
MODULE_LICENSE("GPL");

module_init(obdfilter_init);
module_exit(obdfilter_exit);
