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
 * Copyright (c) 2010, 2011, Intel Corporation.
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

#include <obd_cksum.h>
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
        LASSERT(exp->exp_obd == obd);
        obd_transno_commit_cb(obd, transno, exp, error);
        class_export_cb_put(exp);
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
                cfs_spin_lock(&exp->exp_lock);
                exp->exp_vbr_failed = 1;
                cfs_spin_unlock(&exp->exp_lock);
                RETURN (-EOVERFLOW);
        }
        oti->oti_pre_version = curr_version;
        RETURN(0);
}

/* Assumes caller has already pushed us into the kernel context. */
int filter_finish_transno(struct obd_export *exp, struct inode *inode,
                          struct obd_trans_info *oti, int rc, int force_sync)
{
        struct obd_device_target *obt = &exp->exp_obd->u.obt;
        struct tg_export_data *ted = &exp->exp_target_data;
        struct lr_server_data *lsd = class_server_data(exp->exp_obd);
        struct lsd_client_data *lcd;
        __u64 last_rcvd;
        loff_t off;
        int err, log_pri = D_RPCTRACE;

        /* Propagate error code. */
        if (rc)
                RETURN(rc);

        if (!exp->exp_obd->obd_replayable || oti == NULL)
                RETURN(rc);

        cfs_mutex_down(&ted->ted_lcd_lock);
        lcd = ted->ted_lcd;
        /* if the export has already been disconnected, we have no last_rcvd slot,
         * update server data with latest transno then */
        if (lcd == NULL) {
                cfs_mutex_up(&ted->ted_lcd_lock);
                CWARN("commit transaction for disconnected client %s: rc %d\n",
                      exp->exp_client_uuid.uuid, rc);
                err = filter_update_server_data(exp->exp_obd);
                RETURN(err);
        }

        /* we don't allocate new transnos for replayed requests */
        cfs_spin_lock(&obt->obt_lut->lut_translock);
        if (oti->oti_transno == 0) {
                last_rcvd = le64_to_cpu(lsd->lsd_last_transno) + 1;
                lsd->lsd_last_transno = cpu_to_le64(last_rcvd);
                LASSERT(last_rcvd >= le64_to_cpu(lcd->lcd_last_transno));
        } else {
                last_rcvd = oti->oti_transno;
                if (last_rcvd > le64_to_cpu(lsd->lsd_last_transno))
                        lsd->lsd_last_transno = cpu_to_le64(last_rcvd);
                if (unlikely(last_rcvd < le64_to_cpu(lcd->lcd_last_transno))) {
                        CERROR("Trying to overwrite bigger transno, on-disk: "
                               LPU64", new: "LPU64"\n",
                               le64_to_cpu(lcd->lcd_last_transno), last_rcvd);
                        cfs_spin_lock(&exp->exp_lock);
                        exp->exp_vbr_failed = 1;
                        cfs_spin_unlock(&exp->exp_lock);
                        cfs_spin_unlock(&obt->obt_lut->lut_translock);
                        cfs_mutex_up(&ted->ted_lcd_lock);
                        RETURN(-EOVERFLOW);
                }
        }
        oti->oti_transno = last_rcvd;

        lcd->lcd_last_transno = cpu_to_le64(last_rcvd);
        lcd->lcd_pre_versions[0] = cpu_to_le64(oti->oti_pre_version);
        lcd->lcd_last_xid = cpu_to_le64(oti->oti_xid);
        cfs_spin_unlock(&obt->obt_lut->lut_translock);

        if (inode)
                fsfilt_set_version(exp->exp_obd, inode, last_rcvd);

        off = ted->ted_lr_off;
        if (off <= 0) {
                CERROR("%s: client idx %d is %lld\n", exp->exp_obd->obd_name,
                       ted->ted_lr_idx, ted->ted_lr_off);
                err = -EINVAL;
        } else {
                class_export_cb_get(exp); /* released when the cb is called */
                if (!force_sync)
                        force_sync = fsfilt_add_journal_cb(exp->exp_obd,
                                                           last_rcvd,
                                                           oti->oti_handle,
                                                           filter_commit_cb,
                                                           exp);

                err = fsfilt_write_record(exp->exp_obd, obt->obt_rcvd_filp,
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
               last_rcvd, lcd->lcd_uuid, ted->ted_lr_idx, err);
        cfs_mutex_up(&ted->ted_lcd_lock);
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
                cfs_spin_lock_init(&brw_stats->hist[i].oh_lock);
}

static int lprocfs_init_rw_stats(struct obd_device *obd,
                                 struct lprocfs_stats **stats)
{
        int num_stats;

        num_stats = (sizeof(*obd->obd_type->typ_dt_ops) / sizeof(void *)) +
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
        int rc, newnid = 0;
        ENTRY;

        if (obd_uuid_equals(&exp->exp_client_uuid, &obd->obd_uuid))
                /* Self-export gets no proc entry */
                RETURN(0);

        rc = lprocfs_exp_setup(exp, client_nid, &newnid);
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
                        GOTO(clean, rc = -ENOMEM);

                init_brw_stats(tmp->nid_brw_stats);
                rc = lprocfs_seq_create(exp->exp_nid_stats->nid_proc, "brw_stats",
                                        0644, &filter_per_nid_stats_fops,
                                        exp->exp_nid_stats);
                if (rc)
                        CWARN("Error adding the brw_stats file\n");

                rc = lprocfs_init_rw_stats(obd, &exp->exp_nid_stats->nid_stats);
                if (rc)
                        GOTO(clean, rc);

                rc = lprocfs_register_stats(tmp->nid_proc, "stats",
                                            tmp->nid_stats);
                if (rc)
                        GOTO(clean, rc);
                rc = lprocfs_nid_ldlm_stats_init(tmp);
                if (rc)
                        GOTO(clean, rc);
        }

        RETURN(0);
 clean:
        return rc;
}

/* Add client data to the FILTER.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_idx is -1 (i.e. a new client).
 * Otherwise, we have just read the data from the last_rcvd file and
 * we know its offset. */
static int filter_client_add(struct obd_device *obd, struct obd_export *exp,
                             int cl_idx)
{
        struct obd_device_target *obt = &obd->u.obt;
        struct tg_export_data *ted = &exp->exp_target_data;
        struct lr_server_data *lsd = class_server_data(obd);
        unsigned long *bitmap = obt->obt_lut->lut_client_bitmap;
        int new_client = (cl_idx == -1);

        ENTRY;

        LASSERT(bitmap != NULL);
        LASSERTF(cl_idx > -2, "%d\n", cl_idx);

        /* Self-export */
        if (strcmp(ted->ted_lcd->lcd_uuid, obd->obd_uuid.uuid) == 0)
                RETURN(0);

        /* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        if (new_client) {
                cl_idx = cfs_find_first_zero_bit(bitmap, LR_MAX_CLIENTS);
        repeat:
                if (cl_idx >= LR_MAX_CLIENTS) {
                        CERROR("no room for %u client - fix LR_MAX_CLIENTS\n",
                               cl_idx);
                        RETURN(-EOVERFLOW);
                }
                if (cfs_test_and_set_bit(cl_idx, bitmap)) {
                        cl_idx = cfs_find_next_zero_bit(bitmap, LR_MAX_CLIENTS,
                                                        cl_idx);
                        goto repeat;
                }
        } else {
                if (cfs_test_and_set_bit(cl_idx, bitmap)) {
                        CERROR("FILTER client %d: bit already set in bitmap!\n",
                               cl_idx);
                        LBUG();
                }
        }

        ted->ted_lr_idx = cl_idx;
        ted->ted_lr_off = le32_to_cpu(lsd->lsd_client_start) +
                          cl_idx * le16_to_cpu(lsd->lsd_client_size);
        cfs_init_mutex(&ted->ted_lcd_lock);
        LASSERTF(ted->ted_lr_off > 0, "ted_lr_off = %llu\n", ted->ted_lr_off);

        CDEBUG(D_INFO, "client at index %d (%llu) with UUID '%s' added\n",
               ted->ted_lr_idx, ted->ted_lr_off, ted->ted_lcd->lcd_uuid);

        if (new_client) {
                struct lvfs_run_ctxt saved;
                loff_t off = ted->ted_lr_off;
                int rc;
                void *handle;

                CDEBUG(D_INFO, "writing client lcd at idx %u (%llu) (len %u)\n",
                       ted->ted_lr_idx,off,(unsigned int)sizeof(*ted->ted_lcd));

                if (OBD_FAIL_CHECK(OBD_FAIL_TGT_CLIENT_ADD))
                        RETURN(-ENOSPC);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                /* Transaction needed to fix bug 1403 */
                handle = fsfilt_start(obd,
                                      obt->obt_rcvd_filp->f_dentry->d_inode,
                                      FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        CERROR("unable to start transaction: rc %d\n", rc);
                } else {
                        ted->ted_lcd->lcd_last_epoch = lsd->lsd_start_epoch;
                        exp->exp_last_request_time = cfs_time_current_sec();
                        rc = fsfilt_add_journal_cb(obd, 0, handle,
                                                   target_client_add_cb,
                                                   class_export_cb_get(exp));
                        if (rc == 0) {
                                cfs_spin_lock(&exp->exp_lock);
                                exp->exp_need_sync = 1;
                                cfs_spin_unlock(&exp->exp_lock);
                        }
                        rc = fsfilt_write_record(obd, obt->obt_rcvd_filp,
                                                 ted->ted_lcd,
                                                 sizeof(*ted->ted_lcd),
                                                 &off, rc /* sync if no cb */);
                        fsfilt_commit(obd,
                                      obt->obt_rcvd_filp->f_dentry->d_inode,
                                      handle, 0);
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                if (rc) {
                        CERROR("error writing %s client idx %u: rc %d\n",
                               LAST_RCVD, ted->ted_lr_idx, rc);
                        RETURN(rc);
                }
        }
        RETURN(0);
}

static int filter_client_del(struct obd_export *exp)
{
        struct tg_export_data *ted = &exp->exp_target_data;
        struct obd_device_target *obt = &exp->exp_obd->u.obt;
        struct lvfs_run_ctxt saved;
        int rc;
        loff_t off;
        ENTRY;

        if (ted->ted_lcd == NULL)
                RETURN(0);

        /* XXX if lcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (strcmp(ted->ted_lcd->lcd_uuid, exp->exp_obd->obd_uuid.uuid ) == 0)
                GOTO(free, 0);

        LASSERT(obt->obt_lut->lut_client_bitmap != NULL);

        off = ted->ted_lr_off;

        CDEBUG(D_INFO, "freeing client at idx %u, offset %lld with UUID '%s'\n",
               ted->ted_lr_idx, ted->ted_lr_off, ted->ted_lcd->lcd_uuid);

        /* Don't clear ted_lr_idx here as it is likely also unset.  At worst
         * we leak a client slot that will be cleaned on the next recovery. */
        if (off <= 0) {
                CERROR("%s: client idx %d has med_off %lld\n",
                       exp->exp_obd->obd_name, ted->ted_lr_idx, off);
                GOTO(free, rc = -EINVAL);
        }

        /* Clear the bit _after_ zeroing out the client so we don't
           race with filter_client_add and zero out new clients.*/
        if (!cfs_test_bit(ted->ted_lr_idx, obt->obt_lut->lut_client_bitmap)) {
                CERROR("FILTER client %u: bit already clear in bitmap!!\n",
                       ted->ted_lr_idx);
                LBUG();
        }

        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
        /* Make sure the server's last_transno is up to date.
         * This should be done before zeroing client slot so last_transno will
         * be in server data or in client data in case of failure */
        filter_update_server_data(exp->exp_obd);

        cfs_mutex_down(&ted->ted_lcd_lock);
        memset(ted->ted_lcd->lcd_uuid, 0, sizeof ted->ted_lcd->lcd_uuid);
        rc = fsfilt_write_record(exp->exp_obd, obt->obt_rcvd_filp,
                                 ted->ted_lcd,
                                 sizeof(*ted->ted_lcd), &off, 0);
        cfs_mutex_up(&ted->ted_lcd_lock);
        pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);

        CDEBUG(rc == 0 ? D_INFO : D_ERROR,
               "zero out client %s at idx %u/%llu in %s, rc %d\n",
               ted->ted_lcd->lcd_uuid, ted->ted_lr_idx, ted->ted_lr_off,
               LAST_RCVD, rc);
        EXIT;
free:
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
                cfs_list_del(&fmd->fmd_list);
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
        cfs_spin_lock(&fed->fed_lock);
        filter_fmd_put_nolock(fed, fmd); /* caller reference */
        cfs_spin_unlock(&fed->fed_lock);
}

/* expire entries from the end of the list if there are too many
 * or they are too old */
static void filter_fmd_expire_nolock(struct filter_obd *filter,
                                     struct filter_export_data *fed,
                                     struct filter_mod_data *keep)
{
        struct filter_mod_data *fmd, *tmp;

        cfs_list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
                if (fmd == keep)
                        break;

                if (cfs_time_before(jiffies, fmd->fmd_expire) &&
                    fed->fed_mod_count < filter->fo_fmd_max_num)
                        break;

                cfs_list_del_init(&fmd->fmd_list);
                filter_fmd_put_nolock(fed, fmd); /* list reference */
        }
}

void filter_fmd_expire(struct obd_export *exp)
{
        cfs_spin_lock(&exp->exp_filter_data.fed_lock);
        filter_fmd_expire_nolock(&exp->exp_obd->u.filter,
                                 &exp->exp_filter_data, NULL);
        cfs_spin_unlock(&exp->exp_filter_data.fed_lock);
}

/* find specified objid, group in export fmd list.
 * caller must hold fed_lock and take fmd reference itself */
static struct filter_mod_data *filter_fmd_find_nolock(struct filter_obd *filter,
                                                struct filter_export_data *fed,
                                                obd_id objid, obd_seq group)
{
        struct filter_mod_data *found = NULL, *fmd;

        LASSERT_SPIN_LOCKED(&fed->fed_lock);

        cfs_list_for_each_entry_reverse(fmd, &fed->fed_mod_list, fmd_list) {
                if (fmd->fmd_id == objid && fmd->fmd_gr == group) {
                        found = fmd;
                        cfs_list_del(&fmd->fmd_list);
                        cfs_list_add_tail(&fmd->fmd_list, &fed->fed_mod_list);
                        fmd->fmd_expire = jiffies + filter->fo_fmd_max_age;
                        break;
                }
        }

        filter_fmd_expire_nolock(filter, fed, found);

        return found;
}

/* Find fmd based on objid and group, or return NULL if not found. */
struct filter_mod_data *filter_fmd_find(struct obd_export *exp,
                                        obd_id objid, obd_seq group)
{
        struct filter_mod_data *fmd;

        cfs_spin_lock(&exp->exp_filter_data.fed_lock);
        fmd = filter_fmd_find_nolock(&exp->exp_obd->u.filter,
                                     &exp->exp_filter_data, objid, group);
        if (fmd)
                fmd->fmd_refcount++;    /* caller reference */
        cfs_spin_unlock(&exp->exp_filter_data.fed_lock);

        return fmd;
}

/* Find fmd based on objid and group, or create a new one if none is found.
 * It is possible for this function to return NULL under memory pressure,
 * or if objid = 0 is passed (which will only cause old entries to expire).
 * Currently this is not fatal because any fmd state is transient and
 * may also be freed when it gets sufficiently old. */
struct filter_mod_data *filter_fmd_get(struct obd_export *exp,
                                       obd_id objid, obd_seq group)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_mod_data *found = NULL, *fmd_new = NULL;

        OBD_SLAB_ALLOC_PTR_GFP(fmd_new, ll_fmd_cachep, CFS_ALLOC_IO);

        cfs_spin_lock(&fed->fed_lock);
        found = filter_fmd_find_nolock(&exp->exp_obd->u.filter,fed,objid,group);
        if (fmd_new) {
                if (found == NULL) {
                        cfs_list_add_tail(&fmd_new->fmd_list,
                                          &fed->fed_mod_list);
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

        cfs_spin_unlock(&fed->fed_lock);

        return found;
}

#ifdef DO_FMD_DROP
/* drop fmd list reference so it will disappear when last reference is put.
 * This isn't so critical because it would in fact only affect the one client
 * that is doing the unlink and at worst we have an stale entry referencing
 * an object that should never be used again. */
static void filter_fmd_drop(struct obd_export *exp, obd_id objid, obd_seq group)
{
        struct filter_mod_data *found = NULL;

        cfs_spin_lock(&exp->exp_filter_data.fed_lock);
        found = filter_fmd_find_nolock(&exp->exp_filter_data, objid, group);
        if (found) {
                cfs_list_del_init(&found->fmd_list);
                filter_fmd_put_nolock(&exp->exp_filter_data, found);
        }
        cfs_spin_unlock(&exp->exp_filter_data.fed_lock);
}
#else
#define filter_fmd_drop(exp, objid, group)
#endif

/* remove all entries from fmd list */
static void filter_fmd_cleanup(struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_mod_data *fmd = NULL, *tmp;

        cfs_spin_lock(&fed->fed_lock);
        cfs_list_for_each_entry_safe(fmd, tmp, &fed->fed_mod_list, fmd_list) {
                cfs_list_del_init(&fmd->fmd_list);
                filter_fmd_put_nolock(fed, fmd);
        }
        cfs_spin_unlock(&fed->fed_lock);
}

static int filter_init_export(struct obd_export *exp)
{
        int rc;
        cfs_spin_lock_init(&exp->exp_filter_data.fed_lock);
        CFS_INIT_LIST_HEAD(&exp->exp_filter_data.fed_mod_list);

        cfs_spin_lock(&exp->exp_lock);
        exp->exp_connecting = 1;
        cfs_spin_unlock(&exp->exp_lock);
        rc = lut_client_alloc(exp);
        if (rc == 0)
                rc = ldlm_init_export(exp);

        return rc;
}

static int filter_free_server_data(struct obd_device_target *obt)
{
        lut_fini(NULL, obt->obt_lut);
        OBD_FREE_PTR(obt->obt_lut);
        return 0;
}

/* assumes caller is already in kernel ctxt */
int filter_update_server_data(struct obd_device *obd)
{
        struct file *filp = obd->u.obt.obt_rcvd_filp;
        struct lr_server_data *lsd = class_server_data(obd);
        loff_t off = 0;
        int rc;
        ENTRY;

        CDEBUG(D_INODE, "server uuid      : %s\n", lsd->lsd_uuid);
        CDEBUG(D_INODE, "server last_rcvd : "LPU64"\n",
               le64_to_cpu(lsd->lsd_last_transno));
        CDEBUG(D_INODE, "server last_mount: "LPU64"\n",
               le64_to_cpu(lsd->lsd_mount_count));

        rc = fsfilt_write_record(obd, filp, lsd, sizeof(*lsd), &off, 0);
        if (rc)
                CERROR("error writing lr_server_data: rc = %d\n", rc);

        RETURN(rc);
}

int filter_update_last_objid(struct obd_device *obd, obd_seq group,
                             int force_sync)
{
        struct filter_obd *filter = &obd->u.filter;
        __u64 tmp;
        loff_t off = 0;
        int rc;
        ENTRY;

        if (filter->fo_last_objid_files[group] == NULL) {
                CERROR("Object seq "LPU64" not fully setup; not updating "
                       "last_objid\n", group);
                RETURN(-EINVAL);
        }

        CDEBUG(D_INODE, "%s: server last_objid for "POSTID"\n",
               obd->obd_name, filter->fo_last_objids[group], group);

        tmp = cpu_to_le64(filter->fo_last_objids[group]);
        rc = fsfilt_write_record(obd, filter->fo_last_objid_files[group],
                                 &tmp, sizeof(tmp), &off, force_sync);
        if (rc)
                CERROR("error writing seq "LPU64" last objid: rc = %d\n",
                       group, rc);
        RETURN(rc);
}
extern int ost_handle(struct ptlrpc_request *req);
/* assumes caller has already in kernel ctxt */
static int filter_init_server_data(struct obd_device *obd, struct file * filp)
{
        struct filter_obd *filter = &obd->u.filter;
        struct lr_server_data *lsd;
        struct lsd_client_data *lcd = NULL;
        struct inode *inode = filp->f_dentry->d_inode;
        unsigned long last_rcvd_size = i_size_read(inode);
        struct lu_target *lut;
        __u64 mount_count;
        __u32 start_epoch;
        int cl_idx;
        loff_t off = 0;
        int rc;

        /* ensure padding in the struct is the correct size */
        CLASSERT (offsetof(struct lr_server_data, lsd_padding) +
                 sizeof(lsd->lsd_padding) == LR_SERVER_SIZE);
        CLASSERT (offsetof(struct lsd_client_data, lcd_padding) +
                 sizeof(lcd->lcd_padding) == LR_CLIENT_SIZE);

        /* allocate and initialize lu_target */
        OBD_ALLOC_PTR(lut);
        if (lut == NULL)
                RETURN(-ENOMEM);
        rc = lut_init(NULL, lut, obd, NULL);
        if (rc)
                GOTO(err_lut, rc);
        lsd = class_server_data(obd);
        if (last_rcvd_size == 0) {
                LCONSOLE_WARN("%s: new disk, initializing\n", obd->obd_name);

                memcpy(lsd->lsd_uuid, obd->obd_uuid.uuid,sizeof(lsd->lsd_uuid));
                lsd->lsd_last_transno = 0;
                mount_count = lsd->lsd_mount_count = 0;
                lsd->lsd_server_size = cpu_to_le32(LR_SERVER_SIZE);
                lsd->lsd_client_start = cpu_to_le32(LR_CLIENT_START);
                lsd->lsd_client_size = cpu_to_le16(LR_CLIENT_SIZE);
                lsd->lsd_subdir_count = cpu_to_le16(FILTER_SUBDIR_COUNT);
                filter->fo_subdir_count = FILTER_SUBDIR_COUNT;
                /* OBD_COMPAT_OST is set in filter_connect_internal when the
                 * MDS first connects and assigns the OST index number. */
                lsd->lsd_feature_incompat = cpu_to_le32(OBD_INCOMPAT_COMMON_LR|
                                                        OBD_INCOMPAT_OST);
        } else {
                rc = fsfilt_read_record(obd, filp, lsd, sizeof(*lsd), &off);
                if (rc) {
                        CDEBUG(D_INODE,"OBD filter: error reading %s: rc %d\n",
                               LAST_RCVD, rc);
                        GOTO(err_lut, rc);
                }
                if (strcmp(lsd->lsd_uuid, obd->obd_uuid.uuid) != 0) {
                        LCONSOLE_ERROR_MSG(0x134, "Trying to start OBD %s "
                                           "using the wrong disk %s. Were the "
                                           "/dev/ assignments rearranged?\n",
                                           obd->obd_uuid.uuid, lsd->lsd_uuid);
                        GOTO(err_lut, rc = -EINVAL);
                }
                mount_count = le64_to_cpu(lsd->lsd_mount_count);
                filter->fo_subdir_count = le16_to_cpu(lsd->lsd_subdir_count);
                /* COMPAT_146 */
                /* Assume old last_rcvd format unless I_C_LR is set */
                if (!(lsd->lsd_feature_incompat &
                      cpu_to_le32(OBD_INCOMPAT_COMMON_LR)))
                        lsd->lsd_last_transno = lsd->lsd_compat14;
                /* end COMPAT_146 */
                /* OBD_COMPAT_OST is set in filter_connect_internal when the
                 * MDS first connects and assigns the OST index number. */
                lsd->lsd_feature_incompat |= cpu_to_le32(OBD_INCOMPAT_COMMON_LR|
                                                         OBD_INCOMPAT_OST);
        }

        if (lsd->lsd_feature_incompat & ~cpu_to_le32(FILTER_INCOMPAT_SUPP)) {
                CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
                       obd->obd_name, le32_to_cpu(lsd->lsd_feature_incompat) &
                       ~FILTER_INCOMPAT_SUPP);
                GOTO(err_lut, rc = -EINVAL);
        }
        if (lsd->lsd_feature_rocompat & ~cpu_to_le32(FILTER_ROCOMPAT_SUPP)) {
                CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
                       obd->obd_name, le32_to_cpu(lsd->lsd_feature_rocompat) &
                       ~FILTER_ROCOMPAT_SUPP);
                /* Do something like remount filesystem read-only */
                GOTO(err_lut, rc = -EINVAL);
        }

        start_epoch = le32_to_cpu(lsd->lsd_start_epoch);

        CDEBUG(D_INODE, "%s: server start_epoch : %#x\n",
               obd->obd_name, start_epoch);
        CDEBUG(D_INODE, "%s: server last_transno : "LPX64"\n",
               obd->obd_name, le64_to_cpu(lsd->lsd_last_transno));
        CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
               obd->obd_name, mount_count + 1);
        CDEBUG(D_INODE, "%s: server data size: %u\n",
               obd->obd_name, le32_to_cpu(lsd->lsd_server_size));
        CDEBUG(D_INODE, "%s: per-client data start: %u\n",
               obd->obd_name, le32_to_cpu(lsd->lsd_client_start));
        CDEBUG(D_INODE, "%s: per-client data size: %u\n",
               obd->obd_name, le32_to_cpu(lsd->lsd_client_size));
        CDEBUG(D_INODE, "%s: server subdir_count: %u\n",
               obd->obd_name, le16_to_cpu(lsd->lsd_subdir_count));
        CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", obd->obd_name,
               last_rcvd_size <= le32_to_cpu(lsd->lsd_client_start) ? 0 :
               (last_rcvd_size - le32_to_cpu(lsd->lsd_client_start)) /
                le16_to_cpu(lsd->lsd_client_size));

        if (!obd->obd_replayable) {
                CWARN("%s: recovery support OFF\n", obd->obd_name);
                GOTO(out, rc = 0);
        }

        OBD_ALLOC_PTR(lcd);
        if (!lcd)
                GOTO(err_client, rc = -ENOMEM);

        for (cl_idx = 0, off = le32_to_cpu(lsd->lsd_client_start);
             off < last_rcvd_size; cl_idx++) {
                __u64 last_rcvd;
                struct obd_export *exp;
                struct filter_export_data *fed;

                /* Don't assume off is incremented properly by
                 * fsfilt_read_record(), in case sizeof(*lcd)
                 * isn't the same as lsd->lsd_client_size.  */
                off = le32_to_cpu(lsd->lsd_client_start) +
                        cl_idx * le16_to_cpu(lsd->lsd_client_size);
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

                CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                       " srv lr: "LPU64"\n", lcd->lcd_uuid, cl_idx,
                       last_rcvd, le64_to_cpu(lsd->lsd_last_transno));

                /* These exports are cleaned up by filter_disconnect(), so they
                 * need to be set up like real exports as filter_connect() does.
                 */
                exp = class_new_export(obd, (struct obd_uuid *)lcd->lcd_uuid);
                if (IS_ERR(exp)) {
                        if (PTR_ERR(exp) == -EALREADY) {
                                /* export already exists, zero out this one */
                                CERROR("Duplicate export %s!\n", lcd->lcd_uuid);
                                continue;
                        }
                        OBD_FREE_PTR(lcd);
                        GOTO(err_client, rc = PTR_ERR(exp));
                }

                fed = &exp->exp_filter_data;
                *fed->fed_ted.ted_lcd = *lcd;
                fed->fed_group = 0; /* will be assigned at connect */
                filter_export_stats_init(obd, exp, NULL);
                rc = filter_client_add(obd, exp, cl_idx);
                /* can't fail for existing client */
                LASSERTF(rc == 0, "rc = %d\n", rc);

                /* VBR: set export last committed */
                exp->exp_last_committed = last_rcvd;
                cfs_spin_lock(&exp->exp_lock);
                exp->exp_connecting = 0;
                exp->exp_in_recovery = 0;
                cfs_spin_unlock(&exp->exp_lock);
                obd->obd_max_recoverable_clients++;
                class_export_put(exp);

                if (last_rcvd > le64_to_cpu(lsd->lsd_last_transno))
                        lsd->lsd_last_transno = cpu_to_le64(last_rcvd);
        }
        OBD_FREE_PTR(lcd);

        obd->obd_last_committed = le64_to_cpu(lsd->lsd_last_transno);
out:
        obd->u.obt.obt_mount_count = mount_count + 1;
        lsd->lsd_mount_count = cpu_to_le64(obd->u.obt.obt_mount_count);

        /* save it, so mount count and last_transno is current */
        rc = filter_update_server_data(obd);
        if (rc)
                GOTO(err_client, rc);

        RETURN(0);

err_client:
        class_disconnect_exports(obd);
err_lut:
        filter_free_server_data(&obd->u.obt);
        RETURN(rc);
}

static int filter_cleanup_groups(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct file *filp;
        struct dentry *dentry;
        int i, j;
        ENTRY;

        if (filter->fo_dentry_O_groups != NULL) {
                for (i = 0; i < filter->fo_group_count; i++) {
                        dentry = filter->fo_dentry_O_groups[i];
                        if (dentry != NULL)
                                f_dput(dentry);
                }
                OBD_FREE(filter->fo_dentry_O_groups,
                         filter->fo_group_count *
                         sizeof(*filter->fo_dentry_O_groups));
                filter->fo_dentry_O_groups = NULL;
        }
        if (filter->fo_last_objid_files != NULL) {
                for (i = 0; i < filter->fo_group_count; i++) {
                        filp = filter->fo_last_objid_files[i];
                        if (filp != NULL)
                                filp_close(filp, 0);
                }
                OBD_FREE(filter->fo_last_objid_files,
                         filter->fo_group_count *
                         sizeof(*filter->fo_last_objid_files));
                filter->fo_last_objid_files = NULL;
        }
        if (filter->fo_dentry_O_sub != NULL) {
                for (i = 0; i < filter->fo_group_count; i++) {
                        for (j = 0; j < filter->fo_subdir_count; j++) {
                                dentry = filter->fo_dentry_O_sub[i].dentry[j];
                                if (dentry != NULL)
                                        f_dput(dentry);
                        }
                }
                OBD_FREE(filter->fo_dentry_O_sub,
                         filter->fo_group_count *
                         sizeof(*filter->fo_dentry_O_sub));
                filter->fo_dentry_O_sub = NULL;
        }
        if (filter->fo_last_objids != NULL) {
                OBD_FREE(filter->fo_last_objids,
                         filter->fo_group_count *
                         sizeof(*filter->fo_last_objids));
                filter->fo_last_objids = NULL;
        }
        if (filter->fo_dentry_O != NULL) {
                f_dput(filter->fo_dentry_O);
                filter->fo_dentry_O = NULL;
        }
        RETURN(0);
}

static int filter_update_last_group(struct obd_device *obd, int group)
{
        struct filter_obd *filter = &obd->u.filter;
        struct file *filp = NULL;
        int last_group = 0, rc;
        loff_t off = 0;
        ENTRY;

        if (group <= filter->fo_committed_group)
                RETURN(0);

        filp = filp_open("LAST_GROUP", O_RDWR, 0700);
        if (IS_ERR(filp)) {
                rc = PTR_ERR(filp);
                filp = NULL;
                CERROR("cannot open LAST_GROUP: rc = %d\n", rc);
                GOTO(cleanup, rc);
        }

        rc = fsfilt_read_record(obd, filp, &last_group, sizeof(__u32), &off);
        if (rc) {
                CDEBUG(D_INODE, "error reading LAST_GROUP: rc %d\n",rc);
                GOTO(cleanup, rc);
        }

        CDEBUG(D_INODE, "%s: previous %d, new %d\n",
               obd->obd_name, last_group, group);

        off = 0;
        last_group = group;
        /* must be sync: bXXXX */
        rc = fsfilt_write_record(obd, filp, &last_group, sizeof(__u32), &off, 1);
        if (rc) {
                CDEBUG(D_INODE, "error updating LAST_GROUP: rc %d\n", rc);
                GOTO(cleanup, rc);
        }

        filter->fo_committed_group = group;
cleanup:
        if (filp)
                filp_close(filp, 0);
        RETURN(rc);
}

static int filter_read_group_internal(struct obd_device *obd, int group,
                                      int create)
{
        struct filter_obd *filter = &obd->u.filter;
        __u64 *new_objids = NULL;
        struct filter_subdirs *new_subdirs = NULL, *tmp_subdirs = NULL;
        struct dentry **new_groups = NULL;
        struct file **new_files = NULL;
        struct dentry *dentry;
        struct file *filp;
        int old_count = filter->fo_group_count, rc, stage = 0, i;
        char name[25];
        __u64 last_objid;
        loff_t off = 0;
        int len = group + 1;

        snprintf(name, 24, "%d", group);
        name[24] = '\0';

        if (!create) {
                dentry = ll_lookup_one_len(name, filter->fo_dentry_O,
                                           strlen(name));
                if (IS_ERR(dentry)) {
                        CERROR("Cannot lookup expected object group %d: %ld\n",
                               group, PTR_ERR(dentry));
                        RETURN(PTR_ERR(dentry));
                }
        } else {
                dentry = simple_mkdir(filter->fo_dentry_O,
                                      obd->u.obt.obt_vfsmnt, name, 0700, 1);
                if (IS_ERR(dentry)) {
                        CERROR("cannot lookup/create O/%s: rc = %ld\n", name,
                               PTR_ERR(dentry));
                        RETURN(PTR_ERR(dentry));
                }
        }
        stage = 1;

        snprintf(name, 24, "O/%d/LAST_ID", group);
        name[24] = '\0';
        filp = filp_open(name, O_CREAT | O_RDWR, 0700);
        if (IS_ERR(filp)) {
                CERROR("cannot create %s: rc = %ld\n", name, PTR_ERR(filp));
                GOTO(cleanup, rc = PTR_ERR(filp));
        }
        stage = 2;

        rc = fsfilt_read_record(obd, filp, &last_objid, sizeof(__u64), &off);
        if (rc) {
                CDEBUG(D_INODE, "error reading %s: rc %d\n", name, rc);
                GOTO(cleanup, rc);
        }

        if (filter->fo_subdir_count && fid_seq_is_mdt(group)) {
                OBD_ALLOC(tmp_subdirs, sizeof(*tmp_subdirs));
                if (tmp_subdirs == NULL)
                        GOTO(cleanup, rc = -ENOMEM);
                stage = 3;

                for (i = 0; i < filter->fo_subdir_count; i++) {
                        char dir[20];
                        snprintf(dir, sizeof(dir), "d%u", i);

                        tmp_subdirs->dentry[i] = simple_mkdir(dentry,
                                                              obd->u.obt.obt_vfsmnt,
                                                              dir, 0700, 1);
                        if (IS_ERR(tmp_subdirs->dentry[i])) {
                                rc = PTR_ERR(tmp_subdirs->dentry[i]);
                                CERROR("can't lookup/create O/%d/%s: rc = %d\n",
                                       group, dir, rc);
                                GOTO(cleanup, rc);
                        }

                        CDEBUG(D_INODE, "got/created O/%d/%s: %p\n", group, dir,
                               tmp_subdirs->dentry[i]);
                }
        }

        /* 'group' is an index; we need an array of length 'group + 1' */
        if (group + 1 > old_count) {
                OBD_ALLOC(new_objids, len * sizeof(*new_objids));
                OBD_ALLOC(new_subdirs, len * sizeof(*new_subdirs));
                OBD_ALLOC(new_groups, len * sizeof(*new_groups));
                OBD_ALLOC(new_files, len * sizeof(*new_files));
                stage = 4;
                if (new_objids == NULL || new_subdirs == NULL ||
                    new_groups == NULL || new_files == NULL)
                        GOTO(cleanup, rc = -ENOMEM);

                if (old_count) {
                        memcpy(new_objids, filter->fo_last_objids,
                               old_count * sizeof(*new_objids));
                        memcpy(new_subdirs, filter->fo_dentry_O_sub,
                               old_count * sizeof(*new_subdirs));
                        memcpy(new_groups, filter->fo_dentry_O_groups,
                               old_count * sizeof(*new_groups));
                        memcpy(new_files, filter->fo_last_objid_files,
                               old_count * sizeof(*new_files));

                        OBD_FREE(filter->fo_last_objids,
                                 old_count * sizeof(*new_objids));
                        OBD_FREE(filter->fo_dentry_O_sub,
                                 old_count * sizeof(*new_subdirs));
                        OBD_FREE(filter->fo_dentry_O_groups,
                                 old_count * sizeof(*new_groups));
                        OBD_FREE(filter->fo_last_objid_files,
                                 old_count * sizeof(*new_files));
                }
                filter->fo_last_objids = new_objids;
                filter->fo_dentry_O_sub = new_subdirs;
                filter->fo_dentry_O_groups = new_groups;
                filter->fo_last_objid_files = new_files;
                filter->fo_group_count = len;
        }

        filter->fo_dentry_O_groups[group] = dentry;
        filter->fo_last_objid_files[group] = filp;
        if (filter->fo_subdir_count && fid_seq_is_mdt(group)) {
                filter->fo_dentry_O_sub[group] = *tmp_subdirs;
                OBD_FREE(tmp_subdirs, sizeof(*tmp_subdirs));
        }

        filter_update_last_group(obd, group);

        if (i_size_read(filp->f_dentry->d_inode) == 0) {
                filter->fo_last_objids[group] = FILTER_INIT_OBJID;
                rc = filter_update_last_objid(obd, group, 1);
                RETURN(rc);
        }

        filter->fo_last_objids[group] = le64_to_cpu(last_objid);
        CDEBUG(D_INODE, "%s: server last_objid group %d: "LPU64"\n",
               obd->obd_name, group, last_objid);
        RETURN(0);
 cleanup:
        switch (stage) {
        case 4:
                if (new_objids != NULL)
                        OBD_FREE(new_objids, len * sizeof(*new_objids));
                if (new_subdirs != NULL)
                        OBD_FREE(new_subdirs, len * sizeof(*new_subdirs));
                if (new_groups != NULL)
                        OBD_FREE(new_groups, len * sizeof(*new_groups));
                if (new_files != NULL)
                        OBD_FREE(new_files, len * sizeof(*new_files));
        case 3:
                if (filter->fo_subdir_count && fid_seq_is_mdt(group)) {
                        for (i = 0; i < filter->fo_subdir_count; i++) {
                                if (tmp_subdirs->dentry[i] != NULL)
                                        dput(tmp_subdirs->dentry[i]);
                        }
                        OBD_FREE(tmp_subdirs, sizeof(*tmp_subdirs));
                }
        case 2:
                filp_close(filp, 0);
        case 1:
                dput(dentry);
        }
        RETURN(rc);
}

static int filter_read_groups(struct obd_device *obd, int last_group,
                              int create)
{
        struct filter_obd *filter = &obd->u.filter;
        int old_count, group, rc = 0;

        cfs_down(&filter->fo_init_lock);
        old_count = filter->fo_group_count;
        for (group = old_count; group <= last_group; group++) {
                rc = filter_read_group_internal(obd, group, create);
                if (rc != 0)
                        break;
        }
        cfs_up(&filter->fo_init_lock);
        return rc;
}

/* FIXME: object groups */
static int filter_prep_groups(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct dentry *O_dentry;
        struct file *filp;
        int    last_group, rc = 0, cleanup_phase = 0;
        loff_t off = 0;
        ENTRY;

        O_dentry = simple_mkdir(cfs_fs_pwd(current->fs), obd->u.obt.obt_vfsmnt,
                                "O", 0700, 1);
        CDEBUG(D_INODE, "%s: got/created O: %p\n", obd->obd_name, O_dentry);
        if (IS_ERR(O_dentry)) {
                rc = PTR_ERR(O_dentry);
                CERROR("%s: cannot open/create O: rc = %d\n", obd->obd_name,rc);
                GOTO(cleanup, rc);
        }
        filter->fo_dentry_O = O_dentry;
        cleanup_phase = 1; /* O_dentry */

        /* we have to initialize all groups before first connections from
         * clients because they may send create/destroy for any group -bzzz */
        filp = filp_open("LAST_GROUP", O_CREAT | O_RDWR, 0700);
        if (IS_ERR(filp)) {
                CERROR("%s: cannot create LAST_GROUP: rc = %ld\n",
                       obd->obd_name, PTR_ERR(filp));
                GOTO(cleanup, rc = PTR_ERR(filp));
        }
        cleanup_phase = 2; /* filp */

        rc = fsfilt_read_record(obd, filp, &last_group, sizeof(__u32), &off);
        if (rc) {
                CERROR("%s: error reading LAST_GROUP: rc %d\n",
                       obd->obd_name, rc);
                GOTO(cleanup, rc);
        }

        if (off == 0)
                last_group = FID_SEQ_OST_MDT0;

        CDEBUG(D_INODE, "%s: initialize group %u (max %u)\n", obd->obd_name,
               FID_SEQ_OST_MDT0, last_group);
        filter->fo_committed_group = last_group;
        rc = filter_read_groups(obd, last_group, 1);
        if (rc)
                GOTO(cleanup, rc);

        filp_close(filp, 0);
        RETURN(0);

 cleanup:
        switch (cleanup_phase) {
        case 2:
                filp_close(filp, 0);
        case 1:
                filter_cleanup_groups(obd);
                f_dput(filter->fo_dentry_O);
                filter->fo_dentry_O = NULL;
        default:
                break;
        }
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
        obd->u.obt.obt_rcvd_filp = file;
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
        LASSERT(obd->u.obt.obt_lut);
        target_recovery_init(obd->u.obt.obt_lut, ost_handle);

        /* open and create health check io file*/
        file = filp_open(HEALTH_CHECK, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create %s rc = %d\n",
                       HEALTH_CHECK, rc);
                GOTO(err_server_data, rc);
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
                GOTO(err_health_check, rc);
out:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        return(rc);

err_health_check:
        if (filp_close(filter->fo_obt.obt_health_check_filp, 0))
                CERROR("can't close %s after error\n", HEALTH_CHECK);
        filter->fo_obt.obt_health_check_filp = NULL;
err_server_data:
        target_recovery_fini(obd);
        filter_free_server_data(&obd->u.obt);
err_filp:
        if (filp_close(obd->u.obt.obt_rcvd_filp, 0))
                CERROR("can't close %s after error\n", LAST_RCVD);
        obd->u.obt.obt_rcvd_filp = NULL;
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
        rc = filter_update_server_data(obd);
        if (rc)
                CERROR("error writing server data: rc = %d\n", rc);

        for (i = 0; i < filter->fo_group_count; i++) {
                rc = filter_update_last_objid(obd, i,
                                (i == filter->fo_group_count - 1));
                if (rc)
                        CERROR("error writing group %d lastobjid: rc = %d\n",
                               i, rc);
        }

        rc = filp_close(obd->u.obt.obt_rcvd_filp, 0);
        obd->u.obt.obt_rcvd_filp = NULL;
        if (rc)
                CERROR("error closing %s: rc = %d\n", LAST_RCVD, rc);

        rc = filp_close(filter->fo_obt.obt_health_check_filp, 0);
        filter->fo_obt.obt_health_check_filp = NULL;
        if (rc)
                CERROR("error closing %s: rc = %d\n", HEALTH_CHECK, rc);

        filter_cleanup_groups(obd);
        filter_free_server_data(&obd->u.obt);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        filter_free_capa_keys(filter);
        cleanup_capa_hash(filter->fo_capa_hash);
}

static void filter_set_last_id(struct filter_obd *filter,
                               obd_id id, obd_seq group)
{
        LASSERT(group <= filter->fo_group_count);

        cfs_spin_lock(&filter->fo_objidlock);
        filter->fo_last_objids[group] = id;
        cfs_spin_unlock(&filter->fo_objidlock);
}

obd_id filter_last_id(struct filter_obd *filter, obd_seq group)
{
        obd_id id;
        LASSERT(group <= filter->fo_group_count);
        LASSERT(filter->fo_last_objids != NULL);

        /* FIXME: object groups */
        cfs_spin_lock(&filter->fo_objidlock);
        id = filter->fo_last_objids[group];
        cfs_spin_unlock(&filter->fo_objidlock);
        return id;
}

static int filter_lock_dentry(struct obd_device *obd, struct dentry *dparent)
{
        LOCK_INODE_MUTEX_PARENT(dparent->d_inode);
        return 0;
}

/* We never dget the object parent, so DON'T dput it either */
struct dentry *filter_parent(struct obd_device *obd, obd_seq group, obd_id objid)
{
        struct filter_obd *filter = &obd->u.filter;
        struct filter_subdirs *subdirs;

        if (group >= filter->fo_group_count) /* FIXME: object groups */
                return ERR_PTR(-EBADF);

        if (!fid_seq_is_mdt(group) || filter->fo_subdir_count == 0)
                return filter->fo_dentry_O_groups[group];

        subdirs = &filter->fo_dentry_O_sub[group];
        return subdirs->dentry[objid & (filter->fo_subdir_count - 1)];
}

/* We never dget the object parent, so DON'T dput it either */
struct dentry *filter_parent_lock(struct obd_device *obd, obd_seq group,
                                  obd_id objid)
{
        unsigned long now = jiffies;
        struct dentry *dparent = filter_parent(obd, group, objid);
        int rc;

        if (IS_ERR(dparent))
                return dparent;
        if (dparent == NULL)
                return ERR_PTR(-ENOENT);

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
                                 obd_seq group, obd_id id)
{
        struct dentry *dparent = dir_dentry;
        struct dentry *dchild;
        char name[32];
        int len;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT) &&
            obd->u.filter.fo_destroys_in_progress == 0) {
                /* don't fail lookups for orphan recovery, it causes
                 * later LBUGs when objects still exist during precreate */
                CDEBUG(D_INFO, "*** cfs_fail_loc=%x ***\n",OBD_FAIL_OST_ENOENT);
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
                        CERROR("%s: error getting object "POSTID
                               " parent: rc %ld\n", obd->obd_name,
                               id, group, PTR_ERR(dparent));
                        RETURN(dparent);
                }
        }
        CDEBUG(D_INODE, "looking up object O/%.*s/%s\n",
               dparent->d_name.len, dparent->d_name.name, name);
        /* dparent is already locked here, so we cannot use ll_lookup_one_len() */
        dchild = lookup_one_len(name, dparent, len);
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
                                  obd_id group, struct lustre_handle *lockh)
{
        int flags = LDLM_AST_DISCARD_DATA, rc;
        struct ldlm_res_id res_id;
        ldlm_policy_data_t policy = { .l_extent = { 0, OBD_OBJECT_EOF } };
        ENTRY;

        osc_build_res_name(objid, group, &res_id);
        /* Tell the clients that the object is gone now and that they should
         * throw away any cached pages. */
        rc = ldlm_cli_enqueue_local(obd->obd_namespace, &res_id, LDLM_EXTENT,
                                    &policy, LCK_PW, &flags, ldlm_blocking_ast,
                                    ldlm_completion_ast, NULL, NULL, 0, NULL,
                                    lockh);
        if (rc != ELDLM_OK)
                lockh->cookie = 0;
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
        if ((dentry->d_inode->i_uid != cfs_curproc_fsuid() &&
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
                                   obd_seq group, struct dentry *dparent,
                                   struct dentry *dchild)
{
        struct inode *inode = dchild->d_inode;
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

        rc = filter_vfs_unlink(dparent->d_inode, dchild, obd->u.obt.obt_vfsmnt);
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

        cfs_list_for_each_entry(lck, &node->li_group, l_sl_policy) {
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
                        LDLM_LOCK_RELEASE(*v);
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
        CFS_LIST_HEAD(rpc_list);
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

        LASSERT(ns == ldlm_res_to_ns(res));
        lock_res(res);
        rc = policy(lock, &tmpflags, 0, &err, &rpc_list);
        check_res_locked(res);

        /* FIXME: we should change the policy function slightly, to not make
         * this list at all, since we just turn around and free it */
        while (!cfs_list_empty(&rpc_list)) {
                struct ldlm_lock *wlock =
                        cfs_list_entry(rpc_list.next, struct ldlm_lock,
                                       l_cp_ast);
                LASSERT((lock->l_flags & LDLM_FL_AST_SENT) == 0);
                LASSERT(lock->l_flags & LDLM_FL_CP_REQD);
                lock->l_flags &= ~LDLM_FL_CP_REQD;
                cfs_list_del_init(&wlock->l_cp_ast);
                LDLM_LOCK_RELEASE(wlock);
        }

        /* The lock met with no resistance; we're finished. */
        if (rc == LDLM_ITER_CONTINUE) {
                /* do not grant locks to the liblustre clients: they cannot
                 * handle ASTs robustly.  We need to do this while still
                 * holding lr_lock to avoid the lock remaining on the res_link
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
         * lr_lock guarantees that no new locks are granted, and,
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
                        ldlm_res_lvbo_update(res, NULL, 1);
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

        lock_res(res);
        *reply_lvb = *res_lvb;
        unlock_res(res);

 out:
        LDLM_LOCK_RELEASE(l);

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

static int filter_adapt_sptlrpc_conf(struct obd_device *obd, int initial)
{
        struct filter_obd       *filter = &obd->u.filter;
        struct sptlrpc_rule_set  tmp_rset;
        int                      rc;

        sptlrpc_rule_set_init(&tmp_rset);
        rc = sptlrpc_conf_target_get_rules(obd, &tmp_rset, initial);
        if (rc) {
                CERROR("obd %s: failed get sptlrpc rules: %d\n",
                       obd->obd_name, rc);
                return rc;
        }

        sptlrpc_target_update_exp_flavor(obd, &tmp_rset);

        cfs_write_lock(&filter->fo_sptlrpc_lock);
        sptlrpc_rule_set_free(&filter->fo_sptlrpc_rset);
        filter->fo_sptlrpc_rset = tmp_rset;
        cfs_write_unlock(&filter->fo_sptlrpc_lock);

        return 0;
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
int filter_common_setup(struct obd_device *obd, struct lustre_cfg* lcfg,
                        void *option)
{
        struct filter_obd *filter = &obd->u.filter;
        struct vfsmount *mnt;
        struct lustre_mount_info *lmi;
        struct obd_uuid uuid;
        __u8 *uuid_ptr;
        char *str, *label;
        char ns_name[48];
        struct request_queue *q;
        int rc, i;
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

                /* gets recovery timeouts from mount data */
                if (lsi->lsi_lmd && lsi->lsi_lmd->lmd_recovery_time_soft)
                        obd->obd_recovery_timeout =
                                lsi->lsi_lmd->lmd_recovery_time_soft;
                if (lsi->lsi_lmd && lsi->lsi_lmd->lmd_recovery_time_hard)
                        obd->obd_recovery_time_hard =
                                lsi->lsi_lmd->lmd_recovery_time_hard;
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

        obd->u.obt.obt_vfsmnt = mnt;
        obd->u.obt.obt_sb = mnt->mnt_sb;
        obd->u.obt.obt_magic = OBT_MAGIC;
        filter->fo_fstype = mnt->mnt_sb->s_type->name;
        CDEBUG(D_SUPER, "%s: mnt = %p\n", filter->fo_fstype, mnt);

        fsfilt_setup(obd, obd->u.obt.obt_sb);

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        obd->obd_lvfs_ctxt.cb_ops = filter_lvfs_ops;

        cfs_init_mutex(&filter->fo_init_lock);
        filter->fo_committed_group = 0;
        filter->fo_destroys_in_progress = 0;
        for (i = 0; i < 32; i++)
                cfs_sema_init(&filter->fo_create_locks[i], 1);

        cfs_spin_lock_init(&filter->fo_objidlock);
        CFS_INIT_LIST_HEAD(&filter->fo_export_list);
        cfs_sema_init(&filter->fo_alloc_lock, 1);
        init_brw_stats(&filter->fo_filter_stats);
        cfs_spin_lock_init(&filter->fo_flags_lock);
        filter->fo_read_cache = 1; /* enable read-only cache by default */
        filter->fo_writethrough_cache = 1; /* enable writethrough cache */
        filter->fo_readcache_max_filesize = FILTER_MAX_CACHE_SIZE;
        filter->fo_fmd_max_num = FILTER_FMD_MAX_NUM_DEFAULT;
        filter->fo_fmd_max_age = FILTER_FMD_MAX_AGE_DEFAULT;
        filter->fo_syncjournal = 0; /* Don't sync journals on i/o by default */
        filter_slc_set(filter); /* initialize sync on lock cancel */

        rc = filter_prep(obd);
        if (rc)
                GOTO(err_ops, rc);

        CFS_INIT_LIST_HEAD(&filter->fo_llog_list);
        cfs_spin_lock_init(&filter->fo_llog_list_lock);

        filter->fo_fl_oss_capa = 1;

        CFS_INIT_LIST_HEAD(&filter->fo_capa_keys);
        filter->fo_capa_hash = init_capa_hash();
        if (filter->fo_capa_hash == NULL)
                GOTO(err_post, rc = -ENOMEM);

        sprintf(ns_name, "filter-%s", obd->obd_uuid.uuid);
        obd->obd_namespace = ldlm_namespace_new(obd, ns_name,
                                                LDLM_NAMESPACE_SERVER,
                                                LDLM_NAMESPACE_GREEDY,
                                                LDLM_NS_TYPE_OST);
        if (obd->obd_namespace == NULL)
                GOTO(err_post, rc = -ENOMEM);
        obd->obd_namespace->ns_lvbp = obd;
        obd->obd_namespace->ns_lvbo = &filter_lvbo;
        ldlm_register_intent(obd->obd_namespace, filter_intent_policy);

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "filter_ldlm_cb_client", &obd->obd_ldlm_client);

        rc = obd_llog_init(obd, &obd->obd_olg, obd, NULL);
        if (rc) {
                CERROR("failed to setup llogging subsystems\n");
                GOTO(err_post, rc);
        }

        cfs_rwlock_init(&filter->fo_sptlrpc_lock);
        sptlrpc_rule_set_init(&filter->fo_sptlrpc_rset);
        /* do this after llog being initialized */
        filter_adapt_sptlrpc_conf(obd, 1);

        rc = lquota_setup(filter_quota_interface_ref, obd);
        if (rc)
                GOTO(err_post, rc);

        q = bdev_get_queue(mnt->mnt_sb->s_bdev);
        if (queue_max_sectors(q) < queue_max_hw_sectors(q) &&
            queue_max_sectors(q) < PTLRPC_MAX_BRW_SIZE >> 9)
                LCONSOLE_INFO("%s: underlying device %s should be tuned "
                              "for larger I/O requests: max_sectors = %u "
                              "could be up to max_hw_sectors=%u\n",
                              obd->obd_name, mnt->mnt_sb->s_id,
                              queue_max_sectors(q), queue_max_hw_sectors(q));

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
                              obd->obd_max_recoverable_clients,
                              (obd->obd_max_recoverable_clients == 1) ? "" : "s",
                              (obd->obd_max_recoverable_clients == 1) ? "s": "");


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

static int filter_setup(struct obd_device *obd, struct lustre_cfg* lcfg)
{
        struct lprocfs_static_vars lvars;
        cfs_proc_dir_entry_t *entry;
        unsigned long addr;
        struct page *page;
        int rc;
        ENTRY;

        CLASSERT(offsetof(struct obd_device, u.obt) ==
                 offsetof(struct obd_device, u.filter.fo_obt));

        if (!LUSTRE_CFG_BUFLEN(lcfg, 1) || !LUSTRE_CFG_BUFLEN(lcfg, 2))
                RETURN(-EINVAL);

        /* lprocfs must be setup before the filter so state can be safely added
         * to /proc incrementally as the filter is setup */
        lprocfs_filter_init_vars(&lvars);
        rc = lprocfs_obd_setup(obd, lvars.obd_vars);
        if (rc) {
                CERROR("%s: lprocfs_obd_setup failed: %d.\n",
                       obd->obd_name, rc);
                RETURN(rc);
        }

        rc = lprocfs_alloc_obd_stats(obd, LPROC_FILTER_LAST);
        if (rc) {
                CERROR("%s: lprocfs_alloc_obd_stats failed: %d.\n",
                       obd->obd_name, rc);
                GOTO(obd_cleanup, rc);
        }

        /* Init obdfilter private stats here */
        lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_READ_BYTES,
                             LPROCFS_CNTR_AVGMINMAX, "read_bytes", "bytes");
        lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_WRITE_BYTES,
                             LPROCFS_CNTR_AVGMINMAX, "write_bytes", "bytes");
        lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_GET_PAGE,
                             LPROCFS_CNTR_AVGMINMAX|LPROCFS_CNTR_STDDEV,
                             "get_page", "usec");
        lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_NO_PAGE,
                             LPROCFS_CNTR_AVGMINMAX, "get_page_failures", "num");
        lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_CACHE_ACCESS,
                             LPROCFS_CNTR_AVGMINMAX, "cache_access", "pages");
        lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_CACHE_HIT,
                             LPROCFS_CNTR_AVGMINMAX, "cache_hit", "pages");
        lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_CACHE_MISS,
                             LPROCFS_CNTR_AVGMINMAX, "cache_miss", "pages");

        rc = lproc_filter_attach_seqstat(obd);
        if (rc) {
                CERROR("%s: create seqstat failed: %d.\n", obd->obd_name, rc);
                GOTO(free_obd_stats, rc);
        }

        entry = lprocfs_register("exports", obd->obd_proc_entry, NULL, NULL);
        if (IS_ERR(entry)) {
                rc = PTR_ERR(entry);
                CERROR("%s: error %d setting up lprocfs for %s\n",
                       obd->obd_name, rc, "exports");
                GOTO(free_obd_stats, rc);
        }
        obd->obd_proc_exports_entry = entry;

        entry = lprocfs_add_simple(obd->obd_proc_exports_entry, "clear",
                                   lprocfs_nid_stats_clear_read,
                                   lprocfs_nid_stats_clear_write, obd, NULL);
        if (IS_ERR(entry)) {
                rc = PTR_ERR(entry);
                CERROR("%s: add proc entry 'clear' failed: %d.\n",
                       obd->obd_name, rc);
                GOTO(free_obd_stats, rc);
        }

        /* 2.6.9 selinux wants a full option page for do_kern_mount (bug6471) */
        OBD_PAGE_ALLOC(page, CFS_ALLOC_STD);
        if (!page)
                GOTO(remove_entry_clear, rc = -ENOMEM);
        addr = (unsigned long)cfs_page_address(page);
        clear_page((void *)addr);
        memcpy((void *)addr, lustre_cfg_buf(lcfg, 4),
               LUSTRE_CFG_BUFLEN(lcfg, 4));
        rc = filter_common_setup(obd, lcfg, (void *)addr);
        OBD_PAGE_FREE(page);
        if (rc) {
                CERROR("%s: filter_common_setup failed: %d.\n",
                       obd->obd_name, rc);
                GOTO(remove_entry_clear, rc);
        }

        RETURN(0);

remove_entry_clear:
        lprocfs_remove_proc_entry("clear", obd->obd_proc_exports_entry);
free_obd_stats:
        lprocfs_free_obd_stats(obd);
obd_cleanup:
        lprocfs_obd_cleanup(obd);
        return rc;
}

static struct llog_operations filter_mds_ost_repl_logops;

static struct llog_operations filter_size_orig_logops = {
        .lop_setup   = llog_obd_origin_setup,
        .lop_cleanup = llog_obd_origin_cleanup,
        .lop_add     = llog_obd_origin_add
};

static int filter_olg_fini(struct obd_llog_group *olg)
{
        struct llog_ctxt *ctxt;
        int rc = 0, rc2 = 0;
        ENTRY;

        ctxt = llog_group_get_ctxt(olg, LLOG_MDS_OST_REPL_CTXT);
        if (ctxt)
                rc = llog_cleanup(ctxt);

        ctxt = llog_group_get_ctxt(olg, LLOG_SIZE_ORIG_CTXT);
        if (ctxt) {
                rc2 = llog_cleanup(ctxt);
                if (!rc)
                        rc = rc2;
        }

        ctxt = llog_group_get_ctxt(olg, LLOG_CONFIG_ORIG_CTXT);
        if (ctxt) {
                rc2 = llog_cleanup(ctxt);
                if (!rc)
                        rc = rc2;
        }

        RETURN(rc);
}

static int
filter_olg_init(struct obd_device *obd, struct obd_llog_group *olg,
                struct obd_device *tgt)
{
        int rc;
        ENTRY;

        rc = llog_setup(obd, olg, LLOG_MDS_OST_REPL_CTXT, tgt, 0, NULL,
                        &filter_mds_ost_repl_logops);
        if (rc)
                GOTO(cleanup, rc);

        rc = llog_setup(obd, olg, LLOG_SIZE_ORIG_CTXT, tgt, 0, NULL,
                        &filter_size_orig_logops);
        if (rc)
                GOTO(cleanup, rc);
        EXIT;
cleanup:
        if (rc)
                filter_olg_fini(olg);
        return rc;
}

/**
 * Init the default olg, which is embeded in the obd_device, for filter.
 */
static int
filter_default_olg_init(struct obd_device *obd, struct obd_llog_group *olg,
                        struct obd_device *tgt)
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

        rc = filter_olg_init(obd, olg, tgt);
        if (rc)
                GOTO(cleanup_lcm, rc);

        rc = llog_setup(obd, olg, LLOG_CONFIG_ORIG_CTXT, tgt, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                GOTO(cleanup_olg, rc);

        ctxt = llog_group_get_ctxt(olg, LLOG_MDS_OST_REPL_CTXT);
        if (!ctxt) {
                CERROR("Can't get ctxt for %p:%x\n", olg,
                       LLOG_MDS_OST_REPL_CTXT);
                GOTO(cleanup_olg, rc = -ENODEV);
        }
        ctxt->loc_lcm = lcm_get(filter->fo_lcm);
        ctxt->llog_proc_cb = filter_recov_log_mds_ost_cb;
        llog_ctxt_put(ctxt);

        RETURN(0);
cleanup_olg:
        filter_olg_fini(olg);
cleanup_lcm:
        llog_recov_thread_fini(filter->fo_lcm, 1);
        filter->fo_lcm = NULL;
        return rc;
}

static int
filter_llog_init(struct obd_device *obd, struct obd_llog_group *olg,
                 struct obd_device *tgt, int *index)
{
        struct filter_obd *filter = &obd->u.filter;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        LASSERT(olg != NULL);
        if (olg == &obd->obd_olg)
                return filter_default_olg_init(obd, olg, tgt);

        LASSERT(filter->fo_lcm != NULL);
        rc = filter_olg_init(obd, olg, tgt);
        if (rc)
                RETURN(rc);
        ctxt = llog_group_get_ctxt(olg, LLOG_MDS_OST_REPL_CTXT);
        if (!ctxt) {
                CERROR("Can't get ctxt for %p:%x\n", olg,
                       LLOG_MDS_OST_REPL_CTXT);
                filter_olg_fini(olg);
                RETURN(-ENODEV);
        }
        ctxt->llog_proc_cb = filter_recov_log_mds_ost_cb;
        ctxt->loc_lcm = lcm_get(filter->fo_lcm);
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

static int filter_llog_finish(struct obd_device *obd, int count)
{
        struct filter_obd *filter = &obd->u.filter;
        struct llog_ctxt *ctxt;
        ENTRY;

        ctxt = llog_group_get_ctxt(&obd->obd_olg, LLOG_MDS_OST_REPL_CTXT);
        if (ctxt) {
                /*
                 * Make sure that no cached llcds left in recov_thread.
                 * We actually do sync in disconnect time, but disconnect
                 * may not come being marked rq_no_resend = 1.
                 */
		llog_sync(ctxt, NULL, OBD_LLOG_FL_EXIT);

                /*
                 * Balance class_import_get() in llog_receptor_accept().
                 * This is safe to do, as llog is already synchronized
                 * and its import may go.
                 */
                cfs_mutex_down(&ctxt->loc_sem);
                if (ctxt->loc_imp) {
                        class_import_put(ctxt->loc_imp);
                        ctxt->loc_imp = NULL;
                }

		if (filter->fo_lcm) {
			llog_recov_thread_fini(filter->fo_lcm, obd->obd_force);
			filter->fo_lcm = NULL;
		}

                cfs_mutex_up(&ctxt->loc_sem);
                llog_ctxt_put(ctxt);
        }

        RETURN(filter_olg_fini(&obd->obd_olg));
}

/**
 * Find the group llog according to group index in the llog group list.
 */
static struct obd_llog_group *
filter_find_olg_internal(struct filter_obd *filter, int group)
{
        struct obd_llog_group *olg;

        LASSERT_SPIN_LOCKED(&filter->fo_llog_list_lock);
        cfs_list_for_each_entry(olg, &filter->fo_llog_list, olg_list) {
                if (olg->olg_seq == group)
                        RETURN(olg);
        }
        RETURN(NULL);
}

/**
 * Find the group llog according to group index on the filter
 */
struct obd_llog_group *filter_find_olg(struct obd_device *obd, int group)
{
        struct obd_llog_group *olg = NULL;
        struct filter_obd *filter;

        filter = &obd->u.filter;

        if (group == FID_SEQ_LLOG)
                RETURN(&obd->obd_olg);

        cfs_spin_lock(&filter->fo_llog_list_lock);
        olg = filter_find_olg_internal(filter, group);
        cfs_spin_unlock(&filter->fo_llog_list_lock);

        RETURN(olg);
}
/**
 * Find the llog_group of the filter according to the group. If it can not
 * find, create the llog_group, which only happens when mds is being synced
 * with OST.
 */
struct obd_llog_group *filter_find_create_olg(struct obd_device *obd, int group)
{
        struct obd_llog_group *olg = NULL, *olg_new = NULL;
        struct filter_obd *filter;
        int rc;

        filter = &obd->u.filter;

        if (group == FID_SEQ_LLOG)
                RETURN(&obd->obd_olg);

        OBD_ALLOC_PTR(olg_new);
        if (olg_new == NULL)
               RETURN(ERR_PTR(-ENOMEM));

        cfs_spin_lock(&filter->fo_llog_list_lock);
        olg = filter_find_olg_internal(filter, group);
        if (olg) {
                if (olg->olg_initializing) {
                        GOTO(out_unlock, olg = ERR_PTR(-EBUSY));
                } else {
                        GOTO(out_unlock, olg);
                }
        } else {
                /* set as the newly allocated one */
                olg = olg_new;
                olg_new = NULL;
        }

        llog_group_init(olg, group);
        cfs_list_add(&olg->olg_list, &filter->fo_llog_list);
        olg->olg_initializing = 1;
        cfs_spin_unlock(&filter->fo_llog_list_lock);

        rc = obd_llog_init(obd, olg, obd, NULL);
        if (rc) {
               cfs_spin_lock(&filter->fo_llog_list_lock);
               cfs_list_del(&olg->olg_list);
               cfs_spin_unlock(&filter->fo_llog_list_lock);
               OBD_FREE_PTR(olg);
               GOTO(out, olg = ERR_PTR(-ENOMEM));
        }
        cfs_spin_lock(&filter->fo_llog_list_lock);
        olg->olg_initializing = 0;
        cfs_spin_unlock(&filter->fo_llog_list_lock);
        CDEBUG(D_OTHER, "%s: new llog group %u (0x%p)\n",
              obd->obd_name, group, olg);
out:
        RETURN(olg);

out_unlock:
        cfs_spin_unlock(&filter->fo_llog_list_lock);
        if (olg_new)
               OBD_FREE_PTR(olg_new);
        goto out;
}

static int filter_llog_connect(struct obd_export *exp,
                               struct llogd_conn_body *body)
{
        struct obd_device *obd = exp->exp_obd;
        struct llog_ctxt *ctxt;
        struct obd_llog_group *olg;
        int rc;
        ENTRY;

        CDEBUG(D_OTHER, "%s: LLog connect for: "LPX64"/"LPX64":%x\n",
               obd->obd_name, body->lgdc_logid.lgl_oid,
               body->lgdc_logid.lgl_oseq, body->lgdc_logid.lgl_ogen);

        olg = filter_find_olg(obd, body->lgdc_logid.lgl_oseq);
        if (!olg) {
                CERROR(" %s: can not find olg of group %d\n",
                       obd->obd_name, (int)body->lgdc_logid.lgl_oseq);
                RETURN(-ENOENT);
        }
        llog_group_set_export(olg, exp);

        ctxt = llog_group_get_ctxt(olg, body->lgdc_ctxt_idx);
        LASSERTF(ctxt != NULL, "ctxt is not null, ctxt idx %d \n",
                 body->lgdc_ctxt_idx);

        CDEBUG(D_HA, "%s: Recovery from log "LPX64"/"LPX64":%x\n",
               obd->obd_name, body->lgdc_logid.lgl_oid,
               body->lgdc_logid.lgl_oseq, body->lgdc_logid.lgl_ogen);

        cfs_spin_lock(&obd->u.filter.fo_flags_lock);
        obd->u.filter.fo_mds_ost_sync = 1;
        cfs_spin_unlock(&obd->u.filter.fo_flags_lock);
        rc = llog_connect(ctxt, &body->lgdc_logid,
                          &body->lgdc_gen, NULL);
        llog_ctxt_put(ctxt);
        if (rc != 0)
                CERROR("failed to connect rc %d idx %d\n", rc,
                                body->lgdc_ctxt_idx);

        RETURN(rc);
}

static int filter_llog_preclean(struct obd_device *obd)
{
        struct obd_llog_group *olg, *tmp;
        struct filter_obd *filter;
        cfs_list_t  remove_list;
        int rc = 0;
        ENTRY;

        rc = obd_llog_finish(obd, 0);
        if (rc)
                CERROR("failed to cleanup llogging subsystem\n");

        filter = &obd->u.filter;
        CFS_INIT_LIST_HEAD(&remove_list);

        cfs_spin_lock(&filter->fo_llog_list_lock);
        while (!cfs_list_empty(&filter->fo_llog_list)) {
                olg = cfs_list_entry(filter->fo_llog_list.next,
                                     struct obd_llog_group, olg_list);
                cfs_list_del(&olg->olg_list);
                cfs_list_add(&olg->olg_list, &remove_list);
        }
        cfs_spin_unlock(&filter->fo_llog_list_lock);

        cfs_list_for_each_entry_safe(olg, tmp, &remove_list, olg_list) {
                cfs_list_del_init(&olg->olg_list);
                rc = filter_olg_fini(olg);
                if (rc)
                        CERROR("failed to cleanup llogging subsystem for %u\n",
                               olg->olg_seq);
                OBD_FREE_PTR(olg);
        }

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
                /* Stop recovery before namespace cleanup. */
                target_recovery_fini(obd);

                obd_exports_barrier(obd);
                obd_zombie_barrier();

                rc = filter_llog_preclean(obd);
                lprocfs_remove_proc_entry("clear", obd->obd_proc_exports_entry);
                lprocfs_free_per_client_stats(obd);
                lprocfs_obd_cleanup(obd);
                lprocfs_free_obd_stats(obd);
                lquota_cleanup(filter_quota_interface_ref, obd);
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

        ldlm_namespace_free(obd->obd_namespace, NULL, obd->obd_force);
        obd->obd_namespace = NULL;

        sptlrpc_rule_set_free(&filter->fo_sptlrpc_rset);

        if (obd->u.obt.obt_sb == NULL)
                RETURN(0);

        filter_post(obd);

        ll_vfs_dq_off(obd->u.obt.obt_sb, 0);
        shrink_dcache_sb(obd->u.obt.obt_sb);

        server_put_mount(obd->obd_name, obd->u.obt.obt_vfsmnt);
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
        struct filter_export_data *fed = &exp->exp_filter_data;

        if (!data)
                RETURN(0);

        CDEBUG(D_RPCTRACE, "%s: cli %s/%p ocd_connect_flags: "LPX64
               " ocd_version: %x ocd_grant: %d ocd_index: %u\n",
               exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
               data->ocd_connect_flags, data->ocd_version,
               data->ocd_grant, data->ocd_index);

        if (fed->fed_group != 0 && fed->fed_group != data->ocd_group) {
                CWARN("!!! This export (nid %s) used object group %d "
                       "earlier; now it's trying to use group %d!  This could "
                       "be a bug in the MDS. Please report to "
                       "http://bugs.whamcloud.com/\n",
                       obd_export_nid2str(exp), fed->fed_group,data->ocd_group);
                RETURN(-EPROTO);
        }
        fed->fed_group = data->ocd_group;

        data->ocd_connect_flags &= OST_CONNECT_SUPPORTED;
        exp->exp_connect_flags = data->ocd_connect_flags;
        data->ocd_version = LUSTRE_VERSION_CODE;

        /* Kindly make sure the SKIP_ORPHAN flag is from MDS. */
        if (data->ocd_connect_flags & OBD_CONNECT_MDS)
                CDEBUG(D_HA, "%s: Received MDS connection for group %u\n",
                       exp->exp_obd->obd_name, data->ocd_group);
        else if (data->ocd_connect_flags & OBD_CONNECT_SKIP_ORPHAN)
                RETURN(-EPROTO);

        if (exp->exp_connect_flags & OBD_CONNECT_GRANT) {
                struct filter_obd *filter = &exp->exp_obd->u.filter;
                obd_size left, want;

                cfs_spin_lock(&exp->exp_obd->obd_osfs_lock);
                left = filter_grant_space_left(exp);
                want = data->ocd_grant;
                filter_grant(exp, fed->fed_grant, want, left, (reconnect == 0));
                data->ocd_grant = fed->fed_grant;
                cfs_spin_unlock(&exp->exp_obd->obd_osfs_lock);

                CDEBUG(D_CACHE, "%s: cli %s/%p ocd_grant: %d want: "
                       LPU64" left: "LPU64"\n", exp->exp_obd->obd_name,
                       exp->exp_client_uuid.uuid, exp,
                       data->ocd_grant, want, left);

                filter->fo_tot_granted_clients ++;
        }

        if (data->ocd_connect_flags & OBD_CONNECT_INDEX) {
                struct lr_server_data *lsd = class_server_data(exp->exp_obd);
                int index = le32_to_cpu(lsd->lsd_ost_index);

                if (!(lsd->lsd_feature_compat &
                      cpu_to_le32(OBD_COMPAT_OST))) {
                        /* this will only happen on the first connect */
                        lsd->lsd_ost_index = cpu_to_le32(data->ocd_index);
                        lsd->lsd_feature_compat |= cpu_to_le32(OBD_COMPAT_OST);
                        /* sync is not needed here as filter_client_add will
                         * set exp_need_sync flag */
                        filter_update_server_data(exp->exp_obd);
                } else if (index != data->ocd_index) {
                        LCONSOLE_ERROR_MSG(0x136, "Connection from %s to index"
                                           " %u doesn't match actual OST index"
                                           " %u in last_rcvd file, bad "
                                           "configuration?\n",
                                           obd_export_nid2str(exp), index,
                                           data->ocd_index);
                        RETURN(-EBADF);
                }
                /* FIXME: Do the same with the MDS UUID and lsd_peeruuid.
                 * FIXME: We don't strictly need the COMPAT flag for that,
                 * FIXME: as lsd_peeruuid[0] will tell us if that is set.
                 * FIXME: We needed it for the index, as index 0 is valid. */
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_SIZE)) {
                data->ocd_brw_size = 65536;
        } else if (data->ocd_connect_flags & OBD_CONNECT_BRW_SIZE) {
                data->ocd_brw_size = min(data->ocd_brw_size,
                               (__u32)(PTLRPC_MAX_BRW_PAGES << CFS_PAGE_SHIFT));
                if (data->ocd_brw_size == 0) {
                        CERROR("%s: cli %s/%p ocd_connect_flags: "LPX64
                               " ocd_version: %x ocd_grant: %d ocd_index: %u "
                               "ocd_brw_size is unexpectedly zero, "
                               "network data corruption?"
                               "Refusing connection of this client\n",
                                exp->exp_obd->obd_name,
                                exp->exp_client_uuid.uuid,
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

        if (data->ocd_connect_flags & OBD_CONNECT_MAXBYTES)
                data->ocd_maxbytes = exp->exp_obd->u.obt.obt_sb->s_maxbytes;

        RETURN(0);
}

static int filter_reconnect(const struct lu_env *env,
                            struct obd_export *exp, struct obd_device *obd,
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

static int filter_connect(const struct lu_env *env,
                          struct obd_export **exp, struct obd_device *obd,
                          struct obd_uuid *cluuid,
                          struct obd_connect_data *data, void *localdata)
{
        struct lvfs_run_ctxt saved;
        struct lustre_handle conn = { 0 };
        struct obd_export *lexp;
        int rc;
        ENTRY;

        if (exp == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        rc = class_connect(&conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        lexp = class_conn2export(&conn);
        LASSERT(lexp != NULL);

        rc = filter_connect_internal(lexp, data, 0);
        if (rc)
                GOTO(cleanup, rc);

        filter_export_stats_init(obd, lexp, localdata);
        if (obd->obd_replayable) {
                struct lsd_client_data *lcd = lexp->exp_target_data.ted_lcd;
                LASSERT(lcd);
                memcpy(lcd->lcd_uuid, cluuid, sizeof(lcd->lcd_uuid));
                rc = filter_client_add(obd, lexp, -1);
                if (rc)
                        GOTO(cleanup, rc);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = filter_read_groups(obd, data->ocd_group, 1);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (rc != 0) {
                CERROR("can't read group %u\n", data->ocd_group);
                GOTO(cleanup, rc);
        }

        GOTO(cleanup, rc);

cleanup:
        if (rc) {
                class_disconnect(lexp);
                *exp = NULL;
        } else {
                *exp = lexp;
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

        if (cfs_list_empty(&obd->obd_exports))
                return;

        /* We don't want to do this for large machines that do lots of
           mounts or unmounts.  It burns... */
        if (obd->obd_num_exports > 100)
                return;

        cfs_spin_lock(&obd->obd_osfs_lock);
        cfs_spin_lock(&obd->obd_dev_lock);
        cfs_list_for_each_entry(exp, &obd->obd_exports, exp_obd_chain) {
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
        cfs_spin_unlock(&obd->obd_dev_lock);
        cfs_spin_unlock(&obd->obd_osfs_lock);

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

        cfs_spin_lock(&obd->obd_osfs_lock);
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

        cfs_spin_unlock(&obd->obd_osfs_lock);
}

static int filter_destroy_export(struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        ENTRY;

        if (fed->fed_pending)
                CERROR("%s: cli %s/%p has %lu pending on destroyed export\n",
                       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
                       exp, fed->fed_pending);

        lquota_clearinfo(filter_quota_interface_ref, exp, exp->exp_obd);

        target_destroy_export(exp);
        ldlm_destroy_export(exp);
        lut_client_free(exp);

        if (obd_uuid_equals(&exp->exp_client_uuid, &exp->exp_obd->obd_uuid))
                RETURN(0);

        if (!exp->exp_obd->obd_replayable)
                fsfilt_sync(exp->exp_obd, exp->exp_obd->u.obt.obt_sb);

        filter_grant_discard(exp);
        filter_fmd_cleanup(exp);

        if (exp->exp_connect_flags & OBD_CONNECT_GRANT_SHRINK) {
                struct filter_obd *filter = &exp->exp_obd->u.filter;
                if (filter->fo_tot_granted_clients > 0)
                        filter->fo_tot_granted_clients --;
        }

        if (!(exp->exp_flags & OBD_OPT_FORCE))
                filter_grant_sanity_check(exp->exp_obd, __func__);

        RETURN(0);
}

static void filter_sync_llogs(struct obd_device *obd, struct obd_export *dexp)
{
        struct obd_llog_group *olg_min, *olg;
        struct filter_obd *filter;
        int worked = -1, group;
        struct llog_ctxt *ctxt;
        ENTRY;

        filter = &obd->u.filter;

        /* we can't sync log holding spinlock. also, we do not want to get
         * into livelock. so we do following: loop over MDS's exports in
         * group order and skip already synced llogs -bzzz */
        do {
                /* look for group with min. number, but > worked */
                olg_min = NULL;
                group = 1 << 30;
                cfs_spin_lock(&filter->fo_llog_list_lock);
                cfs_list_for_each_entry(olg, &filter->fo_llog_list, olg_list) {
                        if (olg->olg_seq <= worked) {
                                /* this group is already synced */
                                continue;
                        }
                        if (group < olg->olg_seq) {
                                /* we have group with smaller number to sync */
                                continue;
                        }
                        /* store current minimal group */
                        olg_min = olg;
                        group = olg->olg_seq;
                }
                cfs_spin_unlock(&filter->fo_llog_list_lock);

                if (olg_min == NULL)
                        break;

                worked = olg_min->olg_seq;
                if (olg_min->olg_exp &&
                    (dexp == olg_min->olg_exp || dexp == NULL)) {
                        int err;
                        ctxt = llog_group_get_ctxt(olg_min,
                                                   LLOG_MDS_OST_REPL_CTXT);
                        if (ctxt) {
				err = llog_sync(ctxt, olg_min->olg_exp, 0);
                                llog_ctxt_put(ctxt);
                                if (err) {
                                        CERROR("error flushing logs to MDS: "
                                               "rc %d\n", err);
                                }
                        }
                }
        } while (olg_min != NULL);
}

/* Also incredibly similar to mds_disconnect */
static int filter_disconnect(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        if (!(exp->exp_flags & OBD_OPT_FORCE))
                filter_grant_sanity_check(obd, __func__);
        filter_grant_discard(exp);

        /* Flush any remaining cancel messages out to the target */
        filter_sync_llogs(obd, exp);

        lquota_clearinfo(filter_quota_interface_ref, exp, exp->exp_obd);

        rc = server_disconnect_export(exp);

        /* Do not erase record for recoverable client. */
        if (obd->obd_replayable && (!obd->obd_fail || exp->exp_failed))
                filter_client_del(exp);
        else
                fsfilt_sync(obd, obd->u.obt.obt_sb);

        class_export_put(exp);
        RETURN(rc);
}

/* reverse import is changed, sync all cancels */
static void filter_revimp_update(struct obd_export *exp)
{
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        /* flush any remaining cancel messages out to the target */
        filter_sync_llogs(exp->exp_obd, exp);
        class_export_put(exp);
        EXIT;
}

static int filter_ping(struct obd_export *exp)
{
        filter_fmd_expire(exp);
        return 0;
}

struct dentry *__filter_oa2dentry(struct obd_device *obd, struct ost_id *ostid,
                                  const char *what, int quiet)
{
        struct dentry *dchild = NULL;

        dchild = filter_fid2dentry(obd, NULL,  ostid->oi_seq, ostid->oi_id);

        if (IS_ERR(dchild)) {
                CERROR("%s error looking up object: "POSTID"\n",
                       what, ostid->oi_id, ostid->oi_seq);
                RETURN(dchild);
        }

        if (dchild->d_inode == NULL) {
                if (!quiet)
                        CERROR("%s: %s on non-existent object: "POSTID" \n",
                               obd->obd_name, what, ostid->oi_id,ostid->oi_seq);
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

        rc = filter_auth_capa(exp, NULL, oinfo->oi_oa->o_seq,
                              oinfo_capa(oinfo), CAPA_OPC_META_READ);
        if (rc)
                RETURN(rc);

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client export %p\n", exp);
                RETURN(-EINVAL);
        }

        dentry = filter_oa2dentry(obd, &oinfo->oi_oa->o_oi);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        /* Limit the valid bits in the return data to what we actually use */
        oinfo->oi_oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oinfo->oi_oa, dentry->d_inode, NULL, FILTER_VALID_FLAGS);

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
                        oa->o_seq = 0;
                /* packing fid and converting it to LE for storing into EA.
                 * Here ->o_stripe_idx should be filled by LOV and rest of
                 * fields - by client. */
                ff.ff_parent.f_seq = cpu_to_le64(oa->o_parent_seq);
                ff.ff_parent.f_oid = cpu_to_le32(oa->o_parent_oid);
                /* XXX: we are ignoring o_parent_ver here, since this should
                 *      be the same for all objects in this fileset. */
                ff.ff_parent.f_ver = cpu_to_le32(oa->o_stripe_idx);
                ff.ff_objid = cpu_to_le64(oa->o_id);
                ff.ff_seq = cpu_to_le64(oa->o_seq);

                CDEBUG(D_INODE, "storing filter fid EA (parent "DFID" "
                       LPU64"/"LPU64")\n", PFID(&ff.ff_parent), oa->o_id,
                       oa->o_seq);

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
                unsigned long now = jiffies;
                /* Filter truncates and writes are serialized by
                 * i_alloc_sem, see the comment in
                 * filter_preprw_write.*/
                if (ia_valid & ATTR_SIZE)
                        down_write(&inode->i_alloc_sem);
                LOCK_INODE_MUTEX(inode);
                fsfilt_check_slow(exp->exp_obd, now, "i_alloc_sem and i_mutex");
                old_size = i_size_read(inode);
        }

        /* VBR: version recovery check */
        rc = filter_version_get_check(exp, oti, inode);
        if (rc)
                GOTO(out_unlock, rc);

        /* Let's pin the last page so that ldiskfs_truncate
         * should not start GFP_FS allocation. */
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

        /* Update inode version only if data has changed => size has changed */
        rc = filter_finish_transno(exp, ia_valid & ATTR_SIZE ? inode : NULL,
                                   oti, rc, sync);

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
                int rc2 = lquota_adjust(filter_quota_interface_ref,
                                        exp->exp_obd, cur_ids,
                                        orig_ids, rc, FSFILT_OP_SETATTR);
                CDEBUG(rc2 ? D_ERROR : D_QUOTA,
                       "filter adjust qunit. (rc:%d)\n", rc2);
        }
        return rc;
}

/* this is called from filter_truncate() until we have filter_punch() */
int filter_setattr(struct obd_export *exp, struct obd_info *oinfo,
                   struct obd_trans_info *oti)
{
        struct obdo *oa = oinfo->oi_oa;
        struct lustre_capa *capa = oinfo_capa(oinfo);
        struct ldlm_res_id res_id;
        struct filter_mod_data *fmd;
        struct lvfs_run_ctxt saved;
        struct filter_obd *filter;
        struct ldlm_resource *res;
        struct dentry *dentry;
        __u64 opc = CAPA_OPC_META_WRITE;
        int rc;
        ENTRY;

        if (oa->o_valid & OBD_FL_TRUNC)
                opc |= CAPA_OPC_OSS_TRUNC;

        rc = filter_auth_capa(exp, NULL, oa->o_seq, capa, opc);
        if (rc)
                RETURN(rc);

        if (oa->o_valid & (OBD_MD_FLUID | OBD_MD_FLGID)) {
                rc = filter_capa_fixoa(exp, oa, oa->o_seq, capa);
                if (rc)
                        RETURN(rc);
        }

        osc_build_res_name(oa->o_id, oa->o_seq, &res_id);
        /* This would be very bad - accidentally truncating a file when
         * changing the time or similar - bug 12203. */
        if (oa->o_valid & OBD_MD_FLSIZE &&
            oinfo->oi_policy.l_extent.end != OBD_OBJECT_EOF) {
                static char mdsinum[48];

                if (oa->o_valid & OBD_MD_FLFID)
                        snprintf(mdsinum, sizeof(mdsinum) - 1, " of inode "DFID,
                                 oa->o_parent_seq, oa->o_parent_oid,
                                 oa->o_parent_ver);
                else
                        mdsinum[0] = '\0';

                CERROR("%s: setattr from %s trying to truncate objid "POSTID
                       "%s\n", exp->exp_obd->obd_name, obd_export_nid2str(exp),
                       oa->o_id, oa->o_seq, mdsinum);
                RETURN(-EPERM);
        }

        dentry = __filter_oa2dentry(exp->exp_obd, &oinfo->oi_oa->o_oi, __func__, 1);
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
        if (oa->o_valid &
            (OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME)) {
                unsigned long now = jiffies;
                down_write(&dentry->d_inode->i_alloc_sem);
                fsfilt_check_slow(exp->exp_obd, now, "i_alloc_sem");
                fmd = filter_fmd_get(exp, oa->o_id, oa->o_seq);
                if (fmd && fmd->fmd_mactime_xid < oti->oti_xid)
                        fmd->fmd_mactime_xid = oti->oti_xid;
                filter_fmd_put(exp, fmd);
                up_write(&dentry->d_inode->i_alloc_sem);
        }

        /* setting objects attributes (including owner/group) */
        rc = filter_setattr_internal(exp, dentry, oa, oti);
        if (rc)
                GOTO(out_unlock, rc);

        res = ldlm_resource_get(exp->exp_obd->obd_namespace, NULL,
                                &res_id, LDLM_EXTENT, 0);

        if (res != NULL) {
                LDLM_RESOURCE_ADDREF(res);
                rc = ldlm_res_lvbo_update(res, NULL, 0);
                LDLM_RESOURCE_DELREF(res);
                ldlm_resource_putref(res);
        }

        oa->o_valid = OBD_MD_FLID;

        /* Quota release need uid/gid info */
        obdo_from_inode(oa, dentry->d_inode, NULL,
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

        (*lsmp)->lsm_maxbytes = exp->exp_obd->u.obt.obt_sb->s_maxbytes;

        RETURN(lsm_size);
}

/* caller must hold fo_create_locks[oa->o_seq] */
static int filter_destroy_precreated(struct obd_export *exp, struct obdo *oa,
                                     struct filter_obd *filter)
{
        struct obdo doa = { 0 }; /* XXX obdo on stack */
        obd_id last, id;
        int rc = 0;
        int skip_orphan;
        ENTRY;

        LASSERT(down_trylock(&filter->fo_create_locks[oa->o_seq]) != 0);

        memset(&doa, 0, sizeof(doa));

        doa.o_valid |= OBD_MD_FLGROUP;
        doa.o_seq = oa->o_seq;
        doa.o_mode = S_IFREG;

        if (!cfs_test_bit(doa.o_seq, &filter->fo_destroys_in_progress)) {
                CERROR("%s:["LPU64"] destroys_in_progress already cleared\n",
                       exp->exp_obd->obd_name, doa.o_seq);
                RETURN(0);
        }

        last = filter_last_id(filter, doa.o_seq);

        skip_orphan = !!(exp->exp_connect_flags & OBD_CONNECT_SKIP_ORPHAN);

        CDEBUG(D_HA, "%s: deleting orphan objects from "LPU64" to "LPU64"%s\n",
               exp->exp_obd->obd_name, oa->o_id + 1, last,
               skip_orphan ? ", orphan objids won't be reused any more." : ".");

        for (id = last; id > oa->o_id; id--) {
                doa.o_id = id;
                rc = filter_destroy(exp, &doa, NULL, NULL, NULL, NULL);
                if (rc && rc != -ENOENT) /* this is pretty fatal... */
                        CEMERG("error destroying precreate objid "LPU64": %d\n",
                               id, rc);

                /* update last_id on disk periodically so that if we restart
                 * we don't need to re-scan all of the just-deleted objects. */
                if ((id & 511) == 0 && !skip_orphan) {
                        filter_set_last_id(filter, id - 1, doa.o_seq);
                        filter_update_last_objid(exp->exp_obd, doa.o_seq, 0);
                }
        }

        CDEBUG(D_HA, "%s: after destroy: set last_objids["LPU64"] = "LPU64"\n",
               exp->exp_obd->obd_name, doa.o_seq, oa->o_id);

        if (!skip_orphan) {
                filter_set_last_id(filter, id, doa.o_seq);
                rc = filter_update_last_objid(exp->exp_obd, doa.o_seq, 1);
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
        cfs_clear_bit(doa.o_seq, &filter->fo_destroys_in_progress);

        RETURN(rc);
}

static int filter_precreate(struct obd_device *obd, struct obdo *oa,
                            obd_seq group, int *num);
/* returns a negative error or a nonnegative number of files to create */
static int filter_handle_precreate(struct obd_export *exp, struct obdo *oa,
                                   obd_seq group, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        int diff, rc;
        ENTRY;

        /* delete orphans request */
        if ((oa->o_valid & OBD_MD_FLFLAGS) && (oa->o_flags & OBD_FL_DELORPHAN)){
                obd_id last = filter_last_id(filter, group);

                if (oti->oti_conn_cnt < exp->exp_conn_cnt) {
                        CERROR("%s: dropping old orphan cleanup request\n",
                               obd->obd_name);
                        RETURN(0);
                }
                /* This causes inflight precreates to abort and drop lock */
                cfs_set_bit(group, &filter->fo_destroys_in_progress);
                cfs_down(&filter->fo_create_locks[group]);
                if (!cfs_test_bit(group, &filter->fo_destroys_in_progress)) {
                        CERROR("%s:["LPU64"] destroys_in_progress already cleared\n",
                               exp->exp_obd->obd_name, group);
                        cfs_up(&filter->fo_create_locks[group]);
                        RETURN(0);
                }
                diff = oa->o_id - last;
                CDEBUG(D_HA, "filter_last_id() = "LPU64" -> diff = %d\n",
                       last, diff);

                if (-diff > (OST_MAX_PRECREATE * 3) / 2) {
                        CERROR("%s: ignoring bogus orphan destroy request: "
                               "obdid "LPU64" last_id "LPU64"\n", obd->obd_name,
                               oa->o_id, last);
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
                        /* XXX: Used by MDS for the first time! */
                        cfs_clear_bit(group, &filter->fo_destroys_in_progress);
                }
        } else {
                cfs_down(&filter->fo_create_locks[group]);
                if (oti->oti_conn_cnt < exp->exp_conn_cnt) {
                        CERROR("%s: dropping old precreate request\n",
                               obd->obd_name);
                        GOTO(out, rc = 0);
                }
                /* only precreate if group == 0 and o_id is specfied */
                if (!fid_seq_is_mdt(group) || oa->o_id == 0)
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
                oa->o_seq = group;
                oa->o_valid |= (OBD_MD_FLID | OBD_MD_FLGROUP);
                GOTO(out, rc);
        }
        /* else diff == 0 */
        GOTO(out, rc = 0);
out:
        cfs_up(&filter->fo_create_locks[group]);
        return rc;
}

static int filter_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                         __u64 max_age, __u32 flags)
{
        struct filter_obd *filter = &obd->u.filter;
        int blockbits = obd->u.obt.obt_sb->s_blocksize_bits;
        struct lr_server_data *lsd = class_server_data(obd);
        int rc;
        ENTRY;

        /* at least try to account for cached pages.  its still racey and
         * might be under-reporting if clients haven't announced their
         * caches with brw recently */
        cfs_spin_lock(&obd->obd_osfs_lock);
        rc = fsfilt_statfs(obd, obd->u.obt.obt_sb, max_age);
        memcpy(osfs, &obd->obd_osfs, sizeof(*osfs));
        cfs_spin_unlock(&obd->obd_osfs_lock);

        CDEBUG(D_SUPER | D_CACHE, "blocks cached "LPU64" granted "LPU64
               " pending "LPU64" free "LPU64" avail "LPU64"\n",
               filter->fo_tot_dirty, filter->fo_tot_granted,
               filter->fo_tot_pending,
               osfs->os_bfree << blockbits, osfs->os_bavail << blockbits);

        filter_grant_sanity_check(obd, __func__);

        osfs->os_bavail -= min(osfs->os_bavail, GRANT_FOR_LLOG(obd) +
                               ((filter->fo_tot_dirty + filter->fo_tot_pending +
                                 osfs->os_bsize - 1) >> blockbits));

        if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOSPC,
                                 le32_to_cpu(lsd->lsd_ost_index)))
                osfs->os_bfree = osfs->os_bavail = 2;

        if (OBD_FAIL_CHECK_VALUE(OBD_FAIL_OST_ENOINO,
                                 le32_to_cpu(lsd->lsd_ost_index)))
                osfs->os_ffree = 0;

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

static __u64 filter_calc_free_inodes(struct obd_device *obd)
{
        int rc;
        __u64 os_ffree = -1;

        cfs_spin_lock(&obd->obd_osfs_lock);
        rc = fsfilt_statfs(obd, obd->u.obt.obt_sb, cfs_time_shift_64(1));
        if (rc == 0)
                os_ffree = obd->obd_osfs.os_ffree;
        cfs_spin_unlock(&obd->obd_osfs_lock);

        return os_ffree;
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
 * Caller must hold fo_create_locks[group]
 */
static int filter_precreate(struct obd_device *obd, struct obdo *oa,
                            obd_seq group, int *num)
{
        struct dentry *dchild = NULL, *dparent = NULL;
        struct filter_obd *filter;
        struct obd_statfs *osfs;
        int err = 0, rc = 0, recreate_obj = 0, i;
        cfs_time_t enough_time = cfs_time_shift(DISK_TIMEOUT/2);
        __u64 os_ffree;
        obd_id next_id;
        void *handle = NULL;
        ENTRY;

        filter = &obd->u.filter;

        LASSERT(down_trylock(&filter->fo_create_locks[group]) != 0);

        OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_DELAY_PRECREATE, obd_timeout / 2);

        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            (oa->o_flags & OBD_FL_RECREATE_OBJS)) {
                recreate_obj = 1;
        } else {
                OBD_ALLOC(osfs, sizeof(*osfs));
                if (osfs == NULL)
                        RETURN(-ENOMEM);
                rc = filter_statfs(obd, osfs,
                                   cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
                                   0);
                if (rc == 0 && osfs->os_bavail < (osfs->os_blocks >> 10)) {
                        CDEBUG(D_RPCTRACE,"%s: not enough space for create "
                               LPU64"\n", obd->obd_name, osfs->os_bavail <<
                               obd->u.obt.obt_vfsmnt->mnt_sb->s_blocksize_bits);
                        *num = 0;
                        if (oa->o_valid & OBD_MD_FLFLAGS)
                                oa->o_flags |= OBD_FL_NOSPC_BLK;
                        else {
                                oa->o_valid |= OBD_MD_FLFLAGS;
                                oa->o_flags = OBD_FL_NOSPC_BLK;
                        }

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

                if (cfs_test_bit(group, &filter->fo_destroys_in_progress)) {
                        CWARN("%s: create aborted by destroy\n",
                              obd->obd_name);
                        rc = -EAGAIN;
                        break;
                }

                if (recreate_obj) {
                        __u64 last_id;
                        next_id = oa->o_id;
                        last_id = filter_last_id(filter, group);
                        if (next_id > last_id) {
                                CERROR("Error: Trying to recreate obj greater"
                                       "than last id "LPD64" > "LPD64"\n",
                                       next_id, last_id);
                                GOTO(cleanup, rc = -EINVAL);
                        }
                } else
                        next_id = filter_last_id(filter, group) + 1;

                /* Don't create objects beyond the valid range for this SEQ */
                if (unlikely(fid_seq_is_mdt0(group) &&
                            next_id >= IDIF_MAX_OID)) {
                        CERROR("%s:"POSTID" hit the IDIF_MAX_OID (1<<48)!\n",
                                obd->obd_name, next_id, group);
                        GOTO(cleanup, rc = -ENOSPC);
               } else if (unlikely(!fid_seq_is_mdt0(group) &&
                                   next_id >= OBIF_MAX_OID)) {
                        CERROR("%s:"POSTID" hit the OBIF_MAX_OID (1<<32)!\n",
                                obd->obd_name, next_id, group);
                        GOTO(cleanup, rc = -ENOSPC);
                }

                dparent = filter_parent_lock(obd, group, next_id);
                if (IS_ERR(dparent))
                        GOTO(cleanup, rc = PTR_ERR(dparent));
                cleanup_phase = 1; /* filter_parent_unlock(dparent) */

                dchild = filter_fid2dentry(obd, dparent, group, next_id);
                if (IS_ERR(dchild))
                        GOTO(cleanup, rc = PTR_ERR(dchild));
                cleanup_phase = 2;  /* f_dput(dchild) */

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

                CDEBUG(D_INODE, "%s: filter_precreate(od->o_seq="LPU64
                       ",od->o_id="LPU64")\n", obd->obd_name, group,
                       next_id);

                /* We mark object SUID+SGID to flag it for accepting UID+GID
                 * from client on first write.  Currently the permission bits
                 * on the OST are never used, so this is OK. */
                rc = ll_vfs_create(dparent->d_inode, dchild,
                                   S_IFREG |  S_ISUID | S_ISGID | 0666, NULL);
                if (rc) {
                        CERROR("create failed rc = %d\n", rc);
                        if (rc == -ENOSPC) {
                                os_ffree = filter_calc_free_inodes(obd);
                                if (os_ffree == -1) 
                                        GOTO(cleanup, rc);

                                if (obd->obd_osfs.os_bavail <
                                    (obd->obd_osfs.os_blocks >> 10)) {
                                        if (oa->o_valid & OBD_MD_FLFLAGS)
                                                oa->o_flags |= OBD_FL_NOSPC_BLK;
                                        else {
                                                oa->o_valid |= OBD_MD_FLFLAGS;
                                                oa->o_flags = OBD_FL_NOSPC_BLK;
                                        }

                                        CERROR("%s: free inode "LPU64"\n",
                                               obd->obd_name, os_ffree);
                                }
                        }
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
                if (cfs_time_after(jiffies, enough_time)) {
                        i++;
                        CDEBUG(D_RPCTRACE,
                               "%s: precreate slow - want %d got %d \n",
                               obd->obd_name, *num, i);
                        break;
                }
        }
        *num = i;

        CDEBUG(D_RPCTRACE,
               "%s: created %d objects for group "POSTID" rc %d\n",
               obd->obd_name, i, filter->fo_last_objids[group], group, rc);

        RETURN(rc);
}

int filter_create(struct obd_export *exp, struct obdo *oa,
                  struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_export_data *fed;
        struct filter_obd *filter;
        struct lvfs_run_ctxt saved;
        struct lov_stripe_md *lsm = NULL;
        int rc = 0, diff;
        ENTRY;

        CDEBUG(D_INODE, "%s: filter_create(group="LPU64",id="
               LPU64")\n", obd->obd_name, oa->o_seq, oa->o_id);

        fed = &exp->exp_filter_data;
        filter = &obd->u.filter;

        /* 1.8 client doesn't carry the ocd_group with connect request,
         * so the fed_group will always be zero for 1.8 client. */
        if (!(exp->exp_connect_flags & OBD_CONNECT_FULL20)) {
                if (oa->o_seq != FID_SEQ_OST_MDT0 &&
                    oa->o_seq != FID_SEQ_LLOG &&
                    oa->o_seq != FID_SEQ_ECHO) {
                        CERROR("The request from older client has invalid"
                               " group "LPU64"!\n", oa->o_seq);
                        RETURN(-EINVAL);
                }
        } else if (fed->fed_group != oa->o_seq) {
                CERROR("%s: this export (nid %s) used object group %d "
                        "earlier; now it's trying to use group "LPU64"!"
                        " This could be a bug in the MDS. Please report to "
                        "http://bugzilla.lustre.org/\n", obd->obd_name,
                        obd_export_nid2str(exp), fed->fed_group, oa->o_seq);
                RETURN(-ENOTUNIQ);
        }

        if (ea != NULL) {
                lsm = *ea;
                if (lsm == NULL) {
                        rc = obd_alloc_memmd(exp, &lsm);
                        if (rc < 0)
                                RETURN(rc);
                }
        }

        obd = exp->exp_obd;
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            (oa->o_flags & OBD_FL_RECREATE_OBJS)) {
                if (!obd->obd_recovering ||
                    oa->o_id > filter_last_id(filter, oa->o_seq)) {
                        CERROR("recreate objid "LPU64" > last id "LPU64"\n",
                               oa->o_id, filter_last_id(filter, oa->o_seq));
                        rc = -EINVAL;
                } else {
                        diff = 1;
                        cfs_down(&filter->fo_create_locks[oa->o_seq]);
                        rc = filter_precreate(obd, oa, oa->o_seq, &diff);
                        cfs_up(&filter->fo_create_locks[oa->o_seq]);
                }
        } else {
                rc = filter_handle_precreate(exp, oa, oa->o_seq, oti);
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
                   struct obd_export *md_exp, void *capa)
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
        unsigned long now;
        ENTRY;

        rc = filter_auth_capa(exp, NULL, oa->o_seq,
                              (struct lustre_capa *)capa, CAPA_OPC_OSS_DESTROY);
        if (rc)
                RETURN(rc);

        obd = exp->exp_obd;
        filter = &obd->u.filter;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        cleanup_phase = 1;

        CDEBUG(D_INODE, "%s: filter_destroy(group="LPU64",oid="
               LPU64")\n", obd->obd_name, oa->o_seq, oa->o_id);

        dchild = filter_fid2dentry(obd, NULL, oa->o_seq, oa->o_id);
        if (IS_ERR(dchild))
                GOTO(cleanup, rc = PTR_ERR(dchild));
        cleanup_phase = 2;

        if (dchild->d_inode == NULL) {
                CDEBUG(D_INODE, "destroying non-existent object "POSTID"\n",
                       oa->o_id, oa->o_seq);
                /* If object already gone, cancel cookie right now */
                if (oa->o_valid & OBD_MD_FLCOOKIE) {
                        struct llog_ctxt *ctxt;
                        struct obd_llog_group *olg;

                        olg = filter_find_olg(obd, oa->o_seq);
                        if (!olg) {
                               CERROR(" %s: can not find olg of group %d\n",
                                      obd->obd_name, (int)oa->o_seq);
                               GOTO(cleanup, rc = PTR_ERR(olg));
                        }
                        fcc = &oa->o_lcookie;
                        ctxt = llog_group_get_ctxt(olg, fcc->lgc_subsys + 1);
                        llog_cancel(ctxt, NULL, 1, fcc, 0);
                        llog_ctxt_put(ctxt);
                        fcc = NULL; /* we didn't allocate fcc, don't free it */
                }
                GOTO(cleanup, rc = -ENOENT);
        }

        rc = filter_prepare_destroy(obd, oa->o_id, oa->o_seq, &lockh);
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
        now = jiffies;
        down_write(&dchild->d_inode->i_alloc_sem);
        LOCK_INODE_MUTEX(dchild->d_inode);
        fsfilt_check_slow(exp->exp_obd, now, "i_alloc_sem and i_mutex");

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
        dparent = filter_parent_lock(obd, oa->o_seq, oa->o_id);
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
        obdo_from_inode(oa, dchild->d_inode, NULL, OBD_MD_FLUID|OBD_MD_FLGID);

        filter_fmd_drop(exp, oa->o_id, oa->o_seq);

        /* this drops dchild->d_inode->i_mutex unconditionally */
        rc = filter_destroy_internal(obd, oa->o_id, oa->o_seq, dparent, dchild);

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
               ", o_size = "LPD64"\n", oinfo->oi_oa->o_id,oinfo->oi_oa->o_valid,
                oinfo->oi_policy.l_extent.start);

        oinfo->oi_oa->o_size = oinfo->oi_policy.l_extent.start;
        oinfo->oi_oa->o_valid |= OBD_FL_TRUNC;
        rc = filter_setattr(exp, oinfo, oti);
        oinfo->oi_oa->o_valid &= ~OBD_FL_TRUNC;
        RETURN(rc);
}

static int filter_sync(struct obd_export *exp, struct obd_info *oinfo,
                       obd_off start, obd_off end,
                       struct ptlrpc_request_set *set)
{
        struct lvfs_run_ctxt saved;
        struct obd_device_target *obt;
        struct dentry *dentry;
        int rc, rc2;
        ENTRY;

        rc = filter_auth_capa(exp, NULL, oinfo->oi_oa->o_seq,
                              (struct lustre_capa *)oinfo->oi_capa,
                              CAPA_OPC_OSS_WRITE);
        if (rc)
                RETURN(rc);

        obt = &exp->exp_obd->u.obt;

        /* An objid of zero is taken to mean "sync whole filesystem" */
        if (!oinfo->oi_oa || !(oinfo->oi_oa->o_valid & OBD_MD_FLID)) {
                rc = fsfilt_sync(exp->exp_obd, obt->obt_sb);
                /* Flush any remaining cancel messages out to the target */
                filter_sync_llogs(exp->exp_obd, exp);
                RETURN(rc);
        }

        dentry = filter_oa2dentry(exp->exp_obd, &oinfo->oi_oa->o_oi);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);

        LOCK_INODE_MUTEX(dentry->d_inode);

        rc = filemap_fdatawrite(dentry->d_inode->i_mapping);
        if (rc == 0) {
                /* just any file to grab fsync method - "file" arg unused */
                struct file *file = obt->obt_rcvd_filp;

                if (file->f_op && file->f_op->fsync)
                        rc = file->f_op->fsync(NULL, dentry, 1);

                rc2 = filemap_fdatawait(dentry->d_inode->i_mapping);
                if (!rc)
                        rc = rc2;
        }
        UNLOCK_INODE_MUTEX(dentry->d_inode);

        oinfo->oi_oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oinfo->oi_oa, dentry->d_inode, NULL,
                        FILTER_VALID_FLAGS);

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
                        *last_id = filter_last_id(&obd->u.filter,
                                                  exp->exp_filter_data.fed_group);
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

                dentry = __filter_oa2dentry(exp->exp_obd, &fm_key->oa.o_oi,
                                            __func__, 1);
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

static inline int filter_setup_llog_group(struct obd_export *exp,
                                          struct obd_device *obd,
                                           int group)
{
        struct obd_llog_group *olg;
        struct llog_ctxt *ctxt;
        int rc;

        olg = filter_find_create_olg(obd, group);
        if (IS_ERR(olg))
                RETURN(PTR_ERR(olg));

        llog_group_set_export(olg, exp);

        ctxt = llog_group_get_ctxt(olg, LLOG_MDS_OST_REPL_CTXT);
        LASSERTF(ctxt != NULL, "ctxt is null\n");

        rc = llog_receptor_accept(ctxt, exp->exp_imp_reverse);
        llog_ctxt_put(ctxt);
        return rc;
}

static int filter_set_grant_shrink(struct obd_export *exp,
                                   struct ost_body *body)
{
        /* handle shrink grant */
        cfs_spin_lock(&exp->exp_obd->obd_osfs_lock);
        filter_grant_incoming(exp, &body->oa);
        cfs_spin_unlock(&exp->exp_obd->obd_osfs_lock);

        RETURN(0);

}

static int filter_set_mds_conn(struct obd_export *exp, void *val)
{
        struct obd_device *obd;
        int rc = 0, group;
        ENTRY;

        obd = exp->exp_obd;
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid export %p\n", exp);
                RETURN(-EINVAL);
        }

        LCONSOLE_WARN("%s: received MDS connection from %s\n", obd->obd_name,
                      obd_export_nid2str(exp));
        obd->u.filter.fo_mdc_conn.cookie = exp->exp_handle.h_cookie;

        /* setup llog imports */
        if (val != NULL)
                group = (int)(*(__u32 *)val);
        else
                group = 0; /* default value */

        LASSERT_SEQ_IS_MDT(group);
        rc = filter_setup_llog_group(exp, obd, group);
        if (rc)
                goto out;

        if (group == FID_SEQ_OST_MDT0) {
                /* setup llog group 1 for interop */
                filter_setup_llog_group(exp, obd, FID_SEQ_LLOG);
        }

        lquota_setinfo(filter_quota_interface_ref, obd, exp);
out:
        RETURN(rc);
}

static int filter_set_info_async(struct obd_export *exp, __u32 keylen,
                                 void *key, __u32 vallen, void *val,
                                 struct ptlrpc_request_set *set)
{
        struct obd_device *obd;
        ENTRY;

        obd = exp->exp_obd;
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid export %p\n", exp);
                RETURN(-EINVAL);
        }

        if (KEY_IS(KEY_CAPA_KEY)) {
                int rc;
                rc = filter_update_capa_key(obd, (struct lustre_capa_key *)val);
                if (rc)
                        CERROR("filter update capability key failed: %d\n", rc);
                RETURN(rc);
        }

        if (KEY_IS(KEY_REVIMP_UPD)) {
                filter_revimp_update(exp);
                lquota_clearinfo(filter_quota_interface_ref, exp, exp->exp_obd);
                RETURN(0);
        }

        if (KEY_IS(KEY_SPTLRPC_CONF)) {
                filter_adapt_sptlrpc_conf(obd, 0);
                RETURN(0);
        }

        if (KEY_IS(KEY_MDS_CONN))
                RETURN(filter_set_mds_conn(exp, val));

        if (KEY_IS(KEY_GRANT_SHRINK))
                RETURN(filter_set_grant_shrink(exp, val));

        RETURN(-EINVAL);
}

int filter_iocontrol(unsigned int cmd, struct obd_export *exp,
                     int len, void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_ioctl_data *data = karg;
        int rc = 0;

        switch (cmd) {
        case OBD_IOC_ABORT_RECOVERY: {
                LCONSOLE_WARN("%s: Aborting recovery.\n", obd->obd_name);
                target_stop_recovery_thread(obd);
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
                BDEVNAME_DECLARE_STORAGE(tmp);
                CERROR("*** setting device %s read-only ***\n",
                       ll_bdevname(sb, tmp));

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

static int filter_process_config(struct obd_device *obd, obd_count len,
                                 void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct lprocfs_static_vars lvars;
        int rc = 0;

        switch (lcfg->lcfg_command) {
        default:
                lprocfs_filter_init_vars(&lvars);

                rc = class_process_proc_param(PARAM_OST, lvars.obd_vars,
                                              lcfg, obd);
                if (rc > 0)
                        rc = 0;
                break;
        }

        return rc;
}

static struct lvfs_callback_ops filter_lvfs_ops = {
        l_fid2dentry:     filter_lvfs_fid2dentry,
};

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
};

quota_interface_t *filter_quota_interface_ref;
extern quota_interface_t filter_quota_interface;

static int __init obdfilter_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc, i;

        /** sanity check for group<->mdsno conversion */
        for (i = 0; i < MAX_MDT_COUNT; i++)
                 LASSERT(objseq_to_mdsno(mdt_to_obd_objseq(i)) == i);

        lprocfs_filter_init_vars(&lvars);

        cfs_request_module("%s", "lquota");
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

        rc = class_register_type(&filter_obd_ops, NULL, lvars.module_vars,
                                 LUSTRE_OST_NAME, NULL);
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
