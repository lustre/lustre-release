/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
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
 */

/*
 * Invariant: Get O/R i_sem for lookup, if needed, before any journal ops
 *            (which need to get journal_lock, may block if journal full).
 *
 * Invariant: Call filter_start_transno() before any journal ops to avoid the
 *            same deadlock problem.  We can (and want) to get rid of the
 *            transno sem in favour of the dir/inode i_sem to avoid single
 *            threaded operation on the OST.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
# include <linux/mount.h>
# include <linux/buffer_head.h>
#endif

#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_log.h>
#include <linux/lustre_commit_confd.h>
#include <libcfs/list.h>
#include <linux/lustre_quota.h>

#include "filter_internal.h"

static struct lvfs_callback_ops filter_lvfs_ops;

static void filter_commit_cb(struct obd_device *obd, __u64 transno,
                             void *cb_data, int error)
{
        obd_transno_commit_cb(obd, transno, error);
}

/* Assumes caller has already pushed us into the kernel context. */
int filter_finish_transno(struct obd_export *exp, struct obd_trans_info *oti,
                          int rc)
{
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_client_data *fcd = fed->fed_fcd;
        __u64 last_rcvd;
        loff_t off;
        int err, log_pri = D_HA;

        /* Propagate error code. */
        if (rc)
                RETURN(rc);

        if (!exp->exp_obd->obd_replayable || oti == NULL)
                RETURN(rc);

        /* we don't allocate new transnos for replayed requests */
        if (oti->oti_transno == 0) {
                spin_lock(&filter->fo_translock);
                last_rcvd = le64_to_cpu(filter->fo_fsd->fsd_last_transno) + 1;
                filter->fo_fsd->fsd_last_transno = cpu_to_le64(last_rcvd);
                spin_unlock(&filter->fo_translock);
                oti->oti_transno = last_rcvd;
        } else {
                spin_lock(&filter->fo_translock);
                last_rcvd = oti->oti_transno;
                if (last_rcvd > le64_to_cpu(filter->fo_fsd->fsd_last_transno))
                        filter->fo_fsd->fsd_last_transno =
                                cpu_to_le64(last_rcvd);
                spin_unlock(&filter->fo_translock);
        }
        fcd->fcd_last_rcvd = cpu_to_le64(last_rcvd);

        /* could get xid from oti, if it's ever needed */
        fcd->fcd_last_xid = 0;

        off = fed->fed_lr_off;
        if (off <= 0) {
                CERROR("%s: client idx %d is %lld\n", exp->exp_obd->obd_name,
                       fed->fed_lr_idx, fed->fed_lr_off);
                err = -EINVAL;
        } else {
                fsfilt_add_journal_cb(exp->exp_obd, last_rcvd, oti->oti_handle,
                                      filter_commit_cb, NULL);
                err = fsfilt_write_record(exp->exp_obd, filter->fo_rcvd_filp,
                                          fcd, sizeof(*fcd), &off, 0);
        }
        if (err) {
                log_pri = D_ERROR;
                if (rc == 0)
                        rc = err;
        }

        CDEBUG(log_pri, "wrote trans "LPU64" for client %s at #%d: err = %d\n",
               last_rcvd, fcd->fcd_uuid, fed->fed_lr_idx, err);

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

/* Add client data to the FILTER.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_idx is -1 (i.e. a new client).
 * Otherwise, we have just read the data from the last_rcvd file and
 * we know its offset. */
static int filter_client_add(struct obd_device *obd, struct filter_obd *filter,
                             struct filter_export_data *fed, int cl_idx)
{
        unsigned long *bitmap = filter->fo_last_rcvd_slots;
        int new_client = (cl_idx == -1);
        ENTRY;

        LASSERT(bitmap != NULL);
        LASSERTF(cl_idx > -2, "%d\n", cl_idx);

        /* XXX if fcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp(fed->fed_fcd->fcd_uuid, obd->obd_uuid.uuid))
                RETURN(0);

        /* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        if (new_client) {
                cl_idx = find_first_zero_bit(bitmap, FILTER_LR_MAX_CLIENTS);
        repeat:
                if (cl_idx >= FILTER_LR_MAX_CLIENTS) {
                        CERROR("no client slots - fix FILTER_LR_MAX_CLIENTS\n");
                        RETURN(-EOVERFLOW);
                }
                if (test_and_set_bit(cl_idx, bitmap)) {
                        cl_idx = find_next_zero_bit(bitmap,
                                                    FILTER_LR_MAX_CLIENTS,
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
        fed->fed_lr_off = le32_to_cpu(filter->fo_fsd->fsd_client_start) +
                cl_idx * le16_to_cpu(filter->fo_fsd->fsd_client_size);
        LASSERTF(fed->fed_lr_off > 0, "fed_lr_off = %llu\n", fed->fed_lr_off);

        CDEBUG(D_INFO, "client at index %d (%llu) with UUID '%s' added\n",
               fed->fed_lr_idx, fed->fed_lr_off, fed->fed_fcd->fcd_uuid);

        if (new_client) {
                struct lvfs_run_ctxt saved;
                loff_t off = fed->fed_lr_off;
                int err;
                void *handle;

                CDEBUG(D_INFO, "writing client fcd at idx %u (%llu) (len %u)\n",
                       fed->fed_lr_idx,off,(unsigned int)sizeof(*fed->fed_fcd));

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                /* Transaction needed to fix bug 1403 */
                handle = fsfilt_start(obd,
                                      filter->fo_rcvd_filp->f_dentry->d_inode,
                                      FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle)) {
                        err = PTR_ERR(handle);
                        CERROR("unable to start transaction: rc %d\n", err);
                } else {
                        err = fsfilt_write_record(obd, filter->fo_rcvd_filp,
                                                  fed->fed_fcd,
                                                  sizeof(*fed->fed_fcd),
                                                  &off, 1);
                        fsfilt_commit(obd,
                                      filter->fo_rcvd_filp->f_dentry->d_inode,
                                      handle, 1);
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                if (err) {
                        CERROR("error writing %s client idx %u: rc %d\n",
                               LAST_RCVD, fed->fed_lr_idx, err);
                        RETURN(err);
                }
        }
        RETURN(0);
}

static int filter_client_free(struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct obd_device *obd = exp->exp_obd;
        struct filter_client_data zero_fcd;
        struct lvfs_run_ctxt saved;
        int rc;
        loff_t off;
        ENTRY;

        if (fed->fed_fcd == NULL)
                RETURN(0);

        /* XXX if fcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (strcmp(fed->fed_fcd->fcd_uuid, obd->obd_uuid.uuid ) == 0)
                GOTO(free, 0);

        CDEBUG(D_INFO, "freeing client at idx %u, offset %lld with UUID '%s'\n",
               fed->fed_lr_idx, off, fed->fed_fcd->fcd_uuid);

        LASSERT(filter->fo_last_rcvd_slots != NULL);

        off = fed->fed_lr_off;

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
                memset(&zero_fcd, 0, sizeof zero_fcd);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_write_record(obd, filter->fo_rcvd_filp, &zero_fcd,
                                         sizeof(zero_fcd), &off, 0);

                if (rc == 0)
                        /* update server's transno */
                        filter_update_server_data(obd, filter->fo_rcvd_filp,
                                                  filter->fo_fsd, 1);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                CDEBUG(rc == 0 ? D_INFO : D_ERROR,
                       "zeroing out client %s at idx %u (%llu) in %s rc %d\n",
                       fed->fed_fcd->fcd_uuid, fed->fed_lr_idx, fed->fed_lr_off,
                       LAST_RCVD, rc);
        }

        if (!test_and_clear_bit(fed->fed_lr_idx, filter->fo_last_rcvd_slots)) {
                CERROR("FILTER client %u: bit already clear in bitmap!!\n",
                       fed->fed_lr_idx);
                LBUG();
        }

        EXIT;
free:
        OBD_FREE(fed->fed_fcd, sizeof(*fed->fed_fcd));
        fed->fed_fcd = NULL;

        return 0;
}

static int filter_free_server_data(struct filter_obd *filter)
{
        OBD_FREE(filter->fo_fsd, sizeof(*filter->fo_fsd));
        filter->fo_fsd = NULL;
        OBD_FREE(filter->fo_last_rcvd_slots, FILTER_LR_MAX_CLIENTS / 8);
        filter->fo_last_rcvd_slots = NULL;
        return 0;
}

/* assumes caller is already in kernel ctxt */
int filter_update_server_data(struct obd_device *obd, struct file *filp,
                              struct filter_server_data *fsd, int force_sync)
{
        loff_t off = 0;
        int rc;
        ENTRY;

        CDEBUG(D_INODE, "server uuid      : %s\n", fsd->fsd_uuid);
        CDEBUG(D_INODE, "server last_rcvd : "LPU64"\n",
               le64_to_cpu(fsd->fsd_last_transno));
        CDEBUG(D_INODE, "server last_mount: "LPU64"\n",
               le64_to_cpu(fsd->fsd_mount_count));

        rc = fsfilt_write_record(obd, filp, fsd, sizeof(*fsd), &off,force_sync);
        if (rc)
                CERROR("error writing filter_server_data: rc = %d\n", rc);

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
        struct filter_server_data *fsd;
        struct filter_client_data *fcd = NULL;
        struct inode *inode = filp->f_dentry->d_inode;
        unsigned long last_rcvd_size = inode->i_size;
        __u64 mount_count;
        int cl_idx;
        loff_t off = 0;
        int rc;

        /* ensure padding in the struct is the correct size */
        LASSERT (offsetof(struct filter_server_data, fsd_padding) +
                 sizeof(fsd->fsd_padding) == FILTER_LR_SERVER_SIZE);
        LASSERT (offsetof(struct filter_client_data, fcd_padding) +
                 sizeof(fcd->fcd_padding) == FILTER_LR_CLIENT_SIZE);

        OBD_ALLOC(fsd, sizeof(*fsd));
        if (!fsd)
                RETURN(-ENOMEM);
        filter->fo_fsd = fsd;

        OBD_ALLOC(filter->fo_last_rcvd_slots, FILTER_LR_MAX_CLIENTS / 8);
        if (filter->fo_last_rcvd_slots == NULL) {
                OBD_FREE(fsd, sizeof(*fsd));
                RETURN(-ENOMEM);
        }

        if (last_rcvd_size == 0) {
                CWARN("%s: initializing new %s\n", obd->obd_name, LAST_RCVD);

                memcpy(fsd->fsd_uuid, obd->obd_uuid.uuid,sizeof(fsd->fsd_uuid));
                fsd->fsd_last_transno = 0;
                mount_count = fsd->fsd_mount_count = 0;
                fsd->fsd_server_size = cpu_to_le32(FILTER_LR_SERVER_SIZE);
                fsd->fsd_client_start = cpu_to_le32(FILTER_LR_CLIENT_START);
                fsd->fsd_client_size = cpu_to_le16(FILTER_LR_CLIENT_SIZE);
                fsd->fsd_subdir_count = cpu_to_le16(FILTER_SUBDIR_COUNT);
                filter->fo_subdir_count = FILTER_SUBDIR_COUNT;
        } else {
                rc = fsfilt_read_record(obd, filp, fsd, sizeof(*fsd), &off);
                if (rc) {
                        CDEBUG(D_INODE,"OBD filter: error reading %s: rc %d\n",
                               LAST_RCVD, rc);
                        GOTO(err_fsd, rc);
                }
                if (strcmp(fsd->fsd_uuid, obd->obd_uuid.uuid) != 0) {
                        CERROR("OBD UUID %s does not match last_rcvd UUID %s\n",
                               obd->obd_uuid.uuid, fsd->fsd_uuid);
                        GOTO(err_fsd, rc = -EINVAL);
                }
                mount_count = le64_to_cpu(fsd->fsd_mount_count);
                filter->fo_subdir_count = le16_to_cpu(fsd->fsd_subdir_count);
        }

        if (fsd->fsd_feature_incompat & ~cpu_to_le32(FILTER_INCOMPAT_SUPP)) {
                CERROR("unsupported feature %x\n",
                       le32_to_cpu(fsd->fsd_feature_incompat) &
                       ~FILTER_INCOMPAT_SUPP);
                GOTO(err_fsd, rc = -EINVAL);
        }
        if (fsd->fsd_feature_rocompat & ~cpu_to_le32(FILTER_ROCOMPAT_SUPP)) {
                CERROR("read-only feature %x\n",
                       le32_to_cpu(fsd->fsd_feature_rocompat) &
                       ~FILTER_ROCOMPAT_SUPP);
                /* Do something like remount filesystem read-only */
                GOTO(err_fsd, rc = -EINVAL);
        }

        CDEBUG(D_INODE, "%s: server last_rcvd : "LPU64"\n",
               obd->obd_name, le64_to_cpu(fsd->fsd_last_transno));
        CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
               obd->obd_name, mount_count + 1);
        CDEBUG(D_INODE, "%s: server data size: %u\n",
               obd->obd_name, le32_to_cpu(fsd->fsd_server_size));
        CDEBUG(D_INODE, "%s: per-client data start: %u\n",
               obd->obd_name, le32_to_cpu(fsd->fsd_client_start));
        CDEBUG(D_INODE, "%s: per-client data size: %u\n",
               obd->obd_name, le32_to_cpu(fsd->fsd_client_size));
        CDEBUG(D_INODE, "%s: server subdir_count: %u\n",
               obd->obd_name, le16_to_cpu(fsd->fsd_subdir_count));
        CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", obd->obd_name,
               last_rcvd_size <= le32_to_cpu(fsd->fsd_client_start) ? 0 :
               (last_rcvd_size - le32_to_cpu(fsd->fsd_client_start)) /
                le16_to_cpu(fsd->fsd_client_size));

        if (!obd->obd_replayable) {
                CWARN("%s: recovery support OFF\n", obd->obd_name);
                GOTO(out, rc = 0);
        }

        for (cl_idx = 0, off = le32_to_cpu(fsd->fsd_client_start);
             off < last_rcvd_size; cl_idx++) {
                __u64 last_rcvd;
                struct obd_export *exp;
                struct filter_export_data *fed;

                if (!fcd) {
                        OBD_ALLOC(fcd, sizeof(*fcd));
                        if (!fcd)
                                GOTO(err_client, rc = -ENOMEM);
                }

                /* Don't assume off is incremented properly by
                 * fsfilt_read_record(), in case sizeof(*fcd)
                 * isn't the same as fsd->fsd_client_size.  */
                off = le32_to_cpu(fsd->fsd_client_start) +
                        cl_idx * le16_to_cpu(fsd->fsd_client_size);
                rc = fsfilt_read_record(obd, filp, fcd, sizeof(*fcd), &off);
                if (rc) {
                        CERROR("error reading FILT %s idx %d off %llu: rc %d\n",
                               LAST_RCVD, cl_idx, off, rc);
                        break; /* read error shouldn't cause startup to fail */
                }

                if (fcd->fcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_idx);
                        continue;
                }

                last_rcvd = le64_to_cpu(fcd->fcd_last_rcvd);

                /* These exports are cleaned up by filter_disconnect(), so they
                 * need to be set up like real exports as filter_connect() does.
                 */
                exp = class_new_export(obd);
                CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                       " srv lr: "LPU64"\n", fcd->fcd_uuid, cl_idx,
                       last_rcvd, le64_to_cpu(fsd->fsd_last_transno));
                if (exp == NULL)
                        GOTO(err_client, rc = -ENOMEM);

                memcpy(&exp->exp_client_uuid.uuid, fcd->fcd_uuid,
                       sizeof exp->exp_client_uuid.uuid);
                fed = &exp->exp_filter_data;
                fed->fed_fcd = fcd;
                rc = filter_client_add(obd, filter, fed, cl_idx);
                LASSERTF(rc == 0, "rc = %d\n", rc); /* can't fail existing */

                /* create helper if export init gets more complex */
                spin_lock_init(&fed->fed_lock);

                fcd = NULL;
                exp->exp_replay_needed = 1;
                obd->obd_recoverable_clients++;
                obd->obd_max_recoverable_clients++;
                class_export_put(exp);

                CDEBUG(D_OTHER, "client at idx %d has last_rcvd = "LPU64"\n",
                       cl_idx, last_rcvd);

                if (last_rcvd > le64_to_cpu(fsd->fsd_last_transno))
                        fsd->fsd_last_transno = cpu_to_le64(last_rcvd);

        }

        if (fcd)
                OBD_FREE(fcd, sizeof(*fcd));

        obd->obd_last_committed = le64_to_cpu(fsd->fsd_last_transno);

        if (obd->obd_recoverable_clients) {
                CWARN("RECOVERY: service %s, %d recoverable clients, "
                      "last_rcvd "LPU64"\n", obd->obd_name,
                      obd->obd_recoverable_clients,
                      le64_to_cpu(fsd->fsd_last_transno));
                obd->obd_next_recovery_transno = obd->obd_last_committed + 1;
                obd->obd_recovering = 1;
                obd->obd_recovery_start = CURRENT_SECONDS;
                /* Only used for lprocfs_status */
                obd->obd_recovery_end = obd->obd_recovery_start +
                        OBD_RECOVERY_TIMEOUT / HZ;
        }

out:
        filter->fo_mount_count = mount_count + 1;
        fsd->fsd_mount_count = cpu_to_le64(filter->fo_mount_count);

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

        if (filter->fo_blacklist != NULL) {
                OBD_FREE(filter->fo_blacklist,
                         FILTER_GROUPS * sizeof(struct filter_ext));
                filter->fo_blacklist = NULL;
        }
        
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

        OBD_ALLOC(filter->fo_blacklist,
                  FILTER_GROUPS * sizeof(struct filter_ext));
        if (!filter->fo_blacklist)
                GOTO(cleanup, rc = -ENOMEM);
        
        O_dentry = simple_mkdir(current->fs->pwd, "O", 0700, 1);
        CDEBUG(D_INODE, "got/created O: %p\n", O_dentry);
        if (IS_ERR(O_dentry)) {
                rc = PTR_ERR(O_dentry);
                CERROR("cannot open/create O: rc = %d\n", rc);
                GOTO(cleanup, rc);
        }
        filter->fo_dentry_O = O_dentry;
        cleanup_phase = 1; /* O_dentry */

        /* Lookup "R" to tell if we're on an old OST FS and need to convert
         * from O/R/<dir>/<objid> to O/0/<dir>/<objid>.  This can be removed
         * some time post 1.0 when all old-style OSTs have converted along
         * with the init_objid hack. */
        dentry = ll_lookup_one_len("R", O_dentry, 1);
        if (IS_ERR(dentry))
                GOTO(cleanup, rc = PTR_ERR(dentry));
        if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)) {
                struct dentry *O0_dentry = lookup_one_len("0", O_dentry, 1);
                ENTRY;

                CWARN("converting OST to new object layout\n");
                if (IS_ERR(O0_dentry)) {
                        rc = PTR_ERR(O0_dentry);
                        CERROR("error looking up O/0: rc %d\n", rc);
                        GOTO(cleanup_R, rc);
                }

                if (O0_dentry->d_inode) {
                        CERROR("Both O/R and O/0 exist. Fix manually.\n");
                        GOTO(cleanup_O0, rc = -EEXIST);
                }

                down(&O_dentry->d_inode->i_sem);
                rc = vfs_rename(O_dentry->d_inode, dentry,
                                O_dentry->d_inode, O0_dentry);
                up(&O_dentry->d_inode->i_sem);

                if (rc) {
                        CERROR("error renaming O/R to O/0: rc %d\n", rc);
                        GOTO(cleanup_O0, rc);
                }
                filter->fo_fsd->fsd_feature_incompat |=
                        cpu_to_le32(FILTER_INCOMPAT_GROUPS);
                rc = filter_update_server_data(obd, filter->fo_rcvd_filp,
                                               filter->fo_fsd, 1);
                GOTO(cleanup_O0, rc);

        cleanup_O0:
                f_dput(O0_dentry);
        cleanup_R:
                f_dput(dentry);
                if (rc)
                        GOTO(cleanup, rc);
        } else {
                f_dput(dentry);
        }

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
                dentry = simple_mkdir(O_dentry, name, 0700, 1);
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

                if (filp->f_dentry->d_inode->i_size == 0) {
                        if (i == 0 && filter->fo_fsd->fsd_unused != 0) {
                                /* OST conversion, remove sometime post 1.0 */
                                filter->fo_last_objids[0] =
                                        le64_to_cpu(filter->fo_fsd->fsd_unused);
                                CWARN("saving old objid "LPU64" to LAST_ID\n",
                                      filter->fo_last_objids[0]);
                        } else {
                                filter->fo_last_objids[i] = FILTER_INIT_OBJID;
                        }
                        rc = filter_update_last_objid(obd, i, 1);
                        if (rc)
                                GOTO(cleanup, rc);
                        continue;
                }

                rc = fsfilt_read_record(obd, filp, &filter->fo_last_objids[i],
                                        sizeof(__u64), &off);
                if (rc) {
                        CDEBUG(D_INODE,"OBD filter: error reading %s: rc %d\n",
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

                        dentry = simple_mkdir(O_dentry, dir, 0700, 1);
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

        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LAST_RCVD,
                       file->f_dentry->d_inode->i_mode);
                GOTO(err_filp, rc = -ENOENT);
        }

        /* steal operations */
        inode = file->f_dentry->d_inode;
        filter->fo_fop = file->f_op;
        filter->fo_iop = inode->i_op;
        filter->fo_aops = inode->i_mapping->a_ops;

        rc = filter_init_server_data(obd, file);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_filp, rc);
        }
        filter->fo_rcvd_filp = file;

        rc = filter_prep_groups(obd);
        if (rc)
                GOTO(err_server_data, rc);

 out:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        return(rc);

 err_server_data:
        //class_disconnect_exports(obd, 0);
        filter_free_server_data(filter);
 err_filp:
        if (filp_close(file, 0))
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

        filter_cleanup_groups(obd);
        filter_free_server_data(filter);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
}

static void filter_set_last_id(struct filter_obd *filter, 
			       int group, obd_id id)
{
        LASSERT(filter->fo_fsd != NULL);
        LASSERT(group <= FILTER_GROUPS);

        spin_lock(&filter->fo_objidlock);
        filter->fo_last_objids[group] = id;
        spin_unlock(&filter->fo_objidlock);
}

static void filter_grow_last_id(struct filter_obd *filter, 
                                int group, obd_id id)
{
        LASSERT(filter->fo_fsd != NULL);
        LASSERT(group <= FILTER_GROUPS);

        spin_lock(&filter->fo_objidlock);
        if (id > filter->fo_last_objids[group])
        filter->fo_last_objids[group] = id;
        spin_unlock(&filter->fo_objidlock);
}

__u64 filter_last_id(struct filter_obd *filter, int group)
{
        obd_id id;
        LASSERT(filter->fo_fsd != NULL);
        LASSERT(group < FILTER_GROUPS);

        spin_lock(&filter->fo_objidlock);
        id = filter->fo_last_objids[group];
        spin_unlock(&filter->fo_objidlock);

        return id;
}

static void filter_lock_dentry(struct obd_device *obd,
                               struct dentry *dparent)
{
        down(&dparent->d_inode->i_sem);
}

static void filter_unlock_dentry(struct obd_device *obd,
                                 struct dentry *dparent)
{
        up(&dparent->d_inode->i_sem);
}

static void filter_parents_access(struct obd_device *obd,
                                  obd_gr group, int lock)
{
        void (*access_func) (struct obd_device *, struct dentry *);
        struct filter_obd *filter = &obd->u.filter;
        struct dentry *dparent;
        int i = 0;

        access_func = lock ? filter_lock_dentry :
                filter_unlock_dentry;
        
        if (group > 0 || filter->fo_subdir_count == 0) {
                dparent = filter->fo_dentry_O_groups[group];
                access_func(obd, dparent);
        } else {
                for (i = 0; i < filter->fo_subdir_count; i++) {
                        dparent = filter->fo_dentry_O_sub[i];
                        access_func(obd, dparent);
                }
        }
}

#define LOCK_PARENTS(obd, group)   \
        filter_parents_access(obd, group, 1)

#define UNLOCK_PARENTS(obd, group) \
        filter_parents_access(obd, group, 0)

/* We never dget the object parent, so DON'T dput it either */
struct dentry *filter_parent(struct obd_device *obd, obd_gr group, obd_id objid)
{
        struct filter_obd *filter = &obd->u.filter;
        LASSERT(group < FILTER_GROUPS); /* FIXME: object groups */

        if (group > 0 || filter->fo_subdir_count == 0)
                return filter->fo_dentry_O_groups[group];

        return filter->fo_dentry_O_sub[objid & (filter->fo_subdir_count - 1)];
}

/* We never dget the object parent, so DON'T dput it either */
struct dentry *filter_parent_lock(struct obd_device *obd, obd_gr group,
                                  obd_id objid)
{
        struct dentry *dparent = filter_parent(obd, group, objid);
        unsigned long now = jiffies;

        if (IS_ERR(dparent))
                return dparent;

        filter_lock_dentry(obd, dparent);
        fsfilt_check_slow(now, obd_timeout, "parent lock");
        return dparent;
}

/* we never dget the object parent, so DON'T dput it either */
static void filter_parent_unlock(struct obd_device *obd,
                                 struct dentry *dparent)
{
        filter_unlock_dentry(obd, dparent);
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

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT)) {
                CERROR("test case OBD_FAIL_OST_ENOENT\n");
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
                filter_parent_unlock(obd, dparent);
        if (IS_ERR(dchild)) {
                CERROR("%s: child lookup error %ld\n", obd->obd_name,
                       PTR_ERR(dchild));
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

static int filter_prepare_destroy(struct obd_device *obd, obd_id objid)
{
        struct lustre_handle lockh;
        int flags = LDLM_AST_DISCARD_DATA, rc;
        struct ldlm_res_id res_id = { .name = { objid } };
        ldlm_policy_data_t policy = { .l_extent = { 0, OBD_OBJECT_EOF } };

        ENTRY;
        /* Tell the clients that the object is gone now and that they should
         * throw away any cached pages. */
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, res_id,
                              LDLM_EXTENT, &policy, LCK_PW,
                              &flags, ldlm_blocking_ast, ldlm_completion_ast,
                              NULL, NULL, NULL, 0, NULL, &lockh);

        /* We only care about the side-effects, just drop the lock. */
        if (rc == ELDLM_OK)
                ldlm_lock_decref(&lockh, LCK_PW);

        RETURN(rc);
}

/* Caller must hold LCK_PW on parent and push us into kernel context.
 * Caller is also required to ensure that dchild->d_inode exists. */
static int filter_unlink(struct obd_device *obd, obd_id objid,
                         struct dentry *dparent, struct dentry *dchild)
{
        struct inode *inode = dchild->d_inode;
        int rc;
        ENTRY;

        if (inode->i_nlink != 1 || atomic_read(&inode->i_count) != 1) {
                CERROR("destroying objid %.*s ino %lu nlink %lu count %d\n",
                       dchild->d_name.len, dchild->d_name.name, inode->i_ino,
                       (unsigned long)inode->i_nlink,
                       atomic_read(&inode->i_count));
        }

        rc = vfs_unlink(dparent->d_inode, dchild);
        if (rc)
                CERROR("error unlinking objid %.*s: rc %d\n",
                       dchild->d_name.len, dchild->d_name.name, rc);
        RETURN(rc);
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
        struct list_head *tmp;
        ldlm_error_t err;
        int tmpflags = 0, rc, repsize[2] = {sizeof(*rep), sizeof(*reply_lvb)};
        int only_liblustre = 0;
        ENTRY;

        policy = ldlm_get_processing_policy(res);
        LASSERT(policy != NULL);
        LASSERT(req != NULL);

        rc = lustre_pack_reply(req, 2, repsize, NULL);
        if (rc)
                RETURN(req->rq_status = rc);

        rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*rep));
        LASSERT(rep != NULL);

        reply_lvb = lustre_msg_buf(req->rq_repmsg, 1, sizeof(*reply_lvb));
        LASSERT(reply_lvb != NULL);

        //fixup_handle_for_resent_req(req, lock, &lockh);

        /* If we grant any lock at all, it will be a whole-file read lock.
         * Call the extent policy function to see if our request can be
         * granted, or is blocked. */
        lock->l_policy_data.l_extent.start = 0;
        lock->l_policy_data.l_extent.end = OBD_OBJECT_EOF;
        lock->l_req_mode = LCK_PR;

        LASSERT(ns == res->lr_namespace);
        l_lock(&ns->ns_lock);

        res->lr_tmp = &rpc_list;
        rc = policy(lock, &tmpflags, 0, &err);
        res->lr_tmp = NULL;

        /* FIXME: we should change the policy function slightly, to not make
         * this list at all, since we just turn around and free it */
        while (!list_empty(&rpc_list)) {
                struct ldlm_ast_work *w =
                        list_entry(rpc_list.next, struct ldlm_ast_work, w_list);
                list_del(&w->w_list);
                LDLM_LOCK_PUT(w->w_lock);
                OBD_FREE(w, sizeof(*w));
        }

        /* The lock met with no resistance; we're finished. */
        if (rc == LDLM_ITER_CONTINUE) {
                l_unlock(&ns->ns_lock);
                /*
                 * do not grant locks to the liblustre clients: they cannot
                 * handle ASTs robustly.
                 */
                if (lock->l_export->exp_libclient) {
                        ldlm_resource_unlink_lock(lock);
                        RETURN(ELDLM_LOCK_ABORTED);
                }
                RETURN(ELDLM_LOCK_REPLACED);
        }

        /* Do not grant any lock, but instead send GL callbacks.  The extent
         * policy nicely created a list of all PW locks for us.  We will choose
         * the highest of those which are larger than the size in the LVB, if
         * any, and perform a glimpse callback. */
        down(&res->lr_lvb_sem);
        res_lvb = res->lr_lvb_data;
        LASSERT(res_lvb != NULL);
        *reply_lvb = *res_lvb;
        up(&res->lr_lvb_sem);

        list_for_each(tmp, &res->lr_granted) {
                struct ldlm_lock *tmplock =
                        list_entry(tmp, struct ldlm_lock, l_res_link);

                if (tmplock->l_granted_mode == LCK_PR)
                        continue;
                /*
                 * ->ns_lock guarantees that no new locks are granted, and,
                 * therefore, that res->lr_lvb_data cannot increase beyond the
                 * end of already granted lock. As a result, it is safe to
                 * check against "stale" reply_lvb->lvb_size value without
                 * res->lr_lvb_sem.
                 */
                if (tmplock->l_policy_data.l_extent.end <= reply_lvb->lvb_size)
                        continue;

                /* Don't send glimpse ASTs to liblustre clients.  They aren't
                 * listening for them, and they do entirely synchronous I/O
                 * anyways. */
                if (tmplock->l_export == NULL ||
                    tmplock->l_export->exp_libclient == 1) {
                        only_liblustre = 1;
                        continue;
                }

                if (l == NULL) {
                        l = LDLM_LOCK_GET(tmplock);
                        continue;
                }

                if (l->l_policy_data.l_extent.start >
                    tmplock->l_policy_data.l_extent.start)
                        continue;

                LDLM_LOCK_PUT(l);
                l = LDLM_LOCK_GET(tmplock);
        }
        l_unlock(&ns->ns_lock);

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
                        if (ns->ns_lvbo && ns->ns_lvbo->lvbo_update)
                                ns->ns_lvbo->lvbo_update(res, NULL, 0, 1);
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
        /*
         * XXX nikita: situation when ldlm_server_glimpse_ast() failed before
         * sending ast is not handled. This can result in lost client writes.
         */
        if (rc != 0 && ns->ns_lvbo && ns->ns_lvbo->lvbo_update)
                ns->ns_lvbo->lvbo_update(res, NULL, 0, 1);

        down(&res->lr_lvb_sem);
        *reply_lvb = *res_lvb;
        up(&res->lr_lvb_sem);

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
 * field). This array has size OST_NUM_THREADS, so that each OST thread uses
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
        void **pool;
        int i;

        ENTRY;

        pool = filter->fo_iobuf_pool;
        if (pool != NULL) {
                for (i = 0; i < OST_NUM_THREADS; ++ i) {
                        if (pool[i] != NULL)
                                filter_free_iobuf(pool[i]);
                }
                OBD_FREE(pool, OST_NUM_THREADS * sizeof pool[0]);
                filter->fo_iobuf_pool = NULL;
        }
        EXIT;
}

/*
 * pre-allocate pool of iobuf's to be used by filter_{prep,commit}rw_write().
 */
static int filter_iobuf_pool_init(struct filter_obd *filter, int count)
{
        void **pool;
        int i;
        int result = 0;

        ENTRY;

        LASSERT(count <= OST_NUM_THREADS);

        OBD_ALLOC_GFP(pool, OST_NUM_THREADS * sizeof pool[0], GFP_KERNEL);
        if (pool == NULL)
                RETURN(-ENOMEM);

        filter->fo_iobuf_pool = pool;
        filter->fo_iobuf_count = count;
        for (i = 0; i < count; ++ i) {
                /*
                 * allocate kiobuf to be used by i-th OST thread.
                 */
                result = filter_alloc_iobuf(filter, OBD_BRW_WRITE,
                                            PTLRPC_MAX_BRW_PAGES,
                                            &pool[i]);
                if (result != 0) {
                        filter_iobuf_pool_done(filter);
                        break;
                }
        }
        RETURN(result);
}

/*
 * return iobuf preallocated by filter_iobuf_pool_init() for @thread.
 */
void *filter_iobuf_get(struct ptlrpc_thread *thread, struct filter_obd *filter)
{
        void *kio;

        LASSERT(thread->t_id < filter->fo_iobuf_count);
        kio = filter->fo_iobuf_pool[thread->t_id];
        LASSERT(kio != NULL);
        return kio;
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
        char *str;
        char ns_name[48];
        int rc;
        ENTRY;

        if (lcfg->lcfg_bufcount < 3 ||
            LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
            LUSTRE_CFG_BUFLEN(lcfg, 2) < 1)
                RETURN(-EINVAL);

        obd->obd_fsops = fsfilt_get_ops(lustre_cfg_string(lcfg, 2));
        if (IS_ERR(obd->obd_fsops))
                RETURN(PTR_ERR(obd->obd_fsops));

        rc = filter_iobuf_pool_init(filter, OST_NUM_THREADS);
        if (rc != 0)
                GOTO(err_ops, rc);

        mnt = do_kern_mount(lustre_cfg_string(lcfg, 2),MS_NOATIME|MS_NODIRATIME,
                            lustre_cfg_string(lcfg, 1), option);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                LCONSOLE_ERROR("Can't mount disk %s (%d)\n",
                               lustre_cfg_string(lcfg, 1), rc);
                GOTO(err_ops, rc);
        }

        LASSERT(!lvfs_check_rdonly(lvfs_sbdev(mnt->mnt_sb)));

        obd->obd_replayable = 1;
        obd_sync_filter = 1;

        if (lcfg->lcfg_bufcount > 3 && LUSTRE_CFG_BUFLEN(lcfg, 3) > 0) {
                str = lustre_cfg_string(lcfg, 3);
                if (strchr(str, 'n')) {
                        CWARN("%s: recovery disabled\n", obd->obd_name);
                        obd->obd_replayable = 0;
                        obd_sync_filter = 0;
                }
        }

        filter->fo_vfsmnt = mnt;
        obd->u.obt.obt_sb = mnt->mnt_sb;
        filter->fo_fstype = mnt->mnt_sb->s_type->name;
        CDEBUG(D_SUPER, "%s: mnt = %p\n", filter->fo_fstype, mnt);

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        obd->obd_lvfs_ctxt.cb_ops = filter_lvfs_ops;

        rc = filter_prep(obd);
        if (rc)
                GOTO(err_mntput, rc);

        filter->fo_destroy_in_progress = 0;

        spin_lock_init(&filter->fo_blacklist_lock);
        spin_lock_init(&filter->fo_translock);
        spin_lock_init(&filter->fo_objidlock);
        spin_lock_init(&filter->fo_stats_lock);
        INIT_LIST_HEAD(&filter->fo_export_list);
        sema_init(&filter->fo_alloc_lock, 1);
        spin_lock_init(&filter->fo_r_pages.oh_lock);
        spin_lock_init(&filter->fo_w_pages.oh_lock);
        spin_lock_init(&filter->fo_read_rpc_hist.oh_lock);
        spin_lock_init(&filter->fo_write_rpc_hist.oh_lock);
        spin_lock_init(&filter->fo_r_io_time.oh_lock);
        spin_lock_init(&filter->fo_w_io_time.oh_lock);
        spin_lock_init(&filter->fo_r_discont_pages.oh_lock);
        spin_lock_init(&filter->fo_w_discont_pages.oh_lock);
        spin_lock_init(&filter->fo_r_discont_blocks.oh_lock);
        spin_lock_init(&filter->fo_w_discont_blocks.oh_lock);
        spin_lock_init(&filter->fo_r_disk_iosize.oh_lock);
        spin_lock_init(&filter->fo_w_disk_iosize.oh_lock);
        filter->fo_readcache_max_filesize = FILTER_MAX_CACHE_SIZE;

        sprintf(ns_name, "filter-%s", obd->obd_uuid.uuid);
        obd->obd_namespace = ldlm_namespace_new(ns_name, LDLM_NAMESPACE_SERVER);
        if (obd->obd_namespace == NULL)
                GOTO(err_post, rc = -ENOMEM);
        obd->obd_namespace->ns_lvbp = obd;
        obd->obd_namespace->ns_lvbo = &filter_lvbo;
        ldlm_register_intent(obd->obd_namespace, filter_intent_policy);

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "filter_ldlm_cb_client", &obd->obd_ldlm_client);

        rc = llog_cat_initialize(obd, 1);
        if (rc) {
                CERROR("failed to setup llogging subsystems\n");
                GOTO(err_post, rc);
        }

        rc = lquota_setup(quota_interface, obd, lcfg);
        if (rc)
                GOTO(err_post, rc);

        if (obd->obd_recovering) {
                LCONSOLE_WARN("OST %s now serving %s, but will be in recovery "
                              "until %d %s reconnect, or if no clients "
                              "reconnect for %d:%.02d; during that time new "
                              "clients will not be allowed to connect. "
                              "Recovery progress can be monitored by watching "
                              "/proc/fs/lustre/obdfilter/%s/recovery_status.\n",
                              obd->obd_name,
                              lustre_cfg_string(lcfg, 1),
                              obd->obd_recoverable_clients,
                              (obd->obd_recoverable_clients == 1)
                              ? "client" : "clients",
                              (int)(OBD_RECOVERY_TIMEOUT / HZ) / 60,
                              (int)(OBD_RECOVERY_TIMEOUT / HZ) % 60,
                              obd->obd_name);
        } else {
                LCONSOLE_INFO("OST %s now serving %s with recovery %s.\n",
                              obd->obd_name,
                              lustre_cfg_string(lcfg, 1),
                              obd->obd_replayable ? "enabled" : "disabled");
        }

        RETURN(0);

err_post:
        filter_post(obd);
err_mntput:
        unlock_kernel();
        mntput(mnt);
        obd->u.obt.obt_sb = 0;
        lock_kernel();
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
        filter_iobuf_pool_done(filter);
        return rc;
}

static int filter_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        struct lustre_cfg* lcfg = buf;
        unsigned long page;
        int rc;

        CLASSERT(offsetof(struct obd_device, u.obt) ==
                 offsetof(struct obd_device, u.filter.fo_obt));

        if (!LUSTRE_CFG_BUFLEN(lcfg, 1) || !LUSTRE_CFG_BUFLEN(lcfg, 2))
                RETURN(-EINVAL);

        /* 2.6.9 selinux wants a full option page for do_kern_mount (bug6471) */
        page = get_zeroed_page(GFP_KERNEL);
        if (!page)
                RETURN(-ENOMEM);

        memcpy((void *)page, lustre_cfg_buf(lcfg, 4),
               LUSTRE_CFG_BUFLEN(lcfg, 4));
        rc = filter_common_setup(obd, len, buf, (void *)page);
        free_page(page);

        lprocfs_init_vars(filter, &lvars);
        if (rc == 0 && lprocfs_obd_setup(obd, lvars.obd_vars) == 0 &&
            lprocfs_alloc_obd_stats(obd, LPROC_FILTER_LAST) == 0) {
                /* Init obdfilter private stats here */
                lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_READ_BYTES,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "read_bytes", "bytes");
                lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_WRITE_BYTES,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "write_bytes", "bytes");

                lproc_filter_attach_seqstat(obd);
        }

        ping_evictor_start();

        return rc;
}

static struct llog_operations filter_mds_ost_repl_logops /* initialized below*/;
static struct llog_operations filter_size_orig_logops = {
        lop_setup: llog_obd_origin_setup,
        lop_cleanup: llog_obd_origin_cleanup,
        lop_add: llog_obd_origin_add
};

static int filter_llog_init(struct obd_device *obd, struct obd_device *tgt,
                            int count, struct llog_catid *catid)
{
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        filter_mds_ost_repl_logops = llog_client_ops;
        filter_mds_ost_repl_logops.lop_cancel = llog_obd_repl_cancel;
        filter_mds_ost_repl_logops.lop_connect = llog_repl_connect;
        filter_mds_ost_repl_logops.lop_sync = llog_obd_repl_sync;

        rc = llog_setup(obd, LLOG_MDS_OST_REPL_CTXT, tgt, 0, NULL,
                        &filter_mds_ost_repl_logops);
        if (rc)
                RETURN(rc);

        /* FIXME - assign unlink_cb for filter's recovery */
        ctxt = llog_get_context(obd, LLOG_MDS_OST_REPL_CTXT);
        ctxt->llog_proc_cb = filter_recov_log_mds_ost_cb;

        rc = llog_setup(obd, LLOG_SIZE_ORIG_CTXT, tgt, 0, NULL,
                        &filter_size_orig_logops);
        RETURN(rc);
}

static int filter_llog_finish(struct obd_device *obd, int count)
{
        struct llog_ctxt *ctxt;
        int rc = 0, rc2 = 0;
        ENTRY;

        ctxt = llog_get_context(obd, LLOG_MDS_OST_REPL_CTXT);
        if (ctxt)
                rc = llog_cleanup(ctxt);

        ctxt = llog_get_context(obd, LLOG_SIZE_ORIG_CTXT);
        if (ctxt)
                rc2 = llog_cleanup(ctxt);
        if (!rc)
                rc = rc2;

        RETURN(rc);
}

static int filter_precleanup(struct obd_device *obd, int stage)
{
        int rc = 0;
        ENTRY;

        switch(stage) {
        case 1:
                target_cleanup_recovery(obd);
                break;
        case 2:
                rc = filter_llog_finish(obd, 0);
        }
        RETURN(rc);
}

static int filter_cleanup(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        lvfs_sbdev_type save_dev;
        int must_relock = 0;
        ENTRY;

        if (obd->obd_fail)
                CERROR("%s: shutting down for failover; client state will"
                       " be preserved.\n", obd->obd_name);

        if (!list_empty(&obd->obd_exports)) {
                CERROR("%s: still has clients!\n", obd->obd_name);
                class_disconnect_exports(obd);
                if (!list_empty(&obd->obd_exports)) {
                        CERROR("still has exports after forced cleanup?\n");
                        RETURN(-EBUSY);
                }
        }

        ping_evictor_stop();

        lquota_cleanup(quota_interface, obd);

        ldlm_namespace_free(obd->obd_namespace, obd->obd_force);

        if (obd->u.obt.obt_sb == NULL)
                RETURN(0);
        save_dev = lvfs_sbdev(obd->u.obt.obt_sb);

        lprocfs_free_obd_stats(obd);
        lprocfs_obd_cleanup(obd);

        filter_post(obd);

        shrink_dcache_parent(obd->u.obt.obt_sb->s_root);

        LL_DQUOT_OFF(obd->u.obt.obt_sb);

        if (atomic_read(&filter->fo_vfsmnt->mnt_count) > 1)
                CERROR("%s: mount point %p busy, mnt_count: %d\n",
                       obd->obd_name, filter->fo_vfsmnt,
                       atomic_read(&filter->fo_vfsmnt->mnt_count));

        /* We can only unlock kernel if we are in the context of sys_ioctl,
           otherwise we never called lock_kernel */
        if (kernel_locked()) {
                unlock_kernel();
                must_relock++;
        }

        mntput(filter->fo_vfsmnt);
        //destroy_buffers(obd->u.obt.obt_sb->s_dev);
        obd->u.obt.obt_sb = NULL;

        lvfs_clear_rdonly(save_dev);

        if (must_relock)
                lock_kernel();

        fsfilt_put_ops(obd->obd_fsops);

        filter_iobuf_pool_done(filter);

        LCONSOLE_INFO("OST %s has stopped.\n", obd->obd_name);

        RETURN(0);
}

/* nearly identical to mds_connect */
static int filter_connect(struct lustre_handle *conn, struct obd_device *obd,
                          struct obd_uuid *cluuid, struct obd_connect_data *data)
{
        struct obd_export *exp;
        struct filter_export_data *fed;
        struct filter_client_data *fcd = NULL;
        struct filter_obd *filter = &obd->u.filter;
        int rc;
        ENTRY;

        if (conn == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        LASSERT(exp != NULL);

        fed = &exp->exp_filter_data;

        if (data != NULL) {
                data->ocd_connect_flags &= OST_CONNECT_SUPPORTED;
                exp->exp_connect_flags = data->ocd_connect_flags;
        }

        spin_lock_init(&fed->fed_lock);

        if (!obd->obd_replayable)
                GOTO(cleanup, rc = 0);

        OBD_ALLOC(fcd, sizeof(*fcd));
        if (!fcd) {
                CERROR("filter: out of memory for client data\n");
                GOTO(cleanup, rc = -ENOMEM);
        }

        memcpy(fcd->fcd_uuid, cluuid, sizeof(fcd->fcd_uuid));
        fed->fed_fcd = fcd;

        rc = filter_client_add(obd, filter, fed, -1);
        GOTO(cleanup, rc);

cleanup:
        if (rc) {
                if (fcd) {
                        OBD_FREE(fcd, sizeof(*fcd));
                        fed->fed_fcd = NULL;
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

        target_destroy_export(exp);

        if (exp->exp_obd->obd_replayable)
                filter_client_free(exp);

        filter_grant_discard(exp);

        if (!(exp->exp_flags & OBD_OPT_FORCE))
                filter_grant_sanity_check(exp->exp_obd, __FUNCTION__);

        RETURN(0);
}

/* also incredibly similar to mds_disconnect */
static int filter_disconnect(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        struct llog_ctxt *ctxt;
        int rc, err;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        if (!(exp->exp_flags & OBD_OPT_FORCE))
                filter_grant_sanity_check(obd, __FUNCTION__);
        filter_grant_discard(exp);

        /* Disconnect early so that clients can't keep using export */
        rc = class_disconnect(exp);
        ldlm_cancel_locks_for_export(exp);

        fsfilt_sync(obd, obd->u.obt.obt_sb);

        /* flush any remaining cancel messages out to the target */
        ctxt = llog_get_context(obd, LLOG_MDS_OST_REPL_CTXT);
        err = llog_sync(ctxt, exp);
        if (err)
                CERROR("error flushing logs to MDS: rc %d\n", err);

        class_export_put(exp);
        RETURN(rc);
}

struct dentry *__filter_oa2dentry(struct obd_device *obd, struct obdo *oa,
                                  const char *what, int quiet)
{
        struct dentry *dchild = NULL;
        obd_gr group = 0;

        if (oa->o_valid & OBD_MD_FLGROUP)
                group = oa->o_gr;

        dchild = filter_fid2dentry(obd, NULL, group, oa->o_id);

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

static int filter_getattr(struct obd_export *exp, struct obdo *oa,
                          struct lov_stripe_md *md)
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

        dentry = filter_oa2dentry(obd, oa);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        /* Limit the valid bits in the return data to what we actually use */
        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa, dentry->d_inode, FILTER_VALID_FLAGS);

        f_dput(dentry);
        RETURN(rc);
}

/* this is called from filter_truncate() until we have filter_punch() */
int filter_setattr_internal(struct obd_export *exp, struct dentry *dentry,
                            struct obdo *oa, struct obd_trans_info *oti)
{
        unsigned int orig_ids[MAXQUOTAS] = {0, 0};
        struct llog_cookie *fcc = NULL;
        struct filter_obd *filter;
        struct iattr iattr;
        void *handle;
        int rc, err;
        ENTRY;

        LASSERT(dentry != NULL);
        LASSERT(!IS_ERR(dentry));
        LASSERT(dentry->d_inode != NULL);

        filter = &exp->exp_obd->u.filter;
        iattr_from_obdo(&iattr, oa, oa->o_valid);

        if (oa->o_valid & OBD_MD_FLCOOKIE) {
                OBD_ALLOC(fcc, sizeof(*fcc));
                if (fcc != NULL)
                        memcpy(fcc, obdo_logcookie(oa), sizeof(*fcc));
        }

        if (iattr.ia_valid & ATTR_SIZE)
                down(&dentry->d_inode->i_sem);

        if (iattr.ia_valid & (ATTR_UID | ATTR_GID)) {
                orig_ids[USRQUOTA] = dentry->d_inode->i_uid;
                orig_ids[GRPQUOTA] = dentry->d_inode->i_gid;
                handle = fsfilt_start_log(exp->exp_obd, dentry->d_inode,
                                          FSFILT_OP_SETATTR, oti, 1);
        } else {
                handle = fsfilt_start(exp->exp_obd, dentry->d_inode,
                                      FSFILT_OP_SETATTR, oti);
        }

        if (IS_ERR(handle))
                GOTO(out_unlock, rc = PTR_ERR(handle));

        if (oa->o_valid & OBD_MD_FLFLAGS) {
                rc = fsfilt_iocontrol(exp->exp_obd, dentry->d_inode,
                                      NULL, EXT3_IOC_SETFLAGS,
                                      (long)&iattr.ia_attr_flags);
        } else {
                rc = fsfilt_setattr(exp->exp_obd, dentry, handle, &iattr, 1);
                if (fcc != NULL)
                        /* set cancel cookie callback function */
                        fsfilt_add_journal_cb(exp->exp_obd, 0, oti ?
                                              oti->oti_handle : handle,
                                              filter_cancel_cookies_cb,
                                              fcc);
        }

        rc = filter_finish_transno(exp, oti, rc);
        
        err = fsfilt_commit(exp->exp_obd, dentry->d_inode, handle, 0);
        if (err) {
                CERROR("error on commit, err = %d\n", err);
                if (!rc)
                        rc = err;
        }
        EXIT;
out_unlock:
        if (iattr.ia_valid & ATTR_SIZE)
                up(&dentry->d_inode->i_sem);

        /* trigger quota release */
        if (iattr.ia_valid & (ATTR_SIZE | ATTR_UID | ATTR_GID)) {
                unsigned int cur_ids[MAXQUOTAS] = {oa->o_uid, oa->o_gid};
                int rc2= lquota_adjust(quota_interface, exp->exp_obd, cur_ids,
                                       orig_ids, rc, FSFILT_OP_SETATTR);
                CDEBUG(rc2 ? D_ERROR : D_QUOTA, 
                       "filter adjust qunit. (rc:%d)\n", rc2);
        }
        return rc;
}

/* this is called from filter_truncate() until we have filter_punch() */
int filter_setattr(struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        struct ldlm_res_id res_id = { .name = { oa->o_id } };
        struct ldlm_valblock_ops *ns_lvbo;
        struct lvfs_run_ctxt saved;
        struct filter_obd *filter;
        struct ldlm_resource *res;
        struct dentry *dentry;
        int rc;
        ENTRY;

        LASSERT(oti != NULL);

        filter = &exp->exp_obd->u.filter;
        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
    
        /* make sure that object is allocated. */
        dentry = filter_crow_object(exp->exp_obd, oa);
        if (IS_ERR(dentry))
                GOTO(out_pop, rc = PTR_ERR(dentry));

        lock_kernel();

        /* setting objects attributes (including owner/group) */
        rc = filter_setattr_internal(exp, dentry, oa, oti);
        if (rc)
                GOTO(out_unlock, rc);

        res = ldlm_resource_get(exp->exp_obd->obd_namespace, NULL,
                                res_id, LDLM_EXTENT, 0);
        
        if (res != NULL) {
                ns_lvbo = res->lr_namespace->ns_lvbo;
                if (ns_lvbo && ns_lvbo->lvbo_update)
                        rc = ns_lvbo->lvbo_update(res, NULL, 0, 0);
                ldlm_resource_putref(res);
        }

        oa->o_valid = OBD_MD_FLID;
        
        /* Quota release need uid/gid info */
        obdo_from_inode(oa, dentry->d_inode,
                        FILTER_VALID_FLAGS | OBD_MD_FLUID | OBD_MD_FLGID);

        EXIT;
out_unlock:
        unlock_kernel();
        f_dput(dentry);
out_pop:
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
                OBD_FREE(*lsmp, lsm_size);
                *lsmp = NULL;
                RETURN(0);
        }

        if (*lsmp == NULL) {
                OBD_ALLOC(*lsmp, lsm_size);
                if (*lsmp == NULL)
                        RETURN(-ENOMEM);

                loi_init((*lsmp)->lsm_oinfo);
        }

        if (lmm != NULL) {
                /* XXX zero *lsmp? */
                (*lsmp)->lsm_object_id = le64_to_cpu (lmm->lmm_object_id);
                LASSERT((*lsmp)->lsm_object_id);
        }

        (*lsmp)->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES;

        RETURN(lsm_size);
}

static int filter_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                         unsigned long max_age)
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

        osfs->os_bavail -= min(osfs->os_bavail,
                               (filter->fo_tot_dirty + filter->fo_tot_pending +
                                osfs->os_bsize - 1) >> blockbits);

        /* set EROFS to state field if FS is mounted as RDONLY. The goal is to
         * stop creating files on MDS if OST is not good shape to create
         * objects.*/
        osfs->os_state = (filter->fo_obt.obt_sb->s_flags & MS_RDONLY) ? 
                EROFS : 0;
        RETURN(rc);
}

struct dentry *
filter_create_object(struct obd_device *obd, struct obdo *oa)
{
        struct dentry *dparent = NULL;
        struct dentry *dchild = NULL;
        struct lvfs_ucred uc = {0,};
        struct lvfs_run_ctxt saved;
        struct filter_obd *filter;
        int cleanup_phase = 0;
        int err = 0, rc = 0;
        void *handle = NULL;
        obd_gr group = 0;
        ENTRY;

        filter = &obd->u.filter;

        CDEBUG(D_INFO, "create objid "LPU64"\n", oa->o_id);

        if (oa->o_valid & OBD_MD_FLGROUP)
                group = oa->o_gr;

        dparent = filter_parent_lock(obd, group, oa->o_id);
        if (IS_ERR(dparent))
                GOTO(cleanup, dchild = dparent);
        cleanup_phase = 1;

        /* check if object is in blacklist. This should be done under parent
         * lock. */
        spin_lock(&filter->fo_blacklist_lock);
        if (oa->o_id > filter->fo_blacklist[group].fe_start &&
            oa->o_id <= filter->fo_blacklist[group].fe_end) {
                spin_unlock(&filter->fo_blacklist_lock);
                GOTO(cleanup, dchild = ERR_PTR(-ENOENT));
        }
        spin_unlock(&filter->fo_blacklist_lock);

        /* check if object is already allocated */
        dchild = filter_fid2dentry(obd, dparent, 
				   group, oa->o_id);
        if (IS_ERR(dchild))
                GOTO(cleanup, dchild);

        if (dchild->d_inode)
                GOTO(cleanup, dchild);

        /* create new object */
        handle = fsfilt_start_log(obd, dparent->d_inode,
                                  FSFILT_OP_CREATE, NULL, 1);
        if (IS_ERR(handle))
                GOTO(cleanup, dchild = handle);
        cleanup_phase = 2;

        uc.luc_fsuid = oa->o_valid & OBD_MD_FLUID ?
                oa->o_uid : 0;
        uc.luc_fsgid = oa->o_valid & OBD_MD_FLGID ?
                oa->o_gid : 0;
        uc.luc_cap = current->cap_effective;

        cap_raise(uc.luc_cap, CAP_SYS_RESOURCE);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        rc = ll_vfs_create(dparent->d_inode, dchild, S_IFREG, NULL);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);

        if (rc) {
                CERROR("create failed rc = %d\n", rc);
                f_dput(dchild);
                GOTO(cleanup, dchild = ERR_PTR(rc));
        }

        /* grow last created object id. */
        filter_grow_last_id(filter, group, oa->o_id);
        rc = filter_update_last_objid(obd, group, 0);
        if (rc) {
                CERROR("unable to write lastobjid, but "
                       "object is created, err = %d\n",
                       rc);
                rc = 0;
        }

        /* nobody else is touching this newly created object */
        LASSERT(dchild->d_inode);
        
        if (oa->o_valid & OBD_MD_FLFID) {
                struct ll_fid fid;

                /* packing fid and converting it to LE for storing into EA. Here
                 * oa->o_stripe_idx should be filled by LOV and rest of fields -
                 * by client. */
                fid.id = cpu_to_le64(oa->o_fid);
                fid.f_type = cpu_to_le32(oa->o_stripe_idx);
                fid.generation = cpu_to_le32(oa->o_generation);

                down(&dchild->d_inode->i_sem);
                rc = fsfilt_set_md(obd, dchild->d_inode, handle,
                                   &fid, sizeof(struct ll_fid));
                up(&dchild->d_inode->i_sem);
                if (rc) {
                        CERROR("store fid in object failed! rc:%d\n", rc);
                        f_dput(dchild);
                        GOTO(cleanup, dchild = ERR_PTR(rc));
                }
        } else {
                CDEBUG(D_HA, "create OSS object without fid!\n");
        }

cleanup:
        switch(cleanup_phase) {
        case 2:
                err = fsfilt_commit(obd, dparent->d_inode, handle, 0);
                if (err) {
                        CERROR("error on commit, err = %d\n", err);
                        if (!rc) {
                                rc = err;
                                f_dput(dchild);
                                dchild = ERR_PTR(rc);
                        }
                }
        case 1:
                filter_parent_unlock(obd, dparent);
        case 0:
                break;
        }

        RETURN(dchild);
}

struct dentry *
filter_crow_object(struct obd_device *obd, struct obdo *oa)
{
        struct filter_obd *filter;
        struct dentry *dentry;
        obd_gr group = 0;
        ENTRY;

        if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_CROW_EIO))
                RETURN(ERR_PTR(-EIO));
        
        filter = &obd->u.filter;

        if (oa->o_valid & OBD_MD_FLGROUP)
                group = oa->o_gr;

        /* try to create new object (if it is not yet) */
        dentry = filter_create_object(obd, oa);
        if (IS_ERR(dentry)) {
                CERROR("cannot create OSS object "LPU64"/"LPU64
                       ", err = %d\n", oa->o_id, group,
                       (int)PTR_ERR(dentry));
                RETURN(dentry);
        }

        RETURN(dentry);
}

/* destroys object @oa. Takes care of locking if @lock says that parent is not
 * yet locked. Also drops parent lock before taking ldlm PW lock to avoid
 * deadlocks in lock retraction related paths.
 *
 * This function does not change locking and does not imply hiden locking
 * knowladge. After this fucntion is finished, all parents stay at the same
 * locking state.

 * If @lock == 1, this means that parent of @oa is not locked and should be
 * locked for destroy operation. However, after operation is finished, parent
 * will be unlocked. The same is true about opposite case, when parent is
 * already locked and filter_destroy_internal() does not need to lock it. */
static int
filter_destroy_internal(struct obd_export *exp, struct obdo *oa,
                        struct lov_stripe_md *md, struct obd_trans_info *oti,
                        int lock)
{
        struct obd_device *obd;
        struct filter_obd *filter;
        struct dentry *dchild = NULL, *dparent = NULL;
        struct lvfs_run_ctxt saved;
        void *handle = NULL;
        struct llog_cookie *fcc = NULL;
        int rc, rc2, cleanup_phase = 0, have_prepared = 0;
        unsigned int qcids[MAXQUOTAS] = {0, 0};
        obd_gr group = 0;
        ENTRY;

        if (oa->o_valid & OBD_MD_FLGROUP)
                group = oa->o_gr;

        obd = exp->exp_obd;
        filter = &obd->u.filter;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

 acquire_locks:
        dparent = lock ?
                filter_parent_lock(obd, group, oa->o_id):
                filter_parent(obd, group, oa->o_id);
        if (IS_ERR(dparent))
                GOTO(cleanup, rc = PTR_ERR(dparent));
        cleanup_phase = 1;

        dchild = filter_fid2dentry(obd, dparent, group, oa->o_id);
        if (IS_ERR(dchild))
                GOTO(cleanup, rc = PTR_ERR(dchild));
        cleanup_phase = 2;

        if (dchild->d_inode == NULL) {
                CDEBUG(D_INODE, "destroying non-existent object "LPU64"\n",
                       oa->o_id);
                /* If object already gone, cancel cookie right now */
                if (oa->o_valid & OBD_MD_FLCOOKIE) {
                        fcc = obdo_logcookie(oa);
                        llog_cancel(llog_get_context(obd, fcc->lgc_subsys + 1),
                                    NULL, 1, fcc, 0);
                }
                GOTO(cleanup, rc = -ENOENT);
        }

        if (!have_prepared) {
                /* If we're really going to destroy the object, get ready by
                 * getting the clients to discard their cached data.
                 *
                 * We have to drop the parent lock, because
                 * filter_prepare_destroy() will acquire a PW on the object, and
                 * we don't want to deadlock with an incoming write to the
                 * object, which has the extent PW and then wants to get the
                 * parent dentry to do the lookup.
                 *
                 * We dput the child because it's not worth the extra
                 * complication of condition the above code to skip it on the
                 * second time through. */
                f_dput(dchild);

                filter_unlock_dentry(obd, dparent);
                filter_prepare_destroy(obd, oa->o_id);

                /* lock parent dentry again, to keep locking state the same as
                 * before calling this function. */
                if (!lock)
                        filter_lock_dentry(obd, dparent);

                have_prepared = 1;
                goto acquire_locks;
        }

        handle = fsfilt_start_log(obd, dparent->d_inode,FSFILT_OP_UNLINK,oti,1);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));
        cleanup_phase = 3;

        /* Our MDC connection is established by the MDS to us */
        if (oa->o_valid & OBD_MD_FLCOOKIE) {
                OBD_ALLOC(fcc, sizeof(*fcc));
                if (fcc != NULL)
                        memcpy(fcc, obdo_logcookie(oa), sizeof(*fcc));
        }

        /* Quota release need uid/gid of inode */
        obdo_from_inode(oa, dchild->d_inode, OBD_MD_FLUID|OBD_MD_FLGID);
        rc = filter_unlink(obd, oa->o_id, dparent, dchild);

cleanup:
        switch(cleanup_phase) {
        case 3:
                if (fcc != NULL) {
                        fsfilt_add_journal_cb(obd, 0,
                                              oti ? oti->oti_handle : handle,
                                              filter_cancel_cookies_cb, fcc);
                }
                rc = filter_finish_transno(exp, oti, rc);
                rc2 = fsfilt_commit(obd, dparent->d_inode, handle, 0);
                if (rc2) {
                        CERROR("error on commit, err = %d\n", rc2);
                        if (!rc)
                                rc = rc2;
                }
        case 2:
                f_dput(dchild);
        case 1:
                if (lock)
                        filter_parent_unlock(obd, dparent);
        case 0:
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }

        /* trigger quota release */
        qcids[USRQUOTA] = oa->o_uid;
        qcids[GRPQUOTA] = oa->o_gid;
        rc2 = lquota_adjust(quota_interface, obd, qcids, NULL, rc,
                            FSFILT_OP_UNLINK); 
        CDEBUG(rc2 ? D_ERROR : D_QUOTA, 
               "filter adjust qunit! (rc:%d)\n", rc2);

        RETURN(rc);
}

/* destroy oject with taking lock on parent first. */
int filter_destroy(struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        int rc;

        ENTRY;
        rc = filter_destroy_internal(exp, oa, md, oti, 1);
        RETURN(rc);
}

static int
filter_clear_orphans(struct obd_export *exp, struct obdo *oa)
{
        struct filter_obd *filter;
        struct obd_device *obd;
        struct obdo *doa;
        obd_gr group = 0;
        int rc, orphans;
        __u64 last, id;
        ENTRY;

        LASSERT(oa);

        OBD_RACE(OBD_FAIL_OST_CLEAR_ORPHANS_RACE);

        obd = exp->exp_obd;
        filter = &obd->u.filter;

        if (oa->o_valid & OBD_MD_FLGROUP)
                group = oa->o_gr;

        filter->fo_destroy_in_progress = 1;
        
        LOCK_PARENTS(obd, group);
        if (!filter->fo_destroy_in_progress) {
                UNLOCK_PARENTS(obd, group);
                CDEBUG(D_HA, "cleanup orphans is already canceled\n");
                RETURN(0);
        }

        last = filter_last_id(filter, group);
        orphans = last - oa->o_id;
        
        if (orphans <= 0) {
                filter->fo_destroy_in_progress = 0;
                UNLOCK_PARENTS(obd, group);
                CDEBUG(D_HA, "nothing to cleanup, MDS objid "LPU64
                       " is not bigger than OST one "LPU64"\n",
                       oa->o_id, last);
                RETURN(0);
        }

        CDEBUG(D_HA, "adding orphans extent "LPU64":"LPU64"-"LPU64
               " to blacklist\n", group, oa->o_id, last);

        /* making all orphans entries in blacklist, that will deny to re-create
         * them by CROW in filter_create_object(). This is done for case when
         * orphans already exist on client and will be tried to write something
         * and we want to stop them.
         *
         * In fact the issue is even worse, as we want to put in blacklist not
         * only the objects which we just destroed, but also those which not yet
         * created on OST (and OST has no idea about) but possibly existing on
         * clients. */
        spin_lock(&filter->fo_blacklist_lock);
        filter->fo_blacklist[group].fe_start = oa->o_id;
        filter->fo_blacklist[group].fe_end = last;
        spin_unlock(&filter->fo_blacklist_lock);
        
	doa = obdo_alloc();
        if (doa == NULL) {
                filter->fo_destroy_in_progress = 0;
                UNLOCK_PARENTS(obd, group);
                RETURN(-ENOMEM);
        }

        doa->o_gr = group;
        doa->o_mode = S_IFREG;
        doa->o_valid = oa->o_valid & (OBD_MD_FLGROUP | OBD_MD_FLID);

        CDEBUG(D_ERROR, "%s:["LPU64"] deleting orphan objects from "LPU64" to "
              LPU64"\n", exp->exp_obd->obd_name, doa->o_gr, oa->o_id, last);

        for (id = last; id > oa->o_id; id--) {
                doa->o_id = id;

                /* remove object @doa. It will not lock parent as parents
                 * already locked. */
                filter_destroy_internal(exp, doa, NULL, NULL, 0);

                /* update last id just for case when OST will down in cleanup
                 * orphans time. */
                filter_set_last_id(filter, group, id);

                /* update last_id on disk periodicaly */
                if ((id & 1023) == 0)
                        filter_update_last_objid(obd, group, 0);
        }

        UNLOCK_PARENTS(obd, group);

        /* return next free id to be used as a new start of sequence. As we
         * return last id from OST, this will make sure that MDS will start new
         * sequence from object id which is far from existing and there will not
         * be object id sharing. */
        oa->o_id = last + 1;
        filter_set_last_id(filter, group, oa->o_id);

        CDEBUG(D_ERROR, "%s:["LPU64"] after destroy: set last_objids = "
               LPU64"\n", exp->exp_obd->obd_name, doa->o_gr, oa->o_id);

        rc = filter_update_last_objid(obd, group, 1);
        filter->fo_destroy_in_progress = 0;

        obdo_free(doa);
        RETURN(rc);
}

static int filter_create(struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct filter_export_data *fed;
        struct lvfs_run_ctxt saved;
        struct filter_obd *filter;
        obd_gr group = oa->o_gr;
        struct obd_device *obd;
        int rc = 0;
        ENTRY;

        obd = exp->exp_obd;
        fed = &exp->exp_filter_data;
        filter = &obd->u.filter;

        CDEBUG(D_INFO, "filter_create(od->o_gr="LPU64",od->o_id="LPU64")\n",
               group, oa->o_id);

        if (oa->o_valid & OBD_MD_FLFLAGS && oa->o_flags == OBD_FL_DELORPHAN) {
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                rc = filter_clear_orphans(exp, oa);
                if (rc) {
                        CERROR("cannot clear orphans starting from "
                               LPU64", err = %d\n", oa->o_id, rc);
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                RETURN(rc);
        }

        LASSERT(ergo(oa->o_valid & OBD_MD_FLFLAGS,
                     !!(oa->o_flags & OBD_FL_CREATE_CROW) !=
                     !!(oa->o_flags & OBD_FL_RECREATE_OBJS)));

        /* echo, llog and other "create asap" cases. */
        if (OBDO_URGENT_CREATE(oa)) {
                struct obd_statfs *osfs;
                struct dentry *dentry;
                
                /* check space first. As this is real create and client does not
                 * have yet file created, this is good place to check space. */
                OBD_ALLOC_PTR(osfs);
                if (!osfs)
                        RETURN(-ENOMEM);

                rc = filter_statfs(obd, osfs, jiffies - HZ);
                if (rc == 0 && osfs->os_bavail < (osfs->os_blocks >> 10)) {
                        CDEBUG(D_HA, "OST out of space! avail "LPU64"\n",
                               osfs->os_bavail << filter->fo_obt.obt_sb->s_blocksize_bits);
                        rc = -ENOSPC;
                }

                OBD_FREE_PTR(osfs);
                if (rc)
                        RETURN(rc);

                dentry = filter_create_object(obd, oa);
                if (!IS_ERR(dentry)) {
                        f_dput(dentry);
                        if (ea != NULL) {
                                struct lov_stripe_md *lsm = *ea;
                                if (lsm == NULL) {
                                        rc = obd_alloc_memmd(exp, &lsm);
                                        if (rc)
                                                RETURN(rc);
                                }
                                lsm->lsm_object_id = oa->o_id;
                                *ea = lsm;
                                rc = 0;
                        }
                }
        } else {
                CERROR("wrong @oa flags detected 0x%lx. Not an urgent "
                       "create and not recovery.\n", (unsigned long)oa->o_flags);
                LBUG();
        }
        RETURN(rc);
}

/* NB start and end are used for punch, but not truncate */
static int filter_truncate(struct obd_export *exp, struct obdo *oa,
                           struct lov_stripe_md *lsm, obd_off start,
                           obd_off end, struct obd_trans_info *oti)
{
        int rc;
        ENTRY;

        if (end != OBD_OBJECT_EOF)
                CERROR("PUNCH not supported, only truncate: end = "LPX64"\n",
                       end);

        CDEBUG(D_INODE, "calling truncate for object "LPU64", valid = "LPX64
               ", o_size = "LPD64"\n", oa->o_id, oa->o_valid, start);
        
        oa->o_size = start;
        rc = filter_setattr(exp, oa, NULL, oti);
        RETURN(rc);
}

static int filter_sync(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *lsm, obd_off start, obd_off end)
{
        struct lvfs_run_ctxt saved;
        struct filter_obd *filter;
        struct dentry *dentry;
        struct llog_ctxt *ctxt;
        int rc, rc2;
        ENTRY;

        filter = &exp->exp_obd->u.filter;

        /* an objid of zero is taken to mean "sync whole filesystem" */
        if (!oa || !(oa->o_valid & OBD_MD_FLID)) {
                rc = fsfilt_sync(exp->exp_obd, filter->fo_obt.obt_sb);
                /* flush any remaining cancel messages out to the target */
                ctxt = llog_get_context(exp->exp_obd, LLOG_MDS_OST_REPL_CTXT);
                llog_sync(ctxt, exp);
                RETURN(rc);
        }

        dentry = filter_oa2dentry(exp->exp_obd, oa);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);

        down(&dentry->d_inode->i_sem);
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
        up(&dentry->d_inode->i_sem);

        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa, dentry->d_inode, FILTER_VALID_FLAGS);

        pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);

        f_dput(dentry);
        RETURN(rc);
}

static int filter_get_info(struct obd_export *exp, __u32 keylen,
                           void *key, __u32 *vallen, void *val)
{
        struct obd_device *obd;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client export %p\n", exp);
                RETURN(-EINVAL);
        }

        if (keylen == strlen("blocksize") &&
            memcmp(key, "blocksize", keylen) == 0) {
                __u32 *blocksize = val;
                *vallen = sizeof(*blocksize);
                *blocksize = obd->u.obt.obt_sb->s_blocksize;
                RETURN(0);
        }

        if (keylen == strlen("blocksize_bits") &&
            memcmp(key, "blocksize_bits", keylen) == 0) {
                __u32 *blocksize_bits = val;
                *vallen = sizeof(*blocksize_bits);
                *blocksize_bits = obd->u.obt.obt_sb->s_blocksize_bits;
                RETURN(0);
        }

        if (keylen >= strlen("last_id") && memcmp(key, "last_id", 7) == 0) {
                obd_id *last_id = val;
                /* FIXME: object groups */
                *last_id = filter_last_id(&obd->u.filter, 0);
                RETURN(0);
        }
        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
}

static int filter_set_info(struct obd_export *exp, __u32 keylen,
                           void *key, __u32 vallen, void *val)
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

        if (keylen < strlen("mds_conn") ||
            memcmp(key, "mds_conn", keylen) != 0)
                RETURN(-EINVAL);

        CWARN("%s: received MDS connection from %s\n", obd->obd_name,
              obd_export_nid2str(exp));
        obd->u.filter.fo_mdc_conn.cookie = exp->exp_handle.h_cookie;

        /* setup llog imports */
        ctxt = llog_get_context(obd, LLOG_MDS_OST_REPL_CTXT);
        rc = llog_receptor_accept(ctxt, exp->exp_imp_reverse);
        
        lquota_setinfo(quota_interface, exp, obd);

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
                CDEBUG(D_HA, "syncing ost %s\n", obd->obd_name);
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

                lvfs_set_rdonly(lvfs_sbdev(obd->u.obt.obt_sb));
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
        int rc = 0;

        /*
         * health_check to return 0 on healthy
         * and 1 on unhealthy.
         */
        if(obd->u.obt.obt_sb->s_flags & MS_RDONLY)
                rc = 1;

        return rc;
}

static struct dentry *filter_lvfs_fid2dentry(__u64 id, __u32 gen, __u64 gr,
                                             void *data)
{
        return filter_fid2dentry(data, NULL, gr, id);
}

static struct lvfs_callback_ops filter_lvfs_ops = {
        l_fid2dentry:     filter_lvfs_fid2dentry,
};

static struct obd_ops filter_obd_ops = {
        .o_owner          = THIS_MODULE,
        .o_get_info       = filter_get_info,
        .o_set_info       = filter_set_info,
        .o_setup          = filter_setup,
        .o_precleanup     = filter_precleanup,
        .o_cleanup        = filter_cleanup,
        .o_connect        = filter_connect,
        .o_disconnect     = filter_disconnect,
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
        .o_destroy_export = filter_destroy_export,
        .o_llog_init      = filter_llog_init,
        .o_llog_finish    = filter_llog_finish,
        .o_iocontrol      = filter_iocontrol,
        .o_health_check   = filter_health_check,
};

static struct obd_ops filter_sanobd_ops = {
        .o_owner          = THIS_MODULE,
        .o_get_info       = filter_get_info,
        .o_set_info       = filter_set_info,
        .o_setup          = filter_san_setup,
        .o_precleanup     = filter_precleanup,
        .o_cleanup        = filter_cleanup,
        .o_connect        = filter_connect,
        .o_disconnect     = filter_disconnect,
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
        .o_san_preprw     = filter_san_preprw,
        .o_destroy_export = filter_destroy_export,
        .o_llog_init      = filter_llog_init,
        .o_llog_finish    = filter_llog_finish,
        .o_iocontrol      = filter_iocontrol,
};

quota_interface_t *quota_interface = NULL;
extern quota_interface_t filter_quota_interface;

static int __init obdfilter_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        printk(KERN_INFO "Lustre: Filtering OBD driver; info@clusterfs.com\n");

        lprocfs_init_vars(filter, &lvars);

        OBD_ALLOC(obdfilter_created_scratchpad,
                  OBDFILTER_CREATED_SCRATCHPAD_ENTRIES *
                  sizeof(*obdfilter_created_scratchpad));
        if (obdfilter_created_scratchpad == NULL)
                return -ENOMEM;

        quota_interface = PORTAL_SYMBOL_GET(filter_quota_interface);
        init_obd_quota_ops(quota_interface, &filter_obd_ops);
        init_obd_quota_ops(quota_interface, &filter_sanobd_ops);

        rc = class_register_type(&filter_obd_ops, lvars.module_vars,
                                 OBD_FILTER_DEVICENAME);
        if (rc)
                GOTO(out, rc);

        rc = class_register_type(&filter_sanobd_ops, lvars.module_vars,
                                 OBD_FILTER_SAN_DEVICENAME);
        if (rc) {
                class_unregister_type(OBD_FILTER_DEVICENAME);
out:
                if (quota_interface)
                        PORTAL_SYMBOL_PUT(filter_quota_interface);
                        
                OBD_FREE(obdfilter_created_scratchpad,
                         OBDFILTER_CREATED_SCRATCHPAD_ENTRIES *
                         sizeof(*obdfilter_created_scratchpad));
        } 

        return rc;
}

static void __exit obdfilter_exit(void)
{
        if (quota_interface)
                PORTAL_SYMBOL_PUT(filter_quota_interface);

        class_unregister_type(OBD_FILTER_SAN_DEVICENAME);
        class_unregister_type(OBD_FILTER_DEVICENAME);
        OBD_FREE(obdfilter_created_scratchpad,
                 OBDFILTER_CREATED_SCRATCHPAD_ENTRIES *
                 sizeof(*obdfilter_created_scratchpad));
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Filtering OBD driver");
MODULE_LICENSE("GPL");

module_init(obdfilter_init);
module_exit(obdfilter_exit);
