/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  mds/mds_fs.c
 *  Lustre Metadata Server (MDS) filesystem interface code
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/mount.h>
#endif
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_fsfilt.h>
#include <portals/list.h>

#include "mds_internal.h"

/* This limit is arbitrary, but for now we fit it in 1 page (32k clients) */
#define MDS_MAX_CLIENTS (PAGE_SIZE * 8)
#define MDS_MAX_CLIENT_WORDS (MDS_MAX_CLIENTS / sizeof(unsigned long))

#define LAST_RCVD "last_rcvd"

/* Add client data to the MDS.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_off is -1 (i.e. a new client).
 * Otherwise, we have just read the data from the last_rcvd file and
 * we know its offset.
 */
int mds_client_add(struct obd_device *obd, struct mds_obd *mds,
                   struct mds_export_data *med, int cl_idx)
{
        unsigned long *bitmap = mds->mds_client_bitmap;
        int new_client = (cl_idx == -1);

        LASSERT(bitmap != NULL);

        /* XXX if mcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp(med->med_mcd->mcd_uuid, "OBD_CLASS_UUID"))
                RETURN(0);

        /* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        if (new_client) {
                cl_idx = find_first_zero_bit(bitmap, MDS_MAX_CLIENTS);
        repeat:
                if (cl_idx >= MDS_MAX_CLIENTS) {
                        CERROR("no room for clients - fix MDS_MAX_CLIENTS\n");
                        return -ENOMEM;
                }
                if (test_and_set_bit(cl_idx, bitmap)) {
                        CERROR("MDS client %d: found bit is set in bitmap\n",
                               cl_idx);
                        cl_idx = find_next_zero_bit(bitmap, MDS_MAX_CLIENTS,
                                                    cl_idx);
                        goto repeat;
                }
        } else {
                if (test_and_set_bit(cl_idx, bitmap)) {
                        CERROR("MDS client %d: bit already set in bitmap!!\n",
                               cl_idx);
                        LBUG();
                }
        }

        CDEBUG(D_INFO, "client at index %d with UUID '%s' added\n",
               cl_idx, med->med_mcd->mcd_uuid);

        med->med_idx = cl_idx;
        med->med_off = MDS_LR_CLIENT_START + (cl_idx * MDS_LR_CLIENT_SIZE);

        if (new_client) {
                struct obd_run_ctxt saved;
                loff_t off = med->med_off;
                ssize_t written;
                void *handle;

                push_ctxt(&saved, &mds->mds_ctxt, NULL);
                /* We need to start a transaction here first, to avoid a
                 * possible ordering deadlock on last_rcvd->i_sem and the
                 * journal lock. In most places we start the journal handle
                 * first (because we do compound transactions), and then
                 * later do the write into last_rcvd, which gets i_sem.
                 *
                 * Without this transaction, clients connecting at the same
                 * time other MDS operations are ongoing get last_rcvd->i_sem
                 * first (in generic_file_write()) and start the journal
                 * transaction afterwards, and can deadlock with other ops.
                 *
                 * We use FSFILT_OP_SETATTR because it is smallest, but all
                 * ops include enough space for the last_rcvd update so we
                 * could use any of them, or maybe an FSFILT_OP_NONE is best?
                 */
                handle = fsfilt_start(obd,mds->mds_rcvd_filp->f_dentry->d_inode,
                                      FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle)) {
                        written = PTR_ERR(handle);
                        CERROR("unable to start transaction: rc %d\n",
                               (int)written);
                } else {
                        written = fsfilt_write_record(obd, mds->mds_rcvd_filp,
                                                      med->med_mcd,
                                                      sizeof(*med->med_mcd),
                                                      &off);
                        fsfilt_commit(obd,mds->mds_rcvd_filp->f_dentry->d_inode,
                                      handle, 0);
                }
                pop_ctxt(&saved, &mds->mds_ctxt, NULL);

                if (written != sizeof(*med->med_mcd)) {
                        if (written < 0)
                                RETURN(written);
                        RETURN(-EIO);
                }
                CDEBUG(D_INFO, "wrote client mcd at idx %u off %llu (len %u)\n",
                       med->med_idx, med->med_off,
                       (unsigned int)sizeof(*med->med_mcd));
        }
        return 0;
}

int mds_client_free(struct obd_export *exp)
{
        struct mds_export_data *med = &exp->exp_mds_data;
        struct mds_obd *mds = &exp->exp_obd->u.mds;
        struct obd_device *obd = exp->exp_obd;
        struct mds_client_data zero_mcd;
        struct obd_run_ctxt saved;
        int written;
        unsigned long *bitmap = mds->mds_client_bitmap;

        LASSERT(bitmap);
        if (!med->med_mcd)
                RETURN(0);

        /* XXX if mcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp(med->med_mcd->mcd_uuid, "OBD_CLASS_UUID"))
                GOTO(free_and_out, 0);

        CDEBUG(D_INFO, "freeing client at index %u (%lld)with UUID '%s'\n",
               med->med_idx, med->med_off, med->med_mcd->mcd_uuid);

        if (!test_and_clear_bit(med->med_idx, bitmap)) {
                CERROR("MDS client %u: bit already clear in bitmap!!\n",
                       med->med_idx);
                LBUG();
        }

        memset(&zero_mcd, 0, sizeof zero_mcd);
        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        written = fsfilt_write_record(obd, mds->mds_rcvd_filp, &zero_mcd,
                                      sizeof(zero_mcd), &med->med_off);
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);

        if (written != sizeof(zero_mcd)) {
                CERROR("error zeroing out client %s index %d in %s: %d\n",
                       med->med_mcd->mcd_uuid, med->med_idx, LAST_RCVD,
                       written);
        } else {
                CDEBUG(D_INFO, "zeroed out disconnecting client %s at off %d\n",
                       med->med_mcd->mcd_uuid, med->med_idx);
        }

 free_and_out:
        OBD_FREE(med->med_mcd, sizeof(*med->med_mcd));

        return 0;
}

static int mds_server_free_data(struct mds_obd *mds)
{
        OBD_FREE(mds->mds_client_bitmap,
                 MDS_MAX_CLIENT_WORDS * sizeof(unsigned long));
        OBD_FREE(mds->mds_server_data, sizeof(*mds->mds_server_data));
        mds->mds_server_data = NULL;

        return 0;
}

static int mds_read_last_rcvd(struct obd_device *obd, struct file *file)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mds_server_data *msd;
        struct mds_client_data *mcd = NULL;
        loff_t off = 0;
        int cl_idx;
        unsigned long last_rcvd_size = file->f_dentry->d_inode->i_size;
        __u64 last_transno = 0;
        __u64 mount_count;
        int rc = 0;

        LASSERT(sizeof(struct mds_client_data) == MDS_LR_CLIENT_SIZE);
        LASSERT(sizeof(struct mds_server_data) <= MDS_LR_SERVER_SIZE);

        OBD_ALLOC(msd, sizeof(*msd));
        if (!msd)
                RETURN(-ENOMEM);

        OBD_ALLOC(mds->mds_client_bitmap,
                  MDS_MAX_CLIENT_WORDS * sizeof(unsigned long));
        if (!mds->mds_client_bitmap) {
                OBD_FREE(msd, sizeof(*msd));
                RETURN(-ENOMEM);
        }

        mds->mds_server_data = msd;

        if (last_rcvd_size == 0) {
                int written;
                CWARN("%s: initializing new %s\n", obd->obd_name, LAST_RCVD);
                memcpy(msd->msd_uuid, obd->obd_uuid.uuid,sizeof(msd->msd_uuid));
                msd->msd_server_size = cpu_to_le32(MDS_LR_SERVER_SIZE);
                msd->msd_client_start = cpu_to_le32(MDS_LR_CLIENT_START);
                msd->msd_client_size = cpu_to_le16(MDS_LR_CLIENT_SIZE);
                written = fsfilt_write_record(obd, file, msd, sizeof(*msd),
                                              &off);

                if (written == sizeof(*msd))
                        RETURN(0);
                CERROR("%s: error writing new MSD: %d\n", obd->obd_name,
                       written);
                GOTO(err_msd, rc = (written < 0 ? written : -EIO));
        }

        rc = fsfilt_read_record(obd, file, msd, sizeof(*msd), &off);

        if (rc != sizeof(*msd)) {
                CERROR("error reading MDS %s: rc = %d\n", LAST_RCVD,rc);
                if (rc > 0)
                        rc = -EIO;
                GOTO(err_msd, rc);
        }
        if (!msd->msd_server_size)
                msd->msd_server_size = cpu_to_le32(MDS_LR_SERVER_SIZE);
        if (!msd->msd_client_start)
                msd->msd_client_start = cpu_to_le32(MDS_LR_CLIENT_START);
        if (!msd->msd_client_size)
                msd->msd_client_size = cpu_to_le16(MDS_LR_CLIENT_SIZE);

        if (msd->msd_feature_incompat) {
                CERROR("unsupported incompat feature %x\n",
                       le32_to_cpu(msd->msd_feature_incompat));
                GOTO(err_msd, rc = -EINVAL);
        }
        if (msd->msd_feature_rocompat) {
                CERROR("unsupported read-only feature %x\n",
                       le32_to_cpu(msd->msd_feature_rocompat));
                /* Do something like remount filesystem read-only */
                GOTO(err_msd, rc = -EINVAL);
        }

        last_transno = le64_to_cpu(msd->msd_last_transno);
        mds->mds_last_transno = last_transno;

        mount_count = le64_to_cpu(msd->msd_mount_count);
        mds->mds_mount_count = mount_count;

        CDEBUG(D_INODE, "%s: server last_transno: "LPU64"\n",
               obd->obd_name, last_transno);
        CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
               obd->obd_name, mount_count);
        CDEBUG(D_INODE, "%s: server data size: %u\n",
               obd->obd_name, le32_to_cpu(msd->msd_server_size));
        CDEBUG(D_INODE, "%s: per-client data start: %u\n",
               obd->obd_name, le32_to_cpu(msd->msd_client_start));
        CDEBUG(D_INODE, "%s: per-client data size: %u\n",
               obd->obd_name, le32_to_cpu(msd->msd_client_size));
        CDEBUG(D_INODE, "%s: last_rcvd size: %lu\n",
               obd->obd_name, last_rcvd_size);
        CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", obd->obd_name,
               (last_rcvd_size - MDS_LR_CLIENT_START) / MDS_LR_CLIENT_SIZE);

        /* When we do a clean FILTER shutdown, we save the last_transno into
         * the header.  If we find clients with higher last_transno values
         * then those clients may need recovery done. */
        for (cl_idx = 0; off < last_rcvd_size; cl_idx++) {
                __u64 last_transno;
                int mount_age;

                if (!mcd) {
                        OBD_ALLOC(mcd, sizeof(*mcd));
                        if (!mcd)
                                GOTO(err_msd, rc = -ENOMEM);
                }

                /* Don't assume off is incremented properly, in case
                 * sizeof(fsd) isn't the same as fsd->fsd_client_size.
                 */
                off = le32_to_cpu(msd->msd_client_start) +
                        cl_idx * le16_to_cpu(msd->msd_client_size);
                rc = fsfilt_read_record(obd, file, mcd, sizeof(*mcd), &off);
                if (rc != sizeof(*mcd)) {
                        CERROR("error reading MDS %s offset %d: rc = %d\n",
                               LAST_RCVD, cl_idx, rc);
                        if (rc > 0) /* XXX fatal error or just abort reading? */
                                rc = -EIO;
                        break;
                }

                if (mcd->mcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_idx);
                        continue;
                }

                last_transno = le64_to_cpu(mcd->mcd_last_transno);

                /* These exports are cleaned up by mds_disconnect(), so they
                 * need to be set up like real exports as mds_connect() does.
                 */
                mount_age = mount_count - le64_to_cpu(mcd->mcd_mount_count);
                if (mount_age < MDS_MOUNT_RECOV) {
                        struct obd_export *exp = class_new_export(obd);
                        struct mds_export_data *med;
                        CERROR("RCVRNG CLIENT uuid: %s off: %d lr: "LPU64
                               "srv lr: "LPU64" mnt: "LPU64" last mount: "LPU64
                               "\n", mcd->mcd_uuid, cl_idx,
                               last_transno, le64_to_cpu(msd->msd_last_transno),
                               le64_to_cpu(mcd->mcd_mount_count), mount_count);

                        if (!exp) {
                                rc = -ENOMEM;
                                break;
                        }

                        memcpy(&exp->exp_client_uuid.uuid, mcd->mcd_uuid,
                               sizeof exp->exp_client_uuid.uuid);
                        med = &exp->exp_mds_data;
                        med->med_mcd = mcd;
                        mds_client_add(obd, mds, med, cl_idx);
                        /* create helper if export init gets more complex */
                        INIT_LIST_HEAD(&med->med_open_head);
                        spin_lock_init(&med->med_open_lock);

                        mcd = NULL;
                        obd->obd_recoverable_clients++;
                        class_export_put(exp);
                } else {
                        CDEBUG(D_INFO, "discarded client %d, UUID '%s', count "
                               LPU64"\n", cl_idx, mcd->mcd_uuid,
                               le64_to_cpu(mcd->mcd_mount_count));
                }

                CDEBUG(D_OTHER, "client at offset %d has last_transno = "
                       LPU64"\n", cl_idx, last_transno);

                if (last_transno > mds->mds_last_transno)
                        mds->mds_last_transno = last_transno;
        }

        obd->obd_last_committed = mds->mds_last_transno;
        if (obd->obd_recoverable_clients) {
                CERROR("RECOVERY: %d recoverable clients, last_transno "
                       LPU64"\n",
                       obd->obd_recoverable_clients, mds->mds_last_transno);
                obd->obd_next_recovery_transno = obd->obd_last_committed
                        + 1;
                obd->obd_recovering = 1;
        }

        if (mcd)
                OBD_FREE(mcd, sizeof(*mcd));

        return 0;

err_msd:
        mds_server_free_data(mds);
        return rc;
}

static int mds_fs_prep(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_run_ctxt saved;
        struct dentry *dentry;
        struct file *file;
        int rc;

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        dentry = simple_mkdir(current->fs->pwd, "ROOT", 0755);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create ROOT directory: rc = %d\n", rc);
                GOTO(err_pop, rc);
        }

        mds->mds_rootfid.id = dentry->d_inode->i_ino;
        mds->mds_rootfid.generation = dentry->d_inode->i_generation;
        mds->mds_rootfid.f_type = S_IFDIR;

        dput(dentry);

        dentry = lookup_one_len("__iopen__", current->fs->pwd,
                                strlen("__iopen__"));
        if (IS_ERR(dentry) || !dentry->d_inode) {
                rc = (IS_ERR(dentry)) ? PTR_ERR(dentry): -ENOENT;
                CERROR("cannot open iopen FH directory: rc = %d\n", rc);
                GOTO(err_pop, rc);
        }
        mds->mds_fid_de = dentry;

        dentry = simple_mkdir(current->fs->pwd, "PENDING", 0777);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create PENDING directory: rc = %d\n", rc);
                GOTO(err_fid, rc);
        }
        mds->mds_pending_dir = dentry;

        dentry = simple_mkdir(current->fs->pwd, "LOGS", 0700);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create LOGS directory: rc = %d\n", rc);
                GOTO(err_pending, rc);
        }
        mds->mds_logs_dir = dentry;

        file = filp_open(LAST_RCVD, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open/create %s file: rc = %d\n", LAST_RCVD, rc);

                GOTO(err_logs, rc = PTR_ERR(file));
        }
        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LAST_RCVD,
                       file->f_dentry->d_inode->i_mode);
                GOTO(err_filp, rc = -ENOENT);
        }

        rc = fsfilt_journal_data(obd, file);
        if (rc) {
                CERROR("cannot journal data on %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_filp, rc);
        }

        rc = mds_read_last_rcvd(obd, file);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_client, rc);
        }
        mds->mds_rcvd_filp = file;
#ifdef I_SKIP_PDFLUSH
        /*
         * we need this to protect from deadlock
         * pdflush vs. lustre_fwrite()
         */
        file->f_dentry->d_inode->i_flags |= I_SKIP_PDFLUSH;
#endif
err_pop:
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);

        return rc;

err_client:
        class_disconnect_exports(obd, 0);
err_filp:
        if (filp_close(file, 0))
                CERROR("can't close %s after error\n", LAST_RCVD);
err_logs:
        dput(mds->mds_logs_dir);
err_pending:
        dput(mds->mds_pending_dir);
err_fid:
        dput(mds->mds_fid_de);
        goto err_pop;
}

int mds_fs_setup(struct obd_device *obd, struct vfsmount *mnt)
{
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        mds->mds_vfsmnt = mnt;

        OBD_SET_CTXT_MAGIC(&mds->mds_ctxt);
        mds->mds_ctxt.pwdmnt = mnt;
        mds->mds_ctxt.pwd = mnt->mnt_root;
        mds->mds_ctxt.fs = get_ds();
        RETURN(mds_fs_prep(obd));
}

int mds_fs_cleanup(struct obd_device *obd, int flags)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_run_ctxt saved;
        int rc = 0;

        if (flags & OBD_OPT_FAILOVER)
                CERROR("%s: shutting down for failover; client state will"
                       " be preserved.\n", obd->obd_name);

        class_disconnect_exports(obd, flags); /* cleans up client info too */
        mds_server_free_data(mds);

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        if (mds->mds_rcvd_filp) {
                rc = filp_close(mds->mds_rcvd_filp, 0);
                mds->mds_rcvd_filp = NULL;
                if (rc)
                        CERROR("%s file won't close, rc=%d\n", LAST_RCVD, rc);
        }
        if (mds->mds_logs_dir) {
                l_dput(mds->mds_logs_dir);
                mds->mds_logs_dir = NULL;
        }
        if (mds->mds_pending_dir) {
                l_dput(mds->mds_pending_dir);
                mds->mds_pending_dir = NULL;
        }
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);
        shrink_dcache_parent(mds->mds_fid_de);
        dput(mds->mds_fid_de);

        return rc;
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
int mds_log_close(struct llog_handle *cathandle, struct llog_handle *loghandle)
{
        struct llog_object_hdr *llh = loghandle->lgh_hdr;
        struct mds_obd *mds = &cathandle->lgh_obd->u.mds;
        struct dentry *dchild = NULL;
        int rc;
        ENTRY;

        /* If we are going to delete this log, grab a ref before we close
         * it so we don't have to immediately do another lookup.
         */
        if (llh->llh_hdr.lth_type != LLOG_CATALOG_MAGIC && llh->llh_count == 0){
                CDEBUG(D_INODE, "deleting log file "LPX64":%x\n",
                       loghandle->lgh_cookie.lgc_lgl.lgl_oid,
                       loghandle->lgh_cookie.lgc_lgl.lgl_ogen);
                down(&mds->mds_logs_dir->d_inode->i_sem);
                dchild = dget(loghandle->lgh_file->f_dentry);
                llog_delete_log(cathandle, loghandle);
        } else {
                CDEBUG(D_INODE, "closing log file "LPX64":%x\n",
                       loghandle->lgh_cookie.lgc_lgl.lgl_oid,
                       loghandle->lgh_cookie.lgc_lgl.lgl_ogen);
        }

        rc = filp_close(loghandle->lgh_file, 0);

        llog_free_handle(loghandle); /* also removes loghandle from list */

        if (dchild) {
                int err = vfs_unlink(mds->mds_logs_dir->d_inode, dchild);
                if (err) {
                        CERROR("error unlinking empty log %*s: rc %d\n",
                               dchild->d_name.len, dchild->d_name.name, err);
                        if (!rc)
                                rc = err;
                }
                l_dput(dchild);
                up(&mds->mds_logs_dir->d_inode->i_sem);
        }
        RETURN(rc);
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
struct llog_handle *mds_log_open(struct obd_device *obd,
                                 struct llog_cookie *logcookie)
{
        struct ll_fid fid = { .id = logcookie->lgc_lgl.lgl_oid,
                              .generation = logcookie->lgc_lgl.lgl_ogen,
                              .f_type = S_IFREG };
        struct llog_handle *loghandle;
        struct dentry *dchild;
        int rc;
        ENTRY;

        loghandle = llog_alloc_handle();
        if (loghandle == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        down(&obd->u.mds.mds_logs_dir->d_inode->i_sem);
        dchild = mds_fid2dentry(&obd->u.mds, &fid, NULL);
        up(&obd->u.mds.mds_logs_dir->d_inode->i_sem);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                CERROR("error looking up log file "LPX64":%x: rc %d\n",
                       fid.id, fid.generation, rc);
                GOTO(out, rc);
        }

        if (dchild->d_inode == NULL) {
                rc = -ENOENT;
                CERROR("nonexistent log file "LPX64":%x: rc %d\n",
                       fid.id, fid.generation, rc);
                GOTO(out_put, rc);
        }

        /* dentry_open does a dput(de) and mntput(mds->mds_vfsmnt) on error */
        mntget(obd->u.mds.mds_vfsmnt);
        loghandle->lgh_file = dentry_open(dchild, obd->u.mds.mds_vfsmnt,
                                          O_RDWR | O_LARGEFILE);
        if (IS_ERR(loghandle->lgh_file)) {
                rc = PTR_ERR(loghandle->lgh_file);
                CERROR("error opening logfile "LPX64":%x: rc %d\n",
                       fid.id, fid.generation, rc);
                GOTO(out, rc);
        }
        memcpy(&loghandle->lgh_cookie, logcookie, sizeof(*logcookie));
        loghandle->lgh_log_create = mds_log_create;
        loghandle->lgh_log_open = mds_log_open;
        loghandle->lgh_log_close = mds_log_close;
        loghandle->lgh_obd = obd;

        RETURN(loghandle);

out_put:
        l_dput(dchild);
out:
        llog_free_handle(loghandle);
        return ERR_PTR(rc);
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
struct llog_handle *mds_log_create(struct obd_device *obd)
{
        char logbuf[24], *logname; /* logSSSSSSSSSS.count */
        struct llog_handle *loghandle;
        int rc, open_flags = O_RDWR | O_CREAT | O_LARGEFILE;
        ENTRY;

        loghandle = llog_alloc_handle();
        if (!loghandle)
                RETURN(ERR_PTR(-ENOMEM));

retry:
        if (!obd->u.mds.mds_catalog) {
                logname = "LOGS/catalog";
        } else {
                sprintf(logbuf, "LOGS/log%lu.%u\n",
                        CURRENT_SECONDS, obd->u.mds.mds_catalog->lgh_index++);
                open_flags |= O_EXCL;
                logname = logbuf;
        }
        loghandle->lgh_file = filp_open(logname, open_flags, 0644);
        if (IS_ERR(loghandle->lgh_file)) {
                rc = PTR_ERR(loghandle->lgh_file);
                if (rc == -EEXIST) {
                        CDEBUG(D_HA, "collision in logfile %s creation\n",
                               logname);
                        obd->u.mds.mds_catalog->lgh_index++;
                        goto retry;
                }
                CERROR("error opening/creating %s: rc %d\n", logname, rc);
                GOTO(out_handle, rc);
        }

        loghandle->lgh_cookie.lgc_lgl.lgl_oid =
                loghandle->lgh_file->f_dentry->d_inode->i_ino;
        loghandle->lgh_cookie.lgc_lgl.lgl_ogen =
                loghandle->lgh_file->f_dentry->d_inode->i_generation;
        loghandle->lgh_log_create = mds_log_create;
        loghandle->lgh_log_open = mds_log_open;
        loghandle->lgh_log_close = mds_log_close;
        loghandle->lgh_obd = obd;

        RETURN(loghandle);

out_handle:
        llog_free_handle(loghandle);
        return ERR_PTR(rc);
}

struct llog_handle *mds_get_catalog(struct obd_device *obd)
{
        struct mds_server_data *msd = obd->u.mds.mds_server_data;
        struct obd_run_ctxt saved;
        struct llog_handle *cathandle = NULL;
        int rc = 0;
        ENTRY;

        push_ctxt(&saved, &obd->u.mds.mds_ctxt, NULL);

        if (msd->msd_catalog_oid) {
                struct llog_cookie catcookie;

                catcookie.lgc_lgl.lgl_oid = le64_to_cpu(msd->msd_catalog_oid);
                catcookie.lgc_lgl.lgl_ogen = le32_to_cpu(msd->msd_catalog_ogen);
                cathandle = mds_log_open(obd, &catcookie);
                if (IS_ERR(cathandle)) {
                        CERROR("error opening catalog "LPX64":%x: rc %d\n",
                               catcookie.lgc_lgl.lgl_oid,
                               catcookie.lgc_lgl.lgl_ogen,
                               (int)PTR_ERR(cathandle));
                        msd->msd_catalog_oid = 0;
                        msd->msd_catalog_ogen = 0;
                }
                /* ORPHANS FIXME: compare catalog UUID to msd_peeruuid */
        }

        if (!msd->msd_catalog_oid) {
                struct llog_logid *lgl;

                cathandle = mds_log_create(obd);
                if (IS_ERR(cathandle)) {
                        CERROR("error creating new catalog: rc %d\n",
                               (int)PTR_ERR(cathandle));
                        GOTO(out, cathandle);
                }
                lgl = &cathandle->lgh_cookie.lgc_lgl;
                msd->msd_catalog_oid = cpu_to_le64(lgl->lgl_oid);
                msd->msd_catalog_ogen = cpu_to_le32(lgl->lgl_ogen);
                rc = mds_update_server_data(obd);
                if (rc) {
                        CERROR("error writing new catalog to disk: rc %d\n",rc);
                        GOTO(out_handle, rc);
                }
        }

        rc = llog_init_catalog(cathandle, &obd->u.mds.mds_osc_uuid);

out:
        pop_ctxt(&saved, &obd->u.mds.mds_ctxt, NULL);
        RETURN(cathandle);

out_handle:
        mds_log_close(cathandle, cathandle);
        cathandle = ERR_PTR(rc);
        goto out;

}

void mds_put_catalog(struct llog_handle *cathandle)
{
        struct llog_handle *loghandle, *n;
        int rc;
        ENTRY;

        list_for_each_entry_safe(loghandle, n, &cathandle->lgh_list, lgh_list)
                mds_log_close(cathandle, loghandle);

        rc = filp_close(cathandle->lgh_file, 0);
        if (rc)
                CERROR("error closing catalog: rc %d\n", rc);

        llog_free_handle(cathandle);
        EXIT;
}
