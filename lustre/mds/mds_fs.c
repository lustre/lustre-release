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
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_fsfilt.h>

/* This limit is arbitrary, but for now we fit it in 1 page (32k clients) */
#define MDS_MAX_CLIENTS (PAGE_SIZE * 8)
#define MDS_MAX_CLIENT_WORDS (MDS_MAX_CLIENTS / sizeof(unsigned long))

static unsigned long last_rcvd_slots[MDS_MAX_CLIENT_WORDS];

#define LAST_RCVD "last_rcvd"

/* Add client data to the MDS.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_off is -1 (i.e. a new client).
 * Otherwise, we have just read the data from the last_rcvd file and
 * we know its offset.
 */
int mds_client_add(struct mds_obd *mds, struct mds_export_data *med, int cl_off)
{
        int new_client = (cl_off == -1);

        /* the bitmap operations can handle cl_off > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        if (new_client) {
                cl_off = find_first_zero_bit(last_rcvd_slots, MDS_MAX_CLIENTS);
        repeat:
                if (cl_off >= MDS_MAX_CLIENTS) {
                        CERROR("no room for clients - fix MDS_MAX_CLIENTS\n");
                        return -ENOMEM;
                }
                if (test_and_set_bit(cl_off, last_rcvd_slots)) {
                        CERROR("MDS client %d: found bit is set in bitmap\n",
                               cl_off);
                        cl_off = find_next_zero_bit(last_rcvd_slots,
                                                    MDS_MAX_CLIENTS, cl_off);
                        goto repeat;
                }
        } else {
                if (test_and_set_bit(cl_off, last_rcvd_slots)) {
                        CERROR("MDS client %d: bit already set in bitmap!!\n",
                               cl_off);
                        LBUG();
                }
        }

        CDEBUG(D_INFO, "client at offset %d with UUID '%s' added\n",
               cl_off, med->med_mcd->mcd_uuid);

        med->med_off = cl_off;

        if (new_client) {
                struct obd_run_ctxt saved;
                loff_t off = MDS_LR_CLIENT + (cl_off * MDS_LR_SIZE);
                ssize_t written;

                push_ctxt(&saved, &mds->mds_ctxt, NULL);
                written = lustre_fwrite(mds->mds_rcvd_filp,
                                        (char *)med->med_mcd,
                                        sizeof(*med->med_mcd), &off);
                pop_ctxt(&saved, &mds->mds_ctxt, NULL);

                if (written != sizeof(*med->med_mcd)) {
                        if (written < 0)
                                RETURN(written);
                        RETURN(-EIO);
                }
                CDEBUG(D_INFO, "wrote client mcd at off %u (len %u)\n",
                       MDS_LR_CLIENT + (cl_off * MDS_LR_SIZE),
                       (unsigned int)sizeof(*med->med_mcd));
        }
        return 0;
}

int mds_client_free(struct obd_export *exp)
{
        struct mds_export_data *med = &exp->exp_mds_data;
        struct mds_obd *mds = &exp->exp_obd->u.mds;
        struct mds_client_data zero_mcd;
        struct obd_run_ctxt saved;
        int written;
        loff_t off;

        if (!med->med_mcd)
                RETURN(0);

        off = MDS_LR_CLIENT + (med->med_off * MDS_LR_SIZE);

        CDEBUG(D_INFO, "freeing client at offset %u (%lld)with UUID '%s'\n",
               med->med_off, off, med->med_mcd->mcd_uuid);

        if (!test_and_clear_bit(med->med_off, last_rcvd_slots)) {
                CERROR("MDS client %u: bit already clear in bitmap!!\n",
                       med->med_off);
                LBUG();
        }

        memset(&zero_mcd, 0, sizeof zero_mcd);
        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        written = lustre_fwrite(mds->mds_rcvd_filp, (const char *)&zero_mcd,
                                sizeof(zero_mcd), &off);
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);

        if (written != sizeof(zero_mcd)) {
                CERROR("error zeroing out client %s off %d in %s: %d\n",
                       med->med_mcd->mcd_uuid, med->med_off, LAST_RCVD,
                       written);
        } else {
                CDEBUG(D_INFO, "zeroed out disconnecting client %s at off %d\n",
                       med->med_mcd->mcd_uuid, med->med_off);
        }

        if (med->med_last_reply) {
                OBD_FREE(med->med_last_reply, med->med_last_replen);
                med->med_last_reply = NULL;
        }
        OBD_FREE(med->med_mcd, sizeof(*med->med_mcd));

        return 0;
}

static int mds_server_free_data(struct mds_obd *mds)
{
        OBD_FREE(mds->mds_server_data, sizeof(*mds->mds_server_data));
        mds->mds_server_data = NULL;

        return 0;
}

static int mds_read_last_rcvd(struct obd_device *obddev, struct file *f)
{
        struct mds_obd *mds = &obddev->u.mds;
        struct mds_server_data *msd;
        struct mds_client_data *mcd = NULL;
        loff_t off = 0;
        int cl_off;
        unsigned long last_rcvd_size = f->f_dentry->d_inode->i_size;
        __u64 last_rcvd = 0;
        __u64 last_mount;
        int rc = 0;

        OBD_ALLOC(msd, sizeof(*msd));
        if (!msd)
                RETURN(-ENOMEM);
        rc = lustre_fread(f, (char *)msd, sizeof(*msd), &off);

        mds->mds_server_data = msd;
        if (rc == 0) {
                CERROR("empty MDS %s, new MDS?\n", LAST_RCVD);
                RETURN(0);
        }

        if (rc != sizeof(*msd)) {
                CERROR("error reading MDS %s: rc = %d\n", LAST_RCVD, rc);
                if (rc > 0)
                        rc = -EIO;
                GOTO(err_msd, rc);
        }

        CDEBUG(D_INODE, "last_rcvd has size %lu (msd + %lu clients)\n",
               last_rcvd_size, (last_rcvd_size - MDS_LR_CLIENT)/MDS_LR_SIZE);

        /*
         * When we do a clean MDS shutdown, we save the last_rcvd into
         * the header.  If we find clients with higher last_rcvd values
         * then those clients may need recovery done.
         */
        last_rcvd = le64_to_cpu(msd->msd_last_rcvd);
        mds->mds_last_rcvd = last_rcvd;
        CDEBUG(D_INODE, "got "LPU64" for server last_rcvd value\n", last_rcvd);

        last_mount = le64_to_cpu(msd->msd_mount_count);
        mds->mds_mount_count = last_mount;
        CDEBUG(D_INODE, "got "LPU64" for server last_mount value\n",last_mount);

        /* off is adjusted by lustre_fread, so we don't adjust it in the loop */
        for (off = MDS_LR_CLIENT, cl_off = 0; off < last_rcvd_size; cl_off++) {
                int mount_age;

                if (!mcd) {
                        OBD_ALLOC(mcd, sizeof(*mcd));
                        if (!mcd)
                                GOTO(err_msd, rc = -ENOMEM);
                }

                rc = lustre_fread(f, (char *)mcd, sizeof(*mcd), &off);
                if (rc != sizeof(*mcd)) {
                        CERROR("error reading MDS %s offset %d: rc = %d\n",
                               LAST_RCVD, cl_off, rc);
                        if (rc > 0) /* XXX fatal error or just abort reading? */
                                rc = -EIO;
                        break;
                }

                if (mcd->mcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_off);
                        continue;
                }

                last_rcvd = le64_to_cpu(mcd->mcd_last_rcvd);

                /* These exports are cleaned up by mds_disconnect(), so they
                 * need to be set up like real exports as mds_connect() does.
                 */
                mount_age = last_mount - le64_to_cpu(mcd->mcd_mount_count);
                if (mount_age < MDS_MOUNT_RECOV) {
                        struct obd_export *exp = class_new_export(obddev);
                        struct mds_export_data *med;

                        if (!exp) {
                                rc = -ENOMEM;
                                break;
                        }

                        memcpy(&exp->exp_client_uuid.uuid, mcd->mcd_uuid,
                               sizeof exp->exp_client_uuid.uuid);
                        med = &exp->exp_mds_data;
                        med->med_mcd = mcd;
                        mds_client_add(mds, med, cl_off);
                        /* create helper if export init gets more complex */
                        INIT_LIST_HEAD(&med->med_open_head);
                        spin_lock_init(&med->med_open_lock);

                        mcd = NULL;
                        mds->mds_recoverable_clients++;
                } else {
                        CDEBUG(D_INFO,
                               "discarded client %d, UUID '%s', count %Ld\n",
                               cl_off, mcd->mcd_uuid,
                               (long long)le64_to_cpu(mcd->mcd_mount_count));
                }

                CDEBUG(D_OTHER, "client at offset %d has last_rcvd = %Lu\n",
                       cl_off, (unsigned long long)last_rcvd);

                if (last_rcvd > mds->mds_last_rcvd)
                        mds->mds_last_rcvd = last_rcvd;
        }

        obddev->obd_last_committed = mds->mds_last_rcvd;
        if (mds->mds_recoverable_clients) {
                CERROR("RECOVERY: %d recoverable clients, last_rcvd "LPU64"\n",
                       mds->mds_recoverable_clients, mds->mds_last_rcvd);
                mds->mds_next_recovery_transno = obddev->obd_last_committed + 1;
                obddev->obd_flags |= OBD_RECOVERING;
        }

        if (mcd)
                OBD_FREE(mcd, sizeof(*mcd));

        return 0;

err_msd:
        mds_server_free_data(mds);
        return rc;
}

static int mds_fs_prep(struct obd_device *obddev)
{
        struct mds_obd *mds = &obddev->u.mds;
        struct obd_run_ctxt saved;
        struct dentry *dentry;
        struct file *f;
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

        dentry = simple_mkdir(current->fs->pwd, "FH", 0700);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create FH directory: rc = %d\n", rc);
                GOTO(err_pop, rc);
        }
        /* XXX probably want to hold on to this later... */
        dput(dentry);

        f = filp_open(LAST_RCVD, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(f)) {
                rc = PTR_ERR(f);
                CERROR("cannot open/create %s file: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_pop, rc = PTR_ERR(f));
        }
        if (!S_ISREG(f->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LAST_RCVD,
                       f->f_dentry->d_inode->i_mode);
                GOTO(err_filp, rc = -ENOENT);
        }

        rc = fsfilt_journal_data(obddev, f);
        if (rc) {
                CERROR("cannot journal data on %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_filp, rc);
        }

        rc = mds_read_last_rcvd(obddev, f);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_client, rc);
        }
        mds->mds_rcvd_filp = f;
err_pop:
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);

        return rc;

err_client:
        class_disconnect_all(obddev);
err_filp:
        if (filp_close(f, 0))
                CERROR("can't close %s after error\n", LAST_RCVD);
        goto err_pop;
}

int mds_fs_setup(struct obd_device *obddev, struct vfsmount *mnt)
{
        struct mds_obd *mds = &obddev->u.mds;
        ENTRY;

        mds->mds_vfsmnt = mnt;

        OBD_SET_CTXT_MAGIC(&mds->mds_ctxt);
        mds->mds_ctxt.pwdmnt = mnt;
        mds->mds_ctxt.pwd = mnt->mnt_root;
        mds->mds_ctxt.fs = get_ds();

        RETURN(mds_fs_prep(obddev));
}

int mds_fs_cleanup(struct obd_device *obddev)
{
        struct mds_obd *mds = &obddev->u.mds;
        struct obd_run_ctxt saved;
        int rc = 0;

        class_disconnect_all(obddev); /* this cleans up client info too */
        mds_server_free_data(mds);

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        if (mds->mds_rcvd_filp) {
                rc = filp_close(mds->mds_rcvd_filp, 0);
                mds->mds_rcvd_filp = NULL;

                if (rc)
                        CERROR("last_rcvd file won't close, rc=%d\n", rc);
        }
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);

        return rc;
}
