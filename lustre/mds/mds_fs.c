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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
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
#define LOV_OBJID "lov_objid"

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
        ENTRY;

        LASSERT(bitmap != NULL);

        /* XXX if mcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp(med->med_mcd->mcd_uuid, obd->obd_uuid.uuid))
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

        CDEBUG(D_INFO, "client at idx %d with UUID '%s' added\n",
               cl_idx, med->med_mcd->mcd_uuid);

        med->med_idx = cl_idx;
        med->med_off = MDS_LR_CLIENT_START + (cl_idx * MDS_LR_CLIENT_SIZE);

        if (new_client) {
                struct obd_run_ctxt saved;
                loff_t off = med->med_off;
                struct file *file = mds->mds_rcvd_filp;
                int rc;

                push_ctxt(&saved, &obd->obd_ctxt, NULL);
                rc = fsfilt_write_record(obd, file, med->med_mcd,
                                         sizeof(*med->med_mcd), &off, 1);
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);

                if (rc)
                        return rc;
                CDEBUG(D_INFO, "wrote client mcd at idx %u off %llu (len %u)\n",
                       med->med_idx, med->med_off,
                       (unsigned int)sizeof(*med->med_mcd));
        }
        return 0;
}

int mds_client_free(struct obd_export *exp, int clear_client)
{
        struct mds_export_data *med = &exp->exp_mds_data;
        struct mds_obd *mds = &exp->exp_obd->u.mds;
        struct obd_device *obd = exp->exp_obd;
        struct mds_client_data zero_mcd;
        struct obd_run_ctxt saved;
        int rc;
        unsigned long *bitmap = mds->mds_client_bitmap;

        LASSERT(bitmap);
        if (!med->med_mcd)
                RETURN(0);

        /* XXX if mcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp(med->med_mcd->mcd_uuid, obd->obd_uuid.uuid))
                GOTO(free_and_out, 0);

        CDEBUG(D_INFO, "freeing client at idx %u (%lld)with UUID '%s'\n",
               med->med_idx, med->med_off, med->med_mcd->mcd_uuid);

        /* Clear the bit _after_ zeroing out the client so we don't
           race with mds_client_add and zero out new clients.*/
        if (!test_bit(med->med_idx, bitmap)) {
                CERROR("MDS client %u: bit already clear in bitmap!!\n",
                       med->med_idx);
                LBUG();
        }

        if (clear_client) {
                memset(&zero_mcd, 0, sizeof zero_mcd);
                push_ctxt(&saved, &obd->obd_ctxt, NULL);
                rc = fsfilt_write_record(obd, mds->mds_rcvd_filp, &zero_mcd,
                                         sizeof(zero_mcd), &med->med_off, 1);
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);

                CDEBUG(rc == 0 ? D_INFO : D_ERROR,
                       "zeroing out client %s idx %u in %s rc %d\n",
                       med->med_mcd->mcd_uuid, med->med_idx, LAST_RCVD, rc);
        }

        if (!test_and_clear_bit(med->med_idx, bitmap)) {
                CERROR("MDS client %u: bit already clear in bitmap!!\n",
                       med->med_idx);
                LBUG();
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
        unsigned long last_rcvd_size = file->f_dentry->d_inode->i_size;
        __u64 mount_count;
        int cl_idx, rc = 0;
        ENTRY;

        /* ensure padding in the struct is the correct size */
        LASSERT (offsetof(struct mds_server_data, msd_padding) +
                 sizeof(msd->msd_padding) == MDS_LR_SERVER_SIZE);
        LASSERT (offsetof(struct mds_client_data, mcd_padding) +
                 sizeof(mcd->mcd_padding) == MDS_LR_CLIENT_SIZE);

        OBD_ALLOC_WAIT(msd, sizeof(*msd));
        if (!msd)
                RETURN(-ENOMEM);

        OBD_ALLOC_WAIT(mds->mds_client_bitmap,
                  MDS_MAX_CLIENT_WORDS * sizeof(unsigned long));
        if (!mds->mds_client_bitmap) {
                OBD_FREE(msd, sizeof(*msd));
                RETURN(-ENOMEM);
        }

        mds->mds_server_data = msd;

        if (last_rcvd_size == 0) {
                CWARN("%s: initializing new %s\n", obd->obd_name, LAST_RCVD);

                memcpy(msd->msd_uuid, obd->obd_uuid.uuid,sizeof(msd->msd_uuid));
                msd->msd_last_transno = 0;
                mount_count = msd->msd_mount_count = 0; 
                msd->msd_server_size = cpu_to_le32(MDS_LR_SERVER_SIZE);
                msd->msd_client_start = cpu_to_le32(MDS_LR_CLIENT_START);
                msd->msd_client_size = cpu_to_le16(MDS_LR_CLIENT_SIZE);
                msd->msd_feature_rocompat = cpu_to_le32(MDS_ROCOMPAT_LOVOBJID);
        } else {
                rc = fsfilt_read_record(obd, file, msd, sizeof(*msd), &off);
                if (rc) {
                        CERROR("error reading MDS %s: rc = %d\n", LAST_RCVD, rc);
                        GOTO(err_msd, rc);
                }
                if (strcmp(msd->msd_uuid, obd->obd_uuid.uuid) != 0) {
                        CERROR("OBD UUID %s does not match last_rcvd UUID %s\n",
                               obd->obd_uuid.uuid, msd->msd_uuid);
                        GOTO(err_msd, rc = -EINVAL);
                }
                mount_count = le64_to_cpu(msd->msd_mount_count);
        }
        if (msd->msd_feature_incompat & ~cpu_to_le32(MDS_INCOMPAT_SUPP)) {
                CERROR("unsupported incompat feature %x\n",
                       le32_to_cpu(msd->msd_feature_incompat) &
                       ~MDS_INCOMPAT_SUPP);
                GOTO(err_msd, rc = -EINVAL);
        }
        /* XXX updating existing b_devel fs only, can be removed in future */
        msd->msd_feature_rocompat = cpu_to_le32(MDS_ROCOMPAT_LOVOBJID);
        if (msd->msd_feature_rocompat & ~cpu_to_le32(MDS_ROCOMPAT_SUPP)) {
                CERROR("unsupported read-only feature %x\n",
                       le32_to_cpu(msd->msd_feature_rocompat) &
                       ~MDS_ROCOMPAT_SUPP);
                /* Do something like remount filesystem read-only */
                GOTO(err_msd, rc = -EINVAL);
        }

        mds->mds_last_transno = le64_to_cpu(msd->msd_last_transno);

        CDEBUG(D_INODE, "%s: server last_transno: "LPU64"\n",
               obd->obd_name, mds->mds_last_transno);
        CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
               obd->obd_name, mount_count + 1);
        CDEBUG(D_INODE, "%s: server data size: %u\n",
               obd->obd_name, le32_to_cpu(msd->msd_server_size));
        CDEBUG(D_INODE, "%s: per-client data start: %u\n",
               obd->obd_name, le32_to_cpu(msd->msd_client_start));
        CDEBUG(D_INODE, "%s: per-client data size: %u\n",
               obd->obd_name, le32_to_cpu(msd->msd_client_size));
        CDEBUG(D_INODE, "%s: last_rcvd size: %lu\n",
               obd->obd_name, last_rcvd_size);
        CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", obd->obd_name,
               last_rcvd_size <= MDS_LR_CLIENT_START ? 0 :
               (last_rcvd_size - MDS_LR_CLIENT_START) / MDS_LR_CLIENT_SIZE);

        /* When we do a clean MDS shutdown, we save the last_transno into
         * the header.  If we find clients with higher last_transno values
         * then those clients may need recovery done. */
        for (cl_idx = 0, off = le32_to_cpu(msd->msd_client_start);
             off < last_rcvd_size; cl_idx++) {
                __u64 last_transno;
                struct obd_export *exp;
                struct mds_export_data *med;

                if (!mcd) {
                        OBD_ALLOC_WAIT(mcd, sizeof(*mcd));
                        if (!mcd)
                                GOTO(err_client, rc = -ENOMEM);
                }

                /* Don't assume off is incremented properly by
                 * fsfilt_read_record(), in case sizeof(*mcd)
                 * isn't the same as msd->msd_client_size.  */
                off = le32_to_cpu(msd->msd_client_start) +
                        cl_idx * le16_to_cpu(msd->msd_client_size);
                rc = fsfilt_read_record(obd, file, mcd, sizeof(*mcd), &off);
                if (rc) {
                        CERROR("error reading MDS %s idx %d, off %llu: rc %d\n",
                               LAST_RCVD, cl_idx, off, rc);
                        break; /* read error shouldn't cause startup to fail */
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
                CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                       " srv lr: "LPU64"\n", mcd->mcd_uuid, cl_idx,
                       last_transno, le64_to_cpu(msd->msd_last_transno));

                exp = class_new_export(obd);
                if (exp == NULL)
                        GOTO(err_client, rc = -ENOMEM);

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
                obd->obd_max_recoverable_clients++;
                class_export_put(exp);

                CDEBUG(D_OTHER, "client at idx %d has last_transno = "LPU64"\n",
                       cl_idx, last_transno);

                if (last_transno > mds->mds_last_transno)
                       mds->mds_last_transno = last_transno;
        }

        obd->obd_last_committed = mds->mds_last_transno;
        if (obd->obd_recoverable_clients) {
                CWARN("RECOVERY: service %s, %d recoverable clients, "
                      "last_transno "LPU64"\n", obd->obd_name,
                      obd->obd_recoverable_clients, mds->mds_last_transno);
                obd->obd_next_recovery_transno = obd->obd_last_committed + 1;
                obd->obd_recovering = 1;
        }

        if (mcd)
                OBD_FREE(mcd, sizeof(*mcd));
        
        mds->mds_mount_count = mount_count + 1;
        msd->msd_mount_count = cpu_to_le64(mds->mds_mount_count);

        /* save it, so mount count and last_transno is current */
        rc = mds_update_server_data(obd, 1);

        RETURN(rc);

err_client:
        class_disconnect_exports(obd, 0);
err_msd:
        mds_server_free_data(mds);
        RETURN(rc);
}

int mds_fs_setup(struct obd_device *obd, struct vfsmount *mnt)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_run_ctxt saved;
        struct dentry *dentry;
        struct file *file;
        int rc;
        ENTRY;


        /* Get rid of unneeded supplementary groups */
        current->ngroups = 0;
        memset(current->groups, 0, sizeof(current->groups));

        mds->mds_vfsmnt = mnt;
        mds->mds_sb = mnt->mnt_root->d_inode->i_sb;

        fsfilt_setup(obd, mds->mds_sb);

        OBD_SET_CTXT_MAGIC(&obd->obd_ctxt);
        obd->obd_ctxt.pwdmnt = mnt;
        obd->obd_ctxt.pwd = mnt->mnt_root;
        obd->obd_ctxt.fs = get_ds();
        obd->obd_ctxt.cb_ops = mds_lvfs_ops;

        /* setup the directory tree */
        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        dentry = simple_mkdir(current->fs->pwd, "ROOT", 0755, 0);
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

        dentry = simple_mkdir(current->fs->pwd, "PENDING", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create PENDING directory: rc = %d\n", rc);
                GOTO(err_fid, rc);
        }
        mds->mds_pending_dir = dentry;

        dentry = simple_mkdir(current->fs->pwd, "LOGS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create LOGS directory: rc = %d\n", rc);
                GOTO(err_pending, rc);
        }
        mds->mds_logs_dir = dentry;

        dentry = simple_mkdir(current->fs->pwd, "OBJECTS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create OBJECTS directory: rc = %d\n", rc);
                GOTO(err_logs, rc);
        }
        mds->mds_objects_dir = dentry;

        /* open and test the last rcvd file */
        file = filp_open(LAST_RCVD, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open/create %s file: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_objects, rc = PTR_ERR(file));
        }
        mds->mds_rcvd_filp = file;
        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LAST_RCVD,
                       file->f_dentry->d_inode->i_mode);
                GOTO(err_last_rcvd, rc = -ENOENT);
        }

        rc = mds_read_last_rcvd(obd, file);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_last_rcvd, rc);
        }

        /* open and test the lov objd file */
        file = filp_open(LOV_OBJID, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open/create %s file: rc = %d\n", LOV_OBJID, rc);
                GOTO(err_client, rc = PTR_ERR(file));
        }
        mds->mds_lov_objid_filp = file;
        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LOV_OBJID,
                       file->f_dentry->d_inode->i_mode);
                GOTO(err_lov_objid, rc = -ENOENT);
        }
err_pop:
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        return rc;

err_lov_objid:
        if (mds->mds_lov_objid_filp && filp_close(mds->mds_lov_objid_filp, 0))
                CERROR("can't close %s after error\n", LOV_OBJID);
err_client:
        class_disconnect_exports(obd, 0);
err_last_rcvd:
        if (mds->mds_rcvd_filp && filp_close(mds->mds_rcvd_filp, 0))
                CERROR("can't close %s after error\n", LAST_RCVD);
err_objects:
        dput(mds->mds_objects_dir);
err_logs:
        dput(mds->mds_logs_dir);
err_pending:
        dput(mds->mds_pending_dir);
err_fid:
        dput(mds->mds_fid_de);
        goto err_pop;
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

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        if (mds->mds_rcvd_filp) {
                rc = filp_close(mds->mds_rcvd_filp, 0);
                mds->mds_rcvd_filp = NULL;
                if (rc)
                        CERROR("%s file won't close, rc=%d\n", LAST_RCVD, rc);
        }
        if (mds->mds_lov_objid_filp) {
                rc = filp_close(mds->mds_lov_objid_filp, 0);
                mds->mds_lov_objid_filp = NULL;
                if (rc)
                        CERROR("%s file won't close, rc=%d\n", LOV_OBJID, rc);
        }
        if (mds->mds_objects_dir != NULL) {
                l_dput(mds->mds_objects_dir);
                mds->mds_objects_dir = NULL;
        }
        if (mds->mds_logs_dir) {
                l_dput(mds->mds_logs_dir);
                mds->mds_logs_dir = NULL;
        }
        if (mds->mds_pending_dir) {
                l_dput(mds->mds_pending_dir);
                mds->mds_pending_dir = NULL;
        }
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        shrink_dcache_parent(mds->mds_fid_de);
        dput(mds->mds_fid_de);

        return rc;
}

/* Creates an object with the same name as its fid.  Because this is not at all
 * performance sensitive, it is accomplished by creating a file, checking the
 * fid, and renaming it. */
int mds_obd_create(struct obd_export *exp, struct obdo *oa,
                      struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct mds_obd *mds = &exp->exp_obd->u.mds;
        struct inode *parent_inode = mds->mds_objects_dir->d_inode;
        unsigned int tmpname = ll_insecure_random_int();
        struct file *filp;
        struct dentry *new_child;
        struct obd_run_ctxt saved;
        char fidname[LL_FID_NAMELEN];
        void *handle;
        int rc = 0, err, namelen;
        ENTRY;

        push_ctxt(&saved, &exp->exp_obd->obd_ctxt, NULL);
        
        sprintf(fidname, "OBJECTS/%u", tmpname);
        filp = filp_open(fidname, O_CREAT | O_EXCL, 0644);
        if (IS_ERR(filp)) {
                rc = PTR_ERR(filp);
                if (rc == -EEXIST) {
                        CERROR("impossible object name collision %u\n",
                               tmpname);
                        LBUG();
                }
                CERROR("error creating tmp object %u: rc %d\n", tmpname, rc);
                GOTO(out_pop, rc);
        }

        LASSERT(mds->mds_objects_dir == filp->f_dentry->d_parent);

        oa->o_id = filp->f_dentry->d_inode->i_ino;
        oa->o_generation = filp->f_dentry->d_inode->i_generation;
        namelen = ll_fid2str(fidname, oa->o_id, oa->o_generation);

        down(&parent_inode->i_sem);
        new_child = lookup_one_len(fidname, mds->mds_objects_dir, namelen);

        if (IS_ERR(new_child)) {
                CERROR("getting neg dentry for obj rename: %d\n", rc);
                GOTO(out_close, rc = PTR_ERR(new_child));
        }
        if (new_child->d_inode != NULL) {
                CERROR("impossible non-negative obj dentry " LPU64":%u!\n",
                       oa->o_id, oa->o_generation);
                LBUG();
        }

        handle = fsfilt_start(exp->exp_obd, mds->mds_objects_dir->d_inode,
                              FSFILT_OP_RENAME, NULL);
        if (IS_ERR(handle))
                GOTO(out_dput, rc = PTR_ERR(handle));

        lock_kernel();
        rc = vfs_rename(mds->mds_objects_dir->d_inode, filp->f_dentry,
                        mds->mds_objects_dir->d_inode, new_child);
        unlock_kernel();
        if (rc)
                CERROR("error renaming new object "LPU64":%u: rc %d\n",
                       oa->o_id, oa->o_generation, rc);

        err = fsfilt_commit(exp->exp_obd, mds->mds_objects_dir->d_inode,
                            handle, 0);
        if (!err)
                oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGENER;
        else if (!rc)
                rc = err;
out_dput:
        dput(new_child);
out_close:
        up(&parent_inode->i_sem);
        err = filp_close(filp, 0);
        if (err) {
                CERROR("closing tmpfile %u: rc %d\n", tmpname, rc);
                if (!rc)
                        rc = err;
        }
out_pop:
        pop_ctxt(&saved, &exp->exp_obd->obd_ctxt, NULL);
        RETURN(rc);
}

int mds_obd_destroy(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *ea, struct obd_trans_info *oti)
{
        struct mds_obd *mds = &exp->exp_obd->u.mds;
        struct inode *parent_inode = mds->mds_objects_dir->d_inode;
        struct obd_device *obd = exp->exp_obd;
        struct obd_run_ctxt saved;
        char fidname[LL_FID_NAMELEN];
        struct dentry *de;
        void *handle;
        int err, namelen, rc = 0;
        ENTRY;

        push_ctxt(&saved, &obd->obd_ctxt, NULL);

        namelen = ll_fid2str(fidname, oa->o_id, oa->o_generation);

        down(&parent_inode->i_sem);
        de = lookup_one_len(fidname, mds->mds_objects_dir, namelen);
        if (de == NULL || de->d_inode == NULL) {
                CERROR("destroying non-existent object "LPU64"\n", oa->o_id);
                GOTO(out_dput, rc = IS_ERR(de) ? PTR_ERR(de) : -ENOENT);
        }

        /* Stripe count is 1 here since this is some MDS specific stuff
           that is unlinked, not spanned across multiple OSTs */
        handle = fsfilt_start_log(obd, mds->mds_objects_dir->d_inode,
                                  FSFILT_OP_UNLINK, oti, 1);
        if (IS_ERR(handle)) {
                GOTO(out_dput, rc = PTR_ERR(handle));
        }
        
        rc = vfs_unlink(mds->mds_objects_dir->d_inode, de);
        if (rc) 
                CERROR("error destroying object "LPU64":%u: rc %d\n",
                       oa->o_id, oa->o_generation, rc);
        
        err = fsfilt_commit(obd, mds->mds_objects_dir->d_inode, handle, 0);
        if (err && !rc)
                rc = err;
out_dput:
        if (de != NULL)
                l_dput(de);
        up(&parent_inode->i_sem);
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        RETURN(rc);
}
