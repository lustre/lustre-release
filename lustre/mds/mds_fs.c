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
#include <libcfs/list.h>

#include <linux/lustre_smfs.h>
#include "mds_internal.h"

/* This limit is arbitrary, but for now we fit it in 1 page (32k clients) */
#define MDS_MAX_CLIENTS (PAGE_SIZE * 8)

#define LAST_RCVD "last_rcvd"
#define LOV_OBJID "lov_objid"
#define LAST_FID  "last_fid"
#define VIRT_FID  "virt_fid"

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
        med->med_off = le32_to_cpu(mds->mds_server_data->msd_client_start) +
                (cl_idx * le16_to_cpu(mds->mds_server_data->msd_client_size));

        if (new_client) {
                struct file *file = mds->mds_rcvd_filp;
                struct lvfs_run_ctxt saved;
                loff_t off = med->med_off;
                int rc;

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_write_record(obd, file, med->med_mcd,
                                         sizeof(*med->med_mcd), &off, 1);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

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
        unsigned long *bitmap = mds->mds_client_bitmap;
        struct obd_device *obd = exp->exp_obd;
        struct mds_client_data zero_mcd;
        struct lvfs_run_ctxt saved;
        int rc;

        if (!med->med_mcd)
                RETURN(0);

        /* XXX if mcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp(med->med_mcd->mcd_uuid, obd->obd_uuid.uuid))
                GOTO(free_and_out, 0);

        CDEBUG(D_INFO, "freeing client at idx %u (%lld)with UUID '%s'\n",
               med->med_idx, med->med_off, med->med_mcd->mcd_uuid);

        LASSERT(bitmap);

        /* Clear the bit _after_ zeroing out the client so we don't
           race with mds_client_add and zero out new clients.*/
        if (!test_bit(med->med_idx, bitmap)) {
                CERROR("MDS client %u: bit already clear in bitmap!!\n",
                       med->med_idx);
                LBUG();
        }

        if (clear_client) {
                memset(&zero_mcd, 0, sizeof zero_mcd);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_write_record(obd, mds->mds_rcvd_filp, &zero_mcd,
                                         sizeof(zero_mcd), &med->med_off, 1);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                CDEBUG(rc == 0 ? D_INFO : D_ERROR,
                       "zeroing out client %s idx %u in %s rc %d\n",
                       med->med_mcd->mcd_uuid, med->med_idx, LAST_RCVD, rc);
        }

        if (!test_and_clear_bit(med->med_idx, bitmap)) {
                CERROR("MDS client %u: bit already clear in bitmap!!\n",
                       med->med_idx);
                LBUG();
        }


        /* Make sure the server's last_transno is up to date. Do this
         * after the client is freed so we know all the client's
         * transactions have been committed. */
        mds_update_server_data(exp->exp_obd, 1);

free_and_out:
        OBD_FREE(med->med_mcd, sizeof(*med->med_mcd));
        med->med_mcd = NULL;
        return 0;
}

static int mds_server_free_data(struct mds_obd *mds)
{
        OBD_FREE(mds->mds_client_bitmap, MDS_MAX_CLIENTS / 8);
        OBD_FREE(mds->mds_server_data, sizeof(*mds->mds_server_data));
        mds->mds_server_data = NULL;

        return 0;
}

static int mds_read_last_fid(struct obd_device *obd, struct file *file)
{
        int rc = 0;
        loff_t off = 0;
        struct mds_obd *mds = &obd->u.mds;
        unsigned long last_fid_size = file->f_dentry->d_inode->i_size;
        ENTRY;

        if (last_fid_size == 0) {
                CWARN("%s: initializing new %s\n", obd->obd_name,
                      file->f_dentry->d_name.name);

                /* 
                 * as fid is used for forming res_id for locking, it should not
                 * be zero. This will keep us out of lots possible problems,
                 * asserts, etc.
                 */
                mds_set_last_fid(obd, 0);
        } else {
                __u64 lastfid;
                
                rc = fsfilt_read_record(obd, file, &lastfid,
                                        sizeof(lastfid), &off);
                if (rc) {
                        CERROR("error reading MDS %s: rc = %d\n",
                               file->f_dentry->d_name.name, rc);
                        RETURN(rc);
                }

                /* 
                 * make sure, that fid is up-to-date.
                 */
                mds_set_last_fid(obd, lastfid);
        }

        CDEBUG(D_INODE, "%s: server last_fid: "LPU64"\n",
               obd->obd_name, mds->mds_last_fid);

        rc = mds_update_last_fid(obd, NULL, 1);
        RETURN(rc);
}

static int mds_read_last_rcvd(struct obd_device *obd, struct file *file)
{
        unsigned long last_rcvd_size = file->f_dentry->d_inode->i_size;
        struct mds_obd *mds = &obd->u.mds;
        struct mds_server_data *msd = NULL;
        struct mds_client_data *mcd = NULL;
        loff_t off = 0;
        __u64 mount_count;
        int cl_idx, rc = 0;
        ENTRY;

        /* ensure padding in the struct is the correct size */
        LASSERT(offsetof(struct mds_server_data, msd_padding) +
                sizeof(msd->msd_padding) == MDS_LR_SERVER_SIZE);
        LASSERT(offsetof(struct mds_client_data, mcd_padding) +
                sizeof(mcd->mcd_padding) == MDS_LR_CLIENT_SIZE);

        OBD_ALLOC_WAIT(msd, sizeof(*msd));
        if (!msd)
                RETURN(-ENOMEM);

        OBD_ALLOC_WAIT(mds->mds_client_bitmap, MDS_MAX_CLIENTS / 8);
        if (!mds->mds_client_bitmap) {
                OBD_FREE(msd, sizeof(*msd));
                RETURN(-ENOMEM);
        }

        mds->mds_server_data = msd;

        if (last_rcvd_size == 0) {
                CWARN("%s: initializing new %s\n", obd->obd_name,
                      file->f_dentry->d_name.name);

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
                        CERROR("error reading MDS %s: rc = %d\n",
                               file->f_dentry->d_name.name, rc);
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
               last_rcvd_size <= le32_to_cpu(msd->msd_client_start) ? 0 :
               (last_rcvd_size - le32_to_cpu(msd->msd_client_start)) /
                le16_to_cpu(msd->msd_client_size));

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
                               file->f_dentry->d_name.name, cl_idx, off, rc);
                        break; /* read error shouldn't cause startup to fail */
                }

                if (mcd->mcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_idx);
                        continue;
                }

                last_transno = le64_to_cpu(mcd->mcd_last_transno) >
                               le64_to_cpu(mcd->mcd_last_close_transno) ?
                               le64_to_cpu(mcd->mcd_last_transno) :
                               le64_to_cpu(mcd->mcd_last_close_transno);

                /* These exports are cleaned up by mds_disconnect(), so they
                 * need to be set up like real exports as mds_connect() does.
                 */
                CDEBUG(D_HA|D_WARNING,"RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                       " srv lr: "LPU64" lx: "LPU64"\n", mcd->mcd_uuid, cl_idx,
                       last_transno, le64_to_cpu(msd->msd_last_transno),
                       mcd->mcd_last_xid);

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
                exp->exp_replay_needed = 1;
                obd->obd_recoverable_clients++;
                obd->obd_max_recoverable_clients++;
                class_export_put(exp);

                CDEBUG(D_OTHER, "client at idx %d has last_transno = "LPU64"\n",
                       cl_idx, last_transno);

                if (last_transno > mds->mds_last_transno)
                       mds->mds_last_transno = last_transno;
        }
        if (mcd)
                OBD_FREE(mcd, sizeof(*mcd));
        obd->obd_last_committed = mds->mds_last_transno;
        if (obd->obd_recoverable_clients) {
                CWARN("RECOVERY: service %s, %d recoverable clients, "
                      "last_transno "LPU64"\n", obd->obd_name,
                      obd->obd_recoverable_clients, mds->mds_last_transno);
                obd->obd_next_recovery_transno = obd->obd_last_committed + 1;
                target_start_recovery_thread(obd, mds_handle);
                obd->obd_recovery_start = LTIME_S(CURRENT_TIME);
        }
        
        mds->mds_mount_count = mount_count + 1;
        msd->msd_mount_count = cpu_to_le64(mds->mds_mount_count);

        /* save it, so mount count and last_transno is current */
        rc = mds_update_server_data(obd, 1);
        if (rc)
                GOTO(err_client, rc);

        RETURN(0);

err_client:
        class_disconnect_exports(obd, 0);
err_msd:
        mds_server_free_data(mds);
        RETURN(rc);
}

static int mds_fs_post_setup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct dentry *dentry;
        int rc = 0;
        ENTRY;
       
        dentry = mds_id2dentry(obd, &mds->mds_rootid, NULL);
        if (IS_ERR(dentry)) {
                CERROR("Can't find ROOT, err = %d\n",
                       (int)PTR_ERR(dentry));
                RETURN(PTR_ERR(dentry));
        }
        
        rc = fsfilt_post_setup(obd, dentry);
        if (rc)
                goto out_dentry;

        LASSERT(dentry->d_inode != NULL);
        
        fsfilt_set_fs_flags(obd, dentry->d_inode, 
                            SM_DO_REC | SM_DO_COW);
        
        fsfilt_set_fs_flags(obd, mds->mds_pending_dir->d_inode, 
                            SM_DO_REC | SM_DO_COW);
        
        fsfilt_set_mds_flags(obd, mds->mds_sb);

out_dentry:
        l_dput(dentry);
        RETURN(rc); 
}

/*
 * sets up root inode lustre_id. It tries to read it first from root inode and
 * if it is not there, new rootid is allocated and saved there.
 */
int mds_fs_setup_rootid(struct obd_device *obd)
{
        int rc = 0;
        void *handle;
        struct inode *inode;
        struct dentry *dentry;
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        /* getting root directory and setup its fid. */
        dentry = mds_id2dentry(obd, &mds->mds_rootid, NULL);
        if (IS_ERR(dentry)) {
                CERROR("Can't find ROOT by "DLID4", err = %d\n",
                       OLID4(&mds->mds_rootid), (int)PTR_ERR(dentry));
                RETURN(PTR_ERR(dentry));
        }

        inode = dentry->d_inode;
        LASSERT(dentry->d_inode);

        rc = mds_pack_inode2id(obd, &mds->mds_rootid, inode, 1);
        if (rc < 0) {
                if (rc != -ENODATA)
                        GOTO(out_dentry, rc);
        } else {
                /*
                 * rootid is filled by mds_read_inode_sid(), so we do not need
                 * to allocate it and update. The only thing we need to check is
                 * mds_num.
                 */
                LASSERT(id_group(&mds->mds_rootid) == mds->mds_num);
                mds_set_last_fid(obd, id_fid(&mds->mds_rootid));
                GOTO(out_dentry, rc);
        }

        /* allocating new one, as it is not found in root inode. */
        handle = fsfilt_start(obd, inode,
                              FSFILT_OP_SETATTR, NULL);
        
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                CERROR("fsfilt_start() failed, rc = %d\n", rc);
                GOTO(out_dentry, rc);
        }
        
        down(&inode->i_sem);
        rc = mds_alloc_inode_sid(obd, inode, handle, &mds->mds_rootid);
        up(&inode->i_sem);
        
        if (rc) {
                CERROR("mds_alloc_inode_sid() failed, rc = %d\n",
                       rc);
                GOTO(out_dentry, rc);
        }

        rc = fsfilt_commit(obd, mds->mds_sb, inode, handle, 0);
        if (rc)
                CERROR("fsfilt_commit() failed, rc = %d\n", rc);

        EXIT;
out_dentry:
        l_dput(dentry);
        if (rc == 0)
                CWARN("%s: rootid: "DLID4"\n", obd->obd_name,
                      OLID4(&mds->mds_rootid));
        return rc;
}

static int mds_update_virtid_fid(struct obd_device *obd,
                                 void *handle, int force_sync)
{
        struct mds_obd *mds = &obd->u.mds;
        struct file *filp = mds->mds_virtid_filp;
        struct lvfs_run_ctxt saved;
        loff_t off = 0;
        int rc = 0;
        ENTRY;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = fsfilt_write_record(obd, filp, &mds->mds_virtid_fid,
                                 sizeof(mds->mds_virtid_fid),
                                 &off, force_sync);
        if (rc) {
                CERROR("error writing MDS virtid_fid #"LPU64
                       ", err = %d\n", mds->mds_virtid_fid, rc);
        }
                
        CDEBUG(D_SUPER, "wrote virtid fid #"LPU64" at idx "
               "%llu: err = %d\n", mds->mds_virtid_fid,
               off, rc);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int mds_read_virtid_fid(struct obd_device *obd,
                               struct file *file)
{
        int rc = 0;
        loff_t off = 0;
        struct mds_obd *mds = &obd->u.mds;
        unsigned long virtid_fid_size = file->f_dentry->d_inode->i_size;
        ENTRY;

        if (virtid_fid_size == 0) {
                mds->mds_virtid_fid = mds_alloc_fid(obd);
        } else {
                rc = fsfilt_read_record(obd, file, &mds->mds_virtid_fid,
                                        sizeof(mds->mds_virtid_fid), &off);
                if (rc) {
                        CERROR("error reading MDS %s: rc = %d\n",
                               file->f_dentry->d_name.name, rc);
                        RETURN(rc);
                }
        }
        rc = mds_update_virtid_fid(obd, NULL, 1);

        RETURN(rc);
}

/*
 * initializes lustre_id for virtual id directory, it is needed sometimes, as it
 * is possible that it will be the parent for object an operations is going to
 * be performed on.
 */
int mds_fs_setup_virtid(struct obd_device *obd)
{
        int rc = 0;
        void *handle;
        struct lustre_id sid;
        struct mds_obd *mds = &obd->u.mds;
        struct inode *inode = mds->mds_id_dir->d_inode;
        ENTRY;

        handle = fsfilt_start(obd, inode,
                              FSFILT_OP_SETATTR, NULL);
        
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                CERROR("fsfilt_start() failed, rc = %d\n", rc);
                RETURN(rc);
        }

        id_group(&sid) = mds->mds_num;
        id_fid(&sid) = mds->mds_virtid_fid;

        id_ino(&sid) = inode->i_ino;
        id_gen(&sid) = inode->i_generation;
        id_type(&sid) = (S_IFMT & inode->i_mode);

        down(&inode->i_sem);
        rc = mds_update_inode_sid(obd, inode, handle, &sid);
        up(&inode->i_sem);

        if (rc) {
                CERROR("mds_update_inode_sid() failed, rc = %d\n",
                       rc);
                RETURN(rc);
        }

        rc = fsfilt_commit(obd, mds->mds_sb, inode, handle, 0);
        if (rc) {
                CERROR("fsfilt_commit() failed, rc = %d\n", rc);
                RETURN(rc);
        }

        RETURN(rc);
}

int mds_fs_setup(struct obd_device *obd, struct vfsmount *mnt)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lvfs_run_ctxt saved;
        struct dentry *dentry;
        struct file *file;
        int rc;
        ENTRY;

        rc = cleanup_group_info();
        if (rc)
                RETURN(rc);

        mds->mds_vfsmnt = mnt;
        mds->mds_sb = mnt->mnt_root->d_inode->i_sb;

        fsfilt_setup(obd, mds->mds_sb);

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        obd->obd_lvfs_ctxt.cb_ops = mds_lvfs_ops;

        /* setup the directory tree */
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        dentry = simple_mkdir(current->fs->pwd, "ROOT", 0755, 0);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create ROOT directory: rc = %d\n", rc);
                GOTO(err_pop, rc);
        }

        mdc_pack_id(&mds->mds_rootid, dentry->d_inode->i_ino,
                    dentry->d_inode->i_generation, S_IFDIR, 0, 0);

        dput(dentry);
        
        dentry = lookup_one_len("__iopen__", current->fs->pwd,
                                strlen("__iopen__"));
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot lookup __iopen__ directory: rc = %d\n", rc);
                GOTO(err_pop, rc);
        }
        mds->mds_id_de = dentry;
        if (!dentry->d_inode || is_bad_inode(dentry->d_inode)) {
                rc = -ENOENT;
                CERROR("__iopen__ directory has no inode? rc = %d\n", rc);
                GOTO(err_id_de, rc);
        }

        dentry = simple_mkdir(current->fs->pwd, "PENDING", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create PENDING directory: rc = %d\n", rc);
                GOTO(err_id_de, rc);
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

        dentry = simple_mkdir(current->fs->pwd, "FIDS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create FIDS directory: rc = %d\n", rc);
                GOTO(err_objects, rc);
        }
        mds->mds_id_dir = dentry;

        dentry = simple_mkdir(current->fs->pwd, "UNNAMED", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create UNNAMED directory: rc = %d\n", rc);
                GOTO(err_unnamed, rc);
        }
        mds->mds_unnamed_dir = dentry;

        /* open and test the last rcvd file */
        file = filp_open(LAST_RCVD, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open/create %s file: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_id_dir, rc = PTR_ERR(file));
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

        /* open and test last fid file */
        file = filp_open(LAST_FID, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open/create %s file: rc = %d\n",
                       LAST_FID, rc);
                GOTO(err_client, rc = PTR_ERR(file));
        }
        mds->mds_fid_filp = file;
        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n",
                       LAST_FID, file->f_dentry->d_inode->i_mode);
                GOTO(err_last_fid, rc = -ENOENT);
        }

        rc = mds_read_last_fid(obd, file);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", LAST_FID, rc);
                GOTO(err_last_fid, rc);
        }

        /* open and test virtid fid file */
        file = filp_open(VIRT_FID, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open/create %s file: rc = %d\n",
                       VIRT_FID, rc);
                GOTO(err_last_fid, rc = PTR_ERR(file));
        }
        mds->mds_virtid_filp = file;
        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n",
                       VIRT_FID, file->f_dentry->d_inode->i_mode);
                GOTO(err_virtid_fid, rc = -ENOENT);
        }

        rc = mds_read_virtid_fid(obd, file);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", VIRT_FID, rc);
                GOTO(err_virtid_fid, rc);
        }
        
        /* open and test the lov objid file */
        file = filp_open(LOV_OBJID, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open/create %s file: rc = %d\n", LOV_OBJID, rc);
                GOTO(err_last_fid, rc = PTR_ERR(file));
        }
        mds->mds_dt_objid_filp = file;
        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LOV_OBJID,
                       file->f_dentry->d_inode->i_mode);
                GOTO(err_lov_objid, rc = -ENOENT);
        }
err_pop:
        if (!rc) {
                rc = mds_fs_post_setup(obd);
                if (rc)
                        CERROR("can not post setup fsfilt\n");        
        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        return rc;

err_lov_objid:
        if (mds->mds_dt_objid_filp && filp_close(mds->mds_dt_objid_filp, 0))
                CERROR("can't close %s after error\n", LOV_OBJID);
err_virtid_fid:
        if (mds->mds_virtid_filp && filp_close(mds->mds_virtid_filp, 0))
                CERROR("can't close %s after error\n", VIRT_FID);
err_last_fid:
        if (mds->mds_fid_filp && filp_close(mds->mds_fid_filp, 0))
                CERROR("can't close %s after error\n", LAST_FID);
err_client:
        class_disconnect_exports(obd, 0);
err_last_rcvd:
        if (mds->mds_rcvd_filp && filp_close(mds->mds_rcvd_filp, 0))
                CERROR("can't close %s after error\n", LAST_RCVD);
err_unnamed:
        dput(mds->mds_unnamed_dir);
err_id_dir:
        dput(mds->mds_id_dir);
err_objects:
        dput(mds->mds_objects_dir);
err_logs:
        dput(mds->mds_logs_dir);
err_pending:
        dput(mds->mds_pending_dir);
err_id_de:
        dput(mds->mds_id_de);
        goto err_pop;
}

static int  mds_fs_post_cleanup(struct obd_device *obd)
{
        int    rc = 0;
        rc = fsfilt_post_cleanup(obd);
        return rc; 
}

int mds_fs_cleanup(struct obd_device *obd, int flags)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lvfs_run_ctxt saved;
        int rc = 0;

        if (flags & OBD_OPT_FAILOVER)
                CERROR("%s: shutting down for failover; client state will"
                       " be preserved.\n", obd->obd_name);

        class_disconnect_exports(obd, flags); /* cleans up client info too */
        target_cleanup_recovery(obd);
        mds_server_free_data(mds);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (mds->mds_virtid_filp) {
                rc = filp_close(mds->mds_virtid_filp, 0);
                mds->mds_virtid_filp = NULL;
                if (rc)
                        CERROR("%s file won't close, rc = %d\n", VIRT_FID, rc);
        }
        if (mds->mds_fid_filp) {
                rc = filp_close(mds->mds_fid_filp, 0);
                mds->mds_fid_filp = NULL;
                if (rc)
                        CERROR("%s file won't close, rc = %d\n", LAST_FID, rc);
        }
        if (mds->mds_rcvd_filp) {
                rc = filp_close(mds->mds_rcvd_filp, 0);
                mds->mds_rcvd_filp = NULL;
                if (rc)
                        CERROR("%s file won't close, rc = %d\n", LAST_RCVD, rc);
        }
        if (mds->mds_dt_objid_filp) {
                rc = filp_close(mds->mds_dt_objid_filp, 0);
                mds->mds_dt_objid_filp = NULL;
                if (rc)
                        CERROR("%s file won't close, rc=%d\n", LOV_OBJID, rc);
        }
        if (mds->mds_unnamed_dir != NULL) {
                l_dput(mds->mds_unnamed_dir);
                mds->mds_unnamed_dir = NULL;
        }
        if (mds->mds_id_dir != NULL) {
                l_dput(mds->mds_id_dir);
                mds->mds_id_dir = NULL;
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
        rc = mds_fs_post_cleanup(obd);
        
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        shrink_dcache_parent(mds->mds_id_de);
        dput(mds->mds_id_de);

        return rc;
}

/* Creates an object with the same name as its id.  Because this is not at all
 * performance sensitive, it is accomplished by creating a file, checking the
 * id, and renaming it. */
int mds_obd_create(struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct mds_obd *mds = &exp->exp_obd->u.mds;
        struct inode *parent_inode = mds->mds_objects_dir->d_inode;
        struct file *filp;
        struct dentry *dchild;
        struct lvfs_run_ctxt saved;
        char idname[LL_ID_NAMELEN];
        int rc = 0, err, idlen;
        void *handle;
        ENTRY;

        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
        down(&parent_inode->i_sem);
        if (oa->o_id) {
                idlen = ll_id2str(idname, oa->o_id, oa->o_generation);
                dchild = lookup_one_len(idname, mds->mds_objects_dir, idlen);
                if (IS_ERR(dchild))
                        GOTO(out_pop, rc = PTR_ERR(dchild));

                if (dchild->d_inode == NULL) {
                        struct dentry_params dp;
                        struct inode *inode;

                        CWARN("creating log with ID "LPU64"\n", oa->o_id);
                        
                        dchild->d_fsdata = (void *) &dp;
                        dp.p_ptr = NULL;
                        dp.p_inum = oa->o_id;
                        rc = ll_vfs_create(parent_inode, dchild, S_IFREG, NULL);
                        if (dchild->d_fsdata == (void *)(unsigned long)oa->o_id)
                                dchild->d_fsdata = NULL;
                        if (rc) {
                                CDEBUG(D_INODE, "err during create: %d\n", rc);
                                dput(dchild);
                                GOTO(out_pop, rc);
                        }
                        inode = dchild->d_inode;
                        LASSERT(inode->i_ino == oa->o_id);
                        inode->i_generation = oa->o_generation;
                        CDEBUG(D_HA, "recreated ino %lu with gen %u\n",
                               inode->i_ino, inode->i_generation);
                        mark_inode_dirty(inode);
                } else {
                        CWARN("it should be here!\n");
                }
                GOTO(out_pop, rc);
        }

        sprintf(idname, "OBJECTS/%u.%u", ll_insecure_random_int(), current->pid);
        filp = filp_open(idname, O_CREAT | O_EXCL, 0644);
        if (IS_ERR(filp)) {
                rc = PTR_ERR(filp);
                if (rc == -EEXIST) {
                        CERROR("impossible object name collision %s\n",
                               idname);
                        LBUG();
                }
                CERROR("error creating tmp object %s: rc %d\n", 
                       idname, rc);
                GOTO(out_pop, rc);
        }

        LASSERT(mds->mds_objects_dir == filp->f_dentry->d_parent);

        oa->o_id = filp->f_dentry->d_inode->i_ino;
        oa->o_generation = filp->f_dentry->d_inode->i_generation;
        idlen = ll_id2str(idname, oa->o_id, oa->o_generation);
        
        CWARN("created log anonymous "LPU64"/%u\n",
              oa->o_id, oa->o_generation);

        dchild = lookup_one_len(idname, mds->mds_objects_dir, idlen);
        if (IS_ERR(dchild)) {
                CERROR("getting neg dentry for obj rename: %d\n", rc);
                GOTO(out_close, rc = PTR_ERR(dchild));
        }
        if (dchild->d_inode != NULL) {
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
                        mds->mds_objects_dir->d_inode, dchild);
        unlock_kernel();
        if (rc)
                CERROR("error renaming new object "LPU64":%u: rc %d\n",
                       oa->o_id, oa->o_generation, rc);

        err = fsfilt_commit(exp->exp_obd, mds->mds_sb, 
                            mds->mds_objects_dir->d_inode, handle, 0);
        if (!err) {
                oa->o_gr = FILTER_GROUP_FIRST_MDS + mds->mds_num;
                oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGENER | OBD_MD_FLGROUP;
        } else if (!rc)
                rc = err;
out_dput:
        dput(dchild);
out_close:
        err = filp_close(filp, 0);
        if (err) {
                CERROR("closing tmpfile %s: rc %d\n", idname, rc);
                if (!rc)
                        rc = err;
        }
out_pop:
        up(&parent_inode->i_sem);
        pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
        RETURN(rc);
}

int mds_obd_destroy(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *ea, struct obd_trans_info *oti)
{
        struct mds_obd *mds = &exp->exp_obd->u.mds;
        struct inode *parent_inode = mds->mds_objects_dir->d_inode;
        struct obd_device *obd = exp->exp_obd;
        struct lvfs_run_ctxt saved;
        char idname[LL_ID_NAMELEN];
        struct dentry *de;
        void *handle;
        int err, idlen, rc = 0;
        ENTRY;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        idlen = ll_id2str(idname, oa->o_id, oa->o_generation);

        down(&parent_inode->i_sem);
        de = lookup_one_len(idname, mds->mds_objects_dir, idlen);
        if (IS_ERR(de) || de->d_inode == NULL) {
                rc = IS_ERR(de) ? PTR_ERR(de) : -ENOENT;
                CERROR("destroying non-existent object "LPU64" %s: rc %d\n",
                       oa->o_id, idname, rc);
                GOTO(out_dput, rc);
        }
        /* Stripe count is 1 here since this is some MDS specific stuff
           that is unlinked, not spanned across multiple OSTs */
        handle = fsfilt_start_log(obd, mds->mds_objects_dir->d_inode,
                                  FSFILT_OP_UNLINK, oti, 1);

        if (IS_ERR(handle))
                GOTO(out_dput, rc = PTR_ERR(handle));
        
        rc = vfs_unlink(mds->mds_objects_dir->d_inode, de);
        if (rc) 
                CERROR("error destroying object "LPU64":%u: rc %d\n",
                       oa->o_id, oa->o_generation, rc);
        
        err = fsfilt_commit(obd, mds->mds_sb, mds->mds_objects_dir->d_inode, 
                            handle, exp->exp_sync);
        if (err && !rc)
                rc = err;
out_dput:
        if (de != NULL)
                l_dput(de);
        up(&parent_inode->i_sem);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        RETURN(rc);
}
