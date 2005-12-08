/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  mgs/mgs_fs.c
 *  Lustre Management Server (MGS) filesystem interface code
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Nathan <nathan@clusterfs.com>
 *   Author: LinSongtao <lincent@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_MGS

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/lustre_quota.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/mount.h>
#endif
#include <linux/lustre_mgs.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_disk.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_commit_confd.h>
#include <libcfs/list.h>
#include "mgs_internal.h"

int mgs_fs_setup(struct obd_device *obd, struct vfsmount *mnt)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lvfs_run_ctxt saved;
        struct dentry *dentry;
        int rc;
        ENTRY;

        rc = cleanup_group_info();
        if (rc)
                RETURN(rc);

        mgs->mgs_vfsmnt = mnt;
        mgs->mgs_sb = mnt->mnt_root->d_inode->i_sb;

        fsfilt_setup(obd, mgs->mgs_sb);

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        obd->obd_lvfs_ctxt.cb_ops = mgs_lvfs_ops;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        /* Setup the configs dir */
        dentry = simple_mkdir(current->fs->pwd, MOUNT_CONFIGS_DIR, 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create %s directory: rc = %d\n", 
                       MOUNT_CONFIGS_DIR, rc);
                GOTO(err_pop, rc);
        }
        mgs->mgs_configs_dir = dentry;

        /* Need the iopen dir for fid2dentry, required by
           LLOG_ORIGIN_HANDLE_READ_HEADER */
        dentry = lookup_one_len("__iopen__", current->fs->pwd,
                                strlen("__iopen__"));
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot lookup __iopen__ directory: rc = %d\n", rc);
                GOTO(err_configs, rc);
        }
        mgs->mgs_fid_de = dentry;
        if (!dentry->d_inode || is_bad_inode(dentry->d_inode)) {
                rc = -ENOENT;
                CERROR("__iopen__ directory has no inode? rc = %d\n", rc);
                GOTO(err_fid, rc);
        }

err_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        return rc;
err_fid:
        dput(mgs->mgs_fid_de);
err_configs:
        dput(mgs->mgs_configs_dir);
        goto err_pop;
}

int mgs_fs_cleanup(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lvfs_run_ctxt saved;
        int rc = 0;

        class_disconnect_exports(obd); /* cleans up client info too */

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        if (mgs->mgs_configs_dir) {
                CERROR("configs dir dcount=%d\n",
                       atomic_read(&mgs->mgs_configs_dir->d_count));
                l_dput(mgs->mgs_configs_dir);
                mgs->mgs_configs_dir = NULL;
        }

        shrink_dcache_parent(mgs->mgs_fid_de);
        CERROR("fid dir dcount=%d\n",
               atomic_read(&mgs->mgs_fid_de->d_count));
        dput(mgs->mgs_fid_de);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        return rc;
}
