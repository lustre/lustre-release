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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mgs/mgs_fs.c
 *
 * Lustre Management Server (MGS) filesystem interface code
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MGS

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/version.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/mount.h>
#endif
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_disk.h>
#include <lustre_lib.h>
#include <lustre_fsfilt.h>
#include <libcfs/list.h>
#include "mgs_internal.h"


static int mgs_export_stats_init(struct obd_device *obd,
                                 struct obd_export *exp,
                                 void *localdata)
{
        lnet_nid_t *client_nid = localdata;
        int rc, num_stats, newnid = 0;

        rc = lprocfs_exp_setup(exp, client_nid, &newnid);
        if (rc) {
                /* Mask error for already created
                 * /proc entries */
                if (rc == -EALREADY)
                        rc = 0;
                return rc;
        }

        if (newnid) {
                num_stats = (sizeof(*obd->obd_type->typ_ops) / sizeof(void *)) +
                             LPROC_MGS_LAST - 1;
                exp->exp_ops_stats = lprocfs_alloc_stats(num_stats,
                                                         LPROCFS_STATS_FLAG_NOPERCPU);
                if (exp->exp_ops_stats == NULL)
                        return -ENOMEM;
                lprocfs_init_ops_stats(LPROC_MGS_LAST, exp->exp_ops_stats);
                mgs_stats_counter_init(exp->exp_ops_stats);
                lprocfs_register_stats(exp->exp_nid_stats->nid_proc, "stats", exp->exp_ops_stats);

                /* Always add in ldlm_stats */
                exp->exp_nid_stats->nid_ldlm_stats = lprocfs_alloc_stats(LDLM_LAST_OPC -
                                                                         LDLM_FIRST_OPC, 0);
                if (exp->exp_nid_stats->nid_ldlm_stats == NULL)
                        return -ENOMEM;

                lprocfs_init_ldlm_stats(exp->exp_nid_stats->nid_ldlm_stats);

                rc = lprocfs_register_stats(exp->exp_nid_stats->nid_proc, "ldlm_stats",
                                            exp->exp_nid_stats->nid_ldlm_stats);
        }

        return 0;
}

/* Add client export data to the MGS.  This data is currently NOT stored on
 * disk in the last_rcvd file or anywhere else.  In the event of a MGS
 * crash all connections are treated as new connections.
 */
int mgs_client_add(struct obd_device *obd,
                   struct obd_export *exp,
                   void *localdata)
{
        return mgs_export_stats_init(obd, exp, localdata);
}

/* Remove client export data from the MGS */
int mgs_client_free(struct obd_export *exp)
{
        return 0; 
}

/* Same as mds_fid2dentry */
/* Look up an entry by inode number. */
/* this function ONLY returns valid dget'd dentries with an initialized inode
   or errors */
static struct dentry *mgs_fid2dentry(struct mgs_obd *mgs, struct ll_fid *fid)
{
        char fid_name[32];
        unsigned long ino = fid->id;
        __u32 generation = fid->generation;
        struct inode *inode;
        struct dentry *result;

        CDEBUG(D_DENTRY, "--> mgs_fid2dentry: ino/gen %lu/%u, sb %p\n",
               ino, generation, mgs->mgs_sb);

        if (ino == 0)
                RETURN(ERR_PTR(-ESTALE));

        snprintf(fid_name, sizeof(fid_name), "0x%lx", ino);

        /* under ext3 this is neither supposed to return bad inodes
           nor NULL inodes. */
        result = ll_lookup_one_len(fid_name, mgs->mgs_fid_de, strlen(fid_name));
        if (IS_ERR(result))
                RETURN(result);

        inode = result->d_inode;
        if (!inode)
                RETURN(ERR_PTR(-ENOENT));

        if (inode->i_generation == 0 || inode->i_nlink == 0) {
                LCONSOLE_WARN("Found inode with zero generation or link -- this"
                              " may indicate disk corruption (inode: %lu, link:"
                              " %lu, count: %d)\n", inode->i_ino,
                              (unsigned long)inode->i_nlink,
                              atomic_read(&inode->i_count));
                l_dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        if (generation && inode->i_generation != generation) {
                /* we didn't find the right inode.. */
                CDEBUG(D_INODE, "found wrong generation: inode %lu, link: %lu, "
                       "count: %d, generation %u/%u\n", inode->i_ino,
                       (unsigned long)inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       generation);
                l_dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        RETURN(result);
}

static struct dentry *mgs_lvfs_fid2dentry(__u64 id, __u32 gen, __u64 gr,
                                          void *data)
{
        struct obd_device *obd = data;
        struct ll_fid fid;
        fid.id = id;
        fid.generation = gen;
        return mgs_fid2dentry(&obd->u.mgs, &fid);
}

struct lvfs_callback_ops mgs_lvfs_ops = {
        l_fid2dentry:     mgs_lvfs_fid2dentry,
};

int mgs_fs_setup(struct obd_device *obd, struct vfsmount *mnt)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lvfs_run_ctxt saved;
        struct dentry *dentry;
        int rc;
        ENTRY;

        /* FIXME what's this?  Do I need it? */
        rc = cleanup_group_info();
        if (rc)
                RETURN(rc);

        mgs->mgs_vfsmnt = mnt;
        mgs->mgs_sb = mnt->mnt_root->d_inode->i_sb;

        rc = fsfilt_setup(obd, mgs->mgs_sb);
        if (rc)
                CWARN("fail to set fsfilter options\n");

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        obd->obd_lvfs_ctxt.cb_ops = mgs_lvfs_ops;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        /* Setup the configs dir */
        dentry = simple_mkdir(current->fs->pwd, mnt, MOUNT_CONFIGS_DIR, 0777, 1);
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
                /*CERROR("configs dir dcount=%d\n",
                       atomic_read(&mgs->mgs_configs_dir->d_count));*/
                l_dput(mgs->mgs_configs_dir);
                mgs->mgs_configs_dir = NULL;
        }

        shrink_dcache_parent(mgs->mgs_fid_de);
        /*CERROR("fid dir dcount=%d\n",
               atomic_read(&mgs->mgs_fid_de->d_count));*/
        dput(mgs->mgs_fid_de);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        return rc;
}
