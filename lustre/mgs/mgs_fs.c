/*
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
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

#define DEBUG_SUBSYSTEM S_MGS

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_disk.h>
#include <lustre_lib.h>
#include <lustre_fsfilt.h>
#include <libcfs/list.h>
#include "mgs_internal.h"

int mgs_export_stats_init(struct obd_device *obd, struct obd_export *exp,
                          void *localdata)

{
        lnet_nid_t *client_nid = localdata;
        int rc, newnid;
        ENTRY;

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
                int num_stats = 0;

                num_stats = (sizeof(*obd->obd_type->typ_dt_ops) / sizeof(void *)) +
                            LPROC_MGS_LAST - 1;
                tmp->nid_stats = lprocfs_alloc_stats(num_stats,
                                                     LPROCFS_STATS_FLAG_NOPERCPU);
                if (tmp->nid_stats == NULL)
                        return -ENOMEM;
                lprocfs_init_ops_stats(LPROC_MGS_LAST, tmp->nid_stats);
                mgs_stats_counter_init(tmp->nid_stats);
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

/**
 * Add client export data to the MGS.  This data is currently NOT stored on
 * disk in the last_rcvd file or anywhere else.  In the event of a MGS
 * crash all connections are treated as new connections.
 */
int mgs_client_add(struct obd_device *obd, struct obd_export *exp,
                   void *localdata)
{
        return 0;
}

/* Remove client export data from the MGS */
int mgs_client_free(struct obd_export *exp)
{
        return 0;
}

/* Same as mds_lvfs_fid2dentry */
/* Look up an entry by inode number. */
/* this function ONLY returns valid dget'd dentries with an initialized inode
   or errors */
static struct dentry *mgs_lvfs_fid2dentry(__u64 id, __u32 gen,
                                          __u64 gr, void *data)
{
        struct fsfilt_fid  fid;
        struct obd_device *obd = (struct obd_device *)data;
        ENTRY;

        CDEBUG(D_DENTRY, "--> mgs_fid2dentry: ino/gen %lu/%u, sb %p\n",
               (unsigned long)id, gen, obd->u.mgs.mgs_sb);

        if (id == 0)
                RETURN(ERR_PTR(-ESTALE));

        fid.ino = id;
        fid.gen = gen;

        RETURN(fsfilt_fid2dentry(obd, obd->u.mgs.mgs_vfsmnt, &fid, 0));
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
        rc = cfs_cleanup_group_info();
        if (rc)
                RETURN(rc);

        mgs->mgs_vfsmnt = mnt;
        mgs->mgs_sb = mnt->mnt_root->d_inode->i_sb;

        rc = fsfilt_setup(obd, mgs->mgs_sb);
        if (rc)
                RETURN(rc);

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        obd->obd_lvfs_ctxt.cb_ops = mgs_lvfs_ops;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        /* Setup the configs dir */
        dentry = simple_mkdir(cfs_fs_pwd(current->fs), mnt, MOUNT_CONFIGS_DIR, 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create %s directory: rc = %d\n",
                       MOUNT_CONFIGS_DIR, rc);
                GOTO(err_pop, rc);
        }
        mgs->mgs_configs_dir = dentry;

        /* create directory to store nid table versions */
        dentry = simple_mkdir(cfs_fs_pwd(current->fs), mnt, MGS_NIDTBL_DIR,
                              0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create %s directory: rc = %d\n",
                       MOUNT_CONFIGS_DIR, rc);
                GOTO(err_pop, rc);
        } else {
                dput(dentry);
        }

err_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        return rc;
}

int mgs_fs_cleanup(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lvfs_run_ctxt saved;
        int rc = 0;

        class_disconnect_exports(obd); /* cleans up client info too */

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        if (mgs->mgs_configs_dir) {
                l_dput(mgs->mgs_configs_dir);
                mgs->mgs_configs_dir = NULL;
        }

        shrink_dcache_sb(mgs->mgs_sb);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        return rc;
}
