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
 * lustre/mds/handler.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Mike Shaver <shaver@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <lustre_mds.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/smp_lock.h>
#include <linux/buffer_head.h>
#include <linux/workqueue.h>
#include <linux/mount.h>

#include <lustre_acl.h>
#include <obd_class.h>
#include <lustre_dlm.h>
#include <obd_lov.h>
#include <lustre_fsfilt.h>
#include <lprocfs_status.h>
#include <lustre_quota.h>
#include <lustre_disk.h>
#include <lustre_param.h>

#include "mds_internal.h"

__u32 mds_max_ost_index=0xFFFF;
CFS_MODULE_PARM(mds_max_ost_index, "i", int, 0444,
                "maximal OST index");

/* Look up an entry by inode number. */
/* this function ONLY returns valid dget'd dentries with an initialized inode
   or errors */
struct dentry *mds_fid2dentry(struct mds_obd *mds, struct ll_fid *fid,
                              struct vfsmount **mnt)
{
        char fid_name[32];
        unsigned long ino = fid->id;
        __u32 generation = fid->generation;
        struct inode *inode;
        struct dentry *result;

        if (ino == 0)
                RETURN(ERR_PTR(-ESTALE));

        snprintf(fid_name, sizeof(fid_name), "0x%lx", ino);

        CDEBUG(D_DENTRY, "--> mds_fid2dentry: ino/gen %lu/%u, sb %p\n",
               ino, generation, mds->mds_obt.obt_sb);

        /* under ext3 this is neither supposed to return bad inodes
           nor NULL inodes. */
        result = ll_lookup_one_len(fid_name, mds->mds_fid_de, strlen(fid_name));
        if (IS_ERR(result))
                RETURN(result);

        inode = result->d_inode;
        if (!inode)
                RETURN(ERR_PTR(-ENOENT));

        if (inode->i_generation == 0 || inode->i_nlink == 0) {
                LCONSOLE_WARN("Found inode with zero generation or link -- this"
                              " may indicate disk corruption (inode: %lu/%u, "
                              "link %lu, count %d)\n", inode->i_ino,
                              inode->i_generation,(unsigned long)inode->i_nlink,
                              atomic_read(&inode->i_count));
                dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        if (generation && inode->i_generation != generation) {
                /* we didn't find the right inode.. */
                CDEBUG(D_INODE, "found wrong generation: inode %lu, link: %lu, "
                       "count: %d, generation %u/%u\n", inode->i_ino,
                       (unsigned long)inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       generation);
                dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        if (mnt) {
                *mnt = mds->mds_vfsmnt;
                mntget(*mnt);
        }

        RETURN(result);
}

static int mds_lov_presetup (struct mds_obd *mds, struct lustre_cfg *lcfg)
{
        int rc = 0;
        ENTRY;

        if (lcfg->lcfg_bufcount >= 4 && LUSTRE_CFG_BUFLEN(lcfg, 3) > 0) {
                class_uuid_t uuid;

                ll_generate_random_uuid(uuid);
                class_uuid_unparse(uuid, &mds->mds_lov_uuid);

                OBD_ALLOC(mds->mds_profile, LUSTRE_CFG_BUFLEN(lcfg, 3));
                if (mds->mds_profile == NULL)
                        RETURN(-ENOMEM);

                strncpy(mds->mds_profile, lustre_cfg_string(lcfg, 3),
                        LUSTRE_CFG_BUFLEN(lcfg, 3));
        }
        RETURN(rc);
}

static int mds_lov_clean(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_device *osc = mds->mds_osc_obd;
        ENTRY;

        if (mds->mds_profile) {
                class_del_profile(mds->mds_profile);
                OBD_FREE(mds->mds_profile, strlen(mds->mds_profile) + 1);
                mds->mds_profile = NULL;
        }

        /* There better be a lov */
        if (!osc)
                RETURN(0);
        if (IS_ERR(osc))
                RETURN(PTR_ERR(osc));

        obd_register_observer(osc, NULL);

        /* Give lov our same shutdown flags */
        osc->obd_force = obd->obd_force;
        osc->obd_fail = obd->obd_fail;

        /* Cleanup the lov */
        obd_disconnect(mds->mds_osc_exp);
        class_manual_cleanup(osc);

        RETURN(0);
}

static int mds_postsetup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        rc = llog_setup(obd, &obd->obd_olg, LLOG_CONFIG_ORIG_CTXT, obd, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                RETURN(rc);

        rc = llog_setup(obd, &obd->obd_olg, LLOG_LOVEA_ORIG_CTXT, obd, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                RETURN(rc);

        if (mds->mds_profile) {
                struct lustre_profile *lprof;
                /* The profile defines which osc and mdc to connect to, for a
                   client.  We reuse that here to figure out the name of the
                   lov to use (and ignore lprof->lp_md).
                   The profile was set in the config log with
                   LCFG_MOUNTOPT profilenm oscnm mdcnm */
                lprof = class_get_profile(mds->mds_profile);
                if (lprof == NULL) {
                        CERROR("No profile found: %s\n", mds->mds_profile);
                        GOTO(err_cleanup, rc = -ENOENT);
                }
                rc = mds_lov_connect(obd, lprof->lp_dt);
                if (rc)
                        GOTO(err_cleanup, rc);
        }

        RETURN(rc);

err_cleanup:
        mds_lov_clean(obd);
        llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));
        llog_cleanup(llog_get_context(obd, LLOG_LOVEA_ORIG_CTXT));
        RETURN(rc);
}

int mds_postrecov(struct obd_device *obd)
{
        int rc = 0;
        ENTRY;

        if (obd->obd_fail)
                RETURN(0);

        LASSERT(!obd->obd_recovering);
        LASSERT(!llog_ctxt_null(obd, LLOG_MDS_OST_ORIG_CTXT));

        /* clean PENDING dir */
#if 0
        if (strncmp(obd->obd_name, MDD_OBD_NAME, strlen(MDD_OBD_NAME)))
                rc = mds_cleanup_pending(obd);
                if (rc < 0)
                        GOTO(out, rc);
#endif
        /* FIXME Does target_finish_recovery really need this to block? */
        /* Notify the LOV, which will in turn call mds_notify for each tgt */
        /* This means that we have to hack obd_notify to think we're obd_set_up
           during mds_lov_connect. */
        obd_notify(obd->u.mds.mds_osc_obd, NULL,
                   obd->obd_async_recov ? OBD_NOTIFY_SYNC_NONBLOCK :
                   OBD_NOTIFY_SYNC, NULL);

        /* quota recovery */
        lquota_recovery(mds_quota_interface_ref, obd);

        RETURN(rc);
}

/* We need to be able to stop an mds_lov_synchronize */
static int mds_lov_early_clean(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_device *osc = mds->mds_osc_obd;

        if (!osc || (!obd->obd_force && !obd->obd_fail))
                return(0);

        CDEBUG(D_HA, "abort inflight\n");
        return (obd_precleanup(osc, OBD_CLEANUP_EARLY));
}

static int mds_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        int rc = 0;
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_EARLY:
                break;
        case OBD_CLEANUP_EXPORTS:
                mds_lov_early_clean(obd);
                down_write(&mds->mds_notify_lock);
                mds_lov_disconnect(obd);
                mds_lov_clean(obd);
                llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));
                llog_cleanup(llog_get_context(obd, LLOG_LOVEA_ORIG_CTXT));
                rc = obd_llog_finish(obd, 0);
                mds->mds_osc_exp = NULL;
                up_write(&mds->mds_notify_lock);
                break;
        }
        RETURN(rc);
}

static struct dentry *mds_lvfs_fid2dentry(__u64 id, __u32 gen, __u64 gr,
                                          void *data)
{
        struct obd_device *obd = data;
        struct ll_fid fid;
        fid.id = id;
        fid.generation = gen;
        return mds_fid2dentry(&obd->u.mds, &fid, NULL);
}


struct lvfs_callback_ops mds_lvfs_ops = {
        l_fid2dentry:     mds_lvfs_fid2dentry,
};

quota_interface_t *mds_quota_interface_ref;
extern quota_interface_t mds_quota_interface;

static void mds_init_ctxt(struct obd_device *obd, struct vfsmount *mnt)
{
        struct mds_obd *mds = &obd->u.mds;

        mds->mds_vfsmnt = mnt;
        /* why not mnt->mnt_sb instead of mnt->mnt_root->d_inode->i_sb? */
        obd->u.obt.obt_sb = mnt->mnt_root->d_inode->i_sb;

        fsfilt_setup(obd, obd->u.obt.obt_sb);

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        obd->obd_lvfs_ctxt.cb_ops = mds_lvfs_ops;
        return;
}

/*mds still need lov setup here*/
static int mds_cmd_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lvfs_run_ctxt saved;
        const char     *dev;
        struct vfsmount *mnt;
        struct lustre_sb_info *lsi;
        struct lustre_mount_info *lmi;
        struct dentry  *dentry;
        int rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "obd %s setup \n", obd->obd_name);
        if (strncmp(obd->obd_name, MDD_OBD_NAME, strlen(MDD_OBD_NAME)))
                RETURN(0);

        if (lcfg->lcfg_bufcount < 5) {
                CERROR("invalid arg for setup %s\n", MDD_OBD_NAME);
                RETURN(-EINVAL);
        }
        dev = lustre_cfg_string(lcfg, 4);
        lmi = server_get_mount(dev);
        LASSERT(lmi != NULL);

        lsi = s2lsi(lmi->lmi_sb);
        mnt = lmi->lmi_mnt;
        /* FIXME: MDD LOV initialize objects.
         * we need only lmi here but not get mount
         * OSD did mount already, so put mount back
         */
        atomic_dec(&lsi->lsi_mounts);
        mntput(mnt);
        init_rwsem(&mds->mds_notify_lock);

        obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        mds_init_ctxt(obd, mnt);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        dentry = simple_mkdir(current->fs->pwd, mnt, "OBJECTS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create OBJECTS directory: rc = %d\n", rc);
                GOTO(err_putfs, rc);
        }
        mds->mds_objects_dir = dentry;

        dentry = lookup_one_len("__iopen__", current->fs->pwd,
                                strlen("__iopen__"));
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot lookup __iopen__ directory: rc = %d\n", rc);
                GOTO(err_objects, rc);
        }

        mds->mds_fid_de = dentry;
        if (!dentry->d_inode || is_bad_inode(dentry->d_inode)) {
                rc = -ENOENT;
                CERROR("__iopen__ directory has no inode? rc = %d\n", rc);
                GOTO(err_fid, rc);
        }
        rc = mds_lov_init_objids(obd);
        if (rc != 0) {
               CERROR("cannot init lov objid rc = %d\n", rc);
               GOTO(err_fid, rc );
        }

        rc = mds_lov_presetup(mds, lcfg);
        if (rc < 0)
                GOTO(err_objects, rc);

        /* Don't wait for mds_postrecov trying to clear orphans */
        obd->obd_async_recov = 1;
        rc = mds_postsetup(obd);
        /* Bug 11557 - allow async abort_recov start
           FIXME can remove most of this obd_async_recov plumbing
        obd->obd_async_recov = 0;
        */

        if (rc)
                GOTO(err_objects, rc);

        mds->mds_max_mdsize = sizeof(struct lov_mds_md_v3);
        mds->mds_max_cookiesize = sizeof(struct llog_cookie);

err_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        RETURN(rc);
err_fid:
        dput(mds->mds_fid_de);
err_objects:
        dput(mds->mds_objects_dir);
err_putfs:
        fsfilt_put_ops(obd->obd_fsops);
        goto err_pop;
}

static int mds_cmd_cleanup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lvfs_run_ctxt saved;
        int rc = 0;
        ENTRY;

        mds->mds_osc_exp = NULL;

        if (obd->obd_fail)
                LCONSOLE_WARN("%s: shutting down for failover; client state "
                              "will be preserved.\n", obd->obd_name);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        mds_lov_destroy_objids(obd);

        if (mds->mds_objects_dir != NULL) {
                l_dput(mds->mds_objects_dir);
                mds->mds_objects_dir = NULL;
        }

        shrink_dcache_parent(mds->mds_fid_de);
        dput(mds->mds_fid_de);
        LL_DQUOT_OFF(obd->u.obt.obt_sb);
        fsfilt_put_ops(obd->obd_fsops);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        RETURN(rc);
}

#if 0
static int mds_cmd_health_check(struct obd_device *obd)
{
        return 0;
}
#endif
static struct obd_ops mds_cmd_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_setup           = mds_cmd_setup,
        .o_cleanup         = mds_cmd_cleanup,
        .o_precleanup      = mds_precleanup,
        .o_create          = mds_obd_create,
        .o_destroy         = mds_obd_destroy,
        .o_llog_init       = mds_llog_init,
        .o_llog_finish     = mds_llog_finish,
        .o_notify          = mds_notify,
        .o_postrecov       = mds_postrecov,
        //   .o_health_check    = mds_cmd_health_check,
};

static int __init mds_cmd_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_mds_init_vars(&lvars);
        class_register_type(&mds_cmd_obd_ops, NULL, lvars.module_vars,
                            LUSTRE_MDS_NAME, NULL);

        return 0;
}

static void /*__exit*/ mds_cmd_exit(void)
{
        class_unregister_type(LUSTRE_MDS_NAME);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS)");
MODULE_LICENSE("GPL");

module_init(mds_cmd_init);
module_exit(mds_cmd_exit);
