/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_lov.c
 *  Lustre Metadata Server (mds) handling of striped file data
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_fsfilt.h>

#include "mds_internal.h"

void mds_lov_update_objids(struct obd_device *obd, obd_id *ids)
{
        struct mds_obd *mds = &obd->u.mds;
        int i;
        ENTRY;

        lock_kernel();
        for (i = 0; i < mds->mds_lov_desc.ld_tgt_count; i++)
                if (ids[i] > (mds->mds_lov_objids)[i])
                        (mds->mds_lov_objids)[i] = ids[i];
        unlock_kernel();
        EXIT;
}

static int mds_lov_read_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        obd_id *ids;
        loff_t off = 0;
        int i, rc, size;
        ENTRY;

        LASSERT(!mds->mds_lov_objids_size);

        /* Read everything in the file, even if our current lov desc 
           has fewer targets. Old targets not in the lov descriptor 
           during mds setup may still have valid objids. */
        size = mds->mds_lov_objid_filp->f_dentry->d_inode->i_size;
        if (size == 0)
                RETURN(0);

        OBD_ALLOC(ids, size);
        if (ids == NULL)
                RETURN(-ENOMEM);
        mds->mds_lov_objids = ids;
        mds->mds_lov_objids_size = size;

        rc = fsfilt_read_record(obd, mds->mds_lov_objid_filp, ids, size, &off);
        if (rc < 0) {
                CERROR("Error reading objids %d\n", rc);
        } else {
                mds->mds_lov_objids_red = size / sizeof(*ids); 
                rc = 0;
        }

        for (i = 0; i < mds->mds_lov_objids_red; i++)
                CDEBUG(D_INFO, "read last object "LPU64" for idx %d\n",
                       mds->mds_lov_objids[i], i);

        RETURN(rc);
}

int mds_lov_write_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        loff_t off = 0;
        int i, rc, size = mds->mds_lov_desc.ld_tgt_count * sizeof(obd_id);
        ENTRY;

        if (!mds->mds_lov_desc.ld_tgt_count)
                RETURN(0);

        for (i = 0; i < mds->mds_lov_desc.ld_tgt_count; i++)
                CDEBUG(D_INFO, "writing last object "LPU64" for idx %d\n",
                       mds->mds_lov_objids[i], i);

        rc = fsfilt_write_record(obd, mds->mds_lov_objid_filp,
                                 mds->mds_lov_objids, size, &off, 0);
        RETURN(rc);
}

int mds_lov_clearorphans(struct mds_obd *mds, struct obd_uuid *ost_uuid)
{
        int rc;
        struct obdo oa;
        struct obd_trans_info oti = {0};
        struct lov_stripe_md  *empty_ea = NULL;
        ENTRY;

        LASSERT(mds->mds_lov_objids != NULL);

        /* This create will in fact either create or destroy:  If the OST is
         * missing objects below this ID, they will be created.  If it finds
         * objects above this ID, they will be removed. */
        memset(&oa, 0, sizeof(oa));
        oa.o_valid = OBD_MD_FLFLAGS;
        oa.o_flags = OBD_FL_DELORPHAN;
        if (ost_uuid != NULL) {
                memcpy(&oa.o_inline, ost_uuid, sizeof(*ost_uuid));
                oa.o_valid |= OBD_MD_FLINLINE;
        }
        rc = obd_create(mds->mds_osc_exp, &oa, &empty_ea, &oti);

        RETURN(rc);
}

/* update the LOV-OSC knowledge of the last used object id's */
int mds_lov_set_nextid(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc;
        ENTRY;

        LASSERT(!obd->obd_recovering);

        LASSERT(mds->mds_lov_objids != NULL);

        rc = obd_set_info(mds->mds_osc_exp, strlen("next_id"), "next_id",
                          mds->mds_lov_desc.ld_tgt_count, mds->mds_lov_objids);
        RETURN(rc);
}

/* Update the lov desc for a new size lov.
   From HEAD mds_dt_lov_update_desc (but fixed) */
static int mds_lov_update_desc(struct obd_device *obd, struct obd_export *lov)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_desc *ld; 
        __u32 valsize = sizeof(mds->mds_lov_desc);
        int rc = 0, i, size;
        ENTRY;

        OBD_ALLOC(ld, sizeof(*ld));
        if (!ld)
                RETURN(-ENOMEM);

        rc = obd_get_info(lov, strlen("lovdesc") + 1, "lovdesc",
                          &valsize, ld);
        if (rc)
                GOTO(out, rc);

        /* The size of the LOV target table may have increased. */
        size = ld->ld_tgt_count * sizeof(obd_id);
        if ((mds->mds_lov_objids_size == 0) || 
            (size > mds->mds_lov_objids_size)) {
                obd_id *ids;
                
                /* add room for a bunch at a time */
                size = (ld->ld_tgt_count + 8) * sizeof(obd_id);

                OBD_ALLOC(ids, size);
                if (ids == NULL)
                        GOTO(out, rc = -ENOMEM);
                memset(ids, 0, size);
                if (mds->mds_lov_objids_size) {
                        memcpy(ids, mds->mds_lov_objids, 
                               mds->mds_lov_objids_size);
                        OBD_FREE(mds->mds_lov_objids, mds->mds_lov_objids_size);
                }
                mds->mds_lov_objids = ids;
                mds->mds_lov_objids_size = size;
        }

        /* Only update the tgt count after we have an objid ready.
           The objid may invalidly be 0 right now - is that a problem? */
        mds->mds_lov_desc = *ld;

        i = lov_mds_md_size(mds->mds_lov_desc.ld_tgt_count);
        if (i > mds->mds_max_mdsize)
                mds->mds_max_mdsize = i;
        mds->mds_max_cookiesize = mds->mds_lov_desc.ld_tgt_count *
                                  sizeof(struct llog_cookie);
        mds->mds_has_lov_desc = 1;
out:
        OBD_FREE(ld, sizeof(*ld));
        RETURN(rc);
}

int mds_lov_connect(struct obd_device *obd, char * lov_name)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_handle conn = {0,};
        int rc, i;
        ENTRY;

        if (IS_ERR(mds->mds_osc_obd))
                RETURN(PTR_ERR(mds->mds_osc_obd));

        if (mds->mds_osc_obd)
                RETURN(0);

        mds->mds_osc_obd = class_name2obd(lov_name);
        if (!mds->mds_osc_obd) {
                CERROR("MDS cannot locate LOV %s\n", lov_name);
                mds->mds_osc_obd = ERR_PTR(-ENOTCONN);
                RETURN(-ENOTCONN);
        }

        rc = obd_connect(&conn, mds->mds_osc_obd, &obd->obd_uuid,
                         NULL /* obd_connect_data */);
        if (rc) {
                CERROR("MDS cannot connect to LOV %s (%d)\n", lov_name, rc);
                mds->mds_osc_obd = ERR_PTR(rc);
                RETURN(rc);
        }
        mds->mds_osc_exp = class_conn2export(&conn);

        rc = obd_register_observer(mds->mds_osc_obd, obd);
        if (rc) {
                CERROR("MDS cannot register as observer of LOV %s (%d)\n",
                       lov_name, rc);
                GOTO(err_discon, rc);
        }

        rc = mds_lov_read_objids(obd);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", "lov_objids", rc);
                GOTO(err_reg, rc);
        }

        rc = mds_lov_update_desc(obd, mds->mds_osc_exp);
        if (rc)
                GOTO(err_reg, rc);

        /* tgt_count may be 0! */
        rc = llog_cat_initialize(obd, mds->mds_lov_desc.ld_tgt_count);
        if (rc) {
                CERROR("failed to initialize catalog %d\n", rc);
                GOTO(err_reg, rc);
        }

        /* If we're mounting this code for the first time on an existing FS,
         * we need to populate the objids array from the real OST values */
        if (mds->mds_lov_desc.ld_tgt_count > mds->mds_lov_objids_red) {
                int size = sizeof(obd_id) * mds->mds_lov_desc.ld_tgt_count;
                rc = obd_get_info(mds->mds_osc_exp, strlen("last_id"),
                                  "last_id", &size, mds->mds_lov_objids);
                if (!rc) {
                        for (i = 0; i < mds->mds_lov_desc.ld_tgt_count; i++)
                                CWARN("got last object "LPU64" from OST %d\n",
                                      mds->mds_lov_objids[i], i);
                        rc = mds_lov_write_objids(obd);
                        if (rc)
                                CERROR("got last objids from OSTs, but error "
                                       "writing objids file: %d\n", rc);
                }
        }

        /* I want to see a callback happen when the OBD moves to a
         * "For General Use" state, and that's when we'll call
         * set_nextid().  The class driver can help us here, because
         * it can use the obd_recovering flag to determine when the
         * the OBD is full available. */
        if (!obd->obd_recovering)
                rc = mds_postrecov(obd);
        RETURN(rc);

err_reg:
        obd_register_observer(mds->mds_osc_obd, NULL);
err_discon:
        obd_disconnect(mds->mds_osc_exp);
        mds->mds_osc_exp = NULL;
        mds->mds_osc_obd = ERR_PTR(rc);
        RETURN(rc);
}

int mds_lov_disconnect(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        if (!IS_ERR(mds->mds_osc_obd) && mds->mds_osc_exp != NULL) {
                obd_register_observer(mds->mds_osc_obd, NULL);

                /* The actual disconnect of the mds_lov will be called from
                 * class_disconnect_exports from mds_lov_clean. So we have to
                 * ensure that class_cleanup doesn't fail due to the extra ref
                 * we're holding now. The mechanism to do that already exists -
                 * the obd_force flag. We'll drop the final ref to the
                 * mds_osc_exp in mds_cleanup. */
                mds->mds_osc_obd->obd_force = 1;
        }

        RETURN(rc);
}

int mds_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                  void *karg, void *uarg)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct obd_device *obd = exp->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct obd_ioctl_data *data = karg;
        struct lvfs_run_ctxt saved;
        int rc = 0;

        ENTRY;
        CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);

        switch (cmd) {
        case OBD_IOC_RECORD: {
                char *name = data->ioc_inlbuf1;
                if (mds->mds_cfg_llh)
                        RETURN(-EBUSY);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                                 &mds->mds_cfg_llh, NULL,  name);
                if (rc == 0)
                        llog_init_handle(mds->mds_cfg_llh, LLOG_F_IS_PLAIN,
                                         &cfg_uuid);
                else
                        mds->mds_cfg_llh = NULL;
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                RETURN(rc);
        }

        case OBD_IOC_ENDRECORD: {
                if (!mds->mds_cfg_llh)
                        RETURN(-EBADF);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_close(mds->mds_cfg_llh);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                mds->mds_cfg_llh = NULL;
                RETURN(rc);
        }

        case OBD_IOC_CLEAR_LOG: {
                char *name = data->ioc_inlbuf1;
                if (mds->mds_cfg_llh)
                        RETURN(-EBUSY);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                                 &mds->mds_cfg_llh, NULL, name);
                if (rc == 0) {
                        llog_init_handle(mds->mds_cfg_llh, LLOG_F_IS_PLAIN,
                                         NULL);

                        rc = llog_destroy(mds->mds_cfg_llh);
                        llog_free_handle(mds->mds_cfg_llh);
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                mds->mds_cfg_llh = NULL;
                RETURN(rc);
        }

        case OBD_IOC_DORECORD: {
                char *cfg_buf;
                struct llog_rec_hdr rec;
                if (!mds->mds_cfg_llh)
                        RETURN(-EBADF);

                rec.lrh_len = llog_data_len(data->ioc_plen1);

                if (data->ioc_type == LUSTRE_CFG_TYPE) {
                        rec.lrh_type = OBD_CFG_REC;
                } else {
                        CERROR("unknown cfg record type:%d \n", data->ioc_type);
                        RETURN(-EINVAL);
                }

                OBD_ALLOC(cfg_buf, data->ioc_plen1);
                if (cfg_buf == NULL)
                        RETURN(-EINVAL);
                rc = copy_from_user(cfg_buf, data->ioc_pbuf1, data->ioc_plen1);
                if (rc) {
                        OBD_FREE(cfg_buf, data->ioc_plen1);
                        RETURN(rc);
                }

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_write_rec(mds->mds_cfg_llh, &rec, NULL, 0,
                                    cfg_buf, -1);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                OBD_FREE(cfg_buf, data->ioc_plen1);
                RETURN(rc);
        }

        case OBD_IOC_PARSE: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = class_config_parse_llog(ctxt, data->ioc_inlbuf1, NULL);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        RETURN(rc);

                RETURN(rc);
        }

        case OBD_IOC_DUMP_LOG: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = class_config_dump_llog(ctxt, data->ioc_inlbuf1, NULL);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        RETURN(rc);

                RETURN(rc);
        }

        case OBD_IOC_SYNC: {
                CDEBUG(D_HA, "syncing mds %s\n", obd->obd_name);
                rc = fsfilt_sync(obd, obd->u.mds.mds_sb);
                RETURN(rc);
        }

        case OBD_IOC_SET_READONLY: {
                void *handle;
                struct inode *inode = obd->u.mds.mds_sb->s_root->d_inode;
                BDEVNAME_DECLARE_STORAGE(tmp);
                CERROR("*** setting device %s read-only ***\n",
                       ll_bdevname(obd->u.mds.mds_sb, tmp));

                handle = fsfilt_start(obd, inode, FSFILT_OP_MKNOD, NULL);
                if (!IS_ERR(handle))
                        rc = fsfilt_commit(obd, inode, handle, 1);

                CDEBUG(D_HA, "syncing mds %s\n", obd->obd_name);
                rc = fsfilt_sync(obd, obd->u.mds.mds_sb);

                lvfs_set_rdonly(lvfs_sbdev(obd->u.mds.mds_sb));
                RETURN(0);
        }

        case OBD_IOC_CATLOGLIST: {
                int count = mds->mds_lov_desc.ld_tgt_count;
                rc = llog_catalog_list(obd, count, data);
                RETURN(rc);

        }
        case OBD_IOC_LLOG_CHECK:
        case OBD_IOC_LLOG_CANCEL:
        case OBD_IOC_LLOG_REMOVE: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                int rc2;

                obd_llog_finish(obd, mds->mds_lov_desc.ld_tgt_count);
                push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                rc = llog_ioctl(ctxt, cmd, data);
                pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                llog_cat_initialize(obd, mds->mds_lov_desc.ld_tgt_count);
                rc2 = obd_set_info(mds->mds_osc_exp, strlen("mds_conn"),
                                   "mds_conn", 0, NULL);
                if (!rc)
                        rc = rc2;
                RETURN(rc);
        }
        case OBD_IOC_LLOG_INFO:
        case OBD_IOC_LLOG_PRINT: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);

                push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                rc = llog_ioctl(ctxt, cmd, data);
                pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);

                RETURN(rc);
        }

        case OBD_IOC_ABORT_RECOVERY:
                CERROR("aborting recovery for device %s\n", obd->obd_name);
                target_abort_recovery(obd);
                RETURN(0);

        default:
                CDEBUG(D_INFO, "unknown command %x\n", cmd);
                RETURN(-EINVAL);
        }
        RETURN(0);

}

struct mds_lov_sync_info {
        struct obd_device *mlsi_obd; /* the lov device to sync */
        struct obd_uuid   *mlsi_uuid;  /* target to sync */
};

static int __mds_lov_synchronize(void *data)
{
        struct mds_lov_sync_info *mlsi = data;
        struct obd_device *obd;
        struct obd_uuid *uuid;
        int rc = 0;
        ENTRY;

        obd = mlsi->mlsi_obd;
        uuid = mlsi->mlsi_uuid;

        OBD_FREE(mlsi, sizeof(*mlsi));

        LASSERT(obd != NULL);

        rc = obd_set_info(obd->u.mds.mds_osc_exp, strlen("mds_conn"),
                          "mds_conn", 0, uuid);
        if (rc != 0)
                GOTO(out, rc);

        rc = llog_connect(llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT),
                          obd->u.mds.mds_lov_desc.ld_tgt_count,
                          NULL, NULL, uuid);
        if (rc != 0) {
                CERROR("%s: failed at llog_origin_connect: %d\n",
                       obd->obd_name, rc);
                GOTO(out, rc);
        }

        if (uuid)
                CWARN("MDS %s: %s now active, resetting orphans\n",
                      obd->obd_name, (char *)uuid->uuid);
        else
                CWARN("MDS %s: All %d OSC's now active, resetting orphans\n",
                      obd->obd_name, obd->u.mds.mds_lov_desc.ld_tgt_count);

        if (obd->obd_stopping)
                GOTO(out, rc = -ENODEV);

        rc = mds_lov_clearorphans(&obd->u.mds, uuid);
        if (rc != 0) {
                CERROR("%s: failed at mds_lov_clearorphans: %d\n",
                       obd->obd_name, rc);
                GOTO(out, rc);
        }

out:
        class_decref(obd);
        RETURN(rc);
}

int mds_lov_synchronize(void *data)
{
        unsigned long flags;

        lock_kernel();
        ptlrpc_daemonize();

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
        unlock_kernel();

        return (__mds_lov_synchronize(data));
}

int mds_lov_start_synchronize(struct obd_device *obd, struct obd_uuid *uuid,
                              int nonblock)
{
        struct mds_lov_sync_info *mlsi;
        int rc;

        ENTRY;

        OBD_ALLOC(mlsi, sizeof(*mlsi));
        if (mlsi == NULL)
                RETURN(-ENOMEM);

        mlsi->mlsi_obd = obd;
        mlsi->mlsi_uuid = uuid;

        /* Although class_export_get(obd->obd_self_export) would lock
           the MDS in place, since it's only a self-export
           it doesn't lock the LOV in place.  The LOV can be disconnected
           during MDS precleanup, leaving nothing for __mds_lov_synchronize.
           Simply taking an export ref on the LOV doesn't help, because it's
           still disconnected. Taking an obd reference insures that we don't
           disconnect the LOV.  This of course means a cleanup won't
           finish for as long as the sync is blocking. */
        atomic_inc(&obd->obd_refcount);

        if (nonblock) {
                /* Syncronize in the background */
                rc = kernel_thread(mds_lov_synchronize, mlsi, CLONE_VM | CLONE_FILES);
                if (rc < 0) {
                        CERROR("%s: error starting mds_lov_synchronize: %d\n",
                               obd->obd_name, rc);
                        class_export_put(obd->obd_self_export);
                } else {
                        CDEBUG(D_HA, "%s: mds_lov_synchronize thread: %d\n",
                               obd->obd_name, rc);
                        rc = 0;
                }
        } else {
                rc = __mds_lov_synchronize((void *)mlsi);
        }

        RETURN(rc);
}

int mds_notify(struct obd_device *obd, struct obd_device *watched,
               enum obd_notify_event ev, void *data)
{
        struct obd_uuid *uuid;
        int idx = (int)data;
        int rc = 0;
        ENTRY;

        if (ev != OBD_NOTIFY_ACTIVE)
                RETURN(0);

        if (strcmp(watched->obd_type->typ_name, LUSTRE_OSC_NAME)) {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name, watched->obd_name);
                RETURN(-EINVAL);
        }

        uuid = &watched->u.cli.cl_import->imp_target_uuid;

        if (obd->obd_recovering) {
                CWARN("MDS %s: in recovery, not resetting orphans on %s\n",
                      obd->obd_name, uuid->uuid);
                RETURN(rc);
        } 

        /* FIXME Put all this in the sync, so that we don't change the
           tgt_count out from under it.  We also can't run multiple 
           sync threads simultaneously.  This means we need a single 
           permanent sync thread that we occationally wake to re-sync.
           Sigh, but for a single uuid or a whole lov? */
        /* Tell the mds_lov about the new target */
        if (idx & LOV_IDX_MAGIC) {
                struct mds_obd *mds = &obd->u.mds;
                int old_count = mds->mds_lov_desc.ld_tgt_count;

                idx &= ~LOV_IDX_MAGIC;
                //FIXME remove D_ERROR
                CDEBUG(D_CONFIG|D_ERROR, "Updating mds lov for OST idx %d\n", idx);

                rc = mds_lov_update_desc(obd, mds->mds_osc_exp);
                if (rc)
                        RETURN(rc);
        
                if (idx >= mds->mds_lov_desc.ld_tgt_count) {
                        CERROR("index %d > count %d!\n", idx, 
                               mds->mds_lov_desc.ld_tgt_count);
                        RETURN(-EINVAL);
                }
                
                /* Don't get_info unless we never read it -- this will
                   block on a missing OST */
                if (idx >= mds->mds_lov_objids_red) {
                        obd_id lastid;
                        __u32 size = sizeof(lastid);
                        rc = obd_get_info(watched->obd_self_export,
                                          strlen("last_id"), 
                                          "last_id", &size, &lastid);
                        if (rc)
                                RETURN(rc);
                        mds->mds_lov_objids[idx] = lastid;
                        CWARN("got last object "LPU64" from OST %d\n",
                              mds->mds_lov_objids[idx], idx);
                        rc = mds_lov_write_objids(obd);
                }
                
                obd_llog_finish(obd, old_count);
                llog_cat_initialize(obd, mds->mds_lov_desc.ld_tgt_count);
        }

        LASSERT(llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT) != NULL);
        rc = mds_lov_start_synchronize(obd, uuid, 1);
        RETURN(rc);
}

/* Convert the on-disk LOV EA structre.
 * We always try to convert from an old LOV EA format to the common in-memory
 * (lsm) format (obd_unpackmd() understands the old on-disk (lmm) format) and
 * then convert back to the new on-disk format and save it back to disk
 * (obd_packmd() only ever saves to the new on-disk format) so we don't have
 * to convert it each time this inode is accessed.
 *
 * This function is a bit interesting in the error handling.  We can safely
 * ship the old lmm to the client in case of failure, since it uses the same
 * obd_unpackmd() code and can do the conversion if the MDS fails for some
 * reason.  We will not delete the old lmm data until we have written the
 * new format lmm data in fsfilt_set_md(). */
int mds_convert_lov_ea(struct obd_device *obd, struct inode *inode,
                       struct lov_mds_md *lmm, int lmm_size)
{
        struct lov_stripe_md *lsm = NULL;
        void *handle;
        int rc, err;
        ENTRY;

        if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC)
                RETURN(0);

        CDEBUG(D_INODE, "converting LOV EA on %lu/%u from %#08x to %#08x\n",
               inode->i_ino, inode->i_generation, le32_to_cpu(lmm->lmm_magic),
               LOV_MAGIC);
        rc = obd_unpackmd(obd->u.mds.mds_osc_exp, &lsm, lmm, lmm_size);
        if (rc < 0)
                GOTO(conv_end, rc);

        rc = obd_packmd(obd->u.mds.mds_osc_exp, &lmm, lsm);
        if (rc < 0)
                GOTO(conv_free, rc);
        lmm_size = rc;

        handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                GOTO(conv_free, rc);
        }

        rc = fsfilt_set_md(obd, inode, handle, lmm, lmm_size);

        err = fsfilt_commit(obd, inode, handle, 0);
        if (!rc)
                rc = err ? err : lmm_size;
        GOTO(conv_free, rc);
conv_free:
        obd_free_memmd(obd->u.mds.mds_osc_exp, &lsm);
conv_end:
        return rc;
}

void mds_objids_from_lmm(obd_id *ids, struct lov_mds_md *lmm,
                         struct lov_desc *desc)
{
        int i;
        for (i = 0; i < le32_to_cpu(lmm->lmm_stripe_count); i++) {
                ids[le32_to_cpu(lmm->lmm_objects[i].l_ost_idx)] =
                        le64_to_cpu(lmm->lmm_objects[i].l_object_id);
        }
}

