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
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>
#include <obd_class.h>
#include <obd_lov.h>
#include <lustre_lib.h>
#include <lustre_fsfilt.h>
#include <lustre_ver.h>

#include "mds_internal.h"

void mds_lov_update_objids(struct obd_device *obd, obd_id *ids)
{
        struct mds_obd *mds = &obd->u.mds;
        int i;
        ENTRY;

        lock_kernel();
        for (i = 0; i < mds->mds_lov_desc.ld_tgt_count; i++)
                if (ids[i] > (mds->mds_lov_objids)[i]) {
                        (mds->mds_lov_objids)[i] = ids[i];
                        mds->mds_lov_objids_dirty = 1;
                }
        unlock_kernel();
        EXIT;
}
EXPORT_SYMBOL(mds_lov_update_objids);

static int mds_lov_read_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        obd_id *ids;
        loff_t off = 0;
        int i, rc, size;
        ENTRY;

        LASSERT(!mds->mds_lov_objids_size);
        LASSERT(!mds->mds_lov_objids_dirty);

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
                RETURN(rc);
        }

        mds->mds_lov_objids_in_file = size / sizeof(*ids);

        for (i = 0; i < mds->mds_lov_objids_in_file; i++) {
                CDEBUG(D_INFO, "read last object "LPU64" for idx %d\n",
                       mds->mds_lov_objids[i], i);
        }
        RETURN(0);
}

int mds_lov_write_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        loff_t off = 0;
        int i, rc, tgts;
        ENTRY;

        if (!mds->mds_lov_objids_dirty)
                RETURN(0);

        tgts = max(mds->mds_lov_desc.ld_tgt_count, mds->mds_lov_objids_in_file);

        if (!tgts)
                RETURN(0);

        for (i = 0; i < tgts; i++)
                CDEBUG(D_INFO, "writing last object "LPU64" for idx %d\n",
                       mds->mds_lov_objids[i], i);

        rc = fsfilt_write_record(obd, mds->mds_lov_objid_filp,
                                 mds->mds_lov_objids, tgts * sizeof(obd_id),
                                 &off, 0);
        if (rc >= 0) {
                mds->mds_lov_objids_dirty = 0;
                rc = 0;
        }

        RETURN(rc);
}
EXPORT_SYMBOL(mds_lov_write_objids);

int mds_lov_clear_orphans(struct mds_obd *mds, struct obd_uuid *ost_uuid)
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
        oa.o_flags = OBD_FL_DELORPHAN;
        oa.o_gr = FILTER_GROUP_MDS0 + mds->mds_id;
        oa.o_valid = OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
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

        rc = obd_set_info_async(mds->mds_osc_exp, strlen(KEY_NEXT_ID),
                                KEY_NEXT_ID,
                                mds->mds_lov_desc.ld_tgt_count,
                                mds->mds_lov_objids, NULL);

        if (rc)
                CERROR ("%s: mds_lov_set_nextid failed (%d)\n",
                        obd->obd_name, rc);

        RETURN(rc);
}

/* Update the lov desc for a new size lov. */
static int mds_lov_update_desc(struct obd_device *obd, struct obd_export *lov)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_desc *ld;
        __u32 size, stripes, valsize = sizeof(mds->mds_lov_desc);
        int rc = 0;
        ENTRY;

        OBD_ALLOC(ld, sizeof(*ld));
        if (!ld)
                RETURN(-ENOMEM);

        rc = obd_get_info(lov, strlen(KEY_LOVDESC) + 1, KEY_LOVDESC,
                          &valsize, ld);
        if (rc)
                GOTO(out, rc);

        /* The size of the LOV target table may have increased. */
        size = ld->ld_tgt_count * sizeof(obd_id);
        if ((mds->mds_lov_objids_size == 0) ||
            (size > mds->mds_lov_objids_size)) {
                obd_id *ids;

                /* add room by powers of 2 */
                size = 1;
                while (size < ld->ld_tgt_count)
                        size = size << 1;
                size = size * sizeof(obd_id);

                OBD_ALLOC(ids, size);
                if (ids == NULL)
                        GOTO(out, rc = -ENOMEM);
                memset(ids, 0, size);
                if (mds->mds_lov_objids_size) {
                        obd_id *old_ids = mds->mds_lov_objids;
                        memcpy(ids, mds->mds_lov_objids,
                               mds->mds_lov_objids_size);
                        mds->mds_lov_objids = ids;
                        OBD_FREE(old_ids, mds->mds_lov_objids_size);
                }
                mds->mds_lov_objids = ids;
                mds->mds_lov_objids_size = size;
        }

        /* Don't change the mds_lov_desc until the objids size matches the
           count (paranoia) */
        mds->mds_lov_desc = *ld;
        CDEBUG(D_CONFIG, "updated lov_desc, tgt_count: %d\n",
               mds->mds_lov_desc.ld_tgt_count);

        stripes = min_t(__u32, LOV_MAX_STRIPE_COUNT,
                        max(mds->mds_lov_desc.ld_tgt_count,
                            mds->mds_lov_objids_in_file));
        mds->mds_max_mdsize = lov_mds_md_size(stripes);
        mds->mds_max_cookiesize = stripes * sizeof(struct llog_cookie);
        CDEBUG(D_CONFIG, "updated max_mdsize/max_cookiesize: %d/%d\n",
               mds->mds_max_mdsize, mds->mds_max_cookiesize);

        /*XXX this notifies the MDD until lov handling use old mds code */
        if (obd->obd_upcall.onu_owner) {
                 LASSERT(obd->obd_upcall.onu_upcall != NULL);
                 rc = obd->obd_upcall.onu_upcall(NULL, NULL, 0,
                                                 obd->obd_upcall.onu_owner);
        }
out:
        OBD_FREE(ld, sizeof(*ld));
        RETURN(rc);
}


#define MDSLOV_NO_INDEX -1

/* Inform MDS about new/updated target */
static int mds_lov_update_mds(struct obd_device *obd,
                              struct obd_device *watched,
                              __u32 idx, struct obd_uuid *uuid)
{
        struct mds_obd *mds = &obd->u.mds;
        int old_count;
        int rc = 0;
        ENTRY;

        old_count = mds->mds_lov_desc.ld_tgt_count;
        rc = mds_lov_update_desc(obd, mds->mds_osc_exp);
        if (rc)
                RETURN(rc);

        CDEBUG(D_CONFIG, "idx=%d, recov=%d/%d, cnt=%d/%d\n",
               idx, obd->obd_recovering, obd->obd_async_recov, old_count,
               mds->mds_lov_desc.ld_tgt_count);

        /* idx is set as data from lov_notify. */
        if (idx != MDSLOV_NO_INDEX && !obd->obd_recovering) {
                if (idx >= mds->mds_lov_desc.ld_tgt_count) {
                        CERROR("index %d > count %d!\n", idx,
                               mds->mds_lov_desc.ld_tgt_count);
                        RETURN(-EINVAL);
                }

                if (idx >= mds->mds_lov_objids_in_file) {
                        /* We never read this lastid; ask the osc */
                        obd_id lastid;
                        __u32 size = sizeof(lastid);
                        rc = obd_get_info(watched->obd_self_export,
                                          strlen("last_id"),
                                          "last_id", &size, &lastid);
                        if (rc)
                                RETURN(rc);
                        mds->mds_lov_objids[idx] = lastid;
                        mds->mds_lov_objids_dirty = 1;
                        mds_lov_write_objids(obd);
                } else {
                        /* We have read this lastid from disk; tell the osc.
                           Don't call this during recovery. */
                        rc = mds_lov_set_nextid(obd);
                }

                CDEBUG(D_CONFIG, "last object "LPU64" from OST %d\n",
                      mds->mds_lov_objids[idx], idx);
        }

        /* If we added a target we have to reconnect the llogs */
        /* We only _need_ to do this at first add (idx), or the first time
           after recovery.  However, it should now be safe to call anytime. */
        CDEBUG(D_CONFIG, "reset llogs idx=%d\n", idx);
        mutex_down(&obd->obd_dev_sem);
        llog_cat_initialize(obd, NULL, mds->mds_lov_desc.ld_tgt_count, uuid);
        mutex_up(&obd->obd_dev_sem);

        RETURN(rc);
}

/* update the LOV-OSC knowledge of the last used object id's */
int mds_lov_connect(struct obd_device *obd, char * lov_name)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_handle conn = {0,};
        struct obd_connect_data *data;
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

        OBD_ALLOC(data, sizeof(*data));
        if (data == NULL)
                RETURN(-ENOMEM);
        data->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_INDEX |
                                  OBD_CONNECT_REQPORTAL | OBD_CONNECT_QUOTA64 |
                                  OBD_CONNECT_OSS_CAPA;
        data->ocd_version = LUSTRE_VERSION_CODE;
        data->ocd_group = mds->mds_id +  FILTER_GROUP_MDS0;
        /* NB: lov_connect() needs to fill in .ocd_index for each OST */
        rc = obd_connect(NULL, &conn, mds->mds_osc_obd, &obd->obd_uuid, data);
        OBD_FREE(data, sizeof(*data));
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
        rc = llog_cat_initialize(obd, NULL, mds->mds_lov_desc.ld_tgt_count, NULL);
        if (rc) {
                CERROR("failed to initialize catalog %d\n", rc);
                GOTO(err_reg, rc);
        }

        /* If we're mounting this code for the first time on an existing FS,
         * we need to populate the objids array from the real OST values */
        if (mds->mds_lov_desc.ld_tgt_count > mds->mds_lov_objids_in_file) {
                int size = sizeof(obd_id) * mds->mds_lov_desc.ld_tgt_count;
                rc = obd_get_info(mds->mds_osc_exp, strlen("last_id"),
                                  "last_id", &size, mds->mds_lov_objids);
                if (!rc) {
                        for (i = 0; i < mds->mds_lov_desc.ld_tgt_count; i++)
                                CWARN("got last object "LPU64" from OST %d\n",
                                      mds->mds_lov_objids[i], i);
                        mds->mds_lov_objids_dirty = 1;
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
        /* MDD device will care about that
        if (!obd->obd_recovering)
                rc = mds_postrecov(obd);
         */
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
                                 &mds->mds_cfg_llh, NULL, name);
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
                rc = fsfilt_sync(obd, obd->u.obt.obt_sb);
                RETURN(rc);
        }

        case OBD_IOC_SET_READONLY: {
                void *handle;
                struct inode *inode = obd->u.obt.obt_sb->s_root->d_inode;
                BDEVNAME_DECLARE_STORAGE(tmp);
                CERROR("*** setting device %s read-only ***\n",
                       ll_bdevname(obd->u.obt.obt_sb, tmp));

                handle = fsfilt_start(obd, inode, FSFILT_OP_MKNOD, NULL);
                if (!IS_ERR(handle))
                        rc = fsfilt_commit(obd, inode, handle, 1);

                CDEBUG(D_HA, "syncing mds %s\n", obd->obd_name);
                rc = fsfilt_sync(obd, obd->u.obt.obt_sb);

                lvfs_set_rdonly(lvfs_sbdev(obd->u.obt.obt_sb));
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
                __u32 group;

                obd_llog_finish(obd, mds->mds_lov_desc.ld_tgt_count);
                push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                rc = llog_ioctl(ctxt, cmd, data);
                pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                llog_cat_initialize(obd, NULL, mds->mds_lov_desc.ld_tgt_count, NULL);
                group = FILTER_GROUP_MDS0 + mds->mds_id;
                rc2 = obd_set_info_async(mds->mds_osc_exp,
                                         strlen(KEY_MDS_CONN), KEY_MDS_CONN,
                                         sizeof(group), &group, NULL);
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
                target_stop_recovery_thread(obd);
                RETURN(0);

        default:
                CDEBUG(D_INFO, "unknown command %x\n", cmd);
                RETURN(-EINVAL);
        }
        RETURN(0);

}

struct mds_lov_sync_info {
        struct obd_device *mlsi_obd;     /* the lov device to sync */
        struct obd_device *mlsi_watched; /* target osc */
        __u32              mlsi_index;   /* index of target */
};

static int mds_propagate_capa_keys(struct mds_obd *mds)
{
        struct lustre_capa_key *key;
        int i, rc = 0;

        ENTRY;

        if (!mds->mds_capa_keys)
                RETURN(0);

        for (i = 0; i < 2; i++) {
                key = &mds->mds_capa_keys[i];
                DEBUG_CAPA_KEY(D_SEC, key, "propagate");

                rc = obd_set_info_async(mds->mds_osc_exp, strlen(KEY_CAPA_KEY),
                                        KEY_CAPA_KEY, sizeof(*key), key, NULL);
                if (rc) {
                        DEBUG_CAPA_KEY(D_ERROR, key,
                                       "propagate failed (rc = %d) for", rc);
                        RETURN(rc);
                }
        }

        RETURN(0);
}

/* We only sync one osc at a time, so that we don't have to hold
   any kind of lock on the whole mds_lov_desc, which may change
   (grow) as a result of mds_lov_add_ost.  This also avoids any
   kind of mismatch between the lov_desc and the mds_lov_desc,
   which are not in lock-step during lov_add_obd */
static int __mds_lov_synchronize(void *data)
{
        struct mds_lov_sync_info *mlsi = data;
        struct obd_device *obd = mlsi->mlsi_obd;
        struct obd_device *watched = mlsi->mlsi_watched;
        struct mds_obd *mds = &obd->u.mds;
        struct obd_uuid *uuid;
        __u32  idx = mlsi->mlsi_index;
        struct mds_group_info mgi;
        int rc = 0;
        ENTRY;

        OBD_FREE(mlsi, sizeof(*mlsi));

        LASSERT(obd);
        LASSERT(watched);
        uuid = &watched->u.cli.cl_target_uuid;
        LASSERT(uuid);

        rc = mds_lov_update_mds(obd, watched, idx, uuid);
        if (rc != 0)
                GOTO(out, rc);
        mgi.group = FILTER_GROUP_MDS0 + mds->mds_id;
        mgi.uuid = uuid;
        rc = obd_set_info_async(mds->mds_osc_exp, strlen(KEY_MDS_CONN),
                                KEY_MDS_CONN, sizeof(mgi), &mgi, NULL);
        if (rc != 0)
                GOTO(out, rc);

        /* propagate capability keys */
        rc = mds_propagate_capa_keys(mds);
        if (rc)
                GOTO(out, rc);

        rc = llog_connect(llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT),
                          mds->mds_lov_desc.ld_tgt_count,
                          NULL, NULL, uuid);

        if (rc != 0) {
                CERROR("%s: failed at llog_origin_connect: %d\n",
                       obd->obd_name, rc);
                GOTO(out, rc);
        }

        LCONSOLE_INFO("MDS %s: %s now active, resetting orphans\n",
              obd->obd_name, obd_uuid2str(uuid));

        if (obd->obd_stopping)
                GOTO(out, rc = -ENODEV);

        rc = mds_lov_clear_orphans(mds, uuid);
        if (rc != 0) {
                CERROR("%s: failed at mds_lov_clear_orphans: %d\n",
                       obd->obd_name, rc);
                GOTO(out, rc);
        }
        
        if (obd->obd_upcall.onu_owner) {
                /*
                 * This is a hack for mds_notify->mdd_notify. When the mds obd
                 * in mdd is removed, This hack should be removed.
                 */
                 LASSERT(obd->obd_upcall.onu_upcall != NULL);
                 rc = obd->obd_upcall.onu_upcall(NULL, NULL, 0,
                                                 obd->obd_upcall.onu_owner);
        }
        EXIT;
out:
        class_decref(obd);
        return rc;
}

int mds_lov_synchronize(void *data)
{
        struct mds_lov_sync_info *mlsi = data;
        char name[20];

        if (mlsi->mlsi_index == MDSLOV_NO_INDEX)
                /* There is still a watched target,
                but we don't know its index */
                sprintf(name, "ll_sync_tgt");
        else
                snprintf(name, sizeof(name), "ll_sync_%02u", mlsi->mlsi_index);
        ptlrpc_daemonize(name);

        RETURN(__mds_lov_synchronize(data));
}

int mds_lov_start_synchronize(struct obd_device *obd,
                              struct obd_device *watched,
                              void *data, int nonblock)
{
        struct mds_lov_sync_info *mlsi;
        int rc;

        ENTRY;

        LASSERT(watched);

        OBD_ALLOC(mlsi, sizeof(*mlsi));
        if (mlsi == NULL)
                RETURN(-ENOMEM);

        mlsi->mlsi_obd = obd;
        mlsi->mlsi_watched = watched;
        if (data)
                mlsi->mlsi_index = *(__u32 *)data;
        else
                mlsi->mlsi_index = MDSLOV_NO_INDEX;

        /* Although class_export_get(obd->obd_self_export) would lock
           the MDS in place, since it's only a self-export
           it doesn't lock the LOV in place.  The LOV can be disconnected
           during MDS precleanup, leaving nothing for __mds_lov_synchronize.
           Simply taking an export ref on the LOV doesn't help, because it's
           still disconnected. Taking an obd reference insures that we don't
           disconnect the LOV.  This of course means a cleanup won't
           finish for as long as the sync is blocking. */
        class_incref(obd);

        if (nonblock) {
                /* Synchronize in the background */
                rc = cfs_kernel_thread(mds_lov_synchronize, mlsi,
                                       CLONE_VM | CLONE_FILES);
                if (rc < 0) {
                        CERROR("%s: error starting mds_lov_synchronize: %d\n",
                               obd->obd_name, rc);
                        class_decref(obd);
                } else {
                        CDEBUG(D_HA, "%s: mds_lov_synchronize idx=%d "
                               "thread=%d\n", obd->obd_name,
                               mlsi->mlsi_index, rc);
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
        int rc = 0;
        ENTRY;

        switch (ev) {
        /* We only handle these: */
        case OBD_NOTIFY_ACTIVE:
        case OBD_NOTIFY_SYNC:
        case OBD_NOTIFY_SYNC_NONBLOCK:
                break;
        default:
                RETURN(0);
        }

        CDEBUG(D_CONFIG, "notify %s ev=%d\n", watched->obd_name, ev);

        if (strcmp(watched->obd_type->typ_name, LUSTRE_OSC_NAME) != 0) {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name, watched->obd_name);
                RETURN(-EINVAL);
        }

        if (obd->obd_recovering) {
                CWARN("MDS %s: in recovery, not resetting orphans on %s\n",
                      obd->obd_name,
                      obd_uuid2str(&watched->u.cli.cl_target_uuid));
                /* We still have to fix the lov descriptor for ost's added
                   after the mdt in the config log.  They didn't make it into
                   mds_lov_connect. */
                rc = mds_lov_update_desc(obd, obd->u.mds.mds_osc_exp);
                if (rc)
                        RETURN(rc);
                /* We should update init llog here too for replay unlink and 
                 * possiable llog init race when recovery complete */
                mutex_down(&obd->obd_dev_sem);
                llog_cat_initialize(obd, NULL, 
                                    obd->u.mds.mds_lov_desc.ld_tgt_count,
                                    &watched->u.cli.cl_target_uuid);
                mutex_up(&obd->obd_dev_sem);
                RETURN(rc);
        }

        LASSERT(llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT) != NULL);
        rc = mds_lov_start_synchronize(obd, watched, data,
                                       !(ev == OBD_NOTIFY_SYNC));

        lquota_recovery(quota_interface, obd);

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

        if (le32_to_cpu(lmm->lmm_magic) == LOV_MAGIC ||
            le32_to_cpu(lmm->lmm_magic == LOV_MAGIC_JOIN))
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

        rc = fsfilt_set_md(obd, inode, handle, lmm, lmm_size, "lov");

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
EXPORT_SYMBOL(mds_objids_from_lmm);
