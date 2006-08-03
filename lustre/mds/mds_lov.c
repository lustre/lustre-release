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
#include <dt_object.h>

#include "mds_internal.h"

void md_lov_info_update_objids(struct md_lov_info *mli, obd_id *ids)
{
        int i;
        lock_kernel();
        for (i = 0; i < mli->md_lov_desc.ld_tgt_count; i++)
                if (ids[i] > (mli->md_lov_objids)[i]) {
                        (mli->md_lov_objids)[i] = ids[i];
                        mli->md_lov_objids_dirty = 1;
                }
        unlock_kernel();
}

void mds_lov_update_objids(struct obd_device *obd, obd_id *ids)
{
        struct mds_obd *mds = &obd->u.mds;

        md_lov_info_update_objids(&mds->mds_lov_info, ids);
}

static int mds_lov_read_objids(struct obd_device *obd, struct md_lov_info *mli,
                               const void *ctxt)
{
        struct file *filp = (struct file *)mli->md_lov_objid_obj;
        obd_id *ids;
        loff_t off = 0;
        int i, rc, size;
        ENTRY;

        LASSERT(!mli->md_lov_objids_size);
        LASSERT(!mli->md_lov_objids_dirty);

        /* Read everything in the file, even if our current lov desc
           has fewer targets. Old targets not in the lov descriptor
           during mds setup may still have valid objids. */
        size = filp->f_dentry->d_inode->i_size;
        if (size == 0)
                RETURN(0);

        OBD_ALLOC(ids, size);
        if (ids == NULL)
                RETURN(-ENOMEM);
        mli->md_lov_objids = ids;
        mli->md_lov_objids_size = size;

        rc = fsfilt_read_record(obd, filp, ids, size, &off);
        if (rc < 0) {
                CERROR("Error reading objids %d\n", rc);
                RETURN(rc);
        }

        mli->md_lov_objids_in_file = size / sizeof(*ids);

        for (i = 0; i < mli->md_lov_objids_in_file; i++) {
                CDEBUG(D_INFO, "read last object "LPU64" for idx %d\n",
                       mli->md_lov_objids[i], i);
        }
        RETURN(0);
}

int mds_lov_write_objids(struct obd_device *obd, struct md_lov_info *mli,
                         const void *ctxt)
{
        struct file *filp = (struct file *)mli->md_lov_objid_obj;
        loff_t off = 0;
        int i, rc, tgts;
        ENTRY;

        if (!mli->md_lov_objids_dirty)
                RETURN(0);

        tgts = max(mli->md_lov_desc.ld_tgt_count, mli->md_lov_objids_in_file);

        if (!tgts)
                RETURN(0);

        for (i = 0; i < tgts; i++)
                CDEBUG(D_INFO, "writing last object "LPU64" for idx %d\n",
                       mli->md_lov_objids[i], i);

        rc = fsfilt_write_record(obd, filp, mli->md_lov_objids,
                                 tgts * sizeof(obd_id),
                                 &off, 0);
        if (rc >= 0) {
                mli->md_lov_objids_dirty = 0;
                rc = 0;
        }

        RETURN(rc);
}

struct md_lov_ops mli_ops = {
        .ml_read_objids = mds_lov_read_objids,
        .ml_write_objids = mds_lov_write_objids,
};

int md_lov_clear_orphans(struct md_lov_info *mli, struct obd_uuid *ost_uuid)
{
        int rc;
        struct obdo oa;
        struct obd_trans_info oti = {0};
        struct lov_stripe_md  *empty_ea = NULL;
        ENTRY;

        LASSERT(mli->md_lov_objids != NULL);

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
        rc = obd_create(mli->md_lov_exp, &oa, &empty_ea, &oti);

        RETURN(rc);
}

int mds_lov_clear_orphans(struct mds_obd *mds, struct obd_uuid *ost_uuid)
{
        return md_lov_clear_orphans(&mds->mds_lov_info, ost_uuid);
}

/* update the LOV-OSC knowledge of the last used object id's */
static int md_lov_info_set_nextid(struct obd_device *obd,
                                  struct md_lov_info *mli)
{
        int rc;
        ENTRY;

        LASSERT(!obd->obd_recovering);
        LASSERT(mli->md_lov_objids != NULL);

        rc = obd_set_info_async(mli->md_lov_exp, strlen(KEY_NEXT_ID),
                                KEY_NEXT_ID,
                                mli->md_lov_desc.ld_tgt_count,
                                mli->md_lov_objids, NULL);

        RETURN(rc);
}

int mds_lov_set_nextid(struct obd_device *obd)
{
        struct md_lov_info *mli = &obd->u.mds.mds_lov_info;
        return md_lov_info_set_nextid(obd, mli);
}

int md_lov_info_update_desc(struct md_lov_info *mli, struct obd_export *lov)
{
        struct lov_desc *ld;
        __u32 size, stripes, valsize = sizeof(mli->md_lov_desc);
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
        if ((mli->md_lov_objids_size == 0) ||
            (size > mli->md_lov_objids_size)) {
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
                if (mli->md_lov_objids_size) {
                        obd_id *old_ids = mli->md_lov_objids;
                        memcpy(ids, mli->md_lov_objids,
                               mli->md_lov_objids_size);
                        mli->md_lov_objids = ids;
                        OBD_FREE(old_ids, mli->md_lov_objids_size);
                }
                mli->md_lov_objids = ids;
                mli->md_lov_objids_size = size;
        }

        /* Don't change the mds_lov_desc until the objids size matches the
           count (paranoia) */
        mli->md_lov_desc = *ld;
        CDEBUG(D_CONFIG, "updated lov_desc, tgt_count: %d\n",
               mli->md_lov_desc.ld_tgt_count);

        stripes = min((__u32)LOV_MAX_STRIPE_COUNT,
                      max(mli->md_lov_desc.ld_tgt_count,
                          mli->md_lov_objids_in_file));

        mli->md_lov_max_mdsize = lov_mds_md_size(stripes);
        mli->md_lov_max_cookiesize = stripes * sizeof(struct llog_cookie);
        CDEBUG(D_CONFIG, "updated max_mdsize/max_cookiesize: %d/%d\n",
               mli->md_lov_max_mdsize, mli->md_lov_max_cookiesize);

out:
        OBD_FREE(ld, sizeof(*ld));
        RETURN(rc);
}

#define MDSLOV_NO_INDEX -1
/* Inform MDS about new/updated target */
static int mds_lov_update_mds(struct obd_device *obd,
                              struct md_lov_info *mli,
                              struct obd_device *watched,
                              __u32 idx, const void  *ctxt)
{
        int old_count;
        int rc;
        ENTRY;

        old_count = mli->md_lov_desc.ld_tgt_count;
        rc = md_lov_info_update_desc(mli, mli->md_lov_exp);
        if (rc)
                RETURN(rc);

        CDEBUG(D_CONFIG, "idx=%d, recov=%d/%d, cnt=%d/%d\n",
               idx, obd->obd_recovering, obd->obd_async_recov, old_count,
               mli->md_lov_desc.ld_tgt_count);

        /* idx is set as data from lov_notify. */
        if (idx != MDSLOV_NO_INDEX && !obd->obd_recovering) {
                if (idx >= mli->md_lov_desc.ld_tgt_count) {
                        CERROR("index %d > count %d!\n", idx,
                               mli->md_lov_desc.ld_tgt_count);
                        RETURN(-EINVAL);
                }

                if (idx >= mli->md_lov_objids_in_file) {
                        /* We never read this lastid; ask the osc */
                        obd_id lastid;
                        __u32 size = sizeof(lastid);
                        rc = obd_get_info(watched->obd_self_export,
                                          strlen("last_id"),
                                          "last_id", &size, &lastid);
                        if (rc)
                                RETURN(rc);
                        mli->md_lov_objids[idx] = lastid;
                        mli->md_lov_objids_dirty = 1;
                        mli->md_lov_ops->ml_write_objids(obd, mli, ctxt);
                } else {
                        /* We have read this lastid from disk; tell the osc.
                           Don't call this during recovery. */
                        rc = md_lov_info_set_nextid(obd, mli);
                }

                CDEBUG(D_CONFIG, "last object "LPU64" from OST %d\n",
                       mli->md_lov_objids[idx], idx);
        }
#if 0
      /*FIXME: Do not support llog in mdd, so disable this temporarily*/
        /* If we added a target we have to reconnect the llogs */
        /* Only do this at first add (idx), or the first time after recovery */
        if (idx != MDSLOV_NO_INDEX || 1/*FIXME*/) {
                CDEBUG(D_CONFIG, "reset llogs idx=%d\n", idx);
                /* These two must be atomic */
                down(&mli->md_lov_orphan_recovery_sem);
                obd_llog_finish(obd, old_count);
                llog_cat_initialize(obd, mli->md_lov_desc.ld_tgt_count);
                up(&mli->md_lov_orphan_recovery_sem);
        }
#else
        CDEBUG(D_CONFIG, "reset llogs idx=%d\n", idx);
        llog_cat_initialize(obd, mli->md_lov_desc.ld_tgt_count);
#endif
        RETURN(rc);
}

int md_lov_connect(struct obd_device *obd, struct md_lov_info *mli,
                   char *lov_name, struct obd_uuid *uuid,
                   struct md_lov_ops *mlo, const void *ctxt)
{
        struct lustre_handle conn = {0,};
        struct obd_connect_data *data;
        int rc;

        if (IS_ERR(mli->md_lov_obd))
                RETURN(PTR_ERR(mli->md_lov_obd));

        if (mli->md_lov_obd)
                RETURN(0);

        mli->md_lov_obd = class_name2obd(lov_name);
        if (!mli->md_lov_obd) {
                CERROR("MDS cannot locate LOV %s\n", lov_name);
                mli->md_lov_obd = ERR_PTR(-ENOTCONN);
                RETURN(-ENOTCONN);
        }

        OBD_ALLOC(data, sizeof(*data));
        if (data == NULL)
                RETURN(-ENOMEM);
        data->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_INDEX |
                                  OBD_CONNECT_REQPORTAL;
        data->ocd_version = LUSTRE_VERSION_CODE;

        /* NB: lov_connect() needs to fill in .ocd_index for each OST */
        rc = obd_connect(NULL, &conn, mli->md_lov_obd, uuid, data);
        OBD_FREE(data, sizeof(*data));
        if (rc) {
                CERROR("MDS cannot connect to LOV %s (%d)\n", lov_name, rc);
                GOTO(out, rc);
        }
        mli->md_lov_exp = class_conn2export(&conn);

        rc = obd_register_observer(mli->md_lov_obd, obd);
        if (rc) {
                CERROR("MDS cannot register as observer of LOV %s (%d)\n",
                       lov_name, rc);
                GOTO(out, rc);
        }
        CDEBUG(D_INFO, "regist observer %s to lov %s \n",
                        obd->obd_name, mli->md_lov_obd->obd_name);

        rc = mli->md_lov_ops->ml_read_objids(obd, mli, ctxt);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", "lov_objids", rc);
                GOTO(out, rc);
        }

        rc = md_lov_info_update_desc(mli, mli->md_lov_exp);
        if (rc)
                GOTO(out, rc);
out:
        RETURN(rc);
}
EXPORT_SYMBOL(md_lov_connect);

int md_lov_update_objids(struct obd_device *obd, struct md_lov_info *mli,
                         const void *ctxt)
{
        int rc = 0, i;

        /* If we're mounting this code for the first time on an existing FS,
         * we need to populate the objids array from the real OST values */
        if (mli->md_lov_desc.ld_tgt_count > mli->md_lov_objids_in_file) {
                int size = sizeof(obd_id) * mli->md_lov_desc.ld_tgt_count;
                rc = obd_get_info(mli->md_lov_exp, strlen("last_id"),
                                  "last_id", &size, mli->md_lov_objids);
                if (!rc) {
                        for (i = 0; i < mli->md_lov_desc.ld_tgt_count; i++)
                                CWARN("got last object "LPU64" from OST %d\n",
                                      mli->md_lov_objids[i], i);
                        mli->md_lov_objids_dirty = 1;
                        rc = mli->md_lov_ops->ml_write_objids(obd, mli, ctxt);
                        if (rc)
                                CERROR("got last objids from OSTs, but error "
                                       "writing objids file: %d\n", rc);
                }
        }
        return rc;
}

/* update the LOV-OSC knowledge of the last used object id's */
int mds_lov_connect(struct obd_device *obd, char * lov_name)
{
        struct mds_obd *mds = &obd->u.mds;
        struct md_lov_info *mli = &mds->mds_lov_info;
        int rc;
        ENTRY;

        rc = md_lov_connect(obd, mli, lov_name, &obd->obd_uuid, &mli_ops,
                            NULL);
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
        rc = md_lov_update_objids(obd, mli, NULL);

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
        if (mli->md_lov_exp) {
                obd_disconnect(mli->md_lov_exp);
                mli->md_lov_exp = NULL;
        }
        mli->md_lov_obd = ERR_PTR(rc);
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

                obd_llog_finish(obd, mds->mds_lov_desc.ld_tgt_count);
                push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                rc = llog_ioctl(ctxt, cmd, data);
                pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                llog_cat_initialize(obd, mds->mds_lov_desc.ld_tgt_count);
                rc2 = obd_set_info_async(mds->mds_osc_exp,
                                         strlen(KEY_MDS_CONN), KEY_MDS_CONN,
                                         0, NULL, NULL);
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
        struct obd_device  *mlsi_obd;     /* the lov device to sync */
        struct md_lov_info *mlsi_mli;
        struct obd_device  *mlsi_watched; /* target osc */
        __u32               mlsi_index;   /* index of target */
        const void         *mlsi_ctxt;
};


/* We only sync one osc at a time, so that we don't have to hold
   any kind of lock on the whole mds_lov_desc, which may change
   (grow) as a result of mds_lov_add_ost.  This also avoids any
   kind of mismatch between the lov_desc and the mds_lov_desc,
   which are not in lock-step during lov_add_obd */
static int __mds_lov_synchronize(void *data)
{
        struct mds_lov_sync_info *mlsi = data;
        struct obd_device *obd = mlsi->mlsi_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct obd_device *watched = mlsi->mlsi_watched;
        struct md_lov_info *mli = mlsi->mlsi_mli;
        const void *ctxt = mlsi->mlsi_ctxt;
        struct obd_uuid *uuid;
        __u32  idx = mlsi->mlsi_index;
        int rc = 0;
        ENTRY;

        OBD_FREE(mlsi, sizeof(*mlsi));

        LASSERT(obd);
        LASSERT(watched);
        uuid = &watched->u.cli.cl_target_uuid;
        LASSERT(uuid);

        rc = mds_lov_update_mds(obd, mli, watched, idx, ctxt);
        if (rc != 0)
                GOTO(out, rc);

        rc = obd_set_info_async(mli->md_lov_exp, strlen(KEY_MDS_CONN),
                                KEY_MDS_CONN, 0, uuid, NULL);
        if (rc != 0)
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

        rc = md_lov_clear_orphans(mli, uuid);
        if (rc != 0) {
                CERROR("%s: failed at md_lov_clear_orphans: %d\n",
                       obd->obd_name, rc);
                GOTO(out, rc);
        }
        if (obd->obd_upcall.onu_owner) {
                /*This is an hack for mds_notify->mdd_notify,
                 *When the mds obd in mdd is removed, 
                 *This hack should be removed*/
                LASSERT(obd->obd_upcall.onu_upcall != NULL);
                obd->obd_upcall.onu_upcall(NULL, NULL, 0,
                                 obd->obd_upcall.onu_owner);
        }
out:
        class_decref(obd);
        RETURN(rc);
}

int mds_lov_synchronize(void *data)
{
        struct mds_lov_sync_info *mlsi = data;
        char name[20];

        sprintf(name, "ll_mlov_sync_%02u", mlsi->mlsi_index);
        ptlrpc_daemonize(name);

        RETURN(__mds_lov_synchronize(data));
}

int md_lov_start_synchronize(struct obd_device *obd, struct md_lov_info *mli,
                             struct obd_device *watched,
                             void *data, int nonblock, const void *ctxt)
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
        mlsi->mlsi_mli = mli;
        mlsi->mlsi_ctxt = ctxt;
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
EXPORT_SYMBOL(md_lov_start_synchronize);

int mds_lov_start_synchronize(struct obd_device *obd,
                              struct obd_device *watched,
                              void *data, int nonblock)
{
        return md_lov_start_synchronize(obd, &obd->u.mds.mds_lov_info,
                                        watched, data, nonblock, NULL);
}

int md_lov_notity_pre(struct obd_device *obd, struct md_lov_info *mli,
                      struct obd_device *watched, enum obd_notify_event ev,
                      void *data)
{
        int rc = 0;

        switch (ev) {
        /* We only handle these: */
        case OBD_NOTIFY_ACTIVE:
        case OBD_NOTIFY_SYNC:
        case OBD_NOTIFY_SYNC_NONBLOCK:
                break;
        default:
                RETURN(-ENOENT);
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
                rc = md_lov_info_update_desc(mli, mli->md_lov_exp);
                RETURN(-EBUSY);
        }
        RETURN(rc);
}
EXPORT_SYMBOL(md_lov_notity_pre);

int mds_notify(struct obd_device *obd, struct obd_device *watched,
               enum obd_notify_event ev, void *data)
{
        int rc = 0;
        struct md_lov_info *mli = &obd->u.mds.mds_lov_info;
        ENTRY;

        rc = md_lov_notity_pre(obd, mli, watched, ev, data);
        if (rc) {
                if (rc == -ENOENT || rc == -EBUSY)
                        rc = 0;
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

