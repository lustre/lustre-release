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
 * lustre/mds/mds_lov.c
 *
 * Lustre Metadata Server (mds) handling of striped file data
 *
 * Author: Peter Braam <braam@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>
#include <obd_class.h>
#include <obd_lov.h>
#include <lustre_lib.h>
#include <lustre_fsfilt.h>

#include "mds_internal.h"

static void mds_lov_dump_objids(const char *label, struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        unsigned int i=0, j;

        CDEBUG(D_INFO, "dump from %s\n", label);
        if (mds->mds_lov_page_dirty == NULL) {
                CERROR("NULL bitmap!\n");
                GOTO(skip_bitmap, i);
        }

        for(i=0;i<((mds->mds_lov_page_dirty->size/BITS_PER_LONG)+1);i++)
                CDEBUG(D_INFO, "%u - %lx\n", i, mds->mds_lov_page_dirty->data[i]);
skip_bitmap:
        if (mds->mds_lov_page_array == NULL) {
                CERROR("not init page array!\n");
                GOTO(skip_array, i);

        }
        for(i=0;i<MDS_LOV_OBJID_PAGES_COUNT;i++) {
                obd_id *data = mds->mds_lov_page_array[i];

                if (data == NULL)
                        continue;

                for(j=0; j < OBJID_PER_PAGE(); j++) {
                        if (data[j] == 0)
                                continue;
                        CDEBUG(D_INFO,"objid page %u idx %u - %llu \n", i,j,data[j]);
                }
        }
skip_array:
        EXIT;
}

int mds_lov_init_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int size = MDS_LOV_OBJID_PAGES_COUNT*sizeof(void *);
        struct file *file;
        int rc;
        ENTRY;

        CLASSERT(((MDS_LOV_ALLOC_SIZE % sizeof(obd_id)) == 0));

        mds->mds_lov_page_dirty = ALLOCATE_BITMAP(MDS_LOV_OBJID_PAGES_COUNT);
        if (mds->mds_lov_page_dirty == NULL)
                RETURN(-ENOMEM);


        OBD_ALLOC(mds->mds_lov_page_array, size);
        if (mds->mds_lov_page_array == NULL)
                GOTO(err_free_bitmap, rc = -ENOMEM);

        /* open and test the lov objd file */
        file = filp_open(LOV_OBJID, O_RDWR | O_CREAT, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open/create %s file: rc = %d\n", LOV_OBJID, rc);
                GOTO(err_free, rc = PTR_ERR(file));
        }
        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LOV_OBJID,
                       file->f_dentry->d_inode->i_mode);
                GOTO(err_open, rc = -ENOENT);
        }
        mds->mds_lov_objid_filp = file;

        RETURN (0);
err_open:
        if (filp_close((struct file *)file, 0))
                CERROR("can't close %s after error\n", LOV_OBJID);
err_free:
        OBD_FREE(mds->mds_lov_page_array, size);
err_free_bitmap:
        FREE_BITMAP(mds->mds_lov_page_dirty);

        RETURN(rc);
}

void mds_lov_destroy_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int i, rc;
        ENTRY;

        if (mds->mds_lov_page_array != NULL) {
                for(i=0;i<MDS_LOV_OBJID_PAGES_COUNT;i++) {
                        obd_id *data = mds->mds_lov_page_array[i];
                        if (data != NULL)
                                OBD_FREE(data, MDS_LOV_ALLOC_SIZE);
                }
                OBD_FREE(mds->mds_lov_page_array,
                         MDS_LOV_OBJID_PAGES_COUNT*sizeof(void *));
        }

        if (mds->mds_lov_objid_filp) {
                rc = filp_close((struct file *)mds->mds_lov_objid_filp, 0);
                mds->mds_lov_objid_filp = NULL;
                if (rc)
                        CERROR("%s file won't close, rc=%d\n", LOV_OBJID, rc);
        }

        FREE_BITMAP(mds->mds_lov_page_dirty);
        EXIT;
}

static int mds_lov_read_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        loff_t off = 0;
        int i, rc, count = 0, page = 0;
        unsigned long size;
        ENTRY;

        /* Read everything in the file, even if our current lov desc
           has fewer targets. Old targets not in the lov descriptor
           during mds setup may still have valid objids. */
        size = i_size_read(mds->mds_lov_objid_filp->f_dentry->d_inode);
        if (size == 0)
                RETURN(0);

        page = (size / (OBJID_PER_PAGE() * sizeof(obd_id))) + 1;
        CDEBUG(D_INFO, "file size %lu pages %d\n", size, page);

        for (i = 0; i < page; i++) {
                obd_id *data =  mds->mds_lov_page_array[i];
                loff_t off_old = off;

                LASSERT(data == NULL);
                OBD_ALLOC(data, MDS_LOV_ALLOC_SIZE);
                if (data == NULL)
                        GOTO(out, rc = -ENOMEM);

                mds->mds_lov_page_array[i] = data;

                rc = fsfilt_read_record(obd, mds->mds_lov_objid_filp, data,
                                        OBJID_PER_PAGE()*sizeof(obd_id), &off);
                if (rc < 0) {
                        CERROR("Error reading objids %d\n", rc);
                        GOTO(out, rc);
                }
                if (off == off_old)
                        break; // eof

                count += (off - off_old)/sizeof(obd_id);
        }
        mds->mds_lov_objid_count = count;
	if (count) {
                count --;
                mds->mds_lov_objid_lastpage = count / OBJID_PER_PAGE();
                mds->mds_lov_objid_lastidx = count % OBJID_PER_PAGE();
	}
        CDEBUG(D_INFO, "Read %u - %u %u objid\n", count,
               mds->mds_lov_objid_lastpage, mds->mds_lov_objid_lastidx);
out:
        mds_lov_dump_objids("read",obd);

        RETURN(0);
}

int mds_lov_write_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int i, rc = 0;
        ENTRY;

        if (cfs_bitmap_check_empty(mds->mds_lov_page_dirty))
                RETURN(0);

        mds_lov_dump_objids("write", obd);

        cfs_foreach_bit(mds->mds_lov_page_dirty, i) {
                obd_id *data =  mds->mds_lov_page_array[i];
                unsigned int size = OBJID_PER_PAGE()*sizeof(obd_id);
                loff_t off = i * size;

                LASSERT(data != NULL);

                /* check for particaly filled last page */
                if (i == mds->mds_lov_objid_lastpage)
                        size = (mds->mds_lov_objid_lastidx+1) * sizeof(obd_id);

                rc = fsfilt_write_record(obd, mds->mds_lov_objid_filp, data,
                                         size, &off, 0);
                if (rc < 0)
                        break;
                cfs_bitmap_clear(mds->mds_lov_page_dirty, i);
        }
        if (rc >= 0)
                rc = 0;

        RETURN(rc);
}
EXPORT_SYMBOL(mds_lov_write_objids);

static int mds_lov_get_objid(struct obd_device * obd,
                             __u32 idx)
{
        struct mds_obd *mds = &obd->u.mds;
        unsigned int page;
        unsigned int off;
        obd_id *data;
        int rc = 0;
        ENTRY;

        page = idx / OBJID_PER_PAGE();
        off = idx % OBJID_PER_PAGE();
        data = mds->mds_lov_page_array[page];
        if (data == NULL) {
                OBD_ALLOC(data, MDS_LOV_ALLOC_SIZE);
                if (data == NULL)
                        GOTO(out, rc = -ENOMEM);

                mds->mds_lov_page_array[page] = data;
        }

        if (data[off] == 0) {
                /* We never read this lastid; ask the osc */
                struct obd_id_info lastid;
                __u32 size = sizeof(lastid);

                lastid.idx = idx;
                lastid.data = &data[off];
                rc = obd_get_info(mds->mds_osc_exp, sizeof(KEY_LAST_ID),
                                  KEY_LAST_ID, &size, &lastid, NULL);
                if (rc)
                        GOTO(out, rc);

                if (idx > mds->mds_lov_objid_count) {
                        mds->mds_lov_objid_count = idx;
                        mds->mds_lov_objid_lastpage = page;
                        mds->mds_lov_objid_lastidx = off;
                }
                cfs_bitmap_set(mds->mds_lov_page_dirty, page);
        }
out:
        RETURN(rc);
}

int mds_lov_clear_orphans(struct mds_obd *mds, struct obd_uuid *ost_uuid)
{
        int rc;
        struct obdo oa;
        struct obd_trans_info oti = {0};
        struct lov_stripe_md  *empty_ea = NULL;
        ENTRY;

        LASSERT(mds->mds_lov_page_array != NULL);

        /* This create will in fact either create or destroy:  If the OST is
         * missing objects below this ID, they will be created.  If it finds
         * objects above this ID, they will be removed. */
        memset(&oa, 0, sizeof(oa));
        oa.o_flags = OBD_FL_DELORPHAN;
        oa.o_gr = FILTER_GROUP_MDS0 + mds->mds_id;
        oa.o_valid = OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
        if (ost_uuid != NULL)
                oti.oti_ost_uuid = ost_uuid;       
        rc = obd_create(mds->mds_osc_exp, &oa, &empty_ea, &oti);

        RETURN(rc);
}

/* for one target */
static int mds_lov_set_one_nextid(struct obd_device *obd, __u32 idx, obd_id *id)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc;
        struct obd_id_info info;
        ENTRY;

        LASSERT(!obd->obd_recovering);

        /* obd->obd_dev_sem must be held so mds_lov_objids doesn't change */
        LASSERT_SEM_LOCKED(&obd->obd_dev_sem);

        info.idx = idx;
        info.data = id;
        rc = obd_set_info_async(mds->mds_osc_exp, sizeof(KEY_NEXT_ID),
                                KEY_NEXT_ID, sizeof(info), &info, NULL);
        if (rc)
                CERROR ("%s: mds_lov_set_nextid failed (%d)\n",
                        obd->obd_name, rc);

        RETURN(rc);
}

/* Update the lov desc for a new size lov. */
static int mds_lov_update_desc(struct obd_device *obd, int idx,
                               struct obd_uuid *uuid)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_desc *ld;
        __u32 stripes, valsize = sizeof(mds->mds_lov_desc);
        int rc = 0;
        ENTRY;

        OBD_ALLOC(ld, sizeof(*ld));
        if (!ld)
                RETURN(-ENOMEM);

        rc = obd_get_info(mds->mds_osc_exp, sizeof(KEY_LOVDESC), KEY_LOVDESC,
                          &valsize, ld, NULL);
        if (rc)
                GOTO(out, rc);

        /* Don't change the mds_lov_desc until the objids size matches the
           count (paranoia) */
        mds->mds_lov_desc = *ld;
        CDEBUG(D_CONFIG, "updated lov_desc, tgt_count: %d\n",
               mds->mds_lov_desc.ld_tgt_count);

        stripes = min_t(__u32, LOV_MAX_STRIPE_COUNT,
                               mds->mds_lov_desc.ld_tgt_count);

        mds->mds_max_mdsize = lov_mds_md_size(stripes, LOV_MAGIC_V3);
        mds->mds_max_cookiesize = stripes * sizeof(struct llog_cookie);
        CDEBUG(D_CONFIG, "updated max_mdsize/max_cookiesize for %d stripes: "
               "%d/%d\n", mds->mds_max_mdsize, mds->mds_max_cookiesize,
               stripes);

        /* If we added a target we have to reconnect the llogs */
        /* We only _need_ to do this at first add (idx), or the first time
           after recovery.  However, it should now be safe to call anytime. */
        rc = llog_cat_initialize(obd, &obd->obd_olg, idx, uuid);
        if (rc)
                GOTO(out, rc);

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

/* Inform MDS about new/updated target */
static int mds_lov_update_mds(struct obd_device *obd,
                              struct obd_device *watched,
                              __u32 idx)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        int page;
        int off;
        obd_id *data;

        ENTRY;

        /* Don't let anyone else mess with mds_lov_objids now */
        mutex_down(&obd->obd_dev_sem);

        rc = mds_lov_update_desc(obd, idx, &watched->u.cli.cl_target_uuid);
        if (rc)
                GOTO(out, rc);

        CDEBUG(D_CONFIG, "idx=%d, recov=%d/%d, cnt=%d\n",
               idx, obd->obd_recovering, obd->obd_async_recov,
               mds->mds_lov_desc.ld_tgt_count);

        /* idx is set as data from lov_notify. */
        if (obd->obd_recovering)
                GOTO(out, rc);

        if (idx >= mds->mds_lov_desc.ld_tgt_count) {
                CERROR("index %d > count %d!\n", idx,
                       mds->mds_lov_desc.ld_tgt_count);
                GOTO(out, rc = -EINVAL);
        }

        rc = mds_lov_get_objid(obd, idx);
        if (rc)
                GOTO(out, rc);

        page = idx / OBJID_PER_PAGE();
        off = idx % OBJID_PER_PAGE();
        data = mds->mds_lov_page_array[page];

        /* We have read this lastid from disk; tell the osc.
           Don't call this during recovery. */
        rc = mds_lov_set_one_nextid(obd, idx, &data[off]);
        if (rc) {
                CERROR("Failed to set next id, idx=%d rc=%d\n", idx,rc);
                /* Don't abort the rest of the sync */
                rc = 0;
        } else {
                CDEBUG(D_CONFIG, "last object "LPU64" from OST %d rc=%d\n",
                        data[off], idx, rc);
        }
out:
        mutex_up(&obd->obd_dev_sem);
        RETURN(rc);
}

/* update the LOV-OSC knowledge of the last used object id's */
int mds_lov_connect(struct obd_device *obd, char * lov_name)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_handle conn = {0,};
        struct obd_connect_data *data;
        int rc;
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
        data->ocd_connect_flags = OBD_CONNECT_VERSION   | OBD_CONNECT_INDEX   |
                                  OBD_CONNECT_REQPORTAL | OBD_CONNECT_QUOTA64 |
                                  OBD_CONNECT_OSS_CAPA  | OBD_CONNECT_FID     |
                                  OBD_CONNECT_AT;
#ifdef HAVE_LRU_RESIZE_SUPPORT
        data->ocd_connect_flags |= OBD_CONNECT_LRU_RESIZE;
#endif
        data->ocd_version = LUSTRE_VERSION_CODE;
        data->ocd_group = mds->mds_id +  FILTER_GROUP_MDS0;
        /* NB: lov_connect() needs to fill in .ocd_index for each OST */
        rc = obd_connect(NULL, &conn, mds->mds_osc_obd, &obd->obd_uuid, data, NULL);
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

        /* Deny new client connections until we are sure we have some OSTs */
        obd->obd_no_conn = 1;

        mutex_down(&obd->obd_dev_sem);
        rc = mds_lov_read_objids(obd);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", "lov_objids", rc);
                GOTO(err_reg, rc);
        }
        mutex_up(&obd->obd_dev_sem);

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
        mutex_up(&obd->obd_dev_sem);
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

/* Collect the preconditions we need to allow client connects */
static void mds_allow_cli(struct obd_device *obd, unsigned int flag)
{
        if (flag & CONFIG_LOG)
                obd->u.mds.mds_fl_cfglog = 1;
        if (flag & CONFIG_SYNC)
                obd->u.mds.mds_fl_synced = 1;
        if (obd->u.mds.mds_fl_cfglog /* bz11778: && obd->u.mds.mds_fl_synced */)
                /* Open for clients */
                obd->obd_no_conn = 0;
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

                rc = obd_set_info_async(mds->mds_osc_exp, sizeof(KEY_CAPA_KEY),
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
        struct llog_ctxt *ctxt;
        int rc = 0;
        ENTRY;

        OBD_FREE_PTR(mlsi);

        LASSERT(obd);
        LASSERT(watched);
        uuid = &watched->u.cli.cl_target_uuid;
        LASSERT(uuid);

        down_read(&mds->mds_notify_lock);
        if (obd->obd_stopping || obd->obd_fail)
                GOTO(out, rc = -ENODEV);

        OBD_RACE(OBD_FAIL_MDS_LOV_SYNC_RACE);
        rc = mds_lov_update_mds(obd, watched, idx);
        if (rc != 0) {
                CERROR("%s failed at update_mds: %d\n", obd_uuid2str(uuid), rc);
                GOTO(out, rc);
        }
        mgi.group = FILTER_GROUP_MDS0 + mds->mds_id;
        mgi.uuid = uuid;

        rc = obd_set_info_async(mds->mds_osc_exp, sizeof(KEY_MDS_CONN),
                                KEY_MDS_CONN, sizeof(mgi), &mgi, NULL);
        if (rc != 0)
                GOTO(out, rc);
        /* propagate capability keys */
        rc = mds_propagate_capa_keys(mds);
        if (rc)
                GOTO(out, rc);

        ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
        if (!ctxt) 
                GOTO(out, rc = -ENODEV);

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_LLOG_SYNC_TIMEOUT, 60);
        rc = llog_connect(ctxt, obd->u.mds.mds_lov_desc.ld_tgt_count, 
                          NULL, NULL, uuid); 
        llog_ctxt_put(ctxt);
        if (rc != 0) {
                CERROR("%s failed at llog_origin_connect: %d\n",
                       obd_uuid2str(uuid), rc);
                GOTO(out, rc);
        }

        LCONSOLE_INFO("MDS %s: %s now active, resetting orphans\n",
              obd->obd_name, obd_uuid2str(uuid));
        rc = mds_lov_clear_orphans(mds, uuid);
        if (rc != 0) {
                CERROR("%s failed at mds_lov_clear_orphans: %d\n",
                       obd_uuid2str(uuid), rc);
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
        up_read(&mds->mds_notify_lock);
        if (rc) {
                /* Deactivate it for safety */
                CERROR("%s sync failed %d, deactivating\n", obd_uuid2str(uuid),
                       rc);
                if (!obd->obd_stopping && mds->mds_osc_obd &&
                    !mds->mds_osc_obd->obd_stopping && !watched->obd_stopping)
                        obd_notify(mds->mds_osc_obd, watched,
                                   OBD_NOTIFY_INACTIVE, NULL);
        }

        class_decref(obd);
        return rc;
}

int mds_lov_synchronize(void *data)
{
        struct mds_lov_sync_info *mlsi = data;
        char name[20];

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
        struct obd_uuid *uuid;
        ENTRY;

        LASSERT(watched);
        uuid = &watched->u.cli.cl_target_uuid;

        OBD_ALLOC(mlsi, sizeof(*mlsi));
        if (mlsi == NULL)
                RETURN(-ENOMEM);

        mlsi->mlsi_obd = obd;
        mlsi->mlsi_watched = watched;
        mlsi->mlsi_index = *(__u32 *)data;

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
        case OBD_NOTIFY_CONFIG:
                mds_allow_cli(obd, (unsigned long)data);
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
                mutex_down(&obd->obd_dev_sem);
                rc = mds_lov_update_desc(obd, *(__u32 *)data,
                                        &watched->u.cli.cl_target_uuid);
                mutex_up(&obd->obd_dev_sem);
                if (rc == 0)
                        mds_allow_cli(obd, CONFIG_SYNC);
                RETURN(rc);
        }

        rc = mds_lov_start_synchronize(obd, watched, data,
                                       !(ev == OBD_NOTIFY_SYNC));

        lquota_recovery(mds_quota_interface_ref, obd);

        RETURN(rc);
}
