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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
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
#include <obd_cksum.h>
#include <lustre_log.h>

#include "mds_internal.h"

static void mds_lov_dump_objids(const char *label, struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        unsigned int i=0, j;

        if ((libcfs_debug & D_INFO) == 0)
                return;

        CDEBUG(D_INFO, "dump from %s\n", label);
        if (mds->mds_lov_page_dirty == NULL) {
                CERROR("NULL bitmap!\n");
                GOTO(skip_bitmap, i);
        }

        for(i = 0; i < mds->mds_lov_page_dirty->size / BITS_PER_LONG + 1; i++)
                CDEBUG(D_INFO, "%u - %lx\n", i,
                       mds->mds_lov_page_dirty->data[i]);
skip_bitmap:
        if (mds->mds_lov_page_array == NULL) {
                CERROR("not init page array!\n");
                GOTO(skip_array, i);

        }
        for(i = 0;i < MDS_LOV_OBJID_PAGES_COUNT; i++) {
                obd_id *data = mds->mds_lov_page_array[i];

                if (data == NULL)
                        continue;

                for(j=0; j < OBJID_PER_PAGE(); j++) {
                        if (data[j] == 0)
                                continue;
                        CDEBUG(D_INFO,"objid page %u idx %u - "LPU64" \n",
                               i, j, data[j]);
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

        mds->mds_lov_page_dirty =
                CFS_ALLOCATE_BITMAP(MDS_LOV_OBJID_PAGES_COUNT);
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
        CFS_FREE_BITMAP(mds->mds_lov_page_dirty);

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
                rc = filp_close((struct file *)mds->mds_lov_objid_filp, NULL);
                mds->mds_lov_objid_filp = NULL;
                if (rc)
                        CERROR("%s file won't close, rc=%d\n", LOV_OBJID, rc);
        }

        CFS_FREE_BITMAP(mds->mds_lov_page_dirty);
        EXIT;
}

/**
 * currently exist two ways for know about ost count and max ost index.
 * first - after ost is connected to mds and sync process finished
 * second - get from lmm in recovery process, in case when mds not have configs,
 * and ost isn't registered in mgs.
 *
 * \param mds pointer to mds structure
 * \param index maxium ost index
 *
 * \retval -ENOMEM is not hame memory for new page
 * \retval 0 is update passed
 */
static int mds_lov_update_max_ost(struct mds_obd *mds, obd_id index)
{
        __u32 page = index / OBJID_PER_PAGE();
        __u32 off = index % OBJID_PER_PAGE();
        obd_id *data =  mds->mds_lov_page_array[page];

        if (data == NULL) {
                OBD_ALLOC(data, MDS_LOV_ALLOC_SIZE);
                if (data == NULL)
                        RETURN(-ENOMEM);

                mds->mds_lov_page_array[page] = data;
        }

        if (index > mds->mds_lov_objid_max_index) {
                mds->mds_lov_objid_lastpage = page;
                mds->mds_lov_objid_lastidx = off;
                mds->mds_lov_objid_max_index = index;
        }

        /* workaround - New target not in objids file; increase mdsize */
        /* ld_tgt_count is used as the max index everywhere, despite its name. */
        if (data[off] == 0) {
                __u32 max_easize;
                __u32 stripes;

                max_easize = mds->mds_obt.obt_osd_properties.osd_max_ea_size;
                data[off] = 1;
                mds->mds_lov_objid_count++;
                stripes = min(lov_mds_md_stripecnt(max_easize, LOV_MAGIC_V3),
                              mds->mds_lov_objid_count);

                mds->mds_max_mdsize = lov_mds_md_size(stripes, LOV_MAGIC_V3);
                mds->mds_max_cookiesize = stripes * sizeof(struct llog_cookie);

                CDEBUG(D_CONFIG, "updated max_mdsize/max_cookiesize for %d"
                       " stripes: %d/%d\n", stripes, mds->mds_max_mdsize,
                       mds->mds_max_cookiesize);
        }

        EXIT;
        return 0;
}

static int mds_lov_objinit(struct mds_obd *mds, __u32 index)
{
        __u32 page = index / OBJID_PER_PAGE();
        __u32 off = index % OBJID_PER_PAGE();
        obd_id *data =  mds->mds_lov_page_array[page];

        return (data[off] > 0);
}

int mds_lov_prepare_objids(struct obd_device *obd, struct lov_mds_md *lmm)
{
        struct lov_ost_data_v1 *data;
        __u16 count;
        int rc = 0;
        __u32 j;

        /* if we create file without objects - lmm is NULL */
        if (lmm == NULL)
                return 0;

        switch (le32_to_cpu(lmm->lmm_magic)) {
                case LOV_MAGIC_V1:
                        count = le16_to_cpu(((struct lov_mds_md_v1*)lmm)->lmm_stripe_count);
                        data = &(((struct lov_mds_md_v1*)lmm)->lmm_objects[0]);
                        break;
                case LOV_MAGIC_V3:
                        count = le16_to_cpu(((struct lov_mds_md_v3*)lmm)->lmm_stripe_count);
                        data = &(((struct lov_mds_md_v3*)lmm)->lmm_objects[0]);
                        break;
                default:
                        CERROR("Unknow lmm type %X!\n", le32_to_cpu(lmm->lmm_magic));
                        RETURN(-EINVAL);
        }


        cfs_mutex_lock(&obd->obd_dev_mutex);
        for (j = 0; j < count; j++) {
                __u32 i = le32_to_cpu(data[j].l_ost_idx);
                if (mds_lov_update_max_ost(&obd->u.mds, i)) {
                        rc = -ENOMEM;
                        break;
                }
        }
        cfs_mutex_unlock(&obd->obd_dev_mutex);

        RETURN(rc);
}
EXPORT_SYMBOL(mds_lov_prepare_objids);

/*
 * write llog orphan record about lost ost object,
 * Special lsm is allocated with single stripe, caller should deallocated it
 * after use
 */
static int mds_log_lost_precreated(struct obd_device *obd,
                                   struct lov_stripe_md **lsmp, __u16 *stripes,
                                   obd_id id, obd_count count, int idx)
{
        struct lov_stripe_md *lsm = *lsmp;
        int rc;
        ENTRY;

        if (*lsmp == NULL) {
                rc = obd_alloc_memmd(obd->u.mds.mds_lov_exp, &lsm);
                if (rc < 0)
                        RETURN(rc);
                /* need only one stripe, save old value */
                *stripes = lsm->lsm_stripe_count;
                lsm->lsm_stripe_count = 1;
                *lsmp = lsm;
        }

        lsm->lsm_oinfo[0]->loi_id = id;
        lsm->lsm_oinfo[0]->loi_seq = mdt_to_obd_objseq(obd->u.mds.mds_id);
        lsm->lsm_oinfo[0]->loi_ost_idx = idx;

        rc = mds_log_op_orphan(obd, lsm, count);
        RETURN(rc);
}

void mds_lov_update_objids(struct obd_device *obd, struct lov_mds_md *lmm)
{
        struct mds_obd *mds = &obd->u.mds;
        int j;
        struct lov_ost_data_v1 *obj;
        struct lov_stripe_md *lsm = NULL;
        __u16 stripes = 0;
        int count;
        ENTRY;

        /* if we create file without objects - lmm is NULL */
        if (lmm == NULL)
                return;

        switch (le32_to_cpu(lmm->lmm_magic)) {
                case LOV_MAGIC_V1:
                        count = le16_to_cpu(((struct lov_mds_md_v1*)lmm)->lmm_stripe_count);
                        obj = ((struct lov_mds_md_v1*)lmm)->lmm_objects;
                        break;
                case LOV_MAGIC_V3:
                        count = le16_to_cpu(((struct lov_mds_md_v3*)lmm)->lmm_stripe_count);
                        obj = ((struct lov_mds_md_v3*)lmm)->lmm_objects;
                        break;
                default:
                        CERROR("Unknow lmm type %X !\n",
                               le32_to_cpu(lmm->lmm_magic));
                        return;
        }

        for (j = 0; j < count; j++) {
                __u32 i = le32_to_cpu(obj[j].l_ost_idx);
                obd_id id = le64_to_cpu(obj[j].l_object_id);
                __u32 page = i / OBJID_PER_PAGE();
                __u32 idx = i % OBJID_PER_PAGE();
                obd_id *data;

                data = mds->mds_lov_page_array[page];

                CDEBUG(D_INODE,"update last object for ost %u"
                       " - new "LPU64" old "LPU64"\n", i, id, data[idx]);
                if (id > data[idx]) {
                        int lost = id - data[idx] - 1;
                        /* we might have lost precreated objects due to VBR */
                        if (lost > 0 && obd->obd_recovering) {
                                CDEBUG(D_HA, "Gap in objids is %u\n", lost);
                                if (!obd->obd_version_recov)
                                        CERROR("Unexpected gap in objids\n");
                                /* lsm is allocated if NULL */
                                mds_log_lost_precreated(obd, &lsm, &stripes,
                                                        data[idx]+1, lost, i);
                        }
                        data[idx] = id;
                        cfs_bitmap_set(mds->mds_lov_page_dirty, page);
                }
        }
        if (lsm) {
                /* restore stripes number */
                lsm->lsm_stripe_count = stripes;
                obd_free_memmd(mds->mds_lov_exp, &lsm);
        }
        EXIT;
        return;
}
EXPORT_SYMBOL(mds_lov_update_objids);

static int mds_lov_update_from_read(struct mds_obd *mds, obd_id *data,
                                    __u32 count)
{
        __u32 max_easize = mds->mds_obt.obt_osd_properties.osd_max_ea_size;
        __u32 i, stripes;

        for (i = 0; i < count; i++) {
                if (data[i] == 0)
                        continue;

                mds->mds_lov_objid_count++;
        }

        stripes = min(lov_mds_md_stripecnt(max_easize, LOV_MAGIC_V3),
                         mds->mds_lov_objid_count);

        mds->mds_max_mdsize = lov_mds_md_size(stripes, LOV_MAGIC_V3);
        mds->mds_max_cookiesize = stripes * sizeof(struct llog_cookie);

        CDEBUG(D_CONFIG, "updated max_mdsize/max_cookiesize for %d stripes: "
               "%d/%d\n", stripes, mds->mds_max_mdsize,
               mds->mds_max_cookiesize);

        EXIT;
        return 0;
}

static int mds_lov_read_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        loff_t off = 0;
        int i, rc = 0, count = 0, page = 0;
        unsigned long size;
        ENTRY;

        /* Read everything in the file, even if our current lov desc
           has fewer targets. Old targets not in the lov descriptor
           during mds setup may still have valid objids. */
        size = i_size_read(mds->mds_lov_objid_filp->f_dentry->d_inode);
        if (size == 0)
                RETURN(0);

        page = (size + MDS_LOV_ALLOC_SIZE - 1) / MDS_LOV_ALLOC_SIZE;
        CDEBUG(D_INFO, "file size %lu pages %d\n", size, page);
        for (i = 0; i < page; i++) {
                obd_id *data;
                loff_t off_old = off;

                LASSERT(mds->mds_lov_page_array[i] == NULL);
                OBD_ALLOC(mds->mds_lov_page_array[i], MDS_LOV_ALLOC_SIZE);
                if (mds->mds_lov_page_array[i] == NULL)
                        GOTO(out, rc = -ENOMEM);

                data = mds->mds_lov_page_array[i];

                rc = fsfilt_read_record(obd, mds->mds_lov_objid_filp, data,
                                        MDS_LOV_ALLOC_SIZE, &off);
                if (rc < 0) {
                        CERROR("Error reading objids %d\n", rc);
                        GOTO(out, rc);
                }
                if (off == off_old) /* hole is read */
                        off += MDS_LOV_ALLOC_SIZE;

                count = (off - off_old) / sizeof(obd_id);
                if (mds_lov_update_from_read(mds, data, count)) {
                        CERROR("Can't update mds data\n");
                        GOTO(out, rc = -EIO);
                }
        }
        mds->mds_lov_objid_lastpage = page - 1;
        mds->mds_lov_objid_lastidx = count - 1;

        CDEBUG(D_INFO, "Read %u - %u %u objid\n", mds->mds_lov_objid_count,
               mds->mds_lov_objid_lastpage, mds->mds_lov_objid_lastidx);
out:
        mds_lov_dump_objids("read",obd);

        RETURN(rc);
}

int mds_lov_write_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int i = 0, rc = 0;
        ENTRY;

        if (cfs_bitmap_check_empty(mds->mds_lov_page_dirty))
                RETURN(0);

        mds_lov_dump_objids("write", obd);

        cfs_foreach_bit(mds->mds_lov_page_dirty, i) {
                obd_id *data =  mds->mds_lov_page_array[i];
                unsigned int size = MDS_LOV_ALLOC_SIZE;
                loff_t off = i * size;

                LASSERT(data != NULL);

                if (!cfs_bitmap_test_and_clear(mds->mds_lov_page_dirty, i))
                        continue;

                /* check for particaly filled last page */
                if (i == mds->mds_lov_objid_lastpage)
                        size = (mds->mds_lov_objid_lastidx+1) * sizeof(obd_id);

                CDEBUG(D_INFO, "write %lld - %u\n", off, size);
                rc = fsfilt_write_record(obd, mds->mds_lov_objid_filp, data,
                                         size, &off, 0);
                if (rc < 0) {
                        cfs_bitmap_set(mds->mds_lov_page_dirty, i);
                        break;
                }
        }
        if (rc >= 0)
                rc = 0;

        RETURN(rc);
}
EXPORT_SYMBOL(mds_lov_write_objids);

static int mds_lov_get_objid(struct obd_device * obd,
                             obd_id idx)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_export *lov_exp = mds->mds_lov_exp;
        unsigned int page;
        unsigned int off;
        obd_id *data;
        __u32 size;
        int rc = 0;
        ENTRY;

        page = idx / OBJID_PER_PAGE();
        off = idx % OBJID_PER_PAGE();
        data = mds->mds_lov_page_array[page];

        if (data[off] < 2) {
                /* We never read this lastid; ask the osc */
                struct obd_id_info lastid;

                size = sizeof(lastid);
                lastid.idx = idx;
                lastid.data = &data[off];
                rc = obd_get_info(NULL, lov_exp, sizeof(KEY_LAST_ID),
                                  KEY_LAST_ID, &size, &lastid, NULL);
                if (rc)
                        GOTO(out, rc);

                /* workaround for clean filter */
                if (data[off] == 0)
                        data[off] = 1;

                cfs_bitmap_set(mds->mds_lov_page_dirty, page);
        }
        CDEBUG(D_INFO, "idx "LPU64" - %p - %d/%d - "LPU64"\n",
               idx, data, page, off, data[off]);
out:
        RETURN(rc);
}

int mds_lov_clear_orphans(struct mds_obd *mds, struct obd_uuid *ost_uuid)
{
        int rc;
        struct obdo oa = { 0 };
        struct obd_trans_info oti = {0};
        struct lov_stripe_md  *empty_ea = NULL;
        ENTRY;

        LASSERT(mds->mds_lov_page_array != NULL);

        /* This create will in fact either create or destroy:  If the OST is
         * missing objects below this ID, they will be created.  If it finds
         * objects above this ID, they will be removed. */
        memset(&oa, 0, sizeof(oa));
        oa.o_flags = OBD_FL_DELORPHAN;
        oa.o_seq = mdt_to_obd_objseq(mds->mds_id);
        oa.o_valid = OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
        if (ost_uuid != NULL)
                oti.oti_ost_uuid = ost_uuid;

        rc = obd_create(NULL, mds->mds_lov_exp, &oa, &empty_ea, &oti);

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

        info.idx = idx;
        info.data = id;
        rc = obd_set_info_async(NULL, mds->mds_lov_exp, sizeof(KEY_NEXT_ID),
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
        __u32 valsize = sizeof(mds->mds_lov_desc);
        int rc = 0;
        ENTRY;

        OBD_ALLOC(ld, sizeof(*ld));
        if (!ld)
                RETURN(-ENOMEM);

        rc = obd_get_info(NULL, mds->mds_lov_exp, sizeof(KEY_LOVDESC),
                          KEY_LOVDESC, &valsize, ld, NULL);
        if (rc)
                GOTO(out, rc);

        /* Don't change the mds_lov_desc until the objids size matches the
           count (paranoia) */
        mds->mds_lov_desc = *ld;
        CDEBUG(D_CONFIG, "updated lov_desc, tgt_count: %d - idx %d / uuid %s\n",
               mds->mds_lov_desc.ld_tgt_count, idx, uuid->uuid);

        cfs_mutex_lock(&obd->obd_dev_mutex);
        rc = mds_lov_update_max_ost(mds, idx);
        cfs_mutex_unlock(&obd->obd_dev_mutex);
        if (rc != 0)
                GOTO(out, rc );

        /* If we added a target we have to reconnect the llogs */
        /* We only _need_ to do this at first add (idx), or the first time
           after recovery.  However, it should now be safe to call anytime. */
        rc = obd_llog_init(obd, &obd->obd_olg, obd, &idx);
        if (rc)
                GOTO(out, rc);

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

        LASSERT(mds_lov_objinit(mds, idx));

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
        RETURN(rc);
}

/* update the LOV-OSC knowledge of the last used object id's */
int mds_lov_connect(struct obd_device *obd, char * lov_name)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_connect_data *data;
        int rc;
        ENTRY;

        if (IS_ERR(mds->mds_lov_obd))
                RETURN(PTR_ERR(mds->mds_lov_obd));

        if (mds->mds_lov_obd)
                RETURN(0);

        mds->mds_lov_obd = class_name2obd(lov_name);
        if (!mds->mds_lov_obd) {
                CERROR("MDS cannot locate LOV %s\n", lov_name);
                mds->mds_lov_obd = ERR_PTR(-ENOTCONN);
                RETURN(-ENOTCONN);
        }

        cfs_mutex_lock(&obd->obd_dev_mutex);
        rc = mds_lov_read_objids(obd);
        cfs_mutex_unlock(&obd->obd_dev_mutex);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", "lov_objids", rc);
                GOTO(err_exit, rc);
        }

        rc = obd_register_observer(mds->mds_lov_obd, obd);
        if (rc) {
                CERROR("MDS cannot register as observer of LOV %s (%d)\n",
                       lov_name, rc);
                GOTO(err_exit, rc);
        }

        /* ask lov to generate OBD_NOTIFY_CREATE events for already registered
         * targets */
        obd_notify(mds->mds_lov_obd, NULL, OBD_NOTIFY_CREATE, NULL);

        mds->mds_lov_obd->u.lov.lov_sp_me = LUSTRE_SP_MDT;

        OBD_ALLOC(data, sizeof(*data));
        if (data == NULL)
                GOTO(err_exit, rc = -ENOMEM);

        data->ocd_connect_flags = OBD_CONNECT_VERSION   | OBD_CONNECT_INDEX   |
                                  OBD_CONNECT_REQPORTAL | OBD_CONNECT_QUOTA64 |
                                  OBD_CONNECT_OSS_CAPA  | OBD_CONNECT_FULL20  |
                                  OBD_CONNECT_CHANGE_QS | OBD_CONNECT_AT      |
                                  OBD_CONNECT_MDS | OBD_CONNECT_SKIP_ORPHAN   |
                                  OBD_CONNECT_SOM | OBD_CONNECT_MAX_EASIZE;
#ifdef HAVE_LRU_RESIZE_SUPPORT
        data->ocd_connect_flags |= OBD_CONNECT_LRU_RESIZE;
#endif
        data->ocd_version = LUSTRE_VERSION_CODE;
        data->ocd_group = mdt_to_obd_objseq(mds->mds_id);
        data->ocd_max_easize = mds->mds_obt.obt_osd_properties.osd_max_ea_size;

        /* send max bytes per rpc */
        data->ocd_brw_size = PTLRPC_MAX_BRW_PAGES << CFS_PAGE_SHIFT;
        /* send the list of supported checksum types */
	data->ocd_cksum_types = cksum_types_supported_client();
        /* NB: lov_connect() needs to fill in .ocd_index for each OST */
        rc = obd_connect(NULL, &mds->mds_lov_exp, mds->mds_lov_obd, &obd->obd_uuid, data, NULL);
        OBD_FREE(data, sizeof(*data));
        if (rc) {
                CERROR("MDS cannot connect to LOV %s (%d)\n", lov_name, rc);
                mds->mds_lov_obd = ERR_PTR(rc);
                RETURN(rc);
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

err_exit:
        mds->mds_lov_exp = NULL;
        mds->mds_lov_obd = ERR_PTR(rc);
        RETURN(rc);
}

int mds_lov_disconnect(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        if (!IS_ERR(mds->mds_lov_obd) && mds->mds_lov_exp != NULL) {
                obd_register_observer(mds->mds_lov_obd, NULL);

                /* The actual disconnect of the mds_lov will be called from
                 * class_disconnect_exports from mds_lov_clean. So we have to
                 * ensure that class_cleanup doesn't fail due to the extra ref
                 * we're holding now. The mechanism to do that already exists -
                 * the obd_force flag. We'll drop the final ref to the
                 * mds_lov_exp in mds_cleanup. */
                mds->mds_lov_obd->obd_force = 1;
        }

        RETURN(rc);
}

struct mds_lov_sync_info {
        struct obd_device    *mlsi_obd;     /* the lov device to sync */
        struct obd_device    *mlsi_watched; /* target osc */
        __u32                 mlsi_index;   /* index of target */
};

static int mds_propagate_capa_keys(struct mds_obd *mds, struct obd_uuid *uuid)
{
        struct mds_capa_info    info = { .uuid = uuid };
        struct lustre_capa_key *key;
        int i, rc = 0;

        ENTRY;

        if (!mds->mds_capa_keys)
                RETURN(0);

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_SYNC_CAPA_SL, 5);
        for (i = 0; i < 2; i++) {
                key = &mds->mds_capa_keys[i];
                DEBUG_CAPA_KEY(D_SEC, key, "propagate");

                info.capa = key;
                rc = obd_set_info_async(NULL, mds->mds_lov_exp,
                                        sizeof(KEY_CAPA_KEY), KEY_CAPA_KEY,
                                        sizeof(info), &info, NULL);
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

        cfs_down_read(&mds->mds_notify_lock);
        if (obd->obd_stopping || obd->obd_fail)
                GOTO(out, rc = -ENODEV);

        OBD_RACE(OBD_FAIL_MDS_LOV_SYNC_RACE);
        rc = mds_lov_update_mds(obd, watched, idx);
        if (rc != 0) {
                CERROR("%s failed at update_mds: %d\n", obd_uuid2str(uuid), rc);
                GOTO(out, rc);
        }
        mgi.group = mdt_to_obd_objseq(mds->mds_id);
        mgi.uuid = uuid;

        rc = obd_set_info_async(NULL, mds->mds_lov_exp, sizeof(KEY_MDS_CONN),
                                KEY_MDS_CONN, sizeof(mgi), &mgi, NULL);
        if (rc != 0)
                GOTO(out, rc);
        /* propagate capability keys */
        rc = mds_propagate_capa_keys(mds, uuid);
        if (rc)
                GOTO(out, rc);

        ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
        if (!ctxt)
                GOTO(out, rc = -ENODEV);

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_LLOG_SYNC_TIMEOUT, 60);
        rc = llog_connect(ctxt, NULL, NULL, uuid);
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

#ifdef HAVE_QUOTA_SUPPORT
        if (obd->obd_upcall.onu_owner) {
                /*
                 * This is a hack for mds_notify->mdd_notify. When the mds obd
                 * in mdd is removed, This hack should be removed.
                 */
                LASSERT(obd->obd_upcall.onu_upcall != NULL);
                rc = obd->obd_upcall.onu_upcall(obd, NULL, OBD_NOTIFY_QUOTA,
                                                obd->obd_upcall.onu_owner,NULL);
        }
#endif
        EXIT;
out:
        if (rc) {
                /* Deactivate it for safety */
                CERROR("%s sync failed %d, deactivating\n", obd_uuid2str(uuid),
                       rc);
                if (!obd->obd_stopping && mds->mds_lov_obd &&
                    !mds->mds_lov_obd->obd_stopping && !watched->obd_stopping)
                        obd_notify(mds->mds_lov_obd, watched,
                                   OBD_NOTIFY_INACTIVE, NULL);
        }
	cfs_up_read(&mds->mds_notify_lock);

        class_decref(obd, "mds_lov_synchronize", obd);
        return rc;
}

int mds_lov_synchronize(void *data)
{
        struct mds_lov_sync_info *mlsi = data;
        char name[20];

        snprintf(name, sizeof(name), "ll_sync_%02u", mlsi->mlsi_index);
        cfs_daemonize_ctxt(name);

        RETURN(__mds_lov_synchronize(data));
}

int mds_lov_start_synchronize(struct obd_device *obd,
                              struct obd_device *watched,
                              void *data, enum obd_notify_event ev)
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

        LASSERT(data);
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
        class_incref(obd, "mds_lov_synchronize", obd);

        if (ev != OBD_NOTIFY_SYNC) {
                /* Synchronize in the background */
                rc = cfs_create_thread(mds_lov_synchronize, mlsi,
                                       CFS_DAEMON_FLAGS);
                if (rc < 0) {
                        CERROR("%s: error starting mds_lov_synchronize: %d\n",
                               obd->obd_name, rc);
                        class_decref(obd, "mds_lov_synchronize", obd);
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
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        CDEBUG(D_CONFIG, "notify %s ev=%d\n", watched->obd_name, ev);

        if (strcmp(watched->obd_type->typ_name, LUSTRE_OSC_NAME) != 0) {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name, watched->obd_name);
                RETURN(-EINVAL);
        }

        /*XXX this notifies the MDD until lov handling use old mds code
         * must non block!
         */
        if (obd->obd_upcall.onu_owner) {
                 LASSERT(obd->obd_upcall.onu_upcall != NULL);
                 rc = obd->obd_upcall.onu_upcall(obd, NULL, ev,
                                                 obd->obd_upcall.onu_owner,
                                                 &mds->mds_obt.obt_mount_count);
        }

        switch (ev) {
        /* We only handle these: */
        case OBD_NOTIFY_CREATE:
                CDEBUG(D_CONFIG, "%s: add target %s\n", obd->obd_name,
                       obd_uuid2str(&watched->u.cli.cl_target_uuid));
                /* We still have to fix the lov descriptor for ost's */
                LASSERT(data);
                rc = mds_lov_update_desc(obd, *(__u32 *)data,
                                          &watched->u.cli.cl_target_uuid);
                RETURN(rc);
        case OBD_NOTIFY_ACTIVE:
                /* lov want one or more _active_ targets for work */
                /* activate event should be pass lov idx as argument */
        case OBD_NOTIFY_SYNC:
        case OBD_NOTIFY_SYNC_NONBLOCK:
                /* sync event should be pass lov idx as argument */
                break;
        default:
                RETURN(0);
        }

        if (obd->obd_recovering) {
                CDEBUG(D_CONFIG, "%s: Is in recovery, "
                       "not resetting orphans on %s\n",
                       obd->obd_name,
                       obd_uuid2str(&watched->u.cli.cl_target_uuid));
                /* We still have to fix the lov descriptor for ost's added
                   after the mdt in the config log.  They didn't make it into
                   mds_lov_connect. */
                rc = mds_lov_update_desc(obd, *(__u32 *)data,
                                         &watched->u.cli.cl_target_uuid);
        } else {
                rc = mds_lov_start_synchronize(obd, watched, data, ev);
        }
        RETURN(rc);
}
