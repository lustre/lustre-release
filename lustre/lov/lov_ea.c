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
 * lustre/lov/lov_ea.c
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LOV

#ifdef __KERNEL__
#include <asm/div64.h>
#include <libcfs/libcfs.h>
#else
#include <liblustre.h>
#endif

#include <obd_class.h>
#include <obd_lov.h>
#include <lustre/lustre_idl.h>
#include <lustre_log.h>

#include "lov_internal.h"

struct lovea_unpack_args {
        struct lov_stripe_md *lsm;
        int                   cursor;
};

static int lsm_lmm_verify_common(struct lov_mds_md *lmm, int lmm_bytes,
                                 int stripe_count)
{

        if (stripe_count == 0 || stripe_count > LOV_V1_INSANE_STRIPE_COUNT) {
                CERROR("bad stripe count %d\n", stripe_count);
                lov_dump_lmm_v1(D_WARNING, lmm);
                return -EINVAL;
        }

        if (lmm->lmm_object_id == 0) {
                CERROR("zero object id\n");
                lov_dump_lmm_v1(D_WARNING, lmm);
                return -EINVAL;
        }

        if (lmm->lmm_pattern != cpu_to_le32(LOV_PATTERN_RAID0)) {
                CERROR("bad striping pattern\n");
                lov_dump_lmm_v1(D_WARNING, lmm);
                return -EINVAL;
        }

        if (lmm->lmm_stripe_size == 0 ||
            (stripe_count != -1 &&
             (__u64)le32_to_cpu(lmm->lmm_stripe_size)*stripe_count >
             0xffffffff)) {
                CERROR("bad stripe size %u\n",
                       le32_to_cpu(lmm->lmm_stripe_size));
                lov_dump_lmm_v1(D_WARNING, lmm);
                return -EINVAL;
        }
        return 0;
}

struct lov_stripe_md *lsm_alloc_plain(int stripe_count, int *size)
{
        struct lov_stripe_md *lsm;
        int i, oinfo_ptrs_size;
        struct lov_oinfo *loi;

        LASSERT(stripe_count > 0);

        oinfo_ptrs_size = sizeof(struct lov_oinfo *) * stripe_count;
        *size = sizeof(struct lov_stripe_md) + oinfo_ptrs_size;

        OBD_ALLOC(lsm, *size);
        if (!lsm)
                return NULL;;

        for (i = 0; i < stripe_count; i++) {
                OBD_SLAB_ALLOC(loi, lov_oinfo_slab, CFS_ALLOC_IO, sizeof(*loi));
                if (loi == NULL)
                        goto err;
                lsm->lsm_oinfo[i] = loi;
        }
        lsm->lsm_stripe_count = stripe_count;
        return lsm;

err:
        while (--i >= 0)
                OBD_SLAB_FREE(lsm->lsm_oinfo[i], lov_oinfo_slab, sizeof(*loi));
        OBD_FREE(lsm, *size);
        return NULL;
}

void lsm_free_plain(struct lov_stripe_md *lsm)
{
        int stripe_count = lsm->lsm_stripe_count;
        int i;

        for (i = 0; i < stripe_count; i++)
                OBD_SLAB_FREE(lsm->lsm_oinfo[i], lov_oinfo_slab,
                              sizeof(struct lov_oinfo));
        OBD_FREE(lsm, sizeof(struct lov_stripe_md) +
                 stripe_count * sizeof(struct lov_oinfo *));
}

static void lsm_unpackmd_common(struct lov_stripe_md *lsm,
                                struct lov_mds_md *lmm)
{
        lsm->lsm_object_id = le64_to_cpu(lmm->lmm_object_id);
        lsm->lsm_object_gr = le64_to_cpu(lmm->lmm_object_gr);
        lsm->lsm_stripe_size = le32_to_cpu(lmm->lmm_stripe_size);
        lsm->lsm_pattern = le32_to_cpu(lmm->lmm_pattern);
}

static void
lsm_stripe_by_index_plain(struct lov_stripe_md *lsm, int *stripeno,
                           obd_off *lov_off, unsigned long *swidth)
{
        if (swidth)
                *swidth = (ulong)lsm->lsm_stripe_size * lsm->lsm_stripe_count;
}

static void
lsm_stripe_by_offset_plain(struct lov_stripe_md *lsm, int *stripeno,
                           obd_off *lov_off, unsigned long *swidth)
{
        if (swidth)
                *swidth = (ulong)lsm->lsm_stripe_size * lsm->lsm_stripe_count;
}

static obd_off
lsm_stripe_offset_by_index_plain(struct lov_stripe_md *lsm,
                                  int stripe_index)
{
        return 0;
}

static obd_off
lsm_stripe_offset_by_offset_plain(struct lov_stripe_md *lsm,
                                  obd_off lov_off)
{
        return 0;
}

static int
lsm_stripe_index_by_offset_plain(struct lov_stripe_md *lsm,
                                  obd_off lov_off)
{
        return 0;
}

static int lsm_revalidate_plain(struct lov_stripe_md *lsm,
                                struct obd_device *obd)
{
        return 0;
}

static int lsm_destroy_plain(struct lov_stripe_md *lsm, struct obdo *oa,
                             struct obd_export *md_exp)
{
        return 0;
}

static int lsm_lmm_verify_plain(struct lov_mds_md *lmm, int lmm_bytes,
                             int *stripe_count)
{
        if (lmm_bytes < sizeof(*lmm)) {
                CERROR("lov_mds_md too small: %d, need at least %d\n",
                       lmm_bytes, (int)sizeof(*lmm));
                return -EINVAL;
        }

        *stripe_count = le32_to_cpu(lmm->lmm_stripe_count);

        if (lmm_bytes < lov_mds_md_v1_size(*stripe_count)) {
                CERROR("LOV EA too small: %d, need %d\n",
                       lmm_bytes, lov_mds_md_v1_size(*stripe_count));
                lov_dump_lmm_v1(D_WARNING, lmm);
                return -EINVAL;
        }

        return lsm_lmm_verify_common(lmm, lmm_bytes, *stripe_count);
}

int lsm_unpackmd_plain(struct lov_obd *lov, struct lov_stripe_md *lsm,
                    struct lov_mds_md_v1 *lmm)
{
        struct lov_oinfo *loi;
        int i;

        lsm_unpackmd_common(lsm, lmm);

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                /* XXX LOV STACKING call down to osc_unpackmd() */
                loi = lsm->lsm_oinfo[i];
                loi->loi_id = le64_to_cpu(lmm->lmm_objects[i].l_object_id);
                loi->loi_gr = le64_to_cpu(lmm->lmm_objects[i].l_object_gr);
                loi->loi_ost_idx = le32_to_cpu(lmm->lmm_objects[i].l_ost_idx);
                loi->loi_ost_gen = le32_to_cpu(lmm->lmm_objects[i].l_ost_gen);
                if (loi->loi_ost_idx >= lov->desc.ld_tgt_count) {
                        CERROR("OST index %d more than OST count %d\n",
                               loi->loi_ost_idx, lov->desc.ld_tgt_count);
                        lov_dump_lmm_v1(D_WARNING, lmm);
                        return -EINVAL;
                }
                if (!lov->lov_tgts[loi->loi_ost_idx]) {
                        CERROR("OST index %d missing\n", loi->loi_ost_idx);
                        lov_dump_lmm_v1(D_WARNING, lmm);
                        return -EINVAL;
                }
        }

        return 0;
}

struct lsm_operations lsm_plain_ops = {
        .lsm_free            = lsm_free_plain,
        .lsm_destroy         = lsm_destroy_plain,
        .lsm_stripe_by_index    = lsm_stripe_by_index_plain,
        .lsm_stripe_by_offset   = lsm_stripe_by_offset_plain,
        .lsm_revalidate         = lsm_revalidate_plain,
        .lsm_stripe_offset_by_index  = lsm_stripe_offset_by_index_plain,
        .lsm_stripe_offset_by_offset = lsm_stripe_offset_by_offset_plain,
        .lsm_stripe_index_by_offset  = lsm_stripe_index_by_offset_plain,
        .lsm_lmm_verify         = lsm_lmm_verify_plain,
        .lsm_unpackmd           = lsm_unpackmd_plain,
};

struct lov_extent *lovea_off2le(struct lov_stripe_md *lsm, obd_off lov_off)
{
        struct lov_array_info *lai;
        struct lov_extent *le;
        int i = 0;

        LASSERT(lsm->lsm_array != NULL);
        lai = lsm->lsm_array;
        LASSERT(lai->lai_ext_count > 1);

        for (le = lai->lai_ext_array, i = 0;
             i < lai->lai_ext_count && le->le_start + le->le_len <= lov_off
             && le->le_len != -1;
             i ++, le ++) {
               ; /* empty loop */
        }

        CDEBUG(D_INFO, "off "LPU64" idx %d, ext "LPU64":"LPU64" idx %d sc %d\n",
               lov_off, i, le->le_start, le->le_len, le->le_loi_idx,
               le->le_stripe_count);

        RETURN(le);
}

struct lov_extent *lovea_idx2le(struct lov_stripe_md *lsm, int stripe_no)
{
        struct lov_extent *le;
        struct lov_array_info *lai;
        int i, stripe_index;

        LASSERT(lsm->lsm_array != NULL);
        LASSERT(stripe_no >= 0 && stripe_no <= lsm->lsm_stripe_count);
        lai = lsm->lsm_array;
        LASSERT(lai->lai_ext_count > 1);

        for (le = lai->lai_ext_array, i = 0, stripe_index = le->le_stripe_count;
             i < lai->lai_ext_count && stripe_index <= stripe_no &&
             le->le_len != -1; i ++, le ++,
             stripe_index += le->le_stripe_count) {
                ; /* empty loop */
        }

        CDEBUG(D_INFO, "stripe %d idx %d, ext "LPU64":"LPU64" idx %d sc %d\n",
               stripe_no, i, le->le_start, le->le_len, le->le_loi_idx,
               le->le_stripe_count);
        RETURN(le);
}

static void lovea_free_array_info(struct lov_stripe_md *lsm)
{
        if (!lsm || !lsm->lsm_array)
                return;

        if (lsm->lsm_array->lai_ext_array)
                OBD_FREE(lsm->lsm_array->lai_ext_array,
                         lsm->lsm_array->lai_ext_count *
                         sizeof(struct lov_extent));

        OBD_FREE_PTR(lsm->lsm_array);
}

static void lsm_free_join(struct lov_stripe_md *lsm)
{
        lovea_free_array_info(lsm);
        lsm_free_plain(lsm);
}

static void
lsm_stripe_by_index_join(struct lov_stripe_md *lsm, int *stripeno,
                           obd_off *lov_off, unsigned long *swidth)
{
        struct lov_extent *le;

        LASSERT(stripeno != NULL);

        le = lovea_idx2le(lsm, *stripeno);

        LASSERT(le != NULL && le->le_stripe_count != 0);

        *stripeno -= le->le_loi_idx;

        if (swidth)
                *swidth = (ulong)lsm->lsm_stripe_size * le->le_stripe_count;

        if (lov_off) {
                struct lov_extent *lov_le = lovea_off2le(lsm, *lov_off);
                if (lov_le == le) {
                        *lov_off = (*lov_off > le->le_start) ?
                                   (*lov_off - le->le_start) : 0;
                } else {
                        *lov_off = (*lov_off > le->le_start) ?
                                   le->le_len : 0;
                        LASSERT(*lov_off != -1);
                }
        }
}

static void
lsm_stripe_by_offset_join(struct lov_stripe_md *lsm, int *stripeno,
                           obd_off *lov_off, unsigned long *swidth)
{
        struct lov_extent *le;

        LASSERT(lov_off != NULL);

        le = lovea_off2le(lsm, *lov_off);

        LASSERT(le != NULL && le->le_stripe_count != 0);

        *lov_off = (*lov_off > le->le_start) ? (*lov_off - le->le_start) : 0;

        if (stripeno)
                *stripeno -= le->le_loi_idx;

        if (swidth)
                *swidth = (ulong)lsm->lsm_stripe_size * le->le_stripe_count;
}

static obd_off
lsm_stripe_offset_by_index_join(struct lov_stripe_md *lsm,
                                 int stripe_index)
{
        struct lov_extent *le;

        le = lovea_idx2le(lsm, stripe_index);

        return le ? le->le_start : 0;
}

static obd_off
lsm_stripe_offset_by_offset_join(struct lov_stripe_md *lsm,
                                 obd_off lov_off)
{
        struct lov_extent *le;

        le = lovea_off2le(lsm, lov_off);

        return le ? le->le_start : 0;
}

static int
lsm_stripe_index_by_offset_join(struct lov_stripe_md *lsm,
                                 obd_off lov_off)
{
        struct lov_extent *le = NULL;

        le = lovea_off2le(lsm, lov_off);

        return le ? le->le_loi_idx : 0;
}

static int lovea_unpack_array(struct llog_handle *handle,
                              struct llog_rec_hdr *rec, void *data)
{
        struct lovea_unpack_args *args = (struct lovea_unpack_args *)data;
        struct llog_array_rec *la_rec = (struct llog_array_rec*)rec;
        struct mds_extent_desc *med = &la_rec->lmr_med;
        struct lov_stripe_md *lsm = args->lsm;
        int cursor = args->cursor++;
        struct lov_mds_md *lmm;
        struct lov_array_info *lai;
        struct lov_oinfo * loi;
        int i, loi_index;
        ENTRY;

        /* sanity check */
        LASSERT(lsm->lsm_stripe_count != 0);
        lmm = &med->med_lmm;
        LASSERT(lsm->lsm_array != NULL);

        lai = lsm->lsm_array;

        if (cursor == 0) {
               lai->lai_ext_array[cursor].le_loi_idx = 0;
        } else {
               int next_loi_index = lai->lai_ext_array[cursor - 1].le_loi_idx +
                                 lai->lai_ext_array[cursor - 1].le_stripe_count;
               lai->lai_ext_array[cursor].le_loi_idx = next_loi_index;
        }
        /* insert extent desc into lsm extent array  */
        lai->lai_ext_array[cursor].le_start = le64_to_cpu(med->med_start);
        lai->lai_ext_array[cursor].le_len   = le64_to_cpu(med->med_len);
        lai->lai_ext_array[cursor].le_stripe_count = lmm->lmm_stripe_count;

        /* unpack extent's lmm to lov_oinfo array */
        loi_index = lai->lai_ext_array[cursor].le_loi_idx;
        CDEBUG(D_INFO, "lovea upackmd cursor %d, loi_index %d extent "
                        LPU64":"LPU64"\n", cursor, loi_index, med->med_start,
                        med->med_len);

        for (i = 0; i < le32_to_cpu(lmm->lmm_stripe_count); i ++, loi_index++) {
                /* XXX LOV STACKING call down to osc_unpackmd() */
                loi = lsm->lsm_oinfo[loi_index];
                loi->loi_id = le64_to_cpu(lmm->lmm_objects[i].l_object_id);
                loi->loi_gr = le64_to_cpu(lmm->lmm_objects[i].l_object_gr);
                loi->loi_ost_idx = le32_to_cpu(lmm->lmm_objects[i].l_ost_idx);
                loi->loi_ost_gen = le32_to_cpu(lmm->lmm_objects[i].l_ost_gen);
        }

        RETURN(0);
}

static int lsm_revalidate_join(struct lov_stripe_md *lsm,
                               struct obd_device *obd)
{
        struct llog_handle *llh;
        struct llog_ctxt *ctxt;
        struct lovea_unpack_args args;
        int rc, rc2;
        ENTRY;

        LASSERT(lsm->lsm_array != NULL);

        /*Revalidate lsm might be called from client or MDS server.
         *So the ctxt might be in different position
         */
        ctxt = llog_get_context(obd, LLOG_LOVEA_REPL_CTXT);
        if (!ctxt)
                ctxt = llog_get_context(obd, LLOG_LOVEA_ORIG_CTXT);

        LASSERT(ctxt);

        if (lsm->lsm_array && lsm->lsm_array->lai_ext_array)
                GOTO(release_ctxt, rc = 0);

        CDEBUG(D_INFO, "get lsm logid: "LPU64":"LPU64"\n",
               lsm->lsm_array->lai_array_id.lgl_oid,
               lsm->lsm_array->lai_array_id.lgl_ogr);
        OBD_ALLOC(lsm->lsm_array->lai_ext_array,lsm->lsm_array->lai_ext_count *
                                                sizeof (struct lov_extent));
        if (!lsm->lsm_array->lai_ext_array)
                GOTO(release_ctxt, rc = -ENOMEM);        

        CDEBUG(D_INFO, "get lsm logid: "LPU64":"LPU64"\n",
               lsm->lsm_array->lai_array_id.lgl_oid,
               lsm->lsm_array->lai_array_id.lgl_ogr);

        rc = llog_create(ctxt, &llh, &lsm->lsm_array->lai_array_id, NULL);
        if (rc)
                GOTO(out, rc);

        args.lsm = lsm;
        args.cursor = 0;
        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc == 0)
                rc = llog_process(llh, lovea_unpack_array, &args, NULL);
        rc2 = llog_close(llh);
        if (rc == 0)
                rc = rc2;
out:
        if (rc)
                lovea_free_array_info(lsm);
release_ctxt:
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

int lsm_destroy_join(struct lov_stripe_md *lsm, struct obdo *oa, 
                      struct obd_export *md_exp)
{
        struct llog_ctxt *ctxt;
        struct llog_handle *llh;
        int rc = 0;
        ENTRY;

        LASSERT(md_exp != NULL);
        /*for those orphan inode, we should keep array id*/
        if (!(oa->o_valid & OBD_MD_FLCOOKIE))
                RETURN(rc);

        ctxt = llog_get_context(md_exp->exp_obd, LLOG_LOVEA_REPL_CTXT);
        if (!ctxt)
                RETURN(-EINVAL);

        LASSERT(lsm->lsm_array != NULL);
        rc = llog_create(ctxt, &llh, &lsm->lsm_array->lai_array_id,
                         NULL);
        if (rc)
                GOTO(out, rc);

        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc == 0) {
                rc = llog_destroy(llh);
        }
        llog_free_handle(llh);
out:
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

static int lsm_lmm_verify_join(struct lov_mds_md *lmm, int lmm_bytes,
                               int *stripe_count)
{
        struct lov_mds_md_join *lmmj = (struct lov_mds_md_join *)lmm;

        if (lmm_bytes < sizeof(*lmmj)) {
                CERROR("lov_mds_md too small: %d, need at least %d\n",
                       lmm_bytes, (int)sizeof(*lmmj));
                return -EINVAL;
        }

        if (lmmj->lmmj_array_id.lgl_oid == 0) {
                CERROR("zero array object id\n");
                return -EINVAL;
        }

        *stripe_count = le32_to_cpu(lmmj->lmmj_md.lmm_stripe_count);

        return lsm_lmm_verify_common(&lmmj->lmmj_md, lmm_bytes, *stripe_count);
}

static int lovea_init_array_info(struct lov_stripe_md *lsm,
                                 struct llog_logid *logid,
                                 __u32 extent_count)
{
        struct lov_array_info *lai;
        ENTRY;

        OBD_ALLOC_PTR(lai);
        if (!lai)
                RETURN(-ENOMEM);

        lai->lai_array_id = *logid;
        lai->lai_ext_count = extent_count;
        lsm->lsm_array = lai;
        RETURN(0);
}

static int lsm_unpackmd_join(struct lov_obd *lov, struct lov_stripe_md *lsm,
                      struct lov_mds_md *lmm)
{
        struct lov_mds_md_join *lmmj = (struct lov_mds_md_join*)lmm;
        int    rc;
        ENTRY;

        lsm_unpackmd_common(lsm, &lmmj->lmmj_md);

        rc = lovea_init_array_info(lsm, &lmmj->lmmj_array_id,
                                   lmmj->lmmj_extent_count);
        if (rc) {
                CERROR("Init joined lsm id"LPU64" arrary error %d",
                        lsm->lsm_object_id, rc);
                GOTO(out, rc);
        }
out:
        RETURN(rc);
}

struct lsm_operations lsm_join_ops = {
        .lsm_free             = lsm_free_join,
        .lsm_destroy          = lsm_destroy_join,
        .lsm_stripe_by_index  = lsm_stripe_by_index_join,
        .lsm_stripe_by_offset = lsm_stripe_by_offset_join,
        .lsm_revalidate       = lsm_revalidate_join,
        .lsm_stripe_offset_by_index  = lsm_stripe_offset_by_index_join,
        .lsm_stripe_offset_by_offset = lsm_stripe_offset_by_offset_join,
        .lsm_stripe_index_by_offset  = lsm_stripe_index_by_offset_join,
        .lsm_lmm_verify         = lsm_lmm_verify_join,
        .lsm_unpackmd           = lsm_unpackmd_join,
};
