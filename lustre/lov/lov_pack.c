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
 * lustre/lov/lov_pack.c
 *
 * (Un)packing of OST/MDS requests
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOV
#ifndef __KERNEL__
#include <liblustre.h>
#endif

#include <lustre_net.h>
#include <obd.h>
#include <obd_lov.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre/lustre_user.h>

#include "lov_internal.h"

void lov_dump_lmm_v1(int level, struct lov_mds_md_v1 *lmm)
{
        struct lov_ost_data_v1 *lod;
        int i;

        CDEBUG(level, "objid "LPX64", magic 0x%08x, pattern %#x\n",
               le64_to_cpu(lmm->lmm_object_id), le32_to_cpu(lmm->lmm_magic),
               le32_to_cpu(lmm->lmm_pattern));
        CDEBUG(level,"stripe_size %u, stripe_count %u\n",
               le32_to_cpu(lmm->lmm_stripe_size),
               le32_to_cpu(lmm->lmm_stripe_count));

        if (le32_to_cpu(lmm->lmm_stripe_count) <= LOV_V1_INSANE_STRIPE_COUNT) {
                for (i = 0, lod = lmm->lmm_objects;
                     i < (int)le32_to_cpu(lmm->lmm_stripe_count); i++, lod++)
                         CDEBUG(level,
                                "stripe %u idx %u subobj "LPX64"/"LPX64"\n",
                                i, le32_to_cpu(lod->l_ost_idx),
                                le64_to_cpu(lod->l_object_gr),
                                le64_to_cpu(lod->l_object_id));
        } else {
                CDEBUG(level, "bad stripe_count %u > max_stripe_count %u\n",
                       le32_to_cpu(lmm->lmm_stripe_count),
                       LOV_V1_INSANE_STRIPE_COUNT);
        }
}

void lov_dump_lmm_join(int level, struct lov_mds_md_join *lmmj)
{

        CDEBUG(level, "objid "LPX64", magic 0x%08X, pattern %#X\n",
               le64_to_cpu(lmmj->lmmj_md.lmm_object_id), 
               le32_to_cpu(lmmj->lmmj_md.lmm_magic),
               le32_to_cpu(lmmj->lmmj_md.lmm_pattern));
        CDEBUG(level,"stripe_size %u, stripe_count %u extent_count %u \n",
               le32_to_cpu(lmmj->lmmj_md.lmm_stripe_size),
               le32_to_cpu(lmmj->lmmj_md.lmm_stripe_count), 
               le32_to_cpu(lmmj->lmmj_extent_count));
}

#define LMM_ASSERT(test)                                                \
do {                                                                    \
        if (!(test)) lov_dump_lmm(D_ERROR, lmm);                        \
        LASSERT(test); /* so we know what assertion failed */           \
} while(0)

/* Pack LOV object metadata for disk storage.  It is packed in LE byte
 * order and is opaque to the networking layer.
 *
 * XXX In the future, this will be enhanced to get the EA size from the
 *     underlying OSC device(s) to get their EA sizes so we can stack
 *     LOVs properly.  For now lov_mds_md_size() just assumes one obd_id
 *     per stripe.
 */
int lov_packmd(struct obd_export *exp, struct lov_mds_md **lmmp,
               struct lov_stripe_md *lsm)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_oinfo *loi;
        struct lov_mds_md *lmm;
        int stripe_count = lov->desc.ld_tgt_count;
        int lmm_size;
        int i;
        ENTRY;

        if (lsm) {
                if (lsm->lsm_magic != LOV_MAGIC) {
                        CERROR("bad mem LOV MAGIC: 0x%08X != 0x%08X\n",
                               lsm->lsm_magic, LOV_MAGIC);
                        RETURN(-EINVAL);
                }
                if (!lmmp) {
                        stripe_count = lov_get_stripecnt(lov, lsm->lsm_stripe_count);
                        lsm->lsm_stripe_count = stripe_count;
                } else {
                        stripe_count = lsm->lsm_stripe_count;
                }
        }

        /* XXX LOV STACKING call into osc for sizes */
        lmm_size = lov_mds_md_size(stripe_count);

        if (!lmmp)
                RETURN(lmm_size);

        if (*lmmp && !lsm) {
                stripe_count = le32_to_cpu((*lmmp)->lmm_stripe_count);
                OBD_FREE(*lmmp, lov_mds_md_size(stripe_count));
                *lmmp = NULL;
                RETURN(0);
        }

        if (!*lmmp) {
                OBD_ALLOC(*lmmp, lmm_size);
                if (!*lmmp)
                        RETURN(-ENOMEM);
        }

        lmm = *lmmp;
        lmm->lmm_magic = cpu_to_le32(LOV_MAGIC); /* only write new format */

        if (!lsm)
                RETURN(lmm_size);

        lmm->lmm_object_id = cpu_to_le64(lsm->lsm_object_id);
        lmm->lmm_object_gr = cpu_to_le64(lsm->lsm_object_gr);
        lmm->lmm_stripe_size = cpu_to_le32(lsm->lsm_stripe_size);
        lmm->lmm_stripe_count = cpu_to_le32(stripe_count);
        lmm->lmm_pattern = cpu_to_le32(lsm->lsm_pattern);

        for (i = 0; i < stripe_count; i++) {
                loi = lsm->lsm_oinfo[i];
                /* XXX LOV STACKING call down to osc_packmd() to do packing */
                LASSERTF(loi->loi_id, "lmm_oid "LPU64" stripe %u/%u idx %u\n",
                         lmm->lmm_object_id, i, stripe_count, loi->loi_ost_idx);
                lmm->lmm_objects[i].l_object_id = cpu_to_le64(loi->loi_id);
                lmm->lmm_objects[i].l_object_gr = cpu_to_le64(loi->loi_gr);
                lmm->lmm_objects[i].l_ost_gen = cpu_to_le32(loi->loi_ost_gen);
                lmm->lmm_objects[i].l_ost_idx = cpu_to_le32(loi->loi_ost_idx);
        }

        RETURN(lmm_size);
}

/* Find the max stripecount we should use */
int lov_get_stripecnt(struct lov_obd *lov, __u32 stripe_count)
{
        if (!stripe_count)
                stripe_count = lov->desc.ld_default_stripe_count;
        if (stripe_count > lov->desc.ld_active_tgt_count)
                stripe_count = lov->desc.ld_active_tgt_count;
        if (!stripe_count)
                stripe_count = 1;
        /* for now, we limit the stripe count directly, when bug 4424 is
         * fixed this needs to be somewhat dynamic based on whether ext3
         * can handle larger EA sizes. */
        if (stripe_count > LOV_MAX_STRIPE_COUNT)
                stripe_count = LOV_MAX_STRIPE_COUNT;

        return stripe_count;
}


static int lov_verify_lmm(void *lmm, int lmm_bytes, int *stripe_count)
{
        int rc;

        if (lsm_op_find(le32_to_cpu(*(__u32 *)lmm)) == NULL) {
                CERROR("bad disk LOV MAGIC: 0x%08X; dumping V1 LMM:\n",
                       le32_to_cpu(*(__u32 *)lmm));
                lov_dump_lmm_v1(D_WARNING, lmm);
                return -EINVAL;
        }
        rc = lsm_op_find(le32_to_cpu(*(__u32 *)lmm))->lsm_lmm_verify(lmm,
                                     lmm_bytes, stripe_count);
        return rc;
}

int lov_alloc_memmd(struct lov_stripe_md **lsmp, int stripe_count, 
                      int pattern, int magic)
{
        int i, lsm_size;
        ENTRY;

        CDEBUG(D_INFO, "alloc lsm, stripe_count %d\n", stripe_count);

        *lsmp = lsm_alloc_plain(stripe_count, &lsm_size);
        if (!*lsmp) {
                CERROR("can't allocate lsmp, stripe_count %d\n", stripe_count);
                RETURN(-ENOMEM);
        }

        spin_lock_init(&(*lsmp)->lsm_lock);
        (*lsmp)->lsm_magic = magic;
        (*lsmp)->lsm_stripe_count = stripe_count;
        (*lsmp)->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES * stripe_count;
        (*lsmp)->lsm_pattern = pattern;
        (*lsmp)->lsm_oinfo[0]->loi_ost_idx = ~0;

        for (i = 0; i < stripe_count; i++)
                loi_init((*lsmp)->lsm_oinfo[i]);

        RETURN(lsm_size);
}

void lov_free_memmd(struct lov_stripe_md **lsmp)
{
        struct lov_stripe_md *lsm = *lsmp;
        
        LASSERT(lsm_op_find(lsm->lsm_magic) != NULL);
        lsm_op_find(lsm->lsm_magic)->lsm_free(lsm);
        
        *lsmp = NULL;
}


/* Unpack LOV object metadata from disk storage.  It is packed in LE byte
 * order and is opaque to the networking layer.
 */
int lov_unpackmd(struct obd_export *exp,  struct lov_stripe_md **lsmp, 
                 struct lov_mds_md *lmm, int lmm_bytes)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        int rc = 0, stripe_count, lsm_size;
        __u32 magic;
        ENTRY;

        /* If passed an MDS struct use values from there, otherwise defaults */
        if (lmm) {
                rc = lov_verify_lmm(lmm, lmm_bytes, &stripe_count);
                if (rc)
                        RETURN(rc);
                magic = le32_to_cpu(lmm->lmm_magic);
        } else {
                stripe_count = lov_get_stripecnt(lov, 0);
                magic = LOV_MAGIC;
        }

        /* If we aren't passed an lsmp struct, we just want the size */
        if (!lsmp) {
                /* XXX LOV STACKING call into osc for sizes */
                LBUG();
                RETURN(lov_stripe_md_size(stripe_count));
        }

        /* If we are passed an allocated struct but nothing to unpack, free */
        if (*lsmp && !lmm) {
                lov_free_memmd(lsmp);
                RETURN(0);
        }

        lsm_size = lov_alloc_memmd(lsmp, stripe_count, LOV_PATTERN_RAID0, 
                                   magic);
        if (lsm_size < 0)
                RETURN(lsm_size);

        /* If we are passed a pointer but nothing to unpack, we only alloc */
        if (!lmm)
                RETURN(lsm_size);

        LASSERT(lsm_op_find(magic) != NULL);
        rc = lsm_op_find(magic)->lsm_unpackmd(lov, *lsmp, lmm);
        if (rc) {
                lov_free_memmd(lsmp);
                RETURN(rc);
        }

        RETURN(lsm_size);
}

/* Configure object striping information on a new file.
 *
 * @lmmu is a pointer to a user struct with one or more of the fields set to
 * indicate the application preference: lmm_stripe_count, lmm_stripe_size,
 * lmm_stripe_offset, and lmm_stripe_pattern.  lmm_magic must be LOV_MAGIC.
 * @lsmp is a pointer to an in-core stripe MD that needs to be filled in.
 */
int lov_setstripe(struct obd_export *exp, struct lov_stripe_md **lsmp,
                  struct lov_user_md *lump)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_user_md lum;
        int stripe_count;
        int rc;
        ENTRY;

        rc = copy_from_user(&lum, lump, sizeof(lum));
        if (rc)
                RETURN(-EFAULT);

        if (lum.lmm_magic != LOV_USER_MAGIC) {
                if (lum.lmm_magic == __swab32(LOV_USER_MAGIC)) {
                        lustre_swab_lov_user_md(&lum);
                } else {
                        CDEBUG(D_IOCTL, "bad userland LOV MAGIC:"
                               " %#08x != %#08x\n",
                               lum.lmm_magic, LOV_USER_MAGIC);
                        RETURN(-EINVAL);
                }
        }

        if (lum.lmm_pattern == 0) {
                lum.lmm_pattern = lov->desc.ld_pattern ?
                        lov->desc.ld_pattern : LOV_PATTERN_RAID0;
        }

        if (lum.lmm_pattern != LOV_PATTERN_RAID0) {
                CDEBUG(D_IOCTL, "bad userland stripe pattern: %#x\n",
                       lum.lmm_pattern);
                RETURN(-EINVAL);
        }

        /* 64kB is the largest common page size we see (ia64), and matches the
         * check in lfs */
        if (lum.lmm_stripe_size & (LOV_MIN_STRIPE_SIZE - 1)) {
                CDEBUG(D_IOCTL, "stripe size %u not multiple of %u, fixing\n",
                       lum.lmm_stripe_size, LOV_MIN_STRIPE_SIZE);
                lum.lmm_stripe_size = LOV_MIN_STRIPE_SIZE;
        }

        if ((lum.lmm_stripe_offset >= lov->desc.ld_tgt_count) &&
            (lum.lmm_stripe_offset != (typeof(lum.lmm_stripe_offset))(-1))) {
                CDEBUG(D_IOCTL, "stripe offset %u > number of OSTs %u\n",
                       lum.lmm_stripe_offset, lov->desc.ld_tgt_count);
                RETURN(-EINVAL);
        }
        stripe_count = lov_get_stripecnt(lov, lum.lmm_stripe_count);

        if ((__u64)lum.lmm_stripe_size * stripe_count > ~0U) {
                CDEBUG(D_IOCTL, "stripe width %ux%u exceeds %u bytes\n",
                       lum.lmm_stripe_size, (int)lum.lmm_stripe_count, ~0U);
                RETURN(-EINVAL);
        }

        rc = lov_alloc_memmd(lsmp, stripe_count, lum.lmm_pattern, LOV_MAGIC);

        if (rc < 0)
                RETURN(rc);

        (*lsmp)->lsm_oinfo[0]->loi_ost_idx = lum.lmm_stripe_offset;
        (*lsmp)->lsm_stripe_size = lum.lmm_stripe_size;

        RETURN(0);
}

int lov_setea(struct obd_export *exp, struct lov_stripe_md **lsmp,
              struct lov_user_md *lump)
{
        int i;
        int rc;
        struct obd_export *oexp;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        obd_id last_id = 0;

        ENTRY;
        for (i = 0; i < lump->lmm_stripe_count; i++) {
                __u32 len = sizeof(last_id);
                oexp = lov->lov_tgts[lump->lmm_objects[i].l_ost_idx]->ltd_exp;
                rc = obd_get_info(oexp, sizeof(KEY_LAST_ID), KEY_LAST_ID,
                                  &len, &last_id, NULL);
                if (rc)
                        RETURN(rc);
                if (lump->lmm_objects[i].l_object_id > last_id) {
                        CERROR("Setting EA for object > than last id on "
                               "ost idx %d "LPD64" > "LPD64" \n",
                               lump->lmm_objects[i].l_ost_idx,
                               lump->lmm_objects[i].l_object_id, last_id);
                        RETURN(-EINVAL);
                }
        }

        rc = lov_setstripe(exp, lsmp, lump);
        if (rc)
                RETURN(rc);

        for (i = 0; i < lump->lmm_stripe_count; i++) {
                (*lsmp)->lsm_oinfo[i]->loi_ost_idx =
                        lump->lmm_objects[i].l_ost_idx;
                (*lsmp)->lsm_oinfo[i]->loi_id = lump->lmm_objects[i].l_object_id;
                (*lsmp)->lsm_oinfo[i]->loi_gr = lump->lmm_objects[i].l_object_gr;
        }
        RETURN(0);
}


/* Retrieve object striping information.
 *
 * @lump is a pointer to an in-core struct with lmm_ost_count indicating
 * the maximum number of OST indices which will fit in the user buffer.
 * lmm_magic must be LOV_USER_MAGIC.
 */
int lov_getstripe(struct obd_export *exp, struct lov_stripe_md *lsm,
                  struct lov_user_md *lump)
{
        struct lov_user_md lum;
        struct lov_mds_md *lmmk = NULL;
        int rc, lmm_size;
        ENTRY;

        if (!lsm)
                RETURN(-ENODATA);

        rc = copy_from_user(&lum, lump, sizeof(lum));
        if (rc)
                RETURN(-EFAULT);

        if (lum.lmm_magic != LOV_USER_MAGIC)
                RETURN(-EINVAL);

        rc = lov_packmd(exp, &lmmk, lsm);
        if (rc < 0)
                RETURN(rc);
        lmm_size = rc;
        rc = 0;

        /* FIXME: Bug 1185 - copy fields properly when structs change */
        LASSERT(sizeof(lum) == sizeof(*lmmk));
        LASSERT(sizeof(lum.lmm_objects[0]) == sizeof(lmmk->lmm_objects[0]));

        /* User wasn't expecting this many OST entries */
        if (lum.lmm_stripe_count == 0) {
                if (copy_to_user(lump, lmmk, sizeof(lum)))
                        rc = -EFAULT;
        } else if (lum.lmm_stripe_count < lmmk->lmm_stripe_count) {
                rc = -EOVERFLOW;
        } else if (copy_to_user(lump, lmmk, lmm_size)) {
                rc = -EFAULT;
        }

        obd_free_diskmd(exp, &lmmk);

        RETURN(rc);
}
