/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * (Un)packing of OST/MDS requests
 *
 */

#define DEBUG_SUBSYSTEM S_LLITE
#ifndef __KERNEL__
#include <liblustre.h>
#endif

#include <linux/lustre_net.h>
#include <linux/obd.h>
#include <linux/obd_lov.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_user.h>

#include "lov_internal.h"

void lov_dump_lmm_v0(int level, struct lov_mds_md_v0 *lmm)
{
        int i, num_ost, stripe, idx;

        num_ost = le32_to_cpu(lmm->lmm_ost_count);
        idx = le32_to_cpu(lmm->lmm_stripe_offset);
        CDEBUG(level, "objid "LPX64", magic 0x%08X, ost_count %u\n",
               le64_to_cpu(lmm->lmm_object_id), le32_to_cpu(lmm->lmm_magic),
               num_ost);
        CDEBUG(level,"stripe_size %u, stripe_count %u, stripe_offset %u\n",
               le32_to_cpu(lmm->lmm_stripe_size),
               le32_to_cpu(lmm->lmm_stripe_count), idx);
        for (i = stripe = 0; i < le32_to_cpu(lmm->lmm_ost_count); i++, idx++) {
                idx %= num_ost;
                if (lmm->lmm_objects[idx].l_object_id == 0)
                        continue;
                CDEBUG(level, "stripe %u idx %u subobj "LPX64"\n", stripe, idx,
                       le64_to_cpu(lmm->lmm_objects[idx].l_object_id));
                stripe++;
        }
}

void lov_dump_lmm_v1(int level, struct lov_mds_md_v1 *lmm)
{
        struct lov_ost_data_v1 *lod;
        int i;

        CDEBUG(level, "objid "LPX64", magic 0x%08X, pattern %#X\n",
               le64_to_cpu(lmm->lmm_object_id), le32_to_cpu(lmm->lmm_magic),
               le32_to_cpu(lmm->lmm_pattern));
        CDEBUG(level,"stripe_size %u, stripe_count %u\n",
               le32_to_cpu(lmm->lmm_stripe_size),
               le32_to_cpu(lmm->lmm_stripe_count));
        for (i = 0, lod = lmm->lmm_objects;
             i < le32_to_cpu(lmm->lmm_stripe_count); i++, lod++)
                CDEBUG(level, "stripe %u idx %u subobj "LPX64"/"LPX64"\n",
                       i, le32_to_cpu(lod->l_ost_idx),
                       le64_to_cpu(lod->l_object_gr),
                       le64_to_cpu(lod->l_object_id));
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
                stripe_count = lsm->lsm_stripe_count;
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

        for (i = 0, loi = lsm->lsm_oinfo; i < stripe_count; i++, loi++) {
                /* XXX LOV STACKING call down to osc_packmd() to do packing */
                LASSERT(loi->loi_id);
                lmm->lmm_objects[i].l_object_id = cpu_to_le64(loi->loi_id);
                lmm->lmm_objects[i].l_object_gr = cpu_to_le64(loi->loi_gr);
                lmm->lmm_objects[i].l_ost_gen = cpu_to_le32(loi->loi_ost_gen);
                lmm->lmm_objects[i].l_ost_idx = cpu_to_le32(loi->loi_ost_idx);
        }

        RETURN(lmm_size);
}

int lov_get_stripecnt(struct lov_obd *lov, int stripe_count)
{
        if (!stripe_count)
                stripe_count = lov->desc.ld_default_stripe_count;
        if (!stripe_count || stripe_count > lov->desc.ld_active_tgt_count)
                stripe_count = lov->desc.ld_active_tgt_count;

        return stripe_count;
}

static int lov_verify_lmm_v0(struct lov_mds_md_v0 *lmm, int lmm_bytes,
                             int *stripe_count)
{
        if (lmm_bytes < sizeof(*lmm)) {
                CERROR("lov_mds_md too small: %d, need at least %d\n",
                       lmm_bytes, (int)sizeof(*lmm));
                return -EINVAL;
        }

        *stripe_count = le16_to_cpu(lmm->lmm_stripe_count);

        if (*stripe_count == 0 ||
            *stripe_count > le32_to_cpu(lmm->lmm_ost_count)) {
                CERROR("bad stripe count %d\n", *stripe_count);
                lov_dump_lmm_v0(D_WARNING, lmm);
                return -EINVAL;
        }

        if (lmm_bytes < lov_mds_md_v0_size(*stripe_count)) {
                CERROR("LOV EA too small: %d, need %d\n",
                       lmm_bytes, lov_mds_md_size(*stripe_count));
                lov_dump_lmm_v0(D_WARNING, lmm);
                return -EINVAL;
        }

        if (lmm->lmm_object_id == 0) {
                CERROR("zero object id\n");
                lov_dump_lmm_v0(D_WARNING, lmm);
                return -EINVAL;
        }

        if (le32_to_cpu(lmm->lmm_stripe_offset) >
            le32_to_cpu(lmm->lmm_ost_count)) {
                CERROR("stripe offset %d more than number of OSTs %d\n",
                       le32_to_cpu(lmm->lmm_stripe_offset),
                       le32_to_cpu(lmm->lmm_ost_count));
                lov_dump_lmm_v0(D_WARNING, lmm);
                return -EINVAL;
        }

        if (lmm->lmm_stripe_size == 0) {
                CERROR("zero stripe size\n");
                lov_dump_lmm_v0(D_WARNING, lmm);
                return -EINVAL;
        }

        return 0;
}

static int lov_verify_lmm_v1(struct lov_mds_md_v1 *lmm, int lmm_bytes,
                             int *stripe_count)
{
        if (lmm_bytes < sizeof(*lmm)) {
                CERROR("lov_mds_md too small: %d, need at least %d\n",
                       lmm_bytes, (int)sizeof(*lmm));
                return -EINVAL;
        }

        if (lmm->lmm_magic != le32_to_cpu(LOV_MAGIC_V1)) {
                CERROR("bad disk LOV MAGIC: 0x%08X\n",
                       le32_to_cpu(*(__u32 *)lmm));
                return -EINVAL;
        }

        *stripe_count = le32_to_cpu(lmm->lmm_stripe_count);

        if (*stripe_count == 0) {
                CERROR("bad stripe count %d\n", *stripe_count);
                lov_dump_lmm_v1(D_WARNING, lmm);
                return -EINVAL;
        }

        if (lmm_bytes < lov_mds_md_size(*stripe_count)) {
                CERROR("LOV EA too small: %d, need %d\n",
                       lmm_bytes, lov_mds_md_size(*stripe_count));
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
            (__u64)le32_to_cpu(lmm->lmm_stripe_size) * *stripe_count > ~0UL) {
                CERROR("bad stripe size %u\n",
                       le32_to_cpu(lmm->lmm_stripe_size));
                lov_dump_lmm_v1(D_WARNING, lmm);
                return -EINVAL;
        }

        return 0;
}

static int lov_verify_lmm(void *lmm, int lmm_bytes, int *stripe_count)
{
        switch (le32_to_cpu(*(__u32 *)lmm)) {
        case LOV_MAGIC_V1:
                return lov_verify_lmm_v1(lmm, lmm_bytes, stripe_count);
        case LOV_MAGIC_V0:
                return lov_verify_lmm_v0(lmm, lmm_bytes, stripe_count);
        default:
                CERROR("bad disk LOV MAGIC: 0x%08X\n",
                       le32_to_cpu(*(__u32 *)lmm));
                return -EINVAL;
        }
}

int lov_alloc_memmd(struct lov_stripe_md **lsmp, int stripe_count, int pattern)
{
        int lsm_size = lov_stripe_md_size(stripe_count);
        struct lov_oinfo *loi;
        int i;

        OBD_ALLOC(*lsmp, lsm_size);
        if (!*lsmp)
                return -ENOMEM;

        (*lsmp)->lsm_magic = LOV_MAGIC;
        (*lsmp)->lsm_stripe_count = stripe_count;
        (*lsmp)->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES * stripe_count;
        (*lsmp)->lsm_pattern = pattern;
        (*lsmp)->lsm_oinfo[0].loi_ost_idx = ~0;

        for (i = 0, loi = (*lsmp)->lsm_oinfo; i < stripe_count; i++, loi++)
                loi_init(loi);

        return lsm_size;
}

void lov_free_memmd(struct lov_stripe_md **lsmp)
{
        OBD_FREE(*lsmp, lov_stripe_md_size((*lsmp)->lsm_stripe_count));
        *lsmp = NULL;
}

int lov_unpackmd_v0(struct lov_obd *lov, struct lov_stripe_md *lsm,
                    struct lov_mds_md_v0 *lmm)
{
        struct lov_oinfo *loi;
        int i, ost_offset, ost_count;

        lsm->lsm_object_id = le64_to_cpu(lmm->lmm_object_id);
        /* lsm->lsm_object_gr = 0; implicit */
        lsm->lsm_stripe_size = le32_to_cpu(lmm->lmm_stripe_size);
        lsm->lsm_pattern = LOV_PATTERN_RAID0;
        ost_offset = le32_to_cpu(lmm->lmm_stripe_offset);
        ost_count = le16_to_cpu(lmm->lmm_ost_count);

        for (i = 0, loi = lsm->lsm_oinfo; i < ost_count; i++, ost_offset++) {
                ost_offset %= ost_count;

                if (!lmm->lmm_objects[ost_offset].l_object_id)
                        continue;

                loi->loi_id =
                        le64_to_cpu(lmm->lmm_objects[ost_offset].l_object_id);
                /* loi->loi_gr = 0; implicit */
                loi->loi_ost_idx = ost_offset;
                /* loi->loi_ost_gen = 0; implicit */
                loi++;
        }

        if (loi - lsm->lsm_oinfo != lsm->lsm_stripe_count) {
                CERROR("missing objects in lmm struct\n");
                lov_dump_lmm_v0(D_WARNING, lmm);
                return -EINVAL;
        }

        return 0;
}

int lov_unpackmd_v1(struct lov_obd *lov, struct lov_stripe_md *lsm,
                    struct lov_mds_md_v1 *lmm)
{
        struct lov_oinfo *loi;
        int i;

        lsm->lsm_object_id = le64_to_cpu(lmm->lmm_object_id);
        lsm->lsm_object_gr = le64_to_cpu(lmm->lmm_object_gr);
        lsm->lsm_stripe_size = le32_to_cpu(lmm->lmm_stripe_size);
        lsm->lsm_pattern = le32_to_cpu(lmm->lmm_pattern);

        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++) {
                /* XXX LOV STACKING call down to osc_unpackmd() */
                loi->loi_id = le64_to_cpu(lmm->lmm_objects[i].l_object_id);
                loi->loi_gr = le64_to_cpu(lmm->lmm_objects[i].l_object_gr);
                loi->loi_ost_idx = le32_to_cpu(lmm->lmm_objects[i].l_ost_idx);
                loi->loi_ost_gen = le32_to_cpu(lmm->lmm_objects[i].l_ost_gen);
                if (loi->loi_ost_idx > lov->desc.ld_tgt_count) {
                        CERROR("OST index %d more than OST count %d\n",
                               loi->loi_ost_idx, lov->desc.ld_tgt_count);
                        lov_dump_lmm_v1(D_WARNING, lmm);
                        return -EINVAL;
                }
                loi++;
        }

        return 0;
}

/* Unpack LOV object metadata from disk storage.  It is packed in LE byte
 * order and is opaque to the networking layer.
 */
int lov_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsmp,
                 struct lov_mds_md *lmm, int lmm_bytes)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        int rc = 0, stripe_count, lsm_size;
        ENTRY;

        /* If passed an MDS struct use values from there, otherwise defaults */
        if (lmm) {
                rc = lov_verify_lmm(lmm, lmm_bytes, &stripe_count);
                if (rc)
                        RETURN(rc);
        } else {
                stripe_count = lov_get_stripecnt(lov, 0);
        }

        /* If we aren't passed an lsmp struct, we just want the size */
        if (!lsmp)
                /* XXX LOV STACKING call into osc for sizes */
                RETURN(lov_stripe_md_size(stripe_count));

        /* If we are passed an allocated struct but nothing to unpack, free */
        if (*lsmp && !lmm) {
                lov_free_memmd(lsmp);
                RETURN(0);
        }

        lsm_size = lov_alloc_memmd(lsmp, stripe_count, LOV_PATTERN_RAID0);
        if (lsm_size < 0)
                RETURN(lsm_size);

        /* If we are passed a pointer but nothing to unpack, we only alloc */
        if (!lmm)
                RETURN(lsm_size);

        switch (le32_to_cpu(lmm->lmm_magic)) {
        case LOV_MAGIC_V1:
                rc = lov_unpackmd_v1(lov, *lsmp, lmm);
                break;
        case LOV_MAGIC_V0:
                rc = lov_unpackmd_v0(lov, *lsmp, (void *)lmm);
                break;
        }

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
                CDEBUG(D_IOCTL, "bad userland LOV MAGIC: %#08x != %#08x\n",
                       lum.lmm_magic, LOV_USER_MAGIC);
                RETURN(-EINVAL);
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

        if (lum.lmm_stripe_size & (PAGE_SIZE - 1)) {
                CDEBUG(D_IOCTL, "stripe size %u not multiple of %lu\n",
                       lum.lmm_stripe_size, PAGE_SIZE);
                RETURN(-EINVAL);
        }

        if ((lum.lmm_stripe_offset >= lov->desc.ld_active_tgt_count) &&
            (lum.lmm_stripe_offset != (typeof(lum.lmm_stripe_offset))(-1))) {
                CDEBUG(D_IOCTL, "stripe offset %u > number of active OSTs %u\n",
                       lum.lmm_stripe_offset, lov->desc.ld_active_tgt_count);
                RETURN(-EINVAL);
        }
        stripe_count = lov_get_stripecnt(lov, lum.lmm_stripe_count);

        if ((__u64)lum.lmm_stripe_size * stripe_count > ~0UL) {
                CDEBUG(D_IOCTL, "stripe width %ux%u > %lu on 32-bit system\n",
                       lum.lmm_stripe_size, (int)lum.lmm_stripe_count, ~0UL);
                RETURN(-EINVAL);
        }

        rc = lov_alloc_memmd(lsmp, stripe_count, lum.lmm_pattern);

        if (rc < 0)
                RETURN(rc);

        (*lsmp)->lsm_oinfo[0].loi_ost_idx = lum.lmm_stripe_offset;
        (*lsmp)->lsm_stripe_size = lum.lmm_stripe_size;

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
        if (lum.lmm_stripe_count < lmmk->lmm_stripe_count)
                rc = -EOVERFLOW;
        else if (copy_to_user(lump, lmmk, lmm_size))
                rc = -EFAULT;

        obd_free_diskmd(exp, &lmmk);

        RETURN(rc);
}
