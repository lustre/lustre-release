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

#include "lov_internal.h"

void lov_dump_lmm(int level, struct lov_mds_md *lmm)
{
        struct lov_object_id *loi;
        int idx;

        CDEBUG(level, "objid "LPX64", magic %#08x, ost_count %u\n",
               lmm->lmm_object_id, lmm->lmm_magic, lmm->lmm_ost_count);
        CDEBUG(level,"stripe_size %u, stripe_count %u, stripe_offset %u\n",
               lmm->lmm_stripe_size, lmm->lmm_stripe_count,
               lmm->lmm_stripe_offset);
        for (idx = 0, loi = lmm->lmm_objects; idx < lmm->lmm_ost_count;
             idx++, loi++)
                CDEBUG(level, "ost idx %u subobj "LPX64"\n", idx,
                       loi->l_object_id);
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
int lov_packmd(struct lustre_handle *conn, struct lov_mds_md **lmmp,
               struct lov_stripe_md *lsm)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_oinfo *loi;
        struct lov_mds_md *lmm;
        int ost_count = lov->desc.ld_tgt_count;
        int stripe_count = ost_count;
        int lmm_size;
        int i;
        ENTRY;

        if (lsm) {
                int i, max = 0;
                if (lsm->lsm_magic != LOV_MAGIC) {
                        CERROR("bad mem LOV MAGIC: %#010x != %#010x\n",
                               lsm->lsm_magic, LOV_MAGIC);
                        RETURN(-EINVAL);
                }
                stripe_count = lsm->lsm_stripe_count;

                for (i = 0,loi = lsm->lsm_oinfo; i < stripe_count; i++,loi++) {
                        if (loi->loi_ost_idx > max)
                                max = loi->loi_ost_idx;
                }
                ost_count = max + 1;
        }

        /* XXX LOV STACKING call into osc for sizes */
        lmm_size = lov_mds_md_size(ost_count);

        if (!lmmp)
                RETURN(lmm_size);

        if (*lmmp && !lsm) {
                ost_count = le32_to_cpu ((*lmmp)->lmm_ost_count);
                OBD_FREE(*lmmp, lov_mds_md_size(ost_count));
                *lmmp = NULL;
                RETURN(0);
        }

        if (!*lmmp) {
                OBD_ALLOC(*lmmp, lmm_size);
                if (!*lmmp)
                        RETURN(-ENOMEM);
        }

        lmm = *lmmp;
        lmm->lmm_magic = cpu_to_le32 (LOV_MAGIC);
        lmm->lmm_ost_count = cpu_to_le16 (ost_count);

        if (!lsm)
                RETURN(lmm_size);

        lmm->lmm_object_id = cpu_to_le64 (lsm->lsm_object_id);
        lmm->lmm_stripe_count = cpu_to_le16 (stripe_count);
        lmm->lmm_stripe_size = cpu_to_le32 (lsm->lsm_stripe_size);
        lmm->lmm_stripe_offset = cpu_to_le32 (lsm->lsm_stripe_offset);

        /* Only fill in the object ids which we are actually using.
         * Assumes lmm_objects is otherwise zero-filled. */
        for (i = 0, loi = lsm->lsm_oinfo; i < stripe_count; i++, loi++) {
                /* XXX call down to osc_packmd() to do the packing */
                LASSERT (loi->loi_id);
                lmm->lmm_objects[loi->loi_ost_idx].l_object_id =
                        cpu_to_le64 (loi->loi_id);
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

static int lov_verify_lmm(struct lov_mds_md *lmm, int lmm_bytes,
                          int *ost_count, int *stripe_count, int *ost_offset)
{
        if (lmm_bytes < sizeof(*lmm)) {
                CERROR("lov_mds_md too small: %d, need at least %d\n",
                       lmm_bytes, (int)sizeof(*lmm));
                return -EINVAL;
        }

        if (le32_to_cpu(lmm->lmm_magic) != LOV_MAGIC) {
                CERROR("bad disk LOV MAGIC: %#08x != %#08x\n",
                       le32_to_cpu(lmm->lmm_magic), LOV_MAGIC);
                lov_dump_lmm(D_WARNING, lmm);
                return -EINVAL;
        }

        *ost_count = le16_to_cpu(lmm->lmm_ost_count);
        *stripe_count = le16_to_cpu(lmm->lmm_stripe_count);
        *ost_offset = le32_to_cpu(lmm->lmm_stripe_offset);

        if (*ost_count == 0 || *stripe_count == 0) {
                CERROR("zero OST count %d or stripe count %d\n",
                       *ost_count, *stripe_count);
                lov_dump_lmm(D_WARNING, lmm);
                return -EINVAL;
        }

        if (lmm_bytes < lov_mds_md_size(*ost_count)) {
                CERROR("lov_mds_md too small: %d, need %d\n",
                       lmm_bytes, lov_mds_md_size(*ost_count));
                lov_dump_lmm(D_WARNING, lmm);
                return -EINVAL;
        }

        if (*ost_offset > *ost_count) {
                CERROR("starting OST offset %d > number of OSTs %d\n",
                       *ost_offset, *ost_count);
                lov_dump_lmm(D_WARNING, lmm);
                return -EINVAL;
        }

        if (*stripe_count > *ost_count) {
                CERROR("stripe count %d > number of OSTs %d\n",
                       *stripe_count, *ost_count);
                lov_dump_lmm(D_WARNING, lmm);
                return -EINVAL;
        }

        if (lmm->lmm_object_id == 0) {
                CERROR("zero object id\n");
                lov_dump_lmm(D_WARNING, lmm);
                return -EINVAL;
        }

        return 0;
}

int lov_alloc_memmd(struct lov_stripe_md **lsmp, int stripe_count)
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

        for (i = 0, loi = (*lsmp)->lsm_oinfo; i < stripe_count; i++, loi++){
                loi->loi_dirty_ot = &loi->loi_dirty_ot_inline;
                ot_init(loi->loi_dirty_ot);
        }
        return lsm_size;
}

void lov_free_memmd(struct lov_stripe_md **lsmp)
{
        OBD_FREE(*lsmp, lov_stripe_md_size((*lsmp)->lsm_stripe_count));
        *lsmp = NULL;
}

/* Unpack LOV object metadata from disk storage.  It is packed in LE byte
 * order and is opaque to the networking layer.
 */
int lov_unpackmd(struct lustre_handle *conn, struct lov_stripe_md **lsmp,
                 struct lov_mds_md *lmm, int lmm_bytes)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_stripe_md *lsm;
        struct lov_oinfo *loi;
        int ost_count;
        int ost_offset;
        int stripe_count;
        int lsm_size;
        int i;
        ENTRY;

        /* If passed an MDS struct use values from there, otherwise defaults */
        if (lmm) {
                i = lov_verify_lmm(lmm, lmm_bytes, &ost_count, &stripe_count,
                                   &ost_offset);
                if (i)
                        RETURN(i);
        } else {
                ost_count = 0;
                stripe_count = lov_get_stripecnt(lov, 0);
                ost_offset = 0;
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

        lsm_size = lov_alloc_memmd(lsmp, stripe_count);
        if (lsm_size < 0)
                RETURN(lsm_size);

        /* If we are passed a pointer but nothing to unpack, we only alloc */
        if (!lmm)
                RETURN(lsm_size);

        lsm = *lsmp;
        lsm->lsm_object_id = le64_to_cpu(lmm->lmm_object_id);
        lsm->lsm_stripe_size = le32_to_cpu(lmm->lmm_stripe_size);
        lsm->lsm_stripe_offset = ost_offset;

        for (i = 0, loi = lsm->lsm_oinfo; i < ost_count; i++, ost_offset++) {
                ost_offset %= ost_count;

                if (!lmm->lmm_objects[ost_offset].l_object_id)
                        continue;

                /* XXX LOV STACKING call down to osc_unpackmd() */
                loi->loi_id =
                        le64_to_cpu(lmm->lmm_objects[ost_offset].l_object_id);
                loi->loi_ost_idx = ost_offset;
                loi++;
        }

        if (loi - lsm->lsm_oinfo != stripe_count) {
                CERROR("missing objects in lmm struct\n");
                lov_dump_lmm(D_WARNING, lmm);
                lov_free_memmd(lsmp);
                RETURN(-EINVAL);
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
int lov_setstripe(struct lustre_handle *conn, struct lov_stripe_md **lsmp,
                  struct lov_mds_md *lmmu)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_mds_md lmm;
        int stripe_count;
        int rc;
        ENTRY;

        rc = copy_from_user(&lmm, lmmu, sizeof(lmm));
        if (rc)
                RETURN(-EFAULT);

        /* Bug 1185 FIXME: struct lov_mds_md is little-endian everywhere else */

        if (lmm.lmm_magic != LOV_MAGIC) {
                CERROR("bad userland LOV MAGIC: %#08x != %#08x\n",
                       lmm.lmm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }
#if 0   /* the stripe_count/offset is "advisory", and it gets fixed later */
        if (lmm.lmm_stripe_count > lov->desc.ld_tgt_count &&
            lmm.lmm_stripe_count != 0xffffffff) {
                CERROR("stripe count %u more than OST count %d\n",
                       lmm.lmm_stripe_count, lov->desc.ld_tgt_count);
                RETURN(-EINVAL);
        }
        if (lmm.lmm_stripe_offset >= lov->desc.ld_tgt_count &&
            lmm.lmm_stripe_offset != 0xffffffff) {
                CERROR("stripe offset %u more than max OST index %d\n",
                       lmm.lmm_stripe_offset, lov->desc.ld_tgt_count);
                RETURN(-EINVAL);
        }
#endif
        if (lmm.lmm_stripe_size & (PAGE_SIZE - 1)) {
                CERROR("stripe size %u not multiple of %lu\n",
                       lmm.lmm_stripe_size, PAGE_SIZE);
                RETURN(-EINVAL);
        }
        stripe_count = lov_get_stripecnt(lov, lmm.lmm_stripe_count);

        if ((__u64)lmm.lmm_stripe_size * stripe_count > ~0UL) {
                CERROR("stripe width %ux%u > %lu on 32-bit system\n",
                       lmm.lmm_stripe_size, (int)lmm.lmm_stripe_count, ~0UL);
                RETURN(-EINVAL);
        }

        rc = lov_alloc_memmd(lsmp, stripe_count);

        if (rc < 0)
                RETURN(rc);

        (*lsmp)->lsm_stripe_offset = lmm.lmm_stripe_offset;
        (*lsmp)->lsm_stripe_size = lmm.lmm_stripe_size;

        RETURN(0);
}

/* Retrieve object striping information.
 *
 * @lmmu is a pointer to an in-core struct with lmm_ost_count indicating
 * the maximum number of OST indices which will fit in the user buffer.
 * lmm_magic must be LOV_MAGIC.
 */
int lov_getstripe(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                  struct lov_mds_md *lmmu)
{
        struct lov_mds_md lmm, *lmmk = NULL;
        int rc, lmm_size;
        ENTRY;

        if (!lsm)
                RETURN(-ENODATA);

        rc = copy_from_user(&lmm, lmmu, sizeof(lmm));
        if (rc)
                RETURN(-EFAULT);

        if (lmm.lmm_magic != LOV_MAGIC)
                RETURN(-EINVAL);

        rc = lov_packmd(conn, &lmmk, lsm);
        if (rc < 0)
                RETURN(rc);
        /* Bug 1185 FIXME: convert lmmk to big-endian before copy to userspace */
        lmm_size = rc;
        rc = 0;

        /* User wasn't expecting this many OST entries */
        if (lmm.lmm_ost_count < lmmk->lmm_ost_count)
                rc = -EOVERFLOW;
        else if (copy_to_user(lmmu, lmmk, lmm_size))
                rc = -EFAULT;

        obd_free_diskmd (conn, &lmmk);

        RETURN(rc);
}
