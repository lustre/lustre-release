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

static int lov_get_stripecnt(struct lov_obd *lov, int stripe_count)
{
        if (!stripe_count)
                stripe_count = lov->desc.ld_default_stripe_count;
        if (!stripe_count || stripe_count > lov->desc.ld_active_tgt_count)
                stripe_count = lov->desc.ld_active_tgt_count;

        return stripe_count;
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
        int ost_count = 0;
        int ost_offset = 0;
        int stripe_count;
        int lsm_size;
        int i;
        ENTRY;

        if (lmm) {
                if (lmm_bytes < sizeof (*lmm)) {
                        CERROR ("lov_mds_md too small: %d, need at least %d\n",
                                lmm_bytes, sizeof (*lmm));
                        RETURN (-EINVAL);
                }
                if (le32_to_cpu (lmm->lmm_magic) != LOV_MAGIC) {
                        CERROR("bad disk LOV MAGIC: %#08x != %#08x\n",
                               le32_to_cpu (lmm->lmm_magic), LOV_MAGIC);
                        RETURN(-EINVAL);
                }
                
                ost_count = le16_to_cpu (lmm->lmm_ost_count);
                stripe_count = le16_to_cpu (lmm->lmm_stripe_count);

                if (ost_count == 0 || stripe_count == 0) {
                        CERROR ("zero ost %d or stripe %d count\n",
                                ost_count, stripe_count);
                        RETURN (-EINVAL);
                }

                if (lmm_bytes < lov_mds_md_size (ost_count)) {
                        CERROR ("lov_mds_md too small: %d, need %d\n",
                                lmm_bytes, lov_mds_md_size (ost_count));
                        RETURN (-EINVAL);
                }
        } else
                stripe_count = lov_get_stripecnt(lov, 0);

        /* XXX LOV STACKING call into osc for sizes */
        lsm_size = lov_stripe_md_size(stripe_count);

        if (!lsmp)
                RETURN(lsm_size);

        if (*lsmp && !lmm) {
                stripe_count = (*lsmp)->lsm_stripe_count;
                OBD_FREE(*lsmp, lov_stripe_md_size(stripe_count));
                *lsmp = NULL;
                RETURN(0);
        }

        if (!*lsmp) {
                OBD_ALLOC(*lsmp, lsm_size);
                if (!*lsmp)
                        RETURN(-ENOMEM);
        }

        lsm = *lsmp;
        lsm->lsm_magic = LOV_MAGIC;
        lsm->lsm_stripe_count = stripe_count;

        if (!lmm)
                RETURN(lsm_size);

        lsm->lsm_object_id = le64_to_cpu (lmm->lmm_object_id);
        lsm->lsm_stripe_size = le32_to_cpu (lmm->lmm_stripe_size);
        ost_offset = lsm->lsm_stripe_offset = le32_to_cpu (lmm->lmm_stripe_offset);

        LMM_ASSERT(lsm->lsm_object_id);
        LMM_ASSERT(ost_count);

        for (i = 0, loi = lsm->lsm_oinfo; i < ost_count; i++, ost_offset++) {
                ost_offset %= ost_count;

                if (!lmm->lmm_objects[ost_offset].l_object_id)
                        continue;

                LMM_ASSERT(loi - lsm->lsm_oinfo < stripe_count);
                /* XXX LOV STACKING call down to osc_unpackmd() */
                loi->loi_id = le64_to_cpu (lmm->lmm_objects[ost_offset].l_object_id);
                loi->loi_ost_idx = ost_offset;
                loi++;
        }
        LMM_ASSERT(loi - lsm->lsm_oinfo > 0);
        LMM_ASSERT(loi - lsm->lsm_oinfo == stripe_count);

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
        struct lov_stripe_md *lsm;
        int stripe_count;
        int rc;
        ENTRY;

        rc = copy_from_user(&lmm, lmmu, sizeof(lmm));
        if (rc)
                RETURN(-EFAULT);

#warning FIXME: struct lov_mds_md is little-endian everywhere else

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

        /* XXX LOV STACKING call into osc for sizes */
        OBD_ALLOC(lsm, lov_stripe_md_size(stripe_count));
        if (!lsm)
                RETURN(-ENOMEM);

        lsm->lsm_magic = LOV_MAGIC;
        lsm->lsm_stripe_count = stripe_count;
        lsm->lsm_stripe_offset = lmm.lmm_stripe_offset;
        lsm->lsm_stripe_size = lmm.lmm_stripe_size;

        *lsmp = lsm;

        RETURN(rc);
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
#if __BIG_ENDIAN
#error FIXME: convert lmmk to big-endian before copy to userspace
#endif
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
