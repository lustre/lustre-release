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

/* lov_packdesc() is in mds/mds_lov.c */
void lov_unpackdesc(struct lov_desc *ld)
{
        ld->ld_tgt_count = NTOH__u32(ld->ld_tgt_count);
        ld->ld_default_stripe_count = HTON__u32(ld->ld_default_stripe_count);
        ld->ld_default_stripe_size = HTON__u32(ld->ld_default_stripe_size);
        ld->ld_pattern = HTON__u32(ld->ld_pattern);
}

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

/* Pack LOV object metadata for shipment to the MDS.
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
                /* endianness */
                ost_count = ((*lmmp)->lmm_ost_count);
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

        lmm->lmm_stripe_count = (stripe_count);
        if (!lsm)
                RETURN(lmm_size);

        /* XXX endianness */
        lmm->lmm_magic = (lsm->lsm_magic);
        lmm->lmm_object_id = (lsm->lsm_object_id);
        LASSERT(lsm->lsm_object_id);
        lmm->lmm_stripe_size = (lsm->lsm_stripe_size);
        lmm->lmm_stripe_offset = (lsm->lsm_stripe_offset);
        lmm->lmm_ost_count = (ost_count);

        /* Only fill in the object ids which we are actually using.
         * Assumes lmm_objects is otherwise zero-filled. */
        for (i = 0, loi = lsm->lsm_oinfo; i < stripe_count; i++, loi++) {
                /* XXX call down to osc_packmd() to do the packing */
                LASSERT(loi->loi_id);
                lmm->lmm_objects[loi->loi_ost_idx].l_object_id = (loi->loi_id);
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

int lov_unpackmd(struct lustre_handle *conn, struct lov_stripe_md **lsmp,
                 struct lov_mds_md *lmm)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_stripe_md *lsm;
        struct lov_oinfo *loi;
        int ost_count;
        int ost_offset = 0;
        int stripe_count;
        int lsm_size;
        int i;
        ENTRY;

        if (lmm) {
                /* endianness */
                if (lmm->lmm_magic != LOV_MAGIC) {
                        CERROR("bad wire LOV MAGIC: %#08x != %#08x\n",
                               lmm->lmm_magic, LOV_MAGIC);
                        RETURN(-EINVAL);
                }
                stripe_count = (lmm->lmm_stripe_count);
                LASSERT(stripe_count);
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

        lsm->lsm_stripe_count = stripe_count;
        if (!lmm)
                RETURN(lsm_size);

        /* XXX endianness */
        ost_offset = lsm->lsm_stripe_offset = (lmm->lmm_stripe_offset);
        lsm->lsm_magic = (lmm->lmm_magic);
        lsm->lsm_object_id = (lmm->lmm_object_id);
        lsm->lsm_stripe_size = (lmm->lmm_stripe_size);

        ost_count = (lmm->lmm_ost_count);

        LMM_ASSERT(lsm->lsm_object_id);
        LMM_ASSERT(ost_count);

        for (i = 0, loi = lsm->lsm_oinfo; i < ost_count; i++, ost_offset++) {
                ost_offset %= ost_count;

                if (!lmm->lmm_objects[ost_offset].l_object_id)
                        continue;

                LMM_ASSERT(loi - lsm->lsm_oinfo < stripe_count);
                /* XXX LOV STACKING call down to osc_unpackmd() */
                loi->loi_id = (lmm->lmm_objects[ost_offset].l_object_id);
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

        if (lmm.lmm_magic != LOV_MAGIC) {
                CERROR("bad wire LOV MAGIC: %#08x != %#08x\n",
                       lmm.lmm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }
        if (lmm.lmm_stripe_count > lov->desc.ld_tgt_count) {
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
        if (lmm.lmm_stripe_size & (PAGE_SIZE - 1)) {
                CERROR("stripe size %u not multiple of %lu\n",
                       lmm.lmm_stripe_size, PAGE_SIZE);
                RETURN(-EINVAL);
        }
        if ((__u64)lmm.lmm_stripe_size * lmm.lmm_stripe_count > ~0UL) {
                CERROR("stripe width %ux%u > %lu on 32-bit system\n",
                       lmm.lmm_stripe_size, (int)lmm.lmm_stripe_count, ~0UL);
                RETURN(-EINVAL);
        }

        stripe_count = lov_get_stripecnt(lov, lmm.lmm_stripe_count);

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
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_mds_md lmm, *lmmk = NULL;
        int ost_count, rc, lmm_size;
        ENTRY;

        if (!lsm)
                RETURN(-ENODATA);

        rc = copy_from_user(&lmm, lmmu, sizeof(lmm));
        if (rc)
                RETURN(-EFAULT);

        if (lmm.lmm_magic != LOV_MAGIC)
                RETURN(-EINVAL);

        ost_count = lov->desc.ld_tgt_count;

        /* XXX we _could_ check if indices > user lmm_ost_count are zero */
        if (lmm.lmm_ost_count < ost_count)
                RETURN(-EOVERFLOW);

        rc = lov_packmd(conn, &lmmk, lsm);
        if (rc < 0)
                RETURN(rc);

        lmm_size = rc;
        rc = 0;

        if (lmm_size && copy_to_user(lmmu, lmmk, lmm_size))
                rc = -EFAULT;

        obd_free_wiremd(conn, &lmmk);

        RETURN(rc);
}
