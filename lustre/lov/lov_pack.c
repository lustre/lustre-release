/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc. <adilger@clusterfs.com>
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

#include <linux/lustre_net.h>
#include <linux/obd.h>
#include <linux/obd_lov.h>
#include <linux/obd_support.h>

/* lov_packdesc() is in mds/mds_lov.c */

void lov_unpackdesc(struct lov_desc *ld)
{
        ld->ld_tgt_count = NTOH__u32(ld->ld_tgt_count);
        ld->ld_default_stripe_count = HTON__u32(ld->ld_default_stripe_count);
        ld->ld_default_stripe_size = HTON__u32(ld->ld_default_stripe_size);
        ld->ld_pattern = HTON__u32(ld->ld_pattern);
}

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

        if (lsm)
                stripe_count = lsm->lsm_stripe_count;

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
        lmm->lmm_stripe_size = (lsm->lsm_stripe_size);
        lmm->lmm_stripe_pattern = (lsm->lsm_stripe_pattern);
        lmm->lmm_stripe_offset = (lsm->lsm_stripe_offset);
        lmm->lmm_ost_count = (lov->desc.ld_tgt_count);

        /* Only fill in the object ids which we are actually using.
         * Assumes lmm_objects is otherwise zero-filled. */
        for (i = 0, loi = lsm->lsm_oinfo; i < stripe_count; i++, loi++)
                /* XXX call down to osc_packmd() to do the packing */
                lmm->lmm_objects[loi->loi_ost_idx].l_object_id = (loi->loi_id);

        RETURN(lmm_size);
}

int lov_unpackmd(struct lustre_handle *conn, struct lov_stripe_md **lsmp,
                 struct lov_mds_md *lmm)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_stripe_md *lsm;
        struct lov_oinfo *loi;
        int ost_count = lov->desc.ld_active_tgt_count;
        int ost_offset = 0;
        int stripe_count = 0;
        int lsm_size;
        int i;
        ENTRY;

        if (lmm)
                /* endianness */
                stripe_count = (lmm->lmm_stripe_count);

        if (!stripe_count)
                stripe_count = lov->desc.ld_default_stripe_count;
        if (!stripe_count || stripe_count > ost_count)
                stripe_count = ost_count;

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
        lsm->lsm_stripe_pattern = (lmm->lmm_stripe_pattern);

        for (i = 0, loi = lsm->lsm_oinfo; i < ost_count; i++, ost_offset++) {
                ost_offset %= ost_count;

                if (!lmm->lmm_objects[ost_offset].l_object_id)
                        continue;

                LASSERT(loi - lsm->lsm_oinfo < stripe_count);
                /* XXX LOV STACKING call down to osc_unpackmd() */
                loi->loi_id = (lmm->lmm_objects[ost_offset].l_object_id);
                loi->loi_ost_idx = ost_offset;
                loi++;
        }

        RETURN(lsm_size);
}
