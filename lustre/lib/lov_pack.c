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
#include <linux/obd_support.h>

void lov_packdesc(struct lov_desc *ld)
{
        ld->ld_tgt_count = HTON__u32(ld->ld_tgt_count);
        ld->ld_default_stripe_count = HTON__u32(ld->ld_default_stripe_count);
        ld->ld_default_stripe_size = HTON__u32(ld->ld_default_stripe_size);
        ld->ld_pattern = HTON__u32(ld->ld_pattern);
}

void lov_unpackdesc(struct lov_desc *ld)
{
        ld->ld_tgt_count = NTOH__u32(ld->ld_tgt_count);
        ld->ld_default_stripe_count = HTON__u32(ld->ld_default_stripe_count);
        ld->ld_default_stripe_size = HTON__u32(ld->ld_default_stripe_size);
        ld->ld_pattern = HTON__u32(ld->ld_pattern);
}

void lov_packmd(struct lov_mds_md *lmm, struct lov_stripe_md *lsm)
{
        struct lov_oinfo *loi;
        int i;

        /* XXX endianness */
        lmm->lmm_magic = (lsm->lsm_magic);
        lmm->lmm_easize = (lsm->lsm_mds_easize);
        lmm->lmm_object_id = (lsm->lsm_object_id);
        lmm->lmm_stripe_size = (lsm->lsm_stripe_size);
        lmm->lmm_stripe_pattern = (lsm->lsm_stripe_pattern);
        lmm->lmm_ost_count = (lsm->lsm_ost_count);
        lmm->lmm_stripe_count = (lsm->lsm_stripe_count);
        lmm->lmm_stripe_offset = (lsm->lsm_stripe_offset);

        /* Only fill in the object ids which we are actually using.
         * Assumes lmd_objects is otherwise zero-filled. */
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                lmm->lmm_objects[loi->loi_ost_idx].l_object_id =
                        (loi->loi_id);
        }
}

void lov_unpackmd(struct lov_stripe_md *lsm, struct lov_mds_md *lmm)
{
        struct lov_oinfo *loi;
        int ost_count, ost_offset;
        int i;

        /* XXX endianness */
        lsm->lsm_magic = (lmm->lmm_magic);
        lsm->lsm_mds_easize = (lmm->lmm_easize);
        lsm->lsm_object_id = (lmm->lmm_object_id);
        lsm->lsm_stripe_size = (lmm->lmm_stripe_size);
        lsm->lsm_stripe_pattern = (lmm->lmm_stripe_pattern);
        lsm->lsm_ost_count = (lmm->lmm_ost_count);
        lsm->lsm_stripe_count = (lmm->lmm_stripe_count);
        lsm->lsm_stripe_offset = (lmm->lmm_stripe_offset);

        ost_count = lsm->lsm_ost_count;
        ost_offset = lsm->lsm_stripe_offset;

        for (i = 0, loi = lsm->lsm_oinfo; i < ost_count; i++, ost_offset++) {
                ost_offset %= ost_count;

                if (!lmm->lmm_objects[ost_offset].l_object_id)
                        continue;

                LASSERT(loi - lsm->lsm_oinfo < lsm->lsm_stripe_count);
                loi->loi_id = (lmm->lmm_objects[ost_offset].l_object_id);
                loi->loi_ost_idx = ost_offset;
                loi->loi_size = 0;         /* set by LOV later */
                loi++;
        }
}
