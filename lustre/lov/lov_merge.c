/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LOV

#ifdef __KERNEL__
#include <asm/div64.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/obd_lov.h>

#include "lov_internal.h"

/* Merge rss if kms == 0
 *
 * Even when merging RSS, we will take the KMS value if it's larger.
 * This prevents getattr from stomping on dirty cached pages which
 * extend the file size. */
__u64 lov_merge_size(struct lov_stripe_md *lsm, int kms)
{
        struct lov_oinfo *loi;
        __u64 size = 0;
        int i;

        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++) {
                obd_size lov_size, tmpsize;

                tmpsize = loi->loi_kms;
                if (kms == 0 && loi->loi_rss > tmpsize)
                        tmpsize = loi->loi_rss;

                lov_size = lov_stripe_size(lsm, tmpsize, i);
                if (lov_size > size)
                        size = lov_size;
        }

        return size;
}
EXPORT_SYMBOL(lov_merge_size);

/* Merge blocks */
__u64 lov_merge_blocks(struct lov_stripe_md *lsm)
{
        struct lov_oinfo *loi;
        __u64 blocks = 0;
        int i;

        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++, loi++)
                blocks += loi->loi_blocks;
        return blocks;
}
EXPORT_SYMBOL(lov_merge_blocks);

__u64 lov_merge_mtime(struct lov_stripe_md *lsm, __u64 current_time)
{
        struct lov_oinfo *loi;
        int i;

        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++, loi++)
                if (loi->loi_mtime > current_time)
                        current_time = loi->loi_mtime;
        return current_time;
}
EXPORT_SYMBOL(lov_merge_mtime);

/* Must be called with the inode's lli_size_sem held. */
int lov_adjust_kms(struct obd_export *exp, struct lov_stripe_md *lsm,
                   obd_off size, int shrink)
{
        struct lov_oinfo *loi;
        int stripe = 0;
        __u64 kms;
        ENTRY;

        if (shrink) {
                struct lov_oinfo *loi;
                for (loi = lsm->lsm_oinfo; stripe < lsm->lsm_stripe_count;
                     stripe++, loi++) {
                        kms = lov_size_to_stripe(lsm, size, stripe);
                        loi->loi_kms = loi->loi_rss = kms;
                        CDEBUG(D_INODE,
                               "stripe %d KMS %sing "LPU64"->"LPU64"\n",
                               stripe, kms > loi->loi_kms ? "increas":"shrink",
                               loi->loi_kms, kms);
                }
                RETURN(0);
        }

        if (size > 0)
                stripe = lov_stripe_number(lsm, size - 1);
        kms = lov_size_to_stripe(lsm, size, stripe);
        loi = &(lsm->lsm_oinfo[stripe]);

        CDEBUG(D_INODE, "stripe %d KMS %sincreasing "LPU64"->"LPU64"\n",
               stripe, kms > loi->loi_kms ? "" : "not ", loi->loi_kms, kms);
        if (kms > loi->loi_kms)
                loi->loi_kms = kms;

        RETURN(0);
}

void lov_merge_attrs(struct obdo *tgt, struct obdo *src, obd_flag valid,
                     struct lov_stripe_md *lsm, int stripeno, int *set)
{
        valid &= src->o_valid;

        if (*set) {
                if (valid & OBD_MD_FLSIZE) {
                        /* this handles sparse files properly */
                        obd_size lov_size;

                        lov_size = lov_stripe_size(lsm, src->o_size, stripeno);
                        if (lov_size > tgt->o_size)
                                tgt->o_size = lov_size;
                }
                if (valid & OBD_MD_FLBLOCKS)
                        tgt->o_blocks += src->o_blocks;
                if (valid & OBD_MD_FLBLKSZ)
                        tgt->o_blksize += src->o_blksize;
                if (valid & OBD_MD_FLCTIME && tgt->o_ctime < src->o_ctime)
                        tgt->o_ctime = src->o_ctime;
                if (valid & OBD_MD_FLMTIME && tgt->o_mtime < src->o_mtime)
                        tgt->o_mtime = src->o_mtime;
        } else {
                memcpy(tgt, src, sizeof(*tgt));
                tgt->o_id = lsm->lsm_object_id;
                if (valid & OBD_MD_FLSIZE)
                        tgt->o_size = lov_stripe_size(lsm,src->o_size,stripeno);
                *set = 1;
        }
}
