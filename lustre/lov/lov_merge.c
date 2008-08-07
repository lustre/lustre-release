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
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LOV

#ifdef __KERNEL__
#include <libcfs/libcfs.h>
#else
#include <liblustre.h>
#endif

#include <obd_class.h>
#include <obd_lov.h>

#include "lov_internal.h"

/* Merge the lock value block(&lvb) attributes from each of the stripes in a
 * file into a single lvb. It is expected that the caller initializes the
 * current atime, mtime, ctime to avoid regressing a more uptodate time on
 * the local client.
 *
 * If @kms_only is set then we do not consider the recently seen size (rss)
 * when updating the known minimum size (kms).  Even when merging RSS, we will
 * take the KMS value if it's larger.  This prevents getattr from stomping on
 * dirty cached pages which extend the file size. */
int lov_merge_lvb(struct obd_export *exp, struct lov_stripe_md *lsm,
                  struct ost_lvb *lvb, int kms_only)
{
        __u64 size = 0;
        __u64 blocks = 0;
        __u64 current_mtime = lvb->lvb_mtime;
        __u64 current_atime = lvb->lvb_atime;
        __u64 current_ctime = lvb->lvb_ctime;
        int i;
        int rc = 0;

        LASSERT_SPIN_LOCKED(&lsm->lsm_lock);
#ifdef __KERNEL__
        LASSERT(lsm->lsm_lock_owner == cfs_curproc_pid());
#endif

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                struct lov_oinfo *loi = lsm->lsm_oinfo[i];
                obd_size lov_size, tmpsize;

                if (OST_LVB_IS_ERR(loi->loi_lvb.lvb_blocks)) {
                        rc = OST_LVB_GET_ERR(loi->loi_lvb.lvb_blocks);
                        continue;
                }

                tmpsize = loi->loi_kms;
                if (kms_only == 0 && loi->loi_lvb.lvb_size > tmpsize)
                        tmpsize = loi->loi_lvb.lvb_size;

                lov_size = lov_stripe_size(lsm, tmpsize, i);
                if (lov_size > size)
                        size = lov_size;
                /* merge blocks, mtime, atime */
                blocks += loi->loi_lvb.lvb_blocks;
                if (loi->loi_lvb.lvb_atime > current_atime)
                        current_atime = loi->loi_lvb.lvb_atime;

                /* mtime is always updated with ctime, but can be set in past.
                   As write and utime(2) may happen within 1 second, and utime's
                   mtime has a priority over write's one, leave mtime from mds 
                   for the same ctimes. */
                if (loi->loi_lvb.lvb_ctime > current_ctime) {
                        current_ctime = loi->loi_lvb.lvb_ctime;
                        current_mtime = loi->loi_lvb.lvb_mtime;
                }
        }

        lvb->lvb_size = size;
        lvb->lvb_blocks = blocks;
        lvb->lvb_mtime = current_mtime;
        lvb->lvb_atime = current_atime;
        lvb->lvb_ctime = current_ctime;
        RETURN(rc);
}

/* Must be called under the lov_stripe_lock() */
int lov_adjust_kms(struct obd_export *exp, struct lov_stripe_md *lsm,
                   obd_off size, int shrink)
{
        struct lov_oinfo *loi;
        int stripe = 0;
        __u64 kms;
        ENTRY;

        LASSERT_SPIN_LOCKED(&lsm->lsm_lock);
#ifdef __KERNEL__
        LASSERT(lsm->lsm_lock_owner == cfs_curproc_pid());
#endif

        if (shrink) {
                for (; stripe < lsm->lsm_stripe_count; stripe++) {
                        struct lov_oinfo *loi = lsm->lsm_oinfo[stripe];
                        kms = lov_size_to_stripe(lsm, size, stripe);
                        CDEBUG(D_INODE,
                               "stripe %d KMS %sing "LPU64"->"LPU64"\n",
                               stripe, kms > loi->loi_kms ? "increas":"shrink",
                               loi->loi_kms, kms);
                        loi->loi_kms = loi->loi_lvb.lvb_size = kms;
                }
                RETURN(0);
        }

        if (size > 0)
                stripe = lov_stripe_number(lsm, size - 1);
        kms = lov_size_to_stripe(lsm, size, stripe);
        loi = lsm->lsm_oinfo[stripe];

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
                /* Only mtime from OSTs are merged here, as they cannot be set
                   in past (only MDS's mtime can) do not look at ctime. */
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
