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
 * lustre/llite/rw24.c
 *
 * Lustre Lite I/O page cache for the 2.4 kernel version
 */

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/iobuf.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <lustre_lite.h>
#include "llite_internal.h"
#include <linux/lustre_compat25.h>

static int ll_direct_IO_24(int rw,
#ifdef HAVE_DIO_FILE
                           struct file *file,
#else
                           struct inode *inode,
#endif
                           struct kiobuf *iobuf, unsigned long blocknr,
                           int blocksize)
{
#ifdef HAVE_DIO_FILE
        struct inode *inode = file->f_dentry->d_inode;
#endif
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct brw_page *pga;
        struct obdo oa;
        int length, i, flags, rc = 0;
        loff_t offset, offset_orig;
        ENTRY;

        if (!lsm || !lsm->lsm_object_id)
                RETURN(-EBADF);

        offset = ((obd_off)blocknr << inode->i_blkbits);
        offset_orig = offset;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), size="LPSZ
               ", offset=%lld=%llx, pages %u\n",
               inode->i_ino, inode->i_generation, inode, iobuf->length,
               offset, offset, iobuf->nr_pages);

        /* FIXME: io smaller than CFS_PAGE_SIZE is broken on ia64 */
        if ((iobuf->offset & (~CFS_PAGE_MASK)) ||
            (iobuf->length & (~CFS_PAGE_MASK)))
                RETURN(-EINVAL);

        OBD_ALLOC(pga, sizeof(*pga) * iobuf->nr_pages);
        if (!pga)
                RETURN(-ENOMEM);

        flags = 0 /* | OBD_BRW_DIRECTIO */;
        length = iobuf->length;
        rw = rw ? OBD_BRW_WRITE : OBD_BRW_READ;

        for (i = 0, length = iobuf->length; length > 0;
             length -= pga[i].count, offset += pga[i].count, i++) { /*i last!*/
                pga[i].pg = iobuf->maplist[i];
                pga[i].off = offset;
                /* To the end of the page, or the length, whatever is less */
                pga[i].count = min_t(int, CFS_PAGE_SIZE - (offset & ~CFS_PAGE_MASK),
                                     length);
                pga[i].flag = flags;
                if (rw == OBD_BRW_READ)
                        POISON_PAGE(iobuf->maplist[i], 0x0d);
        }

        ll_inode_fill_obdo(inode, rw, &oa);

        if (rw == OBD_BRW_WRITE)
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_DIRECT_WRITE, iobuf->length);
        else
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_DIRECT_READ, iobuf->length);
        rc = obd_brw_rqset(rw, ll_i2obdexp(inode), &oa, lsm, iobuf->nr_pages,
                           pga, NULL);
        if ((rc > 0) && (rw == OBD_BRW_WRITE)) {
                lov_stripe_lock(lsm);
                obd_adjust_kms(ll_i2obdexp(inode), lsm, offset_orig + rc, 0);
                lov_stripe_unlock(lsm);
        }

        OBD_FREE(pga, sizeof(*pga) * iobuf->nr_pages);
        RETURN(rc);
}

#ifdef KERNEL_HAS_AS_MAX_READAHEAD
static int ll_max_readahead(struct inode *inode)
{
        return 0;
}
#endif

struct address_space_operations ll_aops = {
        .readpage       = ll_readpage,
        .direct_IO      = ll_direct_IO_24,
        .writepage      = ll_writepage,
        .prepare_write  = ll_prepare_write,
        .commit_write   = ll_commit_write,
        .removepage     = ll_removepage,
        .sync_page      = NULL,
        .bmap           = NULL,
#ifdef KERNEL_HAS_AS_MAX_READAHEAD
        .max_readahead  = ll_max_readahead,
#endif
};
