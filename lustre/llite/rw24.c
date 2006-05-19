/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite I/O page cache for the 2.4 kernel version
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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
 */

#include <linux/config.h>
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
#include <asm/segment.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <lustre_mdc.h>
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
        struct ptlrpc_request_set *set;
        struct obdo oa;
        int length, i, flags, rc = 0;
        loff_t offset;
        ENTRY;

        if (!lsm || !lsm->lsm_object_id)
                RETURN(-EBADF);

        /* FIXME: io smaller than PAGE_SIZE is broken on ia64 */
        if ((iobuf->offset & (PAGE_SIZE - 1)) ||
            (iobuf->length & (PAGE_SIZE - 1)))
                RETURN(-EINVAL);

        set = ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC(pga, sizeof(*pga) * iobuf->nr_pages);
        if (!pga) {
                ptlrpc_set_destroy(set);
                RETURN(-ENOMEM);
        }

        flags = 0 /* | OBD_BRW_DIRECTIO */;
        offset = ((obd_off)blocknr << inode->i_blkbits);
        length = iobuf->length;
        rw = rw ? OBD_BRW_WRITE : OBD_BRW_READ;

        for (i = 0, length = iobuf->length; length > 0;
             length -= pga[i].count, offset += pga[i].count, i++) { /*i last!*/
                pga[i].pg = iobuf->maplist[i];
                pga[i].off = offset;
                /* To the end of the page, or the length, whatever is less */
                pga[i].count = min_t(int, PAGE_SIZE - (offset & ~PAGE_MASK),
                                     length);
                pga[i].flag = flags;
                if (rw == OBD_BRW_READ)
                        POISON_PAGE(iobuf->maplist[i], 0x0d);
        }

        ll_inode_fill_obdo(inode, rw, &oa);

        if (rw == OBD_BRW_WRITE)
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_DIRECT_WRITE, iobuf->length);
        else
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_DIRECT_READ, iobuf->length);
        rc = obd_brw_async(rw, ll_i2dtexp(inode), &oa, lsm, iobuf->nr_pages,
                           pga, set, NULL);
        if (rc) {
                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                       "error from obd_brw_async: rc = %d\n", rc);
        } else {
                rc = ptlrpc_set_wait(set);
                if (rc)
                        CERROR("error from callback: rc = %d\n", rc);
        }
        ptlrpc_set_destroy(set);
        if (rc == 0) {
                rc = iobuf->length;
                if (rw == OBD_BRW_WRITE) {
                        lov_stripe_lock(lsm);
                        obd_adjust_kms(ll_i2dtexp(inode), lsm, offset, 0);
                        lov_stripe_unlock(lsm);
                }
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
