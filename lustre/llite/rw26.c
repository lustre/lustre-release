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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 * lustre/llite/rw26.c
 *
 * Lustre Lite I/O page cache routines for the 2.5/2.6 kernel version
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
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#ifdef HAVE_SEGMENT_H
# include <asm/segment.h>
#endif
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <lustre_lite.h>
#include "llite_internal.h"
#include <linux/lustre_compat25.h>

static int ll_writepage_26(struct page *page, struct writeback_control *wbc)
{
        return ll_writepage(page);
}

/* It is safe to not check anything in invalidatepage/releasepage below
   because they are run with page locked and all our io is happening with
   locked page too */
#ifdef HAVE_INVALIDATEPAGE_RETURN_INT
static int ll_invalidatepage(struct page *page, unsigned long offset)
{
        if (offset)
                return 0;
        if (PagePrivate(page))
                ll_removepage(page);
        return 1;
}
#else
static void ll_invalidatepage(struct page *page, unsigned long offset)
{
        if (offset)
                return;
        if (PagePrivate(page))
                ll_removepage(page);
}
#endif

static int ll_releasepage(struct page *page, gfp_t gfp_mask)
{
        if (PagePrivate(page))
                ll_removepage(page);
        return 1;
}

#define MAX_DIRECTIO_SIZE 2*1024*1024*1024UL

static inline int ll_get_user_pages(int rw, unsigned long user_addr,
                                    size_t size, struct page ***pages)
{
        int result = -ENOMEM;
        int page_count;

        /* set an arbitrary limit to prevent arithmetic overflow */
        if (size > MAX_DIRECTIO_SIZE) {
                *pages = NULL;
                return -EFBIG;
        }

        page_count = ((user_addr + size + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT)-
                      (user_addr >> CFS_PAGE_SHIFT);

        OBD_ALLOC_WAIT(*pages, page_count * sizeof(**pages));
        if (*pages) {
                down_read(&current->mm->mmap_sem);
                result = get_user_pages(current, current->mm, user_addr,
                                        page_count, (rw == READ), 0, *pages,
                                        NULL);
                up_read(&current->mm->mmap_sem);
                if (result < 0)
                        OBD_FREE(*pages, page_count * sizeof(**pages));
        }

        return result;
}

/*  ll_free_user_pages - tear down page struct array
 *  @pages: array of page struct pointers underlying target buffer */
static void ll_free_user_pages(struct page **pages, int npages, int do_dirty)
{
        int i;

        for (i = 0; i < npages; i++) {
                if (do_dirty)
                        set_page_dirty_lock(pages[i]);
                page_cache_release(pages[i]);
        }

        OBD_FREE(pages, npages * sizeof(*pages));
}

static ssize_t ll_direct_IO_26_seg(int rw, struct inode *inode,
                                   struct address_space *mapping,
                                   struct obd_info *oinfo,
                                   struct ptlrpc_request_set *set,
                                   size_t size, loff_t file_offset,
                                   struct page **pages, int page_count)
{
        struct brw_page *pga;
        int i, rc = 0;
        size_t length;
        ENTRY;

        OBD_ALLOC(pga, sizeof(*pga) * page_count);
        if (!pga) {
                CDEBUG(D_VFSTRACE, "sizeof(*pga) = %u page_count = %u\n",
                      (int)sizeof(*pga), page_count);
                RETURN(-ENOMEM);
        }

        for (i = 0, length = size; length > 0;
             length -=pga[i].count, file_offset +=pga[i].count,i++) {/*i last!*/
                pga[i].pg = pages[i];
                pga[i].off = file_offset;
                /* To the end of the page, or the length, whatever is less */
                pga[i].count = min_t(int, CFS_PAGE_SIZE -(file_offset & ~CFS_PAGE_MASK),
                                     length);
                pga[i].flag = OBD_BRW_SYNC;
                if (rw == READ)
                        POISON_PAGE(pages[i], 0x0d);
        }

        rc = obd_brw_async(rw == WRITE ? OBD_BRW_WRITE : OBD_BRW_READ,
                           ll_i2obdexp(inode), oinfo, page_count,
                           pga, NULL, set);
        if (rc == 0)
                rc = size;

        OBD_FREE(pga, sizeof(*pga) * page_count);
        RETURN(rc);
}

/* This is the maximum size of a single O_DIRECT request, based on a 128kB
 * kmalloc limit.  We need to fit all of the brw_page structs, each one
 * representing PAGE_SIZE worth of user data, into a single buffer, and
 * then truncate this to be a full-sized RPC.  This is 22MB for 4kB pages. */
#define MAX_DIO_SIZE ((128 * 1024 / sizeof(struct brw_page) * CFS_PAGE_SIZE) & \
                      ~(PTLRPC_MAX_BRW_SIZE - 1))
static ssize_t ll_direct_IO_26(int rw, struct kiocb *iocb,
                               const struct iovec *iov, loff_t file_offset,
                               unsigned long nr_segs)
{
        struct file *file = iocb->ki_filp;
        struct inode *inode = file->f_mapping->host;
        ssize_t count = iov_length(iov, nr_segs), tot_bytes = 0;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ptlrpc_request_set *set;
        struct obd_info oinfo;
        struct obdo oa;
        unsigned long seg;
        size_t size = MAX_DIO_SIZE;
        ENTRY;

        if (!lli->lli_smd || !lli->lli_smd->lsm_object_id)
                RETURN(-EBADF);

        /* FIXME: io smaller than CFS_PAGE_SIZE is broken on ia64 ??? */
        if ((file_offset & (~CFS_PAGE_MASK)) || (count & ~CFS_PAGE_MASK))
                RETURN(-EINVAL);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), size="LPSZ" (max %lu), "
               "offset=%lld=%llx, pages "LPSZ" (max %lu)\n",
               inode->i_ino, inode->i_generation, inode, count, MAX_DIO_SIZE,
               file_offset, file_offset, count >> CFS_PAGE_SHIFT,
               MAX_DIO_SIZE >> CFS_PAGE_SHIFT);

        if (rw == WRITE)
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_DIRECT_WRITE, count);
        else
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_DIRECT_READ, count);

        /* Check that all user buffers are aligned as well */
        for (seg = 0; seg < nr_segs; seg++) {
                if (((unsigned long)iov[seg].iov_base & ~CFS_PAGE_MASK) ||
                    (iov[seg].iov_len & ~CFS_PAGE_MASK))
                        RETURN(-EINVAL);
        }

        set = ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        ll_inode_fill_obdo(inode, rw == WRITE ? OBD_BRW_WRITE : OBD_BRW_READ, &oa);
        oinfo.oi_oa = &oa;
        oinfo.oi_md = lsm;

        /* need locking between buffered and direct access. and race with 
         *size changing by concurrent truncates and writes. */
        if (rw == READ)
                LOCK_INODE_MUTEX(inode);

        for (seg = 0; seg < nr_segs; seg++) {
                size_t iov_left = iov[seg].iov_len;
                unsigned long user_addr = (unsigned long)iov[seg].iov_base;

                if (rw == READ) {
                        if (file_offset >= inode->i_size)
                                break;
                        if (file_offset + iov_left > inode->i_size)
                                iov_left = inode->i_size - file_offset;
                }

                while (iov_left > 0) {
                        struct page **pages;
                        int page_count;
                        ssize_t result;

                        page_count = ll_get_user_pages(rw, user_addr,
                                                       min(size, iov_left),
                                                       &pages);
                        LASSERT(page_count != 0);
                        if (page_count > 0) {
                                result = ll_direct_IO_26_seg(rw, inode,
                                                             file->f_mapping,
                                                             &oinfo, set,
                                                             min(size,iov_left),
                                                             file_offset, pages,
                                                             page_count);
                                ll_free_user_pages(pages, page_count, rw==READ);
                        } else {
                                result = 0;
                        }
                        if (page_count < 0 || result <= 0) {
                                /* If we can't allocate a large enough buffer
                                 * for the request, shrink it to a smaller
                                 * PAGE_SIZE multiple and try again.
                                 * We should always be able to kmalloc for a
                                 * page worth of page pointers = 4MB on i386. */
                                if ((page_count == -ENOMEM||result == -ENOMEM)&&
                                    size > (CFS_PAGE_SIZE / sizeof(*pages)) *
                                           CFS_PAGE_SIZE) {
                                        size = ((((size / 2) - 1) |
                                                 ~CFS_PAGE_MASK) + 1) &
                                                CFS_PAGE_MASK;
                                        CDEBUG(D_VFSTRACE, "DIO size now %u\n",
                                               (int)size);
                                        continue;
                                }
                                if (tot_bytes > 0)
                                        GOTO(wait_io, tot_bytes);
                                GOTO(out, tot_bytes = page_count < 0 ? page_count : result);
                        }

                        tot_bytes += result;
                        file_offset += result;
                        iov_left -= result;
                        user_addr += result;
                }
        }

        if (tot_bytes > 0) {
                int rc;
        wait_io:
                rc = ptlrpc_set_wait(set);
                if (rc)
                        GOTO(out, tot_bytes = rc);
                if (rw == WRITE) {
                        lov_stripe_lock(lsm);
                        obd_adjust_kms(ll_i2obdexp(inode), lsm, file_offset, 0);
                        lov_stripe_unlock(lsm);
                }
        }
out:
        if (rw == READ)
                UNLOCK_INODE_MUTEX(inode);

        ptlrpc_set_destroy(set);
        RETURN(tot_bytes);
}

struct address_space_operations ll_aops = {
        .readpage       = ll_readpage,
//        .readpages      = ll_readpages,
        .direct_IO      = ll_direct_IO_26,
        .writepage      = ll_writepage_26,
        .writepages     = generic_writepages,
        .set_page_dirty = __set_page_dirty_nobuffers,
        .sync_page      = NULL,
        .prepare_write  = ll_prepare_write,
        .commit_write   = ll_commit_write,
        .invalidatepage = ll_invalidatepage,
        .releasepage    = ll_releasepage,
        .bmap           = NULL
};
