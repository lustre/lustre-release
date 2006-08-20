/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite I/O page cache routines for the 2.5/2.6 kernel version
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
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
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

static int ll_writepage_26(struct page *page, struct writeback_control *wbc)
{
        return ll_writepage(page);
}

/* It is safe to not check anything in invalidatepage/releasepage below
   because they are run with page locked and all our io is happening with
   locked page too */
static int ll_invalidatepage(struct page *page, unsigned long offset)
{
        if (offset)
                return 0;
        if (PagePrivate(page))
                ll_removepage(page);
        return 1;
}

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
        unsigned long page_count;

        /* set an arbitrary limit to prevent arithmetic overflow */
        if (size > MAX_DIRECTIO_SIZE) {
                *pages = NULL;
                return -EFBIG;
        }

        page_count = (user_addr + size + PAGE_SIZE - 1) >> PAGE_SHIFT;
        page_count -= user_addr >> PAGE_SHIFT;

        OBD_ALLOC_GFP(*pages, page_count * sizeof(**pages), GFP_KERNEL);
        if (*pages) {
                down_read(&current->mm->mmap_sem);
                result = get_user_pages(current, current->mm, user_addr,
                                        page_count, (rw == READ), 0, *pages,
                                        NULL);
                up_read(&current->mm->mmap_sem);
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

static ssize_t ll_direct_IO_26_seg(int rw, struct file *file,
                                   struct address_space *mapping,
                                   struct inode *inode,
                                   struct lov_stripe_md *lsm,
                                   unsigned long user_addr, size_t size,
                                   loff_t file_offset, struct page **pages,
                                   int page_count)
{
        struct brw_page *pga;
        struct obdo oa;
        int i, rc = 0;
        size_t length;
        ENTRY;

        OBD_ALLOC(pga, sizeof(*pga) * page_count);
        if (!pga)
                RETURN(-ENOMEM);

        for (i = 0, length = size; length > 0;
             length -=pga[i].count, file_offset +=pga[i].count,i++) {/*i last!*/
                pga[i].pg = pages[i];
                pga[i].off = file_offset;
                /* To the end of the page, or the length, whatever is less */
                pga[i].count = min_t(int, PAGE_SIZE -(file_offset & ~PAGE_MASK),
                                     length);
                pga[i].flag = 0;
                if (rw == READ)
                        POISON_PAGE(pages[i], 0x0d);
        }

        ll_inode_fill_obdo(inode, rw, &oa);

        if (rw == WRITE)
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_DIRECT_WRITE, size);
        else
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_DIRECT_READ, size);
        rc = obd_brw_rqset(rw == WRITE ? OBD_BRW_WRITE : OBD_BRW_READ,
                           ll_i2dtexp(inode), &oa, lsm, page_count, pga, NULL);
        if (rc == 0) {
                rc = size;
                if (rw == WRITE) {
                        lov_stripe_lock(lsm);
                        obd_adjust_kms(ll_i2dtexp(inode), lsm, file_offset, 0);
                        lov_stripe_unlock(lsm);
                }
        }

        OBD_FREE(pga, sizeof(*pga) * page_count);
        RETURN(rc);
}

static ssize_t ll_direct_IO_26(int rw, struct kiocb *iocb,
                               const struct iovec *iov, loff_t file_offset,
                               unsigned long nr_segs)
{
        struct file *file = iocb->ki_filp;
        ssize_t count = iov_length(iov, nr_segs), tot_bytes = 0;
        struct ll_inode_info *lli = ll_i2info(file->f_mapping->host);
        unsigned long seg = 0;
        ENTRY;

        if (!lli->lli_smd || !lli->lli_smd->lsm_object_id)
                RETURN(-EBADF);

        /* FIXME: io smaller than PAGE_SIZE is broken on ia64 ??? */
        if ((file_offset & (PAGE_SIZE - 1)) || (count & (PAGE_SIZE - 1)))
                RETURN(-EINVAL);

        while ((seg < nr_segs) && (tot_bytes >= 0)) {
                const struct iovec *vec = &iov[seg++];
                unsigned long user_addr = (unsigned long)vec->iov_base;
                size_t size = vec->iov_len;
                struct page **pages;
                int page_count;
                ssize_t result;

                page_count = ll_get_user_pages(rw, user_addr, size, &pages);
                if (page_count < 0) {
                        ll_free_user_pages(pages, 0, 0);
                        if (tot_bytes > 0)
                                break;
                        return page_count;
                }

                result = ll_direct_IO_26_seg(rw, file, file->f_mapping,
                                             file->f_mapping->host,
                                             lli->lli_smd, user_addr, size,
                                             file_offset, pages, page_count);
                ll_free_user_pages(pages, page_count, rw == READ);

                if (result <= 0) {
                        if (tot_bytes > 0)
                                break;
                        return result;
                }

                tot_bytes += result;
                file_offset += result;
                if (result < size)
                        break;
        }
        return tot_bytes;
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
