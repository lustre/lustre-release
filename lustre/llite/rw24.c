/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite I/O page cache for the 2.4 kernel generation
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

#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>
#include "llite_internal.h"
#include <linux/lustre_compat25.h>

/*
 * we were asked to read a single page but we're going to try and read a batch
 * of pages all at once.  this vaguely simulates client-side read-ahead that
 * is done via ->readpages in 2.5.
 */
static int ll_readpage_24(struct file *file, struct page *first_page)
{
        struct inode *inode = first_page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct page *page = first_page;
        struct list_head *pos;
        struct brw_page *pgs;
        struct obdo *oa;
        unsigned long end_index, extent_end = 0;
        struct ptlrpc_request_set *set;
        int npgs = 0, rc = 0, max_pages;
        ENTRY;

        LASSERT(PageLocked(page));
        LASSERT(!PageUptodate(page));
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),offset="LPX64"\n",
               inode->i_ino, inode->i_generation, inode,
               (((obd_off)page->index) << PAGE_SHIFT));
        LASSERT(atomic_read(&file->f_dentry->d_inode->i_count) > 0);

        if (inode->i_size <= ((obd_off)page->index) << PAGE_SHIFT) {
                CERROR("reading beyond EOF\n");
                memset(kmap(page), 0, PAGE_SIZE);
                kunmap(page);
                SetPageUptodate(page);
                unlock_page(page);
                RETURN(rc);
        }

        /* try to read the file's preferred block size in a one-er */
        end_index = first_page->index +
                (inode->i_blksize >> PAGE_CACHE_SHIFT);
        if (end_index > (inode->i_size >> PAGE_CACHE_SHIFT))
                end_index = inode->i_size >> PAGE_CACHE_SHIFT;

        max_pages = ((end_index - first_page->index) << PAGE_CACHE_SHIFT) >>
                PAGE_SHIFT;
        pgs = kmalloc(max_pages * sizeof(*pgs), GFP_USER);
        if (pgs == NULL)
                RETURN(-ENOMEM);

        /*
         * find how far we're allowed to read under the extent ll_file_read
         * is passing us..
         */
        spin_lock(&lli->lli_read_extent_lock);
        list_for_each(pos, &lli->lli_read_extents) {
                struct ll_read_extent *rextent;
                rextent = list_entry(pos, struct ll_read_extent, re_lli_item);
                if (rextent->re_task != current)
                        continue;

                if (rextent->re_extent.end + PAGE_SIZE < rextent->re_extent.end)
                        /* extent wrapping */
                        extent_end = ~0;
                else {
                        extent_end = (rextent->re_extent.end + PAGE_SIZE)
                                                        << PAGE_CACHE_SHIFT;
                        /* 32bit indexes, 64bit extents.. */
                        if (((u64)extent_end >> PAGE_CACHE_SHIFT) <
                                        rextent->re_extent.end)
                                extent_end = ~0;
                }
                break;
        }
        spin_unlock(&lli->lli_read_extent_lock);

        if (extent_end == 0) {
                static unsigned long next_print;
                if (time_after(jiffies, next_print)) {
                        next_print = jiffies + 30 * HZ;
                        CDEBUG(D_INODE, "mmap readpage - check locks\n");
                }
                end_index = page->index + 1;
        } else if (extent_end < end_index)
                end_index = extent_end;

        /* to balance the find_get_page ref the other pages get that is
         * decrefed on teardown.. */
        page_cache_get(page);
        do {
                unsigned long index ;

                pgs[npgs].pg = page;
                pgs[npgs].off = ((obd_off)page->index) << PAGE_CACHE_SHIFT;
                pgs[npgs].flag = 0;
                pgs[npgs].count = PAGE_SIZE;
                /* XXX Workaround for BA OSTs returning short reads at EOF.
                 * The linux OST will return the full page, zero-filled at the
                 * end, which will just overwrite the data we set here.  Bug
                 * 593 relates to fixing this properly.
                 */
                if (inode->i_size < pgs[npgs].off + PAGE_SIZE) {
                        int count = inode->i_size - pgs[npgs].off;
                        void *addr = kmap(page);
                        pgs[npgs].count = count;
                        //POISON(addr, 0x7c, count);
                        memset(addr + count, 0, PAGE_SIZE - count);
                        kunmap(page);
                }

                npgs++;
                if (npgs == max_pages)
                        break;

                /*
                 * find pages ahead of us that we can read in.
                 * grab_cache_page waits on pages that are locked so
                 * we first try find_get_page, which doesn't.  this stops
                 * the worst case behaviour of racing threads waiting on
                 * each other, but doesn't remove it entirely.
                 */
                for (index = page->index + 1, page = NULL;
                     page == NULL && index < end_index; index++) {

                        /* see if the page already exists and needs updating */
                        page = find_get_page(inode->i_mapping, index);
                        if (page) {
                                if (Page_Uptodate(page) || TryLockPage(page))
                                        goto out_release;
                                if (!page->mapping || Page_Uptodate(page))
                                        goto out_unlock;
                        } else {
                                /* ok, we have to create it.. */
                                page = grab_cache_page(inode->i_mapping, index);
                                if (page == NULL)
                                        continue;
                                if (Page_Uptodate(page))
                                        goto out_unlock;
                        }

                        break;

                out_unlock:
                        unlock_page(page);
                out_release:
                        page_cache_release(page);
                        page = NULL;
                }

        } while (page);

        if ((oa = obdo_alloc()) == NULL) {
                CERROR("ENOMEM allocing obdo\n");
                rc = -ENOMEM;
        } else if ((set = ptlrpc_prep_set()) == NULL) {
                CERROR("ENOMEM allocing request set\n");
                obdo_free(oa);
                rc = -ENOMEM;
        } else {
                struct ll_file_data *fd = file->private_data;

                oa->o_id = lli->lli_smd->lsm_object_id;
                memcpy(obdo_handle(oa), &fd->fd_ost_och.och_fh,
                       sizeof(fd->fd_ost_och.och_fh));
                oa->o_valid = OBD_MD_FLID | OBD_MD_FLHANDLE;
                obdo_from_inode(oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME);

                rc = obd_brw_async(OBD_BRW_READ, ll_i2obdconn(inode), oa,
                                   ll_i2info(inode)->lli_smd, npgs, pgs,
                                   set, NULL);
                if (rc == 0)
                        rc = ptlrpc_set_wait(set);
                ptlrpc_set_destroy(set);
                if (rc == 0)
                        obdo_refresh_inode(inode, oa, oa->o_valid);
                if (rc && rc != -EIO)
                        CERROR("error from obd_brw_async: rc = %d\n", rc);
                obdo_free(oa);
        }

        while (npgs-- > 0) {
                page = pgs[npgs].pg;

                if (rc == 0)
                        SetPageUptodate(page);
                unlock_page(page);
                page_cache_release(page);
        }

        kfree(pgs);
        RETURN(rc);
}

void ll_complete_writepage_24(struct obd_client_page *ocp, int rc)
{
        struct page *page = ocp->ocp_page;

        LASSERT(page->private == (unsigned long)ocp);
        LASSERT(PageLocked(page));

#if 0
        rc = ll_clear_dirty_pages(ll_i2obdconn(inode),
                                  ll_i2info(inode)->lli_smd,
                                  page->index, page->index);
        LASSERT(rc == 0);
#endif
        ll_ocp_free(page);

        unlock_page(page);
}

static int ll_writepage_24(struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct obdo oa;
        struct obd_export *exp;
        struct obd_client_page *ocp;
        int rc;
        ENTRY;

        CDEBUG(D_CACHE, "page %p [lau %d] inode %p\n", page,
               PageLaunder(page), inode);
        LASSERT(PageLocked(page));

        exp = ll_i2obdexp(inode);
        if (exp == NULL)
                RETURN(-EINVAL);

        oa.o_id = ll_i2info(inode)->lli_smd->lsm_object_id;
        oa.o_valid = OBD_MD_FLID;
        obdo_from_inode(&oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                    OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        ocp = ll_ocp_alloc(page);
        if (IS_ERR(ocp)) 
                GOTO(out, rc = PTR_ERR(ocp));

        ocp->ocp_callback = ll_complete_writepage_24;
        ocp->ocp_flag = OBD_BRW_CREATE|OBD_BRW_FROM_GRANT;

        rc = obd_brw_async_ocp(OBD_BRW_WRITE, exp, &oa, 
                               ll_i2info(inode)->lli_smd, ocp,
                               ll_i2sbi(inode)->ll_lc.lc_set, NULL);
        if (rc == 0)
                rc = obd_brw_async_barrier(OBD_BRW_WRITE, exp, 
                                           ll_i2info(inode)->lli_smd,
                                           ll_i2sbi(inode)->ll_lc.lc_set);
out:
        class_export_put(exp);
        RETURN(rc);
}

static int ll_direct_IO_24(int rw, struct inode *inode, struct kiobuf *iobuf,
                           unsigned long blocknr, int blocksize)
{
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

        if ((iobuf->offset & (blocksize - 1)) ||
            (iobuf->length & (blocksize - 1)))
                RETURN(-EINVAL);

        set = ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC(pga, sizeof(*pga) * iobuf->nr_pages);
        if (!pga) {
                ptlrpc_set_destroy(set);
                RETURN(-ENOMEM);
        }

        flags = (rw == WRITE ? OBD_BRW_CREATE : 0) /* | OBD_BRW_DIRECTIO */;
        offset = ((obd_off)blocknr << inode->i_blkbits);
        length = iobuf->length;

        for (i = 0, length = iobuf->length; length > 0;
             length -= pga[i].count, offset += pga[i].count, i++) { /*i last!*/
                pga[i].pg = iobuf->maplist[i];
                pga[i].off = offset;
                /* To the end of the page, or the length, whatever is less */
                pga[i].count = min_t(int, PAGE_SIZE - (offset & ~PAGE_MASK),
                                     length);
                pga[i].flag = flags;
                if (rw == READ) {
                        //POISON(kmap(iobuf->maplist[i]), 0xc5, PAGE_SIZE);
                        //kunmap(iobuf->maplist[i]);
                }
        }

        oa.o_id = lsm->lsm_object_id;
        oa.o_valid = OBD_MD_FLID;
        obdo_from_inode(&oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                    OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        if (rw == WRITE)
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_DIRECT_WRITE, iobuf->length);
        else
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_DIRECT_READ, iobuf->length);
        rc = obd_brw_async(rw == WRITE ? OBD_BRW_WRITE : OBD_BRW_READ,
                           ll_i2obdconn(inode), &oa, lsm, iobuf->nr_pages, pga,
                           set, NULL);
        if (rc) {
                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                       "error from obd_brw_async: rc = %d\n", rc);
        } else {
                rc = ptlrpc_set_wait(set);
                if (rc)
                        CERROR("error from callback: rc = %d\n", rc);
        }
        ptlrpc_set_destroy(set);
        if (rc == 0)
                rc = iobuf->length;

        OBD_FREE(pga, sizeof(*pga) * iobuf->nr_pages);
        RETURN(rc);
}

struct address_space_operations ll_aops = {
        readpage: ll_readpage_24,
        direct_IO: ll_direct_IO_24,
        writepage: ll_writepage_24,
        sync_page: block_sync_page, /* XXX what's this? */
        prepare_write: ll_prepare_write,
        commit_write: ll_commit_write,
        bmap: NULL
};
