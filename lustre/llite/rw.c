/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite I/O Page Cache
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
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
#include <linux/buffer_head.h>
#else
#include <linux/iobuf.h>
#endif
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_compat25.h>

/*
 * Remove page from dirty list
 */
static void __set_page_clean(struct page *page)
{
        struct address_space *mapping = page->mapping;
        struct inode *inode;

        if (!mapping)
                return;

        PGCACHE_WRLOCK(mapping);

        list_del(&page->list);
        list_add(&page->list, &mapping->clean_pages);

        /* XXX doesn't inode_lock protect i_state ? */
        inode = mapping->host;
        if (list_empty(&mapping->dirty_pages)) {
                CDEBUG(D_INODE, "inode clean\n");
                inode->i_state &= ~I_DIRTY_PAGES;
        }

        PGCACHE_WRUNLOCK(mapping);
        EXIT;
}

void set_page_clean(struct page *page)
{
        if (PageDirty(page)) {
                ClearPageDirty(page);
                __set_page_clean(page);
        }
}

/* SYNCHRONOUS I/O to object storage for an inode */
static int ll_brw(int cmd, struct inode *inode, struct page *page, int flags)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct brw_page pg;
        int rc;
        ENTRY;

        pg.pg = page;
        pg.off = ((obd_off)page->index) << PAGE_SHIFT;

        if (cmd == OBD_BRW_WRITE && (pg.off + PAGE_SIZE > inode->i_size))
                pg.count = inode->i_size % PAGE_SIZE;
        else
                pg.count = PAGE_SIZE;

        CDEBUG(D_PAGE, "%s %d bytes ino %lu at "LPU64"/"LPX64"\n",
               cmd & OBD_BRW_WRITE ? "write" : "read", pg.count, inode->i_ino,
               pg.off, pg.off);
        if (pg.count == 0) {
                CERROR("ZERO COUNT: ino %lu: size %p:%Lu(%p:%Lu) idx %lu off "
                       LPU64"\n",
                       inode->i_ino, inode, inode->i_size, page->mapping->host,
                       page->mapping->host->i_size, page->index, pg.off);
        }

        pg.flag = flags;

        rc = obd_brw(cmd, ll_i2obdconn(inode), lsm, 1, &pg, NULL);
        if (rc)
                CERROR("error from obd_brw: rc = %d\n", rc);

        RETURN(rc);
}

/*
 * we were asked to read a single page but we're going to try and read a batch
 * of pages all at once.  this vaguely simulates 2.5's readpages.
 */
static int ll_readpage(struct file *file, struct page *first_page)
{
        struct inode *inode = first_page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct page *page = first_page;
        struct list_head *pos;
        struct brw_page *pgs;
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
                static long next_print;
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

        set = ptlrpc_prep_set();
        if (set == NULL) {
                CERROR("ENOMEM allocing request set\n");
                rc = -ENOMEM;
        } else {
                rc = obd_brw_async(OBD_BRW_READ, ll_i2obdconn(inode),
                                   ll_i2info(inode)->lli_smd, npgs, pgs,
                                   set, NULL);
                if (rc == 0)
                        rc = ptlrpc_set_wait(set);
                ptlrpc_set_destroy(set);
                if (rc && rc != -EIO)
                        CERROR("error from obd_brw_async: rc = %d\n", rc);
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
} /* ll_readpage */

/* this isn't where truncate starts.   roughly:
 * sys_truncate->ll_setattr_raw->vmtruncate->ll_truncate
 * we grab the lock back in setattr_raw to avoid races. */
void ll_truncate(struct inode *inode)
{
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct obdo oa = {0};
        int err;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        if (!lsm) {
                /* object not yet allocated */
                inode->i_mtime = inode->i_ctime = CURRENT_TIME;
                EXIT;
                return;
        }

        /* vmtruncate just threw away our dirty pages, make sure
         * we don't think they're still dirty, being careful to round
         * i_size to the first whole page that was tossed */
        ll_remove_dirty(inode,
                        (inode->i_size + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT,
                        ~0);

        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = inode->i_mode;
        oa.o_valid = OBD_MD_FLID | OBD_MD_FLMODE | OBD_MD_FLTYPE;

        CDEBUG(D_INFO, "calling punch for "LPX64" (all bytes after %Lu)\n",
               oa.o_id, inode->i_size);

        /* truncate == punch from new size to absolute end of file */
        err = obd_punch(ll_i2obdconn(inode), &oa, lsm, inode->i_size,
                        OBD_OBJECT_EOF, NULL);
        if (err)
                CERROR("obd_truncate fails (%d) ino %lu\n", err, inode->i_ino);
        else
                obdo_to_inode(inode, &oa, oa.o_valid);

        EXIT;
        return;
} /* ll_truncate */

//#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))

static int ll_prepare_write(struct file *file, struct page *page, unsigned from,
                            unsigned to)
{
        struct inode *inode = page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        obd_off offset = ((obd_off)page->index) << PAGE_SHIFT;
        struct brw_page pg;
        int rc = 0;
        ENTRY;

        if (!PageLocked(page))
                LBUG();

        if (PageUptodate(page))
                RETURN(0);

        //POISON(addr + from, 0xca, to - from);

        /* Check to see if we should return -EIO right away */
        pg.pg = page;
        pg.off = offset;
        pg.count = PAGE_SIZE;
        pg.flag = 0;
        rc = obd_brw(OBD_BRW_CHECK, ll_i2obdconn(inode), lsm, 1, &pg, NULL);
        if (rc)
                RETURN(rc);

        /* We're completely overwriting an existing page, so _don't_ set it up
         * to date until commit_write */
        if (from == 0 && to == PAGE_SIZE)
                RETURN(0);

        /* If are writing to a new page, no need to read old data.
         * the extent locking and getattr procedures in ll_file_write have
         * guaranteed that i_size is stable enough for our zeroing needs */
        if (inode->i_size <= offset) {
                memset(kmap(page), 0, PAGE_SIZE);
                kunmap(page);
                GOTO(prepare_done, rc = 0);
        }

        rc = ll_brw(OBD_BRW_READ, inode, page, 0);

        EXIT;
 prepare_done:
        if (rc == 0)
                SetPageUptodate(page);

        return rc;
}

/*
 * background file writeback.  This is called regularly from kupdated to write
 * dirty data, from kswapd when memory is low, and from filemap_fdatasync when
 * super blocks or inodes are synced..
 *
 * obd_brw errors down in _batch_writepage are ignored, so pages are always
 * unlocked.  Also, there is nobody to return an error code to from here - the
 * application may not even be running anymore.
 *
 * this should be async so that things like kswapd can have a chance to
 * free some more pages that our allocating writeback may need, but it isn't
 * yet.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int ll_writepage(struct page *page)
{
        struct inode *inode = page->mapping->host;
        ENTRY;

        CDEBUG(D_CACHE, "page %p [lau %d] inode %p\n", page,
                        PageLaunder(page), inode);
        LASSERT(PageLocked(page));

        /* XXX should obd_brw errors trickle up? */
        ll_batch_writepage(inode, page);
        RETURN(0);
}

/*
 * we really don't want to start writeback here, we want to give callers some
 * time to further dirty the pages before we write them out.
 */
static int ll_commit_write(struct file *file, struct page *page,
                           unsigned from, unsigned to)
{
        struct inode *inode = page->mapping->host;
        loff_t size;
        ENTRY;

        LASSERT(inode == file->f_dentry->d_inode);
        LASSERT(PageLocked(page));

        CDEBUG(D_INODE, "inode %p is writing page %p from %d to %d at %lu\n",
               inode, page, from, to, page->index);
        /* to match full page case in prepare_write */
        SetPageUptodate(page);
        /* mark the page dirty, put it on mapping->dirty,
         * mark the inode PAGES_DIRTY, put it on sb->dirty */
        if (!PageDirty(page))
                INODE_IO_STAT_ADD(inode, dirty_misses, 1);
        else
                INODE_IO_STAT_ADD(inode, dirty_hits, 1);

        size = (((obd_off)page->index) << PAGE_SHIFT) + to;
        if (size > inode->i_size)
                inode->i_size = size;

        /* XXX temporary, bug 1286 */
        {
                struct ll_dirty_offsets *lldo = &ll_i2info(inode)->lli_dirty;
                int rc;
                if ((lldo->do_num_dirty * PAGE_CACHE_SIZE) > 10 * 1024 * 1024) {
                        rc = ll_batch_writepage(inode, page);
                        lock_page(page); /* caller expects to unlock */
                        RETURN(rc);
                }
        }

        set_page_dirty(page);
        ll_record_dirty(inode, page->index);

        RETURN(0);
} /* ll_commit_write */
#else
static int ll_writepage(struct page *page,
                        struct writeback_control *wbc)
{

        return 0;
}
static int ll_commit_write(struct file *file, struct page *page,
                           unsigned from, unsigned to)
{
        return 0;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int ll_direct_IO(int rw, struct inode *inode, struct kiobuf *iobuf,
                        unsigned long blocknr, int blocksize)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct brw_page *pga;
        struct ptlrpc_request_set *set;
        int length, i, flags, rc = 0;
        loff_t offset;
        ENTRY;

        if (!lsm || !lsm->lsm_object_id)
                RETURN(-ENOMEM);

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

        rc = obd_brw_async(rw == WRITE ? OBD_BRW_WRITE : OBD_BRW_READ,
                           ll_i2obdconn(inode), lsm, iobuf->nr_pages, pga, set,
                           NULL);
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
#endif

//#endif

struct address_space_operations ll_aops = {
        readpage: ll_readpage,
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,5,0))
        direct_IO: ll_direct_IO,
#endif
        writepage: ll_writepage,
        sync_page: block_sync_page,
        prepare_write: ll_prepare_write,
        commit_write: ll_commit_write,
        bmap: NULL
//#endif
};
