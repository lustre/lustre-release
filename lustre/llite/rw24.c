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

void ll_complete_readpage_24(struct obd_client_page *ocp, int rc)
{
        struct page *page = ocp->ocp_page;

        LASSERT(page->private == (unsigned long)ocp);
        LASSERT(PageLocked(page));

        if (rc == 0)
                SetPageUptodate(page);
        else
                SetPageError(page);

        ocp->ocp_flags &= ~OCP_IO_READY;
        unlock_page(page);
        page_cache_release(page);
}

int ll_start_readpage_24(struct obd_export *exp, struct inode *inode, 
                         struct page *page)
{
        struct obd_client_page *ocp;
        int rc;
        ENTRY;

        ocp = ocp_alloc(page);
        if (IS_ERR(ocp)) 
                RETURN(PTR_ERR(ocp));

        ocp->ocp_io_completion = ll_complete_readpage_24;
        ocp->ocp_off = (obd_off)page->index << PAGE_CACHE_SHIFT;
        ocp->ocp_count = PAGE_CACHE_SIZE;
        ocp->ocp_flags = OCP_IO_READY|OCP_IO_URGENT;
        ocp->ocp_brw_flag = 0;
        /* don't set io ready and update args, we don't need to */
        ocp->ocp_update_obdo = ll_ocp_update_obdo;

        page_cache_get(page);
        rc = obd_queue_async_io(OBD_BRW_READ, exp, ll_i2info(inode)->lli_smd,
                                NULL, ocp, NULL);
        if (rc) {
                ocp_free(page);
                page_cache_release(page);
        }
        RETURN(rc);
}

void ll_start_readahead(struct obd_export *exp, struct inode *inode, 
                        unsigned long first_index)
{
        struct lustre_handle match_lockh = {0};
        struct ldlm_extent page_extent;
        unsigned long index, end_index;
        struct page *page;
        int flags, matched, rc;

        /* for good throughput we need to have many 'blksize' rpcs in
         * flight per stripe, so we try to read-ahead a ridiculous amount
         * of data. "- 3" for 8 rpcs */
        end_index = first_index + (inode->i_blksize >> (PAGE_CACHE_SHIFT - 3));
        if (end_index > (inode->i_size >> PAGE_CACHE_SHIFT))
                end_index = inode->i_size >> PAGE_CACHE_SHIFT;

        for (index = first_index + 1; index < end_index; index++) {
                /* try to get a ref on an existing page or create a new
                 * one.  if we find a locked page or lose the race
                 * with another reader we stop trying */
                page = grab_cache_page_nowait(inode->i_mapping, index);
                if (page == NULL)
                        break;
                /* make sure we didn't race with other teardown/readers */
                if (!page->mapping || Page_Uptodate(page)) {
                        unlock_page(page);
                        page_cache_release(page);
                        continue;
                }

                /* make sure the page we're about to read is covered
                 * by a lock, stop when we go past the end of the lock */
                page_extent.start = (__u64)page->index << PAGE_CACHE_SHIFT;
                page_extent.end = page_extent.start + PAGE_CACHE_SIZE - 1;
                flags = LDLM_FL_CBPENDING | LDLM_FL_BLOCK_GRANTED;
                matched = obd_match(ll_i2sbi(inode)->ll_osc_exp, 
                                    ll_i2info(inode)->lli_smd, LDLM_EXTENT,
                                    &page_extent, sizeof(page_extent), LCK_PR, 
                                    &flags, inode, &match_lockh);
                if (!matched) {
                        unlock_page(page);
                        page_cache_release(page);
                        break;
                }

                /* interestingly, we don't need to hold the lock across the IO.
                 * As long as we match the lock while the page is locked in the
                 * page cache we know that the lock's cancelation will wait for
                 * the page to be unlocked.  XXX this should transition to
                 * proper association of pages and locks in the future */
                obd_cancel(ll_i2sbi(inode)->ll_osc_exp,
                           ll_i2info(inode)->lli_smd, LCK_PR, &match_lockh);

                rc = ll_start_readpage_24(exp, inode, page);
                if (rc != 0) {
                        unlock_page(page);
                        page_cache_release(page);
                        break;
                }
                page_cache_release(page);
        }
}
/*
 * we were asked to read a single page but we're going to try and read a batch
 * of pages all at once.  this vaguely simulates client-side read-ahead that
 * is done via ->readpages in 2.5.
 */
static int ll_readpage_24(struct file *file, struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct lustre_handle match_lockh = {0};
        struct obd_export *exp;
        struct ldlm_extent page_extent;
        int flags, rc = 0, matched;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
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
                GOTO(out, rc = 0);
        }

        exp = ll_i2obdexp(inode);
        if (exp == NULL)
                GOTO(out, rc = -EINVAL);

        page_extent.start = (__u64)page->index << PAGE_CACHE_SHIFT;
        page_extent.end = page_extent.start + PAGE_CACHE_SIZE - 1;
        flags = LDLM_FL_CBPENDING | LDLM_FL_BLOCK_GRANTED;
        matched = obd_match(sbi->ll_osc_exp, ll_i2info(inode)->lli_smd, 
                            LDLM_EXTENT, &page_extent, sizeof(page_extent), 
                            LCK_PR, &flags, inode, &match_lockh);

        /* if we wanted to do read-ahead here we could ldlm_handle2lock
         * on the lock and issue reads up to the end of the lock */
        if (!matched) {
                static unsigned long next_print;
                CDEBUG(D_INODE, "didn't match a lock");
                if (time_after(jiffies, next_print)) {
                        next_print = jiffies + 30 * HZ;
                        CERROR("not covered by a lock (mmap?).  check debug "
                               "logs.\n");
                }
        }

        rc = ll_start_readpage_24(exp, inode, page);
        if (rc == 0 && (sbi->ll_flags & LL_SBI_READAHEAD))
                ll_start_readahead(exp, inode, page->index);

        if (matched)
                obd_cancel(ll_i2sbi(inode)->ll_osc_exp, 
                           ll_i2info(inode)->lli_smd, LCK_PR, &match_lockh);
out:
        if (rc)
                unlock_page(page);
        RETURN(rc);
}

/* called as the osc engine completes an rpc that included our ocp.  
 * the ocp itself holds a reference to the page and will drop it when
 * the page is removed from the page cache.  our job is simply to
 * transfer rc into the page and unlock it */
void ll_complete_writepage_24(struct obd_client_page *ocp, int rc)
{
        struct page *page = ocp->ocp_page;

        LASSERT(page->private == (unsigned long)ocp);
        LASSERT(PageLocked(page));

        if (rc != 0) {
                CERROR("writeback error on page %p index %ld: %d\n", page,
                       page->index, rc);
                SetPageError(page);
        }
        ocp->ocp_flags &= ~OCP_IO_READY;
        unlock_page(page);
        page_cache_release(page);
}

static int ll_writepage_24(struct page *page)
{
        struct obd_client_page *ocp;
        ENTRY;

        LASSERT(!PageDirty(page));
        LASSERT(PageLocked(page));
        LASSERT(page->private != 0);

        ocp = (struct obd_client_page *)page->private;
        ocp->ocp_flags |= OCP_IO_READY;
        page_cache_get(page);

        /* sadly, not all callers who writepage eventually call sync_page
         * (ahem, kswapd) so we need to raise this page's priority 
         * immediately */
        RETURN(ll_sync_page(page));
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
                           ll_i2obdexp(inode), &oa, lsm, iobuf->nr_pages, pga,
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
/* we shouldn't use this until we have a better story about sync_page
 * and writepage completion racing.  also, until we differentiate between 
 * writepage and syncpage it seems of little value to raise the priority
 * twice*/
//        sync_page: ll_sync_page,
        prepare_write: ll_prepare_write,
        commit_write: ll_commit_write,
        removepage: ll_removepage,
        bmap: NULL
};
