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

        ocp_free(page);
        unlock_page(page);
        page_cache_release(page);
}

int ll_start_readpage_24(struct ll_file_data *fd, struct obd_export *exp, 
                         struct inode *inode, struct page *page)
{
        struct obdo oa;
        struct obd_client_page *ocp;
        int rc;
        ENTRY;

        ocp = ocp_alloc(page);
        if (IS_ERR(ocp)) 
                RETURN(PTR_ERR(ocp));

        ocp->ocp_callback = ll_complete_readpage_24;
        ocp->ocp_off = (obd_off)page->index << PAGE_CACHE_SHIFT;
        ocp->ocp_count = PAGE_CACHE_SIZE;
        ocp->ocp_flag = 0;

        oa.o_id = ll_i2info(inode)->lli_smd->lsm_object_id;
        memcpy(obdo_handle(&oa), &fd->fd_ost_och.och_fh,
               sizeof(fd->fd_ost_och.och_fh));
        oa.o_valid = OBD_MD_FLID;
        obdo_from_inode(&oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME);

        rc = obd_brw_async_ocp(OBD_BRW_READ, exp, &oa, 
                               ll_i2info(inode)->lli_smd, NULL, ocp, NULL);
        if (rc)
                ocp_free(page);
        RETURN(rc);
}

void ll_start_readahead(struct ll_file_data *fd, struct obd_export *exp, 
                        struct inode *inode, unsigned long first_index)
{
        struct lustre_handle match_lockh = {0};
        struct ldlm_extent page_extent;
        unsigned long index, end_index;
        struct page *page;
        int flags, matched, rc;

        /* try to read the file's preferred block size in a one-er */
        end_index = first_index + (inode->i_blksize >> PAGE_CACHE_SHIFT);
        if (end_index > (inode->i_size >> PAGE_CACHE_SHIFT))
                end_index = inode->i_size >> PAGE_CACHE_SHIFT;

        for (index = first_index + 1; index < end_index; index++) {
                /* see if the page already exists and needs updating */
                page = find_get_page(inode->i_mapping, index);
                if (page) {
                        if (Page_Uptodate(page) || TryLockPage(page)) {
                                page_cache_release(page);
                                continue;
                        }
                } else {
                        /* ok, we have to create it.. */
                        page = grab_cache_page(inode->i_mapping, index);
                        if (page == NULL)
                                break;
                }
                /* make sure we didn't race with other teardown/readers */
                if (!page->mapping || Page_Uptodate(page)) {
                        unlock_page(page);
                        page_cache_release(page);
                        continue;
                }

                /* our lock matching is presumed to be more expensive
                 * than the pagecache lookups */
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
                /* interestingly, we don't need to hold the lock across the
                 * IO.  As long as we match the lock while the page is in
                 * the page cache we know that the lock's cancelation will
                 * invalidate the page. XXX this should transition to
                 * proper association of pages and locks in the future */
                obd_cancel(ll_i2sbi(inode)->ll_osc_exp,
                           ll_i2info(inode)->lli_smd, LCK_PR, &match_lockh);

                rc = ll_start_readpage_24(fd, exp, inode, page);
                if (rc != 0) {
                        unlock_page(page);
                        page_cache_release(page);
                        break;
                }
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
        struct ll_file_data *fd = file->private_data;
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
        matched = obd_match(ll_i2sbi(inode)->ll_osc_exp, 
                            ll_i2info(inode)->lli_smd, LDLM_EXTENT,
                            &page_extent, sizeof(page_extent), LCK_PR, &flags,
                            inode, &match_lockh);

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

        obd_brw_plug(OBD_BRW_READ, exp, ll_i2info(inode)->lli_smd, NULL);

        page_cache_get(page);
        rc = ll_start_readpage_24(fd, exp, inode, page);
        if (rc == 0) {
                ll_start_readahead(fd, exp, inode, page->index);
        } else {
                page_cache_release(page);
        }

        obd_brw_unplug(OBD_BRW_READ, exp, ll_i2info(inode)->lli_smd, NULL);

        if (matched)
                obd_cancel(ll_i2sbi(inode)->ll_osc_exp, 
                           ll_i2info(inode)->lli_smd, LCK_PR, &match_lockh);
out:
        if (rc)
                unlock_page(page);
        RETURN(rc);
}

void ll_complete_writepage_24(struct obd_client_page *ocp, int rc)
{
        struct page *page = ocp->ocp_page;
        struct inode *inode = page->mapping->host;

        LASSERT(page->private == (unsigned long)ocp);
        LASSERT(PageLocked(page));

        ll_page_acct(0, -1); /* io before dirty, this is so lame. */
        rc = ll_clear_dirty_pages(ll_i2obdexp(inode),
                                  ll_i2info(inode)->lli_smd,
                                  page->index, page->index);
        LASSERT(rc == 0);
        ocp_free(page);

        unlock_page(page);
        page_cache_release(page);
}

static int ll_writepage_24(struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct obd_export *exp;
        struct obd_client_page *ocp;
        int rc;
        ENTRY;

        exp = ll_i2obdexp(inode);
        if (exp == NULL)
                RETURN(-EINVAL);

        ocp = ocp_alloc(page);
        if (IS_ERR(ocp)) 
                RETURN(PTR_ERR(ocp));

        ocp->ocp_callback = ll_complete_writepage_24;
        ocp->ocp_off = (obd_off)page->index << PAGE_CACHE_SHIFT;
        ocp->ocp_count = ll_ocp_write_count(inode, page);
        ocp->ocp_flag = OBD_BRW_CREATE|OBD_BRW_FROM_GRANT;

        obd_brw_plug(OBD_BRW_WRITE, exp, ll_i2info(inode)->lli_smd, NULL);

        page_cache_get(page);
        rc = ll_start_ocp_io(exp, page);
        if (rc == 0) {
                ll_page_acct(0, 1);
                ll_start_io_from_dirty(exp, inode, ll_complete_writepage_24);
        } else {
                ocp_free(page);
                page_cache_release(page);
        }

        obd_brw_unplug(OBD_BRW_WRITE, exp, ll_i2info(inode)->lli_smd, NULL);

        if (rc != 0)
                unlock_page(page);
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
        sync_page: block_sync_page, /* XXX good gravy, we could be smart. */
        prepare_write: ll_prepare_write,
        commit_write: ll_commit_write,
        bmap: NULL
};
