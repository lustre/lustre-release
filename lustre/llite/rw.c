/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite I/O page cache routines shared by different kernel revs
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

#ifndef list_for_each_prev_safe
#define list_for_each_prev_safe(pos, n, head) \
        for (pos = (head)->prev, n = pos->prev; pos != (head); \
                pos = n, n = pos->prev )
#endif

/* SYNCHRONOUS I/O to object storage for an inode */
static int ll_brw(int cmd, struct inode *inode, struct obdo *oa, 
                  struct page *page, int flags)
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

        if (cmd == OBD_BRW_WRITE)
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_BRW_WRITE, pg.count);
        else
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_BRW_READ, pg.count);
        rc = obd_brw(cmd, ll_i2obdexp(inode), oa, lsm, 1, &pg, NULL);
        if (rc == 0)
                obdo_to_inode(inode, oa, OBD_MD_FLBLOCKS);
        else if (rc != -EIO)
                CERROR("error from obd_brw: rc = %d\n", rc);
        RETURN(rc);
}

/* this isn't where truncate starts.   roughly:
 * sys_truncate->ll_setattr_raw->vmtruncate->ll_truncate
 * we grab the lock back in setattr_raw to avoid races. */
void ll_truncate(struct inode *inode)
{
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct obdo oa;
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        /* object not yet allocated - this is handled in ll_setattr_raw */
        if (!lsm) {
                CERROR("truncate on inode %lu with no objects\n", inode->i_ino);
                EXIT;
                return;
        }

        oa.o_id = lsm->lsm_object_id;
        oa.o_valid = OBD_MD_FLID;
        obdo_from_inode(&oa, inode, OBD_MD_FLTYPE|OBD_MD_FLMODE|OBD_MD_FLATIME|
                                    OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        CDEBUG(D_INFO, "calling punch for "LPX64" (all bytes after %Lu)\n",
               oa.o_id, inode->i_size);

        /* truncate == punch from new size to absolute end of file */
        rc = obd_punch(ll_i2obdexp(inode), &oa, lsm, inode->i_size,
                       OBD_OBJECT_EOF, NULL);
        if (rc)
                CERROR("obd_truncate fails (%d) ino %lu\n", rc, inode->i_ino);
        else
                obdo_to_inode(inode, &oa, OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                          OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                          OBD_MD_FLCTIME);

        EXIT;
        return;
} /* ll_truncate */

int ll_prepare_write(struct file *file, struct page *page, unsigned from,
                     unsigned to)
{
        struct inode *inode = page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        obd_off offset = ((obd_off)page->index) << PAGE_SHIFT;
        struct brw_page pg;
        struct obdo oa;
        int rc = 0;
        ENTRY;

        if (!PageLocked(page))
                LBUG();

        if (PageUptodate(page))
                RETURN(0);

        /* Check to see if we should return -EIO right away */
        pg.pg = page;
        pg.off = offset;
        pg.count = PAGE_SIZE;
        pg.flag = 0;
        rc = obd_brw(OBD_BRW_CHECK, ll_i2obdexp(inode), NULL, lsm, 1, &pg, 
                     NULL);
        if (rc)
                RETURN(rc);

        /* We're completely overwriting an existing page, so _don't_ set it up
         * to date until commit_write */
        if (from == 0 && to == PAGE_SIZE) {
                POISON_PAGE(page, 0x11);
                RETURN(0);
        }

        /* If are writing to a new page, no need to read old data.
         * the extent locking and getattr procedures in ll_file_write have
         * guaranteed that i_size is stable enough for our zeroing needs */
        if (inode->i_size <= offset) {
                memset(kmap(page), 0, PAGE_SIZE);
                kunmap(page);
                GOTO(prepare_done, rc = 0);
        }

        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = inode->i_mode;
        oa.o_valid = OBD_MD_FLID | OBD_MD_FLMODE | OBD_MD_FLTYPE;
        
        /* XXX could be an async ocp read.. read-ahead? */
        rc = ll_brw(OBD_BRW_READ, inode, &oa, page, 0);
        if (rc == 0) {
                /* bug 1598: don't clobber blksize */
                oa.o_valid &= ~(OBD_MD_FLSIZE | OBD_MD_FLBLKSZ);
                obdo_refresh_inode(inode, &oa, oa.o_valid);
        }

        EXIT;
 prepare_done:
        if (rc == 0)
                SetPageUptodate(page);

        return rc;
}

int ll_write_count(struct page *page)
{
        struct inode *inode = page->mapping->host;

        /* catch race with truncate */
        if (((loff_t)page->index << PAGE_SHIFT) >= inode->i_size)
                return 0;

        /* catch sub-page write at end of file */
        if (((loff_t)page->index << PAGE_SHIFT) + PAGE_SIZE > inode->i_size)
                return inode->i_size % PAGE_SIZE;

        return PAGE_SIZE;
}

struct ll_async_page *llap_from_cookie(void *cookie)
{
        struct ll_async_page *llap = cookie;
        if (llap->llap_magic != LLAP_MAGIC)
                return ERR_PTR(-EINVAL);
        return llap;
};

static int ll_ap_make_ready(void *data, int cmd)
{
        struct ll_async_page *llap;
        struct page *page;
        ENTRY;
        
        /* reads are always locked between queueing and completion, 
         * llite should never queue pages without _READY */
        LASSERT(cmd != OBD_BRW_READ);

        llap = llap_from_cookie(data);
        if (IS_ERR(llap)) 
                RETURN(-EINVAL);

        page = llap->llap_page;

        if (TryLockPage(page))
                RETURN(-EBUSY);

        LL_CDEBUG_PAGE(page, "made ready\n");
        page_cache_get(page);

        /* if we left PageDirty we might get another writepage call
         * in the future.  list walkers are bright enough
         * to check page dirty so we can leave it on whatever list
         * its on.  XXX also, we're called with the cli list so if
         * we got the page cache list we'd create a lock inversion
         * with the removepage path which gets the page lock then the
         * cli lock */
        clear_page_dirty(page);
        RETURN(0);
}

static int ll_ap_refresh_count(void *data, int cmd)
{
        struct ll_async_page *llap;
        ENTRY;

        /* readpage queues with _COUNT_STABLE, shouldn't get here. */
        LASSERT(cmd != OBD_BRW_READ);

        llap = llap_from_cookie(data);
        if (IS_ERR(llap))
                RETURN(PTR_ERR(llap));

        return ll_write_count(llap->llap_page);
}

void ll_inode_fill_obdo(struct inode *inode, int cmd, struct obdo *oa)
{
        struct lov_stripe_md *lsm;
        obd_flag valid_flags;

        lsm = ll_i2info(inode)->lli_smd;

        oa->o_id = lsm->lsm_object_id;
        oa->o_valid = OBD_MD_FLID;
        valid_flags = OBD_MD_FLTYPE | OBD_MD_FLATIME;
        if (cmd == OBD_BRW_WRITE) {
                oa->o_valid |= OBD_MD_FLIFID | OBD_MD_FLEPOCH;
                mdc_pack_fid(obdo_fid(oa), inode->i_ino, 0, inode->i_mode);
                oa->o_easize = ll_i2info(inode)->lli_io_epoch;

                valid_flags |= OBD_MD_FLMTIME | OBD_MD_FLCTIME;
        }

        obdo_from_inode(oa, inode, valid_flags);
}

static void ll_ap_fill_obdo(void *data, int cmd, struct obdo *oa)
{
        struct ll_async_page *llap;
        ENTRY;

        llap = llap_from_cookie(data);
        if (IS_ERR(llap)) {
                EXIT;
                return;
        }

        ll_inode_fill_obdo(llap->llap_page->mapping->host, cmd, oa);
        EXIT;
}

static struct obd_async_page_ops ll_async_page_ops = {
        .ap_make_ready =        ll_ap_make_ready,
        .ap_refresh_count =     ll_ap_refresh_count,
        .ap_fill_obdo =         ll_ap_fill_obdo,
        .ap_completion =        ll_ap_completion,
};

/* XXX have the exp be an argument? */
struct ll_async_page *llap_from_page(struct page *page)
{
        struct ll_async_page *llap;
        struct obd_export *exp;
        struct inode *inode = page->mapping->host;
        int rc;
        ENTRY;

        if (page->private != 0) {
                llap = (struct ll_async_page *)page->private;
                if (llap->llap_magic != LLAP_MAGIC)
                        RETURN(ERR_PTR(-EINVAL));
                RETURN(llap);
        } 

        exp = ll_i2obdexp(page->mapping->host);
        if (exp == NULL)
                RETURN(ERR_PTR(-EINVAL));

        OBD_ALLOC(llap, sizeof(*llap));
        llap->llap_magic = LLAP_MAGIC;
        rc = obd_prep_async_page(exp, ll_i2info(inode)->lli_smd,
                                 NULL, page, 
                                 (obd_off)page->index << PAGE_SHIFT,
                                 &ll_async_page_ops, llap, &llap->llap_cookie);
        if (rc) {
                OBD_FREE(llap, sizeof(*llap));
                RETURN(ERR_PTR(rc));
        }

        CDEBUG(D_CACHE, "llap %p page %p cookie %p obj off "LPU64"\n", llap, 
               page, llap->llap_cookie, (obd_off)page->index << PAGE_SHIFT);
        page->private = (unsigned long)llap;
        llap->llap_page = page;
        RETURN(llap);
}

/* update our write count to account for i_size increases that may have
 * happened since we've queued the page for io. */

/* be careful not to return success without setting the page Uptodate or
 * the next pass through prepare_write will read in stale data from disk. */
int ll_commit_write(struct file *file, struct page *page, unsigned from,
                    unsigned to)
{
        struct inode *inode = page->mapping->host;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obd_export *exp = NULL;
        struct ll_async_page *llap;
        loff_t size;
        int rc = 0;
        ENTRY;

        SIGNAL_MASK_ASSERT(); /* XXX BUG 1511 */
        LASSERT(inode == file->f_dentry->d_inode);
        LASSERT(PageLocked(page));

        CDEBUG(D_INODE, "inode %p is writing page %p from %d to %d at %lu\n",
               inode, page, from, to, page->index);

        llap = llap_from_page(page);
        if (IS_ERR(llap))
                RETURN(PTR_ERR(llap));

        /* queue a write for some time in the future the first time we
         * dirty the page */
        if (!PageDirty(page)) {
                lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats,
                                     LPROC_LL_DIRTY_MISSES);

                exp = ll_i2obdexp(inode);
                if (exp == NULL)
                        RETURN(-EINVAL);

                rc = obd_queue_async_io(exp, lsm, NULL, llap->llap_cookie, 
                                        OBD_BRW_WRITE, 0, 0, 0, 0);
                if (rc != 0) { /* async failed, try sync.. */
                        struct obd_sync_io_container osic;
                        osic_init(&osic);

                        rc = obd_queue_sync_io(exp, lsm, NULL, &osic, 
                                               llap->llap_cookie, 
                                               OBD_BRW_WRITE, 0, to, 0);
                        if (rc)
                                GOTO(out, rc);

                        rc = obd_trigger_sync_io(exp, lsm, NULL, &osic);
                        if (rc)
                                GOTO(out, rc);

                        rc = osic_wait(&osic);
                        GOTO(out, rc);
                }
                LL_CDEBUG_PAGE(page, "write queued\n");
                llap->llap_queued = 1;
                //llap_write_pending(inode, llap);
        } else {
                lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats,
                                     LPROC_LL_DIRTY_HITS);
        }

        /* put the page in the page cache, from now on ll_removepage is 
         * responsible for cleaning up the llap */
        set_page_dirty(page);

out:
        if (rc == 0) {
                /* XXX needs to be pushed down to the OSC as EOC */
                size = (((obd_off)page->index) << PAGE_SHIFT) + to;
                if (size > inode->i_size) {
                        inode->i_size = size;
                        /* see commentary in file.c:ll_inode_getattr() */
                        set_bit(LLI_F_PREFER_EXTENDED_SIZE, &lli->lli_flags);
                }
                SetPageUptodate(page);
        }
        RETURN(rc);
}

/* the kernel calls us here when a page is unhashed from the page cache.
 * the page will be locked and the kernel is holding a spinlock, so
 * we need to be careful.  we're just tearing down our book-keeping
 * here. */
void ll_removepage(struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct obd_export *exp;
        struct ll_async_page *llap;
        int rc;
        ENTRY;

        LASSERT(!in_interrupt());

        /* sync pages or failed read pages can leave pages in the page
         * cache that don't have our data associated with them anymore */
        if (page->private == 0) {
                EXIT;
                return;
        }

        LL_CDEBUG_PAGE(page, "being evicted\n");

        exp = ll_i2obdexp(inode);
        if (exp == NULL) {
                CERROR("page %p ind %lu gave null export\n", page, 
                       page->index);
                EXIT;
                return;
        }

        llap = llap_from_page(page);
        if (IS_ERR(llap)) {
                CERROR("page %p ind %lu couldn't find llap: %ld\n", page, 
                       page->index, PTR_ERR(llap));
                EXIT;
                return;
        }

        //llap_write_complete(inode, llap);
        rc = obd_teardown_async_page(exp, ll_i2info(inode)->lli_smd, NULL, 
                                     llap->llap_cookie);
        if (rc != 0)
                CERROR("page %p ind %lu failed: %d\n", page, page->index, rc);

        /* this unconditional free is only safe because the page lock
         * is providing exclusivity to memory pressure/truncate/writeback..*/
        page->private = 0;
        OBD_FREE(llap, sizeof(*llap));
        EXIT;
}

static int ll_start_readpage(struct obd_export *exp, struct inode *inode, 
                             struct page *page)
{
        struct ll_async_page *llap;
        int rc;
        ENTRY;

        llap = llap_from_page(page);
        if (IS_ERR(llap))
                RETURN(PTR_ERR(llap));

        page_cache_get(page);

        rc = obd_queue_async_io(exp, ll_i2info(inode)->lli_smd, NULL, 
                                llap->llap_cookie, OBD_BRW_READ, 0, PAGE_SIZE, 
                                0, ASYNC_READY | ASYNC_URGENT | 
                                   ASYNC_COUNT_STABLE);
        /* XXX verify that failed pages here will make their way
         * through ->removepage.. I suspect they will. */
        if (rc)
                page_cache_release(page);
        else  {
                llap->llap_queued = 1;
                LL_CDEBUG_PAGE(page, "read queued\n");
        }
        RETURN(rc);
}

static void ll_start_readahead(struct obd_export *exp, struct inode *inode, 
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
                if (matched < 0) {
                        LL_CDEBUG_PAGE(page, "lock match failed\n");
                        break;
                }
                if (matched == 0) {
                        LL_CDEBUG_PAGE(page, "didn't match a lock\n");
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

                rc = ll_start_readpage(exp, inode, page);
                if (rc != 0) {
                        unlock_page(page);
                        page_cache_release(page);
                        break;
                }
                page_cache_release(page);
        }
}
/*
 * for now we do our readpage the same on both 2.4 and 2.5.  The kernel's
 * read-ahead assumes it is valid to issue readpage all the way up to
 * i_size, but our dlm locks make that not the case.  We disable the
 * kernel's read-ahead and do our own by walking ahead in the page cache
 * checking for dlm lock coverage.  the main difference between 2.4 and
 * 2.6 is how read-ahead gets batched and issued, but we're using our own,
 * so they look the same.
 */
int ll_readpage(struct file *file, struct page *page)
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
        if (matched < 0)
                GOTO(out, rc = matched);

        if (matched == 0) {
                static unsigned long next_print;
                CDEBUG(D_INODE, "didn't match a lock");
                if (time_after(jiffies, next_print)) {
                        next_print = jiffies + 30 * HZ;
                        CERROR("not covered by a lock (mmap?).  check debug "
                               "logs.\n");
                }
        }

        rc = ll_start_readpage(exp, inode, page);
        if (rc == 0 && (sbi->ll_flags & LL_SBI_READAHEAD))
                ll_start_readahead(exp, inode, page->index);

        if (matched == 1)
                obd_cancel(ll_i2sbi(inode)->ll_osc_exp, 
                           ll_i2info(inode)->lli_smd, LCK_PR, &match_lockh);
out:
        if (rc)
                unlock_page(page);
        RETURN(rc);
}
