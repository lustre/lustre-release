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
        
        llap = llap_from_cookie(data);
        if (IS_ERR(llap)) 
                RETURN(-EINVAL);

        page = llap->llap_page;

        if (cmd == OBD_BRW_READ) {
                /* paths that want to cancel a read-ahead clear page-private
                 * before locking the page */ 
		if (test_and_clear_bit(PG_private, &page->flags))
                        RETURN(0);
                RETURN(-EINTR);
        }

        /* we're trying to write, but the page is locked.. come back later */
        if (TryLockPage(page))
                RETURN(-EAGAIN);

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
        struct ll_sb_info *sbi = ll_i2sbi(inode);
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

        spin_lock(&sbi->ll_pglist_lock);
        sbi->ll_pglist_gen++;
        list_add_tail(&llap->llap_proc_item, &sbi->ll_pglist);
        spin_unlock(&sbi->ll_pglist_lock);

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

                /* _make_ready only sees llap once we've unlocked the page */
                llap->llap_write_queued = 1;
                rc = obd_queue_async_io(exp, lsm, NULL, llap->llap_cookie, 
                                        OBD_BRW_WRITE, 0, 0, 0, 0);
                if (rc != 0) { /* async failed, try sync.. */
                        struct obd_sync_io_container *osic;
                        osic_init(&osic);

                        llap->llap_write_queued = 0;
                        rc = obd_queue_sync_io(exp, lsm, NULL, osic, 
                                               llap->llap_cookie, 
                                               OBD_BRW_WRITE, 0, to, 0);
                        if (rc)
                                GOTO(free_osic, rc);

                        rc = obd_trigger_sync_io(exp, lsm, NULL, osic);
                        if (rc)
                                GOTO(free_osic, rc);

                        rc = osic_wait(osic);
free_osic:
                        osic_release(osic);
                        GOTO(out, rc);
                }
                LL_CDEBUG_PAGE(page, "write queued\n");
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
        struct ll_sb_info *sbi = ll_i2sbi(inode);
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

        spin_lock(&sbi->ll_pglist_lock);
        if (!list_empty(&llap->llap_proc_item))
                list_del_init(&llap->llap_proc_item);
        sbi->ll_pglist_gen++;
        spin_unlock(&sbi->ll_pglist_lock);
        OBD_FREE(llap, sizeof(*llap));
        EXIT;
}

static int ll_page_matches(struct page *page)
{
        struct lustre_handle match_lockh = {0};
        struct inode *inode = page->mapping->host;
        struct ldlm_extent page_extent;
        int flags, matches;
        ENTRY;

        page_extent.start = (__u64)page->index << PAGE_CACHE_SHIFT;
        page_extent.end = page_extent.start + PAGE_CACHE_SIZE - 1;
        flags = LDLM_FL_CBPENDING | LDLM_FL_BLOCK_GRANTED;
        matches = obd_match(ll_i2sbi(inode)->ll_osc_exp, 
                            ll_i2info(inode)->lli_smd, LDLM_EXTENT, 
                            &page_extent, sizeof(page_extent), 
                            LCK_PR, &flags, inode, &match_lockh);
        if (matches < 0) {
                LL_CDEBUG_PAGE(page, "lock match failed\n");
                RETURN(matches);
        } 
        if (matches) {
                obd_cancel(ll_i2sbi(inode)->ll_osc_exp, 
                           ll_i2info(inode)->lli_smd, LCK_PR, &match_lockh);
        }
        RETURN(matches);
}
  
static int ll_issue_page_read(struct obd_export *exp, 
                              struct ll_async_page *llap, 
                              int defer_uptodate)
{ 
        struct page *page = llap->llap_page;
        int rc;
  
        /* we don't issue this page as URGENT so that it can be batched
         * with other pages by the kernel's read-ahead.  We have a strong
         * requirement that readpage() callers must call wait_on_page()
         * or lock_page() to get into ->sync_page() to trigger the IO */
        llap->llap_defer_uptodate = defer_uptodate;
        page_cache_get(page);
        SetPagePrivate(page);
        rc = obd_queue_async_io(exp, ll_i2info(page->mapping->host)->lli_smd, 
                                NULL, llap->llap_cookie, OBD_BRW_READ, 0, 
                                PAGE_SIZE, 0, ASYNC_COUNT_STABLE);
        if (rc) {
                LL_CDEBUG_PAGE(page, "read queueing failed\n");
                ClearPagePrivate(page);
                page_cache_release(page);
        }
        RETURN(rc);
}

static void ll_readahead(struct ll_readahead_state *ras, 
                         struct obd_export *exp, struct address_space *mapping)
{
        unsigned long i, start, end;
        struct ll_async_page *llap;
        struct page *page;
        int rc;

        if (mapping->host->i_size == 0)
                return;

        spin_lock(&ras->ras_lock);

        /* make sure to issue a window's worth of read-ahead pages */
        end = ras->ras_last;
        start = end - ras->ras_window;
        if (start > end)
                start = 0;

        /* but don't iterate over pages that we've already issued.  this
         * will set start to end + 1 if we've already read-ahead up to
         * ras_last sothe for() won't be entered */
        if (ras->ras_next_index > start)
                start = ras->ras_next_index;
        if (end != ~0UL)
                ras->ras_next_index = end + 1;

        CDEBUG(D_READA, "ni %lu last %lu win %lu: reading from %lu to %lu\n",
               ras->ras_next_index, ras->ras_last, ras->ras_window,
               start, end); 

        spin_unlock(&ras->ras_lock);

        /* clamp to filesize */
        i = (mapping->host->i_size - 1) >> PAGE_CACHE_SHIFT;
        end = min(end, i);

        for (i = start; i <= end; i++) {
                /* grab_cache_page_nowait returns null if this races with
                 * truncating the page (page->mapping == NULL) */
                page = grab_cache_page_nowait(mapping, i);
                if (page == NULL)
                       continue;
  
                /* the book-keeping above promises that we've tried
                 * all the indices from start to end, so we don't
                 * stop if anyone returns an error. This may not be good. */
                if (Page_Uptodate(page) || ll_page_matches(page) <= 0)
                        goto next_page;

                llap = llap_from_page(page);
                if (IS_ERR(llap) || llap->llap_defer_uptodate)
                        goto next_page;

                rc = ll_issue_page_read(exp, llap, 1);
                if (rc == 0)
                        LL_CDEBUG_PAGE(page, "started read-ahead\n");
                if (rc) {
        next_page:
                        LL_CDEBUG_PAGE(page, "skipping read-ahead\n");

                        unlock_page(page);
                }
                page_cache_release(page);
        }
}

/* XXX this should really bubble up somehow.  */
#define LL_RA_MIN ((unsigned long)PTL_MD_MAX_PAGES / 2)
#define LL_RA_MAX ((unsigned long)(32 * PTL_MD_MAX_PAGES))

/* called with the ras_lock held or from places where it doesn't matter */
static void ll_readahead_set(struct ll_readahead_state *ras, 
                             unsigned long index)
{
        ras->ras_next_index = index;
        if (ras->ras_next_index != ~0UL)
                ras->ras_next_index++;
        ras->ras_window = LL_RA_MIN;
        ras->ras_last = ras->ras_next_index + ras->ras_window;
        if (ras->ras_last < ras->ras_next_index)
                ras->ras_last = ~0UL;
        CDEBUG(D_READA, "ni %lu last %lu win %lu: set %lu\n",
               ras->ras_next_index, ras->ras_last, ras->ras_window,
               index);
}

void ll_readahead_init(struct ll_readahead_state *ras)
{
        spin_lock_init(&ras->ras_lock);
        ll_readahead_set(ras, 0);
}

static void ll_readahead_update(struct ll_readahead_state *ras, 
                                unsigned long index, int hit)
{
        unsigned long issued_start, new_last;

        spin_lock(&ras->ras_lock);

        /* we're interested in noticing the index's relation to the 
         * previously issued read-ahead pages */
        issued_start = ras->ras_next_index - ras->ras_window - 1;
        if (issued_start > ras->ras_next_index)
                issued_start = 0;

        CDEBUG(D_READA, "ni %lu last %lu win %lu: %s ind %lu start %lu\n", 
               ras->ras_next_index, ras->ras_last, ras->ras_window,
               hit ? "hit" : "miss", index, issued_start);
        if (!hit && 
            index == ras->ras_next_index && index == ras->ras_last + 1) {
                /* special case the kernel's read-ahead running into the
                 * page just beyond our read-ahead window as an extension
                 * of our read-ahead.  sigh.  wishing it was easier to
                 * turn off 2.4's read-ahead. */
                ras->ras_window = min(LL_RA_MAX, ras->ras_window + 1);
                if (index != ~0UL)
                        ras->ras_next_index = index + 1;
                ras->ras_last = index;
        } else if (!hit && 
                   (index > issued_start || ras->ras_next_index >= index)) {
                /* deal with a miss way out of the window.  we interpret
                 * this as a seek and restart the window */
                ll_readahead_set(ras, index);

        } else if (!hit && 
                   issued_start <= index && index < ras->ras_next_index) {
                /* a miss inside the window?  surely its memory pressure
                 * evicting our read pages before the app can see them.
                 * we shrink the window aggressively */
                unsigned long old_window = ras->ras_window;

                ras->ras_window = max(ras->ras_window / 2, LL_RA_MIN);
                ras->ras_last -= old_window - ras->ras_window;
                if (ras->ras_next_index > ras->ras_last)
                        ras->ras_next_index = ras->ras_last + 1;
                CDEBUG(D_READA, "ni %lu last %lu win %lu: miss inside\n",
                       ras->ras_next_index, ras->ras_last, ras->ras_window);

        } else if (hit && 
                   issued_start <= index && index < ras->ras_next_index) {
                /* a hit inside the window.  grow the window by twice the 
                 * number of pages that are satisified within the window.  */
                ras->ras_window = min(LL_RA_MAX, ras->ras_window + 2);

                /* we want the next readahead pass to issue a windows worth
                 * beyond where the app currently is */
                new_last = index + ras->ras_window;
                if (new_last > ras->ras_last)
                        ras->ras_last = new_last;

                CDEBUG(D_READA, "ni %lu last %lu win %lu: extended window/last\n",
                       ras->ras_next_index, ras->ras_last, ras->ras_window);
        }

        spin_unlock(&ras->ras_lock);
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
int ll_readpage(struct file *filp, struct page *page)
{
        struct ll_file_data *fd = filp->private_data;
        struct inode *inode = page->mapping->host;
        struct obd_export *exp;
        int rc;
        struct ll_async_page *llap;
        ENTRY;

        LASSERT(PageLocked(page));
        LASSERT(!PageUptodate(page));
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),offset="LPX64"\n",
               inode->i_ino, inode->i_generation, inode,
               (((obd_off)page->index) << PAGE_SHIFT));
        LASSERT(atomic_read(&filp->f_dentry->d_inode->i_count) > 0);

        exp = ll_i2obdexp(inode);
        if (exp == NULL)
                GOTO(out, rc = -EINVAL);

        llap = llap_from_page(page);
        if (IS_ERR(llap))
                GOTO(out, rc = PTR_ERR(llap));

        if (llap->llap_defer_uptodate) {
                ll_readahead_update(&fd->fd_ras, page->index, 1);
                LL_CDEBUG_PAGE(page, "marking uptodate from defer\n");
                SetPageUptodate(page);
                ll_readahead(&fd->fd_ras, exp, page->mapping);
                unlock_page(page);
                RETURN(0);
        }

        ll_readahead_update(&fd->fd_ras, page->index, 0);

        rc = ll_page_matches(page);
        if (rc < 0)
                GOTO(out, rc);

        if (rc == 0) {
                static unsigned long next_print;
                CDEBUG(D_INODE, "didn't match a lock");
                if (time_after(jiffies, next_print)) {
                        next_print = jiffies + 30 * HZ;
                        CERROR("not covered by a lock (mmap?).  check debug "
                               "logs.\n");
                }
        }

        rc = ll_issue_page_read(exp, llap, 0);
        if (rc == 0) {
                LL_CDEBUG_PAGE(page, "queued readpage\n");
                if ((ll_i2sbi(inode)->ll_flags & LL_SBI_READAHEAD))
                        ll_readahead(&fd->fd_ras, exp, page->mapping);
        }
out:
        if (rc) 
                unlock_page(page);
        RETURN(rc);
}

/* this is for read pages.  we issue them as ready but not urgent.  when
 * someone waits on them we fire them off, hopefully merged with adjacent
 * reads that were queued by the kernel's read-ahead.  */
int ll_sync_page(struct page *page)
{
        struct obd_export *exp;
        struct ll_async_page *llap;
        int rc;
        ENTRY;

        /* we're abusing PagePrivate to signify that a queued read should
         * be issued once someone goes to lock it.  it is cleared by 
         * canceling the read-ahead page before discarding and by issuing
         * the read rpc */
        if (!PagePrivate(page))
                RETURN(0);
        ClearPagePrivate(page);

        /* careful to only deref page->mapping after checking PagePrivate */
        exp = ll_i2obdexp(page->mapping->host);
        if (exp == NULL)
                RETURN(-EINVAL);
  
        llap = llap_from_page(page);
        if (IS_ERR(llap))
                RETURN(PTR_ERR(llap));

        LL_CDEBUG_PAGE(page, "setting ready|urgent\n");

        rc = obd_set_async_flags(exp, ll_i2info(page->mapping->host)->lli_smd, 
                                 NULL, llap->llap_cookie, 
                                 ASYNC_READY|ASYNC_URGENT);
        return rc;
}
