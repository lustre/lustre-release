/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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
 *
 *  Copyright (C) 2002, 2003  Cluster File Systems, Inc
 *
 *  this started as an implementation of an io daemon that woke regularly
 *  to force writeback.. the throttling in prepare_write and kupdate's usual
 *  writeback pressure got rid of our thread, but the file name remains.
 */

#include <linux/version.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/kmod.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/rbtree.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include "llite_internal.h"

/* PG_inactive_clean is shorthand for rmap, we want free_high/low here.. */
#ifdef PG_inactive_clean
#include <linux/mm_inline.h>
#endif

#define DEBUG_SUBSYSTEM S_LLITE
#include <linux/lustre_lite.h>

#ifndef list_for_each_prev_safe
#define list_for_each_prev_safe(pos, n, head) \
        for (pos = (head)->prev, n = pos->prev; pos != (head); \
                pos = n, n = pos->prev )
#endif

extern spinlock_t inode_lock;

struct ll_writeback_pages {
        obd_count npgs, max;
        struct brw_page *pga;
};

/*
 * check to see if we're racing with truncate and put the page in
 * the brw_page array.  returns 0 if there is more room and 1
 * if the array is full.
 */
static int llwp_consume_page(struct ll_writeback_pages *llwp,
                             struct inode *inode, struct page *page)
{
        obd_off off = ((obd_off)page->index) << PAGE_SHIFT;
        struct brw_page *pg;

        /* we raced with truncate? */
        if ( off >= inode->i_size ) {
                int rc;
                rc = ll_clear_dirty_pages(ll_i2obdconn(inode),
                                          ll_i2info(inode)->lli_smd,
                                          page->index, page->index);

                LASSERT(rc == 0);
                CDEBUG(D_CACHE, "offset "LPU64" (index %lu) > i_size %llu\n",
                       off, page->index, inode->i_size);
                unlock_page(page);
                return 0;
        }

        page_cache_get(page);
        pg = &llwp->pga[llwp->npgs];
        llwp->npgs++;
        LASSERT(llwp->npgs <= llwp->max);

        pg->pg = page;
        pg->off = off;
        pg->flag = OBD_BRW_CREATE|OBD_BRW_FROM_GRANT;
        pg->count = PAGE_CACHE_SIZE;

        /* catch partial writes for files that end mid-page */
        if (pg->off + pg->count > inode->i_size)
                pg->count = inode->i_size & ~PAGE_CACHE_MASK;

        /*
         * matches ptlrpc_bulk_get assert that trickles down
         * from a 0 page length going through niobuf and into
         * the buffer regions being posted
         */
        LASSERT(pg->count >= 0);

        CDEBUG(D_CACHE, "brw_page %p: off "LPU64" cnt %d, page %p: ind %ld"
                        " i_size: %llu\n", pg, pg->off, pg->count, page,
                        page->index, inode->i_size);

        return llwp->npgs == llwp->max;
}

/*
 * returns the number of pages that it added to the pgs array
 *
 * this duplicates filemap_fdatasync and gives us an opportunity to grab lots
 * of dirty pages..
 */
static void ll_get_dirty_pages(struct inode *inode,
                               struct ll_writeback_pages *llwp)
{
        struct address_space *mapping = inode->i_mapping;
        struct page *page;
        struct list_head *pos, *n;
        ENTRY;

        PGCACHE_WRLOCK(mapping);

        list_for_each_prev_safe(pos, n, &mapping->dirty_pages) {
                page = list_entry(pos, struct page, list);

                if (TryLockPage(page))
                        continue;

                list_del(&page->list);
                list_add(&page->list, &mapping->locked_pages);

                if (!PageDirty(page)) {
                        unlock_page(page);
                        continue;
                }
                ClearPageDirty(page);

                if (llwp_consume_page(llwp, inode, page) != 0)
                        break;
        }

        PGCACHE_WRUNLOCK(mapping);
        EXIT;
}

static void ll_writeback(struct inode *inode, struct ll_writeback_pages *llwp)
{
        int rc, i;
        struct ptlrpc_request_set *set;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),bytes=%u\n",
               inode->i_ino, inode->i_generation, inode,
               ((llwp->npgs-1) << PAGE_SHIFT) + llwp->pga[llwp->npgs-1].count);

        set = ptlrpc_prep_set();
        if (set == NULL) {
                CERROR ("Can't create request set\n");
                rc = -ENOMEM;
        } else {
                rc = obd_brw_async(OBD_BRW_WRITE, ll_i2obdconn(inode),
                                   ll_i2info(inode)->lli_smd, llwp->npgs,
                                   llwp->pga, set, NULL);
                if (rc == 0)
                        rc = ptlrpc_set_wait (set);
                ptlrpc_set_destroy (set);
        }
        /*
         * b=1038, we need to pass _brw errors up so that writeback
         * doesn't get stuck in recovery leaving processes stuck in
         * D waiting for pages
         */
        if (rc) {
                CERROR("error from obd_brw_async: rc = %d\n", rc);
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_WB_FAIL, llwp->npgs);
        } else {
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_WB_OK, (llwp->npgs));
        }

        for (i = 0 ; i < llwp->npgs ; i++) {
                struct page *page = llwp->pga[i].pg;

                CDEBUG(D_CACHE, "finished page %p at index %lu\n", page,
                       page->index);
                LASSERT(PageLocked(page));

                rc = ll_clear_dirty_pages(ll_i2obdconn(inode),
                                          ll_i2info(inode)->lli_smd,
                                          page->index, page->index);
                LASSERT(rc == 0);
                unlock_page(page);
                page_cache_release(page);
        }

        EXIT;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))

#ifndef PG_inactive_clean
#ifdef CONFIG_DISCONTIGMEM
#error "sorry, we don't support DISCONTIGMEM yet"
#endif

/*
 * __alloc_pages marks a zone as needing balancing if an allocation is
 * performed when the zone has fewer free pages than its 'low' water
 * mark.  its cleared when try_to_free_pages makes progress.
 */
static int zones_need_balancing(void)
{
        pg_data_t * pgdat;
        zone_t *zone;
        int i;

        for ( pgdat = pgdat_list ; pgdat != NULL ; pgdat = pgdat->node_next ) {
                for ( i = pgdat->nr_zones-1 ; i >= 0 ; i-- ) {
                        zone = &pgdat->node_zones[i];

                        if ( zone->need_balance )
                                return 1;
                }
        }
        return 0;
}
#endif
/* 2.4 doesn't give us a way to find out how many pages we have
 * cached 'cause we're not using buffer_heads.  we are very
 * conservative here and flush the superblock of all dirty data
 * when the vm (rmap or stock) thinks that it is running low
 * and kswapd would have done work.  kupdated isn't good enough
 * because writers (dbench) can dirty _very quickly_, and we
 * allocate under writepage..
 *
 * 2.5 gets this right, see the {inc,dec}_page_state(nr_dirty, )
 */
static int should_writeback(void)
{
#ifdef PG_inactive_clean
        if (free_high(ALL_ZONES) > 0 || free_low(ANY_ZONE) > 0)
#else
        if (zones_need_balancing())
#endif
                return 1;
        return 0;
}

static int ll_alloc_brw(struct inode *inode, struct ll_writeback_pages *llwp)
{
        memset(llwp, 0, sizeof(struct ll_writeback_pages));

        llwp->max = inode->i_blksize >> PAGE_CACHE_SHIFT;
        if (llwp->max == 0) {
                CERROR("forcing llwp->max to 1.  blksize: %lu\n",
                       inode->i_blksize);
                llwp->max = 1;
        }
        llwp->pga = kmalloc(llwp->max * sizeof(*llwp->pga), GFP_ATOMIC);
        if (llwp->pga == NULL)
                RETURN(-ENOMEM);
        RETURN(0);
}

int ll_check_dirty(struct super_block *sb)
{
        unsigned long old_flags; /* hack? */
        int making_progress;
        struct inode *inode;
        int rc = 0;
        ENTRY;

        if (!should_writeback())
                return 0;

        old_flags = current->flags;
        current->flags |= PF_MEMALLOC;

        spin_lock(&inode_lock);

        /*
         * first we try and write back dirty pages from dirty inodes
         * until the VM thinkgs we're ok again..
         */
        do {
                struct ll_writeback_pages llwp;
                struct list_head *pos;
                inode = NULL;
                making_progress = 0;

                list_for_each_prev(pos, &sb->s_dirty) {
                        inode = list_entry(pos, struct inode, i_list);

                        if (!(inode->i_state & I_DIRTY_PAGES)) {
                                inode = NULL;
                                continue;
                        }
                        break;
                }

                if (inode == NULL)
                        break;

                /* duplicate __sync_one, *sigh* */
                list_del(&inode->i_list);
                list_add(&inode->i_list, &inode->i_sb->s_locked_inodes);
                inode->i_state |= I_LOCK;
                inode->i_state &= ~I_DIRTY_PAGES;

                spin_unlock(&inode_lock);

                rc = ll_alloc_brw(inode, &llwp);
                if (rc != 0)
                        GOTO(cleanup, rc);

                do {
                        llwp.npgs = 0;
                        ll_get_dirty_pages(inode, &llwp);
                        if (llwp.npgs) {
                                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                                    LPROC_LL_WB_PRESSURE,
                                                    llwp.npgs);
                                ll_writeback(inode, &llwp);
                                rc += llwp.npgs;
                                making_progress = 1;
                        }
                } while (llwp.npgs && should_writeback());

                spin_lock(&inode_lock);

                if (!list_empty(&inode->i_mapping->dirty_pages))
                        inode->i_state |= I_DIRTY_PAGES;

                inode->i_state &= ~I_LOCK;
                /*
                 * we are sneaky and leave the inode on the dirty list,
                 * even though it might not still be..
                 */
                if (!(inode->i_state & I_FREEING)) {
                        list_del(&inode->i_list);
                        list_add(&inode->i_list, &inode->i_sb->s_dirty);
                }
                wake_up(&inode->i_wait);
                kfree(llwp.pga);
        } while (making_progress && should_writeback());

        /*
         * and if that didn't work, we sleep on any data that might
         * be under writeback..
         */
        while (should_writeback()) {
                if (list_empty(&sb->s_locked_inodes))
                        break;

                inode = list_entry(sb->s_locked_inodes.next, struct inode,
                                   i_list);

                atomic_inc(&inode->i_count); /* XXX hack? */
                spin_unlock(&inode_lock);
                wait_event(inode->i_wait, !(inode->i_state & I_LOCK));
                iput(inode);
                spin_lock(&inode_lock);
        }

        spin_unlock(&inode_lock);

cleanup:
        current->flags = old_flags;

        RETURN(rc);
}
#endif /* linux 2.5 */

int ll_batch_writepage(struct inode *inode, struct page *page)
{
        unsigned long old_flags; /* hack? */
        struct ll_writeback_pages llwp;
        int rc = 0;
        ENTRY;

        old_flags = current->flags;
        current->flags |= PF_MEMALLOC;
        rc = ll_alloc_brw(inode, &llwp);
        if (rc != 0)
                GOTO(restore_flags, rc);

        if (llwp_consume_page(&llwp, inode, page) == 0)
                ll_get_dirty_pages(inode, &llwp);

        if (llwp.npgs) {
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_WB_WRITEPAGE, llwp.npgs);
                ll_writeback(inode, &llwp);
        }
        kfree(llwp.pga);

restore_flags:
        current->flags = old_flags;
        RETURN(rc);
}
