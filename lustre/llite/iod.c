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

#define LLWP_MAX_PAGES (PTL_MD_MAX_IOV)
struct ll_writeback_pages {
        unsigned        has_whole_pages:1,
                        num_frags:2,
                        num_pages:29;
        struct brw_page pgs[LLWP_MAX_PAGES];
};


/*
 * ugh, we want disk allocation on the target to happen in offset order.  we'll
 * follow sedgewicks advice and stick to the dead simple shellsort -- it'll do
 * fine for our small page arrays and doesn't require allocation.  its an
 * insertion sort that swaps elements that are strides apart, shrinking the
 * stride down until its '1' and the array is sorted.
 */
void sort_brw_pages(struct brw_page *array, int num)
{
        int stride, i, j;
        struct brw_page tmp;

        if ( num == 1 )
                return;

        for( stride = 1; stride < num ; stride = (stride*3) +1  )
                ;

        do {
                stride /= 3;
                for ( i = stride ; i < num ; i++ ) {
                        tmp = array[i];
                        j = i;
                        while ( j >= stride &&
                                        array[j - stride].off > tmp.off ) {
                                array[j] = array[j - stride];
                                j -= stride;
                        }
                        array[j] = tmp;
                }
        } while ( stride > 1 );
}

/*
 * returns 0 if the page was inserted in the array because it was
 * within i_size.  if we raced with truncate and i_size was less
 * than the page we can unlock the page because truncate_inode_pages will
 * be waiting to cleanup the page
 */
static int llwp_consume_page(struct ll_writeback_pages *llwp,
                             struct inode *inode, struct page *page)
{
        obd_off off = ((obd_off)page->index) << PAGE_SHIFT;
        struct brw_page *pg;

        /* we raced with truncate? */
        if ( off >= inode->i_size ) {
                unlock_page(page);
                goto out;
        }

        page_cache_get(page);
        pg = &llwp->pgs[llwp->num_pages];
        llwp->num_pages++;

        pg->pg = page;
        pg->off = off;
        pg->flag = OBD_BRW_CREATE;
        pg->count = PAGE_SIZE;

        /* catch partial writes for files that end mid-page */
        if ( pg->off + pg->count > inode->i_size )
                pg->count = inode->i_size & ~PAGE_MASK;

        if ( pg->count == PAGE_SIZE ) {
                if ( ! llwp->has_whole_pages ) {
                        llwp->has_whole_pages = 1;
                        llwp->num_frags++;
                }
        } else {
                llwp->num_frags++;
        }

        /*
         * matches ptlrpc_bulk_get assert that trickles down
         * from a 0 page length going through niobuf and into
         * the buffer regions being posted
         */
        LASSERT(pg->count >= 0);

        CDEBUG(D_CACHE, "brw_page %p: off "LPU64" cnt %d, page %p: ind %ld"
                        " i_size: "LPU64"\n", pg, pg->off, pg->count, page, 
                        page->index, inode->i_size);

        if ( llwp->num_frags == 3 || llwp->num_pages == LLWP_MAX_PAGES )
                return -1;

out:
        return 0;
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

        spin_lock(&pagecache_lock);

        list_for_each_prev_safe(pos, n, &mapping->dirty_pages) {
                page = list_entry(pos, struct page, list);

                if (TryLockPage(page))
                        continue;

                list_del(&page->list);
                list_add(&page->list, &mapping->locked_pages);

                if ( ! PageDirty(page) ) {
                        unlock_page(page);
                        continue;
                }
                ClearPageDirty(page);

                if ( llwp_consume_page(llwp, inode, page) != 0)
                        break;
        }

        spin_unlock(&pagecache_lock);
        EXIT;
}

static void ll_brw_pages_unlock( struct inode *inode,
                                 struct ll_writeback_pages *llwp)
{
        int rc, i;
        struct obd_brw_set *set;
        ENTRY;

        sort_brw_pages(llwp->pgs, llwp->num_pages);

        set = obd_brw_set_new();
        if (set == NULL) {
                EXIT;
                return;
        }
        set->brw_callback = ll_brw_sync_wait;

        rc = obd_brw(OBD_BRW_WRITE, ll_i2obdconn(inode),
                     ll_i2info(inode)->lli_smd, llwp->num_pages, llwp->pgs,
                     set, NULL);
        if (rc) {
                CERROR("error from obd_brw: rc = %d\n", rc);
        } else {
                rc = ll_brw_sync_wait(set, CB_PHASE_START);
                if (rc)
                        CERROR("error from callback: rc = %d\n", rc);
        }
        obd_brw_set_decref(set);

        /* XXX this doesn't make sense to me */
        rc = 0;

        for ( i = 0 ; i < llwp->num_pages ; i++) {
                struct page *page = llwp->pgs[i].pg;

                CDEBUG(D_CACHE, "cleaning page %p\n", page);
                LASSERT(PageLocked(page));
                unlock_page(page);
                page_cache_release(page);
        }

        EXIT;
}

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

int ll_check_dirty( struct super_block *sb)
{
        unsigned long old_flags; /* hack? */
        int making_progress;
        struct ll_writeback_pages *llwp;
        struct inode *inode;
        int rc = 0;
        ENTRY;

        if ( ! should_writeback() )
                return 0;

        old_flags = current->flags;
        current->flags |= PF_MEMALLOC;
        llwp = kmalloc(sizeof(struct ll_writeback_pages), GFP_ATOMIC);
        if ( llwp == NULL )
                GOTO(cleanup, rc = -ENOMEM);
        memset(llwp, 0, offsetof(struct ll_writeback_pages, pgs));

        spin_lock(&inode_lock);

        /*
         * first we try and write back dirty pages from dirty inodes
         * until the VM thinkgs we're ok again..
         */
        do {
                struct list_head *pos;
                inode = NULL;
                making_progress = 0;

                list_for_each_prev(pos, &sb->s_dirty) {
                        inode = list_entry(pos, struct inode, i_list);

                        if ( ! (inode->i_state & I_DIRTY_PAGES) ) {
                                inode = NULL;
                                continue;
                        }
                        break;
                }

                if ( inode == NULL )
                        break;

                /* duplicate __sync_one, *sigh* */
                list_del(&inode->i_list);
                list_add(&inode->i_list, &inode->i_sb->s_locked_inodes);
                inode->i_state |= I_LOCK;
                inode->i_state &= ~I_DIRTY_PAGES;

                spin_unlock(&inode_lock);

                do { 
                        memset(llwp, 0, sizeof(*llwp));
                        ll_get_dirty_pages(inode, llwp);
                        if ( llwp->num_pages ) {
                                ll_brw_pages_unlock(inode, llwp);
                                rc += llwp->num_pages;
                                making_progress = 1;
                        }
                } while (llwp->num_pages && should_writeback() );

                spin_lock(&inode_lock);

                if ( ! list_empty(&inode->i_mapping->dirty_pages) )
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

        } while ( making_progress && should_writeback() );

        /*
         * and if that didn't work, we sleep on any data that might
         * be under writeback..
         */
        while ( should_writeback() ) {
                if ( list_empty(&sb->s_locked_inodes) )  
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
        if ( llwp != NULL )
                kfree(llwp);
        current->flags = old_flags;

        RETURN(rc);
}

int ll_batch_writepage( struct inode *inode, struct page *page )
{
        unsigned long old_flags; /* hack? */
        struct ll_writeback_pages *llwp;
        int rc = 0;
        ENTRY;

        old_flags = current->flags;
        current->flags |= PF_MEMALLOC;
        llwp = kmalloc(sizeof(struct ll_writeback_pages), GFP_ATOMIC);
        if ( llwp == NULL )
                GOTO(cleanup, rc = -ENOMEM);
        memset(llwp, 0, offsetof(struct ll_writeback_pages, pgs));

        llwp_consume_page(llwp, inode, page);

        ll_get_dirty_pages(inode, llwp);
        if ( llwp->num_pages )
                ll_brw_pages_unlock(inode, llwp);

cleanup:
        if ( llwp != NULL )
                kfree(llwp);
        current->flags = old_flags;
        RETURN(rc);
}
