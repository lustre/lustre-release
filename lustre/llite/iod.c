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
#include <linux/wait.h>

/* PG_inactive_clean is shorthand for rmap, we want free_high/low here.. */
#ifdef PG_inactive_clean
#include <linux/mm_inline.h>
#endif

#define DEBUG_SUBSYSTEM S_LLITE
#include <linux/lustre_lite.h>
#include "llite_internal.h"

#ifndef list_for_each_prev_safe
#define list_for_each_prev_safe(pos, n, head) \
        for (pos = (head)->prev, n = pos->prev; pos != (head); \
                pos = n, n = pos->prev )
#endif

extern spinlock_t inode_lock;

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
                ll_end_writeback(inode, page);
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

        ll_pgcache_lock(mapping);

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

        ll_pgcache_unlock(mapping);
        EXIT;
}

static void ll_writeback(struct inode *inode, struct obdo *oa,
                         struct ll_writeback_pages *llwp)
{
        struct ptlrpc_request_set *set;
        int rc, i;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),bytes=%u\n",
               inode->i_ino, inode->i_generation, inode,
               ((llwp->npgs-1) << PAGE_SHIFT) + llwp->pga[llwp->npgs-1].count);

        SIGNAL_MASK_ASSERT(); /* XXX BUG 1511 */
        set = ptlrpc_prep_set();
        if (set == NULL) {
                CERROR ("Can't create request set\n");
                rc = -ENOMEM;
        } else {
                rc = obd_brw_async(OBD_BRW_WRITE, ll_i2obdconn(inode), oa,
                                   ll_i2info(inode)->lli_smd, llwp->npgs,
                                   llwp->pga, set, NULL);
                if (rc == 0)
                        rc = ptlrpc_set_wait(set);
                if (rc == 0)
                        obdo_refresh_inode(inode, oa,
                                           oa->o_valid & ~OBD_MD_FLSIZE);
                ptlrpc_set_destroy(set);
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

                ll_end_writeback(inode, page);
                page_cache_release(page); /* to match llwp_consume_page */
        }

        EXIT;
}

static struct ll_writeback_pages *llwp_alloc(struct inode *inode)
{
        struct ll_writeback_pages *llwp;
        int size, max = (inode->i_blksize >> PAGE_CACHE_SHIFT);

        if (max == 0) {
                CERROR("forcing llwp->max to 1.  blksize: %lu\n",
                       inode->i_blksize);
                max = 1;
        }
        size = sizeof(*llwp) + (max * sizeof(struct brw_page));

        OBD_ALLOC(llwp, size);
        if (llwp == NULL)
                RETURN(ERR_PTR(-ENOMEM));
        llwp->max = max;
/* XXX don't worry, this will be gone before you know it.. */
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        llwp->inode = inode;
#endif

        RETURN(llwp);
}

void llwp_free(struct ll_writeback_pages *llwp)
{
        int size = sizeof(*llwp) + (llwp->max * sizeof(struct brw_page));
        OBD_FREE(llwp, size);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))

/* 2.4 doesn't give us a way to find out how many pages we have cached 'cause
 * we're not using buffer_heads.  we are very conservative here and flush the
 * superblock of all dirty data when the vm (rmap or stock) thinks that it is
 * running low and kswapd would have done work.  kupdated isn't good enough
 * because writers (dbench) can dirty _very quickly_, and we allocate under
 * writepage..
 */
#ifdef PG_inactive_clean  /* 2.4 rmap */

static int should_writeback(void)
{
        if (free_high(ALL_ZONES) > 0 || free_low(ANY_ZONE) > 0)
                return 1;
        return 0;
}

# else  /* stock 2.4 -aa zone vm */

#ifdef CONFIG_DISCONTIGMEM
#error "sorry, we don't support DISCONTIGMEM"
#endif
/*
 * __alloc_pages marks a zone as needing balancing if an allocation is
 * performed when the zone has fewer free pages than its 'low' water
 * mark.  its cleared when try_to_free_pages makes progress.
 */
static int should_writeback(void) /* aka zones_need_balancing */
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
#endif /* PG_inactive_clean detection of rmap vs stock */

int ll_check_dirty(struct super_block *sb)
{
        unsigned long old_flags; /* hack? */
        int making_progress;
        struct inode *inode;
        struct obdo oa;
        int rc = 0;
        ENTRY;

        if (!should_writeback())
                return 0;

        old_flags = current->flags;
        current->flags |= PF_MEMALLOC;

        spin_lock(&inode_lock);
        /*
         * we're trying to use a very awkward hammer to throttle lustre's
         * dirty data here.  as long as the vm thinks we're "low" we're
         * finding dirty inodes and writing out all their data.  the
         * second while loop is waiting for other threads who are doing
         * the same thing.. we ran into livelocks if one thread was able
         * to blow through here not finding dirty inodes because another
         * thread was busy writing them back..
         *
         * XXX this is all goofy because low memory can stop it from 
         * working properly.  someday we'll be pre-allocating io context
         * in prepare_write/commit_write.
         */
        do {
                struct ll_writeback_pages *llwp;
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

                /* lock the inode while we work on it, which duplicates
                 * __sync_one */
                list_del(&inode->i_list);
                list_add(&inode->i_list, &inode->i_sb->s_locked_inodes);
                inode->i_state |= I_LOCK;
                inode->i_state &= ~I_DIRTY_PAGES;

                spin_unlock(&inode_lock);
                llwp = llwp_alloc(inode);
                spin_lock(&inode_lock);

                if (IS_ERR(llwp)) /* making_progress == 0 will break the loop */
                        goto unlock_inode;

                spin_unlock(&inode_lock);

                do {
                        llwp->npgs = 0;
                        ll_get_dirty_pages(inode, llwp);
                        if (llwp->npgs) {
                                oa.o_id =
                                      ll_i2info(inode)->lli_smd->lsm_object_id;
                                oa.o_valid = OBD_MD_FLID;
                                obdo_from_inode(&oa, inode,
                                                OBD_MD_FLTYPE|OBD_MD_FLATIME|
                                                OBD_MD_FLMTIME|OBD_MD_FLCTIME);

                                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                                    LPROC_LL_WB_PRESSURE,
                                                    llwp->npgs);
                                ll_writeback(inode, &oa, llwp);
                                rc += llwp->npgs;
                                making_progress = 1;
                        }
                } while (llwp->npgs && should_writeback());

                llwp_free(llwp);

                spin_lock(&inode_lock);

unlock_inode:
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

        current->flags = old_flags;
        RETURN(rc);
}

/* called from writepage and allows us to also try and write out other
 * pages.  only called from 2.4 because 2.5 has ->writepages() */
int ll_batch_writepage(struct inode *inode, struct obdo *oa, struct page *page)
{
        unsigned long old_flags; /* hack? */
        struct ll_writeback_pages *llwp;
        int rc = 0;
        ENTRY;

        SIGNAL_MASK_ASSERT(); /* XXX BUG 1511 */
        old_flags = current->flags;
        current->flags |= PF_MEMALLOC;
        llwp = llwp_alloc(inode);
        if (IS_ERR(llwp))
                GOTO(restore_flags, PTR_ERR(llwp));

        if (llwp_consume_page(llwp, inode, page) == 0)
                ll_get_dirty_pages(inode, llwp);

        if (llwp->npgs) {
                lprocfs_counter_add(ll_i2sbi(inode)->ll_stats,
                                    LPROC_LL_WB_WRITEPAGE, llwp->npgs);
                ll_writeback(inode, oa, llwp);
        }
        llwp_free(llwp);

restore_flags:
        current->flags = old_flags;
        RETURN(rc);
}
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
/* we use a singly linked list of page->private to pass pages between
 * readpage/writepage and our worker threads without allocating things
 * and while maintaining fifo order.. */
void plist_init(struct plist *plist) {
        plist->pl_head = NULL;
        plist->pl_tail = NULL;
        plist->pl_num = 0;
}
struct page *plist_get_page(struct plist *plist) {
        struct page *page = plist->pl_head;

        if (page == NULL)
                return NULL;

        plist->pl_head = (struct page *)page->private;
        if (page == plist->pl_tail)
                plist->pl_tail = NULL;
        plist->pl_num--;
        page->private = 0;

        return page;
}
void plist_move(struct plist *to, struct plist *from)
{
        if (to->pl_head == NULL) 
                *to = *from;
        else {
                to->pl_tail->private = (unsigned long)from->pl_head;
                to->pl_tail = from->pl_tail;
                to->pl_num += from->pl_num;
        }
        plist_init(from);
}
void plist_add_page(struct plist *plist, struct page *page)
{
        LASSERT(page->private == 0);
        if (plist->pl_tail) {
                plist->pl_tail->private = (unsigned long)page;
                plist->pl_tail = page;
        } else {
                plist->pl_head = page;
                plist->pl_tail = page;
        }
        plist->pl_num++;
}

void lliod_wakeup(struct inode *inode)
{
        struct lliod_ctl *lc = &ll_i2sbi(inode)->ll_lc;
        wake_up(&lc->lc_waitq);
        lc->lc_new_arrival = 1;
}

/* wake_lliod can be skipped if the path knows that more lliod_give_s will
 * be coming before the path waits on the pages.. it must be called before
 * waiting so that new_arrival is set and lliod comes out of its l_wait */
void lliod_give_plist(struct inode *inode, struct plist *plist, int rw)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lliod_ctl *lc = &ll_i2sbi(inode)->ll_lc;

        CDEBUG(D_CACHE, "rw: %d plist %p num %d\n", rw, plist, 
                        plist ? plist->pl_num : 0);

        if (plist)
                LASSERT(rw == OBD_BRW_READ || rw == OBD_BRW_WRITE);

        spin_lock(&lc->lc_lock);
        if (list_empty(&lli->lli_lc_item)) 
                list_add_tail(&lli->lli_lc_item, &lc->lc_lli_list);

        if (plist) {
                if (rw == OBD_BRW_WRITE) 
                        plist_move(&lli->lli_pl_write, plist);
                else
                        plist_move(&lli->lli_pl_read, plist);
        }
        spin_unlock(&lc->lc_lock);
}

void lliod_give_page(struct inode *inode, struct page *page, int rw)
{
        struct plist plist;

        plist_init(&plist);
        plist_add_page(&plist, page);
        lliod_give_plist(inode, &plist, rw);
}

/* XXX should so something smart with the 'rc' depending on the failover
 * configuration  */
void lliod_complete_llwp(struct inode *inode, struct ll_writeback_pages *llwp,
                         int rc)
{
        struct page *page;
        int i;

        CDEBUG(D_CACHE, "inode: %p rw: %d rc: %d\n", inode, llwp->rw, rc);

        for (i = 0 ; i < llwp->npgs ; i++) {
                page = llwp->pga[i].pg;

                CDEBUG(D_CACHE, "page: %p index: %lu\n", page, page->index);
                if (llwp->rw == OBD_BRW_WRITE)
                        ll_end_writeback(inode, page);
                else {
                        SetPageUptodate(page);
                        unlock_page(page);
                }

                page_cache_release(page); /* to match llwp_consume_page */
        }
}

/* ok, the clump thing wasn't so hot, lets just do brws as writepage hands
 * us pages.  to avoid inter-inode or read/write starvation we take the
 * pages off the lli and then consume them all, first reads then writes */
int lliod_brw(struct lliod_ctl *lc)
{
        struct inode *inode = NULL;
        struct ll_inode_info *lli = NULL;
        struct ll_writeback_pages *llwp;
        struct ptlrpc_request_set *set = NULL;
        struct page *page;
        struct plist plist_read, plist_write, *plist;
        int rc = 0, rw, tmp;
        ENTRY;

        plist_init(&plist_read);
        plist_init(&plist_write);

        spin_lock(&lc->lc_lock);
        if (list_empty(&lc->lc_lli_list)) {
                spin_unlock(&lc->lc_lock);
                RETURN(0);
        }

        lli = list_entry(lc->lc_lli_list.next, struct ll_inode_info, 
                         lli_lc_item);
        inode = ll_info2i(lli);
        list_del_init(&lli->lli_lc_item);

        plist_move(&plist_read, &lli->lli_pl_read);
        plist_move(&plist_write, &lli->lli_pl_write);

        spin_unlock(&lc->lc_lock);

        llwp = llwp_alloc(inode);
        if (IS_ERR(llwp)) {
                rc = -ENOMEM;
                goto out;
        }

        if (plist_read.pl_num) {
                plist = &plist_read;
                rw = OBD_BRW_READ;
        } else {
                plist = &plist_write;
                rw = OBD_BRW_WRITE;
        }

        CDEBUG(D_CACHE, "inode %p #r: %d #w: %d\n", inode, plist_read.pl_num,
               plist_write.pl_num);

        while (plist->pl_num > 0) {
                struct obdo oa;

                set = ptlrpc_prep_set();
                if (set == NULL) {
                        rc = -ENOMEM;
                        break;
                }

                llwp->npgs = 0;
                llwp->rw = rw;
                llwp->inode = inode;
                while ((page = plist_get_page(plist))) {
                        tmp = llwp_consume_page(llwp, inode, page);
                        page_cache_release(page); /* from writepage */
                        if (tmp)
                                break;
                }
                oa.o_id = lli->lli_smd->lsm_object_id;
                oa.o_valid = OBD_MD_FLID;
                obdo_from_inode(&oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                            OBD_MD_FLMTIME | OBD_MD_FLCTIME);
                tmp = obd_brw_async(rw, ll_i2obdconn(inode), &oa,
                                   ll_i2info(inode)->lli_smd, 
                                   llwp->npgs, llwp->pga, set, NULL);
                if (tmp == 0)
                        tmp = ptlrpc_set_wait(set);

                ptlrpc_set_destroy(set);
                lliod_complete_llwp(inode, llwp, tmp);

                if (plist->pl_num == 0 && rw == OBD_BRW_READ) {
                        plist = &plist_write;
                        rw = OBD_BRW_WRITE;
                }
        }

        llwp_free(llwp);
out:
        if (rc) {
                lliod_give_plist(inode, &plist_read, OBD_BRW_READ);
                lliod_give_plist(inode, &plist_write, OBD_BRW_WRITE);
        }

        RETURN(rc);
}
             
static int lliod(void *arg)
{
        struct lliod_ctl *lc = arg;
        ENTRY;

        kportal_daemonize("liod_writeback");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
        sigfillset(&current->blocked);
        recalc_sigpending();
#else
        spin_lock_irqsave(&current->sigmask_lock, flags);
        sigfillset(&current->blocked);
        recalc_sigpending(current);
        spin_unlock_irqrestore(&current->sigmask_lock, flags);
#endif

        complete(&lc->lc_starting);

        /* like kswapd */
        current->flags |= PF_MEMALLOC;

        while (1) {

                /* XXX re-using the clu waitq for now; its harmless.. 
                 * we'll update the path depending on clu's fate */ 
                wait_event_interruptible(lc->lc_waitq,
                                ( test_bit(LIOD_STOP, &lc->lc_flags) ||
                                  (!list_empty(&lc->lc_lli_list)) ) );

                if (test_bit(LIOD_STOP, &lc->lc_flags))
                        break;

                /* sleep for a short amount of time if we get -ENOMEM, 
                 * maybe giving the world a chance to free some memory
                 * for us */
                if (lliod_brw(lc)) {
                        set_current_state(TASK_INTERRUPTIBLE);
                        schedule_timeout(HZ/100);
                }

        }
        /* XXX should be making sure we don't have inodes/
         * pages still in flight */
        complete(&lc->lc_finishing);
        return 0;
}

int lliod_start(struct ll_sb_info *sbi, struct inode *inode)
{
        struct lliod_ctl *lc = &sbi->ll_lc;
        ENTRY;

        init_completion(&lc->lc_starting);
        init_completion(&lc->lc_finishing);
        INIT_LIST_HEAD(&lc->lc_lli_list);
        init_waitqueue_head(&lc->lc_waitq);
        lc->lc_flags = 0;
        lc->lc_new_arrival = 0;
        spin_lock_init(&lc->lc_lock);

        if (kernel_thread(lliod, &sbi->ll_lc, 0) < 0) 
                RETURN(-ECHILD);

        wait_for_completion(&lc->lc_starting);
        RETURN(0);
}

void lliod_stop(struct ll_sb_info *sbi)
{
        struct lliod_ctl *lc = &sbi->ll_lc;

        set_bit(LIOD_STOP, &lc->lc_flags);
        wake_up(&lc->lc_waitq);
        wait_for_completion(&lc->lc_finishing);
}
#endif /* 2.5 check.. */
