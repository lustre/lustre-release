#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/kmod.h>
#include <linux/pagemap.h>
#include <linux/low-latency.h>
#include <linux/mm_inline.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_LLITE
#include <linux/lustre_lite.h>

/* wakeup every 30s */
#define LIOD_WAKEUP_CYCLE	(30)

/* FIXME tempororily copy from mm_inline.h */
static inline void __add_page_to_inactive_clean_list(struct page * page)
{
	struct zone_struct * zone = page_zone(page);
	DEBUG_LRU_PAGE(page);
	SetPageInactiveClean(page);
	list_add(&page->lru, &zone->inactive_clean_list);
	zone->inactive_clean_pages++;
//	nr_inactive_clean_pages++;
}

static inline void __del_page_from_active_list(struct page * page)
{
	struct zone_struct * zone = page_zone(page);
	list_del(&page->lru);
	ClearPageActive(page);
//	nr_active_pages--;
	zone->active_pages--;
	DEBUG_LRU_PAGE(page);
}

static inline void __del_page_from_inactive_dirty_list(struct page * page)
{
	struct zone_struct * zone = page_zone(page);
	list_del(&page->lru);
	ClearPageInactiveDirty(page);
//	nr_inactive_dirty_pages--;
	zone->inactive_dirty_pages--;
	DEBUG_LRU_PAGE(page);
}

/* move page into inactive_clean list.
 *
 * caller need to make sure that this page is not used
 * by anyothers
 */
void refile_clean_page(struct page *page)
{
        LASSERT(PageLocked(page));
	LASSERT(!PageDirty(page));

        ClearPageReferenced(page);
	page->age = 0;

        spin_lock(&pagemap_lru_lock);
        if (PageActive(page)) {
                __del_page_from_active_list(page);
                __add_page_to_inactive_clean_list(page);
        } else if (PageInactiveClean(page)) {
                __del_page_from_inactive_dirty_list(page);
                __add_page_to_inactive_clean_list(page);
        }
        spin_unlock(&pagemap_lru_lock);
}


/* return value:
 * -1: no need to flush
 * 0:  need async flush
 * 1:  need sync flush
 *
 * Note: here we are more sensitive than kswapd, hope we could
 * do more flush work by ourselves, not resort to kswapd
 */
#if 0
static inline int balance_dirty_state(void)
{
	if (free_high(ALL_ZONES) > 0) {
		printk("memory low, sync flush\n");
		return 1;
	}
	if (free_plenty(ALL_ZONES) > 0) {
		printk("memory high, async flush\n");
		return 0;
	}
	else
		return -1;
}
#else
/* FIXME need verify the parameters later */
static inline int balance_dirty_state(void)
{
	if (free_plenty(ALL_ZONES) > -2048) {
		return 1;
	}
	if (free_plenty(ALL_ZONES) > -4096) {
		return 0;
	}

	return -1;
}
#endif
extern spinlock_t inode_lock;
extern void wakeup_kswapd(unsigned int gfp_mask);

static int flush_some_pages(struct super_block *sb);

/* the main liod loop */
static int liod_main(void *arg)
{
	struct super_block *sb = (struct super_block *)arg;
        struct ll_io_daemon *iod = &ll_s2sbi(sb)->ll_iod;

        ENTRY;

        lock_kernel();
        daemonize();
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        spin_lock_irq(&current->sigmask_lock);
        sigfillset(&current->blocked);
        our_recalc_sigpending(current);
        spin_unlock_irq(&current->sigmask_lock);
#else
        sigfillset(&current->blocked);
        our_recalc_sigpending(current);
#endif

        sprintf(current->comm, "liod");
        unlock_kernel();

        /* declare we are ready */
	set_bit(LIOD_FLAG_ALIVE, &iod->io_flag);
        wake_up(&iod->io_waitq);

#if 0
	current->flags |= PF_KERNTHREAD;
#endif

#if 0
	pgdat_list->node_zones[0].pages_min *= 2;
	pgdat_list->node_zones[0].pages_low *= 2;
	pgdat_list->node_zones[0].pages_high *= 2;
	pgdat_list->node_zones[0].pages_plenty *= 2;
#endif

        CDEBUG(D_CACHE, "liod(%d) started\n", current->pid);
        while (1) {
		int flushed;
		int t;

		/* check the stop command */
		if (test_bit(LIOD_FLAG_STOP, &iod->io_flag)) {
			/* at umount time, should not be anyone
			 * trying to flushing pages */
			LASSERT(!waitqueue_active(&iod->io_sem.wait));
			break;
		}

		t = interruptible_sleep_on_timeout(&iod->io_sleepq,
					       LIOD_WAKEUP_CYCLE*HZ);
		CDEBUG(D_NET, "liod(%d) active due to %s\n", current->pid,
				(t ? "wakeup" : "timeout"));

		/* try to flush */
		down(&iod->io_sem);
		do {
			flushed = flush_some_pages(sb);
			conditional_schedule();
		} while (flushed && (balance_dirty_state() >= 0));
		up(&iod->io_sem);

		/* if still out of balance, it shows all dirty
		 * pages generate by this llite are flushing or
		 * flushed, so inbalance must be caused by other
		 * part of the kernel. here we wakeup kswapd
		 * immediately, it probably too earliar (because
		 * we are more sensitive than kswapd), but could
		 * gurantee the the amount of free+inactive_clean
		 * pages, at least could accelerate aging of pages
		 *
		 * Note: it start kswapd and return immediately
		 */
		if (balance_dirty_state() >= 0)
			wakeup_kswapd(GFP_ATOMIC);
	}

	clear_bit(LIOD_FLAG_ALIVE, &iod->io_flag);
        wake_up(&iod->io_waitq);

        CDEBUG(D_NET, "liod(%d) exit\n", current->pid);
        RETURN(0);
}

int liod_start(struct super_block *sb)
{
	struct ll_io_daemon *iod = &ll_s2sbi(sb)->ll_iod;
        int rc;

        /* initialize */
        iod->io_flag = 0;
        init_waitqueue_head(&iod->io_sleepq);
        init_waitqueue_head(&iod->io_waitq);
	init_MUTEX(&iod->io_sem);

        rc = kernel_thread(liod_main, (void *) sb,
                           CLONE_VM | CLONE_FS | CLONE_FILES);

        if (rc < 0) {
		CERROR("fail to start liod, error %d\n", rc);
                return rc;
        }

	/* wait liod start */
	wait_event(iod->io_waitq, test_bit(LIOD_FLAG_ALIVE, &iod->io_flag));

        return 0;
}

static inline void liod_wakeup(struct ll_io_daemon *iod)
{
        wake_up(&iod->io_sleepq);
}

static inline void select_one_page(struct brw_page *pg,
                                   struct inode *inode,
                                   struct page *page)
{
	obd_off off;

	pg->pg = page;
	pg->off = ((obd_off)page->index) << PAGE_SHIFT;
	pg->flag = OBD_BRW_CREATE;

	off = ((obd_off)(page->index + 1)) << PAGE_SHIFT;
	if (off > inode->i_size)
		pg->count = inode->i_size & ~PAGE_MASK;
	else
		pg->count = PAGE_SIZE;
}

/* select candidate dirty pages within an inode
 * return:
 * - npgs contains number of pages selected
 * - 0: all pages in dirty list are searched
 *   1: probably still have dirty pages
 *
 * don't sleep in this functions
 * */
static int select_inode_pages(struct inode *inode, struct brw_page *pgs, int *npgs)
{
	int nrmax = *npgs, nr = 0;
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	struct list_head *list, *end;

	LASSERT(nrmax <= LIOD_FLUSH_NR);

	*npgs = 0;

	spin_lock(&pagecache_lock);

	/* if no dirty pages, just return */
	if (list_empty(&mapping->dirty_pages)) {
		spin_unlock(&pagecache_lock);
		return 0;
	}

	list = mapping->dirty_pages.prev;
	end = &mapping->dirty_pages;
	while (nr < nrmax) {
		/* no more dirty pages on this inode */
		if (list == end)
			break;

		page = list_entry(list, struct page, list);
		list = list->prev;

		/* flush pages only if we could gain the lock */
		if (!TryLockPage(page)) {
			/* remove from dirty list */
			list_del(&page->list);

			if (PageDirty(page)) {
				page_cache_get(page);
				/* add to locked list */
				list_add(&page->list, &mapping->locked_pages);

				select_one_page(&pgs[nr++], inode, page);
				
				if (nr >= nrmax)
					break;
			} else {
				/* it's quite possible. add to clean list */
				list_add(&page->list, &mapping->clean_pages);
				UnlockPage(page);
			}
		} else {
			if (list == &mapping->dirty_pages)
				break;

			/* move to head */
			list_del(&page->list);
			list_add(&page->list, &mapping->dirty_pages);
			if (end == &mapping->dirty_pages)
				end = &page->list;
		}
	}
	spin_unlock(&pagecache_lock);

	*npgs = nr;

	if (list == end)
		return 0;
	else
		return 1;
}

static int bulk_flush_pages(
		struct inode *inode,
		int npgs,
		struct brw_page *pgs,
		struct obd_brw_set *set)
{
	struct page *page;
	int rc;
	
	set->brw_callback = ll_brw_sync_wait;
	rc = obd_brw(OBD_BRW_WRITE, ll_i2obdconn(inode),
                     ll_i2info(inode)->lli_smd, npgs, pgs, set);
	if (rc) {
		CERROR("error from obd_brw: rc = %d\n", rc);
	} else {
		rc = ll_brw_sync_wait(set, CB_PHASE_START);
		if (rc)
			CERROR("error from callback: rc = %d\n", rc);
	}

	rc = 0;

	while (--npgs >= 0) {
		page = pgs[npgs].pg;

		LASSERT(PageLocked(page));

		if (!rc) {
			ClearPageDirty(page);

			/* move pages to clean list */
			spin_lock(&pagecache_lock);
			list_del(&page->list);
			list_add(&page->list, &inode->i_mapping->clean_pages);
			spin_unlock(&pagecache_lock);

			refile_clean_page(page);
			rc++;
		} else {
			SetPageDirty(page);

			/* add back to dirty list */
			spin_lock(&pagecache_lock);
			list_del(&page->list);
			list_add(&page->list, &inode->i_mapping->dirty_pages);
			spin_unlock(&pagecache_lock);
		}
		UnlockPage(page);

		page_cache_release(page);
	}

	spin_lock(&pagecache_lock);
	if (list_empty(&inode->i_mapping->dirty_pages))
		inode->i_state &= ~I_DIRTY_PAGES;
	spin_unlock(&pagecache_lock);

	return rc;
}

/* synchronously flush certain amount of dirty pages right away
 * don't simply call fdatasync(), we need a more efficient way
 * to do flush in bunch mode.
 *
 * return the number of pages were flushed
 *
 * caller should gain the sbi->io_sem lock
 *
 * now we simply flush pages on at most one inode, probably
 * need add multiple inode flush later.
 */
static int flush_some_pages(struct super_block *sb)
{
	struct ll_io_daemon *iod;
	struct brw_page *pgs;
	struct obd_brw_set *set;
	struct list_head *list, *end;
	struct inode *inode;
	int npgs;

	iod = &ll_s2sbi(sb)->ll_iod;
	set = &iod->io_set;
	pgs = iod->io_pgs;

	/* init set */
        init_waitqueue_head(&set->brw_waitq);
        INIT_LIST_HEAD(&set->brw_desc_head);
        atomic_set(&set->brw_refcount, 0);

	spin_lock(&inode_lock);

	/* sync dirty inodes from tail, since we try to sync
	 * from the oldest one */
	npgs = 0;
	list = sb->s_dirty.prev;
	end = &sb->s_dirty;
	while (1) {
		int ret;
			
		/* no dirty inodes left */
		if (list == end)
			break;

		inode = list_entry(list, struct inode, i_list);
		list = list->next;

		/* if inode is locked, it should have been moved away
		 * from dirty list */
		LASSERT(!(inode->i_state & I_LOCK));

		npgs = LIOD_FLUSH_NR;
		ret = select_inode_pages(inode, pgs, &npgs);

		/* quit if found some pages */
		if (npgs) {
			/* if all pages are searched on this inode,
			 * we could move it to the list head */
			if (!ret) {
				list_del(&inode->i_list);
				list_add(&inode->i_list, &sb->s_dirty);
			}
			break;
		} else {
			/* no page found */
			if (list == &sb->s_dirty)
				break;
			/* move inode to the end of list */
			list_del(&inode->i_list);
			list_add(&inode->i_list, &sb->s_dirty);
			if (end == &sb->s_dirty)
				end = &inode->i_list;
		}
	}
	spin_unlock(&inode_lock);

	if (!npgs)
		return 0;

	LASSERT(inode);

	CDEBUG(D_CACHE, "got %d pages of inode %lu to flush\n",
			npgs, inode->i_ino);

	return bulk_flush_pages(inode, npgs, pgs, set);
}

void ll_balance_dirty_pages(struct super_block *sb)
{
	int flush;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	flush = balance_dirty_state();
	if (flush < 0)
		return;

	if (flush > 0) {
		int n = 0, flush;

		if (!down_trylock(&sbi->ll_iod.io_sem)) {
			do {
				flush = flush_some_pages(sb);
			} while (flush && (balance_dirty_state() > 0));

			up(&sbi->ll_iod.io_sem);

			/* this will sleep until kswapd wakeup us.
			 * it maybe low efficient but hope could
			 * slow down the memory-allocation a bit */
			if (balance_dirty_state() >= 0)
				wakeup_kswapd(GFP_KSWAPD);
		}
	}

	/* FIXME we need a way to wake up liods on *all* llite fs */
	liod_wakeup(&sbi->ll_iod);
}

void liod_stop(struct super_block *sb)
{
	struct ll_io_daemon *iod = &ll_s2sbi(sb)->ll_iod;

	if (!test_bit(LIOD_FLAG_ALIVE, &iod->io_flag)) {
		CERROR("liod died unexpectedly!\n");
		return;
	}

        /* send the kill command */
	set_bit(LIOD_FLAG_STOP, &iod->io_flag);

        /* if wakeup daemon */
        wake_up(&iod->io_sleepq);

	/* wait liod exit */
	wait_event(iod->io_waitq, !test_bit(LIOD_FLAG_ALIVE, &iod->io_flag));

	return;
}
