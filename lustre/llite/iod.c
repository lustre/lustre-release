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
static inline void madd_page_to_inactive_clean_list(struct page * page)
{
	struct zone_struct * zone = page_zone(page);
	DEBUG_LRU_PAGE(page);
	SetPageInactiveClean(page);
	list_add(&page->lru, &zone->inactive_clean_list);
	zone->inactive_clean_pages++;
//	nr_inactive_clean_pages++;
}

static inline void mdel_page_from_active_list(struct page * page)
{
	struct zone_struct * zone = page_zone(page);
	list_del(&page->lru);
	ClearPageActive(page);
//	nr_active_pages--;
	zone->active_pages--;
	DEBUG_LRU_PAGE(page);
}

static inline void mdel_page_from_inactive_dirty_list(struct page * page)
{
	struct zone_struct * zone = page_zone(page);
	list_del(&page->lru);
	ClearPageInactiveDirty(page);
//	nr_inactive_dirty_pages--;
	zone->inactive_dirty_pages--;
	DEBUG_LRU_PAGE(page);
}

/* return value:
 * -1: no need to flush
 * 0:  need async flush
 * 1:  need sync flush
 *
 * Note: here we are more sensitive than kswapd, hope we could
 * do more flush work by ourselves, not resort to kswapd
 */
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

extern spinlock_t inode_lock;

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

        CDEBUG(D_CACHE, "liod(%d) started\n", current->pid);
        while (1) {
		int flushed;
		int t;

		/* check the stop command */
		if (test_bit(LIOD_FLAG_STOP, &iod->io_flag))
			break;

		t = interruptible_sleep_on_timeout(&iod->io_sleepq,
					       LIOD_WAKEUP_CYCLE*HZ);
		CDEBUG(D_NET, "liod(%d) active due to %s\n", current->pid,
				(t ? "wakeup" : "timeout"));

		printk("liod(%d) active due to %s\n", current->pid,
				(t ? "wakeup" : "timeout"));

		do {
			int times=0;

			flushed = flush_some_pages(sb);
			conditional_schedule();
			printk("iod: loop %d times\n", ++times);
		} while (flushed && (balance_dirty_state() >= 0));
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

/* syncronously flush certain amount of dirty pages right away
 * don't simply call fdatasync(), we need a more efficient way
 * to do flush in bunch mode.
 * FIXME now we simply flush pages on at most one inode, probably
 * need add multiple inode flush later.
 */
#define FLUSH_NR (32)
static int flush_some_pages(struct super_block *sb)
{
	struct brw_page *pgs;
	struct obd_brw_set *set;
	struct list_head *tmp;
	struct inode *inode;
	struct address_space *mapping;
	struct page *page;
	int cnt, rc;
	int a_c = 0, id_c = 0;

	set = obd_brw_set_new();
	if (!set) {
		CERROR("can't alloc obd_brw_set!\n");
		return 0;
	}

	OBD_ALLOC(pgs, FLUSH_NR * sizeof(struct brw_page));
	if (!pgs)
		goto out_free_set;

	/* FIXME simutanously gain inode_lock and pagecache_lock could
	 * cause busy spin forever? Check this */
	spin_lock(&inode_lock);

	{
		int n = 0;
		tmp = sb->s_dirty.prev;
		while (tmp != &sb->s_dirty) {
			n++;
			tmp = tmp->prev;
		}
		printk("dirty inode length %d\n", n);
	}

	/* sync dirty inodes from tail, since we try to sync
	 * from the oldest one */
	tmp = sb->s_dirty.prev;
	for (cnt = 0; cnt < FLUSH_NR; tmp = tmp->prev) {
		struct list_head *list, *next;

		/* no dirty inodes left */
		if (tmp == &sb->s_dirty)
			break;

		inode = list_entry(tmp, struct inode, i_list);
		mapping = inode->i_mapping;

		/* if inode is locked, it should be have been moved away
		 * from dirty list */
		if (inode->i_state & I_LOCK)
			LBUG();

		/* select candidate dirty pages within the inode */
		spin_lock(&pagecache_lock);
		/* if no dirty pages, search next inode */
		if (list_empty(&mapping->dirty_pages)) {
			spin_unlock(&pagecache_lock);
			continue;
		}

		list = mapping->dirty_pages.prev;
next_page:
		if (list == &mapping->dirty_pages) {
			/* no more dirty pages on this inode, and
			 * if we already got some, just quit */
			if (cnt)
				break;
			else {
				/* this inode have dirty pages, but all of
				 * them are locked by others or in fact clean
				 * ones, so continue search next inode */
				spin_unlock(&pagecache_lock);
				continue;
			}
		}

		next = list->prev;
		page = list_entry(list, struct page, list);

		/* flush pages only if we could gain the lock */
		if (!TryLockPage(page)) {
			/* remove from dirty list */
			list_del(&page->list);

			if (PageDirty(page)) {
				page_cache_get(page);
				/* add to locked list */
				list_add(&page->list, &mapping->locked_pages);
				//ClearPageDirty(page);

				select_one_page(&pgs[cnt++], inode, page);
				
				if (cnt >= FLUSH_NR) {
					spin_unlock(&pagecache_lock);
					continue;
				}
			} else {
				/* it's quite possible. add to clean list */
				list_add(&page->list, &mapping->clean_pages);
				UnlockPage(page);
			}
		} else {
			printk("skip page locked by others\n");
		}

		list = next;
		goto next_page;
	}

	spin_unlock(&inode_lock);

	if (cnt)
		printk("got %d pages of inode %lu to flush\n",
			cnt, inode->i_ino);
	else
		printk("didn't found dirty pages\n");

	if (!cnt)
		goto out_free_pgs;

	if (!inode)
		LBUG();

	CDEBUG(D_CACHE, "got %d pages of inode %lu to flush\n",
			cnt, inode->i_ino);

	set->brw_callback = ll_brw_sync_wait;
	rc = obd_brw(OBD_BRW_WRITE, ll_i2obdconn(inode),
                     ll_i2info(inode)->lli_smd, cnt, pgs, set);
	if (rc) {
		CERROR("error from obd_brw: rc = %d\n", rc);
	} else {
		rc = ll_brw_sync_wait(set, CB_PHASE_START);
		if (rc)
			CERROR("error from callback: rc = %d\n", rc);
	}

	/* finish the page status here */

	while (--cnt >= 0) {
		page = pgs[cnt].pg;

		LASSERT(PageLocked(page));

		if (!rc) {
			ClearPageDirty(page);

			/* move pages to clean list */
			spin_lock(&pagecache_lock);
			list_del(&page->list);
			list_add(&page->list, &inode->i_mapping->clean_pages);
			spin_unlock(&pagecache_lock);
#if 1
			//spin_lock(pagemap_lru_lock);
			pte_chain_lock(page);
			if (PageActive(page)) {
				mdel_page_from_active_list(page);
				madd_page_to_inactive_clean_list(page);
				a_c++;
			} else if (PageInactiveDirty(page)) {
				mdel_page_from_inactive_dirty_list(page);
				madd_page_to_inactive_clean_list(page);
				id_c++;
			}
			pte_chain_unlock(page);
			//spin_lunock(pagemap_lru_lock);
#endif
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

	printk("active-ic: %d, inactive_dirty-ic %d\n", a_c, id_c);
	spin_lock(&pagecache_lock);
	if (list_empty(&inode->i_mapping->dirty_pages))
		inode->i_state &= ~I_DIRTY_PAGES;
	spin_unlock(&pagecache_lock);


out_free_pgs:
	OBD_FREE(pgs, FLUSH_NR * sizeof(struct brw_page));
out_free_set:
	obd_brw_set_free(set);
	return (a_c+id_c);
}

void ll_balance_dirty_pages(struct super_block *sb)
{
	int flush;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	flush = balance_dirty_state();
	if (flush < 0)
		return;

	if (flush > 0) {
		int n, flush;
		do {
			n = 0;
			flush = flush_some_pages(sb);
			printk("ll_balance_dirty: loop %d times\n", ++n);
		} while (flush && (balance_dirty_state() > 0));
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
