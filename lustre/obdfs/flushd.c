/*
 * OBDFS Super operations - also used for Lustre file system
 *
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 * Copryright (C) 1999 Stelias Computing Inc. <braam@stelias.com>
 * Copryright (C) 1999 Seagate Technology Inc.
 *
 */
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/malloc.h>
#include <linux/locks.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <linux/sysrq.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/quotaops.h>
#include <linux/iobuf.h>
#include <linux/highmem.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/bitops.h>
#include <asm/mmu_context.h>

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obdfs.h>


struct {
	int nfract;  /* Percentage of buffer cache dirty to 
			activate bdflush */
	int ndirty;  /* Maximum number of dirty blocks to write out per
			wake-cycle */
	int nrefill; /* Number of clean buffers to try to obtain
				each time we call refill */
	int nref_dirt; /* Dirty buffer threshold for activating bdflush
			  when trying to refill buffers. */
	int interval; /* jiffies delay between kupdate flushes */
	int age_buffer;  /* Time for normal buffer to age before we flush it */
	int age_super;  /* Time for superblock to age before we flush it */
/* } pupd_prm = {40, 500, 64, 256, 5*HZ, 30*HZ, 5*HZ };  */
} pupd_prm = {40, 500, 64, 256, 10*HZ, 30*HZ, 5*HZ }; 

/* Called with the superblock list lock */
static int obdfs_enqueue_pages(struct inode *inode, struct obdo **obdo,
			       int nr_slots, struct page **pages, char **bufs,
			       obd_size *counts, obd_off *offsets,
			       obd_flag *flag, int check_time)
{
	struct list_head *page_list = obdfs_iplist(inode);
	struct list_head *tmp;
	int num = 0;

	ENTRY;
	OIDEBUG(inode);

	*obdo = obdo_fromid(IID(inode), inode->i_ino, OBD_MD_FLNOTOBD);
	if ( IS_ERR(*obdo) ) {
		EXIT;
		return PTR_ERR(*obdo);
	}

	obdfs_from_inode(*obdo, inode); /* FIXME revisit fromid & from_inode */
	*flag = OBD_BRW_CREATE;

	tmp = page_list;
	while ( ((tmp = tmp->next) != page_list) && (num < nr_slots) ) {
		struct obdfs_pgrq *req;
		struct page *page;
		
		req = list_entry(tmp, struct obdfs_pgrq, rq_plist);
		page = req->rq_page;

		
		if (check_time && 
		    (jiffies - req->rq_jiffies) < pupd_prm.age_buffer)
			continue;

		/* Remove request from list before write to avoid conflict.
		 * Note that obdfs_pgrq_del() also deletes the request.
		 */
		obdfs_pgrq_del(req);
		if ( !page ) {
			CDEBUG(D_INODE, "no page \n");
			continue;
		}

		bufs[num] = (char *)page_address(page);
		pages[num] = page;
		counts[num] = PAGE_SIZE;
		offsets[num] = ((obd_off)page->index) << PAGE_SHIFT;
		CDEBUG(D_INODE, "ENQ inode %ld, page %p addr %p to vector\n", 
		       inode->i_ino, page, (char *)page_address(page));
		num++;
	}

	if (!list_empty(page_list))
		CDEBUG(D_INODE, "inode %ld list not empty\n", inode->i_ino);
	CDEBUG(D_INODE, "added %d page(s) to vector\n", num);

	EXIT;
	return num;  
} /* obdfs_enqueue_pages */

/* dequeue requests for a dying inode */
void obdfs_dequeue_reqs(struct inode *inode)
{

	struct list_head *tmp;

	obd_down(&obdfs_i2sbi(inode)->osi_list_mutex);
	tmp = obdfs_islist(inode);
	if ( list_empty(tmp) ) {
		obd_up(&obdfs_i2sbi(inode)->osi_list_mutex);
		EXIT;
		return;
	}

	/* take it out of the super list */
	list_del(tmp);
	INIT_LIST_HEAD(obdfs_islist(inode));

	tmp = obdfs_iplist(inode);
	while ( (tmp = tmp->next) != obdfs_iplist(inode) ) {
		struct obdfs_pgrq *req;
		struct page *page;
		
		req = list_entry(tmp, struct obdfs_pgrq, rq_plist);
		page = req->rq_page;
		/* take it out of the list and free */
		obdfs_pgrq_del(req);
		/* now put the page away */
		put_page(page);
	}
	iput(inode);
	obd_up(&obdfs_i2sbi(inode)->osi_list_mutex);
} /* obdfs_dequeue_reqs */

/* Remove writeback requests for the superblock */
int obdfs_flush_reqs(struct list_head *inode_list, int check_time)
{
	struct list_head *tmp;
	int		  total_io = 0;
	obd_count	  num_io = 0;
	obd_count         num_obdos = 0;
	struct inode	 *inodes[MAX_IOVEC];	/* write data back to these */
	struct page	 *pages[MAX_IOVEC];	/* call put_page on these */
	struct obdo	 *obdos[MAX_IOVEC];
	char		 *bufs[MAX_IOVEC];
	obd_size	  counts[MAX_IOVEC];
	obd_off		  offsets[MAX_IOVEC];
	obd_flag	  flags[MAX_IOVEC];
	obd_count         bufs_per_obdo[MAX_IOVEC];
	int		  err = 0;
	struct obdfs_sb_info *sbi;


	ENTRY;

	if (!inode_list) {
		CDEBUG(D_INODE, "no list\n");
		EXIT;
		return 0;
	}

	sbi = list_entry(inode_list, struct obdfs_sb_info, osi_inodes);

	obd_down(&sbi->osi_list_mutex);
	if ( list_empty(inode_list)) {
		CDEBUG(D_INODE, "list empty\n");
		obd_up(&sbi->osi_list_mutex);
		EXIT;
		return 0;
	}

	/* add each inode's dirty pages to a write vector, and write it */
 again:
	tmp = inode_list;
	while ( (tmp = tmp->next) != inode_list && 
		total_io < pupd_prm.ndirty) {
		struct obdfs_inode_info *ii;
		struct inode *inode;
		int res;

		ii = list_entry(tmp, struct obdfs_inode_info, oi_inodes);
		inode = list_entry(ii, struct inode, u);
		inodes[num_obdos] = inode;
		CDEBUG(D_INODE, "checking inode %ld pages\n", inode->i_ino);

		res = 1;

		/* Loop on this inode until we can't get more pages from it
		 * (either no more pages, or the pages aren't old enough).
		 * Make sure we reference "inode" and not "inodes[num_obdos]",
		 * as num_obdos will change after the loop is run.
		 */
		while (!list_empty(obdfs_iplist(inode)) && res &&
		       total_io < pupd_prm.ndirty ) {
			res = obdfs_enqueue_pages(inode, &obdos[num_obdos],
						  MAX_IOVEC - num_io,
						  &pages[num_io], &bufs[num_io],
						  &counts[num_io],
						  &offsets[num_io],
						  &flags[num_obdos],
						  check_time);
			CDEBUG(D_INODE, "FLUSHED inode %ld, pages flushed: %d\n", 
			       inode->i_ino, res);
			if ( res < 0 ) {
				obd_up(&sbi->osi_list_mutex);
				err = res;
				goto ERR;
			}
			
			num_io += res;
			total_io += res;
			bufs_per_obdo[num_obdos] = res;
			num_obdos++;

			if ( num_io == MAX_IOVEC ) {
				obd_up(&sbi->osi_list_mutex);
				err = obdfs_do_vec_wr(inodes, num_io, num_obdos,
						      obdos, bufs_per_obdo,
						      pages, bufs, counts,
						      offsets, flags);
				if ( err ) {
					EXIT;
					goto ERR;
				}
				inodes[0] = inode;
				num_io = 0;
				num_obdos = 0;
				obd_down(&sbi->osi_list_mutex);
				goto again;
			}
		}
	}

	obd_up(&sbi->osi_list_mutex);

	/* flush any remaining I/Os */
	if ( num_io ) {
		err = obdfs_do_vec_wr(inodes, num_io, num_obdos, obdos,
				      bufs_per_obdo, pages, bufs, counts,
				      offsets, flags);
	}

	/* Remove inode from superblock dirty list when no more pages.
	 * Make sure we don't point at the current inode with tmp
	 * when we re-init the list on the inode, or we will loop.
	 */
	obd_down(&sbi->osi_list_mutex);
	tmp = inode_list;
	while ( (tmp = tmp->next) != inode_list ) {
		struct obdfs_inode_info *ii;
		struct inode *inode;

		ii = list_entry(tmp, struct obdfs_inode_info, oi_inodes);
		inode = list_entry(ii, struct inode, u);
		CDEBUG(D_INODE, "checking inode %ld empty\n", inode->i_ino);
		if (list_empty(obdfs_iplist(inode))) {
			CDEBUG(D_INODE, "remove inode %ld from dirty list\n",
			       inode->i_ino);
			tmp = tmp->prev;
			list_del(obdfs_islist(inode));
			iput(inode);
			INIT_LIST_HEAD(obdfs_islist(inode));
		}
	}
	obd_up(&sbi->osi_list_mutex);

	CDEBUG(D_INODE, "flushed %d pages in total\n", total_io);
	EXIT;
ERR:
	return err;
} /* obdfs_remove_pages_from_cache */


void obdfs_flush_dirty_pages(int check_time)
{
	struct list_head *sl;

	ENTRY;
	sl = &obdfs_super_list;
	while ( (sl = sl->next) != &obdfs_super_list ) {
		struct obdfs_sb_info *sbi = 
			list_entry(sl, struct obdfs_sb_info, osi_list);

		/* walk write requests here, use the sb, check the time */
		obdfs_flush_reqs(&sbi->osi_inodes, check_time);
	}
	EXIT;
}


static struct task_struct *pupdated;

static int pupdate(void *unused) 
{
	struct task_struct * tsk = current;
	int interval;
	
	pupdated = current;

	exit_files(current);
	exit_mm(current);

	tsk->session = 1;
	tsk->pgrp = 1;
	sprintf(tsk->comm, "pupdated");
	pupdated = current;

	MOD_INC_USE_COUNT;	/* XXX until send_sig works */
	printk("pupdated activated...\n");

	/* sigstop and sigcont will stop and wakeup pupdate */
	spin_lock_irq(&tsk->sigmask_lock);
	sigfillset(&tsk->blocked);
	siginitsetinv(&tsk->blocked, sigmask(SIGTERM));
	recalc_sigpending(tsk);
	spin_unlock_irq(&tsk->sigmask_lock);

	for (;;) {
		/* update interval */
		interval = pupd_prm.interval;
		if (interval)
		{
			tsk->state = TASK_INTERRUPTIBLE;
			schedule_timeout(interval);
		}
		else
		{
		stop_pupdate:
			tsk->state = TASK_STOPPED;
			MOD_DEC_USE_COUNT; /* XXX until send_sig works */
			printk("pupdated stopped...\n");
			return 0;
		}
		/* check for sigstop */
		if (signal_pending(tsk))
		{
			int stopped = 0;
			spin_lock_irq(&tsk->sigmask_lock);
			if (sigismember(&tsk->signal, SIGTERM))
			{
				sigdelset(&tsk->signal, SIGTERM);
				stopped = 1;
			}
			recalc_sigpending(tsk);
			spin_unlock_irq(&tsk->sigmask_lock);
			if (stopped)
				goto stop_pupdate;
		}
		/* asynchronous setattr etc for the future ...
		flush_inodes();
		 */
		/* we don't currently check the time on the pages
		obdfs_flush_dirty_pages(1); 
		 */
		obdfs_flush_dirty_pages(0); 
	}
}


int obdfs_flushd_init(void)
{
	/*
	kernel_thread(bdflush, NULL, CLONE_FS | CLONE_FILES | CLONE_SIGHAND);
	 */
	kernel_thread(pupdate, NULL, 0);
	printk("flushd inited\n");
	return 0;
}

int obdfs_flushd_cleanup(void)
{
	ENTRY;
	/* deliver a signal to pupdated to shut it down
	   XXX need to kill it from user space for now XXX
	if (pupdated) {
		send_sig_info(SIGTERM, 1, pupdated);
	}
	 */

	EXIT;
	/* not reached */
	return 0;

}
