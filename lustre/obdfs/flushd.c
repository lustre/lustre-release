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
} pupd_prm = {40, 500, 64, 256, 5*HZ, 30*HZ, 5*HZ }; 


/* Remove writeback requests from an inode */
int obdfs_flush_reqs(struct list_head *page_list, 
			    int flush_inode, int check_time)
{
	struct list_head *tmp = page_list;
	obd_count	  num_io = 0;
	struct obdo	 *oa = NULL;
	struct obdo	 *obdos[MAX_IOVEC];
	struct page	 *pages[MAX_IOVEC];
	char		 *bufs[MAX_IOVEC];
	obd_size	  counts[MAX_IOVEC];
	obd_off		  offsets[MAX_IOVEC];
	obd_flag	  flags[MAX_IOVEC];
	int		  err = 0;
	int i;
	struct inode *inode = NULL;

	ENTRY;

	if ( list_empty(page_list)) {
		CDEBUG(D_INODE, "list empty\n");
		EXIT;
		return 0;
	}


	/* add all of the outstanding pages to a write vector, and write it */
	while ( (tmp = tmp->next) != page_list ) {
		struct obdfs_pgrq *pgrq;
		struct page	  *page;

		if ( flush_inode ) 
			pgrq = list_entry(tmp, struct obdfs_pgrq, rq_ilist);
		else 
			pgrq = list_entry(tmp, struct obdfs_pgrq, rq_slist);
		page = pgrq->rq_page;
		inode = pgrq->rq_inode;

		if (check_time && 
		    pgrq->rq_jiffies > (jiffies - pupd_prm.age_buffer))
			continue;
		
		oa = obdo_fromid(IID(inode), inode->i_ino, OBD_MD_FLNOTOBD);
		if ( IS_ERR(oa) ) {
			EXIT;
			return PTR_ERR(oa);
		}
		obdfs_from_inode(oa, inode);

		CDEBUG(D_INODE, "adding page %p to vector\n", page);
		obdos[num_io] = oa;
		bufs[num_io] = (char *)page_address(page);
		pages[num_io] = page;
		counts[num_io] = PAGE_SIZE;
		offsets[num_io] = ((obd_off)page->index) << PAGE_SHIFT;
		flags[num_io] = OBD_BRW_CREATE;
		num_io++;

		/* remove request from list before write to avoid conflict */
		obdfs_pgrq_del(pgrq);

		if ( num_io == MAX_IOVEC ) {
			err = obdfs_do_vec_wr(inode->i_sb, &num_io, obdos, 
					      pages,
					      bufs, counts, offsets, flags);
			for (i=0 ; i<MAX_IOVEC ; i++) {
				obdo_free(obdos[i]);
			if ( err ) {
				/* XXX Probably should handle error here -
				 *     discard other writes, or put
				 *     (MAX_IOVEC - num_io) I/Os back to list?
				 */
				EXIT;
				goto ERR;
			}
			}
			num_io = 0;
		}
	} 

	/* flush any remaining I/Os */
	if ( num_io ) {
		i = num_io - 1;
		err = obdfs_do_vec_wr(inode->i_sb, &num_io, obdos, pages, bufs,
				      counts, offsets, flags);
		for (  ; i>=0 ; i-- ) {
			obdo_free(obdos[i]);
		}
	}
	EXIT;
ERR:

	return err;
} /* obdfs_remove_pages_from_cache */


static void obdfs_flush_dirty_pages(int check_time)
{
	struct list_head *sl;
	struct obdfs_sb_info *sbi;

	sl = &obdfs_super_list;
	while ( (sl = sl->next) != &obdfs_super_list ) {
		struct obdfs_super_entry *entry = 
			list_entry(sl, struct obdfs_super_entry, sl_chain);
		sbi = entry->sl_sbi;

		/* walk write requests here, use the sb, check the time */
		obdfs_flush_reqs(&sbi->osi_pages, 0, 1);
	}

	/* again, but now we wait for completion */
	sl = &obdfs_super_list;
	while ( (sl = sl->next) != &obdfs_super_list ) {
		struct obdfs_super_entry *entry = 
			list_entry(sl, struct obdfs_super_entry, sl_chain);
		sbi = entry->sl_sbi;

		/* walk write requests here */
		obdfs_flush_reqs(&sbi->osi_pages, 0, check_time);
	}
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
			MOD_DEC_USE_COUNT;
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
		/* asynchronous setattr etc for the future ... */
		/* flush_inodes(); */
		CDEBUG(D_INODE, "about to flush pages...\n");
		obdfs_flush_dirty_pages(1);
		CDEBUG(D_INODE, "done flushing pages...\n");
	}
}


int flushd_init(void)
{
	/*	kernel_thread(bdflush, NULL, CLONE_FS | CLONE_FILES | CLONE_SIGHAND); */
	MOD_INC_USE_COUNT;
	kernel_thread(pupdate, NULL, 0);
	printk("flushd inited\n");
	return 0;
}

int flushd_cleanup(void)
{
	/* this should deliver a signal to */
	

	/* XXX Andreas, we will do this later, for now, you must kill
	   pupdated with a SIGSTOP from userland, before unloading obdfs.o
	*/
	if (pupdated) {
		/* send updated a STOP signal */
		/* then let it run at least once, before continuing */

		1;
	}

	/* not reached */
	return 0;

}
