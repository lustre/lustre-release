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

/* static void obdfs_flush_reqs(struct obdfs_super_info *sbi, int wait, 
			     
*/
static void obdfs_flush_reqs(struct obdfs_super_info *sbi, int check_time) 
{
	struct list_head *wr;
	struct obdfs_pgrq *req;
	
	wr = &sbi->s_wr_head;
	while ( (wr = wr->next) != &sbi->s_wr_head ) {
		req = list_entry(wr, struct obdfs_pgrq, rq_list);

		if (!check_time || 
		    req->rq_jiffies <= (jiffies - pupd_prm.age_buffer)) {
			/* write request out to disk */
			obdfs_do_writepage(req->rq_inode, req->rq_page, 1);
		}

	}

}


static void obdfs_flush_dirty_pages(int check_time)
{
	struct list_head *sl;
	struct obdfs_super_info *sbi;

	sl = &obdfs_super_list;
	while ( (sl = sl->next) != &obdfs_super_list ) {
		struct obdfs_super_entry *entry = 
			list_entry(sl, struct obdfs_super_entry, sl_chain);
		sbi = entry->sl_sbi;

		/* walk write requests here */
		obdfs_flush_reqs(sbi, jiffies);
	}

	/* again, but now we wait for completion */
	sl = &obdfs_super_list;
	while ( (sl = sl->next) != &obdfs_super_list ) {
		struct obdfs_super_entry *entry = 
			list_entry(sl, struct obdfs_super_entry, sl_chain);
		sbi = entry->sl_sbi;

		/* walk write requests here */
		/* XXX should jiffies be 0 here? */
		obdfs_flush_reqs(sbi, jiffies);
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
	sprintf(tsk->comm, "pupd");
	pupdated = current;

	printk("pupdate() activated...\n");

	/* sigstop and sigcont will stop and wakeup pupdate */
	spin_lock_irq(&tsk->sigmask_lock);
	sigfillset(&tsk->blocked);
	siginitsetinv(&tsk->blocked, sigmask(SIGCONT) | sigmask(SIGSTOP));
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
			printk("pupdate() stopped...\n");
			tsk->state = TASK_STOPPED;
			MOD_DEC_USE_COUNT;
			printk("RETURN from PUPD\n");
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
		/* flush_inodes(); */
		obdfs_flush_dirty_pages(1);
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
