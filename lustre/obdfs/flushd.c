/*
 * OBDFS Super operations - also used for Lustre file system
 *
  *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 * Copryright (C) 1999 Stelias Computing Inc. <braam@stelias.com>
 * Copryright (C) 1999 Seagate Technology Inc.
 *
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/segment.h>
#include <linux/sched.h>

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


atatic void obdfs_flush_reqs(struct obdfs_super_info *sbi, int wait, 
			     int check_time) 
{
	struct list_head *wr;
	struct pg_req *req;
	
	wr = &si.s_wr_head;
	while ( (wr = wr->next) != &si.s_wr_head ) {
		req = list_entry(wr, struct pg_req, rq_list);

		if (!check_time || 
		    req->rq_jiffies <= (jiffies - pup_rpm.age_buffer)) {
			/* write request out to disk */
			obdfs_write_page(req->inode, req->page);
		}

	}

}


static void obdfs_flush_dirty_pages(int check_time)
{
	struct list_head *sl;

	sl = &obdfs_super_list;
	while ( (sl = sl->next) != &obdfs_super_listhead ) {
		struct obdfs_super_entry *entry = 
			list_entry(sl, struct obdfs_super_entry, sl_chain);
		struct obdfs_sb_info *sbi = sl->sl_sbi;

		/* walk write requests here */
		obdfs_flush_reqs(sbi, 0);
	}

	/* again, but now we wait for completion */
	sl = &obdfs_super_listhead;
	while ( (sl = sl->next) != &obdfs_super_listhead ) {
		struct obdfs_super_list *entry = 
			list_entry(sl, struct obdfs_super_list, sl_chain);
		struct super_block *sb = sl->sl_sb;

		/* walk write requests here */
		si = &sb->u.generic;
		obdfs_flush_reqs(si, 1);
	}
}

static struct task_struct *pupdatd;

static int pupdate(void) 
{
	struct task_struct * tsk = current;
	int interval;
	
	pupdated = current;
	tsk->session = 1;
	tsk->pgrp = 1;
	strcpy(tsk->comm, "pupdate");

	/* sigstop and sigcont will stop and wakeup kupdate */
	spin_lock_irq(&tsk->sigmask_lock);
	sigfillset(&tsk->blocked);
	siginitsetinv(&current->blocked, sigmask(SIGCONT) | sigmask(SIGSTOP));
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
			schedule(); /* wait for SIGCONT */
		}
		/* check for sigstop */
		if (signal_pending(tsk))
		{
			int stopped = 0;
			spin_lock_irq(&tsk->sigmask_lock);
			if (sigismember(&tsk->signal, SIGSTOP))
			{
				sigdelset(&tsk->signal, SIGSTOP);
				stopped = 1;
			}
			recalc_sigpending(tsk);
			spin_unlock_irq(&tsk->sigmask_lock);
			if (stopped)
				goto stop_pupdate;
		}
		printk("pupdate() activated...\n");
		/* flush_inodes(); */
		obdfs_flush_dirty_pages(1);
	}
}


int flushd_init(void)
{
	/*	kernel_thread(bdflush, NULL, CLONE_FS | CLONE_FILES | CLONE_SIGHAND); */
	kernel_thread(pupdate, NULL, CLONE_FS | CLONE_FILES | CLONE_SIGHAND);
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

}
