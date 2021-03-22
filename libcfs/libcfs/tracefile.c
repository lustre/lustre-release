/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/libcfs/tracefile.c
 *
 * Author: Zach Brown <zab@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LNET
#include "tracefile.h"

#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <libcfs/linux/linux-fs.h>
#include <libcfs/libcfs.h>


enum cfs_trace_buf_type {
	CFS_TCD_TYPE_PROC = 0,
	CFS_TCD_TYPE_SOFTIRQ,
	CFS_TCD_TYPE_IRQ,
	CFS_TCD_TYPE_CNT
};

union cfs_trace_data_union (*cfs_trace_data[CFS_TCD_TYPE_CNT])[NR_CPUS] __cacheline_aligned;

char cfs_tracefile[TRACEFILE_NAME_SIZE];
long long cfs_tracefile_size = CFS_TRACEFILE_SIZE;

struct task_struct *tctl_task;

static atomic_t cfs_tage_allocated = ATOMIC_INIT(0);
static DECLARE_RWSEM(cfs_tracefile_sem);

static void put_pages_on_tcd_daemon_list(struct page_collection *pc,
					struct cfs_trace_cpu_data *tcd);

/* trace file lock routines */
/* The walking argument indicates the locking comes from all tcd types
 * iterator and we must lock it and dissable local irqs to avoid deadlocks
 * with other interrupt locks that might be happening. See LU-1311
 * for details.
 */
int cfs_trace_lock_tcd(struct cfs_trace_cpu_data *tcd, int walking)
	__acquires(&tcd->tcd_lock)
{
	__LASSERT(tcd->tcd_type < CFS_TCD_TYPE_CNT);
	if (tcd->tcd_type == CFS_TCD_TYPE_IRQ)
		spin_lock_irqsave(&tcd->tcd_lock, tcd->tcd_lock_flags);
	else if (tcd->tcd_type == CFS_TCD_TYPE_SOFTIRQ)
		spin_lock_bh(&tcd->tcd_lock);
	else if (unlikely(walking))
		spin_lock_irq(&tcd->tcd_lock);
	else
		spin_lock(&tcd->tcd_lock);
	return 1;
}

void cfs_trace_unlock_tcd(struct cfs_trace_cpu_data *tcd, int walking)
	__releases(&tcd->tcd_lock)
{
	__LASSERT(tcd->tcd_type < CFS_TCD_TYPE_CNT);
	if (tcd->tcd_type == CFS_TCD_TYPE_IRQ)
		spin_unlock_irqrestore(&tcd->tcd_lock, tcd->tcd_lock_flags);
	else if (tcd->tcd_type == CFS_TCD_TYPE_SOFTIRQ)
		spin_unlock_bh(&tcd->tcd_lock);
	else if (unlikely(walking))
		spin_unlock_irq(&tcd->tcd_lock);
	else
		spin_unlock(&tcd->tcd_lock);
}

#define cfs_tcd_for_each(tcd, i, j)					\
	for (i = 0; i < CFS_TCD_TYPE_CNT && cfs_trace_data[i]; i++)	\
		for (j = 0, ((tcd) = &(*cfs_trace_data[i])[j].tcd);	\
		     j < num_possible_cpus();				\
		     j++, (tcd) = &(*cfs_trace_data[i])[j].tcd)

#define cfs_tcd_for_each_type_lock(tcd, i, cpu)				\
	for (i = 0; i < CFS_TCD_TYPE_CNT && cfs_trace_data[i] &&	\
	     (tcd = &(*cfs_trace_data[i])[cpu].tcd) &&			\
	     cfs_trace_lock_tcd(tcd, 1); cfs_trace_unlock_tcd(tcd, 1), i++)

enum cfs_trace_buf_type cfs_trace_buf_idx_get(void)
{
	if (in_irq())
		return CFS_TCD_TYPE_IRQ;
	if (in_softirq())
		return CFS_TCD_TYPE_SOFTIRQ;
	return CFS_TCD_TYPE_PROC;
}

static inline struct cfs_trace_cpu_data *
cfs_trace_get_tcd(void)
{
	struct cfs_trace_cpu_data *tcd =
		&(*cfs_trace_data[cfs_trace_buf_idx_get()])[get_cpu()].tcd;

	cfs_trace_lock_tcd(tcd, 0);

	return tcd;
}

static inline void cfs_trace_put_tcd(struct cfs_trace_cpu_data *tcd)
{
	cfs_trace_unlock_tcd(tcd, 0);

	put_cpu();
}

static inline struct cfs_trace_page *
cfs_tage_from_list(struct list_head *list)
{
	return list_entry(list, struct cfs_trace_page, linkage);
}

static struct cfs_trace_page *cfs_tage_alloc(gfp_t gfp)
{
	struct page            *page;
	struct cfs_trace_page *tage;

	/* My caller is trying to free memory */
	if (!in_interrupt() && (current->flags & PF_MEMALLOC))
		return NULL;

	/*
	 * Don't spam console with allocation failures: they will be reported
	 * by upper layer anyway.
	 */
	gfp |= __GFP_NOWARN;
	page = alloc_page(gfp);
	if (page == NULL)
		return NULL;

	tage = kmalloc(sizeof(*tage), gfp);
	if (tage == NULL) {
		__free_page(page);
		return NULL;
	}

	tage->page = page;
	atomic_inc(&cfs_tage_allocated);
	return tage;
}

static void cfs_tage_free(struct cfs_trace_page *tage)
{
	__LASSERT(tage != NULL);
	__LASSERT(tage->page != NULL);

	__free_page(tage->page);
	kfree(tage);
	atomic_dec(&cfs_tage_allocated);
}

static void cfs_tage_to_tail(struct cfs_trace_page *tage,
			     struct list_head *queue)
{
	__LASSERT(tage != NULL);
	__LASSERT(queue != NULL);

	list_move_tail(&tage->linkage, queue);
}

/* return a page that has 'len' bytes left at the end */
static struct cfs_trace_page *
cfs_trace_get_tage_try(struct cfs_trace_cpu_data *tcd, unsigned long len)
{
	struct cfs_trace_page *tage;
	struct task_struct *tsk;

	if (tcd->tcd_cur_pages > 0) {
		__LASSERT(!list_empty(&tcd->tcd_pages));
		tage = cfs_tage_from_list(tcd->tcd_pages.prev);
		if (tage->used + len <= PAGE_SIZE)
			return tage;
	}

	if (tcd->tcd_cur_pages < tcd->tcd_max_pages) {
		if (tcd->tcd_cur_stock_pages > 0) {
			tage = cfs_tage_from_list(tcd->tcd_stock_pages.prev);
			--tcd->tcd_cur_stock_pages;
			list_del_init(&tage->linkage);
		} else {
			tage = cfs_tage_alloc(GFP_ATOMIC);
			if (unlikely(tage == NULL)) {
				if ((!(current->flags & PF_MEMALLOC) ||
				     in_interrupt()) && printk_ratelimit())
					pr_warn("Lustre: cannot allocate a tage (%ld)\n",
						tcd->tcd_cur_pages);
				return NULL;
			}
		}

		tage->used = 0;
		tage->cpu = smp_processor_id();
		tage->type = tcd->tcd_type;
		list_add_tail(&tage->linkage, &tcd->tcd_pages);
		tcd->tcd_cur_pages++;

		tsk = tctl_task;
		if (tcd->tcd_cur_pages > 8 && tsk)
			/*
			 * wake up tracefiled to process some pages.
			 */
			wake_up_process(tsk);

		return tage;
	}
	return NULL;
}

static void cfs_tcd_shrink(struct cfs_trace_cpu_data *tcd)
{
	int pgcount = tcd->tcd_cur_pages / 10;
	struct page_collection pc;
	struct cfs_trace_page *tage;
	struct cfs_trace_page *tmp;

	/*
	 * XXX nikita: do NOT call portals_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */

	if (printk_ratelimit())
		pr_warn("Lustre: debug daemon buffer overflowed; discarding 10%% of pages (%d of %ld)\n",
			pgcount + 1, tcd->tcd_cur_pages);

	INIT_LIST_HEAD(&pc.pc_pages);

	list_for_each_entry_safe(tage, tmp, &tcd->tcd_pages, linkage) {
		if (pgcount-- == 0)
			break;

		list_move_tail(&tage->linkage, &pc.pc_pages);
		tcd->tcd_cur_pages--;
	}
	put_pages_on_tcd_daemon_list(&pc, tcd);
}

/* return a page that has 'len' bytes left at the end */
static struct cfs_trace_page *cfs_trace_get_tage(struct cfs_trace_cpu_data *tcd,
						 unsigned long len)
{
	struct cfs_trace_page *tage;

	/*
	 * XXX nikita: do NOT call portals_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */

	if (len > PAGE_SIZE) {
		pr_err("LustreError: cowardly refusing to write %lu bytes in a page\n",
		       len);
		return NULL;
	}

	tage = cfs_trace_get_tage_try(tcd, len);
	if (tage != NULL)
		return tage;
	if (tctl_task)
		cfs_tcd_shrink(tcd);
	if (tcd->tcd_cur_pages > 0) {
		tage = cfs_tage_from_list(tcd->tcd_pages.next);
		tage->used = 0;
		cfs_tage_to_tail(tage, &tcd->tcd_pages);
	}
	return tage;
}

static void cfs_set_ptldebug_header(struct ptldebug_header *header,
				    struct libcfs_debug_msg_data *msgdata,
				    unsigned long stack)
{
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);

	header->ph_subsys = msgdata->msg_subsys;
	header->ph_mask = msgdata->msg_mask;
	header->ph_cpu_id = smp_processor_id();
	header->ph_type = cfs_trace_buf_idx_get();
	/* y2038 safe since all user space treats this as unsigned, but
	 * will overflow in 2106
	 */
	header->ph_sec = (u32)ts.tv_sec;
	header->ph_usec = ts.tv_nsec / NSEC_PER_USEC;
	header->ph_stack = stack;
	header->ph_pid = current->pid;
	header->ph_line_num = msgdata->msg_line;
	header->ph_extern_pid = 0;
}

/**
 * tty_write_msg - write a message to a certain tty, not just the console.
 * @tty: the destination tty_struct
 * @msg: the message to write
 *
 * tty_write_message is not exported, so write a same function for it
 *
 */
static void tty_write_msg(struct tty_struct *tty, const char *msg)
{
	mutex_lock(&tty->atomic_write_lock);
	tty_lock(tty);
	if (tty->ops->write && tty->count > 0)
		tty->ops->write(tty, msg, strlen(msg));
	tty_unlock(tty);
	mutex_unlock(&tty->atomic_write_lock);
	wake_up_interruptible_poll(&tty->write_wait, POLLOUT);
}

static void cfs_tty_write_message(const char *prefix, int mask, const char *msg)
{
	struct tty_struct *tty;

	tty = get_current_tty();
	if (!tty)
		return;

	tty_write_msg(tty, prefix);
	if ((mask & D_EMERG) || (mask & D_ERROR))
		tty_write_msg(tty, "Error");
	tty_write_msg(tty, ": ");
	tty_write_msg(tty, msg);
	tty_kref_put(tty);
}

static void cfs_vprint_to_console(struct ptldebug_header *hdr, int mask,
				  struct va_format *vaf, const char *file,
				  const char *fn)
{
	char *prefix = "Lustre";

	if (hdr->ph_subsys == S_LND || hdr->ph_subsys == S_LNET)
		prefix = "LNet";

	if (mask & D_CONSOLE) {
		if (mask & D_EMERG)
			pr_emerg("%sError: %pV", prefix, vaf);
		else if (mask & D_ERROR)
			pr_err("%sError: %pV", prefix, vaf);
		else if (mask & D_WARNING)
			pr_warn("%s: %pV", prefix, vaf);
		else if (mask & libcfs_printk)
			pr_info("%s: %pV", prefix, vaf);
	} else {
		if (mask & D_EMERG)
			pr_emerg("%sError: %d:%d:(%s:%d:%s()) %pV", prefix,
				 hdr->ph_pid, hdr->ph_extern_pid, file,
				 hdr->ph_line_num, fn, vaf);
		else if (mask & D_ERROR)
			pr_err("%sError: %d:%d:(%s:%d:%s()) %pV", prefix,
			       hdr->ph_pid, hdr->ph_extern_pid, file,
			       hdr->ph_line_num, fn, vaf);
		else if (mask & D_WARNING)
			pr_warn("%s: %d:%d:(%s:%d:%s()) %pV", prefix,
				hdr->ph_pid, hdr->ph_extern_pid, file,
				hdr->ph_line_num, fn, vaf);
		else if (mask & (D_CONSOLE | libcfs_printk))
			pr_info("%s: %pV", prefix, vaf);
	}

	if (mask & D_TTY)
		/* tty_write_msg doesn't handle formatting */
		cfs_tty_write_message(prefix, mask, vaf->fmt);
}

static void cfs_print_to_console(struct ptldebug_header *hdr, int mask,
				 const char *file, const char *fn,
				 const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	cfs_vprint_to_console(hdr, mask, &vaf, file, fn);
}

int libcfs_debug_msg(struct libcfs_debug_msg_data *msgdata,
		     const char *format, ...)
{
	struct cfs_trace_cpu_data *tcd = NULL;
	struct ptldebug_header header = {0};
	struct cfs_trace_page *tage;
	/* string_buf is used only if tcd != NULL, and is always set then */
	char *string_buf = NULL;
	char *debug_buf;
	int known_size;
	int needed = 85; /* seeded with average message length */
	int max_nob;
	va_list ap;
	int retry;
	int mask = msgdata->msg_mask;
	char *file = (char *)msgdata->msg_file;
	struct cfs_debug_limit_state *cdls = msgdata->msg_cdls;

	if (strchr(file, '/'))
		file = strrchr(file, '/') + 1;

	tcd = cfs_trace_get_tcd();

	/* cfs_trace_get_tcd() grabs a lock, which disables preemption and
	 * pins us to a particular CPU.  This avoids an smp_processor_id()
	 * warning on Linux when debugging is enabled.
	 */
	cfs_set_ptldebug_header(&header, msgdata, CDEBUG_STACK());

	if (!tcd)                /* arch may not log in IRQ context */
		goto console;

	if (tcd->tcd_cur_pages == 0)
		header.ph_flags |= PH_FLAG_FIRST_RECORD;

	if (tcd->tcd_shutting_down) {
		cfs_trace_put_tcd(tcd);
		tcd = NULL;
		goto console;
	}

	known_size = strlen(file) + 1;
	if (msgdata->msg_fn)
		known_size += strlen(msgdata->msg_fn) + 1;

	if (libcfs_debug_binary)
		known_size += sizeof(header);

	/*
	 * May perform an additional pass to update 'needed' and increase
	 * tage buffer size to match vsnprintf reported size required
	 * On the second pass (retry=1) use vscnprintf [which returns
	 * number of bytes written not including the terminating nul]
	 * to clarify `needed` is used as number of bytes written
	 * for the remainder of this function
	 */
	for (retry = 0; retry < 2; retry++) {
		tage = cfs_trace_get_tage(tcd, needed + known_size + 1);
		if (!tage) {
			if (needed + known_size > PAGE_SIZE)
				mask |= D_ERROR;

			cfs_trace_put_tcd(tcd);
			tcd = NULL;
			goto console;
		}

		string_buf = (char *)page_address(tage->page) +
			     tage->used + known_size;

		max_nob = PAGE_SIZE - tage->used - known_size;
		if (max_nob <= 0) {
			pr_emerg("LustreError: negative max_nob: %d\n",
				 max_nob);
			mask |= D_ERROR;
			cfs_trace_put_tcd(tcd);
			tcd = NULL;
			goto console;
		}

		va_start(ap, format);
		if (retry)
			needed = vscnprintf(string_buf, max_nob, format, ap);
		else
			needed = vsnprintf(string_buf, max_nob, format, ap);
		va_end(ap);

		if (needed < max_nob) /* well. printing ok.. */
			break;
	}

	/* `needed` is actual bytes written to string_buf */
	if (*(string_buf + needed - 1) != '\n') {
		pr_info("Lustre: format at %s:%d:%s doesn't end in newline\n",
			file, msgdata->msg_line, msgdata->msg_fn);
	} else if (mask & D_TTY) {
		/* TTY needs '\r\n' to move carriage to leftmost position */
		if (needed < 2 || *(string_buf + needed - 2) != '\r')
			pr_info("Lustre: format at %s:%d:%s doesn't end in '\\r\\n'\n",
				file, msgdata->msg_line, msgdata->msg_fn);
		if (strnchr(string_buf, needed, '%'))
			pr_info("Lustre: format at %s:%d:%s mustn't contain %%\n",
				file, msgdata->msg_line, msgdata->msg_fn);
	}

	header.ph_len = known_size + needed;
	debug_buf = (char *)page_address(tage->page) + tage->used;

	if (libcfs_debug_binary) {
		memcpy(debug_buf, &header, sizeof(header));
		tage->used += sizeof(header);
		debug_buf += sizeof(header);
	}

	strlcpy(debug_buf, file, PAGE_SIZE - tage->used);
	tage->used += strlen(file) + 1;
	debug_buf += strlen(file) + 1;

	if (msgdata->msg_fn) {
		strlcpy(debug_buf, msgdata->msg_fn, PAGE_SIZE - tage->used);
		tage->used += strlen(msgdata->msg_fn) + 1;
		debug_buf += strlen(msgdata->msg_fn) + 1;
	}

	__LASSERT(debug_buf == string_buf);

	tage->used += needed;
	__LASSERT(tage->used <= PAGE_SIZE);

console:
	if ((mask & libcfs_printk) == 0) {
		/* no console output requested */
		if (tcd != NULL)
			cfs_trace_put_tcd(tcd);
		return 1;
	}

	if (cdls != NULL) {
		if (libcfs_console_ratelimit &&
		    cdls->cdls_next != 0 &&	/* not first time ever */
		    time_before(jiffies, cdls->cdls_next)) {
			/* skipping a console message */
			cdls->cdls_count++;
			if (tcd != NULL)
				cfs_trace_put_tcd(tcd);
			return 1;
		}

		if (time_after(jiffies, cdls->cdls_next +
					libcfs_console_max_delay +
					cfs_time_seconds(10))) {
			/* last timeout was a long time ago */
			cdls->cdls_delay /= libcfs_console_backoff * 4;
		} else {
			cdls->cdls_delay *= libcfs_console_backoff;
		}

		if (cdls->cdls_delay < libcfs_console_min_delay)
			cdls->cdls_delay = libcfs_console_min_delay;
		else if (cdls->cdls_delay > libcfs_console_max_delay)
			cdls->cdls_delay = libcfs_console_max_delay;

		/* ensure cdls_next is never zero after it's been seen */
		cdls->cdls_next = (jiffies + cdls->cdls_delay) | 1;
	}

	if (tcd) {
		cfs_print_to_console(&header, mask, file, msgdata->msg_fn,
				     "%s", string_buf);
		cfs_trace_put_tcd(tcd);
	} else {
		struct va_format vaf;

		va_start(ap, format);
		vaf.fmt = format;
		vaf.va = &ap;
		cfs_vprint_to_console(&header, mask,
				      &vaf, file, msgdata->msg_fn);
		va_end(ap);
	}

	if (cdls != NULL && cdls->cdls_count != 0) {
		/* Do not allow print this to TTY */
		cfs_print_to_console(&header, mask & ~D_TTY, file,
				     msgdata->msg_fn,
				     "Skipped %d previous similar message%s\n",
				     cdls->cdls_count,
				     (cdls->cdls_count > 1) ? "s" : "");

		cdls->cdls_count = 0;
	}

	return 0;
}
EXPORT_SYMBOL(libcfs_debug_msg);

void
cfs_trace_assertion_failed(const char *str,
			   struct libcfs_debug_msg_data *msgdata)
{
	struct ptldebug_header hdr;

	libcfs_panic_in_progress = 1;
	libcfs_catastrophe = 1;
	smp_mb();

	cfs_set_ptldebug_header(&hdr, msgdata, CDEBUG_STACK());

	cfs_print_to_console(&hdr, D_EMERG, msgdata->msg_file, msgdata->msg_fn,
			     "%s", str);

	panic("Lustre debug assertion failure\n");

	/* not reached */
}

static void
panic_collect_pages(struct page_collection *pc)
{
	/* Do the collect_pages job on a single CPU: assumes that all other
	 * CPUs have been stopped during a panic.  If this isn't true for some
	 * arch, this will have to be implemented separately in each arch.  */
	int			   i;
	int			   j;
	struct cfs_trace_cpu_data *tcd;

	INIT_LIST_HEAD(&pc->pc_pages);

	cfs_tcd_for_each(tcd, i, j) {
		list_splice_init(&tcd->tcd_pages, &pc->pc_pages);
		tcd->tcd_cur_pages = 0;

		if (pc->pc_want_daemon_pages) {
			list_splice_init(&tcd->tcd_daemon_pages,
						&pc->pc_pages);
			tcd->tcd_cur_daemon_pages = 0;
		}
	}
}

static void collect_pages_on_all_cpus(struct page_collection *pc)
{
	struct cfs_trace_cpu_data *tcd;
	int i, cpu;

	for_each_possible_cpu(cpu) {
		cfs_tcd_for_each_type_lock(tcd, i, cpu) {
			list_splice_init(&tcd->tcd_pages, &pc->pc_pages);
			tcd->tcd_cur_pages = 0;
			if (pc->pc_want_daemon_pages) {
				list_splice_init(&tcd->tcd_daemon_pages,
							&pc->pc_pages);
				tcd->tcd_cur_daemon_pages = 0;
			}
		}
	}
}

static void collect_pages(struct page_collection *pc)
{
	INIT_LIST_HEAD(&pc->pc_pages);

	if (libcfs_panic_in_progress)
		panic_collect_pages(pc);
	else
		collect_pages_on_all_cpus(pc);
}

static void put_pages_back_on_all_cpus(struct page_collection *pc)
{
        struct cfs_trace_cpu_data *tcd;
	struct list_head *cur_head;
        struct cfs_trace_page *tage;
        struct cfs_trace_page *tmp;
        int i, cpu;

	for_each_possible_cpu(cpu) {
                cfs_tcd_for_each_type_lock(tcd, i, cpu) {
                        cur_head = tcd->tcd_pages.next;

			list_for_each_entry_safe(tage, tmp, &pc->pc_pages,
						 linkage) {

				__LASSERT_TAGE_INVARIANT(tage);

				if (tage->cpu != cpu || tage->type != i)
					continue;

				cfs_tage_to_tail(tage, cur_head);
				tcd->tcd_cur_pages++;
			}
		}
	}
}

static void put_pages_back(struct page_collection *pc)
{
        if (!libcfs_panic_in_progress)
                put_pages_back_on_all_cpus(pc);
}

/* Add pages to a per-cpu debug daemon ringbuffer.  This buffer makes sure that
 * we have a good amount of data at all times for dumping during an LBUG, even
 * if we have been steadily writing (and otherwise discarding) pages via the
 * debug daemon. */
static void put_pages_on_tcd_daemon_list(struct page_collection *pc,
					 struct cfs_trace_cpu_data *tcd)
{
	struct cfs_trace_page *tage;
	struct cfs_trace_page *tmp;

	list_for_each_entry_safe(tage, tmp, &pc->pc_pages, linkage) {
		__LASSERT_TAGE_INVARIANT(tage);

		if (tage->cpu != tcd->tcd_cpu || tage->type != tcd->tcd_type)
			continue;

		cfs_tage_to_tail(tage, &tcd->tcd_daemon_pages);
		tcd->tcd_cur_daemon_pages++;

		if (tcd->tcd_cur_daemon_pages > tcd->tcd_max_pages) {
			struct cfs_trace_page *victim;

			__LASSERT(!list_empty(&tcd->tcd_daemon_pages));
			victim = cfs_tage_from_list(tcd->tcd_daemon_pages.next);

                        __LASSERT_TAGE_INVARIANT(victim);

			list_del(&victim->linkage);
			cfs_tage_free(victim);
			tcd->tcd_cur_daemon_pages--;
		}
	}
}

static void put_pages_on_daemon_list(struct page_collection *pc)
{
        struct cfs_trace_cpu_data *tcd;
        int i, cpu;

	for_each_possible_cpu(cpu) {
                cfs_tcd_for_each_type_lock(tcd, i, cpu)
                        put_pages_on_tcd_daemon_list(pc, tcd);
        }
}

#ifdef LNET_DUMP_ON_PANIC
void cfs_trace_debug_print(void)
{
	struct page_collection pc;
	struct cfs_trace_page *tage;
	struct cfs_trace_page *tmp;

	pc.pc_want_daemon_pages = 1;
	collect_pages(&pc);
	list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {
		char *p, *file, *fn;
		struct page *page;

		__LASSERT_TAGE_INVARIANT(tage);

		page = tage->page;
		p = page_address(page);
		while (p < ((char *)page_address(page) + tage->used)) {
			struct ptldebug_header *hdr;
			int len;
			hdr = (void *)p;
			p += sizeof(*hdr);
			file = p;
			p += strlen(file) + 1;
			fn = p;
			p += strlen(fn) + 1;
			len = hdr->ph_len - (int)(p - (char *)hdr);

			cfs_print_to_console(hdr, D_EMERG, file, fn,
					     "%.*s", len, p);

			p += len;
		}

		list_del(&tage->linkage);
		cfs_tage_free(tage);
	}
}
#endif /* LNET_DUMP_ON_PANIC */

int cfs_tracefile_dump_all_pages(char *filename)
{
	struct page_collection	pc;
	struct file		*filp;
	struct cfs_trace_page	*tage;
	struct cfs_trace_page	*tmp;
	char			*buf;
	int rc;

	down_write(&cfs_tracefile_sem);

	filp = filp_open(filename, O_CREAT|O_EXCL|O_WRONLY|O_LARGEFILE, 0600);
	if (IS_ERR(filp)) {
		rc = PTR_ERR(filp);
		filp = NULL;
		pr_err("LustreError: can't open %s for dump: rc = %d\n",
		      filename, rc);
		goto out;
	}

        pc.pc_want_daemon_pages = 1;
        collect_pages(&pc);
	if (list_empty(&pc.pc_pages)) {
                rc = 0;
                goto close;
        }

	/* ok, for now, just write the pages.  in the future we'll be building
	 * iobufs with the pages and calling generic_direct_IO */
	list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {

		__LASSERT_TAGE_INVARIANT(tage);

		buf = kmap(tage->page);
		rc = cfs_kernel_write(filp, buf, tage->used, &filp->f_pos);
		kunmap(tage->page);
		if (rc != (int)tage->used) {
			pr_warn("Lustre: wanted to write %u but wrote %d\n",
				tage->used, rc);
			put_pages_back(&pc);
			__LASSERT(list_empty(&pc.pc_pages));
			break;
		}
		list_del(&tage->linkage);
                cfs_tage_free(tage);
        }

	rc = vfs_fsync_range(filp, 0, LLONG_MAX, 1);
	if (rc)
		pr_err("LustreError: sync returns: rc = %d\n", rc);
close:
	filp_close(filp, NULL);
out:
	up_write(&cfs_tracefile_sem);
	return rc;
}

void cfs_trace_flush_pages(void)
{
	struct page_collection pc;
	struct cfs_trace_page *tage;

	pc.pc_want_daemon_pages = 1;
	collect_pages(&pc);
	while (!list_empty(&pc.pc_pages)) {
		tage = list_first_entry(&pc.pc_pages,
					struct cfs_trace_page, linkage);
		__LASSERT_TAGE_INVARIANT(tage);

		list_del(&tage->linkage);
		cfs_tage_free(tage);
	}
}

int cfs_trace_copyout_string(char __user *usr_buffer, int usr_buffer_nob,
                             const char *knl_buffer, char *append)
{
        /* NB if 'append' != NULL, it's a single character to append to the
         * copied out string - usually "\n", for /proc entries and "" (i.e. a
         * terminating zero byte) for sysctl entries */
        int   nob = strlen(knl_buffer);

        if (nob > usr_buffer_nob)
                nob = usr_buffer_nob;

	if (copy_to_user(usr_buffer, knl_buffer, nob))
                return -EFAULT;

        if (append != NULL && nob < usr_buffer_nob) {
		if (copy_to_user(usr_buffer + nob, append, 1))
                        return -EFAULT;

                nob++;
        }

        return nob;
}
EXPORT_SYMBOL(cfs_trace_copyout_string);

int cfs_trace_dump_debug_buffer_usrstr(void __user *usr_str, int usr_str_nob)
{
	char *str;
	char *path;
	int rc;

	str = memdup_user_nul(usr_str, usr_str_nob);
	if (!str)
		return -ENOMEM;

	path = strim(str);
	if (path[0] != '/')
		rc = -EINVAL;
	else
		rc = cfs_tracefile_dump_all_pages(path);
	kfree(str);

	return rc;
}

int cfs_trace_daemon_command(char *str)
{
        int       rc = 0;

	down_write(&cfs_tracefile_sem);

        if (strcmp(str, "stop") == 0) {
		up_write(&cfs_tracefile_sem);
                cfs_trace_stop_thread();
		down_write(&cfs_tracefile_sem);
                memset(cfs_tracefile, 0, sizeof(cfs_tracefile));

	} else if (strncmp(str, "size=", 5) == 0) {
		unsigned long tmp;

		rc = kstrtoul(str + 5, 10, &tmp);
		if (!rc) {
			if (tmp < 10 || tmp > 20480)
				cfs_tracefile_size = CFS_TRACEFILE_SIZE;
			else
				cfs_tracefile_size = tmp << 20;
		}
        } else if (strlen(str) >= sizeof(cfs_tracefile)) {
                rc = -ENAMETOOLONG;
        } else if (str[0] != '/') {
                rc = -EINVAL;
        } else {
		strcpy(cfs_tracefile, str);

		pr_info("Lustre: debug daemon will attempt to start writing to %s (%lukB max)\n",
			cfs_tracefile, (long)(cfs_tracefile_size >> 10));

		cfs_trace_start_thread();
        }

	up_write(&cfs_tracefile_sem);
        return rc;
}

int cfs_trace_daemon_command_usrstr(void __user *usr_str, int usr_str_nob)
{
	char *str;
	int   rc;

	str = memdup_user_nul(usr_str, usr_str_nob);
	if (!str)
		return -ENOMEM;

	rc = cfs_trace_daemon_command(strim(str));
	kfree(str);

	return rc;
}

int cfs_trace_set_debug_mb(int mb)
{
	int i;
	int j;
	unsigned long pages;
	unsigned long total_mb = (cfs_totalram_pages() >> (20 - PAGE_SHIFT));
	unsigned long limit = max_t(unsigned long, 512, (total_mb * 4) / 5);
	struct cfs_trace_cpu_data *tcd;

	if (mb < num_possible_cpus()) {
		pr_warn("Lustre: %d MB is too small for debug buffer size, setting it to %d MB.\n",
			mb, num_possible_cpus());
		mb = num_possible_cpus();
	}

	if (mb > limit) {
		pr_warn("Lustre: %d MB is too large for debug buffer size, setting it to %lu MB.\n",
			mb, limit);
		mb = limit;
	}

	mb /= num_possible_cpus();
	pages = mb << (20 - PAGE_SHIFT);

	down_write(&cfs_tracefile_sem);

	cfs_tcd_for_each(tcd, i, j)
		tcd->tcd_max_pages = (pages * tcd->tcd_pages_factor) / 100;

	up_write(&cfs_tracefile_sem);

	return mb;
}

int cfs_trace_get_debug_mb(void)
{
        int i;
        int j;
        struct cfs_trace_cpu_data *tcd;
        int total_pages = 0;

	down_read(&cfs_tracefile_sem);

        cfs_tcd_for_each(tcd, i, j)
                total_pages += tcd->tcd_max_pages;

	up_read(&cfs_tracefile_sem);

	return (total_pages >> (20 - PAGE_SHIFT)) + 1;
}

static int tracefiled(void *arg)
{
	struct page_collection pc;
	struct cfs_trace_page *tage;
	struct cfs_trace_page *tmp;
	struct file *filp;
	char *buf;
	int last_loop = 0;
	int rc;

	pc.pc_want_daemon_pages = 0;

	while (!last_loop) {
		schedule_timeout_interruptible(cfs_time_seconds(1));
		if (kthread_should_stop())
			last_loop = 1;
		collect_pages(&pc);
		if (list_empty(&pc.pc_pages))
			continue;

		filp = NULL;
		down_read(&cfs_tracefile_sem);
		if (cfs_tracefile[0] != 0) {
			filp = filp_open(cfs_tracefile,
					 O_CREAT | O_RDWR | O_LARGEFILE,
					 0600);
			if (IS_ERR(filp)) {
				rc = PTR_ERR(filp);
				filp = NULL;
				pr_warn("Lustre: couldn't open %s: rc = %d\n",
					cfs_tracefile, rc);
			}
		}
		up_read(&cfs_tracefile_sem);
		if (filp == NULL) {
			put_pages_on_daemon_list(&pc);
			__LASSERT(list_empty(&pc.pc_pages));
			continue;
		}

		list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {
			struct dentry *de = file_dentry(filp);
			static loff_t f_pos;

			__LASSERT_TAGE_INVARIANT(tage);

			if (f_pos >= (off_t)cfs_tracefile_size)
				f_pos = 0;
			else if (f_pos > i_size_read(de->d_inode))
				f_pos = i_size_read(de->d_inode);

			buf = kmap(tage->page);
			rc = cfs_kernel_write(filp, buf, tage->used, &f_pos);
			kunmap(tage->page);
			if (rc != (int)tage->used) {
				pr_warn("Lustre: wanted to write %u but wrote %d\n",
					tage->used, rc);
				put_pages_back(&pc);
				__LASSERT(list_empty(&pc.pc_pages));
				break;
			}
		}

		filp_close(filp, NULL);
		put_pages_on_daemon_list(&pc);
		if (!list_empty(&pc.pc_pages)) {
			int i;

			pr_alert("Lustre: trace pages aren't empty\n");
			pr_err("Lustre: total cpus(%d): ", num_possible_cpus());
			for (i = 0; i < num_possible_cpus(); i++)
				if (cpu_online(i))
					pr_cont("%d(on) ", i);
				else
					pr_cont("%d(off) ", i);
			pr_cont("\n");

			i = 0;
			list_for_each_entry_safe(tage, tmp, &pc.pc_pages,
						 linkage)
				pr_err("Lustre: page %d belongs to cpu %d\n",
				       ++i, tage->cpu);
			pr_err("Lustre: There are %d pages unwritten\n", i);
		}
		__LASSERT(list_empty(&pc.pc_pages));
	}

	return 0;
}

int cfs_trace_start_thread(void)
{
	struct task_struct *tsk;
	int rc = 0;

	if (tctl_task)
		return 0;

	tsk = kthread_create(tracefiled, NULL, "ktracefiled");
	if (IS_ERR(tsk))
		rc = -ECHILD;
	else if (cmpxchg(&tctl_task, NULL, tsk) != NULL)
		/* already running */
		kthread_stop(tsk);
	else
		wake_up_process(tsk);

	return rc;
}

void cfs_trace_stop_thread(void)
{
	struct task_struct *tsk;

	tsk = xchg(&tctl_task, NULL);
	if (tsk) {
		pr_info("Lustre: shutting down debug daemon thread...\n");
		kthread_stop(tsk);
	}
}

/* percents to share the total debug memory for each type */
static unsigned int pages_factor[CFS_TCD_TYPE_CNT] = {
	80, /* 80% pages for CFS_TCD_TYPE_PROC */
	10, /* 10% pages for CFS_TCD_TYPE_SOFTIRQ */
	10  /* 10% pages for CFS_TCD_TYPE_IRQ */
};

int cfs_tracefile_init(int max_pages)
{
	struct cfs_trace_cpu_data *tcd;
	int i;
	int j;

	/* initialize trace_data */
	memset(cfs_trace_data, 0, sizeof(cfs_trace_data));
	for (i = 0; i < CFS_TCD_TYPE_CNT; i++) {
		cfs_trace_data[i] =
			kmalloc_array(num_possible_cpus(),
				      sizeof(union cfs_trace_data_union),
				      GFP_KERNEL);
		if (!cfs_trace_data[i])
			goto out_trace_data;
	}

	/* arch related info initialized */
	cfs_tcd_for_each(tcd, i, j) {
		int factor = pages_factor[i];

		spin_lock_init(&tcd->tcd_lock);
		tcd->tcd_pages_factor = factor;
		tcd->tcd_type = i;
		tcd->tcd_cpu = j;

		INIT_LIST_HEAD(&tcd->tcd_pages);
		INIT_LIST_HEAD(&tcd->tcd_stock_pages);
		INIT_LIST_HEAD(&tcd->tcd_daemon_pages);
		tcd->tcd_cur_pages = 0;
		tcd->tcd_cur_stock_pages = 0;
		tcd->tcd_cur_daemon_pages = 0;
		tcd->tcd_max_pages = (max_pages * factor) / 100;
		LASSERT(tcd->tcd_max_pages > 0);
		tcd->tcd_shutting_down = 0;
	}

	return 0;

out_trace_data:
	for (i = 0; cfs_trace_data[i]; i++) {
		kfree(cfs_trace_data[i]);
		cfs_trace_data[i] = NULL;
	}
	pr_err("lnet: Not enough memory\n");
	return -ENOMEM;
}

static void trace_cleanup_on_all_cpus(void)
{
	struct cfs_trace_cpu_data *tcd;
	struct cfs_trace_page *tage;
	int i, cpu;

	for_each_possible_cpu(cpu) {
		cfs_tcd_for_each_type_lock(tcd, i, cpu) {
			if (!tcd->tcd_pages_factor)
				/* Not initialised */
				continue;
			tcd->tcd_shutting_down = 1;

			while (!list_empty(&tcd->tcd_pages)) {
				tage = list_first_entry(&tcd->tcd_pages,
							struct cfs_trace_page,
							linkage);
				__LASSERT_TAGE_INVARIANT(tage);

				list_del(&tage->linkage);
				cfs_tage_free(tage);
			}
			tcd->tcd_cur_pages = 0;
		}
	}
}

static void cfs_trace_cleanup(void)
{
	struct page_collection pc;
	int i;

	INIT_LIST_HEAD(&pc.pc_pages);

	trace_cleanup_on_all_cpus();

	for (i = 0; i < CFS_TCD_TYPE_CNT && cfs_trace_data[i]; i++) {
		kfree(cfs_trace_data[i]);
		cfs_trace_data[i] = NULL;
	}
}

void cfs_tracefile_exit(void)
{
        cfs_trace_stop_thread();
        cfs_trace_cleanup();
}
