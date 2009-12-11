/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LIBCFS_TRACEFILE_H__
#define __LIBCFS_TRACEFILE_H__

#include <libcfs/libcfs.h>

/* trace file lock routines */

#define TRACEFILE_NAME_SIZE 1024
extern char      tracefile[TRACEFILE_NAME_SIZE];
extern long long tracefile_size;

extern void libcfs_run_debug_log_upcall(char *file);

int  tracefile_init_arch(void);
void tracefile_fini_arch(void);

void tracefile_read_lock(void);
void tracefile_read_unlock(void);
void tracefile_write_lock(void);
void tracefile_write_unlock(void);

int tracefile_dump_all_pages(char *filename);
void trace_debug_print(void);
void trace_flush_pages(void);
int trace_start_thread(void);
void trace_stop_thread(void);
int tracefile_init(int max_pages);
void tracefile_exit(void);



int trace_copyin_string(char *knl_buffer, int knl_buffer_nob,
                        const char *usr_buffer, int usr_buffer_nob);
int trace_copyout_string(char *usr_buffer, int usr_buffer_nob,
                         const char *knl_str, char *append);
int trace_allocate_string_buffer(char **str, int nob);
void trace_free_string_buffer(char *str, int nob);
int trace_dump_debug_buffer_usrstr(void *usr_str, int usr_str_nob);
int trace_daemon_command(char *str);
int trace_daemon_command_usrstr(void *usr_str, int usr_str_nob);
int trace_set_debug_mb(int mb);
int trace_set_debug_mb_usrstr(void *usr_str, int usr_str_nob);
int trace_get_debug_mb(void);

extern void libcfs_debug_dumplog_internal(void *arg);
extern void libcfs_register_panic_notifier(void);
extern void libcfs_unregister_panic_notifier(void);
extern int  libcfs_panic_in_progress;
extern int  trace_max_debug_mb(void);

#define TCD_MAX_PAGES (5 << (20 - CFS_PAGE_SHIFT))
#define TCD_STOCK_PAGES (TCD_MAX_PAGES)
#define TRACEFILE_SIZE (500 << 20)

#ifdef LUSTRE_TRACEFILE_PRIVATE

/*
 * Private declare for tracefile
 */
#define TCD_MAX_PAGES (5 << (20 - CFS_PAGE_SHIFT))
#define TCD_STOCK_PAGES (TCD_MAX_PAGES)

#define TRACEFILE_SIZE (500 << 20)

/* Size of a buffer for sprinting console messages if we can't get a page
 * from system */
#define TRACE_CONSOLE_BUFFER_SIZE   1024

union trace_data_union {
	struct trace_cpu_data {
		/*
		 * Even though this structure is meant to be per-CPU, locking
		 * is needed because in some places the data may be accessed
		 * from other CPUs. This lock is directly used in trace_get_tcd
		 * and trace_put_tcd, which are called in libcfs_debug_vmsg2 and
		 * tcd_for_each_type_lock
		 */
		spinlock_t              tcd_lock;
		unsigned long           tcd_lock_flags;

		/*
		 * pages with trace records not yet processed by tracefiled.
		 */
		struct list_head        tcd_pages;
		/* number of pages on ->tcd_pages */
		unsigned long           tcd_cur_pages;

		/*
		 * pages with trace records already processed by
		 * tracefiled. These pages are kept in memory, so that some
		 * portion of log can be written in the event of LBUG. This
		 * list is maintained in LRU order.
		 *
		 * Pages are moved to ->tcd_daemon_pages by tracefiled()
		 * (put_pages_on_daemon_list()). LRU pages from this list are
		 * discarded when list grows too large.
		 */
		struct list_head        tcd_daemon_pages;
		/* number of pages on ->tcd_daemon_pages */
		unsigned long           tcd_cur_daemon_pages;

		/*
		 * Maximal number of pages allowed on ->tcd_pages and
		 * ->tcd_daemon_pages each.
		 * Always TCD_MAX_PAGES * tcd_pages_factor / 100 in current
		 * implementation.
		 */
		unsigned long           tcd_max_pages;

		/*
		 * preallocated pages to write trace records into. Pages from
		 * ->tcd_stock_pages are moved to ->tcd_pages by
		 * portals_debug_msg().
		 *
		 * This list is necessary, because on some platforms it's
		 * impossible to perform efficient atomic page allocation in a
		 * non-blockable context.
		 *
		 * Such platforms fill ->tcd_stock_pages "on occasion", when
		 * tracing code is entered in blockable context.
		 *
		 * trace_get_tage_try() tries to get a page from
		 * ->tcd_stock_pages first and resorts to atomic page
		 * allocation only if this queue is empty. ->tcd_stock_pages
		 * is replenished when tracing code is entered in blocking
		 * context (darwin-tracefile.c:trace_get_tcd()). We try to
		 * maintain TCD_STOCK_PAGES (40 by default) pages in this
		 * queue. Atomic allocation is only required if more than
		 * TCD_STOCK_PAGES pagesful are consumed by trace records all
		 * emitted in non-blocking contexts. Which is quite unlikely.
		 */
		struct list_head        tcd_stock_pages;
		/* number of pages on ->tcd_stock_pages */
		unsigned long           tcd_cur_stock_pages;

		unsigned short          tcd_shutting_down;
		unsigned short          tcd_cpu;
		unsigned short          tcd_type;
		/* The factors to share debug memory. */
		unsigned short          tcd_pages_factor;
	} tcd;
	char __pad[L1_CACHE_ALIGN(sizeof(struct trace_cpu_data))];
};

#define TCD_MAX_TYPES      8
extern union trace_data_union (*trace_data[TCD_MAX_TYPES])[NR_CPUS];

#define tcd_for_each(tcd, i, j)                                       \
    for (i = 0; trace_data[i] != NULL; i++)                           \
        for (j = 0, ((tcd) = &(*trace_data[i])[j].tcd);               \
             j < num_possible_cpus(); j++, (tcd) = &(*trace_data[i])[j].tcd)

#define tcd_for_each_type_lock(tcd, i, cpu)                           \
    for (i = 0; trace_data[i] &&                                      \
         (tcd = &(*trace_data[i])[cpu].tcd) &&                        \
         trace_lock_tcd(tcd); trace_unlock_tcd(tcd), i++)

/* XXX nikita: this declaration is internal to tracefile.c and should probably
 * be moved there */
struct page_collection {
	struct list_head        pc_pages;
	/*
	 * spin-lock protecting ->pc_pages. It is taken by smp_call_function()
	 * call-back functions. XXX nikita: Which is horrible: all processors
	 * receive NMI at the same time only to be serialized by this
	 * lock. Probably ->pc_pages should be replaced with an array of
	 * NR_CPUS elements accessed locklessly.
	 */
	spinlock_t              pc_lock;
	/*
	 * if this flag is set, collect_pages() will spill both
	 * ->tcd_daemon_pages and ->tcd_pages to the ->pc_pages. Otherwise,
	 * only ->tcd_pages are spilled.
	 */
	int                     pc_want_daemon_pages;
};

/* XXX nikita: this declaration is internal to tracefile.c and should probably
 * be moved there */
struct tracefiled_ctl {
	struct completion       tctl_start;
	struct completion       tctl_stop;
	cfs_waitq_t             tctl_waitq;
	pid_t                   tctl_pid;
	atomic_t                tctl_shutdown;
};

/*
 * small data-structure for each page owned by tracefiled.
 */
/* XXX nikita: this declaration is internal to tracefile.c and should probably
 * be moved there */
struct trace_page {
	/*
	 * page itself
	 */
	cfs_page_t      *page;
	/*
	 * linkage into one of the lists in trace_data_union or
	 * page_collection
	 */
	struct list_head linkage;
	/*
	 * number of bytes used within this page
	 */
	unsigned int     used;
	/*
	 * cpu that owns this page
	 */
	unsigned short   cpu;
	/*
	 * type(context) of this page
	 */
	unsigned short   type;
};

extern void set_ptldebug_header(struct ptldebug_header *header,
			   int subsys, int mask, const int line,
			   unsigned long stack);
extern void print_to_console(struct ptldebug_header *hdr, int mask, const char *buf,
			     int len, const char *file, const char *fn);

extern struct trace_cpu_data *trace_get_tcd(void);
extern void trace_put_tcd(struct trace_cpu_data *tcd);
extern int trace_lock_tcd(struct trace_cpu_data *tcd);
extern void trace_unlock_tcd(struct trace_cpu_data *tcd);
extern char *trace_get_console_buffer(void);
extern void trace_put_console_buffer(char *buffer);

int trace_refill_stock(struct trace_cpu_data *tcd, int gfp,
		       struct list_head *stock);


int tcd_owns_tage(struct trace_cpu_data *tcd, struct trace_page *tage);

extern void trace_assertion_failed(const char *str, const char *fn,
				   const char *file, int line);

/* ASSERTION that is safe to use within the debug system */
#define __LASSERT(cond)								\
({										\
	if (unlikely(!(cond))) {						\
                trace_assertion_failed("ASSERTION("#cond") failed",		\
				       __FUNCTION__, __FILE__, __LINE__);	\
	}									\
})

#define __LASSERT_TAGE_INVARIANT(tage)			\
({							\
        __LASSERT(tage != NULL);			\
        __LASSERT(tage->page != NULL);			\
        __LASSERT(tage->used <= CFS_PAGE_SIZE);		\
        __LASSERT(cfs_page_count(tage->page) > 0);	\
})

#endif	/* LUSTRE_TRACEFILE_PRIVATE */

#endif /* __LIBCFS_TRACEFILE_H__ */
