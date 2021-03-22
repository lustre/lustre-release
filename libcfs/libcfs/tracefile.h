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
 */

#ifndef __LIBCFS_TRACEFILE_H__
#define __LIBCFS_TRACEFILE_H__

#include <libcfs/libcfs.h>

#define TRACEFILE_NAME_SIZE 1024
extern char      cfs_tracefile[TRACEFILE_NAME_SIZE];
extern long long cfs_tracefile_size;

/**
 * The path of debug log dump upcall script.
 */
extern char lnet_debug_log_upcall[1024];

int cfs_tracefile_dump_all_pages(char *filename);
void cfs_trace_debug_print(void);
void cfs_trace_flush_pages(void);
int cfs_trace_start_thread(void);
void cfs_trace_stop_thread(void);
int cfs_tracefile_init(int max_pages);
void cfs_tracefile_exit(void);



int cfs_trace_copyout_string(char __user *usr_buffer, int usr_buffer_nob,
                             const char *knl_str, char *append);
int cfs_trace_dump_debug_buffer_usrstr(void __user *usr_str, int usr_str_nob);
int cfs_trace_daemon_command(char *str);
int cfs_trace_daemon_command_usrstr(void __user *usr_str, int usr_str_nob);
int cfs_trace_set_debug_mb(int mb);
int cfs_trace_get_debug_mb(void);

extern int  libcfs_panic_in_progress;

#define TCD_MAX_PAGES (5 << (20 - PAGE_SHIFT))
#define TCD_STOCK_PAGES (TCD_MAX_PAGES)
#define CFS_TRACEFILE_SIZE (500 << 20)

union cfs_trace_data_union {
	struct cfs_trace_cpu_data {
		/*
		 * Even though this structure is meant to be per-CPU, locking
		 * is needed because in some places the data may be accessed
		 * from other CPUs. This lock is directly used in trace_get_tcd
		 * and trace_put_tcd, which are called in libcfs_debug_msg and
		 * tcd_for_each_type_lock
		 */
		spinlock_t		tcd_lock;
		unsigned long           tcd_lock_flags;

		/*
		 * pages with trace records not yet processed by tracefiled.
		 */
		struct list_head	tcd_pages;
		/* number of pages on ->tcd_pages */
		unsigned long		tcd_cur_pages;

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
		struct list_head	tcd_daemon_pages;
		/* number of pages on ->tcd_daemon_pages */
		unsigned long		tcd_cur_daemon_pages;

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
		struct list_head	tcd_stock_pages;
		/* number of pages on ->tcd_stock_pages */
		unsigned long           tcd_cur_stock_pages;

		unsigned short          tcd_shutting_down;
		unsigned short          tcd_cpu;
		unsigned short          tcd_type;
		/* The factors to share debug memory. */
		unsigned short          tcd_pages_factor;
	} tcd;
	char __pad[L1_CACHE_ALIGN(sizeof(struct cfs_trace_cpu_data))];
};

/* XXX nikita: this declaration is internal to tracefile.c and should probably
 * be moved there */
struct page_collection {
	struct list_head	pc_pages;
	/*
	 * if this flag is set, collect_pages() will spill both
	 * ->tcd_daemon_pages and ->tcd_pages to the ->pc_pages. Otherwise,
	 * only ->tcd_pages are spilled.
	 */
	int			pc_want_daemon_pages;
};

/*
 * small data-structure for each page owned by tracefiled.
 */
/* XXX nikita: this declaration is internal to tracefile.c and should probably
 * be moved there */
struct cfs_trace_page {
	/*
	 * page itself
	 */
	struct page		*page;
	/*
	 * linkage into one of the lists in trace_data_union or
	 * page_collection
	 */
	struct list_head	linkage;
	/*
	 * number of bytes used within this page
	 */
	unsigned int		used;
	/*
	 * cpu that owns this page
	 */
	unsigned short		cpu;
	/*
	 * type(context) of this page
	 */
	unsigned short		type;
};

int cfs_tcd_owns_tage(struct cfs_trace_cpu_data *tcd,
                      struct cfs_trace_page *tage);

extern void cfs_trace_assertion_failed(const char *str,
                                       struct libcfs_debug_msg_data *m);

/* ASSERTION that is safe to use within the debug system */
#define __LASSERT(cond)							\
do {									\
	if (unlikely(!(cond))) {					\
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_EMERG, NULL);	\
		cfs_trace_assertion_failed("ASSERTION("#cond") failed",	\
					   &msgdata);			\
	}								\
} while (0)

#define __LASSERT_TAGE_INVARIANT(tage)					\
do {									\
	__LASSERT(tage != NULL);					\
	__LASSERT(tage->page != NULL);					\
	__LASSERT(tage->used <= PAGE_SIZE);				\
	__LASSERT(page_count(tage->page) > 0);				\
} while (0)

#endif /* __LIBCFS_TRACEFILE_H__ */
