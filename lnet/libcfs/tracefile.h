#ifndef __LIBCFS_TRACEFILE_H__
#define __LIBCFS_TRACEFILE_H__

#include <libcfs/libcfs.h>

/* trace file lock routines */

void tracefile_lock_init(void);
void tracefile_read_lock(void);
void tracefile_read_unlock(void);
void tracefile_write_lock(void);
void tracefile_write_unlock(void);

int tracefile_dump_all_pages(char *filename);
void trace_debug_print(void);
void trace_flush_pages(void);
int trace_start_thread(void);
void trace_stop_thread(void);
int tracefile_init(void);
void tracefile_exit(void);
int trace_write_daemon_file(struct file *file, const char *buffer,
			    unsigned long count, void *data);
int trace_read_daemon_file(char *page, char **start, off_t off, int count,
			   int *eof, void *data);
int trace_write_debug_mb(struct file *file, const char *buffer,
			 unsigned long count, void *data);
int trace_read_debug_mb(char *page, char **start, off_t off, int count,
			int *eof, void *data);
int trace_dk(struct file *file, const char *buffer, unsigned long count,
             void *data);

#ifdef LUSTRE_TRACEFILE_PRIVATE
/*
 * Private declare for tracefile
 */
#define TCD_MAX_PAGES (5 << (20 - CFS_PAGE_SHIFT))
#define TCD_STOCK_PAGES (TCD_MAX_PAGES)

#define TRACEFILE_SIZE (500 << 20)

union trace_data_union {
	struct trace_cpu_data {
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
		/* number of pages on ->tcd_cur_daemon_pages */
		unsigned long           tcd_cur_daemon_pages;

		/*
		 * Maximal number of pages allowed on ->tcd_pages and
		 * ->tcd_daemon_pages each. Always TCD_MAX_PAGES in current
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
		 * context (darwin-tracefile.c:__trace_get_tcd()). We try to
		 * maintain TCD_STOCK_PAGES (40 by default) pages in this
		 * queue. Atomic allocation is only required if more than
		 * TCD_STOCK_PAGES pagesful are consumed by trace records all
		 * emitted in non-blocking contexts. Which is quite unlikely.
		 */
		struct list_head        tcd_stock_pages;
		/* number of pages on ->tcd_stock_pages */
		unsigned long           tcd_cur_stock_pages;

		int                     tcd_shutting_down;
		int                     tcd_cpu;
	} tcd;
	char __pad[SMP_CACHE_BYTES];
};

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
	int              cpu;
};

extern void set_ptldebug_header(struct ptldebug_header *header,
			   int subsys, int mask, const int line,
			   unsigned long stack);
extern void print_to_console(struct ptldebug_header *hdr, int mask,
			     char *buf, int len, char *file, const char *fn);
extern struct trace_cpu_data * __trace_get_tcd (unsigned long *flags);
extern void __trace_put_tcd (struct trace_cpu_data *tcd, unsigned long flags);

#define trace_get_tcd(f)	__trace_get_tcd(&(f))
#define trace_put_tcd(t, f)	__trace_put_tcd(t, f)

int tcd_owns_tage(struct trace_cpu_data *tcd, struct trace_page *tage);

#endif	/* LUSTRE_TRACEFILE_PRIVATE */

#endif /* __PORTALS_TRACEFILE_H */
