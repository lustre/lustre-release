#ifndef __LIBCFS_TRACEFILE_H__
#define __LIBCFS_TRACEFILE_H__

#include <libcfs/libcfs.h>

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
#define TCD_MAX_PAGES (5 << (20 - PAGE_SHIFT))

#define TRACEFILE_SIZE (500 << 20)

union trace_data_union {
	struct trace_cpu_data {
		struct list_head        tcd_pages;
		unsigned long           tcd_cur_pages;

		struct list_head        tcd_daemon_pages;
		unsigned long           tcd_cur_daemon_pages;

		unsigned long           tcd_max_pages;
		int                     tcd_shutting_down;
	} tcd;
	char __pad[SMP_CACHE_BYTES];
};

struct page_collection {
	struct list_head        pc_pages;
	spinlock_t              pc_lock;
	int                     pc_want_daemon_pages;
};

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

#endif	/* LUSTRE_TRACEFILE_PRIVATE */

#endif /* __PORTALS_TRACEFILE_H */
