
#define DEBUG_SUBSYSTEM S_LNET
#define LUSTRE_TRACEFILE_PRIVATE
#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>
#include "tracefile.h"

/*
 * We can't support smp tracefile currently.
 * Everything is put on one cpu.
 */

#define M_TCD_MAX_PAGES (128 * 1280)
extern union trace_data_union trace_data[NR_CPUS];
extern char *tracefile;
extern long long tracefile_size;
extern int trace_start_thread(void);
extern void trace_stop_thread(void);

long max_debug_mb = M_TCD_MAX_PAGES;
static long max_permit_mb = (64 * 1024);

spinlock_t trace_cpu_serializer;

/*
 * thread currently executing tracefile code or NULL if none does. Used to
 * detect recursive calls to libcfs_debug_msg().
 */
static thread_t trace_owner = NULL;

extern int get_preemption_level(void);
extern atomic_t tage_allocated;

struct rw_semaphore tracefile_sem;

int tracefile_init_arch() {
    init_rwsem(&tracefile_sem);
#error "Todo: initialise per-cpu console buffers"
    return 0;
}

void tracefile_fini_arch() {
}

void tracefile_read_lock() {
    down_read(&tracefile_sem);
}

void tracefile_read_unlock() {
    up_read(&tracefile_sem);
}

void tracefile_write_lock() {
    down_write(&tracefile_sem);
}

void tracefile_write_unlock() {
    up_write(&tracefile_sem);
}

char *trace_get_console_buffer(void)
{
#error "todo: return a per-cpu/interrupt console buffer and disable pre-emption"
}

void trace_put_console_buffer(char *buffer)
{
#error "todo: re-enable pre-emption"
}

struct trace_cpu_data *trace_get_tcd(void)
{
	struct trace_cpu_data *tcd;
	int nr_pages;
	struct list_head pages;

	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */

	/*
	 * debugging check for recursive call to libcfs_debug_msg()
	 */
	if (trace_owner == current_thread()) {
                /*
                 * Cannot assert here.
                 */
		printk(KERN_EMERG "recursive call to %s", __FUNCTION__);
		/*
                 * "The death of God left the angels in a strange position."
		 */
		cfs_enter_debugger();
	}
	tcd = &trace_data[0].tcd;
        CFS_INIT_LIST_HEAD(&pages);
	if (get_preemption_level() == 0)
		nr_pages = trace_refill_stock(tcd, CFS_ALLOC_STD, &pages);
	else
		nr_pages = 0;
	spin_lock(&trace_cpu_serializer);
	trace_owner = current_thread();
	tcd->tcd_cur_stock_pages += nr_pages;
	list_splice(&pages, &tcd->tcd_stock_pages);
	return tcd;
}

extern void raw_page_death_row_clean(void);

void __trace_put_tcd(struct trace_cpu_data *tcd)
{
	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */
	LASSERT(trace_owner == current_thread());
	trace_owner = NULL;
	spin_unlock(&trace_cpu_serializer);
	if (get_preemption_level() == 0)
		/* purge all pending pages */
		raw_page_death_row_clean();
}

int tcd_owns_tage(struct trace_cpu_data *tcd, struct trace_page *tage)
{
	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */
	/* XNU has global tcd, and all pages are owned by it */
	return 1;
}

void
set_ptldebug_header(struct ptldebug_header *header, int subsys, int mask,
		    const int line, unsigned long stack)
{
	struct timeval tv;
	
	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */
	do_gettimeofday(&tv);
	header->ph_subsys = subsys;
	header->ph_mask = mask;
	header->ph_cpu_id = smp_processor_id();
	header->ph_sec = (__u32)tv.tv_sec;
	header->ph_usec = tv.tv_usec;
	header->ph_stack = stack;
	header->ph_pid = cfs_curproc_pid();
	header->ph_line_num = line;
	header->ph_extern_pid = (__u32)current_thread();
}

void print_to_console(struct ptldebug_header *hdr, int mask, const char *buf,
		      int len, const char *file, const char *fn)
{
	char *prefix = "Lustre", *ptype = KERN_INFO;

	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */
	if ((mask & D_EMERG) != 0) {
		prefix = "LustreError";
		ptype = KERN_EMERG;
	} else if ((mask & D_ERROR) != 0) {
		prefix = "LustreError";
		ptype = KERN_ERR;
	} else if ((mask & D_WARNING) != 0) {
		prefix = "Lustre";
		ptype = KERN_WARNING;
	} else if ((mask & libcfs_printk) != 0 || (mask & D_CONSOLE)) {
		prefix = "Lustre";
		ptype = KERN_INFO;
	}

	if ((mask & D_CONSOLE) != 0) {
		printk("%s%s: %.*s", ptype, prefix, len, buf);
	} else {
		printk("%s%s: %d:%d:(%s:%d:%s()) %*s",
		       ptype, prefix, hdr->ph_pid, hdr->ph_extern_pid,
		       file, hdr->ph_line_num, fn, len, buf);
	}
}

/*
 * Sysctl handle of libcfs
 */
#define MAX_TRACEFILE_PATH_LEN  256
int cfs_trace_daemon SYSCTL_HANDLER_ARGS
{
	int error = 0;
	char *name = NULL;

        if (req->newptr == USER_ADDR_NULL) {
                /* a read */
                if (tracefile)
                        error = sysctl_handle_string(oidp, tracefile, 0, req);
                else
                        error = sysctl_handle_string(oidp, "NA", 0, req);

                return error;
        }
        
        /* now hanle write requests */
	MALLOC(name, char *, MAX_TRACEFILE_PATH_LEN + 1, M_TEMP, M_WAITOK | M_ZERO);
	if (name == NULL)
		return -ENOMEM;
        name[0] = '\0';
	tracefile_write_lock();
	error = sysctl_handle_string(oidp, name, MAX_TRACEFILE_PATH_LEN + 1, req);
	if (!error) {
		if (strcmp(name, "stop") == 0) {
			/* stop tracefile daemon */
			tracefile = NULL;
			trace_stop_thread();
			goto out;
		}else if (strncmp(name, "size=", 5) == 0) {
			tracefile_size = simple_strtoul(name + 5, NULL, 0);
			if (tracefile_size < 10 || tracefile_size > 20480)
				tracefile_size = TRACEFILE_SIZE;
			else
				tracefile_size <<= 20;
			goto out;

		}
		if (name[0] != '/') {
			error = -EINVAL;
			goto out;
		}
		if (tracefile != NULL)
			cfs_free(tracefile);
		tracefile = name;
		name = NULL;
		trace_start_thread();
	} else {
		/* Something was wrong with the write request */
		printf("sysctl debug daemon failed: %d.\n", error);
		goto out;
	}
out:
	if (name != NULL)
		FREE(name, M_TEMP);
	tracefile_write_unlock();
	return error;
}
#undef MAX_TRACEFILE_PATH_LEN


int cfs_debug_mb SYSCTL_HANDLER_ARGS
{
	int i;
	int error = 0;

	error = sysctl_handle_long(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
	if (!error && req->newptr != USER_ADDR_NULL) {
		/* We have a new value stored in the standard location */
		if (max_debug_mb <= 0)
			return -EINVAL;
		if (max_debug_mb > max_permit_mb) {
			printf("sysctl debug_mb is too big: %d.\n", max_debug_mb);
			return 0;
		}
		for (i = 0; i < NR_CPUS; i++) {
			struct trace_cpu_data *tcd;
			tcd = &trace_data[i].tcd;
			tcd->tcd_max_pages = max_debug_mb;
		}
	} else if (req->newptr != USER_ADDR_NULL) {
		/* Something was wrong with the write request */
		printf ("sysctl debug_mb fault: %d.\n", error);
	}

	return error;
}

void
trace_call_on_all_cpus(void (*fn)(void *arg), void *arg)
{
#error "tbd"
}
