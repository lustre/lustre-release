
#define DEBUG_SUBSYSTEM S_PORTALS
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
extern struct rw_semaphore tracefile_sem;
extern int trace_start_thread(void);
extern void trace_stop_thread(void);

long max_debug_mb = M_TCD_MAX_PAGES;
static long max_permit_mb = (64 * 1024);

inline struct trace_cpu_data *
__trace_get_tcd (unsigned long *flags)
{
	return &trace_data[0].tcd;
}

inline void
__trace_put_tcd (struct trace_cpu_data *tcd, unsigned long flags)
{
	return;
}

void
set_ptldebug_header(struct ptldebug_header *header, int subsys, int mask, 
		    const int line, unsigned long stack)
{ 
	struct timeval tv; 
	
	do_gettimeofday(&tv); 
	header->ph_subsys = subsys; 
	header->ph_mask = mask; 
	header->ph_cpu_id = smp_processor_id(); 
	header->ph_sec = (__u32)tv.tv_sec; 
	header->ph_usec = tv.tv_usec; 
	header->ph_stack = stack; 
	header->ph_pid = 0; 
	header->ph_line_num = line; 
	header->ph_extern_pid = 0;
}

void print_to_console(struct ptldebug_header *hdr, int mask, char *buf, 
			     int len, char *file, const char *fn)
{ 
	char *prefix = NULL, *ptype = NULL;
		        
	if ((mask & D_EMERG) != 0) { 
		prefix = "LustreError"; 
		ptype = KERN_EMERG; 
	} else if ((mask & D_ERROR) != 0) { 
		prefix = "LustreError"; 
		ptype = KERN_ERR; 
	} else if ((mask & D_WARNING) != 0) { 
		prefix = "Lustre"; 
		ptype = KERN_WARNING; 
	} else if (portal_printk != 0 || (mask & D_CONSOLE)) {
		prefix = "Lustre"; 
		ptype = KERN_INFO; 
	} 

	if ((mask & D_CONSOLE) != 0) {
		printk("%s%s: %.*s", ptype, prefix, len, buf);
	} else {
		printk("%s%s: %d:%d:(%s:%d:%s()) %*s", ptype, prefix, hdr->ph_pid, 
		       hdr->ph_extern_pid, file, hdr->ph_line_num, fn, len, buf);
	}
}

/*
 * Sysctl handle of libcfs
 */
int cfs_trace_daemon SYSCTL_HANDLER_ARGS
{
	int error = 0;
	char *name = NULL;

	MALLOC(name, char *, req->newlen + 1, M_TEMP, M_WAITOK | M_ZERO);
	if (name == NULL)
		return -ENOMEM;
	down_write(&tracefile_sem);
	error = sysctl_handle_string(oidp, name, req->newlen + 1, req);
	if (!error || req->newptr != NULL) {
		/* write */
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
	} else if (req->newptr != NULL) {
		/* Something was wrong with the write request */
		printf("sysctl debug daemon failed: %d.\n", error);
		goto out;
	} else {
		/* Read request */
		SYSCTL_OUT(req, tracefile, sizeof(tracefile));
	}
out:
	if (name != NULL) 
		FREE(name, M_TEMP);
	up_write(&tracefile_sem);
	return error;
}


int cfs_debug_mb SYSCTL_HANDLER_ARGS
{
	int i;
	int error = 0;

	error = sysctl_handle_long(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
	if (!error && req->newptr != NULL) {
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
	} else if (req->newptr != NULL) {
		/* Something was wrong with the write request */
		printf ("sysctl debug_mb fault: %d.\n", error);
	} else {
		/* Read request */
		error = SYSCTL_OUT(req, &max_debug_mb, sizeof max_debug_mb);
	}
	return error;
}


