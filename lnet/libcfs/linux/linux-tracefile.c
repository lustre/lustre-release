#define DEBUG_SUBSYSTEM S_PORTALS
#define LUSTRE_TRACEFILE_PRIVATE

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>
#include "tracefile.h"

#ifndef get_cpu
#define get_cpu() smp_processor_id()
#define put_cpu() do { } while (0)
#endif

extern union trace_data_union trace_data[NR_CPUS];
extern char *tracefile;
extern long long tracefile_size;
extern struct rw_semaphore tracefile_sem;

inline struct trace_cpu_data *
__trace_get_tcd(unsigned long *flags) 
{
	struct trace_cpu_data *ret;           

	int cpu = get_cpu();                
	local_irq_save(*flags);               
	ret = &trace_data[cpu].tcd;     

	return ret;                             
}

inline void 
trace_put_tcd (struct trace_cpu_data *tcd, unsigned long flags)
{
	local_irq_restore(flags); 
	put_cpu();               
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
	header->ph_pid = current->pid; 
	header->ph_line_num = line; 
#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20)) 
	header->ph_extern_pid = current->thread.extern_pid;
#elif defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)) 
	header->ph_extern_pid = current->thread.mode.tt.extern_pid;
#else 
	header->ph_extern_pid = 0;
#endif
	return;
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
	} else if (portal_printk) { 
		prefix = "Lustre"; 
		ptype = KERN_INFO; 
	} 
	printk("%s%s: %d:%d:(%s:%d:%s()) %.*s", ptype, prefix, hdr->ph_pid, 
		hdr->ph_extern_pid, file, hdr->ph_line_num, fn, len, buf);
	return;
}

int trace_write_daemon_file(struct file *file, const char *buffer, 
			    unsigned long count, void *data)
{ 
	char *name; 
	unsigned long off; 
	int rc; 
	
	name = kmalloc(count + 1, GFP_KERNEL); 
	if (name == NULL) 
		return -ENOMEM; 
	
	if (copy_from_user(name, buffer, count)) { 
		rc = -EFAULT; 
		goto out; 
	} 
	
	/* be nice and strip out trailing '\n' */ 
	for (off = count ; off > 2 && isspace(name[off - 1]); off--) 
		; 
	
	name[off] = '\0'; 
	
	down_write(&tracefile_sem); 
	if (strcmp(name, "stop") == 0) { 
		tracefile = NULL; 
		trace_stop_thread(); 
		goto out_sem; 
	} else if (strncmp(name, "size=", 5) == 0) { 
		tracefile_size = simple_strtoul(name + 5, NULL, 0); 
		if (tracefile_size < 10 || tracefile_size > 20480) 
			tracefile_size = TRACEFILE_SIZE; 
		else 
			tracefile_size <<= 20; 
		goto out_sem; 
	} 
	
	if (name[0] != '/') { 
		rc = -EINVAL; 
		goto out_sem; 
	} 
	
	if (tracefile != NULL) 
		kfree(tracefile); 
	
	tracefile = name; 
	name = NULL; 
	printk(KERN_INFO "Lustre: debug daemon will attempt to start writing " 
	       "to %s (%lukB max)\n", tracefile, (long)(tracefile_size >> 10)); 
	
	trace_start_thread(); 
out_sem: 
	up_write(&tracefile_sem); 
out: 
	kfree(name);
	return count;
}

int trace_read_daemon_file(char *page, char **start, off_t off, int count, 
			   int *eof, void *data)
{ 
	int rc; 
	
	down_read(&tracefile_sem); 
	rc = snprintf(page, count, "%s", tracefile); 
	up_read(&tracefile_sem); 

	return rc;
}

int trace_write_debug_mb(struct file *file, const char *buffer, 
			 unsigned long count, void *data)
{ 
	char string[32]; 
	int i; 
	unsigned max; 
	
	if (count >= sizeof(string)) { 
		printk(KERN_ERR "Lustre: value too large (length %lu bytes)\n", 
		       count); 
		return -EOVERFLOW; 
	} 
	
	if (copy_from_user(string, buffer, count)) 
		return -EFAULT; 
	
	max = simple_strtoul(string, NULL, 0); 
	if (max == 0) 
		return -EINVAL;

	if (max > (num_physpages >> (20 - 2 - PAGE_SHIFT)) / 5 || max >= 512) { 
		printk(KERN_ERR "Lustre: Refusing to set debug buffer size to " 
		       "%dMB, which is more than 80%% of available RAM (%lu)\n", 
		       max, (num_physpages >> (20 - 2 - PAGE_SHIFT)) / 5); 
		return -EINVAL; 
	} 

	max /= smp_num_cpus; 
	
	for (i = 0; i < NR_CPUS; i++) { 
		struct trace_cpu_data *tcd; 
		tcd = &trace_data[i].tcd; 
		tcd->tcd_max_pages = max << (20 - PAGE_SHIFT); 
	} 
	return count;
}

int trace_read_debug_mb(char *page, char **start, off_t off, int count,
		                        int *eof, void *data)
{ 
	struct trace_cpu_data *tcd; 
	unsigned long flags; 
	int rc;
				        
	tcd = trace_get_tcd(flags); 
	rc = snprintf(page, count, "%lu\n", 
		      (tcd->tcd_max_pages >> (20 - PAGE_SHIFT)) * smp_num_cpus); 
	trace_put_tcd(tcd, flags); 
	return rc;
}

