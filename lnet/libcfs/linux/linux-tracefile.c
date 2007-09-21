#define DEBUG_SUBSYSTEM S_LNET
#define LUSTRE_TRACEFILE_PRIVATE

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>
#include "tracefile.h"

#ifndef get_cpu
#define get_cpu() smp_processor_id()
#define put_cpu() do { } while (0)
#endif

extern union trace_data_union trace_data[NR_CPUS];

char *trace_console_buffers[NR_CPUS][3];

struct rw_semaphore tracefile_sem;

int tracefile_init_arch()
{
	int    i;
	int    j;

	init_rwsem(&tracefile_sem);

	for (i = 0; i < NR_CPUS; i++)
		for (j = 0; j < 3; j++) {
			trace_console_buffers[i][j] =
				kmalloc(TRACE_CONSOLE_BUFFER_SIZE,
					GFP_KERNEL);

			if (trace_console_buffers[i][j] == NULL) {
				tracefile_fini_arch();
				printk(KERN_ERR
				       "Can't allocate "
				       "console message buffer\n");
				return -ENOMEM;
			}
		}

	return 0;
}

void tracefile_fini_arch()
{
	int    i;
	int    j;

	for (i = 0; i < NR_CPUS; i++)
		for (j = 0; j < 3; j++)
			if (trace_console_buffers[i][j] != NULL) {
				kfree(trace_console_buffers[i][j]);
				trace_console_buffers[i][j] = NULL;
			}
}

void tracefile_read_lock()
{
	down_read(&tracefile_sem);
}

void tracefile_read_unlock()
{
	up_read(&tracefile_sem);
}

void tracefile_write_lock()
{
	down_write(&tracefile_sem);
}

void tracefile_write_unlock()
{
	up_write(&tracefile_sem);
}

char *
trace_get_console_buffer(void)
{
	int  cpu = get_cpu();
	int  idx;

	if (in_irq()) {
		idx = 0;
	} else if (in_softirq()) {
		idx = 1;
	} else {
		idx = 2;
	}

	return trace_console_buffers[cpu][idx];
}

void
trace_put_console_buffer(char *buffer)
{
	put_cpu();
}

struct trace_cpu_data *
trace_get_tcd(void)
{
	int cpu;

	if (in_interrupt()) /* no logging in IRQ context */
		return NULL;

	cpu = get_cpu();
	return &trace_data[cpu].tcd;
}

void
trace_put_tcd (struct trace_cpu_data *tcd)
{
	__LASSERT (!in_interrupt());
	put_cpu();
}

int tcd_owns_tage(struct trace_cpu_data *tcd, struct trace_page *tage)
{
	/*
	 * XXX nikita: do NOT call portals_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */
	return tcd->tcd_cpu == tage->cpu;
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

void print_to_console(struct ptldebug_header *hdr, int mask, const char *buf,
			     int len, const char *file, const char *fn)
{
	char *prefix = "Lustre", *ptype = NULL;

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
		printk("%s%s: %d:%d:(%s:%d:%s()) %.*s", ptype, prefix, hdr->ph_pid,
		       hdr->ph_extern_pid, file, hdr->ph_line_num, fn, len, buf);
	}
	return;
}

int trace_max_debug_mb(void)
{
	int  total_mb = (num_physpages >> (20 - CFS_PAGE_SHIFT));
	
	return MAX(512, (total_mb * 80)/100);
}

void
trace_call_on_all_cpus(void (*fn)(void *arg), void *arg)
{
        cpumask_t cpus_allowed = current->cpus_allowed;
	/* use cpus_allowed to quiet 2.4 UP kernel warning only */
        cpumask_t m = cpus_allowed;
        int       cpu;

	/* Run the given routine on every CPU in thread context */
        for (cpu = 0; cpu < NR_CPUS; cpu++) {
                if (!cpu_online(cpu))
			continue;

		cpus_clear(m);
		cpu_set(cpu, m);
		set_cpus_allowed(current, m);

		fn(arg);

		set_cpus_allowed(current, cpus_allowed);
        }
}
