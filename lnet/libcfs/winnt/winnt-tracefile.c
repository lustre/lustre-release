/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
 *
 *  Copyright (c) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or modify it under
 *   the terms of version 2 of the GNU General Public License as published by
 *   the Free Software Foundation. Lustre is distributed in the hope that it
 *   will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details. You should have received a
 *   copy of the GNU General Public License along with Lustre; if not, write
 *   to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139,
 *   USA.
 */

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
extern char *tracefile;
extern int64_t tracefile_size;

event_t     tracefile_event;

void tracefile_init_arch()
{
	int    i;
	int    j;

    cfs_init_event(&tracefile_event, TRUE, TRUE);

    memset(trace_console_buffers, 0, sizeof(trace_console_buffers));

	for (i = 0; i < NR_CPUS; i++) {
		for (j = 0; j < 1; j++) {
			trace_console_buffers[i][j] =
				cfs_alloc(TRACE_CONSOLE_BUFFER_SIZE,
					CFS_ALLOC_ZERO);

			if (trace_console_buffers[i][j] == NULL) {
				tracefile_fini_arch();
				KsPrint((0, "Can't allocate console message buffer\n"));
				return -ENOMEM;
			}
		}
    }

	return 0;
}

void tracefile_fini_arch()
{
	int    i;
	int    j;

	for (i = 0; i < NR_CPUS; i++) {
		for (j = 0; j < 2; j++) {
			if (trace_console_buffers[i][j] != NULL) {
				cfs_free(trace_console_buffers[i][j]);
				trace_console_buffers[i][j] = NULL;
			}
        }
    }
}

void tracefile_read_lock()
{
    cfs_wait_event(&tracefile_event, 0);
}

void tracefile_read_unlock()
{
    cfs_wake_event(&tracefile_event);
}

void tracefile_write_lock()
{
    cfs_wait_event(&tracefile_event, 0);
}

void tracefile_write_unlock()
{
    cfs_wake_event(&tracefile_event);
}

char *
trace_get_console_buffer(void)
{
#pragma message ("is there possible problem with pre-emption ?")
    int cpu = (int) KeGetCurrentProcessorNumber();
    return trace_console_buffers[cpu][0];
}

void
trace_put_console_buffer(char *buffer)
{
}

struct trace_cpu_data *
trace_get_tcd(void)
{
#pragma message("todo: return NULL if in interrupt context")

	int cpu = (int) KeGetCurrentProcessorNumber();
	return &trace_data[cpu].tcd;
}

void
trace_put_tcd (struct trace_cpu_data *tcd, unsigned long flags)
{
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
	header->ph_extern_pid = 0;
	return;
}

void print_to_console(struct ptldebug_header *hdr, int mask, const char *buf,
			          int len, const char *file, const char *fn)
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
	} else if ((mask & libcfs_printk) != 0 || (mask & D_CONSOLE)) {
		prefix = "Lustre";
		ptype = KERN_INFO;
	}

	if ((mask & D_CONSOLE) != 0) {
		printk("%s%s: %s", ptype, prefix, buf);
	} else {
		printk("%s%s: %d:%d:(%s:%d:%s()) %s", ptype, prefix, hdr->ph_pid,
		       hdr->ph_extern_pid, file, hdr->ph_line_num, fn, buf);
	}
	return;
}

int tcd_owns_tage(struct trace_cpu_data *tcd, struct trace_page *tage)
{
	return 1;
}


int trace_write_daemon_file(struct file *file, const char *buffer,
                            unsigned long count, void *data)
{
	char *name;
	unsigned long off;
	int rc;

	name =cfs_alloc(count + 1, 0);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user((void *)name, (void*)buffer, count)) {
		rc = -EFAULT;
		goto out;
	}

	/* be nice and strip out trailing '\n' */
	for (off = count ; off > 2 && isspace(name[off - 1]); off--)
		;

	name[off] = '\0';

	tracefile_write_lock();
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

	if (tracefile != NULL)
		cfs_free(tracefile);

	tracefile = name;
	name = NULL;
	printk(KERN_INFO "Lustre: debug daemon will attempt to start writing "
	       "to %s (%lukB max)\n", tracefile, (long)(tracefile_size >> 10));

	trace_start_thread();
out_sem:
    tracefile_write_unlock();
out:
    if (name != NULL)
	    cfs_free(name);
	return count;
}

int trace_read_daemon_file(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
	int rc;

	tracefile_read_lock();
	rc = snprintf(page, count, "%s", tracefile);
	tracefile_read_unlock();

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

	if (copy_from_user((void *)string, (void *)buffer, count))
		return -EFAULT;

	max = simple_strtoul(string, NULL, 0);
	if (max == 0)
		return -EINVAL;

	if (max > (num_physpages >> (20 - 2 - CFS_PAGE_SHIFT)) / 5 || max >= 512) {
		printk(KERN_ERR "Lustre: Refusing to set debug buffer size to "
		       "%dMB, which is more than 80%% of available RAM (%lu)\n",
		       max, (num_physpages >> (20 - 2 - CFS_PAGE_SHIFT)) / 5);
		return -EINVAL;
	}

	max /= smp_num_cpus;

	for (i = 0; i < NR_CPUS; i++) {
		struct trace_cpu_data *tcd;
		tcd = &trace_data[i].tcd;
		tcd->tcd_max_pages = max << (20 - CFS_PAGE_SHIFT);
	}
	return count;
}

int trace_read_debug_mb(char *page, char **start, off_t off, int count,
                        int *eof, void *data)
{
	struct trace_cpu_data *tcd;
	int rc;

	tcd = trace_get_tcd();
        LASSERT (tcd != NULL);
	rc = snprintf(page, count, "%lu\n",
		      (tcd->tcd_max_pages >> (20 - CFS_PAGE_SHIFT)) * smp_num_cpus);
	trace_put_tcd(tcd);
	return rc;
}

void
trace_call_on_all_cpus(void (*fn)(void *arg), void *arg)
{
#error "tbd"
}

