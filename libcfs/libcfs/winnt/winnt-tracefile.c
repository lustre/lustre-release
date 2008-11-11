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

#define DEBUG_SUBSYSTEM S_LNET
#define LUSTRE_TRACEFILE_PRIVATE

#include <libcfs/libcfs.h>
#include "tracefile.h"

#ifndef get_cpu
#define get_cpu() smp_processor_id()
#define put_cpu() do { } while (0)
#endif

/* only define one trace_data type for windows */
enum {
        TCD_TYPE_PASSIVE = 0,
        TCD_TYPE_DISPATCH,
        TCD_TYPE_MAX
};

/* percents to share the total debug memory for each type */
static unsigned int pages_factor[TCD_TYPE_MAX] = {
        90,  /* 90% pages for TCD_TYPE_PASSIVE */
        10   /* 10% pages for TCD_TYPE_DISPATCH */
};

char *trace_console_buffers[NR_CPUS][TCD_TYPE_MAX];

struct rw_semaphore tracefile_sem;

int tracefile_init_arch()
{
	int    i;
	int    j;
	struct trace_cpu_data *tcd;

	init_rwsem(&tracefile_sem);

	/* initialize trace_data */
	memset(trace_data, 0, sizeof(trace_data));
	for (i = 0; i < TCD_TYPE_MAX; i++) {
		trace_data[i]=cfs_alloc(sizeof(union trace_data_union)*NR_CPUS,
							  GFP_KERNEL);
		if (trace_data[i] == NULL)
			goto out;
	}

	/* arch related info initialized */
	tcd_for_each(tcd, i, j) {
		tcd->tcd_pages_factor = (USHORT) pages_factor[i];
		tcd->tcd_type = (USHORT) i;
		tcd->tcd_cpu = (USHORT)j;
	}

	for (i = 0; i < num_possible_cpus(); i++)
		for (j = 0; j < TCD_TYPE_MAX; j++) {
			trace_console_buffers[i][j] =
				cfs_alloc(TRACE_CONSOLE_BUFFER_SIZE,
                                          GFP_KERNEL);

			if (trace_console_buffers[i][j] == NULL)
				goto out;
		}

	return 0;

out:
	tracefile_fini_arch();
	printk(KERN_ERR "lnet: No enough memory\n");
	return -ENOMEM;

}

void tracefile_fini_arch()
{
	int    i;
	int    j;

	for (i = 0; i < num_possible_cpus(); i++) {
		for (j = 0; j < TCD_TYPE_MAX; j++) {
			if (trace_console_buffers[i][j] != NULL) {
				cfs_free(trace_console_buffers[i][j]);
				trace_console_buffers[i][j] = NULL;
			}
		}
	}

	for (i = 0; trace_data[i] != NULL; i++) {
		cfs_free(trace_data[i]);
		trace_data[i] = NULL;
	}

	fini_rwsem(&tracefile_sem);
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
        int cpu  = get_cpu();
        int type = 0;
        
        if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
                type = TCD_TYPE_DISPATCH;
        else
                type = TCD_TYPE_PASSIVE;
	return trace_console_buffers[cpu][type];
}

void
trace_put_console_buffer(char *buffer)
{
	put_cpu();
}

struct trace_cpu_data *
trace_get_tcd(void)
{
        int cpu  = get_cpu();
        int type = 0;
        
        if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
                type = TCD_TYPE_DISPATCH;
        else
                type = TCD_TYPE_PASSIVE;
	return &(*trace_data[type])[cpu].tcd;
}

void
trace_put_tcd (struct trace_cpu_data *tcd)
{
	put_cpu();
}

int trace_lock_tcd(struct trace_cpu_data *tcd)
{
	__LASSERT(tcd->tcd_type < TCD_TYPE_MAX);
	return 1;
}

void trace_unlock_tcd(struct trace_cpu_data *tcd)
{
	__LASSERT(tcd->tcd_type < TCD_TYPE_MAX);
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
	header->ph_pid = (__u32)(ULONG_PTR)current->pid;
	header->ph_line_num = line;
	header->ph_extern_pid = 0;
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
	} else if ((mask & (D_CONSOLE | libcfs_printk)) != 0) {
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
