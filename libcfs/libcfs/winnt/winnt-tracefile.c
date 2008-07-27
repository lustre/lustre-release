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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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

#define TCD_TYPE_MAX        1

event_t     tracefile_event;

void tracefile_init_arch()
{
	int    i;
	int    j;
    struct trace_cpu_data *tcd;

    cfs_init_event(&tracefile_event, TRUE, TRUE);

    /* initialize trace_data */
    memset(trace_data, 0, sizeof(trace_data));
    for (i = 0; i < TCD_TYPE_MAX; i++) {
        trace_data[i]=cfs_alloc(sizeof(struct trace_data_union)*NR_CPUS, 0);
        if (trace_data[i] == NULL)
            goto out;
    }

    /* arch related info initialized */
    tcd_for_each(tcd, i, j) {
        tcd->tcd_pages_factor = 100; /* Only one type */
        tcd->tcd_cpu = j;
        tcd->tcd_type = i;
    }

    memset(trace_console_buffers, 0, sizeof(trace_console_buffers));

	for (i = 0; i < NR_CPUS; i++) {
		for (j = 0; j < 1; j++) {
			trace_console_buffers[i][j] =
				cfs_alloc(TRACE_CONSOLE_BUFFER_SIZE,
					CFS_ALLOC_ZERO);

			if (trace_console_buffers[i][j] == NULL)
                goto out;
		}
    }

	return 0;

out:
	tracefile_fini_arch();
	KsPrint((0, "lnet: No enough memory\n"));
	return -ENOMEM;
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

    for (i = 0; trace_data[i] != NULL; i++) {
        cfs_free(trace_data[i]);
        trace_data[i] = NULL;
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
	return &(*trace_data[0])[cpu].tcd;
}

void
trace_put_tcd (struct trace_cpu_data *tcd, unsigned long flags)
{
}

int 
trace_lock_tcd(struct trace_cpu_data *tcd)
{
    __LASSERT(tcd->tcd_type < TCD_TYPE_MAX);
    return 1;
}

void
trace_unlock_tcd(struct trace_cpu_data *tcd)
{
    __LASSERT(tcd->tcd_type < TCD_TYPE_MAX);
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

int trace_max_debug_mb(void)
{
	int  total_mb = (num_physpages >> (20 - CFS_PAGE_SHIFT));
	
	return MAX(512, (total_mb * 80)/100);
}

void
trace_call_on_all_cpus(void (*fn)(void *arg), void *arg)
{
#error "tbd"
}
