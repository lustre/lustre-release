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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
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

/*
 * We can't support smp tracefile currently.
 * Everything is put on one cpu.
 */

#define M_TCD_MAX_PAGES (128 * 1280)

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
    fini_rwsem(&tracefile_sem);
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
	header->ph_cpu_id = cfs_smp_processor_id();
	header->ph_type = 0;
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

int trace_max_debug_mb(void)
{
	return max_permit_mb;
}
