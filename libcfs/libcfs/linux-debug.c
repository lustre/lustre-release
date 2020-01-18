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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/linux/linux-debug.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/stacktrace.h>
#include <linux/utsname.h>

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

#include "tracefile.h"

char lnet_debug_log_upcall[1024] = "/usr/lib/lustre/lnet_debug_log_upcall";

/**
 * Upcall function once a Lustre log has been dumped.
 *
 * \param file  path of the dumped log
 */
void libcfs_run_debug_log_upcall(char *file)
{
        char *argv[3];
        int   rc;
        char *envp[] = {
                "HOME=/",
                "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
                NULL};
        ENTRY;

        argv[0] = lnet_debug_log_upcall;

        LASSERTF(file != NULL, "called on a null filename\n");
        argv[1] = file; //only need to pass the path of the file

        argv[2] = NULL;

        rc = call_usermodehelper(argv[0], argv, envp, 1);
        if (rc < 0 && rc != -ENOENT) {
                CERROR("Error %d invoking LNET debug log upcall %s %s; "
                       "check /proc/sys/lnet/debug_log_upcall\n",
                       rc, argv[0], argv[1]);
        } else {
                CDEBUG(D_HA, "Invoked LNET debug log upcall %s %s\n",
                       argv[0], argv[1]);
        }

        EXIT;
}

/* coverity[+kill] */
void lbug_with_loc(struct libcfs_debug_msg_data *msgdata)
{
	libcfs_catastrophe = 1;
	libcfs_debug_msg(msgdata, "LBUG\n");

	if (in_interrupt()) {
		panic("LBUG in interrupt.\n");
		/* not reached */
	}

	libcfs_debug_dumpstack(NULL);
	if (libcfs_panic_on_lbug)
		panic("LBUG");
	else
		libcfs_debug_dumplog();
	set_current_state(TASK_UNINTERRUPTIBLE);
	while (1)
		schedule();
}
EXPORT_SYMBOL(lbug_with_loc);

#ifdef CONFIG_STACKTRACE

#ifndef HAVE_SAVE_STACK_TRACE_TSK
#define save_stack_trace_tsk(tsk, trace)				       \
do {									       \
	if (tsk == current)						       \
		save_stack_trace(trace);				       \
	else								       \
		pr_info("No stack, save_stack_trace_tsk() not exported\n");    \
} while (0)
#endif

#define MAX_ST_ENTRIES	100
static DEFINE_SPINLOCK(st_lock);

/*
 * Linux v5.1-rc5 214d8ca6ee ("stacktrace: Provide common infrastructure")
 * CONFIG_ARCH_STACKWALK indicates that save_stack_trace_tsk symbol is not
 * exported. Use symbol_get() to find if save_stack_trace_tsk is available.
 */
#ifdef CONFIG_ARCH_STACKWALK
typedef unsigned int (stack_trace_save_tsk_t)(struct task_struct *task,
		unsigned long *store, unsigned int size,
		unsigned int skipnr);
static stack_trace_save_tsk_t *task_dump_stack;
#endif

static void libcfs_call_trace(struct task_struct *tsk)
{
#ifdef CONFIG_ARCH_STACKWALK
	static unsigned long entries[MAX_ST_ENTRIES];
	unsigned int i, nr_entries;

	if (!task_dump_stack)
		task_dump_stack = (stack_trace_save_tsk_t *)
			symbol_get("stack_trace_save_tsk");

	spin_lock(&st_lock);
	pr_info("Pid: %d, comm: %.20s %s %s\n", tsk->pid, tsk->comm,
	       init_utsname()->release, init_utsname()->version);
	pr_info("Call Trace TBD:\n");
	if (task_dump_stack) {
		nr_entries = task_dump_stack(tsk, entries, MAX_ST_ENTRIES, 0);
		for (i = 0; i < nr_entries; i++)
			pr_info("[<0>] %pB\n", (void *)entries[i]);
	}
	spin_unlock(&st_lock);
#else
	struct stack_trace trace;
	static unsigned long entries[MAX_ST_ENTRIES];

	trace.nr_entries = 0;
	trace.max_entries = MAX_ST_ENTRIES;
	trace.entries = entries;
	trace.skip = 0;

	spin_lock(&st_lock);
	pr_info("Pid: %d, comm: %.20s %s %s\n", tsk->pid, tsk->comm,
	       init_utsname()->release, init_utsname()->version);
	pr_info("Call Trace:\n");
	save_stack_trace_tsk(tsk, &trace);
	print_stack_trace(&trace, 0);
	spin_unlock(&st_lock);
#endif
}

#else /* !CONFIG_STACKTRACE */

#ifdef CONFIG_X86
#include <linux/nmi.h>
#include <asm/stacktrace.h>

#ifdef HAVE_STACKTRACE_OPS
static int print_trace_stack(void *data, char *name)
{
	printk(" <%s> ", name);
	return 0;
}

#ifdef STACKTRACE_OPS_ADDRESS_RETURN_INT
static int
#else
static void
#endif
print_trace_address(void *data, unsigned long addr, int reliable)
{
	char fmt[32];

	touch_nmi_watchdog();
	sprintf(fmt, " [<%016lx>] %s%%s\n", addr, reliable ? "": "? ");
	__print_symbol(fmt, addr);
#ifdef STACKTRACE_OPS_ADDRESS_RETURN_INT
	return 0;
#endif
}

static const struct stacktrace_ops print_trace_ops = {
	.stack = print_trace_stack,
	.address = print_trace_address,
	.walk_stack = print_context_stack,
};
#endif /* HAVE_STACKTRACE_OPS */

static void libcfs_call_trace(struct task_struct *tsk)
{
#ifdef HAVE_STACKTRACE_OPS
	printk("Pid: %d, comm: %.20s\n", tsk->pid, tsk->comm);
	printk("\nCall Trace:\n");
	dump_trace(tsk, NULL, NULL, 0, &print_trace_ops, NULL);
	printk("\n");
#else /* !HAVE_STACKTRACE_OPS */
	if (tsk == current)
		dump_stack();
	else
		CWARN("can't show stack: kernel doesn't export show_task\n");
#endif /* HAVE_STACKTRACE_OPS */
}

#else /* !CONFIG_X86 */

static void libcfs_call_trace(struct task_struct *tsk)
{
	if (tsk == current)
		dump_stack();
	else
		CWARN("can't show stack: kernel doesn't export show_task\n");
}

#endif /* CONFIG_X86 */

#endif /* CONFIG_STACKTRACE */

void libcfs_debug_dumpstack(struct task_struct *tsk)
{
	libcfs_call_trace(tsk ?: current);
}
EXPORT_SYMBOL(libcfs_debug_dumpstack);

static int panic_notifier(struct notifier_block *self, unsigned long unused1,
                         void *unused2)
{
        if (libcfs_panic_in_progress)
                return 0;

        libcfs_panic_in_progress = 1;
        mb();

#ifdef LNET_DUMP_ON_PANIC
        /* This is currently disabled because it spews far too much to the
         * console on the rare cases it is ever triggered. */

        if (in_interrupt()) {
                cfs_trace_debug_print();
        } else {
		libcfs_debug_dumplog_internal((void *)(long)current_pid());
        }
#endif
        return 0;
}

static struct notifier_block libcfs_panic_notifier = {
	.notifier_call	= panic_notifier,
	.next		= NULL,
	.priority	= 10000
};

void libcfs_register_panic_notifier(void)
{
        atomic_notifier_chain_register(&panic_notifier_list, &libcfs_panic_notifier);
}

void libcfs_unregister_panic_notifier(void)
{
        atomic_notifier_chain_unregister(&panic_notifier_list, &libcfs_panic_notifier);
}
