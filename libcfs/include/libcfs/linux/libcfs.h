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
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LIBCFS_LINUX_LIBCFS_H__
#define __LIBCFS_LINUX_LIBCFS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifndef __KERNEL__
#error This include is only for kernel use.
#endif

#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#endif
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <net/sock.h>
#include <linux/atomic.h>
#include <asm/div64.h>
#include <linux/timex.h>
#include <linux/uaccess.h>
#include <stdarg.h>

#include <libcfs/linux/linux-cpu.h>
#include <libcfs/linux/linux-time.h>
#include <libcfs/linux/linux-mem.h>
#include <libcfs/linux/linux-misc.h>
#include <libcfs/linux/linux-fs.h>

#if !defined(__x86_64__)
# ifdef  __ia64__
#  define CDEBUG_STACK() (THREAD_SIZE -                                 \
                          ((unsigned long)__builtin_dwarf_cfa() &       \
                           (THREAD_SIZE - 1)))
# else
#  define CDEBUG_STACK() (THREAD_SIZE -                                 \
                          ((unsigned long)__builtin_frame_address(0) &  \
                           (THREAD_SIZE - 1)))
# endif /* __ia64__ */

#define __CHECK_STACK(msgdata, mask, cdls)                              \
do {                                                                    \
        if (unlikely(CDEBUG_STACK() > libcfs_stack)) {                  \
                LIBCFS_DEBUG_MSG_DATA_INIT(msgdata, D_WARNING, NULL);   \
                libcfs_stack = CDEBUG_STACK();                          \
                libcfs_debug_msg(msgdata,                               \
                                 "maximum lustre stack %lu\n",          \
                                 CDEBUG_STACK());                       \
                (msgdata)->msg_mask = mask;                             \
                (msgdata)->msg_cdls = cdls;                             \
                dump_stack();                                           \
              /*panic("LBUG");*/                                        \
        }                                                               \
} while (0)
#define CFS_CHECK_STACK(msgdata, mask, cdls)  __CHECK_STACK(msgdata, mask, cdls)
#else /* __x86_64__ */
#define CFS_CHECK_STACK(msgdata, mask, cdls) do {} while(0)
#define CDEBUG_STACK() (0L)
#endif /* __x86_64__ */

/**
 * Platform specific declarations for cfs_curproc API (libcfs/curproc.h)
 *
 * Implementation is in linux-curproc.c
 */
#define CFS_CURPROC_COMM_MAX (sizeof ((struct task_struct *)0)->comm)

/* helper for sysctl handlers */
int lprocfs_call_handler(void *data, int write, loff_t *ppos,
			 void __user *buffer, size_t *lenp,
			 int (*handler)(void *data, int write,
			 loff_t pos, void __user *buffer, int len));

#ifndef WITH_WATCHDOG
#define WITH_WATCHDOG
#endif

/*
 * Macros to access common characteristics of "current" UNIX process.
 */
#define current_pid()             (current->pid)
#define current_comm()            (current->comm)

/* check if task is running in compat mode.*/
int current_is_32bit(void);

#endif /* _LINUX_LIBCFS_H */
