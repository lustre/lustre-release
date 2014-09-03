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
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/linux/linux-prim.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_PRIM_H__
#define __LIBCFS_LINUX_CFS_PRIM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifndef __KERNEL__
#error This include is only for kernel use.
#endif

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#ifdef HAVE_LINUX_RANDOM_H
#include <linux/random.h>
#endif
#ifdef HAVE_UIDGID_HEADER
#include <linux/uidgid.h>
#endif
#include <linux/user_namespace.h>
#include <linux/miscdevice.h>
#include <libcfs/linux/portals_compat25.h>
#include <asm/div64.h>

#include <libcfs/linux/linux-time.h>


/*
 * CPU
 */
#ifdef for_each_possible_cpu
#define cfs_for_each_possible_cpu(cpu) for_each_possible_cpu(cpu)
#elif defined(for_each_cpu)
#define cfs_for_each_possible_cpu(cpu) for_each_cpu(cpu)
#endif

#ifndef NR_CPUS
#define NR_CPUS				1
#endif

#define DECLARE_PROC_HANDLER(name)                      \
static int                                              \
LL_PROC_PROTO(name)                                     \
{                                                       \
        return proc_call_handler(table->data, write,    \
                                 ppos, buffer, lenp,    \
                                 __##name);             \
}

/*
 * Wait Queue
 */


#define CFS_DECL_WAITQ(wq)		DECLARE_WAIT_QUEUE_HEAD(wq)

#define LIBCFS_WQITQ_MACROS           1
#define init_waitqueue_entry_current(w)          init_waitqueue_entry(w, current)
#define waitq_wait(w, s)          schedule()
#define waitq_timedwait(w, s, t)  schedule_timeout(t)

#ifndef HAVE___ADD_WAIT_QUEUE_EXCLUSIVE
static inline void __add_wait_queue_exclusive(wait_queue_head_t *q,
					      wait_queue_t *wait)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue(q, wait);
}
#endif /* HAVE___ADD_WAIT_QUEUE_EXCLUSIVE */

/**
 * wait_queue_t of Linux (version < 2.6.34) is a FIFO list for exclusively
 * waiting threads, which is not always desirable because all threads will
 * be waken up again and again, even user only needs a few of them to be
 * active most time. This is not good for performance because cache can
 * be polluted by different threads.
 *
 * LIFO list can resolve this problem because we always wakeup the most
 * recent active thread by default.
 *
 * NB: please don't call non-exclusive & exclusive wait on the same
 * waitq if add_wait_queue_exclusive_head is used.
 */
#define add_wait_queue_exclusive_head(waitq, link)			\
{									\
	unsigned long flags;						\
									\
	spin_lock_irqsave(&((waitq)->lock), flags);			\
	__add_wait_queue_exclusive(waitq, link);			\
	spin_unlock_irqrestore(&((waitq)->lock), flags);		\
}

#define schedule_timeout_and_set_state(state, timeout)			\
{									\
	set_current_state(state);					\
	schedule_timeout(timeout);					\
}

/* deschedule for a bit... */
#define cfs_pause(ticks)						\
{									\
	set_current_state(TASK_UNINTERRUPTIBLE);			\
	schedule_timeout(ticks);					\
}

#define DECL_JOURNAL_DATA           void *journal_info
#define PUSH_JOURNAL                do {    \
        journal_info = current->journal_info;   \
        current->journal_info = NULL;           \
        } while(0)
#define POP_JOURNAL                 do {    \
        current->journal_info = journal_info;   \
        } while(0)

/* Module interfaces */
#define cfs_module(name, version, init, fini) \
        module_init(init);                    \
        module_exit(fini)

#endif
