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

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/signal.h>
#include <linux/sched.h>

#include <linux/miscdevice.h>
#include <libcfs/linux/portals_compat25.h>
#include <asm/div64.h>

#include <libcfs/linux/linux-time.h>

/*
 * Pseudo device register
 */
typedef struct miscdevice		cfs_psdev_t;
#define cfs_psdev_register(dev)		misc_register(dev)
#define cfs_psdev_deregister(dev)	misc_deregister(dev)

/*
 * Sysctl register
 */
typedef struct ctl_table		cfs_sysctl_table_t;
typedef struct ctl_table_header		cfs_sysctl_table_header_t;

#ifdef HAVE_2ARGS_REGISTER_SYSCTL
#define cfs_register_sysctl_table(t, a)	register_sysctl_table(t, a)
#else
#define cfs_register_sysctl_table(t, a) register_sysctl_table(t)
#endif
#define cfs_unregister_sysctl_table(t)	unregister_sysctl_table(t)

/*
 * Symbol register
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define cfs_symbol_register(s, p)       inter_module_register(s, THIS_MODULE, p)
#define cfs_symbol_unregister(s)        inter_module_unregister(s)
#define cfs_symbol_get(s)               inter_module_get(s)
#define cfs_symbol_put(s)               inter_module_put(s)
#define cfs_module_get()                MOD_INC_USE_COUNT
#define cfs_module_put()                MOD_DEC_USE_COUNT
#else
#define cfs_symbol_register(s, p)       do {} while(0)
#define cfs_symbol_unregister(s)        do {} while(0)
#define cfs_symbol_get(s)               symbol_get(s)
#define cfs_symbol_put(s)               symbol_put(s)
#define cfs_module_get()                try_module_get(THIS_MODULE)
#define cfs_module_put()                module_put(THIS_MODULE)
#endif

/*
 * Proc file system APIs
 */
typedef read_proc_t                     cfs_read_proc_t;
typedef write_proc_t                    cfs_write_proc_t;
typedef struct proc_dir_entry           cfs_proc_dir_entry_t;
#define cfs_create_proc_entry(n, m, p)  create_proc_entry(n, m, p)
#define cfs_free_proc_entry(e)          free_proc_entry(e)
#define cfs_remove_proc_entry(n, e)     remove_proc_entry(n, e)

/*
 * Wait Queue
 */
#define CFS_TASK_INTERRUPTIBLE          TASK_INTERRUPTIBLE
#define CFS_TASK_UNINT                  TASK_UNINTERRUPTIBLE
#define CFS_TASK_RUNNING                TASK_RUNNING

typedef wait_queue_t			cfs_waitlink_t;
typedef wait_queue_head_t		cfs_waitq_t;
typedef long                            cfs_task_state_t;

/* Kernel thread */
typedef int (*cfs_thread_t)(void *);

static inline int cfs_kernel_thread(int (*fn)(void *),
                                    void *arg, unsigned long flags)
{
        void *orig_info = current->journal_info;
        int rc;

        current->journal_info = NULL;
        rc = kernel_thread(fn, arg, flags);
        current->journal_info = orig_info;
        return rc;
}


/*
 * Task struct
 */
typedef struct task_struct              cfs_task_t;
#define cfs_current()                   current
#define cfs_task_lock(t)                task_lock(t)
#define cfs_task_unlock(t)              task_unlock(t)
#define CFS_DECL_JOURNAL_DATA           void *journal_info
#define CFS_PUSH_JOURNAL                do {    \
        journal_info = current->journal_info;   \
        current->journal_info = NULL;           \
        } while(0)
#define CFS_POP_JOURNAL                 do {    \
        current->journal_info = journal_info;   \
        } while(0)

/* Module interfaces */
#define cfs_module(name, version, init, fini) \
module_init(init);                            \
module_exit(fini)

/*
 * Signal
 */
typedef sigset_t                        cfs_sigset_t;

/*
 * Timer
 */
typedef struct timer_list cfs_timer_t;


#ifndef wait_event_timeout /* Only for RHEL3 2.4.21 kernel */
#define __wait_event_timeout(wq, condition, timeout, ret)        \
do {                                                             \
	int __ret = 0;                                           \
	if (!(condition)) {                                      \
		wait_queue_t __wait;                             \
		unsigned long expire;                            \
                                                                 \
		init_waitqueue_entry(&__wait, current);          \
		expire = timeout + jiffies;                      \
		add_wait_queue(&wq, &__wait);                    \
		for (;;) {                                       \
			set_current_state(TASK_UNINTERRUPTIBLE); \
			if (condition)                           \
				break;                           \
			if (jiffies > expire) {                  \
				ret = jiffies - expire;          \
				break;                           \
			}                                        \
			schedule_timeout(timeout);               \
		}                                                \
		current->state = TASK_RUNNING;                   \
		remove_wait_queue(&wq, &__wait);                 \
	}                                                        \
} while (0)
/*
   retval == 0; condition met; we're good.
   retval > 0; timed out.
*/
#define cfs_waitq_wait_event_timeout(wq, condition, timeout)         \
({                                                                   \
	int __ret = 0;                                               \
	if (!(condition))                                            \
		__wait_event_timeout(wq, condition, timeout, __ret); \
	__ret;                                                       \
})
#else
#define cfs_waitq_wait_event_timeout  wait_event_timeout
#endif

#ifndef wait_event_interruptible_timeout /* Only for RHEL3 2.4.21 kernel */
#define __wait_event_interruptible_timeout(wq, condition, timeout, ret)   \
do {                                                           \
	int __ret = 0;                                         \
	if (!(condition)) {                                    \
		wait_queue_t __wait;                           \
		unsigned long expire;                          \
                                                               \
		init_waitqueue_entry(&__wait, current);        \
		expire = timeout + jiffies;                    \
		add_wait_queue(&wq, &__wait);                  \
		for (;;) {                                     \
			set_current_state(TASK_INTERRUPTIBLE); \
			if (condition)                         \
				break;                         \
			if (jiffies > expire) {                \
				ret = jiffies - expire;        \
				break;                         \
			}                                      \
			if (!signal_pending(current)) {        \
				schedule_timeout(timeout);     \
				continue;                      \
			}                                      \
			ret = -ERESTARTSYS;                    \
			break;                                 \
		}                                              \
		current->state = TASK_RUNNING;                 \
		remove_wait_queue(&wq, &__wait);               \
	}                                                      \
} while (0)

/*
   retval == 0; condition met; we're good.
   retval < 0; interrupted by signal.
   retval > 0; timed out.
*/
#define cfs_waitq_wait_event_interruptible_timeout(wq, condition, timeout) \
({                                                                \
	int __ret = 0;                                            \
	if (!(condition))                                         \
		__wait_event_interruptible_timeout(wq, condition, \
						timeout, __ret);  \
	__ret;                                                    \
})
#else
#define cfs_waitq_wait_event_interruptible_timeout wait_event_interruptible_timeout
#endif

#endif
