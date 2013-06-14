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

#include <linux/miscdevice.h>
#include <libcfs/linux/portals_compat25.h>
#include <asm/div64.h>

#include <libcfs/linux/linux-time.h>

#define CFS_KERN_EMERG   KERN_EMERG
#define CFS_KERN_ALERT   KERN_ALERT
#define CFS_KERN_CRIT    KERN_CRIT
#define CFS_KERN_ERR     KERN_ERR
#define CFS_KERN_WARNING KERN_WARNING
#define CFS_KERN_NOTICE  KERN_NOTICE
#define CFS_KERN_INFO    KERN_INFO
#define CFS_KERN_DEBUG   KERN_DEBUG

/*
 * CPU
 */
#ifdef for_each_possible_cpu
#define cfs_for_each_possible_cpu(cpu) for_each_possible_cpu(cpu)
#elif defined(for_each_cpu)
#define cfs_for_each_possible_cpu(cpu) for_each_cpu(cpu)
#endif

#ifdef NR_CPUS
#define CFS_NR_CPUS     NR_CPUS
#else
#define CFS_NR_CPUS     1
#endif

#ifdef HAVE_SET_CPUS_ALLOWED
#define cfs_set_cpus_allowed(t, mask)  set_cpus_allowed(t, mask)
#else
#define cfs_set_cpus_allowed(t, mask)  set_cpus_allowed_ptr(t, &(mask))
#endif

/*
 * cache
 */
#define CFS_L1_CACHE_ALIGN(x)           L1_CACHE_ALIGN(x)

/*
 * IRQs
 */
#define CFS_NR_IRQS                     NR_IRQS

#define CFS_EXPORT_SYMBOL(s)            EXPORT_SYMBOL(s)

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

#define DECLARE_PROC_HANDLER(name)                      \
static int                                              \
LL_PROC_PROTO(name)                                     \
{                                                       \
        DECLARE_LL_PROC_PPOS_DECL;                      \
                                                        \
        return proc_call_handler(table->data, write,    \
                                 ppos, buffer, lenp,    \
                                 __##name);             \
}

/*
 * Symbol register
 */
#define cfs_symbol_register(s, p)       do {} while(0)
#define cfs_symbol_unregister(s)        do {} while(0)
#define cfs_symbol_get(s)               symbol_get(s)
#define cfs_symbol_put(s)               symbol_put(s)
#define cfs_module_get()                try_module_get(THIS_MODULE)
#define cfs_try_module_get(m)           try_module_get(m)
#define __cfs_module_get(m)             __module_get(m)
#define cfs_module_put(m)               module_put(m)
#define cfs_module_refcount(m)          module_refcount(m)

typedef struct module cfs_module_t;

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

#define cfs_set_current_state(state)    set_current_state(state)
#define cfs_wait_event(wq, cond)        wait_event(wq, cond)

typedef wait_queue_t			cfs_waitlink_t;
typedef wait_queue_head_t		cfs_waitq_t;
typedef long                            cfs_task_state_t;

#define CFS_DECL_WAITQ(wq)		DECLARE_WAIT_QUEUE_HEAD(wq)

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
        module_init(init);                    \
        module_exit(fini)
#define cfs_request_module              request_module

/*
 * Signal
 */
typedef sigset_t                        cfs_sigset_t;

/*
 * Timer
 */
typedef struct timer_list cfs_timer_t;

#define CFS_MAX_SCHEDULE_TIMEOUT MAX_SCHEDULE_TIMEOUT

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
#define cfs_waitq_wait_event_timeout(wq, condition, timeout, ret)    \
do {                                                                 \
	ret = 0;                                                     \
	if (!(condition))                                            \
		__wait_event_timeout(wq, condition, timeout, ret);   \
} while (0)
#else
#define cfs_waitq_wait_event_timeout(wq, condition, timeout, ret)    \
        ret = wait_event_timeout(wq, condition, timeout)
#endif

#define cfs_waitq_wait_event_interruptible_timeout(wq, c, timeout, ret) \
        ret = wait_event_interruptible_timeout(wq, c, timeout)

/*
 * atomic
 */

typedef atomic_t cfs_atomic_t;

#define cfs_atomic_read(atom)                atomic_read(atom)
#define cfs_atomic_inc(atom)                 atomic_inc(atom)
#define cfs_atomic_inc_and_test(atom)        atomic_inc_and_test(atom)
#define cfs_atomic_inc_return(atom)          atomic_inc_return(atom)
#define cfs_atomic_inc_not_zero(atom)        atomic_inc_not_zero(atom)
#define cfs_atomic_add_unless(atom, a, u)    atomic_add_unless(atom, a, u)
#define cfs_atomic_dec(atom)                 atomic_dec(atom)
#define cfs_atomic_dec_and_test(atom)        atomic_dec_and_test(atom)
#define cfs_atomic_dec_and_lock(atom, lock)  atomic_dec_and_lock(atom, lock)
#define cfs_atomic_dec_return(atom)          atomic_dec_return(atom)
#define cfs_atomic_set(atom, value)          atomic_set(atom, value)
#define cfs_atomic_add(value, atom)          atomic_add(value, atom)
#define cfs_atomic_add_return(value, atom)   atomic_add_return(value, atom)
#define cfs_atomic_sub(value, atom)          atomic_sub(value, atom)
#define cfs_atomic_sub_and_test(value, atom) atomic_sub_and_test(value, atom)
#define cfs_atomic_sub_return(value, atom)   atomic_sub_return(value, atom)
#define cfs_atomic_cmpxchg(atom, old, nv)    atomic_cmpxchg(atom, old, nv)
#define CFS_ATOMIC_INIT(i)                   ATOMIC_INIT(i)

/*
 * membar
 */

#define cfs_mb() mb()

/*
 * interrupt
 */

#define cfs_in_interrupt() in_interrupt()

/*
 * might_sleep
 */
#define cfs_might_sleep() might_sleep()

/*
 * group_info
 */
typedef struct group_info cfs_group_info_t;

#define cfs_get_group_info(group_info)     get_group_info(group_info)
#define cfs_put_group_info(group_info)     put_group_info(group_info)
#define cfs_set_current_groups(group_info) set_current_groups(group_info)
#define cfs_groups_free(group_info)        groups_free(group_info)
#define cfs_groups_alloc(gidsetsize)       groups_alloc(gidsetsize)

/*
 * Random bytes
 */
#define cfs_get_random_bytes_prim(buf, nbytes)  get_random_bytes(buf, nbytes)
#endif
