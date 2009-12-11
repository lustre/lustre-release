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
 *
 * lnet/include/libcfs/linux/linux-prim.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_PRIM_H__
#define __LIBCFS_LINUX_CFS_PRIM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__
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

#define cfs_set_current_state(state) set_current_state(state)

typedef wait_queue_t			cfs_waitlink_t;
typedef wait_queue_head_t		cfs_waitq_t;

typedef long                            cfs_task_state_t;

#define cfs_waitq_init(w)               init_waitqueue_head(w)
#define cfs_waitlink_init(l)            init_waitqueue_entry(l, current)
#define cfs_waitq_add(w, l)             add_wait_queue(w, l)
#define cfs_waitq_add_exclusive(w, l)   add_wait_queue_exclusive(w, l)
#define cfs_waitq_forward(l, w)         do {} while(0)
#define cfs_waitq_del(w, l)             remove_wait_queue(w, l)
#define cfs_waitq_active(w)             waitqueue_active(w)
#define cfs_waitq_signal(w)             wake_up(w)
#define cfs_waitq_signal_nr(w,n)        wake_up_nr(w, n)
#define cfs_waitq_broadcast(w)          wake_up_all(w)
#define cfs_waitq_wait(l, s)            schedule()
#define cfs_waitq_timedwait(l, s, t)    schedule_timeout(t)
#define cfs_schedule_timeout(s, t)      schedule_timeout(t)
#define cfs_schedule()                  schedule()

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

#define CFS_MAX_SCHEDULE_TIMEOUT MAX_SCHEDULE_TIMEOUT

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
typedef  void (*timer_func_t)(unsigned long);

#define cfs_init_timer(t)       init_timer(t)

static inline void cfs_timer_init(cfs_timer_t *t, void (*func)(unsigned long), void *arg)
{
        init_timer(t);
        t->function = (timer_func_t)func;
        t->data = (unsigned long)arg;
}

static inline void cfs_timer_done(cfs_timer_t *t)
{
        return;
}

static inline void cfs_timer_arm(cfs_timer_t *t, cfs_time_t deadline)
{
        mod_timer(t, deadline);
}

static inline void cfs_timer_disarm(cfs_timer_t *t)
{
        del_timer(t);
}

static inline int  cfs_timer_is_armed(cfs_timer_t *t)
{
        return timer_pending(t);
}

static inline cfs_time_t cfs_timer_deadline(cfs_timer_t *t)
{
        return t->expires;
}

#define CFS_MAX_SCHEDULE_TIMEOUT MAX_SCHEDULE_TIMEOUT

/* deschedule for a bit... */
static inline void cfs_pause(cfs_duration_t ticks)
{
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(ticks);
}

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

#define cfs_wait_event_interruptible_exclusive(wq, condition, rc)       \
({                                                                      \
        rc = wait_event_interruptible_exclusive(wq, condition);         \
})

/*
 * atomic
 */

typedef atomic_t cfs_atomic_t;

#define cfs_atomic_read(atom)         atomic_read(atom)
#define cfs_atomic_inc(atom)          atomic_inc(atom)
#define cfs_atomic_dec(atom)          atomic_dec(atom)
#define cfs_atomic_dec_and_test(atom) atomic_dec_and_test(atom)
#define cfs_atomic_set(atom, value)   atomic_set(atom, value)
#define cfs_atomic_add(value, atom)   atomic_add(value, atom)
#define cfs_atomic_sub(value, atom)   atomic_sub(value, atom)

/*
 * membar
 */

#define cfs_mb() mb()

/*
 * interrupt
 */

#define cfs_in_interrupt() in_interrupt()

#else   /* !__KERNEL__ */

typedef struct proc_dir_entry           cfs_proc_dir_entry_t;
#include "../user-prim.h"

#endif /* __KERNEL__ */

#endif
