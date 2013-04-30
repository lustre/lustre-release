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
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>

#include <libcfs/libcfs.h>

#if defined(CONFIG_KGDB)
#include <asm/kgdb.h>
#endif

#define LINUX_WAITQ(w) ((wait_queue_t *) w)
#define LINUX_WAITQ_HEAD(w) ((wait_queue_head_t *) w)

void
cfs_waitq_init(cfs_waitq_t *waitq)
{
        init_waitqueue_head(LINUX_WAITQ_HEAD(waitq));
}
EXPORT_SYMBOL(cfs_waitq_init);

void
cfs_waitlink_init(cfs_waitlink_t *link)
{
        init_waitqueue_entry(LINUX_WAITQ(link), current);
}
EXPORT_SYMBOL(cfs_waitlink_init);

void
cfs_waitq_add(cfs_waitq_t *waitq, cfs_waitlink_t *link)
{
        add_wait_queue(LINUX_WAITQ_HEAD(waitq), LINUX_WAITQ(link));
}
EXPORT_SYMBOL(cfs_waitq_add);

#ifndef HAVE___ADD_WAIT_QUEUE_EXCLUSIVE

static inline void __add_wait_queue_exclusive(wait_queue_head_t *q,
                                              wait_queue_t *wait)
{
        wait->flags |= WQ_FLAG_EXCLUSIVE;
        __add_wait_queue(q, wait);
}

#endif /* HAVE___ADD_WAIT_QUEUE_EXCLUSIVE */

void
cfs_waitq_add_exclusive(cfs_waitq_t *waitq,
                        cfs_waitlink_t *link)
{
        add_wait_queue_exclusive(LINUX_WAITQ_HEAD(waitq), LINUX_WAITQ(link));
}
EXPORT_SYMBOL(cfs_waitq_add_exclusive);

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
 * waitq if cfs_waitq_add_exclusive_head is used.
 */
void
cfs_waitq_add_exclusive_head(cfs_waitq_t *waitq, cfs_waitlink_t *link)
{
	unsigned long flags;

	spin_lock_irqsave(&LINUX_WAITQ_HEAD(waitq)->lock, flags);
	__add_wait_queue_exclusive(LINUX_WAITQ_HEAD(waitq), LINUX_WAITQ(link));
	spin_unlock_irqrestore(&LINUX_WAITQ_HEAD(waitq)->lock, flags);
}
EXPORT_SYMBOL(cfs_waitq_add_exclusive_head);

void
cfs_waitq_del(cfs_waitq_t *waitq, cfs_waitlink_t *link)
{
        remove_wait_queue(LINUX_WAITQ_HEAD(waitq), LINUX_WAITQ(link));
}
EXPORT_SYMBOL(cfs_waitq_del);

int
cfs_waitq_active(cfs_waitq_t *waitq)
{
        return waitqueue_active(LINUX_WAITQ_HEAD(waitq));
}
EXPORT_SYMBOL(cfs_waitq_active);

void
cfs_waitq_signal(cfs_waitq_t *waitq)
{
        wake_up(LINUX_WAITQ_HEAD(waitq));
}
EXPORT_SYMBOL(cfs_waitq_signal);

void
cfs_waitq_signal_nr(cfs_waitq_t *waitq, int nr)
{
        wake_up_nr(LINUX_WAITQ_HEAD(waitq), nr);
}
EXPORT_SYMBOL(cfs_waitq_signal_nr);

void
cfs_waitq_broadcast(cfs_waitq_t *waitq)
{
        wake_up_all(LINUX_WAITQ_HEAD(waitq));
}
EXPORT_SYMBOL(cfs_waitq_broadcast);

void
cfs_waitq_wait(cfs_waitlink_t *link, cfs_task_state_t state)
{
        schedule();
}
EXPORT_SYMBOL(cfs_waitq_wait);

int64_t
cfs_waitq_timedwait(cfs_waitlink_t *link, cfs_task_state_t state,
                    int64_t timeout)
{
        return schedule_timeout(timeout);
}
EXPORT_SYMBOL(cfs_waitq_timedwait);

void
cfs_schedule_timeout_and_set_state(cfs_task_state_t state, int64_t timeout)
{
        set_current_state(state);
        schedule_timeout(timeout);
}
EXPORT_SYMBOL(cfs_schedule_timeout_and_set_state);

void
cfs_schedule_timeout(int64_t timeout)
{
        schedule_timeout(timeout);
}
EXPORT_SYMBOL(cfs_schedule_timeout);

void
cfs_schedule(void)
{
        schedule();
}
EXPORT_SYMBOL(cfs_schedule);

/* deschedule for a bit... */
void
cfs_pause(cfs_duration_t ticks)
{
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(ticks);
}
EXPORT_SYMBOL(cfs_pause);

int cfs_need_resched(void)
{
        return need_resched();
}
EXPORT_SYMBOL(cfs_need_resched);

void cfs_cond_resched(void)
{
        cond_resched();
}
EXPORT_SYMBOL(cfs_cond_resched);

void cfs_init_timer(cfs_timer_t *t)
{
        init_timer(t);
}
EXPORT_SYMBOL(cfs_init_timer);

void cfs_timer_init(cfs_timer_t *t, cfs_timer_func_t *func, void *arg)
{
        init_timer(t);
        t->function = func;
        t->data = (unsigned long)arg;
}
EXPORT_SYMBOL(cfs_timer_init);

void cfs_timer_done(cfs_timer_t *t)
{
        return;
}
EXPORT_SYMBOL(cfs_timer_done);

void cfs_timer_arm(cfs_timer_t *t, cfs_time_t deadline)
{
        mod_timer(t, deadline);
}
EXPORT_SYMBOL(cfs_timer_arm);

void cfs_timer_disarm(cfs_timer_t *t)
{
        del_timer(t);
}
EXPORT_SYMBOL(cfs_timer_disarm);

int  cfs_timer_is_armed(cfs_timer_t *t)
{
        return timer_pending(t);
}
EXPORT_SYMBOL(cfs_timer_is_armed);

cfs_time_t cfs_timer_deadline(cfs_timer_t *t)
{
        return t->expires;
}
EXPORT_SYMBOL(cfs_timer_deadline);

void cfs_enter_debugger(void)
{
#if defined(CONFIG_KGDB)
//        BREAKPOINT();
#else
        /* nothing */
#endif
}

void cfs_daemonize(char *str) {
        unsigned long flags;

        daemonize(str);
        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
}

int cfs_daemonize_ctxt(char *str) {

        cfs_daemonize(str);
#ifndef HAVE_UNSHARE_FS_STRUCT
        {
        struct task_struct *tsk = current;
        struct fs_struct *fs = NULL;
        fs = copy_fs_struct(tsk->fs);
        if (fs == NULL)
                return -ENOMEM;
        exit_fs(tsk);
        tsk->fs = fs;
        }
#else
        unshare_fs_struct();
#endif
        return 0;
}

sigset_t
cfs_block_allsigs(void)
{
        unsigned long          flags;
        sigset_t        old;

        SIGNAL_MASK_LOCK(current, flags);
        old = current->blocked;
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        return old;
}

sigset_t cfs_block_sigs(unsigned long sigs)
{
	unsigned long  flags;
	sigset_t	old;

	SIGNAL_MASK_LOCK(current, flags);
	old = current->blocked;
	sigaddsetmask(&current->blocked, sigs);
	RECALC_SIGPENDING;
	SIGNAL_MASK_UNLOCK(current, flags);
	return old;
}

/* Block all signals except for the @sigs */
sigset_t cfs_block_sigsinv(unsigned long sigs)
{
	unsigned long flags;
	sigset_t old;

	SIGNAL_MASK_LOCK(current, flags);
	old = current->blocked;
	sigaddsetmask(&current->blocked, ~sigs);
	RECALC_SIGPENDING;
	SIGNAL_MASK_UNLOCK(current, flags);

	return old;
}

void
cfs_restore_sigs (cfs_sigset_t old)
{
        unsigned long  flags;

        SIGNAL_MASK_LOCK(current, flags);
        current->blocked = old;
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
}

int
cfs_signal_pending(void)
{
        return signal_pending(current);
}

void
cfs_clear_sigpending(void)
{
        unsigned long flags;

        SIGNAL_MASK_LOCK(current, flags);
        CLEAR_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
}

int
libcfs_arch_init(void)
{
        return 0;
}

void
libcfs_arch_cleanup(void)
{
        return;
}

EXPORT_SYMBOL(libcfs_arch_init);
EXPORT_SYMBOL(libcfs_arch_cleanup);
EXPORT_SYMBOL(cfs_enter_debugger);
EXPORT_SYMBOL(cfs_daemonize);
EXPORT_SYMBOL(cfs_daemonize_ctxt);
EXPORT_SYMBOL(cfs_block_allsigs);
EXPORT_SYMBOL(cfs_block_sigs);
EXPORT_SYMBOL(cfs_block_sigsinv);
EXPORT_SYMBOL(cfs_restore_sigs);
EXPORT_SYMBOL(cfs_signal_pending);
EXPORT_SYMBOL(cfs_clear_sigpending);
