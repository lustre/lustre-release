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

void cfs_init_timer(struct timer_list *t)
{
	init_timer(t);
}
EXPORT_SYMBOL(cfs_init_timer);

void cfs_timer_init(struct timer_list *t, cfs_timer_func_t *func, void *arg)
{
	init_timer(t);
	t->function = func;
	t->data = (unsigned long)arg;
}
EXPORT_SYMBOL(cfs_timer_init);

void cfs_timer_done(struct timer_list *t)
{
	return;
}
EXPORT_SYMBOL(cfs_timer_done);

void cfs_timer_arm(struct timer_list *t, cfs_time_t deadline)
{
	mod_timer(t, deadline);
}
EXPORT_SYMBOL(cfs_timer_arm);

void cfs_timer_disarm(struct timer_list *t)
{
	del_timer(t);
}
EXPORT_SYMBOL(cfs_timer_disarm);

int  cfs_timer_is_armed(struct timer_list *t)
{
	return timer_pending(t);
}
EXPORT_SYMBOL(cfs_timer_is_armed);

cfs_time_t cfs_timer_deadline(struct timer_list *t)
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

sigset_t
cfs_block_allsigs(void)
{
	unsigned long	flags;
	sigset_t	old;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	old = current->blocked;
	sigfillset(&current->blocked);
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
	return old;
}

sigset_t cfs_block_sigs(unsigned long sigs)
{
	unsigned long  flags;
	sigset_t	old;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	old = current->blocked;
	sigaddsetmask(&current->blocked, sigs);
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
	return old;
}

/* Block all signals except for the @sigs */
sigset_t cfs_block_sigsinv(unsigned long sigs)
{
	unsigned long flags;
	sigset_t old;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	old = current->blocked;
	sigaddsetmask(&current->blocked, ~sigs);
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
	return old;
}

void
cfs_restore_sigs(sigset_t old)
{
	unsigned long  flags;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	current->blocked = old;
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
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

	spin_lock_irqsave(&current->sighand->siglock, flags);
	clear_tsk_thread_flag(current, TIF_SIGPENDING);
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
}

EXPORT_SYMBOL(cfs_enter_debugger);
EXPORT_SYMBOL(cfs_block_allsigs);
EXPORT_SYMBOL(cfs_block_sigs);
EXPORT_SYMBOL(cfs_block_sigsinv);
EXPORT_SYMBOL(cfs_restore_sigs);
EXPORT_SYMBOL(cfs_signal_pending);
EXPORT_SYMBOL(cfs_clear_sigpending);
