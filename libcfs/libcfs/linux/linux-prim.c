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

#ifndef HAVE_KTIME_GET_TS64
void ktime_get_ts64(struct timespec64 *ts)
{
	struct timespec now;

	ktime_get_ts(&now);
	*ts = timespec_to_timespec64(now);
}
EXPORT_SYMBOL(ktime_get_ts64);
#endif /* HAVE_KTIME_GET_TS64 */

#ifndef HAVE_KTIME_GET_REAL_TS64
void ktime_get_real_ts64(struct timespec64 *ts)
{
	struct timespec now;

	getnstimeofday(&now);
	*ts = timespec_to_timespec64(now);
}
EXPORT_SYMBOL(ktime_get_real_ts64);
#endif /* HAVE_KTIME_GET_REAL_TS64 */

#ifndef HAVE_KTIME_GET_REAL_SECONDS
/*
 * Get the seconds portion of CLOCK_REALTIME (wall clock).
 * This is the clock that can be altered by NTP and is
 * independent of a reboot.
 */
time64_t ktime_get_real_seconds(void)
{
	return (time64_t)get_seconds();
}
EXPORT_SYMBOL(ktime_get_real_seconds);
#endif /* HAVE_KTIME_GET_REAL_SECONDS */

#ifndef HAVE_KTIME_GET_SECONDS
/*
 * Get the seconds portion of CLOCK_MONOTONIC
 * This clock is immutable and is reset across
 * reboots. For older platforms this is a
 * wrapper around get_seconds which is valid
 * until 2038. By that time this will be gone
 * one would hope.
 */
time64_t ktime_get_seconds(void)
{
	struct timespec64 now;

	ktime_get_ts64(&now);
	return now.tv_sec;
}
EXPORT_SYMBOL(ktime_get_seconds);
#endif /* HAVE_KTIME_GET_SECONDS */

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
EXPORT_SYMBOL(cfs_block_allsigs);

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
EXPORT_SYMBOL(cfs_block_sigs);

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
EXPORT_SYMBOL(cfs_block_sigsinv);

void
cfs_restore_sigs(sigset_t old)
{
	unsigned long  flags;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	current->blocked = old;
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
}
EXPORT_SYMBOL(cfs_restore_sigs);

void
cfs_clear_sigpending(void)
{
	unsigned long flags;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	clear_tsk_thread_flag(current, TIF_SIGPENDING);
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
}
EXPORT_SYMBOL(cfs_clear_sigpending);
