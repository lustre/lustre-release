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
 */

#define DEBUG_SUBSYSTEM S_LNET
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <libcfs/libcfs.h>

#if defined(CONFIG_KGDB)
#include <asm/kgdb.h>
#endif

void cfs_enter_debugger(void)
{
#if defined(CONFIG_KGDB)
//        BREAKPOINT();
#elif defined(__arch_um__)
        asm("int $3");
#else
        /* nothing */
#endif
}

void cfs_daemonize(char *str) {
        unsigned long flags;

        lock_kernel();
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,63))
        daemonize(str);
#else
        daemonize();
        exit_files(current);
        reparent_to_init();
        snprintf (current->comm, sizeof (current->comm), "%s", str);
#endif
        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
        unlock_kernel();
}

int cfs_daemonize_ctxt(char *str) {
        struct task_struct *tsk = current;
        struct fs_struct *fs = NULL;

        cfs_daemonize(str);
        fs = copy_fs_struct(tsk->fs);
        if (fs == NULL)
                return -ENOMEM;
        exit_fs(tsk);
        tsk->fs = fs;
        return 0;
}


sigset_t
cfs_get_blockedsigs(void)
{
        unsigned long          flags;
        sigset_t        old;

        SIGNAL_MASK_LOCK(current, flags);
        old = current->blocked;
        SIGNAL_MASK_UNLOCK(current, flags);
        return old;
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

sigset_t
cfs_block_sigs(sigset_t bits)
{
        unsigned long  flags;
        sigset_t        old;

        SIGNAL_MASK_LOCK(current, flags);
        old = current->blocked;
        current->blocked = bits;
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
EXPORT_SYMBOL(cfs_daemonize);
EXPORT_SYMBOL(cfs_daemonize_ctxt);
EXPORT_SYMBOL(cfs_block_allsigs);
EXPORT_SYMBOL(cfs_block_sigs);
EXPORT_SYMBOL(cfs_get_blockedsigs);
EXPORT_SYMBOL(cfs_restore_sigs);
EXPORT_SYMBOL(cfs_signal_pending);
EXPORT_SYMBOL(cfs_clear_sigpending);
