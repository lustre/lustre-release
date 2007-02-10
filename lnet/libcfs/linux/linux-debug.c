/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#ifdef HAVE_KERNEL_CONFIG_H
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/interrupt.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/completion.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/miscdevice.h>
#include <linux/version.h>

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/kp30.h>
#include <libcfs/linux/portals_compat25.h>
#include <libcfs/libcfs.h>

#include "tracefile.h"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
#include <linux/kallsyms.h>
#endif

char lnet_upcall[1024] = "/usr/lib/lustre/lnet_upcall";

void libcfs_run_upcall(char **argv)
{
        int   rc;
        int   argc;
        char *envp[] = {
                "HOME=/",
                "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
                NULL};
        ENTRY;

        argv[0] = lnet_upcall;
        argc = 1;
        while (argv[argc] != NULL)
                argc++;

        LASSERT(argc >= 2);

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("Error %d invoking LNET upcall %s %s%s%s%s%s%s%s%s; "
                       "check /proc/sys/lnet/upcall\n",
                       rc, argv[0], argv[1],
                       argc < 3 ? "" : ",", argc < 3 ? "" : argv[2],
                       argc < 4 ? "" : ",", argc < 4 ? "" : argv[3],
                       argc < 5 ? "" : ",", argc < 5 ? "" : argv[4],
                       argc < 6 ? "" : ",...");
        } else {
                CWARN("Invoked LNET upcall %s %s%s%s%s%s%s%s%s\n",
                       argv[0], argv[1],
                       argc < 3 ? "" : ",", argc < 3 ? "" : argv[2],
                       argc < 4 ? "" : ",", argc < 4 ? "" : argv[3],
                       argc < 5 ? "" : ",", argc < 5 ? "" : argv[4],
                       argc < 6 ? "" : ",...");
        }
}

void libcfs_run_lbug_upcall(char *file, const char *fn, const int line)
{
        char *argv[6];
        char buf[32];

        ENTRY;
        snprintf (buf, sizeof buf, "%d", line);

        argv[1] = "LBUG";
        argv[2] = file;
        argv[3] = (char *)fn;
        argv[4] = buf;
        argv[5] = NULL;

        libcfs_run_upcall (argv);
}

#ifdef __arch_um__
void lbug_with_loc(char *file, const char *func, const int line)
{
        libcfs_catastrophe = 1;
        libcfs_debug_msg(NULL, 0, D_EMERG, file, func, line,
                         "LBUG - trying to dump log to /tmp/lustre-log\n");
        libcfs_debug_dumplog();
        libcfs_run_lbug_upcall(file, func, line);
        asm("int $3");
        panic("LBUG");
}
#else
/* coverity[+kill] */
void lbug_with_loc(char *file, const char *func, const int line)
{
        libcfs_catastrophe = 1;
        libcfs_debug_msg(NULL, 0, D_EMERG, file, func, line, "LBUG\n");

        if (in_interrupt()) {
                panic("LBUG in interrupt.\n");
                /* not reached */
        }

        libcfs_debug_dumpstack(NULL);
        libcfs_debug_dumplog();
        libcfs_run_lbug_upcall(file, func, line);
        set_task_state(current, TASK_UNINTERRUPTIBLE);
        while (1)
                schedule();
}
#endif /* __arch_um__ */

#ifdef __KERNEL__

void libcfs_debug_dumpstack(struct task_struct *tsk)
{
#if defined(__arch_um__)
        if (tsk != NULL)
                CWARN("stack dump for pid %d (%d) requested; wake up gdb.\n",
                      tsk->pid, UML_PID(tsk));
        //asm("int $3");
#elif defined(HAVE_SHOW_TASK)
        /* this is exported by lustre kernel version 42 */
        extern void show_task(struct task_struct *);

        if (tsk == NULL)
                tsk = current;
        CWARN("showing stack for process %d\n", tsk->pid);
        show_task(tsk);
#else
        CWARN("can't show stack: kernel doesn't export show_task\n");
        if ((tsk == NULL) || (tsk == current))
                dump_stack();
#endif
}

cfs_task_t *libcfs_current(void)
{
        CWARN("current task struct is %p\n", current);
        return current;
}

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
                trace_debug_print();
        } else {
                while (current->lock_depth >= 0)
                        unlock_kernel();

                libcfs_debug_dumplog_internal((void *)(long)cfs_curproc_pid());
        }
#endif
        return 0;
}

static struct notifier_block libcfs_panic_notifier = {
        notifier_call :     panic_notifier,
        next :              NULL,
        priority :          10000
};

void libcfs_register_panic_notifier(void)
{
#ifdef HAVE_ATOMIC_PANIC_NOTIFIER
        atomic_notifier_chain_register(&panic_notifier_list, &libcfs_panic_notifier);
#else
        notifier_chain_register(&panic_notifier_list, &libcfs_panic_notifier);
#endif
}

void libcfs_unregister_panic_notifier(void)
{
#ifdef HAVE_ATOMIC_PANIC_NOTIFIER
        atomic_notifier_chain_unregister(&panic_notifier_list, &libcfs_panic_notifier);
#else
        notifier_chain_unregister(&panic_notifier_list, &libcfs_panic_notifier);
#endif
}

EXPORT_SYMBOL(libcfs_debug_dumpstack);
EXPORT_SYMBOL(libcfs_current);

#endif /* __KERNEL__ */

EXPORT_SYMBOL(libcfs_run_upcall);
EXPORT_SYMBOL(libcfs_run_lbug_upcall);
EXPORT_SYMBOL(lbug_with_loc);
