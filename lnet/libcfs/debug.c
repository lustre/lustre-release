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

# define DEBUG_SUBSYSTEM S_PORTALS

#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>

#include "tracefile.h"

unsigned int portal_subsystem_debug = ~0 - (S_PORTALS | S_NAL);
EXPORT_SYMBOL(portal_subsystem_debug);

unsigned int portal_debug = (D_WARNING | D_DLMTRACE | D_ERROR | D_EMERG | D_HA |
                             D_RPCTRACE | D_VFSTRACE);
EXPORT_SYMBOL(portal_debug);

unsigned int portal_printk;
EXPORT_SYMBOL(portal_printk);

unsigned int portal_stack;
EXPORT_SYMBOL(portal_stack);

#ifdef __KERNEL__
atomic_t portal_kmemory = ATOMIC_INIT(0);
EXPORT_SYMBOL(portal_kmemory);
#endif

static cfs_waitq_t debug_ctlwq;

char debug_file_path[1024] = "/tmp/lustre-log";
static char debug_file_name[1024];

void portals_debug_dumplog_internal(void *arg)
{
        CFS_DECL_JOURNAL_DATA;

        CFS_PUSH_JOURNAL;

        snprintf(debug_file_name, sizeof(debug_file_path) - 1,
                 "%s.%ld.%ld", debug_file_path, cfs_time_current_sec(), (long)arg);
        printk(KERN_ALERT "LustreError: dumping log to %s\n", debug_file_name);
        tracefile_dump_all_pages(debug_file_name);

        CFS_POP_JOURNAL;
}

int portals_debug_dumplog_thread(void *arg)
{
        kportal_daemonize("");
        reparent_to_init();
        portals_debug_dumplog_internal(arg);
        cfs_waitq_signal(&debug_ctlwq);
        return 0;
}

void portals_debug_dumplog(void)
{
        int            rc;
        cfs_waitlink_t wait;
        ENTRY;

        /* we're being careful to ensure that the kernel thread is
         * able to set our state to running as it exits before we
         * get to schedule() */
        cfs_waitlink_init(&wait);
        set_current_state(TASK_INTERRUPTIBLE);
        cfs_waitq_add(&debug_ctlwq, &wait);

        rc = cfs_kernel_thread(portals_debug_dumplog_thread,
                               (void *)(long)cfs_curproc_pid(),
                               CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0)
                printk(KERN_ERR "LustreError: cannot start log dump thread: "
                       "%d\n", rc);
        else
                schedule();

        /* be sure to teardown if kernel_thread() failed */
        cfs_waitq_del(&debug_ctlwq, &wait);
        set_current_state(TASK_RUNNING);
}

#ifdef PORTALS_DUMP_ON_PANIC
static int panic_dumplog(struct notifier_block *self, unsigned long unused1,
                         void *unused2)
{
        static int handled_panic; /* to avoid recursive calls to notifiers */

        if (handled_panic)
                return 0;
        else
                handled_panic = 1;

        if (in_interrupt()) {
                trace_debug_print();
                return 0;
        }

        while (current->lock_depth >= 0)
                unlock_kernel();
        portals_debug_dumplog();
        return 0;
}

static struct notifier_block lustre_panic_notifier = {
        notifier_call :     panic_dumplog,
        next :              NULL,
        priority :          10000
};
#endif

#ifdef CRAY_PORTALS
extern void *lus_portals_debug;
#endif

int portals_debug_init(unsigned long bufsize)
{
        cfs_waitq_init(&debug_ctlwq);
#ifdef CRAY_PORTALS
        lus_portals_debug = &portals_debug_msg;
#endif
#ifdef PORTALS_DUMP_ON_PANIC
        /* This is currently disabled because it spews far too much to the
         * console on the rare cases it is ever triggered. */
        notifier_chain_register(&panic_notifier_list, &lustre_panic_notifier);
#endif
        return tracefile_init();
}

int portals_debug_cleanup(void)
{
        tracefile_exit();
#ifdef PORTALS_DUMP_ON_PANIC
        notifier_chain_unregister(&panic_notifier_list, &lustre_panic_notifier);
#endif
#ifdef CRAY_PORTALS
        lus_portals_debug = NULL;
#endif
        return 0;
}

int portals_debug_clear_buffer(void)
{
        trace_flush_pages();
        return 0;
}

/* Debug markers, although printed by S_PORTALS
 * should not be be marked as such. */
#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_UNDEFINED
int portals_debug_mark_buffer(char *text)
{
        CDEBUG(D_TRACE,"***************************************************\n");
        CDEBUG(D_WARNING, "DEBUG MARKER: %s\n", text);
        CDEBUG(D_TRACE,"***************************************************\n");

        return 0;
}
#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_PORTALS

void portals_debug_set_level(unsigned int debug_level)
{
        printk(KERN_WARNING "Lustre: Setting portals debug level to %08x\n",
               debug_level);
        portal_debug = debug_level;
}

char *portals_nid2str(int nal, ptl_nid_t nid, char *str)
{
        if (nid == PTL_NID_ANY) {
                snprintf(str, PTL_NALFMT_SIZE, "%s", "PTL_NID_ANY");
                return str;
        }

        switch(nal){
/* XXX this could be a nal method of some sort, 'cept it's config
 * dependent whether (say) socknal NIDs are actually IP addresses... */
#if !CRAY_PORTALS
        case TCPNAL:
                /* userspace NAL */
        case IIBNAL:
        case VIBNAL:
        case OPENIBNAL:
        case RANAL:
        case SOCKNAL:
                snprintf(str, PTL_NALFMT_SIZE, "%u:%u.%u.%u.%u",
                         (__u32)(nid >> 32), HIPQUAD(nid));
                break;
        case QSWNAL:
        case GMNAL:
        case LONAL:
                snprintf(str, PTL_NALFMT_SIZE, "%u:%u",
                         (__u32)(nid >> 32), (__u32)nid);
                break;
#endif
        default:
                snprintf(str, PTL_NALFMT_SIZE, "?%x? %llx",
                         nal, (long long)nid);
                break;
        }
        return str;
}

char *portals_id2str(int nal, ptl_process_id_t id, char *str)
{
        int   len;

        portals_nid2str(nal, id.nid, str);
        len = strlen(str);
        snprintf(str + len, PTL_NALFMT_SIZE - len, "-%u", id.pid);
        return str;
}

EXPORT_SYMBOL(portals_debug_dumplog);
EXPORT_SYMBOL(portals_debug_set_level);
EXPORT_SYMBOL(portals_nid2str);
EXPORT_SYMBOL(portals_id2str);
