/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@zabbo.net>
 *   Author: Peter J. Braam <braam@clusterfs.com>
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
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <net/sock.h>
#include <linux/uio.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <asm/segment.h>

#include <linux/proc_fs.h>
#include <linux/sysctl.h>

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/kp30.h>
#include <asm/div64.h>
#include "tracefile.h"

static struct ctl_table_header *lnet_table_header = NULL;
extern char lnet_upcall[1024];

#define PSDEV_LNET  (0x100)
enum {
        PSDEV_DEBUG = 1,          /* control debugging */
        PSDEV_SUBSYSTEM_DEBUG,    /* control debugging */
        PSDEV_PRINTK,             /* force all messages to console */
        PSDEV_CONSOLE_RATELIMIT,  /* ratelimit console messages */
        PSDEV_DEBUG_PATH,         /* crashdump log location */
        PSDEV_DEBUG_DUMP_PATH,    /* crashdump tracelog location */
        PSDEV_LNET_UPCALL,        /* User mode upcall script  */
        PSDEV_LNET_MEMUSED,       /* bytes currently PORTAL_ALLOCated */
        PSDEV_LNET_CATASTROPHE,   /* if we have LBUGged or panic'd */
};

int LL_PROC_PROTO(proc_dobitmasks);

static struct ctl_table lnet_table[] = {
        {PSDEV_DEBUG, "debug", &libcfs_debug, sizeof(int), 0644, NULL,
         &proc_dobitmasks},
        {PSDEV_SUBSYSTEM_DEBUG, "subsystem_debug", &libcfs_subsystem_debug,
         sizeof(int), 0644, NULL, &proc_dobitmasks},
        {PSDEV_PRINTK, "printk", &libcfs_printk, sizeof(int), 0644, NULL,
         &proc_dobitmasks},
        {PSDEV_CONSOLE_RATELIMIT, "console_ratelimit",&libcfs_console_ratelimit,
         sizeof(int), 0644, NULL, &proc_dointvec},
        {PSDEV_DEBUG_PATH, "debug_path", debug_file_path,
         sizeof(debug_file_path), 0644, NULL, &proc_dostring, &sysctl_string},
        {PSDEV_LNET_UPCALL, "upcall", lnet_upcall,
         sizeof(lnet_upcall), 0644, NULL, &proc_dostring,
         &sysctl_string},
        {PSDEV_LNET_MEMUSED, "memused", (int *)&libcfs_kmemory.counter,
         sizeof(int), 0444, NULL, &proc_dointvec},
        {PSDEV_LNET_CATASTROPHE, "catastrophe", &libcfs_catastrophe,
         sizeof(int), 0444, NULL, &proc_dointvec},
        {0}
};

static struct ctl_table top_table[2] = {
        {PSDEV_LNET, "lnet", NULL, 0, 0555, lnet_table},
        {0}
};

int LL_PROC_PROTO(proc_dobitmasks)
{
        const int     tmpstrlen = 512;
        char         *str;
        int           rc = 0;
        /* the proc filling api stumps me always, coax proc_dointvec
         * and proc_dostring into doing the drudgery by cheating
         * with a dummy ctl_table
         */
        struct ctl_table dummy = *table;
        unsigned int *mask = (unsigned int *)table->data;
        int           is_subsys = (mask == &libcfs_subsystem_debug) ? 1 : 0;

	str = kmalloc(tmpstrlen, GFP_USER);
        if (str == NULL)
                return -ENOMEM;

        if (write) {
                size_t oldlen = *lenp;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
                loff_t oldpos = *ppos;
#endif

                dummy.proc_handler = &proc_dointvec;

                /* old proc interface allows user to specify just an int
                 * value; be compatible and don't break userland.
                 */
                rc = ll_proc_dointvec(&dummy, write, filp, buffer, lenp, ppos);

                if (rc != -EINVAL)
                        goto out;

                /* using new interface */
                dummy.data = str;
                dummy.maxlen = tmpstrlen;
                dummy.proc_handler = &proc_dostring;

                /* proc_dointvec might have changed these */
                *lenp = oldlen;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
                *ppos = oldpos;
#endif

                rc = ll_proc_dostring(&dummy, write, filp, buffer, lenp, ppos);

                if (rc != 0)
                        goto out;

                rc = libcfs_debug_str2mask(mask, dummy.data, is_subsys);
        } else {
                dummy.data = str;
                dummy.maxlen = tmpstrlen;
                dummy.proc_handler = &proc_dostring;

                libcfs_debug_mask2str(dummy.data, dummy.maxlen,*mask,is_subsys);

                rc = ll_proc_dostring(&dummy, write, filp, buffer, lenp, ppos);
        }

out:
        kfree(str);
        return rc;
}

int insert_proc(void)
{
        struct proc_dir_entry *ent;

#ifdef CONFIG_SYSCTL
        if (!lnet_table_header)
                lnet_table_header = register_sysctl_table(top_table, 0);
#endif

        ent = create_proc_entry("sys/lnet/dump_kernel", 0, NULL);
        if (ent == NULL) {
                CERROR("couldn't register dump_kernel\n");
                return -1;
        }
        ent->write_proc = trace_dk;

        ent = create_proc_entry("sys/lnet/daemon_file", 0, NULL);
        if (ent == NULL) {
                CERROR("couldn't register daemon_file\n");
                return -1;
        }
        ent->write_proc = trace_write_daemon_file;
        ent->read_proc = trace_read_daemon_file;

        ent = create_proc_entry("sys/lnet/debug_mb", 0, NULL);
        if (ent == NULL) {
                CERROR("couldn't register debug_mb\n");
                return -1;
        }
        ent->write_proc = trace_write_debug_mb;
        ent->read_proc = trace_read_debug_mb;

        return 0;
}

void remove_proc(void)
{
        remove_proc_entry("sys/lnet/dump_kernel", NULL);
        remove_proc_entry("sys/lnet/daemon_file", NULL);
        remove_proc_entry("sys/lnet/debug_mb", NULL);

#ifdef CONFIG_SYSCTL
        if (lnet_table_header)
                unregister_sysctl_table(lnet_table_header);
        lnet_table_header = NULL;
#endif
}
