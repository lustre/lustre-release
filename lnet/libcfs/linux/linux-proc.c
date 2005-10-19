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

#include <linux/config.h>
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
extern char debug_file_path[1024];
extern char lnet_upcall[1024];

#define PSDEV_LNET  (0x100)
enum {
        PSDEV_DEBUG = 1,          /* control debugging */
        PSDEV_SUBSYSTEM_DEBUG,    /* control debugging */
        PSDEV_PRINTK,             /* force all errors to console */
        PSDEV_CONSOLE,            /* allow _any_ messages to console */
        PSDEV_DEBUG_PATH,         /* crashdump log location */
        PSDEV_DEBUG_DUMP_PATH,    /* crashdump tracelog location */
        PSDEV_LNET_UPCALL,        /* User mode upcall script  */
        PSDEV_LNET_MEMUSED,       /* bytes currently PORTAL_ALLOCated */
        PSDEV_LNET_CATASTROPHE,   /* if we have LBUGged or panic'd */
};

static struct ctl_table lnet_table[] = {
        {PSDEV_DEBUG, "debug", &libcfs_debug, sizeof(int), 0644, NULL,
         &proc_dointvec},
        {PSDEV_SUBSYSTEM_DEBUG, "subsystem_debug", &libcfs_subsystem_debug,
         sizeof(int), 0644, NULL, &proc_dointvec},
        {PSDEV_PRINTK, "printk", &libcfs_printk, sizeof(int), 0644, NULL,
         &proc_dointvec},
        {PSDEV_DEBUG_PATH, "debug_path", debug_file_path,
         sizeof(debug_file_path), 0644, NULL, &proc_dostring, &sysctl_string},
        {PSDEV_LNET_UPCALL, "upcall", lnet_upcall,
         sizeof(lnet_upcall), 0644, NULL, &proc_dostring,
         &sysctl_string},
        {PSDEV_LNET_MEMUSED, "memused", (int *)&libcfs_kmemory.counter,
         sizeof(int), 0644, NULL, &proc_dointvec},
        {PSDEV_LNET_CATASTROPHE, "catastrophe", &libcfs_catastrophe,
         sizeof(int), 0444, NULL, &proc_dointvec},
        {0}
};

static struct ctl_table top_table[2] = {
        {PSDEV_LNET, "lnet", NULL, 0, 0555, lnet_table},
        {0}
};


#ifdef PORTALS_PROFILING
/*
 * profiling stuff.  we do this statically for now 'cause its simple,
 * but we could do some tricks with elf sections to have this array
 * automatically built.
 */
#define def_prof(FOO) [PROF__##FOO] = {#FOO, 0, }

struct prof_ent prof_ents[] = {
        def_prof(placeholder),
};

EXPORT_SYMBOL(prof_ents);

/*
 * this function is as crazy as the proc filling api
 * requires.
 *
 * buffer: page allocated for us to scribble in.  the
 *  data returned to the user will be taken from here.
 * *start: address of the pointer that will tell the 
 *  caller where in buffer the data the user wants is.
 * ppos: offset in the entire /proc file that the user
 *  currently wants.
 * wanted: the amount of data the user wants.
 *
 * while going, 'curpos' is the offset in the entire
 * file where we currently are.  We only actually
 * start filling buffer when we get to a place in
 * the file that the user cares about.
 *
 * we take care to only sprintf when the user cares because
 * we're holding a lock while we do this.
 *
 * we're smart and know that we generate fixed size lines.
 * we only start writing to the buffer when the user cares.
 * This is unpredictable because we don't snapshot the
 * list between calls that are filling in a file from
 * the list.  The list could change mid read and the
 * output will look very weird indeed.  oh well.
 */

static int prof_read_proc(char *buffer, char **start, off_t ppos, int wanted,
                          int *eof, void *data)
{
        int len = 0, i;
        int curpos;
        char *header = "Interval        Cycles_per (Starts Finishes Total)\n";
        int header_len = strlen(header);
        char *format = "%-15s %.12Ld (%.12d %.12d %.12Ld)";
        int line_len = (15 + 1 + 12 + 2 + 12 + 1 + 12 + 1 + 12 + 1);

        *start = buffer;

        if (ppos < header_len) {
                int diff = MIN(header_len, wanted);
                memcpy(buffer, header + ppos, diff);
                len += diff;
                ppos += diff;
        }

        if (len >= wanted)
                goto out;

        curpos = header_len;

        for ( i = 0; i < MAX_PROFS ; i++) {
                int copied;
                struct prof_ent *pe = &prof_ents[i];
                long long cycles_per;
                /*
                 * find the part of the array that the buffer wants
                 */
                if (ppos >= (curpos + line_len))  {
                        curpos += line_len;
                        continue;
                }
                /* the clever caller split a line */
                if (ppos > curpos) {
                        *start = buffer + (ppos - curpos);
                }

                if (pe->finishes == 0)
                        cycles_per = 0;
                else
                {
                        cycles_per = pe->total_cycles;
                        do_div (cycles_per, pe->finishes);
                }

                copied = sprintf(buffer + len, format, pe->str, cycles_per,
                                 pe->starts, pe->finishes, pe->total_cycles);

                len += copied;

                /* pad to line len, -1 for \n */
                if ((copied < line_len-1)) {
                        int diff = (line_len-1) - copied;
                        memset(buffer + len, ' ', diff);
                        len += diff;
                        copied += diff;
                }

                buffer[len++]= '\n';

                /* bail if we have enough */
                if (((buffer + len) - *start) >= wanted)
                        break;

                curpos += line_len;
        }

        /* lameness */
        if (i == MAX_PROFS)
                *eof = 1;
 out:

        return MIN(((buffer + len) - *start), wanted);
}

/*
 * all kids love /proc :/
 */
static unsigned char basedir[]="net/lnet";
#endif /* PORTALS_PROFILING */

int insert_proc(void)
{
        struct proc_dir_entry *ent;
#if PORTALS_PROFILING
        unsigned char dir[128];

        if (ARRAY_SIZE(prof_ents) != MAX_PROFS) {
                CERROR("profiling enum and array are out of sync.\n");
                return -1;
        }

        /*
         * This is pretty lame.  assuming that failure just
         * means that they already existed.
         */
        strcat(dir, basedir);
        create_proc_entry(dir, S_IFDIR, 0);

        strcat(dir, "/cycles");
        ent = create_proc_entry(dir, 0, 0);
        if (!ent) {
                CERROR("couldn't register %s?\n", dir);
                return -1;
        }

        ent->data = NULL;
        ent->read_proc = prof_read_proc;
#endif /* PORTALS_PROFILING */

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

        proc_symlink("sys/portals", NULL, "/proc/sys/lnet");

        return 0;
}

void remove_proc(void)
{
#if PORTALS_PROFILING
        unsigned char dir[128];
        int end;

        dir[0]='\0';
        strcat(dir, basedir);

        end = strlen(dir);

        strcat(dir, "/cycles");
        remove_proc_entry(dir, 0);

        dir[end] = '\0';
        remove_proc_entry(dir, 0);
#endif /* PORTALS_PROFILING */

        remove_proc_entry("sys/portals", NULL);
        remove_proc_entry("sys/lnet/dump_kernel", NULL);
        remove_proc_entry("sys/lnet/daemon_file", NULL);
        remove_proc_entry("sys/lnet/debug_mb", NULL);

#ifdef CONFIG_SYSCTL
        if (lnet_table_header)
                unregister_sysctl_table(lnet_table_header);
        lnet_table_header = NULL;
#endif
}
