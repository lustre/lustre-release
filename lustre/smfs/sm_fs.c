/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/sm_fs.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_SM

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/miscdevice.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>

#include "smfs_internal.h"

int sm_stack = 0;
long sm_kmemory = 0;

MODULE_AUTHOR("Peter J. Braam <braam@cs.cmu.edu>");
MODULE_DESCRIPTION("Smfs file system filters v0.01");
MODULE_LICENSE("GPL");

extern int init_smfs(void);
extern int cleanup_smfs(void);

static int __init smfs_init(void)
{
        int err;

        if ( (err = init_smfs_psdev()) ) {
                printk("Error initializing smfs_psdev, %d\n", err);
                return -EINVAL;
        }

        if ( (err = init_smfs()) ) {
                printk("Error initializing smfs, %d\n", err);
                return -EINVAL;
        }

        if ( (err = init_smfs_proc_sys()) ) {
                printk("Error initializing smfs proc sys, %d\n", err);
                return -EINVAL;
        }

        return 0;
}

static void __exit smfs_cleanup(void)
{
        cleanup_smfs();
        smfs_cleanup_psdev();
}
module_init(smfs_init);
module_exit(smfs_cleanup);
