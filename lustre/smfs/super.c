/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/super.c
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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/loop.h>
#include <linux/errno.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include "smfs_internal.h"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static struct super_block *smfs_read_super(struct super_block *sb, 
                                           void *data, int silent)
{
        int err;

        err = smfs_fill_super(sb, data, silent);
        if (err)
                return NULL;

        return sb;
}

static struct file_system_type smfs_type = {
        .owner       = THIS_MODULE,
        .name        = "smfs",
        .read_super  = smfs_read_super,
};
#else
struct super_block *smfs_get_sb(struct file_system_type *fs_type, int flags, 
                                const char *dev_name, void *data)
{
        return get_sb_nodev(fs_type, flags, data, smfs_fill_super);
}
void smfs_kill_super(struct super_block *sb)
{
        smfs_cleanup_hooks(S2SMI(sb));
        kill_anon_super(sb);
}
static struct file_system_type smfs_type = {
        .owner       = THIS_MODULE,
        .name        = "smfs",
        .get_sb      = smfs_get_sb,
        .kill_sb     = smfs_kill_super,
};
#endif

static int cleanup_smfs(void)
{
        int err = 0;

        err = unregister_filesystem(&smfs_type);
        if (err)
                CERROR("unregister_filesystem() failed, rc = %d\n", err);
        return 0;
}
static int init_smfs(void)
{
        int err;
        
        err = register_filesystem(&smfs_type);
        if (err)
                CERROR("register_filesystem() failed, rc = %d\n", err);
        return err;
}
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

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Smfs file system filters v0.01");
MODULE_LICENSE("GPL");

module_init(smfs_init);
module_exit(smfs_cleanup);
