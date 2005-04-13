/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lib/fsfilt_smfs.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Wang Di <wangdi@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/version.h>
#include <libcfs/kp30.h>
#include <linux/lustre_fsfilt.h>
//#include <linux/lustre_smfs.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/module.h>
#include <linux/init.h>

extern struct fsfilt_operations * get_smfs_fs_ops(void);

static int __init fsfilt_smfs_init(void)
{
        int rc = -ENOSYS;
        struct fsfilt_operations * fs_ops = get_smfs_fs_ops();
        
        rc = fsfilt_register_ops(fs_ops);
        return rc;
}

static void __exit fsfilt_smfs_exit(void)
{
        fsfilt_unregister_ops(get_smfs_fs_ops());
}

module_init(fsfilt_smfs_init);
module_exit(fsfilt_smfs_exit);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre SMFS Filesystem Helper v0.1");
MODULE_LICENSE("GPL");
