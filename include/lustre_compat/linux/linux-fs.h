/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_FS_H__
#define __LIBCFS_LINUX_CFS_FS_H__

#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/mount.h>
#include <linux/backing-dev.h>
#include <linux/pagemap.h>

#ifndef HAVE_FILE_DENTRY
static inline struct dentry *file_dentry(const struct file *file)
{
	return file->f_path.dentry;
}
#endif

#ifndef S_DT_SHIFT
#define S_DT_SHIFT		12
#endif

#ifndef S_DT
#define S_DT(type)		(((type) & S_IFMT) >> S_DT_SHIFT)
#endif
#ifndef DTTOIF
#define DTTOIF(dirtype)		((dirtype) << S_DT_SHIFT)
#endif

#ifdef HAVE_PROC_OPS
#define PROC_OWNER(_fn)
#else
#define proc_ops file_operations
#define PROC_OWNER(_owner)		.owner = (_owner),
#define proc_open			open
#define proc_read			read
#define proc_write			write
#define proc_lseek			llseek
#define proc_release			release
#define proc_poll			poll
#define proc_ioctl			unlocked_ioctl
#define proc_compat_ioctl		compat_ioctl
#define proc_mmap			mmap
#define proc_get_unmapped_area		get_unmapped_area
#endif

static inline void mapping_clear_exiting(struct address_space *mapping)
{
#ifdef HAVE_MAPPING_AS_EXITING_FLAG
	clear_bit(AS_EXITING, &mapping->flags);
#endif
}

#endif /* __LIBCFS_LINUX_CFS_FS_H__ */
