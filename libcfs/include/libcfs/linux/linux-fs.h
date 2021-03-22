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
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/include/libcfs/linux/linux-fs.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_FS_H__
#define __LIBCFS_LINUX_CFS_FS_H__

#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/mount.h>
#include <linux/backing-dev.h>

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

#endif
