/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_PROC_FS_H__
#define __LIBCFS_LINUX_PROC_FS_H__

#include_next <linux/proc_fs.h>

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

#endif /* __LIBCFS_LINUX_PROC_FS_H__ */
