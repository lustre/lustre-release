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
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/linux/linux-fs.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_FS_H__
#define __LIBCFS_LINUX_CFS_FS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifndef __KERNEL__
#error This include is only for kernel use.
#endif

#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/mount.h>
#include <linux/backing-dev.h>
#include <linux/posix_acl_xattr.h>

#ifndef HAVE_FILE_DENTRY
static inline struct dentry *file_dentry(const struct file *file)
{
	return file->f_path.dentry;
}
#endif

#if defined(HAVE_FILE_FSYNC_4ARGS) || defined(HAVE_FILE_FSYNC_2ARGS)
#define ll_vfs_fsync_range(fp, start, end, datasync) \
	vfs_fsync_range(fp, start, end, datasync)
#else
#define ll_vfs_fsync_range(fp, start, end, datasync) \
	vfs_fsync_range(fp, file_dentry(fp), start, end, datasync)
#endif

#define flock_type(fl)			((fl)->fl_type)
#define flock_set_type(fl, type)	do { (fl)->fl_type = (type); } while (0)
#define flock_pid(fl)			((fl)->fl_pid)
#define flock_set_pid(fl, pid)		do { (fl)->fl_pid = (pid); } while (0)
#define flock_start(fl)			((fl)->fl_start)
#define flock_set_start(fl, st)		do { (fl)->fl_start = (st); } while (0)
#define flock_end(fl)			((fl)->fl_end)
#define flock_set_end(fl, end)		do { (fl)->fl_end = (end); } while (0)

#ifndef IFSHIFT
#define IFSHIFT			12
#endif

#ifndef IFTODT
#define IFTODT(type)		(((type) & S_IFMT) >> IFSHIFT)
#endif
#ifndef DTTOIF
#define DTTOIF(dirtype)		((dirtype) << IFSHIFT)
#endif

#ifndef HAVE_POSIXACL_USER_NS
/*
 * Mask out &init_user_ns so we don't jump
 * through hoops to define it somehow only
 * to have it ignored anyway.
 */
#define posix_acl_from_xattr(a,b,c)	posix_acl_from_xattr(b,c)
#define posix_acl_to_xattr(a,b,c,d)	posix_acl_to_xattr(b,c,d)
#endif

#ifndef HAVE_POSIX_ACL_VALID_USER_NS
#define posix_acl_valid(a,b) posix_acl_valid(b)
#endif
#endif
