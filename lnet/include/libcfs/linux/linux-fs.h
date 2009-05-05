/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/include/libcfs/linux/linux-fs.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_FS_H__
#define __LIBCFS_LINUX_CFS_FS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/mount.h>
#else /* !__KERNEL__ */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <mntent.h>
#endif  /* __KERNEL__ */

typedef struct file cfs_file_t;
typedef struct dentry cfs_dentry_t;
typedef struct dirent64 cfs_dirent_t;

#ifdef __KERNEL__
#define cfs_filp_size(f)               (i_size_read((f)->f_dentry->d_inode))
#define cfs_filp_poff(f)                (&(f)->f_pos)

/* 
 * XXX Do we need to parse flags and mode in cfs_filp_open? 
 */
cfs_file_t *cfs_filp_open (const char *name, int flags, int mode, int *err);
#define cfs_filp_close(f)                   filp_close(f, NULL)
#define cfs_filp_read(fp, buf, size, pos)   (fp)->f_op->read((fp), (buf), (size), pos)
#define cfs_filp_write(fp, buf, size, pos)  (fp)->f_op->write((fp), (buf), (size), pos)
#define cfs_filp_fsync(fp)                  (fp)->f_op->fsync((fp), (fp)->f_dentry, 1)

#define cfs_get_file(f)                     get_file(f)
#define cfs_put_file(f)                     fput(f)
#define cfs_file_count(f)                   file_count(f)

typedef struct file_lock cfs_flock_t;
#define cfs_flock_type(fl)                  ((fl)->fl_type)
#define cfs_flock_set_type(fl, type)        do { (fl)->fl_type = (type); } while(0)
#define cfs_flock_pid(fl)                   ((fl)->fl_pid)
#define cfs_flock_set_pid(fl, pid)          do { (fl)->fl_pid = (pid); } while(0)
#define cfs_flock_start(fl)                 ((fl)->fl_start)
#define cfs_flock_set_start(fl, start)      do { (fl)->fl_start = (start); } while(0)
#define cfs_flock_end(fl)                   ((fl)->fl_end)
#define cfs_flock_set_end(fl, end)          do { (fl)->fl_end = (end); } while(0)

ssize_t cfs_user_write (cfs_file_t *filp, const char *buf, size_t count, loff_t *offset);

#endif
#define CFS_IFTODT(type)   (((type) & 0170000) >> 12)

#endif
