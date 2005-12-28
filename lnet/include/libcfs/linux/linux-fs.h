/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 *
 * Basic library routines. 
 *
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
#endif

typedef struct file cfs_file_t;
typedef struct dentry cfs_dentry_t;

#ifdef __KERNEL__

/*
 * Platform defines
 *
 * cfs_rdev_t
 */

typedef dev_t cfs_rdev_t;
typedef unsigned int cfs_major_nr_t;
typedef unsigned int cfs_minor_nr_t;

/*
 * Defined by platform.
 */
cfs_rdev_t     cfs_rdev_build(cfs_major_nr_t major, cfs_minor_nr_t minor);
cfs_major_nr_t cfs_rdev_major(cfs_rdev_t rdev);
cfs_minor_nr_t cfs_rdev_minor(cfs_rdev_t rdev);

/*
 * Generic on-wire rdev format.
 */

typedef __u32 cfs_wire_rdev_t;

cfs_wire_rdev_t cfs_wire_rdev_build(cfs_major_nr_t major, cfs_minor_nr_t minor);
cfs_major_nr_t  cfs_wire_rdev_major(cfs_wire_rdev_t rdev);
cfs_minor_nr_t  cfs_wire_rdev_minor(cfs_wire_rdev_t rdev);

#define cfs_filp_size(f)               ((f)->f_dentry->d_inode->i_size)
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
#define CFS_FLOCK_TYPE(fl)                  ((fl)->fl_type)
#define CFS_FLOCK_SET_TYPE(fl, type)        do { (fl)->fl_type = (type); } while(0)
#define CFS_FLOCK_PID(fl)                   ((fl)->fl_pid)
#define CFS_FLOCK_SET_PID(fl, pid)          do { (fl)->fl_pid = (pid); } while(0)
#define CFS_FLOCK_START(fl)                 ((fl)->fl_start)
#define CFS_FLOCK_SET_START(fl, start)      do { (fl)->fl_start = (start); } while(0)
#define CFS_FLOCK_END(fl)                   ((fl)->fl_end)
#define CFS_FLOCK_SET_END(fl, end)          do { (fl)->fl_end = (end); } while(0)

ssize_t cfs_user_write (cfs_file_t *filp, const char *buf, size_t count, loff_t *offset);
#endif

#endif
