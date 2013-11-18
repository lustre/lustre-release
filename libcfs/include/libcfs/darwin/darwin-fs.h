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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/darwin/darwin-fs.h
 *
 * Implementation of standard file system interfaces for XNU kernel.
 */

#ifndef __LIBCFS_DARWIN_FS_H__
#define __LIBCFS_DARWIN_FS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__

#include <sys/types.h>
#include <sys/systm.h>

#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/filedesc.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <sys/mbuf.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <stdarg.h>

#include <mach/mach_types.h>
#include <mach/time_value.h>
#include <kern/clock.h>
#include <sys/param.h>
#include <IOKit/system.h>

#include <libcfs/darwin/darwin-types.h>
#include <libcfs/darwin/darwin-lock.h>
#include <libcfs/darwin/darwin-mem.h>
#include <libcfs/list.h>

/*
 * File operating APIs in kernel
 */
#ifdef __DARWIN8__
/*
 * Kernel file descriptor
 */
struct file {
	unsigned	f_flags;
	vnode_t		f_vp;
	vfs_context_t	f_ctxt;
};
#endif

int kern_file_size(struct file *fp, off_t *size);
#define filp_size(fp)				\
	({					\
		off_t		__size;		\
		kern_file_size((fp), &__size);	\
		__size;				\
	 })
#define filp_poff(fp)               (NULL)

struct file *kern_file_open(const char *name, int flags, int mode);
int kern_file_close(struct file *fp);
int kern_file_read(struct file *fp, void *buf, size_t nbytes, off_t *pos);
int kern_file_write(struct file *fp, void *buf, size_t nbytes, off_t *pos);
int kern_file_sync(struct file *fp);

#define filp_open(n, f, m)		kern_file_open(n, f, m)
#define filp_close(f, i)		kern_file_close(f)
#define filp_read(f, b, n, p)		kern_file_read(f, b, n, p)
#define filp_write(f, b, n, p)		kern_file_write(f, b, n, p)
#define filp_fsync(f)			kern_file_sync(f)

int ref_file(struct file *fp);
int rele_file(struct file *fp);
int file_count(struct file *fp);
#define get_file(f)			ref_file(f)
#define fput(f)				rele_file(f)

#define INT_LIMIT(x)			(~((x)1 << (sizeof(x)*8 - 1)))
#define OFFSET_MAX			INT_LIMIT(loff_t)

#define file_lock			flock
#define flock_type(fl)			((fl)->l_type)
#define flock_set_type(fl, type)	do { (fl)->l_type = (type); } while (0)
#define flock_pid(fl)			((fl)->l_pid)
#define flock_set_pid(fl, pid)		do { (fl)->l_pid = (pid); } while (0)
#define flock_start(fl)			((fl)->l_start)
#define flock_set_start(fl, st)		do { (fl)->l_start = (st); } while (0)

static inline loff_t flock_end(struct file_lock *fl)
{
	return (fl->l_len == 0 ? OFFSET_MAX : (fl->l_start + fl->l_len));
}

static inline void flock_set_end(struct file_lock *fl, loff_t end)
{
	if (end == OFFSET_MAX)
		fl->l_len = 0;
	else
		fl->l_len = end - fl->l_start;
}

#define ATTR_MODE       0x0001
#define ATTR_UID        0x0002
#define ATTR_GID        0x0004
#define ATTR_SIZE       0x0008
#define ATTR_ATIME      0x0010
#define ATTR_MTIME      0x0020
#define ATTR_CTIME      0x0040
#define ATTR_ATIME_SET  0x0080
#define ATTR_MTIME_SET  0x0100
#define ATTR_FORCE      0x0200  /* Not a change, but a change it */
#define ATTR_ATTR_FLAG  0x0400
#define ATTR_RAW        0x0800  /* file system, not vfs will massage attrs */
#define ATTR_FROM_OPEN  0x1000  /* called from open path, ie O_TRUNC */
#define ATTR_CTIME_SET  0x2000
#define ATTR_BLOCKS     0x4000
#define ATTR_KILL_SUID  0
#define ATTR_KILL_SGID  0

#define in_group_p(x)	(0)

struct posix_acl_entry {
        short                   e_tag;
        unsigned short          e_perm;
        unsigned int            e_id;
};

struct posix_acl {
        atomic_t                a_refcount;
        unsigned int            a_count;
        struct posix_acl_entry  a_entries[0];
};

struct posix_acl *posix_acl_alloc(int count, int flags);
static inline struct posix_acl *posix_acl_from_xattr(const void *value,
                                                     size_t size)
{
        return posix_acl_alloc(0, 0);
}
#define posix_acl_from_xattr(a,b,c) posix_acl_from_xattr(b,c)

static inline void posix_acl_release(struct posix_acl *acl) {};
static inline int posix_acl_valid(const struct posix_acl *acl) { return 0; }
static inline struct posix_acl * posix_acl_dup(struct posix_acl *acl) 
{ 
        return acl;
}
#endif	/* END __KERNEL__ */

struct dentry {
	void	*d;
};

#ifndef O_SYNC
#define O_SYNC					0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY				0
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE				0
#endif

#endif
