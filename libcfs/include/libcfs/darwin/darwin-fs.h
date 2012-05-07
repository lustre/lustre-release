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
typedef struct cfs_kern_file {
        int             f_flags;
        vnode_t         f_vp;
        vfs_context_t   f_ctxt;
} cfs_file_t;

#else

typedef struct file cfs_file_t;

#endif

int	kern_file_size(cfs_file_t *fp, off_t	*size);
#define cfs_filp_size(fp)			\
	({					\
		off_t		__size;		\
		kern_file_size((fp), &__size);	\
		__size;				\
	 })
#define cfs_filp_poff(fp)               (NULL)

cfs_file_t *kern_file_open(const char *name, int flags, int mode, int *err);
int kern_file_close(cfs_file_t *fp);
int kern_file_read(cfs_file_t *fp, void *buf, size_t nbytes, off_t *pos);
int kern_file_write(cfs_file_t *fp, void *buf, size_t nbytes, off_t *pos);
int kern_file_sync(cfs_file_t *fp);

#define cfs_filp_open(n, f, m, e)	kern_file_open(n, f, m, e)
#define cfs_filp_close(f)		kern_file_close(f)
#define cfs_filp_read(f, b, n, p)	kern_file_read(f, b, n, p)
#define cfs_filp_write(f, b, n, p)	kern_file_write(f, b, n, p)
#define cfs_filp_fsync(f)		kern_file_sync(f)

int ref_file(cfs_file_t *fp);
int rele_file(cfs_file_t *fp);
int file_count(cfs_file_t *fp);
#define cfs_get_file(f)			ref_file(f)
#define cfs_put_file(f)			rele_file(f)
#define cfs_file_count(f)		file_count(f)

#define CFS_INT_LIMIT(x)		(~((x)1 << (sizeof(x)*8 - 1)))
#define CFS_OFFSET_MAX			CFS_INT_LIMIT(loff_t)

typedef struct flock			cfs_flock_t;
#define cfs_flock_type(fl)		((fl)->l_type)
#define cfs_flock_set_type(fl, type)	do { (fl)->l_type = (type); } while(0)
#define cfs_flock_pid(fl)		((fl)->l_pid)
#define cfs_flock_set_pid(fl, pid)	do { (fl)->l_pid = (pid); } while(0)
#define cfs_flock_start(fl)		((fl)->l_start)
#define cfs_flock_set_start(fl, start)	do { (fl)->l_start = (start); } while(0)

static inline loff_t cfs_flock_end(cfs_flock_t *fl)
{
        return (fl->l_len == 0 ? CFS_OFFSET_MAX: (fl->l_start + fl->l_len));
}

static inline void cfs_flock_set_end(cfs_flock_t *fl, loff_t end)
{
        if (end == CFS_OFFSET_MAX)
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
static inline void posix_acl_release(struct posix_acl *acl) {};
static inline int posix_acl_valid(const struct posix_acl *acl) { return 0; }
static inline struct posix_acl * posix_acl_dup(struct posix_acl *acl) 
{ 
        return acl;
}

#else	/* !__KERNEL__ */

typedef struct file cfs_file_t;

#endif	/* END __KERNEL__ */

typedef struct {
	void	*d;
} cfs_dentry_t;

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
