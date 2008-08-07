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
 * libcfs/include/libcfs/winnt/winnt-fs.h
 *
 * File operations & routines.
 */

#ifndef __LIBCFS_WINNT_CFS_FS_H__
#define __LIBCFS_WINNT_CFS_FS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif


#define MINORBITS	8
#define MINORMASK	((1U << MINORBITS) - 1)

#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))
#define NODEV		0
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))


#ifdef __KERNEL__

struct file_operations
{
    loff_t (*lseek)(struct file * file, loff_t offset, int origin);
    ssize_t (*read) (struct file * file, char * buf, size_t nbytes, loff_t *ppos);
    ssize_t (*write)(struct file * file, const char * buffer,
        size_t count, loff_t *ppos);
    int (*ioctl) (struct file *, unsigned int, ulong_ptr);
    int (*open) (struct file *);
    int (*release) (struct file *);
};

struct file {

    cfs_handle_t            f_handle;
    unsigned int            f_flags;
    mode_t                  f_mode;
    ulong_ptr           f_count;

    //struct list_head      f_list;
    //struct dentry *       f_dentry;

    cfs_proc_entry_t *      proc_dentry;
    cfs_file_operations_t * f_op;

    size_t                  f_size;
    loff_t                  f_pos;
    unsigned int            f_uid, f_gid;
    int                     f_error;

    ulong_ptr           f_version;

    void *                  private_data;

    char                    f_name[1];

};

#define cfs_filp_size(f)               ((f)->f_size)
#define cfs_filp_poff(f)                (&(f)->f_pos)

cfs_file_t *cfs_filp_open(const char *name, int flags, int mode, int *err);
int cfs_filp_close(cfs_file_t *fp);
int cfs_filp_read(cfs_file_t *fp, void *buf, size_t nbytes, loff_t *pos);
int cfs_filp_write(cfs_file_t *fp, void *buf, size_t nbytes, loff_t *pos);
int cfs_filp_fsync(cfs_file_t *fp);
int cfs_get_file(cfs_file_t *fp);
int cfs_put_file(cfs_file_t *fp);
int cfs_file_count(cfs_file_t *fp);



/*
 * CFS_FLOCK routines
 */

typedef struct file_lock{
    int         fl_type;
    pid_t       fl_pid;
    size_t      fl_len;
    off_t       fl_start;
    off_t       fl_end;
} cfs_flock_t; 

#define CFS_INT_LIMIT(x)		(~((x)1 << (sizeof(x)*8 - 1)))
#define CFS_OFFSET_MAX			CFS_INT_LIMIT(loff_t)

#define cfs_flock_type(fl)                  ((fl)->fl_type)
#define cfs_flock_set_type(fl, type)        do { (fl)->fl_type = (type); } while(0)
#define cfs_flock_pid(fl)                   ((fl)->fl_pid)
#define cfs_flock_set_pid(fl, pid)          do { (fl)->fl_pid = (pid); } while(0)
#define cfs_flock_start(fl)                 ((fl)->fl_start)
#define cfs_flock_set_start(fl, start)      do { (fl)->fl_start = (start); } while(0)
#define cfs_flock_end(fl)                   ((fl)->fl_end)
#define cfs_flock_set_end(fl, end)          do { (fl)->fl_end = (end); } while(0)

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
//#define ATTR_CTIME_SET  0x2000
#define ATTR_BLOCKS     0x4000
#define ATTR_KILL_SUID  0
#define ATTR_KILL_SGID  0

#define in_group_p(x)	(0)

/*
 * proc fs routines
 */

int proc_init_fs();
void proc_destroy_fs();


/*
 *  misc
 */

static inline void *ERR_PTR(long_ptr error)
{
	return (void *) error;
}

static inline long_ptr PTR_ERR(const void *ptr)
{
	return (long_ptr) ptr;
}

static inline long_ptr IS_ERR(const void *ptr)
{
	return (ulong_ptr)ptr > (ulong_ptr)-1000L;
}

#else  /* !__KERNEL__ */

#define CREATE_NEW          1
#define CREATE_ALWAYS       2
#define OPEN_EXISTING       3
#define OPEN_ALWAYS         4
#define TRUNCATE_EXISTING   5

#define SECTION_QUERY       0x0001
#define SECTION_MAP_WRITE   0x0002
#define SECTION_MAP_READ    0x0004
#define SECTION_MAP_EXECUTE 0x0008
#define SECTION_EXTEND_SIZE 0x0010

#define FILE_MAP_COPY       SECTION_QUERY
#define FILE_MAP_WRITE      SECTION_MAP_WRITE
#define FILE_MAP_READ       SECTION_MAP_READ
#define FILE_MAP_ALL_ACCESS SECTION_ALL_ACCESS


NTSYSAPI
HANDLE
NTAPI
CreateFileA(
    IN LPCSTR lpFileName,
    IN DWORD dwDesiredAccess,
    IN DWORD dwShareMode,
    IN PVOID lpSecurityAttributes,
    IN DWORD dwCreationDisposition,
    IN DWORD dwFlagsAndAttributes,
    IN HANDLE hTemplateFile
    );

#define CreateFile  CreateFileA

NTSYSAPI
BOOL
NTAPI
CloseHandle(
    IN OUT HANDLE hObject
    );

NTSYSAPI
HANDLE
NTAPI
CreateFileMappingA(
    IN HANDLE hFile,
    IN PVOID lpFileMappingAttributes,
    IN DWORD flProtect,
    IN DWORD dwMaximumSizeHigh,
    IN DWORD dwMaximumSizeLow,
    IN LPCSTR lpName
    );
#define CreateFileMapping  CreateFileMappingA

NTSYSAPI
DWORD
NTAPI
GetFileSize(
    IN HANDLE hFile,
    OUT DWORD * lpFileSizeHigh
    );

NTSYSAPI
PVOID
NTAPI
MapViewOfFile(
    IN HANDLE hFileMappingObject,
    IN DWORD dwDesiredAccess,
    IN DWORD dwFileOffsetHigh,
    IN DWORD dwFileOffsetLow,
    IN SIZE_T dwNumberOfBytesToMap
    );

NTSYSAPI
BOOL
NTAPI
UnmapViewOfFile(
    IN PVOID lpBaseAddress
    );

#endif /* __KERNEL__ */

typedef struct {
	void	*d;
} cfs_dentry_t;


#endif /* __LIBCFS_WINNT_CFS_FS_H__*/
