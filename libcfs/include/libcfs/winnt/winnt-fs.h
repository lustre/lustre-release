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
 *
 * Copyright (c) 2012, Intel Corporation.
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

#define PATH_MAX (260)

#ifdef __KERNEL__

/* linux/fs.h */

#define MAY_EXEC 1
#define MAY_WRITE 2
#define MAY_READ 4
#define MAY_APPEND 8

#define FMODE_READ 1
#define FMODE_WRITE 2

/* Internal kernel extensions */
#define FMODE_LSEEK	4
#define FMODE_PREAD	8
#define FMODE_PWRITE	FMODE_PREAD	/* These go hand in hand */

/* File is being opened for execution. Primary users of this flag are
   distributed filesystems that can use it to achieve correct ETXTBUSY
   behavior for cross-node execution/opening_for_writing of files */
#define FMODE_EXEC	16

#define RW_MASK         1
#define RWA_MASK        2
#define READ 0
#define WRITE 1
#define READA 2         /* read-ahead  - don't block if no resources */
#define SWRITE 3        /* for ll_rw_block() - wait for buffer lock */
#define SPECIAL 4       /* For non-blockdevice requests in request queue */
#define READ_SYNC       (READ | (1 << BIO_RW_SYNC))
#define WRITE_SYNC      (WRITE | (1 << BIO_RW_SYNC))
#define WRITE_BARRIER   ((1 << BIO_RW) | (1 << BIO_RW_BARRIER))

struct file_operations
{
    struct module *owner;
    loff_t (*llseek)(struct file * file, loff_t offset, int origin);
    ssize_t (*read) (struct file * file, char * buf, size_t nbytes, loff_t *ppos);
    ssize_t (*write)(struct file * file, const char * buffer,
        size_t count, loff_t *ppos);
    int (*ioctl) (struct file *, unsigned int, ulong_ptr_t);
    int (*open) (struct inode*, struct file *);
    int (*release) (struct inode*, struct file *);
};

struct file {

    cfs_handle_t            f_handle;
    unsigned int            f_flags;
    mode_t                  f_mode;
    __u32                   f_count;

    size_t                  f_size;
    loff_t                  f_pos;
    unsigned int            f_uid, f_gid;
    int                     f_error;

    __u32                   f_version;

    //struct list_head      f_list;
    struct dentry *         f_dentry;

    cfs_proc_entry_t *      proc_dentry;
    cfs_file_operations_t * f_op;

    void *                  private_data;
    struct inode *          f_inode;
    char                    f_name[1];

};

#define filp_size(f)		((f)->f_size)
#define filp_poff(f)		(&(f)->f_pos)

struct file *filp_open(const char *name, int flags, int mode);
int filp_close(struct file *fp, void *id);
int filp_read(struct file *fp, void *buf, size_t nbytes, loff_t *pos);
int filp_write(struct file *fp, void *buf, size_t nbytes, loff_t *pos);
int filp_fsync(struct file *fp);
int get_file(struct file *fp);
int fput(struct file *fp);
int file_count(struct file *fp);
#define cfs_filp_unlink(x, y) (KdBreakPoint(), 0)
/*
 * CFS_FLOCK routines
 */

struct file_lock {
	int	fl_type;
	pid_t	fl_pid;
	size_t	fl_len;
	off_t	fl_start;
	off_t	fl_end;
};

#define INT_LIMIT(x)			(~((x)1 << (sizeof(x)*8 - 1)))
#define OFFSET_MAX			INT_LIMIT(loff_t)

#define flock_type(fl)			((fl)->fl_type)
#define flock_set_type(fl, type)	do { (fl)->fl_type = (type); } while (0)
#define flock_pid(fl)			((fl)->fl_pid)
#define flock_set_pid(fl, pid)		do { (fl)->fl_pid = (pid); } while (0)
#define flock_start(fl)			((fl)->fl_start)
#define flock_set_start(fl, st)		do { (fl)->fl_start = (st); } while (0)
#define flock_end(fl)			((fl)->fl_end)
#define flock_set_end(fl, end)		do { (fl)->fl_end = (end); } while (0)

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

/*
 * set ATTR_BLOCKS to a high value to avoid any risk of collision with other
 * ATTR_* attributes (see bug 13828): lustre/include/winnt/lustre_compat25.h
 */
/* #define ATTR_BLOCKS     0x4000 */
#define ATTR_BLOCKS    (1 << 27)

#define ATTR_KILL_SUID  0
#define ATTR_KILL_SGID  0



#define in_group_p(x)	(0)


/* VFS structures for windows */

/* 
 * inode formats
 */

#define S_IFMT   00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

/* Inode flags - they have nothing to superblock flags now */

#define S_SYNC		1	/* Writes are synced at once */
#define S_NOATIME	2	/* Do not update access times */
#define S_APPEND	4	/* Append-only file */
#define S_IMMUTABLE	8	/* Immutable file */
#define S_DEAD		16	/* removed, but still open directory */
#define S_NOQUOTA	32	/* Inode is not counted to quota */
#define S_DIRSYNC	64	/* Directory modifications are synchronous */
#define S_NOCMTIME	128	/* Do not update file c/mtime */
#define S_SWAPFILE	256	/* Do not truncate: swapon got its bmaps */
#define S_PRIVATE	512	/* Inode is fs-internal */


struct inode {
        __u32           i_mode;
        __u64           i_size;
        __u64           i_blocks;
        struct timespec i_atime;
        struct timespec i_ctime;
        struct timespec i_mtime;
        struct timespec i_dtime;
        __u32           i_ino;
        __u32           i_generation;
        __u32           i_state;
        __u32           i_blkbits;
        int             i_uid;
        int             i_gid;
        __u32           i_flags;
	struct mutex	i_sem;
        void *          i_priv;
};

#define I_FREEING       0x0001

struct dentry {
	atomic_t    d_count;
	struct {
	    int         len;
	    char *      name;
	} d_name;
	struct inode *  d_inode;
	struct dentry*  d_parent;
};

extern struct dentry *dget(struct dentry *de);
extern void dput(struct dentry *de);
static __inline struct dentry *lookup_one_len(const char *name, struct dentry *de, int len)
{
    cfs_enter_debugger();
    return NULL;
}

static inline loff_t i_size_read(const struct inode *inode)
{
    cfs_enter_debugger();
    return inode->i_size;
}

static inline void i_size_write(struct inode *inode, loff_t i_size)
{
    cfs_enter_debugger();
    inode->i_size = i_size;
}

struct kstatfs {
	u64	f_type;
	long	f_bsize;
	u64	f_blocks;
	u64	f_bfree;
	u64	f_bavail;
	u64	f_files;
	u64	f_ffree;
	__u32	f_fsid;
	long	f_namelen;
	long	f_frsize;
	long	f_spare[5];
};

struct super_block {
        void *  s_fs_info;
};

struct vfsmount {
        struct dentry * pwd;
        struct dentry * mnt_root;
        struct super_block *mnt_sb;
};


/*
 * quota definitions (linux/quota.h)
 */

#define MAXQUOTAS 2
#define USRQUOTA  0		/* element used for user quotas */
#define GRPQUOTA  1		/* element used for group quotas */


/*
 * proc fs routines
 */

typedef int (read_proc_t)(char *page, char **start, off_t off,
                          int count, int *eof, void *data);

struct file; /* forward ref */
typedef int (write_proc_t)(struct file *file, const char *buffer,
                           unsigned long count, void *data);

void proc_destory_subtree(cfs_proc_entry_t *entry);

int proc_init_fs();
void proc_destroy_fs();

/*
 *  thread affinity
 */

HANDLE cfs_open_current_thread();
void cfs_close_thread_handle(HANDLE handle);
KAFFINITY cfs_query_thread_affinity();
int cfs_set_thread_affinity(KAFFINITY affinity);
int cfs_tie_thread_to_cpu(int cpu);
typedef PVOID mm_segment_t;

/*
 * thread priority
 */
int cfs_set_thread_priority(KPRIORITY priority);

#define MAKE_MM_SEG(s) ((mm_segment_t)(ulong_ptr_t)(s))
#define KERNEL_DS       MAKE_MM_SEG(0xFFFFFFFFUL)
#define USER_DS         MAKE_MM_SEG(PAGE_OFFSET)

#define get_ds()        (KERNEL_DS)
#define set_fs(x) do {} while(0)
#define get_fs() (NULL)

/*
 * radix tree (linux/radix_tree.h)
 */

/* radix tree root structure */
struct radix_tree_root {
    RTL_GENERIC_TABLE   table;
};

/* #define RADIX_TREE_INIT(mask) {0}

#define RADIX_TREE(name, mask) \
	struct radix_tree_root name RADIX_TREE_INIT(mask) */

VOID RadixInitTable(IN PRTL_GENERIC_TABLE Table);
#define INIT_RADIX_TREE(root, mask)	RadixInitTable(&((root)->table))

/* all radix tree routines should be protected by external locks */
unsigned int
radix_tree_gang_lookup(struct radix_tree_root *root, void **results,
                       unsigned long first_index, unsigned int max_items);
void *radix_tree_lookup(struct radix_tree_root *root, unsigned long index);
int radix_tree_insert(struct radix_tree_root *root, unsigned long index,
                      void *item);
void *radix_tree_delete(struct radix_tree_root *root, unsigned long index);

#else  /* !__KERNEL__ */

#if !defined(_WINDOWS_)

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
DWORD
NTAPI
GetLastError(
   VOID
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
#endif

#endif /* __KERNEL__ */

struct dentry {
	void	*d;
};

/*
 *  misc
 */

#endif /* __LIBCFS_WINNT_CFS_FS_H__*/
