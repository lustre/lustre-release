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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/liblustre.h
 *
 * User-space Lustre headers.
 */

#ifndef LIBLUSTRE_H__
#define LIBLUSTRE_H__

/** \defgroup liblustre liblustre
 *
 * @{
 */
#include <fcntl.h>
#include <endian.h>
#include <sys/queue.h>

#ifdef __KERNEL__
#error Kernel files should not #include <liblustre.h>
#endif

#include <libcfs/libcfs.h>
#include <lnet/lnet.h>

/* definitions for liblustre */

#ifdef __CYGWIN__

#define loff_t long long
#define ERESTART 2001
typedef unsigned short umode_t;

#endif

#ifndef page_private
#define page_private(page) ((page)->private)
#define set_page_private(page, v) ((page)->private = (v))
#endif

/* bits ops */

/* a long can be more than 32 bits, so use BITS_PER_LONG
 * to allow the compiler to adjust the bit shifting accordingly
 */

static inline int ext2_set_bit(int nr, void *addr)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	return set_bit((nr ^ ((BITS_PER_LONG - 1) & ~0x7)), addr);
#else
	return set_bit(nr, addr);
#endif
}

static inline int ext2_clear_bit(int nr, void *addr)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	return clear_bit((nr ^ ((BITS_PER_LONG - 1) & ~0x7)), addr);
#else
	return clear_bit(nr, addr);
#endif
}

static inline int ext2_test_bit(int nr, const void *addr)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	const unsigned char *tmp = addr;
	return (tmp[nr >> 3] >> (nr & 7)) & 1;
#else
	return test_bit(nr, addr);
#endif
}

/* module initialization */
extern int init_obdclass(void);
extern int ptlrpc_init(void);
extern int ldlm_init(void);
extern int osc_init(void);
extern int lov_init(void);
extern int mdc_init(void);
extern int lmv_init(void);
extern int mgc_init(void);

/* general stuff */

#ifndef min
#define min(x,y) ((x)<(y) ? (x) : (y))
#endif

#ifndef max
#define max(x,y) ((x)>(y) ? (x) : (y))
#endif

#ifndef min_t
#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#endif
#ifndef max_t
#define max_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
#endif

/* registering symbols */
#ifndef ERESTARTSYS
#define ERESTARTSYS ERESTART
#endif

#ifdef HZ
#undef HZ
#endif
#define HZ 1

/* random */

void cfs_get_random_bytes(void *ptr, int size);

/* memory */

/* memory size: used for some client tunables */
#define totalram_pages  (256 * 1024) /* 1GB */
#define NUM_CACHEPAGES totalram_pages


/* VFS stuff */
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
#define ATTR_FILE       0

struct iattr {
	unsigned int    ia_valid;
	umode_t		ia_mode;
	uid_t           ia_uid;
	gid_t           ia_gid;
	loff_t          ia_size;
	time_t          ia_atime;
	time_t          ia_mtime;
	time_t          ia_ctime;
	unsigned int    ia_attr_flags;
};

/* defined in kernel header include/linux/namei.h */
#define INTENT_MAGIC 0x19620323

struct lustre_intent_data {
        int       it_disposition;
        int       it_status;
        __u64     it_lock_handle;
        int       it_lock_mode;
	int       it_remote_lock_mode;
	__u64	  it_remote_lock_handle;
        void     *it_data;

	unsigned int    it_lock_set:1;
};

struct lookup_intent {
	int	it_magic;
	void	(*it_op_release)(struct lookup_intent *);
	int	it_op;
	int	it_create_mode;
	__u64	it_flags;
	union {
		struct lustre_intent_data lustre;
	} d;
};

static inline int it_disposition(const struct lookup_intent *it, int flag)
{
	return it->d.lustre.it_disposition & flag;
}

static inline void it_set_disposition(struct lookup_intent *it, int flag)
{
	it->d.lustre.it_disposition |= flag;
}

static inline void it_clear_disposition(struct lookup_intent *it, int flag)
{
	it->d.lustre.it_disposition &= ~flag;
}

#undef  LL_TASK_CL_ENV
#define LL_TASK_CL_ENV          cl_env

struct task_struct {
        int state;
        char comm[32];
        int uid;
        int gid;
        int pid;
        int fsuid;
        int fsgid;
        int max_groups;
        int ngroups;
        gid_t *groups;
        void  *cl_env;
        __u32 cap_effective;
};


#define current_pid()       (current->pid)
#define current_comm()      (current->comm)
#define current_fsuid()     (current->fsuid)
#define current_fsgid()     (current->fsgid)
#define current_umask()     ({ mode_t mask = umask(0); umask(mask); mask; })

extern struct task_struct *current;
int in_group_p(gid_t gid);

#define set_current_state(foo) do { current->state = foo; } while (0)

#define wait_event_interruptible(wq, condition)                         \
{                                                                       \
	struct l_wait_info lwi;                                         \
	int timeout = 100000000;/* forever */				\
	int ret;                                                        \
									\
	lwi = LWI_TIMEOUT(timeout, NULL, NULL);                         \
	ret = l_wait_event(NULL, condition, &lwi);                      \
									\
	ret;                                                            \
}

#define call_usermodehelper(path, argv, envp, wait) (0)

#if HZ != 1
#error "liblustre's jiffies currently expects HZ to be 1"
#endif
#define jiffies                                 \
({                                              \
        unsigned long _ret = 0;                 \
        struct timeval tv;                      \
        if (gettimeofday(&tv, NULL) == 0)       \
                _ret = tv.tv_sec;               \
        _ret;                                   \
})
#define get_jiffies_64()  (__u64)jiffies

#ifndef likely
#define likely(exp) (exp)
#endif
#ifndef unlikely
#define unlikely(exp) (exp)
#endif

#define might_sleep()
#define might_sleep_if(c)
#define smp_mb()

/* FIXME sys/capability will finally included linux/fs.h thus
 * cause numerous trouble on x86-64. as temporary solution for
 * build broken at Cray, we copy definition we need from capability.h
 * FIXME
 */
struct _cap_struct;
typedef struct _cap_struct *cap_t;
typedef int cap_value_t;
typedef enum {
    CAP_EFFECTIVE=0,
    CAP_PERMITTED=1,
    CAP_INHERITABLE=2
} cap_flag_t;
typedef enum {
    CAP_CLEAR=0,
    CAP_SET=1
} cap_flag_value_t;

cap_t   cap_get_proc(void);
int     cap_get_flag(cap_t, cap_value_t, cap_flag_t, cap_flag_value_t *);

struct liblustre_wait_callback {
        cfs_list_t              llwc_list;
        const char             *llwc_name;
        int                   (*llwc_fn)(void *arg);
        void                   *llwc_arg;
};

void *liblustre_register_wait_callback(const char *name,
                                       int (*fn)(void *arg), void *arg);
void liblustre_deregister_wait_callback(void *notifier);
int liblustre_wait_event(int timeout);

void *liblustre_register_idle_callback(const char *name,
                                       int (*fn)(void *arg), void *arg);
void liblustre_deregister_idle_callback(void *notifier);
void liblustre_wait_idle(void);

struct file_lock {
        struct file_lock *fl_next;  /* singly linked list for this inode  */
        cfs_list_t fl_link;   /* doubly linked list of all locks */
        cfs_list_t fl_block;  /* circular list of blocked processes */
	void *fl_owner;
	unsigned int fl_pid;
	wait_queue_head_t fl_wait;
	struct file *fl_file;
        unsigned char fl_flags;
        unsigned char fl_type;
        loff_t fl_start;
        loff_t fl_end;

        void (*fl_notify)(struct file_lock *);  /* unblock callback */
        void (*fl_insert)(struct file_lock *);  /* lock insertion callback */
        void (*fl_remove)(struct file_lock *);  /* lock removal callback */

        void *fl_fasync; /* for lease break notifications */
        unsigned long fl_break_time;    /* for nonblocking lease breaks */
};

#define flock_type(fl)			((fl)->fl_type)
#define flock_set_type(fl, type)	do { (fl)->fl_type = (type); } while (0)
#define flock_pid(fl)			((fl)->fl_pid)
#define flock_set_pid(fl, pid)		do { (fl)->fl_pid = (pid); } while (0)
#define flock_start(fl)			((fl)->fl_start)
#define flock_set_start(fl, st)		do { (fl)->fl_start = (st); } while (0)
#define flock_end(fl)			((fl)->fl_end)
#define flock_set_end(fl, end)		do { (fl)->fl_end = (end); } while (0)

#ifndef OFFSET_MAX
#define INT_LIMIT(x)    (~((x)1 << (sizeof(x)*8 - 1)))
#define OFFSET_MAX      INT_LIMIT(loff_t)
#endif

#define i_atime                     i_stbuf.st_atime
#define i_mtime                     i_stbuf.st_mtime
#define i_ctime                     i_stbuf.st_ctime
/* use i_size_read() i_size_write() to access i_stbuf.st_size */
#define i_blocks                    i_stbuf.st_blocks
#define i_blksize                   i_stbuf.st_blksize
#define i_mode                      i_stbuf.st_mode
#define i_uid                       i_stbuf.st_uid
#define i_gid                       i_stbuf.st_gid

/* XXX: defined in kernel */
#define FL_POSIX        1
#define FL_SLEEP        128

/* quota */
#define QUOTA_OK 0
#define NO_QUOTA 1

/* ACL */
typedef struct {
        __u16           e_tag;
        __u16           e_perm;
        __u32           e_id;
} posix_acl_xattr_entry;

struct posix_acl {
	atomic_t		a_refcount;
	unsigned int		a_count;
	posix_acl_xattr_entry	a_entries[0];
};

typedef struct {
        __u32                 a_version;
        posix_acl_xattr_entry a_entries[0];
} posix_acl_xattr_header;

static inline size_t posix_acl_xattr_size(int count)
{
        return sizeof(posix_acl_xattr_header) + count *
               sizeof(posix_acl_xattr_entry);
}

static inline
struct posix_acl * posix_acl_from_xattr(const void *value, size_t size)
{
        return NULL;
}

/* The kernel version takes 3 arguments, so strip that off first. */
#define posix_acl_from_xattr(a,b,c)	posix_acl_from_xattr(b,c)
#define posix_acl_to_xattr(a,b,c)	posix_acl_to_xattr(b,c)

static inline
int posix_acl_valid(const struct posix_acl *acl)
{
        return 0;
}

static inline
void posix_acl_release(struct posix_acl *acl)
{
}

#if defined(LIBLUSTRE_POSIX_ACL) && !defined(CONFIG_FS_POSIX_ACL)
# define CONFIG_FS_POSIX_ACL 1
#endif

#ifndef ENOTSUPP
#define ENOTSUPP ENOTSUP
#endif

typedef int mm_segment_t;

#define S_IRWXUGO       (S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO       (S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)

#include <obd_support.h>
#include <lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_import.h>
#include <lustre_export.h>
#include <lustre_net.h>

/** @} liblustre */

#endif
