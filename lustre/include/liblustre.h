/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <info@clusterfs.com>
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
 * User-space Lustre headers.
 *
 */
#ifndef LIBLUSTRE_H__
#define LIBLUSTRE_H__

#include <sys/mman.h>
#ifndef  __CYGWIN__
#include <stdint.h>
#include <asm/page.h>
#else
#include <sys/types.h>
#include "ioctl.h"
#endif
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <portals/list.h>
#include <portals/p30.h>
#include <linux/kp30.h>

/* definitions for liblustre */

#ifdef __CYGWIN__

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
#define loff_t __u64
#define ERESTART 2001
typedef unsigned short umode_t;

#endif

/* This is because lprocfs_status.h gets included here indirectly.  It would
 * be much better to just avoid lprocfs being included into liblustre entirely
 * but that requires more header surgery than I can handle right now.
 */
#ifndef smp_processor_id
#define smp_processor_id() 0
#endif

/* always adopt 2.5 definitions */
#define KERNEL_VERSION(a,b,c) ((a)*100+(b)*10+c)
#define LINUX_VERSION_CODE (2*200+5*10+0)

static inline void inter_module_put(void *a)
{
        return;
}

extern ptl_handle_ni_t         tcpnal_ni;

void *inter_module_get(char *arg);

/* cheats for now */

struct work_struct {
        void (*ws_task)(void *arg);
        void *ws_arg;
};

static inline void prepare_work(struct work_struct *q, void (*t)(void *),
                                void *arg)
{
        q->ws_task = t;
        q->ws_arg = arg;
        return;
}

static inline void schedule_work(struct work_struct *q)
{
        q->ws_task(q->ws_arg);
}


#define strnlen(a,b) strlen(a)
static inline void *kmalloc(int size, int prot)
{
        return malloc(size);
}
#define vmalloc malloc
#define vfree free
#define kfree(a) free(a)
#define GFP_KERNEL 1
#define GFP_HIGHUSER 1
#define IS_ERR(a) (((a) && abs((int)(a)) < 500) ? 1 : 0)
#define PTR_ERR(a) ((int)(a))

#define capable(foo) 1
#define CAP_SYS_ADMIN 1

typedef struct {
        void *cwd;

}mm_segment_t;

typedef void *read_proc_t;
typedef void *write_proc_t;


/* byteorder */
#define __swab16(x) \
({ \
	__u16 __x = (x); \
	((__u16)( \
		(((__u16)(__x) & (__u16)0x00ffU) << 8) | \
		(((__u16)(__x) & (__u16)0xff00U) >> 8) )); \
})

#define __swab32(x) \
({ \
	__u32 __x = (x); \
	((__u32)( \
		(((__u32)(__x) & (__u32)0x000000ffUL) << 24) | \
		(((__u32)(__x) & (__u32)0x0000ff00UL) <<  8) | \
		(((__u32)(__x) & (__u32)0x00ff0000UL) >>  8) | \
		(((__u32)(__x) & (__u32)0xff000000UL) >> 24) )); \
})

#define __swab64(x) \
({ \
	__u64 __x = (x); \
	((__u64)( \
		(__u64)(((__u64)(__x) & (__u64)0x00000000000000ffULL) << 56) | \
		(__u64)(((__u64)(__x) & (__u64)0x000000000000ff00ULL) << 40) | \
		(__u64)(((__u64)(__x) & (__u64)0x0000000000ff0000ULL) << 24) | \
		(__u64)(((__u64)(__x) & (__u64)0x00000000ff000000ULL) <<  8) | \
	        (__u64)(((__u64)(__x) & (__u64)0x000000ff00000000ULL) >>  8) | \
		(__u64)(((__u64)(__x) & (__u64)0x0000ff0000000000ULL) >> 24) | \
		(__u64)(((__u64)(__x) & (__u64)0x00ff000000000000ULL) >> 40) | \
		(__u64)(((__u64)(__x) & (__u64)0xff00000000000000ULL) >> 56) )); \
})

#define __swab16s(x)    __swab16(*(x))
#define __swab32s(x)    __swab32(*(x))
#define __swab64s(x)    __swab64(*(x))

#define __LITTLE_ENDIAN__
#ifdef  __LITTLE_ENDIAN__
# define le16_to_cpu(x) ((__u16)(x))
# define cpu_to_le16(x) ((__u16)(x))
# define le32_to_cpu(x) ((__u32)(x))
# define cpu_to_le32(x) ((__u32)(x))
# define le64_to_cpu(x) ((__u64)(x))
# define cpu_to_le64(x) ((__u64)(x))
#else
# define le16_to_cpu(x) __swab16(x)
# define cpu_to_le16(x) __swab16(x)
# define le32_to_cpu(x) __swab32(x)
# define cpu_to_le32(x) __swab32(x)
# define le64_to_cpu(x) __swab64(x)
# define cpu_to_le64(x) __swab64(x)
# error "do more check here!!!"
#endif

/* bits ops */
static __inline__ int set_bit(int nr,long * addr)
{
	int	mask, retval;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	retval = (mask & *addr) != 0;
	*addr |= mask;
	return retval;
}

static __inline__ int clear_bit(int nr, long * addr)
{
	int	mask, retval;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	retval = (mask & *addr) != 0;
	*addr &= ~mask;
	return retval;
}

static __inline__ int test_bit(int nr, long * addr)
{
	int	mask;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	return ((mask & *addr) != 0);
}

/* modules */

struct module {
        int count;
};

static inline void MODULE_AUTHOR(char *name)
{
        printf("%s\n", name);
}
#define MODULE_DESCRIPTION(name) MODULE_AUTHOR(name)
#define MODULE_LICENSE(name) MODULE_AUTHOR(name)

#define THIS_MODULE NULL
#define __init
#define __exit

/* devices */

static inline int misc_register(void *foo)
{
        return 0;
}
#define misc_deregister misc_register

#define __MOD_INC_USE_COUNT(m)  do {int a = 1; a++; } while (0)
#define __MOD_DEC_USE_COUNT(m)  do {int a = 1; a++; } while (0)
#define MOD_INC_USE_COUNT  do {int a = 1; a++; } while (0)
#define MOD_DEC_USE_COUNT  do {int a = 1; a++; } while (0)

/* module initialization */
extern int init_obdclass(void);
extern int ptlrpc_init(void);
extern int ldlm_init(void);
extern int osc_init(void);
extern int lov_init(void);
extern int mdc_init(void);
extern int echo_client_init(void);



/* general stuff */
#define jiffies 0

#define EXPORT_SYMBOL(S)

typedef int spinlock_t;
typedef __u64 kdev_t;

#define SPIN_LOCK_UNLOCKED 0
#define spin_lock(l) do {int a = 1; a++; } while (0)
#define spin_unlock(l) do {int a= 1; a++; } while (0)
#define spin_lock_init(l) do {int a= 1; a++; } while (0)
static inline void spin_lock_bh(spinlock_t *l)
{
        return;
}
static inline void spin_unlock_bh(spinlock_t *l)
{
        return;
}
static inline void spin_unlock_irqrestore(spinlock_t *a, long b)
{
        return;
}
static inline void spin_lock_irqsave(spinlock_t *a, long b)
{
        return;
}

#define barrier() do {int a= 1; a++; } while (0)

#define min(x,y) ((x)<(y) ? (x) : (y))
#define max(x,y) ((x)>(y) ? (x) : (y))

/* registering symbols */

#define ERESTARTSYS ERESTART
#define HZ 1

/* random */

static inline void get_random_bytes(void *ptr, int size)
{
        int *p = (int *)ptr;
        int i, count = size/sizeof(int);

        for (i = 0; i< count; i++)
                *p++ = rand();
}

/* memory */

/* FIXME */
#define num_physpages (16 * 1024)

static inline int copy_from_user(void *a,void *b, int c)
{
        memcpy(a,b,c);
        return 0;
}

static inline int copy_to_user(void *a,void *b, int c)
{
        memcpy(a,b,c);
        return 0;
}


/* slabs */
typedef struct {
         int size;
} kmem_cache_t;
#define SLAB_HWCACHE_ALIGN 0
static inline kmem_cache_t *
kmem_cache_create(const char *name, size_t objsize, size_t cdum,
                  unsigned long d,
                  void (*e)(void *, kmem_cache_t *, unsigned long),
                  void (*f)(void *, kmem_cache_t *, unsigned long))
{
        kmem_cache_t *c;
        c = malloc(sizeof(*c));
        if (!c)
                return NULL;
        c->size = objsize;
        CDEBUG(D_MALLOC, "alloc slab cache %s at %p, objsize %d\n",
               name, c, (int)objsize);
        return c;
};

static inline int kmem_cache_destroy(kmem_cache_t *a)
{
        CDEBUG(D_MALLOC, "destroy slab cache %p, objsize %u\n", a, a->size);
        free(a);
        return 0;
}
#define kmem_cache_validate(a,b) 1
#define kmem_cache_alloc(cache, prio) malloc(cache->size)
#define kmem_cache_free(cache, obj) free(obj)

#define PAGE_CACHE_SIZE PAGE_SIZE
#define PAGE_CACHE_SHIFT 12
#define PAGE_CACHE_MASK PAGE_MASK

struct page {
        void *addr;
        int index;
};

#define kmap(page) (page)->addr
#define kunmap(a) do { int foo = 1; foo++; } while (0)

static inline struct page *alloc_pages(int mask, unsigned long foo)
{
        struct page *pg = malloc(sizeof(*pg));

        if (!pg)
                return NULL;
#ifdef MAP_ANONYMOUS
        pg->addr = mmap(0, PAGE_SIZE, PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
#else
        pg->addr = malloc(PAGE_SIZE);
#endif

        if (!pg->addr) {
                free(pg);
                return NULL;
        }
        return pg;
}

static inline void __free_pages(struct page *pg, int what)
{
#ifdef MAP_ANONYMOUS
        munmap(pg->addr, PAGE_SIZE);
#else
        free(pg->addr);
#endif
        free(pg);
}

static inline struct page* __grab_cache_page(int index)
{
        struct page *pg = alloc_pages(0, 0);

        if (pg)
                pg->index = index;
        return pg;
}

#define grab_cache_page(index) __grab_cache_page(index)
#define page_cache_release(page) __free_pages(page, 0)

/* arithmetic */
#define do_div(a,b)                     \
        ({                              \
                unsigned long ret;      \
                ret = (a)%(b);          \
                (a) = (a)/(b);          \
                (ret);                  \
        })

/* VFS stuff */
#define ATTR_MODE       1
#define ATTR_UID        2
#define ATTR_GID        4
#define ATTR_SIZE       8
#define ATTR_ATIME      16
#define ATTR_MTIME      32
#define ATTR_CTIME      64
#define ATTR_ATIME_SET  128
#define ATTR_MTIME_SET  256
#define ATTR_FORCE      512     /* Not a change, but a change it */
#define ATTR_ATTR_FLAG  1024
#define ATTR_RAW        2048    /* file system, not vfs will massage attrs */
#define ATTR_FROM_OPEN  4096    /* called from open path, ie O_TRUNC */

struct iattr {
        unsigned int    ia_valid;
        umode_t         ia_mode;
        uid_t           ia_uid;
        gid_t           ia_gid;
        loff_t          ia_size;
        time_t          ia_atime;
        time_t          ia_mtime;
        time_t          ia_ctime;
        unsigned int    ia_attr_flags;
};

/* copy from kernel header */
#define IT_OPEN     (1)
#define IT_CREAT    (1<<1)
#define IT_READDIR  (1<<2)
#define IT_GETATTR  (1<<3)
#define IT_LOOKUP   (1<<4)
#define IT_UNLINK   (1<<5)

struct lookup_intent {
        int it_op;
        int it_mode;
        int it_flags;
        int it_disposition;
        int it_status;
        struct iattr *it_iattr;
        __u64 it_lock_handle[2];
        int it_lock_mode;
        void *it_data;
};

struct dentry {
        int d_count;
};

struct vfsmount {
        void *pwd;
};

#define cpu_to_le32(x) ((__u32)(x))

/* semaphores */
struct semaphore {
        int count;
};

#define down(a) do {(a)->count++;} while (0)
#define up(a) do {(a)->count--;} while (0)
#define sema_init(a,b) do { (a)->count = b; } while (0)

typedef struct  {
        struct list_head sleepers;
} wait_queue_head_t;

typedef struct  {
        struct list_head sleeping;
        void *process;
} wait_queue_t;

struct signal {
        int signal;
};

struct fs_struct {
        int umask;
};

struct task_struct {
        struct fs_struct *fs;
        int state;
        struct signal pending;
        char comm[32];
        int pid;
        int fsuid;
        int fsgid;
        __u32 cap_effective;
};

extern struct task_struct *current;

#define in_group_p(a) 0 /* FIXME */

#define set_current_state(foo) do { current->state = foo; } while (0)

#define init_waitqueue_entry(q,p) do { (q)->process = p; } while (0)
#define add_wait_queue(q,p) do {  list_add(&(q)->sleepers, &(p)->sleeping); } while (0)
#define del_wait_queue(p) do { list_del(&(p)->sleeping); } while (0)
#define remove_wait_queue(q,p) do { list_del(&(p)->sleeping); } while (0)

#define init_waitqueue_head(l) INIT_LIST_HEAD(&(l)->sleepers)
#define wake_up(l) do { int a; a++; } while (0)
#define TASK_INTERRUPTIBLE 0
#define TASK_UNINTERRUPTIBLE 1
#define TASK_RUNNING 2

#define in_interrupt() (0)

#define schedule() do { int a; a++; } while (0)
static inline int schedule_timeout(signed long t)
{
        return 0;
}

#define lock_kernel() do { int a; a++; } while (0)
#define daemonize(l) do { int a; a++; } while (0)
#define sigfillset(l) do { int a; a++; } while (0)
#define recalc_sigpending(l) do { int a; a++; } while (0)
#define kernel_thread(l,m,n)

static inline int call_usermodehelper(char *prog, char **argv, char **evnp, int unknown)
{
        return 0;
}



#define KERN_INFO



struct timer_list {
        struct list_head tl_list;
        void (*function)(unsigned long unused);
        void *data;
        int expires;
};

static inline int timer_pending(struct timer_list *l)
{
        if (l->expires > jiffies)
                return 1;
        else
                return 0;
}

static inline int init_timer(struct timer_list *l)
{
        INIT_LIST_HEAD(&l->tl_list);
        return 0;
}

static inline void mod_timer(struct timer_list *l, int thetime)
{
        l->expires = thetime;
}

static inline void del_timer(struct timer_list *l)
{
        free(l);
}

typedef struct { volatile int counter; } atomic_t;

#define atomic_read(a) ((a)->counter)
#define atomic_set(a,b) do {(a)->counter = b; } while (0)
#define atomic_dec_and_test(a) ((--((a)->counter)) == 0)
#define atomic_inc(a)  (((a)->counter)++)
#define atomic_dec(a)  do { (a)->counter--; } while (0)
#define atomic_add(b,a)  do {(a)->counter += b;} while (0)
#define atomic_sub(b,a)  do {(a)->counter -= b;} while (0)

#define LBUG()                                                          \
        do {                                                            \
                printf("!!!LBUG at %s:%d\n", __FILE__, __LINE__);       \
                sleep(1000000);                                         \
        } while (0)

#include <linux/obd_support.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_import.h>
#include <linux/lustre_export.h>
#include <linux/lustre_net.h>


#endif

