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

#include <asm/byteorder.h>
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
#define loff_t long long
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
#define GFP_ATOMIC 1
#define GFP_NOFS 1
#define IS_ERR(a) (((a) && abs((long)(a)) < 500) ? 1 : 0)
#define PTR_ERR(a) ((long)(a))
#define ERR_PTR(a) ((void*)((long)(a)))

#define capable(foo) 1
#define CAP_SYS_ADMIN 1

typedef struct {
        void *cwd;
}mm_segment_t;

typedef int (read_proc_t)(char *page, char **start, off_t off,
                          int count, int *eof, void *data);

struct file; /* forward ref */
typedef int (write_proc_t)(struct file *file, const char *buffer,
                           unsigned long count, void *data);

# define le16_to_cpu(x) __le16_to_cpu(x)
# define cpu_to_le16(x) __cpu_to_le16(x)
# define le32_to_cpu(x) __le32_to_cpu(x)
# define cpu_to_le32(x) __cpu_to_le32(x)
# define le64_to_cpu(x) __le64_to_cpu(x)
# define cpu_to_le64(x) __cpu_to_le64(x)

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]
                                                                                                                        
#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr) \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD NIPQUAD
#else
#error "Undefined byteorder??"
#endif /* __LITTLE_ENDIAN */

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

static __inline__ int ext2_set_bit(int nr, void *addr)
{
        return set_bit(nr, (long*)addr);
}

static __inline__ int ext2_clear_bit(int nr, void *addr)
{
        return clear_bit(nr, (long*)addr);
}

static __inline__ int ext2_test_bit(int nr, void *addr)
{
        return test_bit(nr, (long*)addr);
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

static inline int misc_deregister(void *foo)
{
        return 0;
}

static inline int request_module(char *name)
{
        return (-EINVAL);
}

#define __MOD_INC_USE_COUNT(m)  do {} while (0)
#define __MOD_DEC_USE_COUNT(m)  do {} while (0)
#define MOD_INC_USE_COUNT       do {} while (0)
#define MOD_DEC_USE_COUNT       do {} while (0)
#define try_module_get          __MOD_INC_USE_COUNT
#define module_put              __MOD_DEC_USE_COUNT

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
#define LASSERT_SPIN_LOCKED(lock) do {} while(0)

static inline void spin_lock(spinlock_t *l) {return;}
static inline void spin_unlock(spinlock_t *l) {return;}
static inline void spin_lock_init(spinlock_t *l) {return;}
static inline void local_irq_save(unsigned long flag) {return;}
static inline void local_irq_restore(unsigned long flag) {return;}
static inline int spin_is_locked(spinlock_t *l) {return 1;}

static inline void spin_lock_bh(spinlock_t *l) {}
static inline void spin_unlock_bh(spinlock_t *l) {}
static inline void spin_lock_irqsave(spinlock_t *a, unsigned long b) {}
static inline void spin_unlock_irqrestore(spinlock_t *a, unsigned long b) {}

#define min(x,y) ((x)<(y) ? (x) : (y))
#define max(x,y) ((x)>(y) ? (x) : (y))

#ifndef min_t
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#endif
#ifndef max_t
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
#endif

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
#define kmem_cache_alloc(cache, prio) malloc(cache->size)
#define kmem_cache_free(cache, obj) free(obj)

#define PAGE_CACHE_SIZE PAGE_SIZE
#define PAGE_CACHE_SHIFT 12
#define PAGE_CACHE_MASK PAGE_MASK

/* XXX
 * for this moment, liblusre will not rely OST for non-page-aligned write
 */
#define LIBLUSTRE_HANDLE_UNALIGNED_PAGE

struct page {
        void   *addr;
        unsigned long index;
        struct list_head list;
        unsigned long private;

        /* internally used by liblustre file i/o */
        int     _offset;
        int     _count;
#ifdef LIBLUSTRE_HANDLE_UNALIGNED_PAGE
        int     _managed;
#endif
};

/* 2.4 defines */
#define PAGE_LIST_ENTRY list
#define PAGE_LIST(page) ((page)->list)

#define kmap(page) (page)->addr
#define kunmap(a) do {} while (0)

static inline struct page *alloc_pages(int mask, unsigned long order)
{
        struct page *pg = malloc(sizeof(*pg));

        if (!pg)
                return NULL;
#if 0 //#ifdef MAP_ANONYMOUS
        pg->addr = mmap(0, PAGE_SIZE << order, PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
#else
        pg->addr = malloc(PAGE_SIZE << order);
#endif

        if (!pg->addr) {
                free(pg);
                return NULL;
        }
        return pg;
}

#define alloc_page(mask) alloc_pages((mask), 0)

static inline void __free_pages(struct page *pg, int what)
{
#if 0 //#ifdef MAP_ANONYMOUS
        munmap(pg->addr, PAGE_SIZE);
#else
        free(pg->addr);
#endif
        free(pg);
}

#define __free_page(page) __free_pages((page), 0)
#define free_page(page) __free_page(page)

static inline struct page* __grab_cache_page(unsigned long index)
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
                unsigned long remainder;\
                remainder = (a) % (b);  \
                (a) = (a) / (b);        \
                (remainder);            \
        })

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

#define IT_OPEN     0x0001
#define IT_CREAT    0x0002
#define IT_READDIR  0x0004
#define IT_GETATTR  0x0008
#define IT_LOOKUP   0x0010
#define IT_UNLINK   0x0020
#define IT_GETXATTR 0x0040
#define IT_EXEC     0x0080
#define IT_PIN      0x0100

#define IT_FL_LOCKED   0x0001
#define IT_FL_FOLLOWED 0x0002 /* set by vfs_follow_link */

#define INTENT_MAGIC 0x19620323

struct lustre_intent_data {
        int       it_disposition;
        int       it_status;
        __u64     it_lock_handle;
        void     *it_data;
        int       it_lock_mode;
        int it_int_flags;
};
struct lookup_intent {
        int     it_magic;
        void    (*it_op_release)(struct lookup_intent *);
        int     it_op;
        int     it_flags;
        int     it_create_mode;
        union {
                struct lustre_intent_data lustre;
        } d;
};

static inline void intent_init(struct lookup_intent *it, int op, int flags)
{
        memset(it, 0, sizeof(*it));
        it->it_magic = INTENT_MAGIC;
        it->it_op = op;
        it->it_flags = flags;
}


struct dentry {
        int d_count;
};

struct vfsmount {
        void *pwd;
};

/* semaphores */
struct rw_semaphore {
        int count;
};

/* semaphores */
struct semaphore {
        int count;
};

#define down(a) do {} while (0)
#define up(a) do {} while (0)
#define down_read(a) do {} while (0)
#define up_read(a) do {} while (0)
#define down_write(a) do {} while (0)
#define up_write(a) do {} while (0)
#define sema_init(a,b) do {} while (0)
#define init_rwsem(a) do {} while (0)
#define DECLARE_MUTEX(name)     \
        struct semaphore name = { 1 }
static inline void init_MUTEX (struct semaphore *sem)
{
        sema_init(sem, 1);
}


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

#define DECLARE_WAIT_QUEUE_HEAD(HEAD)                           \
        wait_queue_head_t HEAD = {                              \
                .sleepers = LIST_HEAD_INIT(HEAD.sleepers)       \
        }
#define init_waitqueue_head(l) INIT_LIST_HEAD(&(l)->sleepers)
#define wake_up(l) do { int a; a++; } while (0)
#define TASK_INTERRUPTIBLE 0
#define TASK_UNINTERRUPTIBLE 1
#define TASK_RUNNING 2

#define wait_event_interruptible(wq, condition)                         \
({                                                                      \
        struct l_wait_info lwi;                                         \
        int timeout = 100000000;/* for ever */                          \
        int ret;                                                        \
                                                                        \
        lwi = LWI_TIMEOUT(timeout, NULL, NULL);                         \
        ret = l_wait_event(NULL, condition, &lwi);                      \
                                                                        \
        ret;                                                            \
})

#define in_interrupt() (0)

#define schedule() do {} while (0)
static inline int schedule_timeout(signed long t)
{
        return 0;
}

#define lock_kernel() do {} while (0)
#define daemonize(l) do {} while (0)
#define sigfillset(l) do {} while (0)
#define recalc_sigpending(l) do {} while (0)
#define kernel_thread(l,m,n) LBUG()

#define USERMODEHELPER(path, argv, envp) (0)
#define SIGNAL_MASK_ASSERT()
#define KERN_INFO


struct timer_list {
        struct list_head tl_list;
        void (*function)(unsigned long unused);
        unsigned long data;
        long expires;
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

#define time_after(a, b)                                        \
({                                                              \
        1;                                                      \
})

typedef struct { volatile int counter; } atomic_t;

#define atomic_read(a) ((a)->counter)
#define atomic_set(a,b) do {(a)->counter = b; } while (0)
#define atomic_dec_and_test(a) ((--((a)->counter)) == 0)
#define atomic_inc(a)  (((a)->counter)++)
#define atomic_dec(a)  do { (a)->counter--; } while (0)
#define atomic_add(b,a)  do {(a)->counter += b;} while (0)
#define atomic_sub(b,a)  do {(a)->counter -= b;} while (0)

#ifndef likely
#define likely(exp) (exp)
#endif
#ifndef unlikely
#define unlikely(exp) (exp)
#endif

/* log related */
static inline int llog_init_commit_master(void) { return 0; }
static inline int llog_cleanup_commit_master(int force) { return 0; }
static inline void portals_run_lbug_upcall(char *file, const char *fn,
                                           const int l){}

#define LBUG()                                                          \
        do {                                                            \
                printf("!!!LBUG at %s:%d\n", __FILE__, __LINE__);       \
                sleep(1000000);                                         \
        } while (0)



/* completion */
struct completion {
        unsigned int done;
        wait_queue_head_t wait;
};

#define COMPLETION_INITIALIZER(work) \
        { 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }

#define DECLARE_COMPLETION(work) \
        struct completion work = COMPLETION_INITIALIZER(work)

#define INIT_COMPLETION(x)      ((x).done = 0)

static inline void init_completion(struct completion *x)
{
        x->done = 0;
        init_waitqueue_head(&x->wait);
}

struct liblustre_wait_callback {
        struct list_head    llwc_list;
        int               (*llwc_fn)(void *arg);
        void               *llwc_arg;
};

void *liblustre_register_wait_callback(int (*fn)(void *arg), void *arg);
void liblustre_deregister_wait_callback(void *notifier);
int liblustre_wait_event(int timeout);

#include <linux/obd_support.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_import.h>
#include <linux/lustre_export.h>
#include <linux/lustre_net.h>


#endif
