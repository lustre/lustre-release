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

#ifdef __KERNEL__
#error Kernel files should not #include <liblustre.h>
#else
/*
 * The userspace implementations of linux/spinlock.h vary; we just
 * include our own for all of them
 */
#define __LINUX_SPINLOCK_H
#endif

#include <libcfs/list.h>
#include <lnet/lnet.h>
#include <libcfs/kp30.h>
#include <libcfs/user-bitops.h>

#include <sys/mman.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_ASM_PAGE_H
# include <asm/page.h>
#endif
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <libcfs/list.h>
#include <lnet/lnet.h>
#include <libcfs/kp30.h>
#include <libcfs/user-bitops.h>

#ifndef _IOWR
# include "ioctl.h"
#endif

/* definitions for liblustre */

#ifdef __CYGWIN__

#define loff_t long long
#define ERESTART 2001
typedef unsigned short umode_t;

#endif


#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) ((sizeof (a))/(sizeof ((a)[0])))
#endif

/* This is because lprocfs_status.h gets included here indirectly.  It would
 * be much better to just avoid lprocfs being included into liblustre entirely
 * but that requires more header surgery than I can handle right now.
 */
#ifndef smp_processor_id
#define smp_processor_id() 0
#endif
#ifndef num_online_cpus
#define num_online_cpus() 1
#endif
#ifndef num_possible_cpus
#define num_possible_cpus() 1
#endif

/* always adopt 2.5 definitions */
#define KERNEL_VERSION(a,b,c) ((a)*100+(b)*10+c)
#define LINUX_VERSION_CODE KERNEL_VERSION(2,6,5)

#ifndef page_private
#define page_private(page) ((page)->private)
#define set_page_private(page, v) ((page)->private = (v))
#endif


static inline void inter_module_put(void *a)
{
        return;
}

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
#define IS_ERR(a) ((unsigned long)(a) > (unsigned long)-1000L)
#define PTR_ERR(a) ((long)(a))
#define ERR_PTR(a) ((void*)((long)(a)))

typedef int (read_proc_t)(char *page, char **start, off_t off,
                          int count, int *eof, void *data);

struct file; /* forward ref */
typedef int (write_proc_t)(struct file *file, const char *buffer,
                           unsigned long count, void *data);

/* bits ops */

/* a long can be more than 32 bits, so use BITS_PER_LONG
 * to allow the compiler to adjust the bit shifting accordingly
 */

static __inline__ int ext2_set_bit(int nr, void *addr)
{
        return set_bit(nr, addr);
}

static __inline__ int ext2_clear_bit(int nr, void *addr)
{
        return clear_bit(nr, addr);
}

static __inline__ int ext2_test_bit(int nr, void *addr)
{
        return test_bit(nr, addr);
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
static inline void __module_get(struct module *module)
{
}

static inline int try_module_get(struct module *module)
{
        return 1;
}

static inline void module_put(struct module *module)
{
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
extern int echo_client_init(void);



/* general stuff */

#define EXPORT_SYMBOL(S)

struct rcu_head { };

typedef struct { } spinlock_t;
typedef __u64 kdev_t;

#define SPIN_LOCK_UNLOCKED (spinlock_t) { }
#define LASSERT_SPIN_LOCKED(lock) do {} while(0)
#define LASSERT_SEM_LOCKED(sem) do {} while(0)

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

typedef spinlock_t rwlock_t;
#define RW_LOCK_UNLOCKED        SPIN_LOCK_UNLOCKED
#define read_lock(l)            spin_lock(l)
#define read_unlock(l)          spin_unlock(l)
#define write_lock(l)           spin_lock(l)
#define write_unlock(l)         spin_unlock(l)
#define rwlock_init(l)          spin_lock_init(l)

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

#define simple_strtol strtol

/* registering symbols */
#ifndef ERESTARTSYS
#define ERESTARTSYS ERESTART
#endif
#define HZ 1

/* random */

void get_random_bytes(void *ptr, int size);

/* memory */

/* memory size: used for some client tunables */
#define num_physpages (256 * 1024) /* 1GB */

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

/* struct page decl moved out from here into portals/include/libcfs/user-prim.h */

/* 2.4 defines */
#define PAGE_LIST_ENTRY list
#define PAGE_LIST(page) ((page)->list)

#define kmap(page) (page)->addr
#define kunmap(a) do {} while (0)

static inline cfs_page_t *alloc_pages(int mask, unsigned long order)
{
        cfs_page_t *pg = malloc(sizeof(*pg));

        if (!pg)
                return NULL;
#if 0 //#ifdef MAP_ANONYMOUS
        pg->addr = mmap(0, PAGE_SIZE << order, PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
#else
        pg->addr = malloc(CFS_PAGE_SIZE << order);
#endif

        if (!pg->addr) {
                free(pg);
                return NULL;
        }
        return pg;
}
#define cfs_alloc_pages(mask, order)  alloc_pages((mask), (order))

#define alloc_page(mask)      alloc_pages((mask), 0)
#define cfs_alloc_page(mask)  alloc_page(mask)

static inline void __free_pages(cfs_page_t *pg, int what)
{
#if 0 //#ifdef MAP_ANONYMOUS
        munmap(pg->addr, PAGE_SIZE);
#else
        free(pg->addr);
#endif
        free(pg);
}
#define __cfs_free_pages(pg, order)  __free_pages((pg), (order))

#define __free_page(page) __free_pages((page), 0)
#define free_page(page) __free_page(page)
#define __cfs_free_page(page)  __cfs_free_pages((page), 0)

static inline cfs_page_t* __grab_cache_page(unsigned long index)
{
        cfs_page_t *pg = alloc_pages(0, 0);

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
#define ATTR_BLOCKS     0x4000
#define ATTR_KILL_SUID  0
#define ATTR_KILL_SGID  0

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

#define ll_iattr iattr

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

/* use the macro's argument to avoid unused warnings */
#define down(a) do { (void)a; } while (0)
#define mutex_down(a)   down(a)
#define up(a) do { (void)a; } while (0)
#define mutex_up(a)     up(a)
#define down_read(a) do { (void)a; } while (0)
#define up_read(a) do { (void)a; } while (0)
#define down_write(a) do { (void)a; } while (0)
#define up_write(a) do { (void)a; } while (0)
#define sema_init(a,b) do { (void)a; } while (0)
#define init_rwsem(a) do { (void)a; } while (0)
#define DECLARE_MUTEX(name)     \
        struct semaphore name = { 1 }
static inline void init_MUTEX (struct semaphore *sem)
{
        sema_init(sem, 1);
}
static inline void init_MUTEX_LOCKED (struct semaphore *sem)
{
        sema_init(sem, 0);
}

#define init_mutex(s)   init_MUTEX(s)

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

struct task_struct {
        int state;
        struct signal pending;
        char comm[32];
        int uid;
        int gid;
        int pid;
        int fsuid;
        int fsgid;
        int max_groups;
        int ngroups;
        gid_t *groups;
        __u32 cap_effective;
};

typedef struct task_struct cfs_task_t;
#define cfs_current()           current
#define cfs_curproc_pid()       (current->pid)
#define cfs_curproc_comm()      (current->comm)

extern struct task_struct *current;
int in_group_p(gid_t gid);
static inline int capable(int cap)
{
        if (current->cap_effective & (1 << cap))
                return 1;
        else
                return 0;
}

#define set_current_state(foo) do { current->state = foo; } while (0)

#define init_waitqueue_entry(q,p) do { (q)->process = p; } while (0)
#define add_wait_queue(q,p) do {  list_add(&(q)->sleepers, &(p)->sleeping); } while (0)
#define del_wait_queue(p) do { list_del(&(p)->sleeping); } while (0)
#define remove_wait_queue(q,p) do { list_del(&(p)->sleeping); } while (0)

#define DECLARE_WAIT_QUEUE_HEAD(HEAD)                           \
        wait_queue_head_t HEAD = {                              \
                .sleepers = CFS_LIST_HEAD_INIT(HEAD.sleepers)   \
        }
#define init_waitqueue_head(l) CFS_INIT_LIST_HEAD(&(l)->sleepers)
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
#define unlock_kernel() do {} while (0)
#define daemonize(l) do {} while (0)
#define sigfillset(l) do {} while (0)
#define recalc_sigpending(l) do {} while (0)
#define kernel_thread(l,m,n) LBUG()

#define USERMODEHELPER(path, argv, envp) (0)
#define SIGNAL_MASK_ASSERT()
#define KERN_INFO

#include <sys/time.h>
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
#define time_after(a, b) ((long)(b) - (long)(a) < 0)
#define time_before(a, b) time_after(b,a)
#define time_after_eq(a,b)      ((long)(a) - (long)(b) >= 0)

struct timer_list {
        struct list_head tl_list;
        void (*function)(unsigned long unused);
        unsigned long data;
        long expires;
};

static inline int timer_pending(struct timer_list *l)
{
        if (time_after(l->expires, jiffies))
                return 1;
        else
                return 0;
}

static inline int init_timer(struct timer_list *l)
{
        CFS_INIT_LIST_HEAD(&l->tl_list);
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

#define ATOMIC_INIT(i) { (i) }

#define atomic_read(a) ((a)->counter)
#define atomic_set(a,b) do {(a)->counter = b; } while (0)
#define atomic_dec_and_test(a) ((--((a)->counter)) == 0)
#define atomic_dec_and_lock(a,b) ((--((a)->counter)) == 0)
#define atomic_inc(a)  (((a)->counter)++)
#define atomic_dec(a)  do { (a)->counter--; } while (0)
#define atomic_add(b,a)  do {(a)->counter += b;} while (0)
#define atomic_add_return(n,a) ((a)->counter += n)
#define atomic_inc_return(a) atomic_add_return(1,a)
#define atomic_sub(b,a)  do {(a)->counter -= b;} while (0)
#define atomic_sub_return(n,a) ((a)->counter -= n)
#define atomic_dec_return(a)  atomic_sub_return(1,a)

#ifndef likely
#define likely(exp) (exp)
#endif
#ifndef unlikely
#define unlikely(exp) (exp)
#endif

#define might_sleep()
#define might_sleep_if(c)
#define smp_mb()

static inline
int test_and_set_bit(int nr, unsigned long *addr)
{
        int oldbit;

        while (nr >= sizeof(long)) {
                nr -= sizeof(long);
                addr++;
        }

        oldbit = (*addr) & (1 << nr);
        *addr |= (1 << nr);
        return oldbit;
}

static inline
int test_and_clear_bit(int nr, unsigned long *addr)
{
        int oldbit;

        while (nr >= sizeof(long)) {
                nr -= sizeof(long);
                addr++;
        }

        oldbit = (*addr) & (1 << nr);
        *addr &= ~(1 << nr);
        return oldbit;
}

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

#define CAP_DAC_OVERRIDE        1
#define CAP_DAC_READ_SEARCH     2
#define CAP_FOWNER              3
#define CAP_FSETID              4
#define CAP_SYS_ADMIN          21

cap_t   cap_get_proc(void);
int     cap_get_flag(cap_t, cap_value_t, cap_flag_t, cap_flag_value_t *);

static inline void libcfs_run_lbug_upcall(char *file, const char *fn,
                                           const int l){}

/* completion */
struct completion {
        unsigned int done;
        cfs_waitq_t wait;
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
        const char         *llwc_name;
        int               (*llwc_fn)(void *arg);
        void               *llwc_arg;
};

void *liblustre_register_wait_callback(const char *name,
                                       int (*fn)(void *arg), void *arg);
void liblustre_deregister_wait_callback(void *notifier);
int liblustre_wait_event(int timeout);

void *liblustre_register_idle_callback(const char *name, 
                                       int (*fn)(void *arg), void *arg);
void liblustre_deregister_idle_callback(void *notifier);
void liblustre_wait_idle(void);

/* flock related */
struct nfs_lock_info {
        __u32             state;
        __u32             flags;
        void            *host;
};

typedef struct file_lock {
        struct file_lock *fl_next;      /* singly linked list for this inode  */
        struct list_head fl_link;       /* doubly linked list of all locks */
        struct list_head fl_block;      /* circular list of blocked processes */
        void *fl_owner;
        unsigned int fl_pid;
        cfs_waitq_t fl_wait;
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

        union {
                struct nfs_lock_info    nfs_fl;
        } fl_u;
} cfs_flock_t;

#define cfs_flock_type(fl)                  ((fl)->fl_type)
#define cfs_flock_set_type(fl, type)        do { (fl)->fl_type = (type); } while(0)
#define cfs_flock_pid(fl)                   ((fl)->fl_pid)
#define cfs_flock_set_pid(fl, pid)          do { (fl)->fl_pid = (pid); } while(0)
#define cfs_flock_start(fl)                 ((fl)->fl_start)
#define cfs_flock_set_start(fl, start)      do { (fl)->fl_start = (start); } while(0)
#define cfs_flock_end(fl)                   ((fl)->fl_end)
#define cfs_flock_set_end(fl, end)          do { (fl)->fl_end = (end); } while(0)

#ifndef OFFSET_MAX
#define INT_LIMIT(x)    (~((x)1 << (sizeof(x)*8 - 1)))
#define OFFSET_MAX      INT_LIMIT(loff_t)
#endif

/* XXX: defined in kernel */
#define FL_POSIX        1
#define FL_SLEEP        128

/* quota */
#define QUOTA_OK 0
#define NO_QUOTA 1

/* ACL */
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

typedef struct {
        __u16           e_tag;
        __u16           e_perm;
        __u32           e_id;
} xattr_acl_entry;

typedef struct {
        __u32           a_version;
        xattr_acl_entry a_entries[0];
} xattr_acl_header;

static inline size_t xattr_acl_size(int count)
{
        return sizeof(xattr_acl_header) + count * sizeof(xattr_acl_entry);
}

static inline
struct posix_acl * posix_acl_from_xattr(const void *value, size_t size)
{
        return NULL;
}

static inline
int posix_acl_valid(const struct posix_acl *acl)
{
        return 0;
}

static inline
void posix_acl_release(struct posix_acl *acl)
{
}

#ifdef LIBLUSTRE_POSIX_ACL
# ifndef posix_acl_xattr_entry 
#  define posix_acl_xattr_entry xattr_acl_entry
# endif
# ifndef posix_acl_xattr_header 
#  define posix_acl_xattr_header xattr_acl_header
# endif
# ifndef posix_acl_xattr_size
#  define posix_acl_xattr_size(entry) xattr_acl_size(entry)
# endif
# ifndef CONFIG_FS_POSIX_ACL
#  define CONFIG_FS_POSIX_ACL 1
# endif
#endif

#ifndef ENOTSUPP
#define ENOTSUPP ENOTSUP
#endif

typedef int mm_segment_t;
enum {
        KERNEL_DS,
        USER_DS
};
static inline mm_segment_t get_fs(void)
{
        return USER_DS;
}

static inline void set_fs(mm_segment_t seg)
{
}

#include <obd_support.h>
#include <lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_import.h>
#include <lustre_export.h>
#include <lustre_net.h>

/* Fast hashing routine for a long.
   (C) 2002 William Lee Irwin III, IBM */

/*
 * Knuth recommends primes in approximately golden ratio to the maximum
 * integer representable by a machine word for multiplicative hashing.
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * These primes are chosen to be bit-sparse, that is operations on
 * them can use shifts and additions instead of multiplications for
 * machines where multiplications are slow.
 */
#if BITS_PER_LONG == 32
/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME 0x9e370001UL
#elif BITS_PER_LONG == 64
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME 0x9e37fffffffc0001UL
#else
#error Define GOLDEN_RATIO_PRIME for your wordsize.
#endif

static inline unsigned long hash_long(unsigned long val, unsigned int bits)
{
	unsigned long hash = val;

#if BITS_PER_LONG == 64
	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	unsigned long n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;
#else
	/* On some cpus multiply is faster, on others gcc will do shifts */
	hash *= GOLDEN_RATIO_PRIME;
#endif

	/* High bits are more random, so use them. */
	return hash >> (BITS_PER_LONG - bits);
}
	
static inline unsigned long hash_ptr(void *ptr, unsigned int bits)
{
	return hash_long((unsigned long)ptr, bits);
}

#endif
