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
#include <asm/page.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <portals/list.h>
#include <portals/p30.h>

/* definitions for liblustre */

/* always adopt 2.5 definitions */
#define LINUX_VERSION_CODE 1
#define KERNEL_VERSION(a,b,c) 0

static inline void inter_module_put(void *a)
{
        return;
}

extern ptl_handle_ni_t         tcpnal_ni;

static inline void *inter_module_get(char *arg)
{

        if (strcmp(arg, "tcpnal_ni") == 0 )
                return &tcpnal_ni;
        else
                return NULL;

}


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
#define IS_ERR(a) ((abc && abs((int)(a)) < 500) ? 1 : 0)
#define PTR_ERR(a) ((int)(a))

#define capable(foo) 1
#define CAP_SYS_ADMIN 1

typedef struct {
        void *cwd;

}mm_segment_t;

typedef void *read_proc_t;
typedef void *write_proc_t;


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
static inline void spin_lock_irqrestore(a,b)
{
        return;
}
static inline void spin_unlock_irqrestore(a,b)
{
        return;
}
static inline void spin_lock_irqsave(a,b)
{
        return;
}

#define barrier() do {int a= 1; a++; } while (0)

/* registering symbols */

#define ERESTARTSYS ERESTART
#define HZ 1

/* random */

static inline void get_random_bytes(void *ptr, int size)
{
        static int r;
        int *p = (int *)ptr;
        int *end = p + (size / sizeof(int));
        r = rand();
        while ( p + sizeof(int) < end ) {
                *p = r;
                p++;
        }
}

/* memory */

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
static inline kmem_cache_t *kmem_cache_create(name,objsize,cdum,d,e,f)
{
        kmem_cache_t *c;
        c = malloc(sizeof(*c));
        if (!c)
                return NULL;
        c->size = objsize;
        return c;
};

static inline int kmem_cache_destroy(kmem_cache_t *a)
{
        free(a);
        return 0;
}
#define kmem_cache_validate(a,b) 1
#define kmem_cache_alloc(cache, prio) malloc(cache->size)
#define kmem_cache_free(cache, obj) OBD_FREE(obj, cache->size)
#define PORTAL_SLAB_ALLOC(lock,cache,size) do { lock = kmem_cache_alloc(cache,prio); } while (0)
#define PORTAL_SLAB_FREE(lock,cache,size) do { lock = kmem_cache_alloc(cache,prio); } while (0)

struct page {
        void *addr;
        int index;
};

#define kmap(page) (page)->addr
#define kunmap(a) do { int foo = 1; foo++; } while (0)

static inline struct page *alloc_pages(mask,foo)
{
        struct page *pg = malloc(sizeof(*pg));

        if (!pg)
                return NULL;
#ifdef MAP_ANONYMOUS
        pg->addr = mmap(0, PAGE_SIZE, PROT_WRITE, MAP_ANONYMOUS, 0, 0);
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

/* arithmetic */
#define do_div(a,b) (a)/(b)

/* dentries / intents */
struct lookup_intent {
        void *it_iattr;
};

struct iattr {
        int mode;
};

struct dentry {
        int d_count;
};
struct file {
        struct dentry *f_dentry;
        void *private_data;
} ;

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

struct task_struct {
        int state;
        struct signal pending;
        char comm[32];
        int pid;
};

extern struct task_struct *current;



#define set_current_state(foo) do { current->state = foo; } while (0)

#define init_waitqueue_entry(q,p) do { (q)->process = p; } while (0)
#define add_wait_queue(q,p) do {  list_add(&(q)->sleepers, &(p)->sleeping); } while (0)
#define del_wait_queue(p) do { list_del(&(p)->sleeping); } while (0)
#define remove_wait_queue(q,p) do { list_del(&(p)->sleeping); } while (0)

#define init_waitqueue_head(l) INIT_LIST_HEAD(&(l)->sleepers)
#define wake_up(l) do { int a; a++; } while (0)
#define wait_event(l,m) do { int a; a++; } while (0)
#define TASK_INTERRUPTIBLE 0
#define TASK_UNINTERRUPTIBLE 1
#define TASK_RUNNING 2


#define schedule() do { int a; a++; } while (0)
static inline int schedule_timeout(t)
{
        return 0;
}

#define lock_kernel() do { int a; a++; } while (0)
#define daemonize(l) do { int a; a++; } while (0)
#define sigfillset(l) do { int a; a++; } while (0)
#define recalc_sigpending(l) do { int a; a++; } while (0)
#define kernel_thread(l,m,n)

static inline int call_usermodehelper(char *prog, char **argv, char **evnp)
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

#define LBUG() do { sleep(1000000); } while (0)

#include <linux/obd_support.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_import.h>
#include <linux/lustre_export.h>
#include <linux/lustre_net.h>


#endif

