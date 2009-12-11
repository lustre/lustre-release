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
 * lnet/include/libcfs/user-prim.h
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_USER_PRIM_H__
#define __LIBCFS_USER_PRIM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

/* Implementations of portable APIs for liblustre */

/*
 * liblustre is single-threaded, so most "synchronization" APIs are trivial.
 */

#ifndef __KERNEL__

#include <stdlib.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <libcfs/list.h>
#include <libcfs/user-time.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#endif


/*
 * Wait Queue. No-op implementation.
 */

typedef struct cfs_waitlink {
        struct list_head sleeping;
        void *process;
} cfs_waitlink_t;

typedef struct cfs_waitq {
        struct list_head sleepers;
} cfs_waitq_t;

void cfs_waitq_init(struct cfs_waitq *waitq);
void cfs_waitlink_init(struct cfs_waitlink *link);
void cfs_waitq_add(struct cfs_waitq *waitq, struct cfs_waitlink *link);
void cfs_waitq_add_exclusive(struct cfs_waitq *waitq, 
                             struct cfs_waitlink *link);
void cfs_waitq_forward(struct cfs_waitlink *link, struct cfs_waitq *waitq);
void cfs_waitq_del(struct cfs_waitq *waitq, struct cfs_waitlink *link);
int  cfs_waitq_active(struct cfs_waitq *waitq);
void cfs_waitq_signal(struct cfs_waitq *waitq);
void cfs_waitq_signal_nr(struct cfs_waitq *waitq, int nr);
void cfs_waitq_broadcast(struct cfs_waitq *waitq);
void cfs_waitq_wait(struct cfs_waitlink *link, int state);
int64_t cfs_waitq_timedwait(struct cfs_waitlink *link, int state, int64_t timeout);
#define cfs_schedule_timeout(s, t)              \
        do {                                    \
                cfs_waitlink_t    l;            \
                cfs_waitq_timedwait(&l, s, t);  \
        } while (0)

#define CFS_TASK_INTERRUPTIBLE  (0)
#define CFS_TASK_UNINT          (0)

/* 2.4 defines */

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
        struct list_head _node;
};

typedef struct page cfs_page_t;

/* ppc64 defined PAGE_SIZE but without PAGE_SHIFT
 */
#if !defined(PAGE_SHIFT) || !defined(PAGE_SIZE)

/* 4K */
#define CFS_PAGE_SHIFT 12
#define CFS_PAGE_SIZE (1UL << CFS_PAGE_SHIFT)
#define CFS_PAGE_MASK (~((__u64)CFS_PAGE_SIZE-1))

#else

#define CFS_PAGE_SIZE                   PAGE_SIZE
#define CFS_PAGE_SHIFT                  PAGE_SHIFT
#define CFS_PAGE_MASK                   (~((__u64)CFS_PAGE_SIZE-1))

#endif

cfs_page_t *cfs_alloc_page(unsigned int flags);
void cfs_free_page(cfs_page_t *pg);
void *cfs_page_address(cfs_page_t *pg);
void *cfs_kmap(cfs_page_t *pg);
void cfs_kunmap(cfs_page_t *pg);

#define cfs_get_page(p)			__I_should_not_be_called__(at_all)
#define cfs_page_count(p)		__I_should_not_be_called__(at_all)
#define cfs_page_index(p)               ((p)->index)
#define cfs_page_pin(page) do {} while (0)
#define cfs_page_unpin(page) do {} while (0)

/*
 * Memory allocator
 * Inline function, so utils can use them without linking of libcfs
 */
#define __ALLOC_ZERO    (1 << 2)
static inline void *cfs_alloc(size_t nr_bytes, u_int32_t flags)
{
        void *result;

        result = malloc(nr_bytes);
        if (result != NULL && (flags & __ALLOC_ZERO))
                memset(result, 0, nr_bytes);
        return result;
}

#define cfs_free(addr)  free(addr)
#define cfs_alloc_large(nr_bytes) cfs_alloc(nr_bytes, 0)
#define cfs_free_large(addr) cfs_free(addr)

#define CFS_ALLOC_ATOMIC_TRY   (0)
/*
 * SLAB allocator
 */
typedef struct {
         int size;
} cfs_mem_cache_t;

#define SLAB_HWCACHE_ALIGN 0
#define SLAB_KERNEL 0
#define SLAB_NOFS 0

cfs_mem_cache_t *
cfs_mem_cache_create(const char *, size_t, size_t, unsigned long);
int cfs_mem_cache_destroy(cfs_mem_cache_t *c);
void *cfs_mem_cache_alloc(cfs_mem_cache_t *c, int gfp);
void cfs_mem_cache_free(cfs_mem_cache_t *c, void *addr);

typedef int (cfs_read_proc_t)(char *page, char **start, off_t off,
                          int count, int *eof, void *data);

struct file; /* forward ref */
typedef int (cfs_write_proc_t)(struct file *file, const char *buffer,
                               unsigned long count, void *data);

/*
 * Signal
 */
typedef sigset_t                        cfs_sigset_t;

/*
 * Timer
 */
#include <sys/time.h>

typedef struct {
        struct list_head tl_list;
        void (*function)(unsigned long unused);
        unsigned long data;
        long expires;
} cfs_timer_t;

#define cfs_init_timer(t)       do {} while(0)
#define cfs_jiffies                             \
({                                              \
        unsigned long _ret = 0;                 \
        struct timeval tv;                      \
        if (gettimeofday(&tv, NULL) == 0)       \
                _ret = tv.tv_sec;               \
        _ret;                                   \
})

static inline int cfs_timer_init(cfs_timer_t *l, void (* func)(unsigned long), void *arg)
{
        CFS_INIT_LIST_HEAD(&l->tl_list);
        l->function = func;
        l->data = (unsigned long)arg;
        return 0;
}

static inline int cfs_timer_is_armed(cfs_timer_t *l)
{
        if (cfs_time_before(cfs_jiffies, l->expires))
                return 1;
        else
                return 0;
}

static inline void cfs_timer_arm(cfs_timer_t *l, int thetime)
{
        l->expires = thetime;
}

static inline void cfs_timer_disarm(cfs_timer_t *l)
{
}

static inline long cfs_timer_deadline(cfs_timer_t *l)
{
        return l->expires;
}

#if 0
#define cfs_init_timer(t)	do {} while(0)
void cfs_timer_init(struct cfs_timer *t, void (*func)(unsigned long), void *arg);
void cfs_timer_done(struct cfs_timer *t);
void cfs_timer_arm(struct cfs_timer *t, cfs_time_t deadline);
void cfs_timer_disarm(struct cfs_timer *t);
int  cfs_timer_is_armed(struct cfs_timer *t);

cfs_time_t cfs_timer_deadline(struct cfs_timer *t);
#endif

#define in_interrupt()    (0)

static inline void cfs_pause(cfs_duration_t d)
{
        struct timespec s;
        
        cfs_duration_nsec(d, &s);
        nanosleep(&s, NULL);
}

typedef void cfs_psdev_t;

static inline int cfs_psdev_register(cfs_psdev_t *foo)
{
        return 0;
}

static inline int cfs_psdev_deregister(cfs_psdev_t *foo)
{
        return 0;
}

#define cfs_lock_kernel()               do {} while (0)
#define cfs_sigfillset(l) do {}         while (0)
#define cfs_recalc_sigpending(l)        do {} while (0)
#define cfs_kernel_thread(l,m,n)        LBUG()

#ifdef HAVE_LIBPTHREAD
typedef int (*cfs_thread_t)(void *);
int cfs_create_thread(cfs_thread_t func, void *arg);
#else
#define cfs_create_thread(l,m) LBUG()
#endif

int cfs_parse_int_tunable(int *value, char *name);
uid_t cfs_curproc_uid(void);

#define LIBCFS_REALLOC(ptr, size) realloc(ptr, size)

#define cfs_online_cpus() sysconf(_SC_NPROCESSORS_ONLN)

// static inline void local_irq_save(unsigned long flag) {return;}
// static inline void local_irq_restore(unsigned long flag) {return;}

enum {
        CFS_STACK_TRACE_DEPTH = 16
};

struct cfs_stack_trace {
        void *frame[CFS_STACK_TRACE_DEPTH];
};

/*
 * arithmetic
 */
#define do_div(a,b)                     \
        ({                              \
                unsigned long remainder;\
                remainder = (a) % (b);  \
                (a) = (a) / (b);        \
                (remainder);            \
        })

/* !__KERNEL__ */
#endif

/* __LIBCFS_USER_PRIM_H__ */
#endif
/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
