/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 * Author: Nikita Danilov <nikita@clusterfs.com>
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or modify it under the
 * terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * Lustre is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with Lustre; if not, write to the Free Software Foundation, Inc., 675 Mass
 * Ave, Cambridge, MA 02139, USA.
 *
 * Implementation of portable time API for user-level.
 *
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

#include <libcfs/list.h>

/*
 * Wait Queue. No-op implementation.
 */

typedef struct cfs_waitlink {} cfs_waitlink_t;
typedef struct cfs_waitq {} cfs_waitq_t;

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
void cfs_waitq_wait(struct cfs_waitlink *link);
int64_t cfs_waitq_timedwait(struct cfs_waitlink *link, int64_t timeout);

/*
 * Allocator
 */

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
};

typedef struct page cfs_page_t;

#define CFS_PAGE_SIZE                   PAGE_CACHE_SIZE
#define CFS_PAGE_SHIFT                  PAGE_CACHE_SHIFT
#define CFS_PAGE_MASK                   PAGE_CACHE_MASK

cfs_page_t *cfs_alloc_pages(unsigned int flags, unsigned int order);
void cfs_free_pages(struct page *pg, int what);

cfs_page_t *cfs_alloc_page(unsigned int flags);
void cfs_free_page(cfs_page_t *pg, int what);
void *cfs_page_address(cfs_page_t *pg);
void *cfs_kmap(cfs_page_t *pg);
void cfs_kunmap(cfs_page_t *pg);

#define cfs_get_page(p)			__I_should_not_be_called__(at_all)
#define cfs_page_count(p)		__I_should_not_be_called__(at_all)
#define cfs_set_page_count(p, v)	__I_should_not_be_called__(at_all)

/*
 * Memory allocator
 */
void *cfs_alloc(size_t nr_bytes, u_int32_t flags);
void cfs_free(void *addr);
void *cfs_alloc_large(size_t nr_bytes);
void  cfs_free_large(void *addr);

/*
 * SLAB allocator
 */
typedef struct {
         int size;
} cfs_mem_cache_t;

#define SLAB_HWCACHE_ALIGN 0

cfs_mem_cache_t *
cfs_mem_cache_create(const char *, size_t, size_t, unsigned long,
                     void (*)(void *, cfs_mem_cache_t *, unsigned long),
                     void (*)(void *, cfs_mem_cache_t *, unsigned long));
int cfs_mem_cache_destroy(cfs_mem_cache_t *c);
void *cfs_mem_cache_alloc(cfs_mem_cache_t *c, int gfp);
void cfs_mem_cache_free(cfs_mem_cache_t *c, void *addr);

typedef int (cfs_read_proc_t)(char *page, char **start, off_t off,
                          int count, int *eof, void *data);

struct file; /* forward ref */
typedef int (cfs_write_proc_t)(struct file *file, const char *buffer,
                               unsigned long count, void *data);

/*
 * Timer
 */

typedef struct cfs_timer {} cfs_timer_t;

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
#define irqs_disabled()   (0)

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
