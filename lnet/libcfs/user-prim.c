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
 * Implementation of portable APIs for user-level.
 *
 */

/* Implementations of portable APIs for liblustre */

/*
 * liblustre is single-threaded, so most "synchronization" APIs are trivial.
 */

#ifndef __KERNEL__

#include <sys/mman.h>
#ifndef  __CYGWIN__
#include <stdint.h>
#include <asm/page.h>
#else
#include <sys/types.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <libcfs/libcfs.h>

/*
 * Sleep channel. No-op implementation.
 */

void cfs_waitq_init(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitlink_init(struct cfs_waitlink *link)
{
        LASSERT(link != NULL);
        (void)link;
}

void cfs_waitq_add(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

void cfs_waitq_add_exclusive(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

void cfs_waitq_forward(struct cfs_waitlink *link, struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

void cfs_waitq_del(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

int cfs_waitq_active(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_signal(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_signal_nr(struct cfs_waitq *waitq, int nr)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_broadcast(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_wait(struct cfs_waitlink *link)
{
        LASSERT(link != NULL);
        (void)link;
}

int64_t cfs_waitq_timedwait(struct cfs_waitlink *link, int64_t timeout)
{
        LASSERT(link != NULL);
        (void)link;
}

/*
 * Allocator
 */

cfs_page_t *cfs_alloc_pages(unsigned int flags, unsigned int order)
{
        cfs_page_t *pg = malloc(sizeof(*pg));

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

void cfs_free_pages(struct page *pg, int what)
{
#if 0 //#ifdef MAP_ANONYMOUS
        munmap(pg->addr, PAGE_SIZE);
#else
        free(pg->addr);
#endif
        free(pg);
}

cfs_page_t *cfs_alloc_page(unsigned int flags)
{
        return cfs_alloc_pages(flags, 0);
}

void cfs_free_page(cfs_page_t *pg, int what)
{
        cfs_free_page(pg, what);
}

void *cfs_page_address(cfs_page_t *pg)
{
        return pg->addr;
}

void *cfs_kmap(cfs_page_t *pg)
{
        return pg->addr;
}

void cfs_kunmap(cfs_page_t *pg)
{
}

/*
 * Memory allocator
 */
void *cfs_alloc(size_t nr_bytes, u_int32_t flags)
{
        void *result;

        result = malloc(nr_bytes);
        if (result != NULL && (flags & CFS_ALLOC_ZERO))
		memset(result, 0, nr_bytes);
}

void cfs_free(void *addr)
{
        free(addr);
}

void *cfs_alloc_large(size_t nr_bytes)
{
        return cfs_alloc(nr_bytes, 0);
}

void  cfs_free_large(void *addr)
{
        return cfs_free(addr);
}

/*
 * SLAB allocator
 */

cfs_mem_cache_t *
cfs_mem_cache_create(const char *, size_t, size_t, unsigned long,
                     void (*)(void *, cfs_mem_cache_t *, unsigned long),
                     void (*)(void *, cfs_mem_cache_t *, unsigned long))
{
        cfs_mem_cache_t *c;

        c = malloc(sizeof(*c));
        if (!c)
                return NULL;
        c->size = objsize;
        CDEBUG(D_MALLOC, "alloc slab cache %s at %p, objsize %d\n",
               name, c, (int)objsize);
        return c;
}

int cfs_mem_cache_destroy(cfs_mem_cache_t *c)
{
        CDEBUG(D_MALLOC, "destroy slab cache %p, objsize %u\n", c, c->size);
        free(c);
        return 0;
}

void *cfs_mem_cache_alloc(cfs_mem_cache_t *c, int gfp)
{
        return cfs_alloc(c, gfp);
}

void cfs_mem_cache_free(cfs_mem_cache_t *c, void *addr)
{
        cfs_free(addr);
}


/* !__KERNEL__ */
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
