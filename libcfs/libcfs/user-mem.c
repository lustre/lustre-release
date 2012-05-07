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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/user-mem.c
 *
 * Userspace memory management.
 *
 */

#ifdef __KERNEL__
#error "This is not kernel code."
#endif

#include <libcfs/libcfs.h>

/*
 * Allocator
 */

cfs_page_t *cfs_alloc_page(unsigned int flags)
{
        cfs_page_t *pg = malloc(sizeof(*pg));
        int rc = 0;

        if (!pg)
                return NULL;
        pg->addr = NULL;

#if defined (__DARWIN__)
        pg->addr = valloc(CFS_PAGE_SIZE);
#elif defined (__WINNT__)
        pg->addr = pgalloc(0);
#else
        rc = posix_memalign(&pg->addr, CFS_PAGE_SIZE, CFS_PAGE_SIZE);
#endif
        if (rc != 0 || pg->addr == NULL) {
                free(pg);
                return NULL;
        }
        return pg;
}

void cfs_free_page(cfs_page_t *pg)
{
#if defined (__WINNT__)
        pgfree(pg->addr);
#else
        free(pg->addr);
#endif

        free(pg);
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
 * SLAB allocator
 */

cfs_mem_cache_t *
cfs_mem_cache_create(const char *name, size_t objsize, size_t off, unsigned long flags)
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
        return cfs_alloc(c->size, gfp);
}

void cfs_mem_cache_free(cfs_mem_cache_t *c, void *addr)
{
        cfs_free(addr);
}

/**
 * Returns true if \a addr is an address of an allocated object in a slab \a
 * kmem. Used in assertions. This check is optimistically imprecise, i.e., it
 * occasionally returns true for the incorrect addresses, but if it returns
 * false, then the addresses is guaranteed to be incorrect.
 */
int cfs_mem_is_in_cache(const void *addr, const cfs_mem_cache_t *kmem)
{
        return 1;
}
