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

struct page *alloc_page(unsigned int flags)
{
	struct page *pg = malloc(sizeof(*pg));
        int rc = 0;

        if (!pg)
                return NULL;
        pg->addr = NULL;

#if defined (__DARWIN__)
	pg->addr = valloc(PAGE_CACHE_SIZE);
#else
	rc = posix_memalign(&pg->addr, PAGE_CACHE_SIZE, PAGE_CACHE_SIZE);
#endif
        if (rc != 0 || pg->addr == NULL) {
                free(pg);
                return NULL;
        }
        return pg;
}

void __free_page(struct page *pg)
{
        free(pg->addr);

        free(pg);
}

void *page_address(struct page *pg)
{
        return pg->addr;
}

void *kmap(struct page *pg)
{
        return pg->addr;
}

void kunmap(struct page *pg)
{
}

/*
 * SLAB allocator
 */

struct kmem_cache *
kmem_cache_create(const char *name, size_t objsize, size_t off,
		  unsigned long flags, void *ctor)
{
	struct kmem_cache *c;

        c = malloc(sizeof(*c));
        if (!c)
                return NULL;
        c->size = objsize;
        CDEBUG(D_MALLOC, "alloc slab cache %s at %p, objsize %d\n",
               name, c, (int)objsize);
        return c;
}

void kmem_cache_destroy(struct kmem_cache *c)
{
        CDEBUG(D_MALLOC, "destroy slab cache %p, objsize %u\n", c, c->size);
        free(c);
}

void *kmem_cache_alloc(struct kmem_cache *c, int gfp)
{
	return kmalloc(c->size, gfp);
}

void kmem_cache_free(struct kmem_cache *c, void *addr)
{
	kfree(addr);
}

/**
 * Returns true if \a addr is an address of an allocated object in a slab \a
 * kmem. Used in assertions. This check is optimistically imprecise, i.e., it
 * occasionally returns true for the incorrect addresses, but if it returns
 * false, then the addresses is guaranteed to be incorrect.
 */
int kmem_is_in_cache(const void *addr, const struct kmem_cache *kmem)
{
        return 1;
}
