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
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_LNET

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <libcfs/libcfs.h>

static unsigned int cfs_alloc_flags_to_gfp(u_int32_t flags)
{
	unsigned int mflags = 0;

        if (flags & CFS_ALLOC_ATOMIC)
                mflags |= __GFP_HIGH;
        else
                mflags |= __GFP_WAIT;
        if (flags & CFS_ALLOC_NOWARN)
                mflags |= __GFP_NOWARN;
        if (flags & CFS_ALLOC_IO)
                mflags |= __GFP_IO;
        if (flags & CFS_ALLOC_FS)
                mflags |= __GFP_FS;
	if (flags & CFS_ALLOC_HIGHMEM)
		mflags |= __GFP_HIGHMEM;
        return mflags;
}

void *
cfs_alloc(size_t nr_bytes, u_int32_t flags)
{
	void *ptr = NULL;

	ptr = kmalloc(nr_bytes, cfs_alloc_flags_to_gfp(flags));
	if (ptr != NULL && (flags & CFS_ALLOC_ZERO))
		memset(ptr, 0, nr_bytes);
	return ptr;
}

void
cfs_free(void *addr)
{
	kfree(addr);
}

void *
cfs_alloc_large(size_t nr_bytes)
{
	return vmalloc(nr_bytes);
}

void
cfs_free_large(void *addr)
{
	vfree(addr);
}

cfs_page_t *cfs_alloc_page(unsigned int flags)
{
        /*
         * XXX nikita: do NOT call portals_debug_msg() (CDEBUG/ENTRY/EXIT)
         * from here: this will lead to infinite recursion.
         */
        return alloc_page(cfs_alloc_flags_to_gfp(flags));
}

void cfs_free_page(cfs_page_t *page)
{
        __free_page(page);
}

cfs_mem_cache_t *
cfs_mem_cache_create (const char *name, size_t size, size_t offset,
                      unsigned long flags)
{
#ifdef HAVE_KMEM_CACHE_CREATE_DTOR
        return kmem_cache_create(name, size, offset, flags, NULL, NULL);
#else
        return kmem_cache_create(name, size, offset, flags, NULL);
#endif
}

int
cfs_mem_cache_destroy (cfs_mem_cache_t * cachep)
{
#ifdef HAVE_KMEM_CACHE_DESTROY_INT
        return kmem_cache_destroy(cachep);
#else
        kmem_cache_destroy(cachep);
        return 0;
#endif
}

void *
cfs_mem_cache_alloc(cfs_mem_cache_t *cachep, int flags)
{
        return kmem_cache_alloc(cachep, cfs_alloc_flags_to_gfp(flags));
}

void
cfs_mem_cache_free(cfs_mem_cache_t *cachep, void *objp)
{
        return kmem_cache_free(cachep, objp);
}

/**
 * Returns true if \a addr is an address of an allocated object in a slab \a
 * kmem. Used in assertions. This check is optimistically imprecise, i.e., it
 * occasionally returns true for the incorrect addresses, but if it returns
 * false, then the addresses is guaranteed to be incorrect.
 */
int cfs_mem_is_in_cache(const void *addr, const cfs_mem_cache_t *kmem)
{
#ifdef CONFIG_SLAB
        struct page *page;

        /*
         * XXX Copy of mm/slab.c:virt_to_cache(). It won't work with other
         * allocators, like slub and slob.
         */
        page = virt_to_page(addr);
        if (unlikely(PageCompound(page)))
                page = (struct page *)page->private;
        return PageSlab(page) && ((void *)page->lru.next) == kmem;
#else
        return 1;
#endif
}
EXPORT_SYMBOL(cfs_mem_is_in_cache);


EXPORT_SYMBOL(cfs_alloc);
EXPORT_SYMBOL(cfs_free);
EXPORT_SYMBOL(cfs_alloc_large);
EXPORT_SYMBOL(cfs_free_large);
EXPORT_SYMBOL(cfs_alloc_page);
EXPORT_SYMBOL(cfs_free_page);
EXPORT_SYMBOL(cfs_mem_cache_create);
EXPORT_SYMBOL(cfs_mem_cache_destroy);
EXPORT_SYMBOL(cfs_mem_cache_alloc);
EXPORT_SYMBOL(cfs_mem_cache_free);

/*
 * NB: we will rename some of above functions in another patch:
 * - rename cfs_alloc to cfs_malloc
 * - rename cfs_alloc/free_page to cfs_page_alloc/free
 * - rename cfs_alloc/free_large to cfs_vmalloc/vfree
 */

void *
cfs_cpt_malloc(struct cfs_cpt_table *cptab, int cpt,
	       size_t nr_bytes, unsigned int flags)
{
	void    *ptr;

	ptr = kmalloc_node(nr_bytes, cfs_alloc_flags_to_gfp(flags),
			   cfs_cpt_spread_node(cptab, cpt));
	if (ptr != NULL && (flags & CFS_ALLOC_ZERO) != 0)
		memset(ptr, 0, nr_bytes);

	return ptr;
}
EXPORT_SYMBOL(cfs_cpt_malloc);

void *
cfs_cpt_vmalloc(struct cfs_cpt_table *cptab, int cpt, size_t nr_bytes)
{
	return vmalloc_node(nr_bytes, cfs_cpt_spread_node(cptab, cpt));
}
EXPORT_SYMBOL(cfs_cpt_vmalloc);

cfs_page_t *
cfs_page_cpt_alloc(struct cfs_cpt_table *cptab, int cpt, unsigned int flags)
{
	return alloc_pages_node(cfs_cpt_spread_node(cptab, cpt),
				cfs_alloc_flags_to_gfp(flags), 0);
}
EXPORT_SYMBOL(cfs_page_cpt_alloc);

void *
cfs_mem_cache_cpt_alloc(cfs_mem_cache_t *cachep, struct cfs_cpt_table *cptab,
			int cpt, unsigned int flags)
{
	return kmem_cache_alloc_node(cachep, cfs_alloc_flags_to_gfp(flags),
				     cfs_cpt_spread_node(cptab, cpt));
}
EXPORT_SYMBOL(cfs_mem_cache_cpt_alloc);
