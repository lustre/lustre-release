/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
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
 */
#define DEBUG_SUBSYSTEM S_PORTALS

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <libcfs/libcfs.h>

void *
cfs_alloc(size_t nr_bytes, u_int32_t flags)
{
	void *ptr = NULL;
	unsigned int mflags = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
	if (flags & CFS_ALLOC_ATOMIC)
		mflags |= __GFP_HIGH;
        else if (flags & CFS_ALLOC_WAIT)
                mflags |= __GFP_WAIT;
	else
		mflags |= (__GFP_HIGH | __GFP_WAIT);

	if (flags & CFS_ALLOC_FS)
		mflags |= __GFP_FS;
	if (flags & CFS_ALLOC_IO)
		mflags |= __GFP_IO | __GFP_HIGHIO;
#else
        if (flags & CFS_ALLOC_ATOMIC)
                mflags |= __GFP_HIGH;
        else
                mflags |= __GFP_WAIT;
        if (flags & CFS_ALLOC_FS)
                mflags |= __GFP_FS;
        if (flags & CFS_ALLOC_IO)
                mflags |= __GFP_IO;
#endif

	ptr = kmalloc(nr_bytes, mflags);
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

cfs_page_t *
cfs_alloc_pages(unsigned int flags, unsigned int order)
{
        unsigned int mflags = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
	if (flags & CFS_ALLOC_ATOMIC)
		mflags |= __GFP_HIGH;
        else if (flags & CFS_ALLOC_WAIT)
                mflags |= __GFP_WAIT;
	else
		mflags |= (__GFP_HIGH | __GFP_WAIT);

	if (flags & CFS_ALLOC_FS)
		mflags |= __GFP_FS;
	if (flags & CFS_ALLOC_IO)
		mflags |= __GFP_IO | __GFP_HIGHIO;
        if (flags & CFS_ALLOC_HIGH)
                mflags |=  __GFP_HIGHMEM;
#else
        if (flags & CFS_ALLOC_ATOMIC)
                mflags |= __GFP_HIGH;
        else
                mflags |= __GFP_WAIT;
        if (flags & CFS_ALLOC_FS)
                mflags |= __GFP_FS;
        if (flags & CFS_ALLOC_IO)
                mflags |= __GFP_IO;
        if (flags & CFS_ALLOC_HIGH)
                mflags |=  __GFP_HIGHMEM;
#endif

        return alloc_pages(mflags, order);
}

cfs_mem_cache_t *
cfs_mem_cache_create (const char *name, size_t size, size_t offset,
                      unsigned long flags, void (*ctor)(void*, kmem_cache_t *, unsigned long),
                      void (*dtor)(void*, cfs_mem_cache_t *, unsigned long))
{
        return kmem_cache_create(name, size, offset, flags, ctor, dtor);
}

int
cfs_mem_cache_destroy (cfs_mem_cache_t * cachep)
{
        return kmem_cache_destroy(cachep);
}

void *
cfs_mem_cache_alloc(cfs_mem_cache_t *cachep, int flags)
{
        unsigned int mflags = 0;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
	if (flags & CFS_SLAB_ATOMIC)
		mflags |= __GFP_HIGH;
        else if (flags & CFS_ALLOC_WAIT)
                mflags |= __GFP_WAIT;
	else
		mflags |= (__GFP_HIGH | __GFP_WAIT);

	if (flags & CFS_SLAB_FS)
		mflags |= __GFP_FS;
	if (flags & CFS_SLAB_IO)
		mflags |= __GFP_IO | __GFP_HIGHIO;
#else
        if (flags & CFS_SLAB_ATOMIC)
                mflags |= __GFP_HIGH;
        else
                mflags |= __GFP_WAIT;
        if (flags & CFS_SLAB_FS)
                mflags |= __GFP_FS;
        if (flags & CFS_SLAB_IO)
                mflags |= __GFP_IO;
#endif

        return kmem_cache_alloc(cachep, mflags);
}

void
cfs_mem_cache_free(cfs_mem_cache_t *cachep, void *objp)
{
        return kmem_cache_free(cachep, objp);
}

EXPORT_SYMBOL(cfs_alloc);
EXPORT_SYMBOL(cfs_free);
EXPORT_SYMBOL(cfs_alloc_large);
EXPORT_SYMBOL(cfs_free_large);
EXPORT_SYMBOL(cfs_alloc_pages);
EXPORT_SYMBOL(cfs_mem_cache_create);
EXPORT_SYMBOL(cfs_mem_cache_destroy);
EXPORT_SYMBOL(cfs_mem_cache_alloc);
EXPORT_SYMBOL(cfs_mem_cache_free);
