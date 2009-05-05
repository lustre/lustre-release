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
 * lnet/include/libcfs/winnt/winnt-mem.h
 *
 * Basic library routines of memory manipulation routines.
 */

#ifndef __LIBCFS_WINNT_CFS_MEM_H__
#define __LIBCFS_WINNT_CFS_MEM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__

#define CFS_PAGE_SIZE                   PAGE_SIZE
#define CFS_PAGE_SHIFT                  PAGE_SHIFT
#define CFS_PAGE_MASK                   (~(PAGE_SIZE - 1))

typedef struct cfs_page {
    void *      addr;
    atomic_t    count;
} cfs_page_t;


cfs_page_t *cfs_alloc_page(int flags);
void cfs_free_page(cfs_page_t *pg);

static inline void *cfs_page_address(cfs_page_t *page)
{
    return page->addr;
}

static inline void *cfs_kmap(cfs_page_t *page)
{
    return page->addr;
}

static inline void cfs_kunmap(cfs_page_t *page)
{
    return;
}

static inline void cfs_get_page(cfs_page_t *page)
{
    atomic_inc(&page->count);
}

static inline void cfs_put_page(cfs_page_t *page)
{
    atomic_dec(&page->count);
}

static inline int cfs_page_count(cfs_page_t *page)
{
    return atomic_read(&page->count);
}

/*
 * Memory allocator
 */

#define CFS_ALLOC_ATOMIC_TRY	(0)

extern void *cfs_alloc(size_t nr_bytes, u_int32_t flags);
extern void  cfs_free(void *addr);

extern void *cfs_alloc_large(size_t nr_bytes);
extern void  cfs_free_large(void *addr);

/*
 * SLAB allocator
 */

#define SLAB_HWCACHE_ALIGN		0

/* The cache name is limited to 20 chars */

typedef struct cfs_mem_cache {

    char                    name[20];
    ulong_ptr           flags;
    NPAGED_LOOKASIDE_LIST   npll;

} cfs_mem_cache_t;


extern cfs_mem_cache_t * cfs_mem_cache_create (const char *, size_t, size_t, ulong_ptr);
extern int cfs_mem_cache_destroy ( cfs_mem_cache_t * );
extern void *cfs_mem_cache_alloc ( cfs_mem_cache_t *, int);
extern void cfs_mem_cache_free ( cfs_mem_cache_t *, void *);


/*
 * Page allocator slabs 
 */

extern cfs_mem_cache_t *cfs_page_t_slab;
extern cfs_mem_cache_t *cfs_page_p_slab;


#define CFS_DECL_MMSPACE
#define CFS_MMSPACE_OPEN    do {} while(0)
#define CFS_MMSPACE_CLOSE   do {} while(0)


#define mb()    do {} while(0)
#define rmb()   mb()
#define wmb()   mb()


/* __KERNEL__ */
#endif

#endif /* __WINNT_CFS_MEM_H__ */
