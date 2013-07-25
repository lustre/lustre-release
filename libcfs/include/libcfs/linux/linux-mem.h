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
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/linux/linux-mem.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_MEM_H__
#define __LIBCFS_LINUX_CFS_MEM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifndef __KERNEL__
#error This include is only for kernel use.
#endif

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#ifdef HAVE_MM_INLINE
# include <linux/mm_inline.h>
#endif

typedef struct page                     cfs_page_t;
#define CFS_PAGE_SIZE                   PAGE_CACHE_SIZE
#define CFS_PAGE_SHIFT                  PAGE_CACHE_SHIFT
#define CFS_PAGE_MASK                   (~((__u64)CFS_PAGE_SIZE-1))

#define cfs_num_physpages               num_physpages

#define cfs_copy_from_user(to, from, n) copy_from_user(to, from, n)
#define cfs_copy_to_user(to, from, n)   copy_to_user(to, from, n)

static inline void *cfs_page_address(cfs_page_t *page)
{
        /*
         * XXX nikita: do NOT call portals_debug_msg() (CDEBUG/ENTRY/EXIT)
         * from here: this will lead to infinite recursion.
         */
        return page_address(page);
}

static inline void *cfs_kmap(cfs_page_t *page)
{
        return kmap(page);
}

static inline void cfs_kunmap(cfs_page_t *page)
{
        kunmap(page);
}

static inline void cfs_get_page(cfs_page_t *page)
{
        get_page(page);
}

static inline int cfs_page_count(cfs_page_t *page)
{
        return page_count(page);
}

#define cfs_page_index(p)       ((p)->index)

#define cfs_page_pin(page) page_cache_get(page)
#define cfs_page_unpin(page) page_cache_release(page)

/*
 * Memory allocator
 * XXX Liang: move these declare to public file
 */
extern void *cfs_alloc(size_t nr_bytes, u_int32_t flags);
extern void  cfs_free(void *addr);

extern void *cfs_alloc_large(size_t nr_bytes);
extern void  cfs_free_large(void *addr);

extern cfs_page_t *cfs_alloc_page(unsigned int flags);
extern void cfs_free_page(cfs_page_t *page);

#define cfs_memory_pressure_get() (current->flags & PF_MEMALLOC)
#define cfs_memory_pressure_set() do { current->flags |= PF_MEMALLOC; } while (0)
#define cfs_memory_pressure_clr() do { current->flags &= ~PF_MEMALLOC; } while (0)

#if BITS_PER_LONG == 32
/* limit to lowmem on 32-bit systems */
#define CFS_NUM_CACHEPAGES \
        min(cfs_num_physpages, 1UL << (30 - CFS_PAGE_SHIFT) * 3 / 4)
#else
#define CFS_NUM_CACHEPAGES cfs_num_physpages
#endif

/*
 * In Linux there is no way to determine whether current execution context is
 * blockable.
 */
#define CFS_ALLOC_ATOMIC_TRY   CFS_ALLOC_ATOMIC

/*
 * SLAB allocator
 * XXX Liang: move these declare to public file
 */
typedef struct kmem_cache cfs_mem_cache_t;
extern cfs_mem_cache_t * cfs_mem_cache_create (const char *, size_t, size_t, unsigned long);
extern int cfs_mem_cache_destroy ( cfs_mem_cache_t * );
extern void *cfs_mem_cache_alloc ( cfs_mem_cache_t *, int);
extern void cfs_mem_cache_free ( cfs_mem_cache_t *, void *);
extern int cfs_mem_is_in_cache(const void *addr, const cfs_mem_cache_t *kmem);

#define CFS_DECL_MMSPACE                mm_segment_t __oldfs
#define CFS_MMSPACE_OPEN \
        do { __oldfs = get_fs(); set_fs(get_ds());} while(0)
#define CFS_MMSPACE_CLOSE               set_fs(__oldfs)

#define CFS_SLAB_HWCACHE_ALIGN          SLAB_HWCACHE_ALIGN
#define CFS_SLAB_KERNEL                 SLAB_KERNEL
#define CFS_SLAB_NOFS                   SLAB_NOFS

/*
 * NUMA allocators
 *
 * NB: we will rename these functions in a separate patch:
 * - rename cfs_alloc to cfs_malloc
 * - rename cfs_alloc/free_page to cfs_page_alloc/free
 * - rename cfs_alloc/free_large to cfs_vmalloc/vfree
 */
extern void *cfs_cpt_malloc(struct cfs_cpt_table *cptab, int cpt,
			    size_t nr_bytes, unsigned int flags);
extern void *cfs_cpt_vmalloc(struct cfs_cpt_table *cptab, int cpt,
			     size_t nr_bytes);
extern cfs_page_t *cfs_page_cpt_alloc(struct cfs_cpt_table *cptab,
				      int cpt, unsigned int flags);
extern void *cfs_mem_cache_cpt_alloc(cfs_mem_cache_t *cachep,
				     struct cfs_cpt_table *cptab,
				     int cpt, unsigned int flags);

/*
 * Shrinker
 */
#define cfs_shrinker    shrinker

#ifdef HAVE_SHRINK_CONTROL
# define SHRINKER_ARGS(sc, nr_to_scan, gfp_mask)  \
                       struct shrinker *shrinker, \
                       struct shrink_control *sc
# define shrink_param(sc, var) ((sc)->var)
#else
# ifdef HAVE_SHRINKER_WANT_SHRINK_PTR
#  define SHRINKER_ARGS(sc, nr_to_scan, gfp_mask)  \
                        struct shrinker *shrinker, \
                        int nr_to_scan, gfp_t gfp_mask
# else
#  define SHRINKER_ARGS(sc, nr_to_scan, gfp_mask)  \
                        int nr_to_scan, gfp_t gfp_mask
# endif
# define shrink_param(sc, var) (var)
#endif

#ifdef HAVE_REGISTER_SHRINKER
typedef int (*cfs_shrinker_t)(SHRINKER_ARGS(sc, nr_to_scan, gfp_mask));

static inline
struct cfs_shrinker *cfs_set_shrinker(int seek, cfs_shrinker_t func)
{
        struct shrinker *s;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
        if (s == NULL)
                return (NULL);

        s->shrink = func;
        s->seeks = seek;

        register_shrinker(s);

        return s;
}

static inline
void cfs_remove_shrinker(struct cfs_shrinker *shrinker)
{
        if (shrinker == NULL)
                return;

        unregister_shrinker(shrinker);
        kfree(shrinker);
}
#else
typedef shrinker_t              cfs_shrinker_t;
#define cfs_set_shrinker(s, f)  set_shrinker(s, f)
#define cfs_remove_shrinker(s)  remove_shrinker(s)
#endif

#define CFS_DEFAULT_SEEKS                 DEFAULT_SEEKS
#endif /* __LINUX_CFS_MEM_H__ */
