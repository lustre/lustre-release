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

#ifndef HAVE_LIBCFS_CPT
/* Need this for cfs_cpt_table */
#include <libcfs/libcfs_cpu.h>
#endif

#define CFS_PAGE_MASK                   (~((__u64)PAGE_CACHE_SIZE-1))

#define page_index(p)       ((p)->index)


#define memory_pressure_get() (current->flags & PF_MEMALLOC)
#define memory_pressure_set() do { current->flags |= PF_MEMALLOC; } while (0)
#define memory_pressure_clr() do { current->flags &= ~PF_MEMALLOC; } while (0)

#if BITS_PER_LONG == 32
/* limit to lowmem on 32-bit systems */
#define NUM_CACHEPAGES \
	min(totalram_pages, 1UL << (30 - PAGE_CACHE_SHIFT) * 3 / 4)
#else
#define NUM_CACHEPAGES totalram_pages
#endif

/*
 * In Linux there is no way to determine whether current execution context is
 * blockable.
 */
#define ALLOC_ATOMIC_TRY   GFP_ATOMIC
/* GFP_IOFS was added in 2.6.33 kernel */
#ifndef GFP_IOFS
#define GFP_IOFS       (__GFP_IO | __GFP_FS)
#endif

#define DECL_MMSPACE                mm_segment_t __oldfs
#define MMSPACE_OPEN \
        do { __oldfs = get_fs(); set_fs(get_ds());} while(0)
#define MMSPACE_CLOSE               set_fs(__oldfs)


extern void *cfs_cpt_malloc(struct cfs_cpt_table *cptab, int cpt,
			    size_t nr_bytes, gfp_t flags);
extern void *cfs_cpt_vzalloc(struct cfs_cpt_table *cptab, int cpt,
			     size_t nr_bytes);
extern struct page *cfs_page_cpt_alloc(struct cfs_cpt_table *cptab,
				      int cpt, gfp_t flags);
extern void *cfs_mem_cache_cpt_alloc(struct kmem_cache *cachep,
				     struct cfs_cpt_table *cptab,
				     int cpt, gfp_t flags);

/*
 * Shrinker
 */
#ifdef HAVE_SHRINK_CONTROL
# define SHRINKER_ARGS(sc, nr_to_scan, gfp_mask)  \
                       struct shrinker *shrinker, \
                       struct shrink_control *sc
# define shrink_param(sc, var) ((sc)->var)
#else
struct shrink_control {
	gfp_t gfp_mask;
	unsigned long nr_to_scan;
};
# ifdef HAVE_SHRINKER_WANT_SHRINK_PTR
#  define SHRINKER_ARGS(sc, nr_to_scan, gfp_mask)  \
                        struct shrinker *shrinker, \
                        int nr_to_scan, gfp_t gfp_mask
# else
#  define SHRINKER_ARGS(sc, nr_to_scan, gfp_mask)  \
                        int nr_to_scan, gfp_t gfp_mask
# endif
	/* avoid conflict with spl mm_compat.h */
# define HAVE_SHRINK_CONTROL_STRUCT 1
# define shrink_param(sc, var) (var)
#endif

#ifdef HAVE_SHRINKER_COUNT
struct shrinker_var {
	unsigned long (*count)(struct shrinker *,
			       struct shrink_control *sc);
	unsigned long (*scan)(struct shrinker *,
			      struct shrink_control *sc);
};
# define DEF_SHRINKER_VAR(name, shrink, count_obj, scan_obj) \
	    struct shrinker_var name = { .count = count_obj, .scan = scan_obj }
#else
struct shrinker_var {
	int (*shrink)(SHRINKER_ARGS(sc, nr_to_scan, gfp_mask));
};
# define DEF_SHRINKER_VAR(name, shrinker, count, scan) \
	    struct shrinker_var name = { .shrink = shrinker }
# define SHRINK_STOP (~0UL)
#endif

static inline
struct shrinker *set_shrinker(int seek, struct shrinker_var *var)
{
        struct shrinker *s;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
        if (s == NULL)
                return (NULL);

#ifdef HAVE_SHRINKER_COUNT
	s->count_objects = var->count;
	s->scan_objects = var->scan;
#else
	s->shrink = var->shrink;
#endif
        s->seeks = seek;

        register_shrinker(s);

        return s;
}

static inline
void remove_shrinker(struct shrinker *shrinker)
{
        if (shrinker == NULL)
                return;

        unregister_shrinker(shrinker);
        kfree(shrinker);
}

#endif /* __LINUX_CFS_MEM_H__ */
