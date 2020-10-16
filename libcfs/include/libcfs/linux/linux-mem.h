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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
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

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#ifdef HAVE_MM_INLINE
# include <linux/mm_inline.h>
#endif
#include <linux/sched.h>
#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/mm.h>
#endif

#ifdef HAVE_TOTALRAM_PAGES_AS_FUNC
 #ifndef cfs_totalram_pages
  #define cfs_totalram_pages() totalram_pages()
 #endif
#else
 #ifndef cfs_totalram_pages
  #define cfs_totalram_pages() totalram_pages
 #endif
#endif

#ifndef HAVE_MEMALLOC_RECLAIM
static inline unsigned int memalloc_noreclaim_save(void)
{
	unsigned int flags = current->flags & PF_MEMALLOC;

	current->flags |= PF_MEMALLOC;
	return flags;
}

static inline void memalloc_noreclaim_restore(unsigned int flags)
{
	current->flags = (current->flags & ~PF_MEMALLOC) | flags;
}
#endif /* !HAVE_MEMALLOC_RECLAIM */

#ifndef HAVE_BITMAP_ALLOC
static inline unsigned long *bitmap_alloc(unsigned int nbits, gfp_t flags)
{
	return kmalloc_array(BITS_TO_LONGS(nbits), sizeof(unsigned long),
			     flags);
}

static inline unsigned long *bitmap_zalloc(unsigned int nbits, gfp_t flags)
{
	return bitmap_alloc(nbits, flags | __GFP_ZERO);
}

static inline void bitmap_free(const unsigned long *bitmap)
{
	kfree(bitmap);
}
#endif /* !HAVE_BITMAP_ALLOC */

/*
 * Shrinker
 */
# define SHRINKER_ARGS(sc, nr_to_scan, gfp_mask)  \
                       struct shrinker *shrinker, \
                       struct shrink_control *sc
# define shrink_param(sc, var) ((sc)->var)

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

#ifndef HAVE_MMAP_LOCK
static inline void mmap_write_lock(struct mm_struct *mm)
{
	down_write(&mm->mmap_sem);
}

static inline bool mmap_write_trylock(struct mm_struct *mm)
{
	return down_write_trylock(&mm->mmap_sem) != 0;
}

static inline void mmap_write_unlock(struct mm_struct *mm)
{
	up_write(&mm->mmap_sem);
}

static inline void mmap_read_lock(struct mm_struct *mm)
{
	down_read(&mm->mmap_sem);
}

static inline bool mmap_read_trylock(struct mm_struct *mm)
{
	return down_read_trylock(&mm->mmap_sem) != 0;
}

static inline void mmap_read_unlock(struct mm_struct *mm)
{
	up_read(&mm->mmap_sem);
}
#endif

#endif /* __LINUX_CFS_MEM_H__ */
