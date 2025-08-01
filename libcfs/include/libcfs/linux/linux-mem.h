/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
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

unsigned long cfs_totalram_pages(void);

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
#ifndef SHRINK_STOP
# define SHRINK_STOP (~0UL)
#endif

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
#else
 #ifndef HAVE_MMAP_WRITE_TRYLOCK
/* Replacement for mmap_write_trylock() */
static inline bool mmap_write_trylock(struct mm_struct *mm)
{
	return down_write_trylock(&mm->mmap_lock) != 0;
}
 #endif /* HAVE_MMAP_WRITE_TRYLOCK */
#endif

#ifdef HAVE_VMALLOC_2ARGS
#define __ll_vmalloc(size, flags) __vmalloc(size, flags)
#else
#define __ll_vmalloc(size, flags) __vmalloc(size, flags, PAGE_KERNEL)
#endif

void init_libcfs_vfree_atomic(void);
void exit_libcfs_vfree_atomic(void);

/* atomic-context safe vfree */
void libcfs_vfree_atomic(const void *addr);

#ifndef HAVE_KFREE_SENSITIVE
#define kfree_sensitive(x)      kzfree(x)
#endif

#endif /* __LINUX_CFS_MEM_H__ */
