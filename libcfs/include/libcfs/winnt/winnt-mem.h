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
 *
 * libcfs/include/libcfs/winnt/winnt-mem.h
 *
 * Basic library routines of memory manipulation routines.
 */

#ifndef __LIBCFS_WINNT_CFS_MEM_H__
#define __LIBCFS_WINNT_CFS_MEM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#include <libcfs/winnt/portals_utils.h>

#ifdef __KERNEL__

/*
 * page definitions
 */

#define PAGE_CACHE_SIZE                   PAGE_SIZE
#define PAGE_CACHE_SHIFT                  PAGE_SHIFT
#define CFS_PAGE_MASK                   (~(PAGE_SIZE - 1))

#define memory_pressure_get() (0)
#define memory_pressure_set() do {} while (0)
#define memory_pressure_clr() do {} while (0)

struct page {
    void *          addr;
    atomic_t    count;
    void *          private;
    void *          mapping;
    __u32           index;
    __u32           flags;
};

#define page cfs_page

#ifndef page_private
#define page_private(page) ((page)->private)
#define set_page_private(page, v) ((page)->private = (v))
#endif

#define page_count(page) (0)

#define PG_locked	 	 0	/* Page is locked. Don't touch. */
#define PG_error		 1
#define PG_referenced		 2
#define PG_uptodate		 3

#define PG_dirty	 	 4
#define PG_lru			 5
#define PG_active		 6
#define PG_slab			 7	/* slab debug (Suparna wants this) */

#define PG_owner_priv_1		 8	/* Owner use. If pagecache, fs may use*/
#define PG_arch_1		 9
#define PG_reserved		10
#define PG_private		11	/* If pagecache, has fs-private data */

#define PG_writeback		12	/* Page is under writeback */
#define PG_compound		14	/* Part of a compound page */
#define PG_swapcache		15	/* Swap page: swp_entry_t in private */

#define PG_mappedtodisk		16	/* Has blocks allocated on-disk */
#define PG_reclaim		17	/* To be reclaimed asap */
#define PG_buddy		19	/* Page is free, on buddy lists */

#define PG_virt         31  /* addr is not */

#ifndef arch_set_page_uptodate
#define arch_set_page_uptodate(page)
#endif

/* Make it prettier to test the above... */
#define UnlockPage(page)        unlock_page(page)
#define Page_Uptodate(page)     test_bit(PG_uptodate, &(page)->flags)
#define SetPageUptodate(page)						\
	do {								\
		arch_set_page_uptodate(page);				\
		set_bit(PG_uptodate, &(page)->flags);			\
	} while (0)
#define ClearPageUptodate(page) clear_bit(PG_uptodate, &(page)->flags)
#define PageDirty(page)	test_bit(PG_dirty, &(page)->flags)
#define SetPageDirty(page)	set_bit(PG_dirty, &(page)->flags)
#define ClearPageDirty(page)	clear_bit(PG_dirty, &(page)->flags)
#define PageLocked(page)	test_bit(PG_locked, &(page)->flags)
#define LockPage(page)		set_bit(PG_locked, &(page)->flags)
#define TryLockPage(page)	test_and_set_bit(PG_locked, &(page)->flags)
#define PageChecked(page)	test_bit(PG_checked, &(page)->flags)
#define SetPageChecked(page)	set_bit(PG_checked, &(page)->flags)
#define ClearPageChecked(page)	clear_bit(PG_checked, &(page)->flags)
#define PageLaunder(page)	test_bit(PG_launder, &(page)->flags)
#define SetPageLaunder(page)	set_bit(PG_launder, &(page)->flags)
#define ClearPageLaunder(page)	clear_bit(PG_launder, &(page)->flags)
#define ClearPageArch1(page)	clear_bit(PG_arch_1, &(page)->flags)

#define PageError(page)	test_bit(PG_error, &(page)->flags)
#define SetPageError(page)	set_bit(PG_error, &(page)->flags)
#define ClearPageError(page)	clear_bit(PG_error, &(page)->flags)
#define PageReferenced(page)	test_bit(PG_referenced, &(page)->flags)
#define SetPageReferenced(page) set_bit(PG_referenced, &(page)->flags)
#define ClearPageReferenced(page) clear_bit(PG_referenced, &(page)->flags)

#define PageActive(page)        test_bit(PG_active, &(page)->flags)
#define SetPageActive(page)     set_bit(PG_active, &(page)->flags)
#define ClearPageActive(page)   clear_bit(PG_active, &(page)->flags)

#define PageWriteback(page)	test_bit(PG_writeback, &(page)->flags)
#define TestSetPageWriteback(page) test_and_set_bit(PG_writeback,	\
							&(page)->flags)
#define TestClearPageWriteback(page) test_and_clear_bit(PG_writeback,	\
							&(page)->flags)

/*
 * Universal memory allocator API
 */
enum cfs_alloc_flags {
	/* allocation is not allowed to block */
	GFP_ATOMIC = 0x1,
	/* allocation is allowed to block */
	__GFP_WAIT   = 0x2,
	/* allocation should return zeroed memory */
	__GFP_ZERO   = 0x4,
	/* allocation is allowed to call file-system code to free/clean
	 * memory */
	__GFP_FS     = 0x8,
	/* allocation is allowed to do io to free/clean memory */
	__GFP_IO     = 0x10,
	/* don't report allocation failure to the console */
	__GFP_NOWARN = 0x20,
	/* standard allocator flag combination */
	GFP_IOFS    = __GFP_FS | __GFP_IO,
	GFP_USER   = __GFP_WAIT | __GFP_FS | __GFP_IO,
	GFP_NOFS   = __GFP_WAIT | __GFP_IO,
	GFP_KERNEL = __GFP_WAIT | __GFP_IO | __GFP_FS,
};

/* flags for cfs_page_alloc() in addition to enum cfs_alloc_flags */
enum cfs_alloc_page_flags {
	/* allow to return page beyond KVM. It has to be mapped into KVM by
	 * kmap() and unmapped with kunmap(). */
	__GFP_HIGHMEM  = 0x40,
	GFP_HIGHUSER = __GFP_WAIT | __GFP_FS | __GFP_IO |
			     __GFP_HIGHMEM,
};

struct page *alloc_page(int flags);
void __free_page(struct page *pg);
void cfs_release_page(struct page *pg);
struct page *virt_to_page(void *addr);

#define page_cache_get(a) do {} while (0)
#define page_cache_release(a) do {} while (0)

static inline void *page_address(struct page *page)
{
    return page->addr;
}

static inline void *kmap(struct page *page)
{
    return page->addr;
}

static inline void kunmap(struct page *page)
{
    return;
}

static inline void get_page(struct page *page)
{
    atomic_inc(&page->count);
}

static inline void cfs_put_page(struct page *page)
{
    atomic_dec(&page->count);
}

static inline int page_count(struct page *page)
{
    return atomic_read(&page->count);
}

#define page_index(p)       ((p)->index)

/*
 * Memory allocator
 */

#define ALLOC_ATOMIC_TRY	(0)
extern void *kmalloc(size_t nr_bytes, u_int32_t flags);
extern void  kfree(void *addr);
extern void *vmalloc(size_t nr_bytes);
extern void  vfree(void *addr);

/*
 * SLAB allocator
 */

#define SLAB_HWCACHE_ALIGN		0

/* The cache name is limited to 20 chars */

struct kmem_cache {
    char                    name[20];
    ulong_ptr_t             flags;
    NPAGED_LOOKASIDE_LIST   npll;
};


extern struct kmem_cache *kmem_cache_create(const char *, size_t, size_t,
					    unsigned long, void *);
extern kmem_cache_destroy(struct kmem_cache *);
extern void *kmem_cache_alloc(struct kmem_cache *, int);
extern void kmem_cache_free(struct kmem_cache *, void *);

/*
 * shrinker
 */
typedef int (*shrink_callback)(int nr_to_scan, gfp_t gfp_mask);
struct shrinker {
	shrink_callback cb;
	int seeks;	/* seeks to recreate an obj */

	/* These are for internal use */
	struct list_head list;
	long nr;	/* objs pending delete */
};

struct shrinker *set_shrinker(int seeks, shrink_callback cb);
void remove_shrinker(struct shrinker *s);

int start_shrinker_timer();
void stop_shrinker_timer();

/*
 * Page allocator slabs
 */

extern struct kmem_cache *cfs_page_t_slab;
extern struct kmem_cache *cfs_page_p_slab;


#define DECL_MMSPACE
#define MMSPACE_OPEN    do {} while (0)
#define MMSPACE_CLOSE   do {} while (0)


#define smp_mb()     do {} while(0)
#define rmb()        smp_mb()
#define wmb()        smp_mb()

/*
 * MM defintions from (linux/mm.h)
 */

#define DEFAULT_SEEKS 2 /* shrink seek */

#else  /* !__KERNEL__ */

#include "../user-mem.h"

/* page alignmed buffer allocation */
void* pgalloc(size_t factor);
void  pgfree(void * page);

#endif /* __KERNEL__ */

#endif /* __WINNT_CFS_MEM_H__ */
