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

typedef struct cfs_mem_cache cfs_mem_cache_t;

/*
 * page definitions
 */

#define CFS_PAGE_SIZE                   PAGE_SIZE
#define CFS_PAGE_SHIFT                  PAGE_SHIFT
#define CFS_PAGE_MASK                   (~(PAGE_SIZE - 1))

typedef struct cfs_page {
    void *          addr;
    cfs_atomic_t    count;
    void *          private;
    void *          mapping;
    __u32           index;
    __u32           flags;
} cfs_page_t;

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

#define __GFP_FS    (1)
#define GFP_KERNEL  (2)
#define GFP_ATOMIC  (4)

cfs_page_t *cfs_alloc_page(int flags);
void cfs_free_page(cfs_page_t *pg);
void cfs_release_page(cfs_page_t *pg);
cfs_page_t * virt_to_page(void * addr);
int cfs_mem_is_in_cache(const void *addr, const cfs_mem_cache_t *kmem);

#define page_cache_get(a) do {} while (0)
#define page_cache_release(a) do {} while (0)

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
    cfs_atomic_inc(&page->count);
}

static inline void cfs_put_page(cfs_page_t *page)
{
    cfs_atomic_dec(&page->count);
}

static inline int cfs_page_count(cfs_page_t *page)
{
    return cfs_atomic_read(&page->count);
}

#define cfs_page_index(p)       ((p)->index)

/*
 * Memory allocator
 */

#define CFS_ALLOC_ATOMIC_TRY	(0)
extern void *cfs_alloc(size_t nr_bytes, u_int32_t flags);
extern void  cfs_free(void *addr);

#define kmalloc cfs_alloc

extern void *cfs_alloc_large(size_t nr_bytes);
extern void  cfs_free_large(void *addr);

/*
 * SLAB allocator
 */

#define CFS_SLAB_HWCACHE_ALIGN		0

/* The cache name is limited to 20 chars */

struct cfs_mem_cache {
    char                    name[20];
    ulong_ptr_t             flags;
    NPAGED_LOOKASIDE_LIST   npll;
};


extern cfs_mem_cache_t *cfs_mem_cache_create (const char *, size_t, size_t,
                                              unsigned long);
extern int cfs_mem_cache_destroy (cfs_mem_cache_t * );
extern void *cfs_mem_cache_alloc (cfs_mem_cache_t *, int);
extern void cfs_mem_cache_free (cfs_mem_cache_t *, void *);

/*
 * shrinker 
 */
typedef int (*shrink_callback)(int nr_to_scan, gfp_t gfp_mask);
struct cfs_shrinker {
        shrink_callback cb;
	int seeks;	/* seeks to recreate an obj */

	/* These are for internal use */
	cfs_list_t list;
	long nr;	/* objs pending delete */
};

struct cfs_shrinker *cfs_set_shrinker(int seeks, shrink_callback cb);
void cfs_remove_shrinker(struct cfs_shrinker *s);

int start_shrinker_timer();
void stop_shrinker_timer();

/*
 * Page allocator slabs 
 */

extern cfs_mem_cache_t *cfs_page_t_slab;
extern cfs_mem_cache_t *cfs_page_p_slab;


#define CFS_DECL_MMSPACE
#define CFS_MMSPACE_OPEN    do {} while(0)
#define CFS_MMSPACE_CLOSE   do {} while(0)


#define cfs_mb()     do {} while(0)
#define rmb()        cfs_mb()
#define wmb()        cfs_mb()

/*
 * MM defintions from (linux/mm.h)
 */

#define CFS_DEFAULT_SEEKS 2 /* shrink seek */

#else  /* !__KERNEL__ */

#include "../user-mem.h"

/* page alignmed buffer allocation */
void* pgalloc(size_t factor);
void  pgfree(void * page);

#endif /* __KERNEL__ */

#endif /* __WINNT_CFS_MEM_H__ */
