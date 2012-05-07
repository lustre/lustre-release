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
 */

#ifndef __LIBCFS_DARWIN_CFS_MEM_H__
#define __LIBCFS_DARWIN_CFS_MEM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__

#include <sys/types.h>
#include <sys/systm.h>

#include <sys/vm.h>
#include <sys/kernel.h>
#include <sys/ubc.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/lockf.h>

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <mach/machine/vm_param.h>
#include <kern/thread_call.h>
#include <sys/param.h>
#include <sys/vm.h>

#include <libcfs/darwin/darwin-types.h>
#include <libcfs/darwin/darwin-sync.h>
#include <libcfs/darwin/darwin-lock.h>
#include <libcfs/list.h>

/*
 * Basic xnu_page struct, should be binary compatibility with
 * all page types in xnu (we have only xnu_raw_page, xll_page now)
 */

/* Variable sized pages are not supported */

#ifdef PAGE_SHIFT
#define CFS_PAGE_SHIFT	PAGE_SHIFT
#else
#define CFS_PAGE_SHIFT	12
#endif

#define CFS_PAGE_SIZE	(1UL << CFS_PAGE_SHIFT)

#define CFS_PAGE_MASK	(~((__u64)CFS_PAGE_SIZE - 1))

enum {
	XNU_PAGE_RAW,
	XNU_PAGE_XLL,
	XNU_PAGE_NTYPES
};

typedef __u32 page_off_t;

/*
 * For XNU we have our own page cache built on top of underlying BSD/MACH
 * infrastructure. In particular, we have two disjoint types of pages:
 *
 *    - "raw" pages (XNU_PAGE_RAW): these are just buffers mapped into KVM,
 *    based on UPLs, and
 *
 *    - "xll" pages (XNU_PAGE_XLL): these are used by file system to cache
 *    file data, owned by file system objects, hashed, lrued, etc.
 *
 * cfs_page_t has to cover both of them, because core Lustre code is based on
 * the Linux assumption that page is _both_ memory buffer and file system
 * caching entity.
 *
 * To achieve this, all types of pages supported on XNU has to start from
 * common header that contains only "page type". Common cfs_page_t operations
 * dispatch through operation vector based on page type.
 *
 */
typedef struct xnu_page {
	int type;
} cfs_page_t;

struct xnu_page_ops {
	void *(*page_map)        (cfs_page_t *);
	void  (*page_unmap)      (cfs_page_t *);
	void *(*page_address)    (cfs_page_t *);
};

void xnu_page_ops_register(int type, struct xnu_page_ops *ops);
void xnu_page_ops_unregister(int type);

/*
 * raw page, no cache object, just like buffer
 */
struct xnu_raw_page {
	struct xnu_page  header;
	void            *virtual;
	atomic_t         count;
	struct list_head link;
};

/*
 * Public interface to lustre
 *
 * - cfs_alloc_page(f)
 * - cfs_free_page(p)
 * - cfs_kmap(p)
 * - cfs_kunmap(p)
 * - cfs_page_address(p)
 */

/*
 * Of all functions above only cfs_kmap(), cfs_kunmap(), and
 * cfs_page_address() can be called on file system pages. The rest is for raw
 * pages only.
 */

cfs_page_t *cfs_alloc_page(u_int32_t flags);
void cfs_free_page(cfs_page_t *page);
void cfs_get_page(cfs_page_t *page);
int cfs_put_page_testzero(cfs_page_t *page);
int cfs_page_count(cfs_page_t *page);
#define cfs_page_index(pg)	(0)

void *cfs_page_address(cfs_page_t *pg);
void *cfs_kmap(cfs_page_t *pg);
void cfs_kunmap(cfs_page_t *pg);

/*
 * Memory allocator
 */

void *cfs_alloc(size_t nr_bytes, u_int32_t flags);
void  cfs_free(void *addr);

void *cfs_alloc_large(size_t nr_bytes);
void  cfs_free_large(void *addr);

extern int get_preemption_level(void);

#define CFS_ALLOC_ATOMIC_TRY                                    \
	(get_preemption_level() != 0 ? CFS_ALLOC_ATOMIC : 0)

/*
 * Slab:
 *
 * No slab in OSX, use zone allocator to simulate slab
 */
#define SLAB_HWCACHE_ALIGN		0

#ifdef __DARWIN8__
/* 
 * In Darwin8, we cannot use zalloc_noblock(not exported by kernel),
 * also, direct using of zone allocator is not recommended.
 */
#define CFS_INDIVIDUAL_ZONE     (0)

#if !CFS_INDIVIDUAL_ZONE
#include <libkern/OSMalloc.h>
typedef 	OSMallocTag	mem_cache_t;
#else
typedef		void*		zone_t;
typedef		zone_t		mem_cache_t;
#endif

#else /* !__DARWIN8__ */

#define CFS_INDIVIDUAL_ZONE     (1)

typedef 	zone_t		mem_cache_t;

#endif /* !__DARWIN8__ */

#define MC_NAME_MAX_LEN		64

typedef struct cfs_mem_cache {
	int			mc_size;
	mem_cache_t		mc_cache;
	struct list_head	mc_link;
	char			mc_name [MC_NAME_MAX_LEN];
} cfs_mem_cache_t;

#define KMEM_CACHE_MAX_COUNT	64
#define KMEM_MAX_ZONE		8192

cfs_mem_cache_t * cfs_mem_cache_create (const char *, size_t, size_t, unsigned long);
int cfs_mem_cache_destroy ( cfs_mem_cache_t * );
void *cfs_mem_cache_alloc ( cfs_mem_cache_t *, int);
void cfs_mem_cache_free ( cfs_mem_cache_t *, void *);

/*
 * Misc
 */
/* XXX Liang: num_physpages... fix me */
#define num_physpages			(64 * 1024)
#define CFS_NUM_CACHEPAGES		num_physpages

#define CFS_DECL_MMSPACE		
#define CFS_MMSPACE_OPEN		do {} while(0)
#define CFS_MMSPACE_CLOSE		do {} while(0)

#define copy_from_user(kaddr, uaddr, size)	copyin(CAST_USER_ADDR_T(uaddr), (caddr_t)kaddr, size)
#define copy_to_user(uaddr, kaddr, size)	copyout((caddr_t)kaddr, CAST_USER_ADDR_T(uaddr), size)

#if 0
static inline int strncpy_from_user(char *kaddr, char *uaddr, int size)
{
	size_t count;
	return copyinstr((const user_addr_t)uaddr, (void *)kaddr, size, &count);
}
#endif

#if defined (__ppc__)
#define mb()  __asm__ __volatile__ ("sync" : : : "memory")
#define rmb()  __asm__ __volatile__ ("sync" : : : "memory")
#define wmb()  __asm__ __volatile__ ("eieio" : : : "memory")
#elif defined (__i386__)
#define mb()    __asm__ __volatile__ ("lock; addl $0,0(%%esp)": : :"memory")
#define rmb()   mb()
#define wmb()   __asm__ __volatile__ ("": : :"memory")
#else
#error architecture not supported
#endif

#else	/* !__KERNEL__ */

#define CFS_CACHE_SHIFT 12
#define PAGE_CACHE_SIZE (1 << CFS_CACHE_SHIFT)
#include <libcfs/user-prim.h>

#endif	/* __KERNEL__ */

#endif	/* __XNU_CFS_MEM_H__ */
