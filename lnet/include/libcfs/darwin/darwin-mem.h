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
 * Page of OSX
 *
 * There is no page in OSX, however, we need page in lustre.
 */
#define PAGE_MASK				(~(PAGE_SIZE-1))
#define _ALIGN_UP(addr,size)			(((addr)+((size)-1))&(~((size)-1)))
#define _ALIGN(addr,size)			_ALIGN_UP(addr,size)
#define PAGE_ALIGN(addr)			_ALIGN(addr, PAGE_SIZE)

/*
 * Basic xnu_page struct, should be binary compatibility with
 * all page types in xnu (we have only xnu_raw_page, xll_page now)
 */

/* Variable sized pages are not supported */

#define CFS_PAGE_SHIFT	12
#define CFS_PAGE_SIZE	(1 << CFS_PAGE_SHIFT)
#define PAGE_CACHE_SIZE CFS_PAGE_SIZE
#define CFS_PAGE_MASK	(~(CFS_PAGE_SIZE - 1))

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
	struct xnu_page header;
	vm_address_t    virtual;
	upl_t		upl;
	int		order;
	atomic_t	count;
	void           *private;
};

/*
 * Public interface to lustre
 *
 * - cfs_alloc_pages(f, o)
 * - cfs_alloc_page(f)
 * - cfs_free_pages(p, o)
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

cfs_page_t *cfs_alloc_pages(u_int32_t flags, u_int32_t order);
cfs_page_t *cfs_alloc_page(u_int32_t flags);
void cfs_free_pages(cfs_page_t *pages, int order);
void cfs_free_page(cfs_page_t *page);
void cfs_get_page(cfs_page_t *page);
int cfs_put_page_testzero(cfs_page_t *page);
int cfs_page_count(cfs_page_t *page);
void cfs_set_page_count(cfs_page_t *page, int v);

void *cfs_page_address(cfs_page_t *pg);
void *cfs_kmap(cfs_page_t *pg);
void cfs_kunmap(cfs_page_t *pg);

/*
 * Memory allocator
 */

extern void *cfs_alloc(size_t nr_bytes, u_int32_t flags);
extern void  cfs_free(void *addr);

extern void *cfs_alloc_large(size_t nr_bytes);
extern void  cfs_free_large(void *addr);

/*
 * Slab:
 *
 * No slab in OSX, use zone allocator to fake slab
 */
#define SLAB_HWCACHE_ALIGN		0

typedef struct cfs_mem_cache {
	struct list_head	link;
	zone_t			zone;
	int			size;
	char			name [ZONE_NAME_MAX_LEN];
} cfs_mem_cache_t;

#define KMEM_CACHE_MAX_COUNT	64
#define KMEM_MAX_ZONE		8192

extern cfs_mem_cache_t * cfs_mem_cache_create (const char *, size_t, size_t, unsigned long,
					       void (*)(void *, cfs_mem_cache_t *, unsigned long),
					       void (*)(void *, cfs_mem_cache_t *, unsigned long));
extern int cfs_mem_cache_destroy ( cfs_mem_cache_t * );
extern void *cfs_mem_cache_alloc ( cfs_mem_cache_t *, int);
extern void cfs_mem_cache_free ( cfs_mem_cache_t *, void *);

/*
 * Misc
 */
/* XXX fix me */
#define num_physpages			(64 * 1024)

#define CFS_DECL_MMSPACE		
#define CFS_MMSPACE_OPEN		do {} while(0)
#define CFS_MMSPACE_CLOSE		do {} while(0)

#define copy_from_user(kaddr, uaddr, size)	copyin((caddr_t)uaddr, (caddr_t)kaddr, size)
#define copy_to_user(uaddr, kaddr, size)	copyout((caddr_t)kaddr, (caddr_t)uaddr, size)

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

typedef struct cfs_page{
	void	*foo;
} cfs_page_t;
#endif	/* __KERNEL__ */

#endif	/* __XNU_CFS_MEM_H__ */
