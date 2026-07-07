/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_UIO_H__
#define __LIBCFS_LINUX_UIO_H__

#include <linux/uio.h>
#include <linux/mm.h>

/*
 * Since 4.20 commit 00e23707442a75b404392cef1405ab4fd498de6b
 * iov_iter: Use accessor functions to access an iterator's type and direction.
 * iter_is_iovec() and iov_iter_is_* are available, supply the missing
 * functionality for older kernels.
 */
#ifndef HAVE_ENUM_ITER_PIPE
#define iov_iter_is_pipe(iter)	0
#endif

#ifdef HAVE_USER_BACKED_ITER
#define iter_ubuf(iter)			((iter)->ubuf)
#else
#define iter_is_ubuf(iter)		0
#define user_backed_iter(iter)		iter_is_iovec(iter)
#define iter_ubuf(iter)			(0ul) /* unused */
#endif /* HAVE_USER_BACKED_ITER */

#if !defined HAVE_IOV_ITER_GET_PAGES_ALLOC2
static inline ssize_t iov_iter_get_pages_alloc2(struct iov_iter *i,
						   struct page ***pages,
						   size_t maxsize,
						   size_t *start)
{
	ssize_t result = 0;

	/* iov_iter_get_pages_alloc is non advancing version of alloc2 */
	result = iov_iter_get_pages_alloc(i, pages, maxsize, start);
	if (result > 0 && user_backed_iter(i))
		iov_iter_advance(i, result);

	return result;
}
#endif

/*
 * ll_iov_iter_extract_pages - Wrapper for page extraction from iterator.
 *
 * iov_iter_extract_pages() (introduced in Linux 6.3) has different pinning
 * semantics based on the iterator type:
 * - For user-backed iterators (ITER_IOVEC, ITER_UBUF), it pins the pages.
 *   These must be released using unpin_user_page().
 * - For kernel-backed iterators (ITER_KVEC, ITER_BVEC, etc.), it returns the
 *   pages without taking a reference. No release is required.
 *
 * For older kernels, we fall back to iov_iter_get_pages_alloc2(), which
 * always pins the pages for user-backed iterators (needing put_page() to
 * release). The @flags argument is intentionally discarded on older kernels,
 * cleanly degrading any P2P DMA requests to standard get_user_pages()
 * extraction.
 *
 * Lustre tracks whether pages are pinned using 'cdp_pinned' (which is set
 * based on `iov_iter_extract_will_pin()`) and releases them using
 * `ll_release_page()`, which wraps `unpin_user_page()` to unpin the pages.
 */
#ifndef HAVE_IOV_ITER_EXTRACT_PAGES
#define ITER_ALLOW_P2PDMA 0
#endif

#ifdef HAVE_IOV_ITER_EXTRACT_PAGES
static inline ssize_t ll_iov_iter_extract_pages(struct iov_iter *i,
						struct page ***pages,
						size_t maxsize,
						unsigned int maxpages,
						iov_iter_extraction_t flags,
						size_t *start)
{
	return iov_iter_extract_pages(i, pages, maxsize, maxpages,
				      flags, start);
}
#else
static inline ssize_t ll_iov_iter_extract_pages(struct iov_iter *i,
						struct page ***pages,
						size_t maxsize,
						unsigned int maxpages,
						unsigned int flags,
						size_t *start)
{
	return iov_iter_get_pages_alloc2(i, pages, maxsize, start);
}
#endif

static inline void ll_release_page(struct page *page, bool pinned)
{
#ifdef HAVE_IOV_ITER_EXTRACT_PAGES
	if (pinned)
		unpin_user_page(page);
#else
	put_page(page);
#endif
}

#endif /* __LIBCFS_LINUX_UIO_H__ */
