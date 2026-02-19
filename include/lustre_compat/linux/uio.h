/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_UIO_H__
#define __LIBCFS_LINUX_UIO_H__

#include <linux/uio.h>

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

#endif /* __LIBCFS_LINUX_UIO_H__ */
