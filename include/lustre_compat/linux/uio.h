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

#ifndef HAVE_IOV_ITER_IS_ALIGNED
static inline bool iov_iter_aligned_iovec(const struct iov_iter *i,
					  unsigned addr_mask, unsigned len_mask)
{
	const struct iovec *iov = iter_iov(i);
	size_t size = i->count;
	size_t skip = i->iov_offset;

	do {
		size_t len = iov->iov_len - skip;

		if (len > size)
			len = size;
		if (len & len_mask)
			return false;
		if ((unsigned long)(iov->iov_base + skip) & addr_mask)
			return false;

		iov++;
		size -= len;
		skip = 0;
	} while (size);

	return true;
}

static inline bool iov_iter_is_aligned(const struct iov_iter *i,
				       unsigned addr_mask, unsigned len_mask)
{
	if (likely(iter_is_ubuf(i))) {
		if (i->count & len_mask)
			return false;
		if ((unsigned long)(iter_ubuf(i) + i->iov_offset) & addr_mask)
			return false;
		return true;
	}
	if (likely(iter_is_iovec(i) || iov_iter_is_kvec(i)))
		return iov_iter_aligned_iovec(i, addr_mask, len_mask);

	return true;
}
#endif /* HAVE_IOV_ITER_IS_ALIGNED */

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
