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
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#ifndef _LIBCFS_BITMAP_H_
#define _LIBCFS_BITMAP_H_

#include <linux/interrupt.h>
#include <libcfs/libcfs_private.h>

struct cfs_bitmap {
	unsigned int size;
	unsigned long data[0];
};

#define CFS_BITMAP_SIZE(nbits) \
	(BITS_TO_LONGS(nbits) * sizeof(long) + sizeof(struct cfs_bitmap))

static inline
struct cfs_bitmap *CFS_ALLOCATE_BITMAP(int size)
{
	struct cfs_bitmap *ptr;

	LIBCFS_ALLOC(ptr, CFS_BITMAP_SIZE(size));
	if (ptr == NULL)
		RETURN(ptr);

	ptr->size = size;

	RETURN(ptr);
}

static inline void CFS_RESET_BITMAP(struct cfs_bitmap *bitmap)
{
	if (bitmap->size > 0) {
		int nbits = bitmap->size;

		memset(bitmap, 0, CFS_BITMAP_SIZE(nbits));
		bitmap->size = nbits;
	}
}

#define CFS_FREE_BITMAP(ptr)	LIBCFS_FREE(ptr, CFS_BITMAP_SIZE(ptr->size))

static inline
void cfs_bitmap_set(struct cfs_bitmap *bitmap, int nbit)
{
	set_bit(nbit, bitmap->data);
}

static inline
void cfs_bitmap_clear(struct cfs_bitmap *bitmap, int nbit)
{
	test_and_clear_bit(nbit, bitmap->data);
}

static inline
int cfs_bitmap_check(struct cfs_bitmap *bitmap, int nbit)
{
	return test_bit(nbit, bitmap->data);
}

static inline
int cfs_bitmap_test_and_clear(struct cfs_bitmap *bitmap, int nbit)
{
	return test_and_clear_bit(nbit, bitmap->data);
}

/* return 0 is bitmap has none set bits */
static inline
int cfs_bitmap_check_empty(struct cfs_bitmap *bitmap)
{
	return find_first_bit(bitmap->data, bitmap->size) == bitmap->size;
}

static inline
void cfs_bitmap_copy(struct cfs_bitmap *new, struct cfs_bitmap *old)
{
	size_t newsize;

	LASSERT(new->size >= old->size);
	newsize = new->size;
	memcpy(new, old, CFS_BITMAP_SIZE(old->size));
	new->size = newsize;
}

#define cfs_foreach_bit(bitmap, pos)					\
	for ((pos) = find_first_bit((bitmap)->data, bitmap->size);	\
	     (pos) < (bitmap)->size;					\
	     (pos) = find_next_bit((bitmap)->data, (bitmap)->size, (pos) + 1))

#endif
