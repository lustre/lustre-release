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
#ifndef _LIBCFS_BITMAP_H_
#define _LIBCFS_BITMAP_H_


typedef struct {
        int             size;
        unsigned long   data[0];
} cfs_bitmap_t;

#define CFS_BITMAP_SIZE(nbits) \
     (((nbits/BITS_PER_LONG)+1)*sizeof(long)+sizeof(cfs_bitmap_t))

static inline
cfs_bitmap_t *CFS_ALLOCATE_BITMAP(int size)
{
        cfs_bitmap_t *ptr;

        OBD_ALLOC(ptr, CFS_BITMAP_SIZE(size));
        if (ptr == NULL)
                RETURN(ptr);

        ptr->size = size;

        RETURN (ptr);
}

#define CFS_FREE_BITMAP(ptr)        OBD_FREE(ptr, CFS_BITMAP_SIZE(ptr->size))

static inline
void cfs_bitmap_set(cfs_bitmap_t *bitmap, int nbit)
{
        cfs_set_bit(nbit, bitmap->data);
}

static inline
void cfs_bitmap_clear(cfs_bitmap_t *bitmap, int nbit)
{
        cfs_test_and_clear_bit(nbit, bitmap->data);
}

static inline
int cfs_bitmap_check(cfs_bitmap_t *bitmap, int nbit)
{
        return cfs_test_bit(nbit, bitmap->data);
}

static inline
int cfs_bitmap_test_and_clear(cfs_bitmap_t *bitmap, int nbit)
{
        return cfs_test_and_clear_bit(nbit, bitmap->data);
}

/* return 0 is bitmap has none set bits */
static inline
int cfs_bitmap_check_empty(cfs_bitmap_t *bitmap)
{
        return cfs_find_first_bit(bitmap->data, bitmap->size) == bitmap->size;
}

#define cfs_foreach_bit(bitmap, pos) \
	for((pos)=cfs_find_first_bit((bitmap)->data, bitmap->size);   \
            (pos) < (bitmap)->size;                               \
            (pos) = cfs_find_next_bit((bitmap)->data, (bitmap)->size, (pos)))

#endif
