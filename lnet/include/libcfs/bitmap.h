/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2007 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#ifndef _LIBCFS_BITMAP_H_
#define _LIBCFS_BITMAP_H_


typedef struct {
        int             size;
        unsigned long   data[0];
} bitmap_t;

#define CFS_BITMAP_SIZE(nbits) \
     (((nbits/BITS_PER_LONG)+1)*sizeof(long)+sizeof(bitmap_t))

static inline
bitmap_t *ALLOCATE_BITMAP(int size)
{
        bitmap_t *ptr;

        OBD_ALLOC(ptr, CFS_BITMAP_SIZE(size));
        if (ptr == NULL)
                RETURN(ptr);

        ptr->size = size;

        RETURN (ptr);
}

#define FREE_BITMAP(ptr)        OBD_FREE(ptr, CFS_BITMAP_SIZE(ptr->size))

static inline
void cfs_bitmap_set(bitmap_t *bitmap, int nbit)
{
	set_bit(nbit, bitmap->data);
}

static inline
void cfs_bitmap_clear(bitmap_t *bitmap, int nbit)
{
        clear_bit(nbit, bitmap->data);
}

static inline
int cfs_bitmap_check(bitmap_t *bitmap, int nbit)
{
	return test_bit(nbit, bitmap->data);
}

/* return 0 is bitmap has none set bits */
static inline
int cfs_bitmap_check_empty(bitmap_t *bitmap)
{
        return find_first_bit(bitmap->data, bitmap->size) == bitmap->size;
}

#define cfs_foreach_bit(bitmap, pos) \
	for((pos)=find_first_bit((bitmap)->data, bitmap->size);   \
            (pos) < (bitmap)->size;                               \
            (pos) = find_next_bit((bitmap)->data, (bitmap)->size, (pos)))

#endif
