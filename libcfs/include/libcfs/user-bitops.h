/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 * Author: Nikita Danilov <nikita@clusterfs.com>
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or modify it under the
 * terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * Lustre is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with Lustre; if not, write to the Free Software Foundation, Inc., 675 Mass
 * Ave, Cambridge, MA 02139, USA.
 *
 * Implementation of portable time API for user-level.
 *
 */

#ifndef __LIBCFS_USER_BITOPS_H__
#define __LIBCFS_USER_BITOPS_H__

/* test if bit nr is set in bitmap addr; returns previous value of bit nr */
static __inline__ int set_bit(int nr, unsigned long * addr)
{
        long    mask;

        addr += nr / BITS_PER_LONG;
        mask = 1UL << (nr & (BITS_PER_LONG - 1));
        nr = (mask & *addr) != 0;
        *addr |= mask;
        return nr;
}

/* clear bit nr in bitmap addr; returns previous value of bit nr*/
static __inline__ int clear_bit(int nr, unsigned long * addr)
{
        long    mask;

        addr += nr / BITS_PER_LONG;
        mask = 1UL << (nr & (BITS_PER_LONG - 1));
        nr = (mask & *addr) != 0;
        *addr &= ~mask;
        return nr;
}

static __inline__ int test_bit(int nr, const unsigned long * addr)
{
        return ((1UL << (nr & (BITS_PER_LONG - 1))) & ((addr)[nr / BITS_PER_LONG])) != 0;
}

/* using binary seach */
static __inline__ unsigned long __ffs(long data)
{
        int pos = 0;

#if BITS_PER_LONG == 64
        if ((data & 0xFFFFFFFF) == 0) {
                pos += 32;
                data >>= 32;
        }
#endif
        if ((data & 0xFFFF) == 0) {
                pos += 16;
                data >>= 16;
        }
        if ((data & 0xFF) == 0) {
                pos += 8;
                data >>= 8;
        }
        if ((data & 0xF) == 0) {
                pos += 4;
                data >>= 4;
        }
        if ((data & 0x3) == 0) {
                pos += 2;
                data >>= 2;
        }
        if ((data & 0x1) == 0)
                pos += 1;

        return pos;
}

#define __ffz(x)	__ffs(~(x))

unsigned long find_next_bit(unsigned long *addr,
                            unsigned long size, unsigned long offset);

unsigned long find_next_zero_bit(unsigned long *addr,
                                 unsigned long size, unsigned long offset);

#define find_first_bit(addr,size)       (find_next_bit((addr),(size),0))
#define find_first_zero_bit(addr,size)  (find_next_zero_bit((addr),(size),0))

#endif
