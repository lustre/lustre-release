/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/include/libcfs/user-bitops.h
 *
 * Implementation of portable time API for user-level.
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_USER_BITOPS_H__
#define __LIBCFS_USER_BITOPS_H__

/* test if bit nr is set in bitmap addr; returns previous value of bit nr */
static __inline__ int set_bit(int nr, unsigned long *addr)
{
        unsigned long mask;

        addr += nr / BITS_PER_LONG;
        mask = 1UL << (nr & (BITS_PER_LONG - 1));
        nr = (mask & *addr) != 0;
        *addr |= mask;
        return nr;
}

/* clear bit nr in bitmap addr; returns previous value of bit nr*/
static __inline__ int clear_bit(int nr, unsigned long *addr)
{
        unsigned long mask;

        addr += nr / BITS_PER_LONG;
        mask = 1UL << (nr & (BITS_PER_LONG - 1));
        nr = (mask & *addr) != 0;
        *addr &= ~mask;
        return nr;
}

static __inline__ int test_bit(int nr, const unsigned long *addr)
{
        return ((1UL << (nr & (BITS_PER_LONG - 1))) &
                ((addr)[nr / BITS_PER_LONG])) != 0;
}

/* using binary seach */
static __inline__ unsigned long __fls(long data)
{
	int pos = 32;

	if (!data)
		return 0;

#if BITS_PER_LONG == 64
        pos += 32;

        if ((data & 0xFFFFFFFF) == 0) {
                data <<= 32;
                pos -= 32;
        }
#endif

	if (!(data & 0xFFFF0000u)) {
		data <<= 16;
		pos -= 16;
	}
	if (!(data & 0xFF000000u)) {
		data <<= 8;
		pos -= 8;
	}
	if (!(data & 0xF0000000u)) {
		data <<= 4;
		pos -= 4;
	}
	if (!(data & 0xC0000000u)) {
		data <<= 2;
		pos -= 2;
	}
	if (!(data & 0x80000000u)) {
		data <<= 1;
		pos -= 1;
	}
	return pos;
}

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
#define __flz(x)	__fls(~(x))

unsigned long find_next_bit(unsigned long *addr,
                            unsigned long size, unsigned long offset);

unsigned long find_next_zero_bit(unsigned long *addr,
                                 unsigned long size, unsigned long offset);

#define find_first_bit(addr,size)       (find_next_bit((addr),(size),0))
#define find_first_zero_bit(addr,size)  (find_next_zero_bit((addr),(size),0))

#endif
