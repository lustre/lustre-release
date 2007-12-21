/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2007 Cluster File Systems, Inc.
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
 */
#ifndef __KERNEL__

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>
#include <libcfs/user-bitops.h>

#define OFF_BY_START(start)     ((start)/BITS_PER_LONG)

unsigned long find_next_bit(unsigned long *addr,
                            unsigned long size, unsigned long offset)
{
        unsigned long *word, *last;
        unsigned long first_bit, bit, base;

        word = addr + OFF_BY_START(offset);
        last = addr + OFF_BY_START(size-1);
        first_bit = offset % BITS_PER_LONG;
        base = offset - first_bit;

        if (offset >= size)
                return size;
        if (first_bit != 0) {
                int tmp = (*word++) & (~0UL << first_bit);
                bit = __ffs(tmp);
                if (bit < BITS_PER_LONG)
                        goto found;
                word++;
                base += BITS_PER_LONG;
        }
        while (word <= last) {
                if (*word != 0UL) {
                        bit = __ffs(*word);
                        goto found;
                }
                word++;
                base += BITS_PER_LONG;
        }
        return size;
found:
        return base + bit;
}

unsigned long find_next_zero_bit(unsigned long *addr,
                                 unsigned long size, unsigned long offset)
{
        unsigned long *word, *last;
        unsigned long first_bit, bit, base;

        word = addr + OFF_BY_START(offset);
        last = addr + OFF_BY_START(size-1);
        first_bit = offset % BITS_PER_LONG;
        base = offset - first_bit;

        if (offset >= size)
                return size;
        if (first_bit != 0) {
                int tmp = (*word++) & (~0UL << first_bit);
                bit = __ffz(tmp);
                if (bit < BITS_PER_LONG)
                        goto found;
                word++;
                base += BITS_PER_LONG;
        }
        while (word <= last) {
                if (*word != ~0UL) {
                        bit = __ffz(*word);
                        goto found;
                }
                word++;
                base += BITS_PER_LONG;
        }
        return size;
found:
        return base + bit;
}

#endif
