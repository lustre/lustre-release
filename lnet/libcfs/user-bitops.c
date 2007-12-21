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

#include <string.h> /* for ffs - confirm POSIX */

#define BITS_PER_WORD           32
#define OFF_BY_START(start)     ((start)/BITS_PER_WORD)

unsigned long find_next_bit(const unsigned int *addr,
                unsigned long size, unsigned long offset)
{
        uint32_t *word, *last;
        unsigned int first_bit, bit, base;

        word = addr + OFF_BY_START(offset);
        last = addr + OFF_BY_START(size-1);
        first_bit = offset % BITS_PER_WORD;
        base = offset - first_bit;

        if (offset >= size)
                return size;
        if (first_bit != 0) {
                int tmp = (*word++) & (~0UL << first_bit);
                bit = ffs(tmp);
                if (bit < BITS_PER_WORD)
                        goto found;
                word++;
                base += BITS_PER_WORD;
        }
        while (word <= last) {
                if (*word != 0ul) {
                        bit = ffs(*word);
                        goto found;
                }
                word++;
                base += BITS_PER_WORD;
        }
        return size;
found:
        return base + bit;
}

unsigned long find_next_zero_bit(const unsigned int *addr,
                unsigned long size, unsigned long offset)
{
        uint32_t *word, *last;
        unsigned int first_bit, bit, base;

        word = addr + OFF_BY_START(offset);
        last = addr + OFF_BY_START(size-1);
        first_bit = offset % BITS_PER_WORD;
        base = offset - first_bit;

        if (offset >= size)
                return size;
        if (first_bit != 0) {
                int tmp = (*word++) & (~0UL << first_bit);
                bit = ffs(~tmp);
                if (bit < BITS_PER_WORD)
                        goto found;
                word++;
                base += BITS_PER_WORD;
        }
        while (word <= last) {
                if (*word != ~0ul) {
                        bit = ffs(*word);
                        goto found;
                }
                word++;
                base += BITS_PER_WORD;
        }
        return size;
found:
        return base + bit;
}

#endif
