/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 * Basic library routines. 
 *
 */

#ifndef __LIBCFS_PORTALS_LIB_H__
#define __LIBCFS_PORTALS_LIB_H__

#if defined(__linux__)
#include <libcfs/linux/portals_lib.h>
#elif defined(__APPLE__)
#include <libcfs/darwin/portals_lib.h>
#else
#error Unsupported Operating System
#endif

#undef MIN
#define MIN(a,b) (((a)<(b)) ? (a): (b))
#undef MAX
#define MAX(a,b) (((a)>(b)) ? (a): (b))
#define MKSTR(ptr) ((ptr))? (ptr) : ""

static inline int size_round4 (int val)
{
        return (val + 3) & (~0x3);
}

static inline int size_round (int val)
{
        return (val + 7) & (~0x7);
}

static inline int size_round16(int val)
{
        return (val + 0xf) & (~0xf);
}

static inline int size_round32(int val)
{
        return (val + 0x1f) & (~0x1f);
}

static inline int size_round0(int val)
{
        if (!val)
                return 0;
        return (val + 1 + 7) & (~0x7);
}

static inline size_t round_strlen(char *fset)
{
        return size_round(strlen(fset) + 1);
}

#define LOGL(var,len,ptr)                                       \
do {                                                            \
        if (var)                                                \
                memcpy((char *)ptr, (const char *)var, len);    \
        ptr += size_round(len);                                 \
} while (0)

#define LOGU(var,len,ptr)                                       \
do {                                                            \
        if (var)                                                \
                memcpy((char *)var, (const char *)ptr, len);    \
        ptr += size_round(len);                                 \
} while (0)

#define LOGL0(var,len,ptr)                              \
do {                                                    \
        if (!len)                                       \
                break;                                  \
        memcpy((char *)ptr, (const char *)var, len);    \
        *((char *)(ptr) + len) = 0;                     \
        ptr += size_round(len + 1);                     \
} while (0)

#endif /* _PORTALS_LIB_H */
