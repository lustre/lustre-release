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

#ifndef _PORTALS_LIB_H
#define _PORTALS_LIB_H

#ifndef __KERNEL__
# include <string.h>
#else 
# include <asm/types.h>
#endif

#undef MIN
#define MIN(a,b) (((a)<(b)) ? (a): (b))
#undef MAX
#define MAX(a,b) (((a)>(b)) ? (a): (b))
#define MKSTR(ptr) ((ptr))? (ptr) : ""

static inline int size_round (int val)
{
        return (val + 7) & (~0x7);
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

#ifdef __KERNEL__
static inline char *strdup(const char *str)
{
        int len = strlen(str) + 1;
        char *tmp = kmalloc(len, GFP_KERNEL);
        if (tmp)
                memcpy(tmp, str, len);

        return tmp;
}
#endif

#ifdef __KERNEL__
# define NTOH__u32(var) le32_to_cpu(var)
# define NTOH__u64(var) le64_to_cpu(var)
# define HTON__u32(var) cpu_to_le32(var)
# define HTON__u64(var) cpu_to_le64(var)
#else
# define expansion_u64(var) \
    ({  __u64 ret; \
       switch (sizeof(var)) {   \
       case 8: (ret) = (var); break; \
       case 4: (ret) = (__u32)(var); break; \
       case 2: (ret) = (__u16)(var); break; \
       case 1: (ret) = (__u8)(var); break; \
       };       \
       (ret);     \
    })
# define NTOH__u32(var) (var)
# define NTOH__u64(var) (expansion_u64(var))
# define HTON__u32(var) (var)
# define HTON__u64(var) (expansion_u64(var))
#endif

/* 
 * copy sizeof(type) bytes from pointer to var and move ptr forward.
 * return EFAULT if pointer goes beyond end
 */
#define UNLOGV(var,type,ptr,end)                \
do {                                            \
        var = *(type *)ptr;                     \
        ptr += sizeof(type);                    \
        if (ptr > end )                         \
                return -EFAULT;                 \
} while (0)

/* the following two macros convert to little endian */
/* type MUST be __u32 or __u64 */
#define LUNLOGV(var,type,ptr,end)               \
do {                                            \
        var = NTOH##type(*(type *)ptr);         \
        ptr += sizeof(type);                    \
        if (ptr > end )                         \
                return -EFAULT;                 \
} while (0)

/* now log values */
#define LOGV(var,type,ptr)                      \
do {                                            \
        *((type *)ptr) = var;                   \
        ptr += sizeof(type);                    \
} while (0)

/* and in network order */
#define LLOGV(var,type,ptr)                     \
do {                                            \
        *((type *)ptr) = HTON##type(var);       \
        ptr += sizeof(type);                    \
} while (0)


/* 
 * set var to point at (type *)ptr, move ptr forward with sizeof(type)
 * return from function with EFAULT if ptr goes beyond end
 */
#define UNLOGP(var,type,ptr,end)                \
do {                                            \
        var = (type *)ptr;                      \
        ptr += sizeof(type);                    \
        if (ptr > end )                         \
                return -EFAULT;                 \
} while (0)

#define LOGP(var,type,ptr)                      \
do {                                            \
        memcpy(ptr, var, sizeof(type));         \
        ptr += sizeof(type);                    \
} while (0)

/* 
 * set var to point at (char *)ptr, move ptr forward by size_round(len);
 * return from function with EFAULT if ptr goes beyond end
 */
#define UNLOGL(var,type,len,ptr,end)            \
do {                                            \
        var = (type *)ptr;                      \
        ptr += size_round(len * sizeof(type));  \
        if (ptr > end )                         \
                return -EFAULT;                 \
} while (0)

#define UNLOGL0(var,type,len,ptr,end)                                   \
do {                                                                    \
        UNLOGL(var,type,len,ptr,end);                                   \
        if ( *((char *)ptr - size_round(len) + len - 1) != '\0')        \
                return -EFAULT;                                         \
} while (0)

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
