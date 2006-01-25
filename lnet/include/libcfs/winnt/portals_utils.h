/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
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

#ifndef __LIBCFS_WINNT_PORTALS_UTILS_H__
#define __LIBCFS_WINNT_PORTALS_UTILS_H__

#ifndef __LIBCFS_PORTALS_UTILS_H__
#error Do not #include this file directly. #include <libcfs/portals_utils.h> instead
#endif

#ifndef cfs_is_flag_set
#define cfs_is_flag_set(x,f) (((x)&(f))==(f))
#endif

#ifndef cfs_set_flag
#define cfs_set_flag(x,f)    ((x) |= (f))
#endif

#ifndef cfs_clear_flag
#define cfs_clear_flag(x,f)  ((x) &= ~(f))
#endif


static inline __u32 __do_div(__u32 * n, __u32 b) 
{
    __u32   mod;

    mod = *n % b;
    *n  = *n / b;
    return mod;
} 

#define do_div(n,base)  __do_div((__u32 *)&(n), (__u32) (base))

#ifdef __KERNEL__

#include <stdlib.h>
#include <libcfs/winnt/winnt-types.h>

char * strsep(char **s, const char *ct);
static inline size_t strnlen(const char * s, size_t count) {
    size_t len = 0;
    while(len < count && s[len++]);
    return len;
}
char * ul2dstr(ulong_ptr address, char *buf, int len);

#define simple_strtol(a1, a2, a3)               strtol(a1, a2, a3)
#define simple_strtoll(a1, a2, a3)              (__s64)strtoull(a1, a2, a3)
#define simple_strtoull(a1, a2, a3)             strtoull(a1, a2, a3)

unsigned long simple_strtoul(const char *cp,char **endp, unsigned int base);

static inline int test_bit(int nr, void * addr)
{
    return ((1UL << (nr & 31)) & (((volatile ULONG *) addr)[nr >> 5])) != 0;
}

static inline void clear_bit(int nr, void * addr)
{
    (((volatile ULONG *) addr)[nr >> 5]) &= (~(1UL << (nr & 31)));
}


static inline void set_bit(int nr, void * addr)
{
    (((volatile ULONG *) addr)[nr >> 5]) |= (1UL << (nr & 31));
}

static inline void read_random(char *buf, int len)
{
    ULONG   Seed = (ULONG) buf;
    Seed = RtlRandom(&Seed);
    while (len >0) {
        if (len > sizeof(ULONG)) {
            memcpy(buf, &Seed, sizeof(ULONG));
            len -= sizeof(ULONG);
            buf += sizeof(ULONG);
        } else {
            memcpy(buf, &Seed, len);
            len = 0;
            break;
        } 
    }
}
#define get_random_bytes(buf, len)  read_random(buf, len)

/* do NOT use function or expression as parameters ... */

#ifndef min_t
#define min_t(type,x,y) (type)(x) < (type)(y) ? (x): (y)
#endif

#ifndef max_t
#define max_t(type,x,y) (type)(x) < (type)(y) ? (y): (x)
#endif


#define NIPQUAD(addr)			    \
	((unsigned char *)&addr)[0],	\
	((unsigned char *)&addr)[1],	\
	((unsigned char *)&addr)[2],	\
	((unsigned char *)&addr)[3]

#define HIPQUAD(addr)			    \
	((unsigned char *)&addr)[3],	\
	((unsigned char *)&addr)[2],	\
	((unsigned char *)&addr)[1],	\
	((unsigned char *)&addr)[0]

static int copy_from_user(void *to, void *from, int c) 
{
    memcpy(to, from, c);
    return 0;
}

static int copy_to_user(void *to, void *from, int c) 
{
    memcpy(to, from, c);
    return 0;
}


#define put_user(x, ptr)        \
(                               \
    *(ptr) = x,                 \
    0                           \
)


#define get_user(x,ptr)         \
(                               \
    x = *(ptr),                 \
    0                           \
)

#define num_physpages			(64 * 1024)

#define snprintf  _snprintf
#define vsnprintf _vsnprintf


#endif	/* !__KERNEL__ */

int cfs_error_code(NTSTATUS);

#endif
