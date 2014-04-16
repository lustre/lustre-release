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
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/winnt/portals_utils.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_WINNT_PORTALS_UTILS_H__
#define __LIBCFS_WINNT_PORTALS_UTILS_H__

#ifndef cfs_is_flag_set
#define cfs_is_flag_set(x,f) (((x)&(f))==(f))
#endif

#ifndef cfs_set_flag
#define cfs_set_flag(x,f)    ((x) |= (f))
#endif

#ifndef cfs_clear_flag
#define cfs_clear_flag(x,f)  ((x) &= ~(f))
#endif

static inline __u32 do_div64(__u64 * n, __u64 b) 
{
    __u64   mod;

    mod = *n % b;
    *n  = *n / b;
    return (__u32)mod;
} 

#define do_div(n, b) do_div64(&(n), (__u64)b)
#ifdef __KERNEL__

#include <stdlib.h>
#include <libcfs/winnt/winnt-types.h>

char * strsep(char **s, const char *ct);
char * ul2dstr(ulong_ptr_t address, char *buf, int len);

#define simple_strtol(a1, a2, a3)               strtol(a1, a2, a3)
#define simple_strtoll(a1, a2, a3)              (__s64)strtoull(a1, a2, a3)
#define simple_strtoull(a1, a2, a3)             strtoull(a1, a2, a3)

unsigned long simple_strtoul(const char *cp,char **endp, unsigned int base);

static inline int set_bit(int nr, void * addr)
{
    (((volatile ULONG *) addr)[nr >> 5]) |= (1UL << (nr & 31));
    return *((int *) addr);
}

static inline int test_bit(int nr, void * addr)
{
    return (int)(((1UL << (nr & 31)) & (((volatile ULONG *) addr)[nr >> 5])) != 0);
}

static inline int clear_bit(int nr, void * addr)
{
    (((volatile ULONG *) addr)[nr >> 5]) &= (~(1UL << (nr & 31)));
    return *((int *) addr);
}

static inline int test_and_set_bit(int nr, volatile void *addr)
{
    int rc;
    unsigned char  mask;
    volatile unsigned char *ADDR = addr;

    ADDR += nr >> 3;
    mask = 1 << (nr & 0x07);
    rc = ((mask & *ADDR) != 0);
    *ADDR |= mask;

    return rc;
}

#define ext2_set_bit(nr, addr)		(set_bit(nr, addr), 0)
#define ext2_clear_bit(nr, addr)	(clear_bit(nr, addr), 0)
#define ext2_test_bit(nr, addr)		test_bit(nr, addr)

static inline int ffs(int x)
{
        int r = 1;

        if (!x)
                return 0;
        if (!(x & 0xffff)) {
                x >>= 16;
                r += 16;
        }
        if (!(x & 0xff)) {
                x >>= 8;
                r += 8;
        }
        if (!(x & 0xf)) {
                x >>= 4;
                r += 4;
        }
        if (!(x & 3)) {
                x >>= 2;
                r += 2;
        }
        if (!(x & 1)) {
                x >>= 1;
                r += 1;
        }
        return r;
}

static inline unsigned long __cfs_ffs(unsigned long word)
{
        int num = 0;

#if BITS_PER_LONG == 64
        if ((word & 0xffffffff) == 0) {
                num += 32;
                word >>= 32;
        }
#endif
        if ((word & 0xffff) == 0) {
                num += 16;
                word >>= 16;
        }
        if ((word & 0xff) == 0) {
                num += 8;
                word >>= 8;
        }
        if ((word & 0xf) == 0) {
                num += 4;
                word >>= 4;
        }
        if ((word & 0x3) == 0) {
                num += 2;
                word >>= 2;
        }
        if ((word & 0x1) == 0)
                num += 1;
        return num;
}

/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
static inline
int fls(int x)
{
        int r = 32;

        if (!x)
                return 0;
        if (!(x & 0xffff0000u)) {
                x <<= 16;
                r -= 16;
        }
        if (!(x & 0xff000000u)) {
                x <<= 8;
                r -= 8;
        }
        if (!(x & 0xf0000000u)) {
                x <<= 4;
                r -= 4;
        }
        if (!(x & 0xc0000000u)) {
                x <<= 2;
                r -= 2;
        }
        if (!(x & 0x80000000u)) {
                x <<= 1;
                r -= 1;
        }
        return r;
}

static inline unsigned find_first_bit(const unsigned long *addr,
                                          unsigned size)
{
        unsigned x = 0;

        while (x < size) {
                unsigned long val = *addr++;
                if (val)
                        return __cfs_ffs(val) + x;
                x += (sizeof(*addr)<<3);
        }
        return x;
}

static inline void read_random(char *buf, int len)
{
    ULONG   Seed = (ULONG)(ULONG_PTR) buf;
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

static int copy_to_user(void *to, const void *from, int c)
{
	memcpy(to, from, c);
	return 0;
}

static unsigned long
clear_user(void __user *to, unsigned long n)
{
    memset(to, 0, n);
	return n;
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

#define totalram_pages               (64 * 1024)
#define NUM_CACHEPAGES              totalram_pages

#else

#define unlink _unlink 
#define close  _close
#define open   _open
#define fdopen _fdopen
#define strdup _strdup
#define fileno _fileno
#define isattry _isattry
#define stat    _stat

#endif	/* !__KERNEL__ */

int cfs_error_code(NTSTATUS);

static inline int vsnprintf(char *buf, size_t cnt,
                            const char *fmt, va_list va)
{
    int rc;

#ifdef TRUE /* using msvcrt from windkk 3790 */
    rc = _vsnprintf(buf, cnt, fmt, va);
#else
    rc = _vsnprintf_s(buf, cnt, cnt, fmt, va);
#endif
    if (rc == -1)
        return cnt;
    return rc;
}

static inline int snprintf(char *buf, size_t cnt, 
                           const char *fmt, ...)
{
    int         rc;
    va_list     va;

    va_start(va, fmt);
    rc = vsnprintf(buf, cnt, fmt, va);
    va_end(va);
    return rc;
}

#endif
