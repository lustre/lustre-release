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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
#ifndef _LIBCFS_TYPES_H
#define _LIBCFS_TYPES_H

#include <linux/types.h>

#ifndef __KERNEL__
# include <limits.h> /* LONG_MAX */
# include <stdbool.h> /* bool */
#endif /* !__KERNEL__ */

#if defined(_ASM_GENERIC_INT_L64_H)
# define LPF64 "l"
#elif defined(_ASM_GENERIC_INT_LL64_H)
# define LPF64 "ll"
#elif !defined(LPF64)
# error "cannot define LPF64"
#endif /* !LPF64 */

#define LPU64 "%"LPF64"u"
#define LPD64 "%"LPF64"d"
#define LPX64 "%#"LPF64"x"
#define LPX64i "%"LPF64"x"
#define LPO64 "%#"LPF64"o"

#define LPLU "%lu"
#define LPLD "%ld"
#define LPLX "%#lx"
#define LPPID "%d"

#ifndef BITS_PER_LONG
# if LONG_MAX == 9223372036854775807
#  define BITS_PER_LONG 64
# elif LONG_MAX == 2147483647
#  define BITS_PER_LONG 32
# else /* LONG_MAX == 2147483647 */
#  error "cannot define BITS_PER_LONG"
# endif /* LONG_MAX != 2147483647 */
#endif /* !BITS_PER_LONG */

#if BITS_PER_LONG == 64
# define LI_POISON ((int)0x5a5a5a5a5a5a5a5a)
# define LL_POISON ((long)0x5a5a5a5a5a5a5a5a)
# define LP_POISON ((void *)(long)0x5a5a5a5a5a5a5a5a)
#elif BITS_PER_LONG == 32
# define LI_POISON ((int)0x5a5a5a5a)
# define LL_POISON ((long)0x5a5a5a5a)
# define LP_POISON ((void *)(long)0x5a5a5a5a)
#else /* BITS_PER_LONG == 32 */
# error "cannot define L{I,L,P}_POISON"
#endif /* BITS_PER_LONG != 32 */

typedef unsigned long ulong_ptr_t;
typedef long long_ptr_t;

#endif /* _LIBCFS_TYPES_H */
