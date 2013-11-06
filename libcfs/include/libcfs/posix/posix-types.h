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
 * libcfs/include/libcfs/posix/posix-types.h
 *
 * Define the linux types we use for posix userspace.
 *
 * Author: Robert Read <rread@sun.com>
 */
#ifndef _LUSTRE_POSIX_TYPES_H
#define _LUSTRE_POSIX_TYPES_H

#include <asm/types.h>
#include <stdbool.h> /* for bool */
#ifndef HAVE_UMODE_T
typedef unsigned short umode_t;
#else
#endif

/*
 * __xx is ok: it doesn't pollute the POSIX namespace. Use these in the
 * header files exported to user space
 */

#ifndef HAVE___S8
typedef __signed__ char __s8;
#endif
#ifndef HAVE___U8
typedef unsigned char __u8;
#endif

#ifndef HAVE___S16
typedef __signed__ short __s16;
#endif
#ifndef HAVE___U16
typedef unsigned short __u16;
#endif

#ifndef HAVE___S32
typedef __signed__ int __s32;
#endif
#ifndef HAVE___U32
typedef unsigned int __u32;
#endif

/*
 * The kernel defines user space 64bit values as l64 on powerpc. We must
 * match that definition to avoid conflicting definition compile errors.
 */
#if defined(__powerpc64__) && !defined(__KERNEL__)
# ifndef HAVE___S64
typedef __signed__ long __s64;
# endif
# ifndef HAVE___U64
typedef unsigned long __u64;
# endif
#else /* !defined(__powerpc64__) || defined(__KERNEL__) */
# ifndef HAVE___S64
typedef __signed__ long long __s64;
# endif
# ifndef HAVE___U64
typedef unsigned long long __u64;
# endif
#endif

/* long integer with size equal to pointer */
typedef unsigned long ulong_ptr_t;
typedef long long_ptr_t;

/* Sparse annotations, copied from linux/compiler.h. */
#define __user
#define __kernel
#define __safe
#define __force
#define __nocast
#define __iomem
#define __chk_user_ptr(x) ((void)0)
#define __chk_io_ptr(x) ((void)0)
#define __builtin_warning(x, y...) (1)
#define __acquires(x)
#define __releases(x)
#define __acquire(x) ((void)0)
#define __release(x) ((void)0)
#define __cond_lock(x, c) (c)

typedef unsigned long pgoff_t;

#endif
