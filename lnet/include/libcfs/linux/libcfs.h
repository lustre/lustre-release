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
 */

#ifndef __LIBCFS_LINUX_LIBCFS_H__
#define __LIBCFS_LINUX_LIBCFS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#else
#include <libcfs/types.h>
#endif

#include <stdarg.h>
#include <libcfs/linux/linux-time.h>
#include <libcfs/linux/linux-mem.h>
#include <libcfs/linux/linux-prim.h>
#include <libcfs/linux/linux-lock.h>
#include <libcfs/linux/linux-fs.h>
#include <libcfs/linux/linux-tcpip.h>


#ifdef __KERNEL__
# include <linux/types.h>
# include <linux/time.h>
# include <asm/timex.h>
#else
# include <sys/types.h>
# include <sys/time.h>
# define do_gettimeofday(tv) gettimeofday(tv, NULL);
typedef unsigned long long cycles_t;
#endif

#ifndef __KERNEL__
/* Userpace byte flipping */
# include <endian.h>
# include <byteswap.h>
# define __swab16(x) bswap_16(x)
# define __swab32(x) bswap_32(x)
# define __swab64(x) bswap_64(x)
# define __swab16s(x) do {*(x) = bswap_16(*(x));} while (0)
# define __swab32s(x) do {*(x) = bswap_32(*(x));} while (0)
# define __swab64s(x) do {*(x) = bswap_64(*(x));} while (0)
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define le16_to_cpu(x) (x)
#  define cpu_to_le16(x) (x)
#  define le32_to_cpu(x) (x)
#  define cpu_to_le32(x) (x)
#  define le64_to_cpu(x) (x)
#  define cpu_to_le64(x) (x)

#  define be16_to_cpu(x) bswap_16(x)
#  define cpu_to_be16(x) bswap_16(x)
#  define be32_to_cpu(x) bswap_32(x)
#  define cpu_to_be32(x) bswap_32(x)
#  define be64_to_cpu(x) bswap_64(x)
#  define cpu_to_be64(x) bswap_64(x)

# else
#  if __BYTE_ORDER == __BIG_ENDIAN
#   define le16_to_cpu(x) bswap_16(x)
#   define cpu_to_le16(x) bswap_16(x)
#   define le32_to_cpu(x) bswap_32(x)
#   define cpu_to_le32(x) bswap_32(x)
#   define le64_to_cpu(x) bswap_64(x)
#   define cpu_to_le64(x) bswap_64(x)

#   define be16_to_cpu(x) (x)
#   define cpu_to_be16(x) (x)
#   define be32_to_cpu(x) (x)
#   define cpu_to_be32(x) (x)
#   define be64_to_cpu(x) (x)
#   define cpu_to_be64(x) (x)

#  else
#   error "Unknown byte order"
#  endif /* __BIG_ENDIAN */
# endif /* __LITTLE_ENDIAN */
#endif /* ! __KERNEL__ */

struct ptldebug_header {
        __u32 ph_len;
        __u32 ph_flags;
        __u32 ph_subsys;
        __u32 ph_mask;
        __u32 ph_cpu_id;
        __u32 ph_sec;
        __u64 ph_usec;
        __u32 ph_stack;
        __u32 ph_pid;
        __u32 ph_extern_pid;
        __u32 ph_line_num;
} __attribute__((packed));

#ifdef __KERNEL__
# include <linux/sched.h> /* THREAD_SIZE */
#else
# ifndef THREAD_SIZE /* x86_64 has THREAD_SIZE in userspace */
#  define THREAD_SIZE 8192
# endif
#endif

#define LUSTRE_TRACE_SIZE (THREAD_SIZE >> 5)

#if defined(__KERNEL__) && !defined(__x86_64__)
# ifdef  __ia64__
#  define CDEBUG_STACK() (THREAD_SIZE -                                 \
                          ((unsigned long)__builtin_dwarf_cfa() &       \
                           (THREAD_SIZE - 1)))
# else
#  define CDEBUG_STACK() (THREAD_SIZE -                                 \
                          ((unsigned long)__builtin_frame_address(0) &  \
                           (THREAD_SIZE - 1)))
# endif /* __ia64__ */

#define __CHECK_STACK(file, func, line)                                 \
do {                                                                    \
        unsigned long _stack = CDEBUG_STACK();                          \
                                                                        \
        if (_stack > 3*THREAD_SIZE/4 && _stack > libcfs_stack) {        \
                libcfs_stack = _stack;                                  \
                libcfs_debug_msg(NULL, DEBUG_SUBSYSTEM, D_WARNING,      \
                                 file, func, line,                      \
                                 "maximum lustre stack %lu\n", _stack); \
              /*panic("LBUG");*/                                        \
        }                                                               \
} while (0)
#define CHECK_STACK()     __CHECK_STACK(__FILE__, __func__, __LINE__)
#else /* !__KERNEL__ */
#define __CHECK_STACK(X, Y, Z) do { } while(0)
#define CHECK_STACK() do { } while(0)
#define CDEBUG_STACK() (0L)
#endif /* __KERNEL__ */

/* initial pid  */
#define LUSTRE_LNET_PID          12345

#define ENTRY_NESTING_SUPPORT (1)
#define ENTRY_NESTING   do {;} while (0)
#define EXIT_NESTING   do {;} while (0)
#define __current_nesting_level() (0)

/*
 * Platform specific declarations for cfs_curproc API (libcfs/curproc.h)
 *
 * Implementation is in linux-curproc.c
 */
#define CFS_CURPROC_COMM_MAX (sizeof ((struct task_struct *)0)->comm)

#if defined(__KERNEL__)
#include <linux/capability.h>
typedef kernel_cap_t cfs_kernel_cap_t;
#else
typedef __u32 cfs_kernel_cap_t;
#endif

#if defined(__KERNEL__)
/*
 * No stack-back-tracing in Linux for now.
 */
struct cfs_stack_trace {
};

#ifndef WITH_WATCHDOG
#define WITH_WATCHDOG
#endif

#endif

#endif /* _LINUX_LIBCFS_H */
