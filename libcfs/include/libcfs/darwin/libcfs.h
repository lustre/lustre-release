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
 */

#ifndef __LIBCFS_DARWIN_LIBCFS_H__
#define __LIBCFS_DARWIN_LIBCFS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#include <mach/mach_types.h>
#include <sys/errno.h>
#include <string.h>
#include <libcfs/darwin/darwin-types.h>
#include <libcfs/darwin/darwin-time.h>
#include <libcfs/darwin/darwin-prim.h>
#include <libcfs/darwin/darwin-mem.h>
#include <libcfs/darwin/darwin-lock.h>
#include <libcfs/darwin/darwin-fs.h>
#include <libcfs/darwin/darwin-tcpip.h>
#include <libcfs/darwin/kp30.h>

#ifdef __KERNEL__
# include <sys/types.h>
# include <sys/time.h>
# define do_gettimeofday(tv) microuptime(tv)
#else
# include <sys/time.h>
# define do_gettimeofday(tv) gettimeofday(tv, NULL);
typedef unsigned long long cycles_t;
#endif

#define __cpu_to_le64(x)                        OSSwapHostToLittleInt64(x)
#define __cpu_to_le32(x)                        OSSwapHostToLittleInt32(x)
#define __cpu_to_le16(x)                        OSSwapHostToLittleInt16(x)

#define __le16_to_cpu(x)                        OSSwapLittleToHostInt16(x)
#define __le32_to_cpu(x)                        OSSwapLittleToHostInt32(x)
#define __le64_to_cpu(x)                        OSSwapLittleToHostInt64(x)

#define cpu_to_le64(x)                          __cpu_to_le64(x)
#define cpu_to_le32(x)                          __cpu_to_le32(x)
#define cpu_to_le16(x)                          __cpu_to_le16(x)

#define le64_to_cpu(x)                          __le64_to_cpu(x)
#define le32_to_cpu(x)                          __le32_to_cpu(x)
#define le16_to_cpu(x)                          __le16_to_cpu(x)

#define __swab16(x)                             OSSwapInt16(x)
#define __swab32(x)                             OSSwapInt32(x)
#define __swab64(x)                             OSSwapInt64(x)
#define __swab16s(x)                            do { *(x) = __swab16(*(x)); } while (0)
#define __swab32s(x)                            do { *(x) = __swab32(*(x)); } while (0)
#define __swab64s(x)                            do { *(x) = __swab64(*(x)); } while (0)


#ifdef __KERNEL__
# include <sys/systm.h>
# include <pexpert/pexpert.h>
/* Fix me */
# define THREAD_SIZE 8192
#else
# define THREAD_SIZE 8192
#endif
#define LUSTRE_TRACE_SIZE (THREAD_SIZE >> 5)

#define CHECK_STACK(msgdata, mask, cdls) do {} while(0)
#define CDEBUG_STACK() (0L)

/* Darwin has defined RETURN, so we have to undef it in lustre */
#ifdef RETURN
#undef RETURN
#endif

/*
 * When this is enabled debugging messages are indented according to the
 * current "nesting level". Nesting level in increased when ENTRY macro
 * is executed, and decreased on EXIT and RETURN.
 */
#ifdef __KERNEL__
#define ENTRY_NESTING_SUPPORT (0)
#endif

#if ENTRY_NESTING_SUPPORT

/*
 * Currently ENTRY_NESTING_SUPPORT is only supported for XNU port. Basic
 * idea is to keep per-thread pointer to small data structure (struct
 * cfs_debug_data) describing current nesting level. In XNU unused
 * proc->p_wmegs field in hijacked for this. On Linux
 * current->journal_info can be used. In user space
 * pthread_{g,s}etspecific().
 *
 * ENTRY macro allocates new cfs_debug_data on stack, and installs it as
 * a current nesting level, storing old data in cfs_debug_data it just
 * created.
 *
 * EXIT pops old value back.
 *
 */

/*
 * One problem with this approach is that there is a lot of code that
 * does ENTRY and then escapes scope without doing EXIT/RETURN. In this
 * case per-thread current nesting level pointer is dangling (it points
 * to the stack area that is possible already overridden). To detect
 * such cases, we add two magic fields to the cfs_debug_data and check
 * them whenever current nesting level pointer is dereferenced. While
 * looking flaky this works because stack is always consumed
 * "continously".
 */
enum {
        CDD_MAGIC1 = 0x02128506,
        CDD_MAGIC2 = 0x42424242
};

struct cfs_debug_data {
        unsigned int           magic1;
        struct cfs_debug_data *parent;
        int                    nesting_level;
        unsigned int           magic2;
};

void __entry_nesting(struct cfs_debug_data *child);
void __exit_nesting(struct cfs_debug_data *child);
unsigned int __current_nesting_level(void);

#define ENTRY_NESTING                                           \
struct cfs_debug_data __cdd = { .magic1        = CDD_MAGIC1,    \
                                .parent        = NULL,          \
                                .nesting_level = 0,             \
                                .magic2        = CDD_MAGIC2 };  \
__entry_nesting(&__cdd);

#define EXIT_NESTING __exit_nesting(&__cdd)

/* ENTRY_NESTING_SUPPORT */
#else

#define ENTRY_NESTING   do {;} while (0)
#define EXIT_NESTING   do {;} while (0)
#define __current_nesting_level() (0)

/* ENTRY_NESTING_SUPPORT */
#endif

#define LUSTRE_LNET_PID          12345

#define _XNU_LIBCFS_H

/*
 * Platform specific declarations for cfs_curproc API (libcfs/curproc.h)
 *
 * Implementation is in darwin-curproc.c
 */
#define CFS_CURPROC_COMM_MAX    MAXCOMLEN
/*
 * XNU has no capabilities
 */
typedef __u32 cfs_kernel_cap_t;

#ifdef __KERNEL__
enum {
        /* if you change this, update darwin-util.c:cfs_stack_trace_fill() */
        CFS_STACK_TRACE_DEPTH = 16
};

struct cfs_stack_trace {
        void *frame[CFS_STACK_TRACE_DEPTH];
};

#define printk(format, args...)                 printf(format, ## args)

#ifdef WITH_WATCHDOG
#undef WITH_WATCHDOG
#endif

#endif /* __KERNEL__ */

#endif /* _XNU_LIBCFS_H */
