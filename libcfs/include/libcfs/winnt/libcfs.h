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

#ifndef __LIBCFS_WINNT_LIBCFS_H__
#define __LIBCFS_WINNT_LIBCFS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

/* workgroud for VC compiler */
#if _MSC_VER <= 1300
#define __FUNCTION__ ("generic")
#endif

#include <config.h>
#include <libcfs/winnt/winnt-types.h>
#include <libcfs/list.h>
#include <libcfs/winnt/winnt-time.h>
#include <libcfs/winnt/winnt-lock.h>
#include <libcfs/winnt/winnt-mem.h>
#include <libcfs/winnt/winnt-prim.h>
#include <libcfs/winnt/winnt-fs.h>
#include <libcfs/winnt/winnt-tcpip.h>
#include <libcfs/winnt/kp30.h>

#ifdef __KERNEL__

enum {
        /* if you change this, update darwin-util.c:cfs_stack_trace_fill() */
        CFS_STACK_TRACE_DEPTH = 16
};

struct cfs_stack_trace {
        void *frame[CFS_STACK_TRACE_DEPTH];
};

static inline __u32 query_stack_size()
{
    ULONG   LowLimit, HighLimit;

    IoGetStackLimits((PULONG_PTR)&LowLimit, (PULONG_PTR)&HighLimit);
    ASSERT(HighLimit > LowLimit);

    return (__u32) (HighLimit - LowLimit);
}

/* disable watchdog */
#undef WITH_WATCHDOG

#else /* !__KERNEL__*/

#include <libcfs/user-bitops.h>

static inline __u32 query_stack_size()
{
   return PAGE_SIZE; /* using one page in default */
}

#endif /* __KERNEL__*/

#ifndef CFS_THREAD_SIZE
# define CFS_THREAD_SIZE query_stack_size()
#endif

#define LUSTRE_TRACE_SIZE (CFS_THREAD_SIZE >> 5)

#ifdef __KERNEL__
#define CDEBUG_STACK() (CFS_THREAD_SIZE - (__u32)IoGetRemainingStackSize())
#define CFS_CHECK_STACK(msgdata, mask, cdls) do {} while(0)
#else /* !__KERNEL__ */
#define CFS_CHECK_STACK(msgdata, mask, cdls) do {} while(0)
#define CDEBUG_STACK() (0L)
#endif /* __KERNEL__ */

/* initial pid  */
#define LUSTRE_LNET_PID          12345

#define ENTRY_NESTING_SUPPORT (0)
#define ENTRY_NESTING   do {} while (0)
#define EXIT_NESTING   do {} while (0)
#define __current_nesting_level() (0)

#endif /* _WINNT_LIBCFS_H */
