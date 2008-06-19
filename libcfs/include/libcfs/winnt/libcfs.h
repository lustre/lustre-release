/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
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

#ifndef __LIBCFS_WINNT_LIBCFS_H__
#define __LIBCFS_WINNT_LIBCFS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

/* workgroud for VC compiler */
#ifndef __FUNCTION__
#define __FUNCTION__ "generic"
#endif

#include <libcfs/winnt/winnt-types.h>
#include <libcfs/portals_utils.h>
#include <libcfs/winnt/winnt-time.h>
#include <libcfs/winnt/winnt-lock.h>
#include <libcfs/winnt/winnt-mem.h>
#include <libcfs/winnt/winnt-prim.h>
#include <libcfs/winnt/winnt-fs.h>
#include <libcfs/winnt/winnt-tcpip.h>

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

    IoGetStackLimits(&LowLimit, &HighLimit);
    ASSERT(HighLimit > LowLimit);

    return (__u32) (HighLimit - LowLimit);
}
#else
static inline __u32 query_stack_size()
{
   return 4096;
}
#endif


#ifndef THREAD_SIZE
# define THREAD_SIZE query_stack_size()
#endif

#define LUSTRE_TRACE_SIZE (THREAD_SIZE >> 5)

#ifdef __KERNEL__
# ifdef  __ia64__
#  define CDEBUG_STACK() (THREAD_SIZE -                         \
                          ((ulong_ptr)__builtin_dwarf_cfa() &   \
                           (THREAD_SIZE - 1)))
# else
#  define CDEBUG_STACK (IoGetRemainingStackSize())
#  error "This doesn't seem right; CDEBUG_STACK should grow with the stack"
# endif /* __ia64__ */

#define CHECK_STACK()                                                   \
do {                                                                    \
        unsigned long _stack = CDEBUG_STACK();                          \
                                                                        \
        if (_stack > 3*THREAD_SIZE/4 && _stack > libcfs_stack) {        \
                libcfs_stack = _stack;                                  \
                libcfs_debug_msg(NULL, DEBUG_SUBSYSTEM, D_WARNING,      \
                                 __FILE__, NULL, __LINE__,              \
                                 "maximum lustre stack %lu\n", _stack); \
        }                                                               \
} while (0)
#else /* !__KERNEL__ */
#define CHECK_STACK() do { } while(0)
#define CDEBUG_STACK() (0L)
#endif /* __KERNEL__ */

/* initial pid  */
#define LUSTRE_LNET_PID          12345

#define ENTRY_NESTING_SUPPORT (0)
#define ENTRY_NESTING   do {;} while (0)
#define EXIT_NESTING   do {;} while (0)
#define __current_nesting_level() (0)

#endif /* _WINNT_LIBCFS_H */
