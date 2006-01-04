/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 * Author: Nikita Danilov <nikita@clusterfs.com>
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
 * Implementation of portable time API for XNU kernel
 *
 */

#ifndef __LIBCFS_DARWIN_DARWIN_TIME_H__
#define __LIBCFS_DARWIN_DARWIN_TIME_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

/* Portable time API */

/*
 * Platform provides three opaque data-types:
 *
 *  cfs_time_t        represents point in time. This is internal kernel
 *                    time rather than "wall clock". This time bears no
 *                    relation to gettimeofday().
 *
 *  cfs_duration_t    represents time interval with resolution of internal
 *                    platform clock
 *
 *  cfs_fs_time_t     represents instance in world-visible time. This is
 *                    used in file-system time-stamps
 *
 *  cfs_time_t     cfs_time_current(void);
 *  cfs_time_t     cfs_time_add    (cfs_time_t, cfs_duration_t);
 *  cfs_duration_t cfs_time_sub    (cfs_time_t, cfs_time_t);
 *  int            cfs_time_before (cfs_time_t, cfs_time_t);
 *  int            cfs_time_beforeq(cfs_time_t, cfs_time_t);
 *
 *  cfs_duration_t cfs_duration_build(int64_t);
 *
 *  time_t         cfs_duration_sec (cfs_duration_t);
 *  void           cfs_duration_usec(cfs_duration_t, struct timeval *);
 *  void           cfs_duration_nsec(cfs_duration_t, struct timespec *);
 *
 *  void           cfs_fs_time_current(cfs_fs_time_t *);
 *  time_t         cfs_fs_time_sec    (cfs_fs_time_t *);
 *  void           cfs_fs_time_usec   (cfs_fs_time_t *, struct timeval *);
 *  void           cfs_fs_time_nsec   (cfs_fs_time_t *, struct timespec *);
 *  int            cfs_fs_time_before (cfs_fs_time_t *, cfs_fs_time_t *);
 *  int            cfs_fs_time_beforeq(cfs_fs_time_t *, cfs_fs_time_t *);
 *
 *  cfs_duration_t cfs_time_minimal_timeout(void)
 *
 *  CFS_TIME_FORMAT
 *  CFS_DURATION_FORMAT
 *
 */

#define ONE_BILLION ((u_int64_t)1000000000)
#define ONE_MILLION ((u_int64_t)   1000000)

#ifdef __KERNEL__
#include <sys/types.h>
#include <sys/systm.h>

#ifndef __APPLE_API_PRIVATE
#define __APPLE_API_PRIVATE
#include <sys/user.h>
#undef __APPLE_API_PRIVATE
#else
#include <sys/user.h>
#endif

#include <sys/kernel.h>

#include <mach/thread_act.h>
#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/thread_switch.h>
#include <mach/time_value.h>
#include <kern/sched_prim.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <mach/machine/vm_param.h>
#include <kern/clock.h>
#include <kern/thread_call.h>
#include <sys/param.h>
#include <sys/vm.h>

#include <libcfs/darwin/darwin-types.h>
#include <libcfs/darwin/darwin-utils.h>
#include <libcfs/darwin/darwin-lock.h>

typedef u_int64_t cfs_time_t; /* nanoseconds */
typedef int64_t cfs_duration_t;

#define CFS_TIME_T		"%llu"
#define CFS_DURATION_T		"%lld"

typedef struct timeval cfs_fs_time_t;

static inline cfs_time_t cfs_time_current(void)
{
        struct timespec instant;

        nanotime(&instant);
        return ((u_int64_t)instant.tv_sec) * ONE_BILLION + instant.tv_nsec;
}

static inline time_t cfs_time_current_sec(void)
{
        struct timespec instant;

        nanotime(&instant);
	return instant.tv_sec;
}

static inline cfs_time_t cfs_time_add(cfs_time_t t, cfs_duration_t d)
{
        return t + d;
}

static inline cfs_duration_t cfs_time_sub(cfs_time_t t1, cfs_time_t t2)
{
        return t1 - t2;
}

static inline int cfs_time_before(cfs_time_t t1, cfs_time_t t2)
{
        return (int64_t)t1 - (int64_t)t2 < 0;
}

static inline int cfs_time_beforeq(cfs_time_t t1, cfs_time_t t2)
{
        return (int64_t)t1 - (int64_t)t2 <= 0;
}

static inline void cfs_fs_time_current(cfs_fs_time_t *t)
{
        *t = time;
}

static inline time_t cfs_fs_time_sec(cfs_fs_time_t *t)
{
        return t->tv_sec;
}

static inline cfs_duration_t cfs_duration_build(int64_t nano)
{
        return nano;
}


static inline void cfs_fs_time_usec(cfs_fs_time_t *t, struct timeval *v)
{
        *v = *t;
}

static inline void cfs_fs_time_nsec(cfs_fs_time_t *t, struct timespec *s)
{
        s->tv_sec  = t->tv_sec;
        s->tv_nsec = t->tv_usec * 1000;
}

static inline cfs_duration_t cfs_time_seconds(int seconds)
{
	return cfs_duration_build(ONE_BILLION * (int64_t)seconds);
}

/*
 * internal helper function used by cfs_fs_time_before*()
 */
static inline int64_t __cfs_fs_time_flat(cfs_fs_time_t *t)
{
        return ((int64_t)t->tv_sec) * ONE_BILLION + t->tv_usec;
}

static inline int cfs_fs_time_before(cfs_fs_time_t *t1, cfs_fs_time_t *t2)
{
        return __cfs_fs_time_flat(t1) - __cfs_fs_time_flat(t2) < 0;
}

static inline int cfs_fs_time_beforeq(cfs_fs_time_t *t1, cfs_fs_time_t *t2)
{
        return __cfs_fs_time_flat(t1) - __cfs_fs_time_flat(t2) <= 0;
}

static inline time_t cfs_duration_sec(cfs_duration_t d)
{
        return d / ONE_BILLION;
}

static inline void cfs_duration_usec(cfs_duration_t d, struct timeval *s)
{
        s->tv_sec = d / ONE_BILLION;
        s->tv_usec = (d - s->tv_sec * ONE_BILLION) / 1000;
}

static inline void cfs_duration_nsec(cfs_duration_t d, struct timespec *s)
{
        s->tv_sec = d / ONE_BILLION;
        s->tv_nsec = d - ((int64_t)s->tv_sec) * ONE_BILLION;
}

static inline cfs_duration_t cfs_time_minimal_timeout(void)
{
        return ONE_BILLION / (u_int64_t)hz;
}

/* inline function cfs_time_minimal_timeout() can not be used to
 * initiallize static variable */
#define CFS_MIN_DELAY		(ONE_BILLION / (u_int64_t)100)

#define LTIME_S(t)		(t)

/* __KERNEL__ */
#else

/*
 * User level
 */
#include <libcfs/user-time.h>

/* __KERNEL__ */
#endif

/* __LIBCFS_DARWIN_DARWIN_TIME_H__ */
#endif
/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
