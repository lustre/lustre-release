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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/darwin/darwin-time.h
 *
 * Implementation of portable time API for XNU kernel
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
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
 *  CFS_TIME_FORMAT
 *  CFS_DURATION_FORMAT
 *
 */

#define ONE_BILLION ((u_int64_t)1000000000)
#define ONE_MILLION 1000000

#ifdef __KERNEL__
#include <sys/types.h>
#include <sys/systm.h>

#include <sys/kernel.h>

#include <mach/mach_types.h>
#include <mach/time_value.h>
#include <kern/clock.h>
#include <sys/param.h>

#include <libcfs/darwin/darwin-types.h>
#include <libcfs/darwin/darwin-utils.h>
#include <libcfs/darwin/darwin-lock.h>

/*
 * There are three way to measure time in OS X:
 * 1. nanoseconds
 * 2. absolute time (abstime unit equal to the length of one bus cycle),
 *    schedule of thread/timer are counted by absolute time, but abstime
 *    in different mac can be different also, so we wouldn't use it.
 * 3. clock interval (1sec = 100hz). But clock interval only taken by KPI
 *    like tsleep().
 *
 * We use nanoseconds (uptime, not calendar time)
 *
 * clock_get_uptime()   :get absolute time since bootup.
 * nanouptime()         :get nanoseconds since bootup
 * microuptime()        :get microseonds since bootup
 * nanotime()           :get nanoseconds since epoch
 * microtime()          :get microseconds since epoch
 */
typedef u_int64_t cfs_time_t; /* nanoseconds */
typedef int64_t cfs_duration_t;

#define CFS_TIME_T		"%llu"
#define CFS_DURATION_T		"%lld"

typedef struct timeval cfs_fs_time_t;

static inline cfs_time_t cfs_time_current(void)
{
        struct timespec instant;

        nanouptime(&instant);
        return ((u_int64_t)instant.tv_sec) * NSEC_PER_SEC + instant.tv_nsec;
}

static inline time_t cfs_time_current_sec(void)
{
        struct timespec instant;

        nanouptime(&instant);
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
        microtime((struct timeval *)t);
}

static inline time_t cfs_fs_time_sec(cfs_fs_time_t *t)
{
        return t->tv_sec;
}

static inline void cfs_fs_time_usec(cfs_fs_time_t *t, struct timeval *v)
{
        *v = *t;
}

static inline void cfs_fs_time_nsec(cfs_fs_time_t *t, struct timespec *s)
{
        s->tv_sec  = t->tv_sec;
        s->tv_nsec = t->tv_usec * NSEC_PER_USEC;
}

static inline cfs_duration_t cfs_time_seconds(int seconds)
{
	return (NSEC_PER_SEC * (int64_t)seconds);
}

/*
 * internal helper function used by cfs_fs_time_before*()
 */
static inline int64_t __cfs_fs_time_flat(cfs_fs_time_t *t)
{
        return ((int64_t)t->tv_sec)*NSEC_PER_SEC + t->tv_usec*NSEC_PER_USEC;
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
        return d / NSEC_PER_SEC;
}

static inline void cfs_duration_usec(cfs_duration_t d, struct timeval *s)
{
        s->tv_sec = d / NSEC_PER_SEC;
        s->tv_usec = (d - ((int64_t)s->tv_sec) * NSEC_PER_SEC) / NSEC_PER_USEC;
}

static inline void cfs_duration_nsec(cfs_duration_t d, struct timespec *s)
{
        s->tv_sec = d / NSEC_PER_SEC;
        s->tv_nsec = d - ((int64_t)s->tv_sec) * NSEC_PER_SEC;
}

#define cfs_time_current_64 cfs_time_current
#define cfs_time_add_64     cfs_time_add
#define cfs_time_shift_64   cfs_time_shift
#define cfs_time_before_64  cfs_time_before
#define cfs_time_beforeq_64 cfs_time_beforeq

/* 
 * One jiffy (in nanoseconds)
 *
 * osfmk/kern/sched_prim.c
 * #define DEFAULT_PREEMPTION_RATE      100
 */
#define CFS_TICK		(NSEC_PER_SEC / (u_int64_t)100)

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
