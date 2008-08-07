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
 *
 * libcfs/include/libcfs/winnt/winnt-time.h
 *
 * Implementation of portable time API for Winnt (kernel and user-level).
 */

#ifndef __LIBCFS_WINNT_LINUX_TIME_H__
#define __LIBCFS_WINNT_LINUX_TIME_H__

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
#define ONE_MILLION ((u_int64_t)   1000000)

#define HZ (100)

struct timeval {
	time_t		tv_sec;		/* seconds */
	suseconds_t	tv_usec;	/* microseconds */
};

struct timespec {
    ulong_ptr tv_sec;
    ulong_ptr tv_nsec;
};

#ifdef __KERNEL__

#include <libcfs/winnt/portals_compat25.h>

/*
 * Generic kernel stuff
 */

typedef struct timeval cfs_fs_time_t;

typedef u_int64_t cfs_time_t;
typedef int64_t cfs_duration_t;

static inline void do_gettimeofday(struct timeval *tv)
{
    LARGE_INTEGER Time;

    KeQuerySystemTime(&Time);

    tv->tv_sec  = (long_ptr) (Time.QuadPart / 10000000);
    tv->tv_usec = (long_ptr) (Time.QuadPart % 10000000) / 10;
}

static inline cfs_time_t JIFFIES()
{
    LARGE_INTEGER Tick;
    LARGE_INTEGER Elapse;

    KeQueryTickCount(&Tick);

    Elapse.QuadPart  = Tick.QuadPart * KeQueryTimeIncrement();
    Elapse.QuadPart /= (10000000 / HZ);

    return Elapse.QuadPart;
}

static inline cfs_time_t cfs_time_current(void)
{
    return JIFFIES();
}

static inline cfs_time_t cfs_time_current_sec(void)
{
    return (JIFFIES() / HZ);
}

static inline cfs_time_t cfs_time_add(cfs_time_t t, cfs_duration_t d)
{
    return (t + d);
}

static inline cfs_duration_t cfs_time_sub(cfs_time_t t1, cfs_time_t t2)
{
    return (t1 - t2);
}

static inline int cfs_time_before(cfs_time_t t1, cfs_time_t t2)
{
    return ((int64_t)t1 - (int64_t)t2) < 0; 
}

static inline int cfs_time_beforeq(cfs_time_t t1, cfs_time_t t2)
{
    return ((int64_t)t1 - (int64_t)t2) <= 0;
}

static inline void cfs_fs_time_current(cfs_fs_time_t *t)
{
    ULONG         Linux;
    LARGE_INTEGER Sys;

    KeQuerySystemTime(&Sys);

    RtlTimeToSecondsSince1970(&Sys, &Linux);

    t->tv_sec  = Linux;
    t->tv_usec = (Sys.LowPart % 10000000) / 10;
}

static inline cfs_time_t cfs_fs_time_sec(cfs_fs_time_t *t)
{
    return t->tv_sec;
}

static inline u_int64_t __cfs_fs_time_flat(cfs_fs_time_t *t)
{
    return ((u_int64_t)t->tv_sec) * ONE_MILLION + t->tv_usec;
}

static inline int cfs_fs_time_before(cfs_fs_time_t *t1, cfs_fs_time_t *t2)
{
    return (__cfs_fs_time_flat(t1) < __cfs_fs_time_flat(t2));
}

static inline int cfs_fs_time_beforeq(cfs_fs_time_t *t1, cfs_fs_time_t *t2)
{
    return (__cfs_fs_time_flat(t1) <= __cfs_fs_time_flat(t2));
}

static inline cfs_duration_t cfs_time_seconds(int seconds)
{
    return (cfs_duration_t)seconds * HZ;
}

static inline cfs_time_t cfs_duration_sec(cfs_duration_t d)
{
        return d / HZ;
}

static inline void cfs_duration_usec(cfs_duration_t d, struct timeval *s)
{
        s->tv_sec = (suseconds_t) (d / HZ);
        s->tv_usec = (time_t)((d - (cfs_duration_t)s->tv_sec * HZ) *
                              ONE_MILLION / HZ);
}

static inline void cfs_duration_nsec(cfs_duration_t d, struct timespec *s)
{
        s->tv_sec = (suseconds_t) (d / HZ);
        s->tv_nsec = (time_t)((d - (cfs_duration_t)s->tv_sec * HZ) *
                              ONE_BILLION / HZ);
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

#define cfs_time_current_64 cfs_time_current
#define cfs_time_add_64     cfs_time_add
#define cfs_time_shift_64   cfs_time_shift
#define cfs_time_before_64  cfs_time_before
#define cfs_time_beforeq_64 cfs_time_beforeq

/*
 * One jiffy
 */
#define CFS_TICK                (1)

#define LTIME_S(t)		        (t)

#define CFS_TIME_T              "%I64u"
#define CFS_DURATION_T          "%I64d"

#else   /* !__KERNEL__ */

/*
 * Liblustre. time(2) based implementation.
 */
#include <libcfs/user-time.h>


//
// Time routines ...
//

NTSYSAPI
CCHAR
NTAPI
NtQuerySystemTime(
    OUT PLARGE_INTEGER  CurrentTime
    );


NTSYSAPI
BOOLEAN
NTAPI
RtlTimeToSecondsSince1970(
    IN PLARGE_INTEGER  Time,
    OUT PULONG  ElapsedSeconds
    );


NTSYSAPI
VOID
NTAPI
RtlSecondsSince1970ToTime(
    IN ULONG  ElapsedSeconds,
    OUT PLARGE_INTEGER  Time
    );

NTSYSAPI
VOID
NTAPI
Sleep(
  DWORD dwMilliseconds   // sleep time in milliseconds
);


static inline void sleep(int time)
{
    DWORD Time = 1000 * time;
    Sleep(Time);
}


static inline void do_gettimeofday(struct timeval *tv)
{
    LARGE_INTEGER Time;

    NtQuerySystemTime(&Time);

    tv->tv_sec  = (long_ptr) (Time.QuadPart / 10000000);
    tv->tv_usec = (long_ptr) (Time.QuadPart % 10000000) / 10;
}

static inline int gettimeofday(struct timeval *tv, void * tz)
{
    do_gettimeofday(tv);
    return 0;
}

#endif /* __KERNEL__ */

/* __LIBCFS_LINUX_LINUX_TIME_H__ */
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
