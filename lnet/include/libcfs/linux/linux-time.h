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
 * Implementation of portable time API for Linux (kernel and user-level).
 *
 */

#ifndef __LIBCFS_LINUX_LINUX_TIME_H__
#define __LIBCFS_LINUX_LINUX_TIME_H__

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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/time.h>
#include <asm/div64.h>

#include <libcfs/linux/portals_compat25.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))

/*
 * old kernels---CURRENT_TIME is struct timeval
 */
typedef struct timeval cfs_fs_time_t;

static inline void cfs_fs_time_usec(cfs_fs_time_t *t, struct timeval *v)
{
        *v = *t;
}

static inline void cfs_fs_time_nsec(cfs_fs_time_t *t, struct timespec *s)
{
        s->tv_sec  = t->tv_sec;
        s->tv_nsec = t->tv_usec * 1000;
}

/*
 * internal helper function used by cfs_fs_time_before*()
 */
static inline unsigned long __cfs_fs_time_flat(cfs_fs_time_t *t)
{
        return ((unsigned long)t->tv_sec) * ONE_MILLION + t->tv_usec * 1000;
}

#define CURRENT_KERN_TIME        xtime

/* (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)) */
#else

/*
 * post 2.5 kernels.
 */

#include <linux/jiffies.h>

typedef struct timespec cfs_fs_time_t;

static inline void cfs_fs_time_usec(cfs_fs_time_t *t, struct timeval *v)
{
        v->tv_sec  = t->tv_sec;
        v->tv_usec = t->tv_nsec / 1000;
}

static inline void cfs_fs_time_nsec(cfs_fs_time_t *t, struct timespec *s)
{
        *s = *t;
}

/*
 * internal helper function used by cfs_fs_time_before*()
 */
static inline unsigned long __cfs_fs_time_flat(cfs_fs_time_t *t)
{
        return ((unsigned long)t->tv_sec) * ONE_BILLION + t->tv_nsec;
}

#define CURRENT_KERN_TIME        CURRENT_TIME

/* (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)) */
#endif

/*
 * Generic kernel stuff
 */

typedef unsigned long cfs_time_t;      /* jiffies */
typedef long cfs_duration_t;


static inline cfs_time_t cfs_time_current(void)
{
        return jiffies;
}

static inline time_t cfs_time_current_sec(void)
{
        return CURRENT_SECONDS;
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
        return time_before(t1, t2);
}

static inline int cfs_time_beforeq(cfs_time_t t1, cfs_time_t t2)
{
        return time_before_eq(t1, t2);
}

static inline void cfs_fs_time_current(cfs_fs_time_t *t)
{
        *t = CURRENT_KERN_TIME;
}

static inline time_t cfs_fs_time_sec(cfs_fs_time_t *t)
{
        return t->tv_sec;
}

static inline int cfs_fs_time_before(cfs_fs_time_t *t1, cfs_fs_time_t *t2)
{
        return time_before(__cfs_fs_time_flat(t1), __cfs_fs_time_flat(t2));
}

static inline int cfs_fs_time_beforeq(cfs_fs_time_t *t1, cfs_fs_time_t *t2)
{
        return time_before_eq(__cfs_fs_time_flat(t1), __cfs_fs_time_flat(t2));
}

#if 0
static inline cfs_duration_t cfs_duration_build(int64_t nano)
{
#if (BITS_PER_LONG == 32)
        /* We cannot use do_div(t, ONE_BILLION), do_div can only process
         * 64 bits n and 32 bits base */
        int64_t  t = nano * HZ;
        do_div(t, 1000);
        do_div(t, 1000000);
        return (cfs_duration_t)t;
#else
        return (nano * HZ / ONE_BILLION);
#endif
}
#endif

static inline cfs_duration_t cfs_time_seconds(int seconds)
{
        return ((cfs_duration_t)seconds) * HZ;
}

static inline cfs_time_t cfs_time_shift(int seconds)
{
        return jiffies + ((cfs_duration_t)seconds) * HZ;
}

static inline time_t cfs_duration_sec(cfs_duration_t d)
{
        return d / HZ;
}

static inline void cfs_duration_usec(cfs_duration_t d, struct timeval *s)
{
#if (BITS_PER_LONG == 32)
        uint64_t t;

        s->tv_sec = d / HZ;
        t = (d - s->tv_sec * HZ) * ONE_MILLION;
        s->tv_usec = do_div (t, HZ);
#else
        s->tv_sec = d / HZ;
        s->tv_usec = ((d - s->tv_sec * HZ) * ONE_MILLION) / HZ;
#endif
}

static inline void cfs_duration_nsec(cfs_duration_t d, struct timespec *s)
{
#if (BITS_PER_LONG == 32)
        uint64_t t;

        s->tv_sec = d / HZ;
        t = (d - s->tv_sec * HZ) * ONE_BILLION;
        s->tv_nsec = do_div (t, HZ);
#else
        s->tv_sec = d / HZ;
        s->tv_nsec = ((d - s->tv_sec * HZ) * ONE_BILLION) / HZ;
#endif
}

static inline cfs_duration_t cfs_time_minimal_timeout(void)
{
        return 1;
}

/* inline function cfs_time_minimal_timeout() can not be used
 * to initiallize static variable */
#define CFS_MIN_DELAY           (1)

#define CFS_TIME_T              "%lu"
#define CFS_DURATION_T          "%ld"

#else   /* !__KERNEL__ */

/*
 * Liblustre. time(2) based implementation.
 */
#include <libcfs/user-time.h>
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
