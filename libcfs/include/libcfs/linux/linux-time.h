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
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/linux/linux-time.h
 *
 * Implementation of portable time API for Linux (kernel and user-level).
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_LINUX_LINUX_TIME_H__
#define __LIBCFS_LINUX_LINUX_TIME_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifndef __KERNEL__
#error This include is only for kernel use.
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
 *  cfs_time_t     cfs_time_current(void);
 *  cfs_time_t     cfs_time_add    (cfs_time_t, cfs_duration_t);
 *  cfs_duration_t cfs_time_sub    (cfs_time_t, cfs_time_t);
 *  int            cfs_impl_time_before (cfs_time_t, cfs_time_t);
 *  int            cfs_impl_time_before_eq(cfs_time_t, cfs_time_t);
 *
 *  cfs_duration_t cfs_duration_build(int64_t);
 *
 *  time_t         cfs_duration_sec (cfs_duration_t);
 *  void           cfs_duration_usec(cfs_duration_t, struct timeval *);
 *  void           cfs_duration_nsec(cfs_duration_t, struct timespec *);
 *
 *  CFS_TIME_FORMAT
 *  CFS_DURATION_FORMAT
 *
 */

#define ONE_BILLION ((u_int64_t)1000000000)
#define ONE_MILLION 1000000

#ifndef __KERNEL__
#error This include is only for kernel use.
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/time.h>
#include <asm/div64.h>

/*
 * Generic kernel stuff
 */

typedef unsigned long cfs_time_t;      /* jiffies */
typedef long cfs_duration_t;
typedef cycles_t cfs_cycles_t;

#ifndef HAVE_TIMESPEC64

typedef __s64 time64_t;

#if __BITS_PER_LONG == 64

# define timespec64 timespec

static inline struct timespec64 timespec_to_timespec64(const struct timespec ts)
{
	return ts;
}

#else
struct timespec64 {
	time64_t	tv_sec;		/* seconds */
	long		tv_nsec;	/* nanoseconds */
};

static inline struct timespec64 timespec_to_timespec64(const struct timespec ts)
{
	struct timespec64 ret;

	ret.tv_sec = ts.tv_sec;
	ret.tv_nsec = ts.tv_nsec;
	return ret;
}
#endif /* __BITS_PER_LONG != 64 */

#endif /* HAVE_TIMESPEC64 */

#ifndef HAVE_KTIME_GET_REAL_TS64
void ktime_get_real_ts64(struct timespec64 *ts);
#endif /* HAVE_KTIME_GET_REAL_TS */

static inline int cfs_time_before(cfs_time_t t1, cfs_time_t t2)
{
        return time_before(t1, t2);
}

static inline int cfs_time_beforeq(cfs_time_t t1, cfs_time_t t2)
{
        return time_before_eq(t1, t2);
}

static inline cfs_time_t cfs_time_current(void)
{
        return jiffies;
}

static inline time_t cfs_time_current_sec(void)
{
	return get_seconds();
}

static inline cfs_duration_t cfs_time_seconds(int seconds)
{

	return ((cfs_duration_t)seconds) * msecs_to_jiffies(MSEC_PER_SEC);
}

static inline time_t cfs_duration_sec(cfs_duration_t d)
{

	return d / msecs_to_jiffies(MSEC_PER_SEC);
}

static inline void cfs_duration_usec(cfs_duration_t d, struct timeval *s)
{
#if (BITS_PER_LONG == 32)
	if (msecs_to_jiffies(MSEC_PER_SEC) > 4096) {
		__u64 t;

		s->tv_sec = d / msecs_to_jiffies(MSEC_PER_SEC);
		t = (d - (cfs_duration_t)s->tv_sec *
		     msecs_to_jiffies(MSEC_PER_SEC)) * USEC_PER_SEC;
		do_div(t, msecs_to_jiffies(MSEC_PER_SEC));
		s->tv_usec = t;
	} else {
		s->tv_sec = d / msecs_to_jiffies(MSEC_PER_SEC);
		s->tv_usec = ((d - (cfs_duration_t)s->tv_sec *
			       msecs_to_jiffies(MSEC_PER_SEC)) *
			       USEC_PER_SEC) / msecs_to_jiffies(MSEC_PER_SEC);
	}
#else
	s->tv_sec = d / msecs_to_jiffies(MSEC_PER_SEC);
	s->tv_usec = ((d - (cfs_duration_t)s->tv_sec *
		       msecs_to_jiffies(MSEC_PER_SEC)) *
		       USEC_PER_SEC) / msecs_to_jiffies(MSEC_PER_SEC);
#endif
}

static inline void cfs_duration_nsec(cfs_duration_t d, struct timespec *s)
{
#if (BITS_PER_LONG == 32)
	__u64 t;

	s->tv_sec = d / msecs_to_jiffies(MSEC_PER_SEC);
	t = (d - s->tv_sec * msecs_to_jiffies(MSEC_PER_SEC)) * NSEC_PER_SEC;
	do_div(t, msecs_to_jiffies(MSEC_PER_SEC));
	s->tv_nsec = t;
#else
	s->tv_sec = d / msecs_to_jiffies(MSEC_PER_SEC);
	s->tv_nsec = ((d - s->tv_sec * msecs_to_jiffies(MSEC_PER_SEC)) *
		      NSEC_PER_SEC) / msecs_to_jiffies(MSEC_PER_SEC);
#endif
}

#define cfs_time_current_64 get_jiffies_64

static inline __u64 cfs_time_add_64(__u64 t, __u64 d)
{
        return t + d;
}

static inline __u64 cfs_time_shift_64(int seconds)
{
        return cfs_time_add_64(cfs_time_current_64(),
                               cfs_time_seconds(seconds));
}

static inline int cfs_time_before_64(__u64 t1, __u64 t2)
{
        return (__s64)t2 - (__s64)t1 > 0;
}

static inline int cfs_time_beforeq_64(__u64 t1, __u64 t2)
{
        return (__s64)t2 - (__s64)t1 >= 0;
}

/*
 * One jiffy
 */
#define CFS_TIME_T              "%lu"
#define CFS_DURATION_T          "%ld"


#endif /* __LIBCFS_LINUX_LINUX_TIME_H__ */
/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
