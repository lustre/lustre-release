/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of portable time API for Linux (kernel and user-level).
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_LINUX_LINUX_TIME_H__
#define __LIBCFS_LINUX_LINUX_TIME_H__

/* Portable time API */
#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/jiffies.h>
#include <linux/hrtimer.h>
#include <linux/types.h>
#include <linux/time.h>
#include <asm/div64.h>

/*
 * Generic kernel stuff
 */
static inline unsigned long cfs_time_seconds(time64_t seconds)
{
	return nsecs_to_jiffies64(seconds * NSEC_PER_SEC);
}

#ifdef HAVE_NEW_DEFINE_TIMER
# ifndef TIMER_DATA_TYPE
# define TIMER_DATA_TYPE struct timer_list *
# endif

#define CFS_DEFINE_TIMER(_name, _function, _expires, _data) \
	DEFINE_TIMER((_name), (_function))
#else
# ifndef TIMER_DATA_TYPE
# define TIMER_DATA_TYPE unsigned long
# endif

#define CFS_DEFINE_TIMER(_name, _function, _expires, _data) \
	DEFINE_TIMER((_name), (_function), (_expires), (_data))
#endif

#ifdef HAVE_TIMER_SETUP
#define cfs_timer_cb_arg_t struct timer_list *
#define cfs_from_timer(var, callback_timer, timer_fieldname) \
	from_timer(var, callback_timer, timer_fieldname)
#define cfs_timer_setup(timer, callback, data, flags) \
	timer_setup((timer), (callback), (flags))
#define cfs_timer_cb_arg(var, timer_fieldname) (&(var)->timer_fieldname)
#else
#define cfs_timer_cb_arg_t unsigned long
#define cfs_from_timer(var, data, timer_fieldname) (typeof(var))(data)
#define cfs_timer_setup(timer, callback, data, flags) \
	setup_timer((timer), (callback), (data))
#define cfs_timer_cb_arg(var, timer_fieldname) (cfs_timer_cb_arg_t)(var)
#endif

#endif /* __LIBCFS_LINUX_LINUX_TIME_H__ */
