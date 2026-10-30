/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of portable time API for Linux (kernel and user-level).
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_LINUX_LINUX_TIME_H__
#define __LIBCFS_LINUX_LINUX_TIME_H__

/*
 * <linux/timer.h> is included from deep inside other kernel headers
 * (mm_types.h -> workqueue.h), so do not pull in heavy headers here.
 */
#include_next <linux/timer.h>

#ifndef HAVE_TIMER_DESTROY_ON_STACK
#define timer_destroy_on_stack(timer) destroy_timer_on_stack(timer)
#endif

#define cfs_timer_cb_arg_t struct timer_list *
#define cfs_from_timer(var, callback_timer, timer_fieldname) \
	timer_container_of(var, callback_timer, timer_fieldname)
#define cfs_timer_setup(timer, callback, data, flags) \
	timer_setup((timer), (callback), (flags))
#define cfs_timer_cb_arg(var, timer_fieldname) (&(var)->timer_fieldname)

#endif /* __LIBCFS_LINUX_LINUX_TIME_H__ */
