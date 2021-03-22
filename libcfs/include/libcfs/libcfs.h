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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LIBCFS_H__
#define __LIBCFS_LIBCFS_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/signal.h>
#endif

#include <libcfs/linux/linux-misc.h>
#include <libcfs/linux/linux-mem.h>
#include <libcfs/linux/linux-time.h>
#include <libcfs/linux/linux-wait.h>

#include <uapi/linux/lnet/libcfs_ioctl.h>
#include <libcfs/libcfs_debug.h>
#include <libcfs/libcfs_private.h>
#include <libcfs/bitmap.h>
#include <libcfs/libcfs_cpu.h>
#include <libcfs/libcfs_string.h>
#include <libcfs/libcfs_workitem.h>
#include <libcfs/libcfs_hash.h>
#include <libcfs/libcfs_fail.h>
#include "curproc.h"

#define LIBCFS_VERSION	"0.7.1"

/* Sparse annotations */
#if !defined(__must_hold)
# ifdef __CHECKER__
#  define __must_hold(x) __attribute__((context(x, 1, 1)))
# else	/* __CHECKER__ */
#  define __must_hold(x)
# endif /* !__CHECKER__ */
#endif /* !__must_hold */

typedef s32 timeout_t;

/* need both kernel and user-land acceptor */
#define LNET_ACCEPTOR_MIN_RESERVED_PORT    512
#define LNET_ACCEPTOR_MAX_RESERVED_PORT    1023

extern struct blocking_notifier_head libcfs_ioctl_list;
static inline int notifier_from_ioctl_errno(int err)
{
	if (err == -EINVAL)
		return NOTIFY_OK;
	return notifier_from_errno(err) | NOTIFY_STOP_MASK;
}

int libcfs_ioctl_data_adjust(struct libcfs_ioctl_data *data);

extern struct workqueue_struct *cfs_rehash_wq;

struct lnet_debugfs_symlink_def {
	const char *name;
	const char *target;
};

void lnet_insert_debugfs(struct ctl_table *table);
void lnet_remove_debugfs(struct ctl_table *table);

/* helper for sysctl handlers */
int lprocfs_call_handler(void *data, int write, loff_t *ppos,
			 void __user *buffer, size_t *lenp,
			 int (*handler)(void *data, int write, loff_t pos,
					void __user *buffer, int len));
int debugfs_doint(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos);

/*
 * Memory
 */
#if BITS_PER_LONG == 32
/* limit to lowmem on 32-bit systems */
#define NUM_CACHEPAGES \
	min(cfs_totalram_pages(), 1UL << (30 - PAGE_SHIFT) * 3 / 4)
#else
#define NUM_CACHEPAGES cfs_totalram_pages()
#endif

#define wait_var_event_warning(var, condition, format, ...)		\
do {									\
	int counter = 4;						\
	might_sleep();							\
	if (condition)							\
		break;							\
	___wait_var_event(var, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			  if (schedule_timeout(cfs_time_seconds(1)) == 0)\
				  CDEBUG(is_power_of_2(counter++) ?	\
					 D_WARNING : D_NET,		\
					 format, ## __VA_ARGS__)	\
		);							\
} while (0)

/* atomic-context safe vfree */
void libcfs_vfree_atomic(const void *addr);

/* interval tree */

#ifdef HAVE_INTERVAL_TREE_CACHED
#define interval_tree_root rb_root_cached
#define interval_tree_first rb_first_cached
#define INTERVAL_TREE_ROOT RB_ROOT_CACHED
#else
#define interval_tree_root rb_root
#define interval_tree_first rb_first
#define INTERVAL_TREE_ROOT RB_ROOT
#endif /* HAVE_INTERVAL_TREE_CACHED */

#endif /* _LIBCFS_LIBCFS_H_ */
