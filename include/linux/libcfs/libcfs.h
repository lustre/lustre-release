/* SPDX-License-Identifier: GPL-2.0 */

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
#include <linux/sched/signal.h>

#include <uapi/linux/lnet/libcfs_ioctl.h>
#include <linux/libcfs/libcfs_debug.h>
#include <linux/libcfs/libcfs_private.h>
#include <linux/libcfs/libcfs_fail.h>

#define LIBCFS_VERSION LUSTRE_VERSION_STRING

/* Sparse annotations */
#if !defined(__must_hold)
# ifdef __CHECKER__
#  define __must_hold(x) __attribute__((context(x, 1, 1)))
# else	/* __CHECKER__ */
#  define __must_hold(x)
# endif /* !__CHECKER__ */
#endif /* !__must_hold */

typedef s32 timeout_t;

int libcfs_setup(void);

#ifdef HAVE_CONST_CTR_TABLE
#define DEFINE_CTL_TABLE_INIT(__name, init)\
	const struct ctl_table *__name = init
#define cfs_proc_handler(h)	(h)
#else
#define DEFINE_CTL_TABLE_INIT(__name, init)\
	struct ctl_table *__name = init
typedef int (*cfs_ctl_table_handler_t)(struct ctl_table *,
				       int, void __user *, size_t *, loff_t *);
#define cfs_proc_handler(h)	((cfs_ctl_table_handler_t)(h))
#endif

void lnet_insert_debugfs(const struct ctl_table *table,
			 struct module *mod, void **statep);
void lnet_remove_debugfs(const struct ctl_table *table);
void lnet_debugfs_fini(void **statep);

/* helper for sysctl handlers */
int debugfs_doint(const struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos);

/*
 * Memory
 */
#if BITS_PER_LONG == 32
/* limit to lowmem on 32-bit systems */
#define NUM_CACHEPAGES \
	min(compat_totalram_pages(), 1UL << (30 - PAGE_SHIFT) * 3 / 4)
#else
#define NUM_CACHEPAGES compat_totalram_pages()
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

#ifndef container_of_safe
/**
 * container_of_safe - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 * If IS_ERR_OR_NULL(ptr), ptr is returned unchanged.
 *
 * Note: Copied from Linux 5.6, with BUILD_BUG_ON_MSG section removed.
 */
#define container_of_safe(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	IS_ERR_OR_NULL(__mptr) ? ERR_CAST(__mptr) :			\
		((type *)(__mptr - offsetof(type, member))); })
#endif

#define FLEXIBLE_OBJECT \
	"Struct contains a flexible member, the size of object is checked" \
	"and can be safely copied in a single memcpy()"

/* Linux commit v6.18-rc2-1-g70e0a80a1f358
 *   treewide: Remove in_irq()
 */
#ifndef in_hardirq
#define in_hardirq()	in_irq()
#endif

#endif /* _LIBCFS_LIBCFS_H_ */
