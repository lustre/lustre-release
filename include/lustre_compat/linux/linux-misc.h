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

#ifndef __LIBCFS_LINUX_MISC_H__
#define __LIBCFS_LINUX_MISC_H__

#include <linux/kallsyms.h>

static inline unsigned long cfs_time_seconds(time64_t seconds)
{
	return nsecs_to_jiffies64(seconds * NSEC_PER_SEC);
}

/* TODO: This will soon be private... */
void *cfs_kallsyms_lookup_name(const char *name);
int lustre_symbols_init(void);

int cfs_arch_init(void);
void cfs_arch_exit(void);

/*
 * compat_module_init() / compat_module_exit() wrap a module's init/exit
 * functions so that cfs_arch_init() / cfs_arch_exit() run around them.
 * They are overridable: when lustre_compat is not linked into libcfs.ko,
 * redefine these to bare late_initcall() / module_exit() before including
 * this header.
 */
#ifndef compat_module_init
#define compat_module_init(init_fn)					\
static int __init __compat_module_init(void)				\
{									\
	int __rc;							\
									\
	__rc = cfs_arch_init();						\
	if (__rc < 0) {							\
		pr_err("LustreError: cfs_arch_init: rc = %d\n", __rc);	\
		return __rc;						\
	}								\
									\
	__rc = (init_fn)();						\
	if (__rc) {							\
		cfs_arch_exit();					\
		return __rc;						\
	}								\
									\
	return 0;							\
}									\
late_initcall(__compat_module_init)
#endif

#ifndef compat_module_exit
#define compat_module_exit(exit_fn)					\
static void __exit __compat_module_exit(void)				\
{									\
	(exit_fn)();							\
	cfs_arch_exit();						\
}									\
module_exit(__compat_module_exit)
#endif

#endif /* __LIBCFS_LINUX_MISC_H__ */
