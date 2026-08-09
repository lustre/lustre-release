/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LINUX_MODULE_LUSTRE_H
#define _LINUX_MODULE_LUSTRE_H

#include_next <linux/module.h>

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

#endif /* _LINUX_MODULE_LUSTRE_H */
