/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_DEVICE_H__
#define __LIBCFS_LINUX_DEVICE_H__

#include <linux/device.h>

#ifndef HAVE_CLASS_CREATE_NO_ARG
# ifdef class_create
static inline struct class *compat_class_create(struct module *owner,
						const char *name)
{
	return class_create(owner, name);
}
#  undef class_create
#  define class_create(name)	compat_class_create(THIS_MODULE, name)
# endif
#endif /* HAVE_CLASS_CREATE_NO_ARG */

#endif /* __LIBCFS_LINUX_DEVICE_H__ */
