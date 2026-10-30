/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_SYSFS_H__
#define __LIBCFS_LINUX_SYSFS_H__

#include_next <linux/sysfs.h>

#ifndef HAVE_KOBJ_TYPE_DEFAULT_GROUPS
#define default_groups          default_attrs
#define ATTRIBUTE_GROUPS(_name) static struct attribute *_name##_groups = _name##_attrs
#endif

#endif /* __LIBCFS_LINUX_SYSFS_H__ */
