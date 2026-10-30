/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_STRING_H__
#define __LIBCFS_LINUX_STRING_H__

#include_next <linux/string.h>
#include <linux/fortify-string.h>

#ifndef memset_startat
/** from linux 5.19 include/linux/string.h: */
#define memset_startat(obj, v, member)					\
({									\
	u8 *__ptr = (u8 *)(obj);					\
	typeof(v) __val = (v);						\
	memset(__ptr + offsetof(typeof(*(obj)), member), __val,		\
	       sizeof(*(obj)) - offsetof(typeof(*(obj)), member));	\
})
#endif /* memset_startat() */

#endif /* __LIBCFS_LINUX_STRING_H__ */
