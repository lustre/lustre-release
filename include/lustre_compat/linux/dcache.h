/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_DCACHE_H__
#define __LIBCFS_LINUX_DCACHE_H__

#include_next <linux/dcache.h>

#ifndef QSTR
#define QSTR(name) QSTR_LEN((name), strlen((name)))
#endif

#ifndef QSTR_LEN
#define QSTR_LEN(name, len) ((struct qstr)QSTR_INIT((name), (len)))
#endif

#endif /* __LIBCFS_LINUX_DCACHE_H__ */
