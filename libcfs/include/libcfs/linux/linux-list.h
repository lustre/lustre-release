/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_LINUX_LIST_H__
#define __LIBCFS_LINUX_LIST_H__

#include <linux/list.h>

#ifdef HAVE_HLIST_ADD_AFTER
#define hlist_add_behind(hnode, tail)	hlist_add_after(tail, hnode)
#endif /* HAVE_HLIST_ADD_AFTER */

#endif /* __LIBCFS_LINUX_LIST_H__ */
