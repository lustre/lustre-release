/* SPDX-License-Identifier: GPL-2.0 */

/* This file is part of Lustre, http://www.lustre.org/ */

#ifndef __LIBCFS_LINUX_NET_H__
#define __LIBCFS_LINUX_NET_H__

#include <linux/net.h>

#if !defined(HAVE_SENDPAGE_OK)
static inline bool sendpage_ok(struct page *page)
{
	return true;
}
#endif

#endif
