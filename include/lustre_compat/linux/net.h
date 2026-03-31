/* SPDX-License-Identifier: GPL-2.0 */

/* This file is part of Lustre, http://www.lustre.org/ */

#ifndef __LIBCFS_LINUX_NET_H__
#define __LIBCFS_LINUX_NET_H__

#include <linux/net.h>

#ifdef HAVE_KERN_SOCK_GETNAME_2ARGS
#define lnet_kernel_getpeername(sock, addr, addrlen) \
	kernel_getpeername(sock, addr)
#define lnet_kernel_getsockname(sock, addr, addrlen) \
	kernel_getsockname(sock, addr)
#else
#define lnet_kernel_getpeername(sock, addr, addrlen) \
	kernel_getpeername(sock, addr, addrlen)
#define lnet_kernel_getsockname(sock, addr, addrlen) \
	kernel_getsockname(sock, addr, addrlen)
#endif

#if !defined(HAVE_SENDPAGE_OK)
static inline bool sendpage_ok(struct page *page)
{
	return true;
}
#endif

#endif
