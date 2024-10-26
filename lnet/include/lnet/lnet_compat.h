/* SPDX-License-Identifier: GPL-2.0 */

/* This file is part of Lustre, http://www.lustre.org/ */

#ifndef __LNET_LNET_COMPAT_H__
#define __LNET_LNET_COMPAT_H__

/* kernel v5.17-rc1: commit d477eb9004845cb2dc92ad5eed79a437738a868a
 * added static function sock_inuse_add() to the kernel headers, backport
 * a copy for vendor kernels that may not provide it; such kernels will
 * be lacking the all member added to the prot_inuse structure in the
 * next commit, 4199bae10c49e24bc2c5d8c06a68820d56640000.
 */
#ifdef HAVE_SOCK_NOT_OWNED_BY_ME
#ifndef HAVE_SOCK_INUSE_ADD
#ifdef CONFIG_PROC_FS
static inline void sock_inuse_add(const struct net *net, int val)
{
	this_cpu_add(*net->core.sock_inuse, val);
}
#else
static inline void sock_inuse_add(const struct net *net, int val)
{
}
#endif
#endif
#endif

#endif
