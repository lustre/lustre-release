/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LIBCFS_LINUX_MISC_H__
#define __LIBCFS_LINUX_MISC_H__

#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/user_namespace.h>
#include <linux/uio.h>

#ifdef HAVE_SYSCTL_CTLNAME
#define INIT_CTL_NAME	.ctl_name = CTL_UNNUMBERED,
#define INIT_STRATEGY	.strategy = &sysctl_intvec,
#else
#define INIT_CTL_NAME
#define INIT_STRATEGY
#endif

#ifndef HAVE_IOV_ITER_TYPE
#ifdef HAVE_IOV_ITER_HAS_TYPE_MEMBER
#define iter_is_iovec(iter)		((iter)->type & ITER_IOVEC)
#define iov_iter_is_kvec(iter)		((iter)->type & ITER_KVEC)
#define iov_iter_is_bvec(iter)		((iter)->type & ITER_BVEC)
#define iov_iter_is_pipe(iter)		((iter)->type & ITER_PIPE)
#define iov_iter_is_discard(iter)	((iter)->type & ITER_DISCARD)
#else
#define iter_is_iovec(iter)		1
#define iov_iter_is_kvec(iter)		0
#define iov_iter_is_bvec(iter)		0
#define iov_iter_is_pipe(iter)		0
#define iov_iter_is_discard(iter)	0
#endif
#endif /* HAVE_IOV_ITER_TYPE */

#ifndef HAVE_MODULE_PARAM_LOCKING
static DEFINE_MUTEX(param_lock);
#endif

#ifndef HAVE_UIDGID_HEADER

#ifndef _LINUX_UIDGID_H
#define _LINUX_UIDGID_H

typedef uid_t kuid_t;
typedef gid_t kgid_t;

#define INVALID_UID	-1
#define INVALID_GID	-1

#define GLOBAL_ROOT_UID	0
#define GLOBAL_ROOT_GID	0

static inline uid_t __kuid_val(kuid_t uid)
{
	return uid;
}

static inline gid_t __kgid_val(kgid_t gid)
{
	return gid;
}

static inline kuid_t make_kuid(struct user_namespace *from, uid_t uid)
{
	return uid;
}

static inline kgid_t make_kgid(struct user_namespace *from, gid_t gid)
{
	return gid;
}

static inline uid_t from_kuid(struct user_namespace *to, kuid_t uid)
{
	return uid;
}

static inline gid_t from_kgid(struct user_namespace *to, kgid_t gid)
{
	return gid;
}

static inline bool uid_eq(kuid_t left, kuid_t right)
{
	return left == right;
}

static inline bool uid_valid(kuid_t uid)
{
	return uid != (typeof(uid))INVALID_UID;
}

static inline bool gid_valid(kgid_t gid)
{
	return gid != (typeof(gid))INVALID_GID;
}
#endif /* _LINUX_UIDGID_H */

#endif

int cfs_get_environ(const char *key, char *value, int *val_len);

int cfs_kernel_write(struct file *filp, const void *buf, size_t count,
		     loff_t *pos);

/*
 * For RHEL6 struct kernel_parm_ops doesn't exist. Also
 * the arguments for .set and .get take different
 * parameters which is handled below
 */
#ifdef HAVE_KERNEL_PARAM_OPS
#define cfs_kernel_param_arg_t const struct kernel_param
#else
#define cfs_kernel_param_arg_t struct kernel_param_ops
#define kernel_param_ops kernel_param
#endif /* ! HAVE_KERNEL_PARAM_OPS */

#ifndef HAVE_KERNEL_PARAM_LOCK
static inline void kernel_param_unlock(struct module *mod)
{
#ifndef	HAVE_MODULE_PARAM_LOCKING
	mutex_unlock(&param_lock);
#else
	__kernel_param_unlock();
#endif
}

static inline void kernel_param_lock(struct module *mod)
{
#ifndef	HAVE_MODULE_PARAM_LOCKING
	mutex_lock(&param_lock);
#else
	__kernel_param_lock();
#endif
}
#endif /* ! HAVE_KERNEL_PARAM_LOCK */

#ifndef HAVE_KSTRTOUL
static inline int kstrtoul(const char *s, unsigned int base, unsigned long *res)
{
	char *end = (char *)s;

	*res = simple_strtoul(s, &end, base);
	if (end - s == 0)
		return -EINVAL;
	return 0;
}
#endif /* !HAVE_KSTRTOUL */

#ifndef HAVE_KSTRTOBOOL_FROM_USER

#define kstrtobool strtobool

int kstrtobool_from_user(const char __user *s, size_t count, bool *res);
#endif
#endif
