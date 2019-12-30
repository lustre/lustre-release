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

int cfs_get_environ(const char *key, char *value, int *val_len);

int cfs_kernel_write(struct file *filp, const void *buf, size_t count,
		     loff_t *pos);
ssize_t cfs_kernel_read(struct file *file, void *buf, size_t count,
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
	__kernel_param_unlock();
}

static inline void kernel_param_lock(struct module *mod)
{
	__kernel_param_lock();
}
#endif /* ! HAVE_KERNEL_PARAM_LOCK */

#ifndef HAVE_KSTRTOBOOL_FROM_USER

#define kstrtobool strtobool

int kstrtobool_from_user(const char __user *s, size_t count, bool *res);
#endif
#endif
