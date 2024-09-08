/* SPDX-License-Identifier: GPL-2.0 */

/*
 * TODO: Remove after dropping RHEL7 support
 */

#ifndef __LIBCFS_LINUX_REFCOUNT_H__
#define __LIBCFS_LINUX_REFCOUNT_H__

#include <linux/atomic.h>

#ifndef HAVE_REFCOUNT_T

#define refcount_t		atomic_t

#define refcount_set		atomic_set
#define refcount_inc		atomic_inc
#define refcount_inc_not_zero	atomic_inc_not_zero
#define refcount_dec		atomic_dec
#define refcount_dec_and_test	atomic_dec_and_test
#define refcount_read		atomic_read

#endif

#endif /* __LIBCFS_LINUX_REFCOUNT_H__ */
