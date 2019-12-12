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
