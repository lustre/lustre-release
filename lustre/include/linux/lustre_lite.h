/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _LINUX_LL_H
#define _LINUX_LL_H

#ifndef _LL_H
#error Do not #include this file directly. #include <lustre_lite.h> instead
#endif

#ifdef __KERNEL__

#include <linux/version.h>

#include <asm/statfs.h>

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/proc_fs.h>

#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_ha.h>

#include <linux/rbtree.h>
#include <linux/lustre_compat25.h>
#include <linux/pagemap.h>

#ifdef HAVE_PERCPU_COUNTER
#include <linux/percpu_counter.h>

typedef struct percpu_counter lcounter_t;

#define lcounter_read(counter)          (int)percpu_counter_read(counter)
#define lcounter_inc(counter)           percpu_counter_inc(counter)
#define lcounter_dec(counter)           percpu_counter_dec(counter)

#ifdef HAVE_PERCPU_2ND_ARG
# define lcounter_init(counter)          percpu_counter_init(counter, 0)
#else
# define lcounter_init(counter)          percpu_counter_init(counter)
#endif

#define lcounter_destroy(counter)       percpu_counter_destroy(counter)

#else
typedef struct { cfs_atomic_t count; } lcounter_t;

#define lcounter_read(counter)          cfs_atomic_read(&counter->count)
#define lcounter_inc(counter)           cfs_atomic_inc(&counter->count)
#define lcounter_dec(counter)           cfs_atomic_dec(&counter->count)
#define lcounter_init(counter)          cfs_atomic_set(&counter->count, 0)
#define lcounter_destroy(counter)       

#endif /* if defined HAVE_PERCPU_COUNTER */

/* lprocfs.c */
enum {
         LPROC_LL_DIRTY_HITS = 0,
         LPROC_LL_DIRTY_MISSES,
         LPROC_LL_WB_WRITEPAGE,
         LPROC_LL_WB_PRESSURE,
         LPROC_LL_WB_OK,
         LPROC_LL_WB_FAIL,
         LPROC_LL_READ_BYTES,
         LPROC_LL_WRITE_BYTES,
         LPROC_LL_BRW_READ,
         LPROC_LL_BRW_WRITE,
         LPROC_LL_OSC_READ,
         LPROC_LL_OSC_WRITE,
         LPROC_LL_IOCTL,
         LPROC_LL_OPEN,
         LPROC_LL_RELEASE,
         LPROC_LL_MAP,
         LPROC_LL_LLSEEK,
         LPROC_LL_FSYNC,
         LPROC_LL_SETATTR,
         LPROC_LL_TRUNC,
         LPROC_LL_LOCKLESS_TRUNC,
         LPROC_LL_FLOCK,
         LPROC_LL_GETATTR,
         LPROC_LL_STAFS,
         LPROC_LL_ALLOC_INODE,
         LPROC_LL_SETXATTR,
         LPROC_LL_GETXATTR,
         LPROC_LL_LISTXATTR,
         LPROC_LL_REMOVEXATTR,
         LPROC_LL_INODE_PERM,
         LPROC_LL_DIRECT_READ,
         LPROC_LL_DIRECT_WRITE,
         LPROC_LL_LOCKLESS_READ,
         LPROC_LL_LOCKLESS_WRITE,
         LPROC_LL_FILE_OPCODES
};

#else
#include <lustre/lustre_idl.h>
#endif /* __KERNEL__ */

#endif
