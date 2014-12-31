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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * API and structure definitions for params_tree.
 *
 * Author: LiuYing <emoly.liu@oracle.com>
 */
#ifndef __PARAMS_TREE_H__
#define __PARAMS_TREE_H__

#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>

#ifdef CONFIG_PROC_FS
# define LPROCFS
#endif /* CONFIG_PROC_FS */

#ifdef LPROCFS
# ifndef HAVE_ONLY_PROCFS_SEQ
/* in lprocfs_stat.c, to protect the private data for proc entries */
extern struct rw_semaphore		_lprocfs_lock;

static inline int LPROCFS_ENTRY_CHECK(struct inode *inode)
{
	struct proc_dir_entry *dp = PDE(inode);
	int deleted = 0;

	spin_lock(&(dp)->pde_unload_lock);
	if (dp->proc_fops == NULL)
		deleted = 1;
	spin_unlock(&(dp)->pde_unload_lock);
	if (deleted)
		return -ENODEV;
	return 0;
}

#  define LPROCFS_SRCH_ENTRY()			\
	do {					\
		down_read(&_lprocfs_lock);	\
	} while (0)

#  define LPROCFS_SRCH_EXIT()			\
	do {					\
		up_read(&_lprocfs_lock);	\
	} while (0)

#  define LPROCFS_WRITE_ENTRY()			\
	do {					\
		down_write(&_lprocfs_lock);	\
	} while (0)

#  define LPROCFS_WRITE_EXIT()			\
	do {					\
		up_write(&_lprocfs_lock);	\
	} while (0)

#  define PDE_DATA(inode)	(PDE(inode)->data)

# else /* HAVE_ONLY_PROCFS_SEQ */

static inline int LPROCFS_ENTRY_CHECK(struct inode *inode)
{
	return 0;
}

#define LPROCFS_WRITE_ENTRY() do {} while(0)
#define LPROCFS_WRITE_EXIT()  do {} while(0)

# endif /* !HAVE_ONLY_PROCFS_SEQ */
#endif /* LPROCFS */
#endif  /* __PARAMS_TREE_H__ */
