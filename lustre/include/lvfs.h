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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lvfs.h
 *
 * lustre VFS/process permission interface
 */

#ifndef __LVFS_H__
#define __LVFS_H__

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <lustre_compat.h>

#define OBD_RUN_CTXT_MAGIC	0xC0FFEEAA
#define OBD_CTXT_DEBUG		/* development-only debugging */

struct dt_device;

struct lvfs_run_ctxt {
	struct vfsmount		*pwdmnt;
	struct dentry		*pwd;
	mm_segment_t		 fs;
	int			 umask;
	struct dt_device	*dt;
#ifdef OBD_CTXT_DEBUG
	unsigned int		 magic;
#endif
};

static inline void OBD_SET_CTXT_MAGIC(struct lvfs_run_ctxt *ctxt)
{
#ifdef OBD_CTXT_DEBUG
	ctxt->magic = OBD_RUN_CTXT_MAGIC;
#endif
}

/* ptlrpc_sec_ctx.c */
void push_ctxt(struct lvfs_run_ctxt *save, struct lvfs_run_ctxt *new_ctx);
void pop_ctxt(struct lvfs_run_ctxt *saved, struct lvfs_run_ctxt *new_ctx);

/* We need to hold the inode semaphore over the dcache lookup itself, or we
 * run the risk of entering the filesystem lookup path concurrently on SMP
 * systems, and instantiating two inodes for the same entry.  We still
 * protect against concurrent addition/removal races with the DLM locking.
 */
static inline struct dentry *
ll_lookup_one_len(const char *fid_name, struct dentry *dparent,
		  int fid_namelen)
{
	struct dentry *dchild;

	inode_lock(dparent->d_inode);
	dchild = lookup_one_len(fid_name, dparent, fid_namelen);
	inode_unlock(dparent->d_inode);

	if (IS_ERR(dchild) || dchild->d_inode == NULL)
		return dchild;

	if (is_bad_inode(dchild->d_inode)) {
		CERROR("bad inode returned %lu/%u\n",
		       dchild->d_inode->i_ino, dchild->d_inode->i_generation);
		dput(dchild);
		dchild = ERR_PTR(-ENOENT);
	}

	return dchild;
}

#endif
