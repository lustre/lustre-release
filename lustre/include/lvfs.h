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

#if !defined(HAVE_ALLOC_FILE_PSEUDO) && defined(HAVE_SERVER_SUPPORT)
#define OPEN_FMODE(flag) ((__force fmode_t)(((flag + 1) & O_ACCMODE) | \
					    (flag & __FMODE_NONOTIFY)))
static inline
struct file *alloc_file_pseudo(struct inode *inode, struct vfsmount *mnt,
			       const char *name, int flags,
			       const struct file_operations *fops)
{
	struct qstr this = QSTR_INIT(name, strlen(name));
	struct path path;
	struct file *file;

	path.dentry = d_alloc_pseudo(mnt->mnt_sb, &this);
	if (!path.dentry)
		return ERR_PTR(-ENOMEM);
	path.mnt = mntget(mnt);
	d_instantiate(path.dentry, inode);
	file = alloc_file(&path, OPEN_FMODE(flags), fops);
	if (IS_ERR(file)) {
		ihold(inode);
		path_put(&path);
	} else {
		file->f_flags = flags;
	}
	return file;
}
#endif /* !HAVE_ALLOC_FILE_PSEUDO */

#endif
