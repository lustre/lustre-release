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
 *
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2014, Intel Corporation.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/fs.h>
#include <libcfs/libcfs.h>
#include <lvfs.h>
#include <obd_class.h>

#include "ptlrpc_internal.h"

/* refine later and change to seqlock or simlar from libcfs */
/* Debugging check only needed during development */
#ifdef OBD_CTXT_DEBUG
# define ASSERT_CTXT_MAGIC(magic) LASSERT((magic) == OBD_RUN_CTXT_MAGIC)
# define ASSERT_NOT_KERNEL_CTXT(msg) LASSERTF(!segment_eq(get_fs(), get_ds()),\
					      msg)
# define ASSERT_KERNEL_CTXT(msg) LASSERTF(segment_eq(get_fs(), get_ds()), msg)
#else
# define ASSERT_CTXT_MAGIC(magic) do {} while(0)
# define ASSERT_NOT_KERNEL_CTXT(msg) do {} while(0)
# define ASSERT_KERNEL_CTXT(msg) do {} while(0)
#endif

/* push / pop to root of obd store */
void push_ctxt(struct lvfs_run_ctxt *save, struct lvfs_run_ctxt *new_ctx)
{
	/* if there is underlaying dt_device then push_ctxt is not needed */
	if (new_ctx->dt != NULL)
		return;

	//ASSERT_NOT_KERNEL_CTXT("already in kernel context!\n");
	ASSERT_CTXT_MAGIC(new_ctx->magic);
	OBD_SET_CTXT_MAGIC(save);

	save->fs = get_fs();
	LASSERT(ll_d_count(current->fs->pwd.dentry));
	LASSERT(ll_d_count(new_ctx->pwd));
	save->pwd = dget(current->fs->pwd.dentry);
	save->pwdmnt = mntget(current->fs->pwd.mnt);
	save->umask = current_umask();

	LASSERT(save->pwd);
	LASSERT(save->pwdmnt);
	LASSERT(new_ctx->pwd);
	LASSERT(new_ctx->pwdmnt);

	current->fs->umask = 0; /* umask already applied on client */
	set_fs(new_ctx->fs);
	ll_set_fs_pwd(current->fs, new_ctx->pwdmnt, new_ctx->pwd);
}
EXPORT_SYMBOL(push_ctxt);

void pop_ctxt(struct lvfs_run_ctxt *saved, struct lvfs_run_ctxt *new_ctx)
{
	/* if there is underlaying dt_device then pop_ctxt is not needed */
	if (new_ctx->dt != NULL)
		return;

	ASSERT_CTXT_MAGIC(saved->magic);
	ASSERT_KERNEL_CTXT("popping non-kernel context!\n");

	LASSERTF(current->fs->pwd.dentry == new_ctx->pwd, "%p != %p\n",
		 current->fs->pwd.dentry, new_ctx->pwd);
	LASSERTF(current->fs->pwd.mnt == new_ctx->pwdmnt, "%p != %p\n",
		 current->fs->pwd.mnt, new_ctx->pwdmnt);

	set_fs(saved->fs);
	ll_set_fs_pwd(current->fs, saved->pwdmnt, saved->pwd);

	dput(saved->pwd);
	mntput(saved->pwdmnt);
	current->fs->umask = saved->umask;
}
EXPORT_SYMBOL(pop_ctxt);
