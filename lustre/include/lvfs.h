/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * lustre VFS/process permission interface
 */

#ifndef __LVFS_H__
#define __LVFS_H__

#define LL_FID_NAMELEN (16 + 1 + 8 + 1)

#include <libcfs/libcfs.h>
#if defined(__linux__)
#include <linux/lvfs.h>
#elif defined(__APPLE__)
#include <darwin/lvfs.h>
#elif defined(__WINNT__)
#include <winnt/lvfs.h>
#else
#error Unsupported operating system.
#endif

#include <lustre_ucache.h>


#ifdef LIBLUSTRE
#include <lvfs_user_fs.h>
#endif

/* lvfs_common.c */
struct dentry *lvfs_fid2dentry(struct lvfs_run_ctxt *, __u64, __u32, __u64 ,void *data);

void push_ctxt(struct lvfs_run_ctxt *save, struct lvfs_run_ctxt *new_ctx,
               struct lvfs_ucred *cred);
void pop_ctxt(struct lvfs_run_ctxt *saved, struct lvfs_run_ctxt *new_ctx,
              struct lvfs_ucred *cred);


static inline int ll_fid2str(char *str, __u64 id, __u32 generation)
{
        return sprintf(str, "%llx:%08x", (unsigned long long)id, generation);
}

#endif
