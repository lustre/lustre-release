/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/osd/osd_oi.h
 *  OSD Object Index
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef _OSD_OI_H
#define _OSD_OI_H

#if defined(__KERNEL__)

/* struct rw_semaphore */
#include <linux/rwsem.h>
#include <lu_object.h>

struct dentry;
struct lu_fid;
struct osd_thread_info;
struct lu_site;
struct thandle;

struct osd_oi {
        struct dentry       *oi_dir;
        struct rw_semaphore  oi_lock;
        struct lu_site      *oi_site;
};

struct osd_inode_id {
        __u64 oii_ino;
        __u32 oii_gen;
};

enum {
        OSD_GEN_IGNORE = (__u32)~0
};

int  osd_oi_init(struct osd_oi *oi, struct dentry *root, struct lu_site *s);
void osd_oi_fini(struct osd_oi *oi);

void osd_oi_read_lock(struct osd_oi *oi);
void osd_oi_read_unlock(struct osd_oi *oi);
void osd_oi_write_lock(struct osd_oi *oi);
void osd_oi_write_unlock(struct osd_oi *oi);

int  osd_oi_lookup(struct osd_thread_info *info, struct osd_oi *oi,
                   const struct lu_fid *fid, struct osd_inode_id *id);
int  osd_oi_insert(struct osd_thread_info *info, struct osd_oi *oi,
                   const struct lu_fid *fid, const struct osd_inode_id *id,
                   struct thandle *th);
int  osd_oi_delete(struct osd_thread_info *info,
                   struct osd_oi *oi, const struct lu_fid *fid,
                   struct thandle *th);

#define OI_IN_MEMORY (1)

#endif /* __KERNEL__ */
#endif /* _OSD_OI_H */
