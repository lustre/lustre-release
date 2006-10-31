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
/*
 * Object Index (oi) service runs in the bottom layer of server stack. In
 * translates fid local to this service to the storage cookie that uniquely
 * and efficiently identifies object (inode) of the underlying file system.
 */

#ifndef _OSD_OI_H
#define _OSD_OI_H

#if defined(__KERNEL__)

/* struct rw_semaphore */
#include <linux/rwsem.h>
#include <lu_object.h>

struct lu_fid;
struct osd_thread_info;
struct lu_site;
struct thandle;

struct dt_device;


/*
 * Object Index (oi) instance.
 */
struct osd_oi {
        /*
         * underlying index object, where fid->id mapping in stored.
         */
        struct dt_object    *oi_dir;
};

/*
 * Storage cookie. Datum uniquely identifying inode on the underlying file
 * system.
 *
 * XXX Currently this is ext2/ext3/ldiskfs specific thing. In the future this
 * should be generalized to work with other local file systems.
 */
struct osd_inode_id {
        __u64 oii_ino; /* inode number */
        __u32 oii_gen; /* inode generation */
        __u32 oii_pad; /* alignment padding */
};

int  osd_oi_init(struct osd_thread_info *info,
                 struct osd_oi *oi, struct dt_device *dev);
void osd_oi_fini(struct osd_thread_info *info, struct osd_oi *oi);

int  osd_oi_lookup(struct osd_thread_info *info, struct osd_oi *oi,
                   const struct lu_fid *fid, struct osd_inode_id *id);
int  osd_oi_insert(struct osd_thread_info *info, struct osd_oi *oi,
                   const struct lu_fid *fid, const struct osd_inode_id *id,
                   struct thandle *th);
int  osd_oi_delete(struct osd_thread_info *info,
                   struct osd_oi *oi, const struct lu_fid *fid,
                   struct thandle *th);

#endif /* __KERNEL__ */
#endif /* _OSD_OI_H */
