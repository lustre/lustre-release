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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_oi.h
 *
 * OSD Object Index
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
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
#include <lustre_fid.h>
#include <lu_object.h>
#include <md_object.h>

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
        struct dt_object *oi_dir;
};

/*
 * Storage cookie. Datum uniquely identifying inode on the underlying file
 * system.
 *
 * XXX Currently this is ext2/ext3/ldiskfs specific thing. In the future this
 * should be generalized to work with other local file systems.
 */
struct osd_inode_id {
        __u32 oii_ino; /* inode number */
        __u32 oii_gen; /* inode generation */
};

int osd_oi_mod_init(void);
int osd_oi_init(struct osd_thread_info *info,
                struct osd_oi **oi_table,
                struct dt_device *dev,
                struct md_device *mdev);
void osd_oi_fini(struct osd_thread_info *info,
                 struct osd_oi **oi_table, unsigned oi_count);

int  osd_oi_lookup(struct osd_thread_info *info, struct osd_oi *oi,
                   const struct lu_fid *fid, struct osd_inode_id *id);
int  osd_oi_insert(struct osd_thread_info *info, struct osd_oi *oi,
                   const struct lu_fid *fid, const struct osd_inode_id *id,
                   struct thandle *th, int ingore_quota);
int  osd_oi_delete(struct osd_thread_info *info,
                   struct osd_oi *oi, const struct lu_fid *fid,
                   struct thandle *th);

#endif /* __KERNEL__ */
#endif /* _OSD_OI_H */
