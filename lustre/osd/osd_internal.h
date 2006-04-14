/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/osd/osd_internal.h
 *  Shared definitions and declarations for osd module
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

#ifndef _OSD_INTERNAL_H
#define _OSD_INTERNAL_H

#if defined(__KERNEL__)

/* struct rw_semaphore */
#include <linux/rwsem.h>

#include <linux/lu_object.h>

struct dentry;

struct osd_object {
        struct dt_object     oo_dt;
        /*
         * Dentry for file system object represented by this osd_object. This
         * dentry is pinned for the whole duration of lu_object life.
         */
        struct dentry       *oo_dentry;
        struct rw_semaphore  oo_sem;
};

struct osd_device {
        struct dt_device          od_dt_dev;
        struct lustre_mount_info *od_mount;
        struct dentry            *od_objdir;
};

static inline struct osd_object * dt2osd_obj(struct dt_object *o)
{
        return container_of(o, struct osd_object, oo_dt);
}

static inline struct osd_device * osd_obj2dev(struct osd_object *o) {
        struct lu_device *lu = o->oo_dt.do_lu.lo_dev;
        struct dt_device *dt = container_of(lu, struct dt_device, dd_lu_dev);

        return container_of(dt, struct osd_device, od_dt_dev);
}

static inline struct osd_device * dt2osd_dev(struct dt_device *dt) {
        return container_of(dt, struct osd_device, od_dt_dev);
}

static inline struct osd_device * lu2osd_dev(struct lu_device *d) {
        return dt2osd_dev(container_of(d, struct dt_device, dd_lu_dev));
}

static inline struct lu_device * osd2lu_dev(struct osd_device * osd)
{
        return &osd->od_dt_dev.dd_lu_dev;
}

#endif /* __KERNEL__ */
#endif /* _OSD_INTERNAL_H */
