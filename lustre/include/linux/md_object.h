/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 * 
 *  Extention of lu_object.h for metadata objects
 *  
 *  Copyright (C) 2006 Cluster File Systems, Inc.
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
 */

#ifndef _LINUX_MD_OBJECT_H
#define _LINUX_MD_OBJECT_H

#include <linux/lu_object.h>

struct md_device;
struct md_device_operations;
struct md_object;

struct md_device_operations {
        /* get root FID */
        int (*mdo_root_get)(struct md_device *m, struct ll_fid *f);
        /* metadata API */
        int (*mdo_mkdir)(struct md_object *o, const char *name,
                         struct md_object *child);
};

struct md_device {
        struct lu_device             md_lu_dev;
        struct md_device_operations *md_ops;
};

struct md_object {
        struct lu_object mo_lu;
};

static inline int lu_device_is_md(struct lu_device *d)
{
        return d->ld_type->ldt_tags & LU_DEVICE_MD;
}

static inline struct md_object *lu2md(struct lu_object *o)
{
        LASSERT(lu_device_is_md(o->lo_dev));
        return container_of(o, struct md_object, mo_lu);
}

static inline struct md_device *md_device_get(struct md_object *o)
{
        LASSERT(lu_device_is_md(o->mo_lu.lo_dev));
        return container_of(o->mo_lu.lo_dev, struct md_device, md_lu_dev);
}

static int md_device_init(struct md_device *md, struct lu_device_type *t)
{
	return lu_device_init(&md->md_lu_dev, t);
}

static void md_device_fini(struct md_device *md)
{
	lu_device_fini(&md->md_lu_dev);
}
#endif /* _LINUX_MD_OBJECT_H */
