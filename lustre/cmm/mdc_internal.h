/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
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

#ifndef _CMM_MDC_INTERNAL_H
#define _CMM_MDC_INTERNAL_H

#if defined(__KERNEL__)

#include <obd.h>
#include <md_object.h>

struct mdc_cli_desc {
        struct obd_connect_data  cl_conn_data;
        struct obd_uuid          cl_srv_uuid;
        struct obd_uuid          cl_cli_uuid;
        struct obd_export        *cl_exp;
};

struct mdc_device {
        struct md_device        mc_md_dev;
        /* other MD servers in cluster */
        struct list_head        mc_linkage;
        __u32                   mc_num;
        struct mdc_cli_desc     mc_desc;
};

struct mdc_object {
	struct md_object        mco_obj;
};

static inline struct lu_device *mdc2lu_dev(struct mdc_device *mc)
{
	return (&mc->mc_md_dev.md_lu_dev);
}

static inline struct mdc_device *md2mdc_dev(struct md_device *md)
{
        return container_of0(md, struct mdc_device, mc_md_dev);
}

static inline struct mdc_device *mdc_obj2dev(struct mdc_object *mco)
{
	return (md2mdc_dev(md_device_get(&mco->mco_obj)));
}

static inline struct mdc_object *lu2mdc_obj(struct lu_object *lo)
{
	return container_of0(lo, struct mdc_object, mco_obj.mo_lu);
}

static inline struct mdc_object *md2mdc_obj(struct md_object *mo)
{
	return container_of0(mo, struct mdc_object, mco_obj);
}

static inline struct mdc_device *lu2mdc_dev(struct lu_device *ld)
{
	return container_of0(ld, struct mdc_device, mc_md_dev.md_lu_dev);
}

int mdc_object_init(const struct lu_context *, struct lu_object*);
struct lu_object *mdc_object_alloc(const struct lu_context *,
                                   struct lu_device *);
void mdc_object_free(const struct lu_context *, struct lu_object *);
void mdc_object_release(const struct lu_context *, struct lu_object *);

#endif /* __KERNEL__ */
#endif /* _CMM_MDC_INTERNAL_H */
