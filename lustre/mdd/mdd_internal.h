/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *  mdd/mdd_internel.c
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Wang Di <wangdi@clusterfs.com>
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

#ifndef _MDD_INTERNAL_H
#define _MDD_INTERNAL_H

#include <asm/semaphore.h>
#include <md_object.h>

struct dt_device;

struct mdd_device {
        struct md_device                 mdd_md_dev;
        struct dt_device                *mdd_child;
        struct md_lov_info               mdd_lov_info;
        struct dt_device                 mdd_lov_dev;
        struct lu_fid                    mdd_root_fid;
        struct dt_device_param           mdd_dt_conf;
};

struct mdd_object {
        struct md_object  mod_obj;
};

struct mdd_thread_info {
        struct txn_param mti_param;
        struct lu_fid    mti_fid;
        struct lu_attr    mti_la;
        struct lov_desc  mti_ld;
        struct lov_mds_md mti_lmm;
};

int mdd_init_obd(const struct lu_context *ctxt, struct mdd_device *mdd,
                 char *dev);
int mdd_xattr_set_txn(const struct lu_context *ctxt, struct md_object *obj,
                      const void *buf, int buf_len, const char *name, int fl,
                      struct thandle *txn);
int mdd_lov_set_md(const struct lu_context *ctxt, struct md_object *pobj,
                   struct md_object *child, struct lov_mds_md *lmm,
                   int lmm_size, int mode, struct thandle *handle);
int mdd_lov_create(const struct lu_context *ctxt, struct mdd_device *mdd,
                   struct mdd_object *parent, struct mdd_object *child,
                   struct lov_mds_md **lmm, int *lmm_size,
                   const struct md_create_spec *spec, struct lu_attr *la);

int mdd_get_md(const struct lu_context *ctxt, struct md_object *obj,
               void *md, int *md_size);
int mdd_unlink_log(const struct lu_context *ctxt, struct mdd_device *mdd,
                   struct mdd_object *mdd_cobj, struct md_attr *ma);
struct mdd_thread_info *mdd_ctx_info(const struct lu_context *ctx);

extern struct lu_device_operations mdd_lu_ops;
static inline int lu_device_is_mdd(struct lu_device *d)
{
	return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &mdd_lu_ops);
}

static inline struct mdd_device* lu2mdd_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_mdd(d));
	return container_of0(d, struct mdd_device, mdd_md_dev.md_lu_dev);
}

static inline struct lu_device *mdd2lu_dev(struct mdd_device *d)
{
	return (&d->mdd_md_dev.md_lu_dev);
}

static inline struct mdd_object *lu2mdd_obj(struct lu_object *o)
{
	LASSERT(lu_device_is_mdd(o->lo_dev));
	return container_of0(o, struct mdd_object, mod_obj.mo_lu);
}

static inline struct mdd_device* mdo2mdd(struct md_object *mdo)
{
        return lu2mdd_dev(mdo->mo_lu.lo_dev);
}

static inline struct mdd_object* md2mdd_obj(struct md_object *mdo)
{
        return container_of0(mdo, struct mdd_object, mod_obj);
}

static inline struct dt_device_operations *mdd_child_ops(struct mdd_device *d)
{
        return d->mdd_child->dd_ops;
}

static inline struct lu_object *mdd2lu_obj(struct mdd_object *obj)
{
        return &obj->mod_obj.mo_lu;
}

static inline struct dt_object* mdd_object_child(struct mdd_object *o)
{
        return container_of0(lu_object_next(mdd2lu_obj(o)),
                             struct dt_object, do_lu);
}
static inline struct obd_device *mdd2_obd(struct mdd_device *mdd)
{
        return mdd->mdd_md_dev.md_lu_dev.ld_obd;
}

static inline const struct lu_fid *mdo2fid(const struct mdd_object *obj)
{
        return lu_object_fid(&obj->mod_obj.mo_lu);
}

int mdd_lov_mdsize(const struct lu_context *ctxt, struct mdd_device *mdd,
                   int *md_size);
int mdd_lov_cookiesize(const struct lu_context *ctxt, struct mdd_device *mdd,
                       int *cookie_size);
#endif
