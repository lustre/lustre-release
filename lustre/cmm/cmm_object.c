/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/cmm_object.c
 *  Lustre Cluster Metadata Manager (cmm)
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Mike Pershin <tappro@clusterfs.com>
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_MDS

#include "cmm_internal.h"
#include "mdc_internal.h"

static struct md_object_operations cmm_mo_ops;
static struct md_dir_operations    cmm_dir_ops;
static struct lu_object_operations cmm_obj_ops;

static int cmm_fld_lookup(const struct lu_fid *fid)
{
        int rc;
        /* temporary hack for proto mkdir */
        rc = (unsigned long)fid_seq(fid) / LUSTRE_SEQ_RANGE;
        CWARN("Get MDS %d for sequence: "LPU64"\n", rc, fid_seq(fid));
        RETURN(rc);
}

/* get child device by mdsnum*/
static struct lu_device *cmm_get_child(struct cmm_device *d, __u32 num)
{
        struct lu_device *next = NULL;
        ENTRY;
        if (likely(num == d->cmm_local_num)) {
	        next = &d->cmm_child->md_lu_dev;
        } else {
                struct mdc_device *mdc;
                list_for_each_entry(mdc, &d->cmm_targets, mc_linkage) {
                        if (mdc->mc_num == num) {
                                next = mdc2lu_dev(mdc);
                                break;
                        }
                }
        }
        RETURN(next);
}

struct lu_object *cmm_object_alloc(const struct lu_context *ctx,
                                   struct lu_device *ld)
{
        struct cmm_object *co;
        struct lu_object  *lo;
        ENTRY;

        OBD_ALLOC_PTR(co);
	if (co != NULL) {
		lo = &co->cmo_obj.mo_lu;
                lu_object_init(lo, NULL, ld);
                co->cmo_obj.mo_ops = &cmm_mo_ops;
                co->cmo_obj.mo_dir_ops = &cmm_dir_ops;
                lo->lo_ops = &cmm_obj_ops;
        } else
                lo = NULL;

        RETURN(lo);
}

void cmm_object_free(const struct lu_context *ctx, struct lu_object *lo)
{
        struct cmm_object *co = lu2cmm_obj(lo);
        lu_object_fini(lo);
        OBD_FREE_PTR(co);
}

int cmm_object_init(const struct lu_context *ctx, struct lu_object *lo)
{
        struct cmm_device *cd = lu2cmm_dev(lo->lo_dev);
        struct lu_device  *c_dev;
        struct lu_object  *c_obj;
        const struct lu_fid *fid = lu_object_fid(lo);
        int mdsnum, rc;

        ENTRY;

        /* under device can be MDD or MDC */
        mdsnum = cmm_fld_lookup(fid);
        c_dev = cmm_get_child(cd, mdsnum);
        if (c_dev == NULL) {
                rc = -ENOENT;
        } else {
                c_obj = c_dev->ld_ops->ldo_object_alloc(ctx, c_dev);
                if (c_obj != NULL) {
                        struct cmm_object *co = lu2cmm_obj(lo);

                        lu_object_add(lo, c_obj);
                        co->cmo_num = mdsnum;
                        rc = 0;
                } else {
                        rc = -ENOMEM;
                }
        }

        RETURN(rc);
}

static int cmm_object_exists(const struct lu_context *ctx, struct lu_object *lo)
{
        return lu_object_exists(ctx, lu_object_next(lo));
}

static int cmm_object_print(const struct lu_context *ctx,
                            struct seq_file *f, const struct lu_object *lo)
{
	return seq_printf(f, LUSTRE_CMM0_NAME"-object@%p", lo);
}

static struct lu_object_operations cmm_obj_ops = {
	.loo_object_init    = cmm_object_init,
	.loo_object_print   = cmm_object_print,
	.loo_object_exists  = cmm_object_exists
};

/* md_object operations */
static int cmm_object_create(const struct lu_context *ctx, struct md_object *mo,
                             struct lu_attr *attr)
{
        struct md_object  *ch = cmm2child_obj(md2cmm_obj(mo));
        int rc;

        ENTRY;

        LASSERT (cmm_is_local_obj(md2cmm_obj(mo)));

        rc = mo_object_create(ctx, ch, attr);

        RETURN(rc);
}

static int cmm_attr_get(const struct lu_context *ctx, struct md_object *mo,
                        struct lu_attr *attr)
{
        struct md_object *ch = cmm2child_obj(md2cmm_obj(mo));
        int rc;

        ENTRY;

        LASSERT (cmm_is_local_obj(md2cmm_obj(mo)));

        rc = mo_attr_get(ctx, ch, attr);

        RETURN(rc);
}

static struct md_object_operations cmm_mo_ops = {
        .moo_attr_get      = cmm_attr_get,
        .moo_object_create = cmm_object_create,
};

static int cmm_lookup(const struct lu_context *ctx, struct md_object *mo_p,
                      const char *name, struct lu_fid *lf)
{
        struct md_object *ch_p = cmm2child_obj(md2cmm_obj(mo_p));
        int rc;

        ENTRY;

        LASSERT(cmm_is_local_obj(md2cmm_obj(mo_p)));

        rc = mdo_lookup(ctx, ch_p, name, lf);

        RETURN(rc);

}

static int cmm_mkdir(const struct lu_context *ctx, struct lu_attr *attr,
                     struct md_object *mo_p, const char *name,
                     struct md_object *mo_c)
{
	struct md_object *ch_c = cmm2child_obj(md2cmm_obj(mo_c));
        struct md_object *ch_p = cmm2child_obj(md2cmm_obj(mo_p));
        int rc;

        ENTRY;

        if (cmm_is_local_obj(md2cmm_obj(mo_c))) {
                /* fully local mkdir */
                rc = mdo_mkdir(ctx, attr, ch_p, name, ch_c);
        } else {
                const struct lu_fid *lf = lu_object_fid(&mo_c->mo_lu);

                /* remote object creation and local name insert */
                rc = mo_object_create(ctx, ch_c, attr);
                if (rc == 0) {
                        rc = mdo_name_insert(ctx, ch_p, name, lf, attr);
                }
        }

        RETURN(rc);
}

static struct md_dir_operations cmm_dir_ops = {
        .mdo_lookup        = cmm_lookup,
        .mdo_mkdir         = cmm_mkdir,
};



