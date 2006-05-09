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

static int cmm_fld_lookup(struct lu_fid *fid)
{
        int rc;
        /* temporary hack for proto mkdir */
        rc = fid_seq(fid) == LUSTRE_ROOT_FID_SEQ ? 0 : 1;
        RETURN(0);
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

struct lu_object *cmm_object_alloc(struct lu_context *ctx,
                                   struct lu_device *d)
{
	struct cmm_object *mo;
        ENTRY;

	OBD_ALLOC_PTR(mo);
	if (mo != NULL) {
		struct lu_object *o;

		o = &mo->cmo_obj.mo_lu;
                lu_object_init(o, NULL, d);
                mo->cmo_obj.mo_ops = &cmm_mo_ops;
                mo->cmo_obj.mo_dir_ops = &cmm_dir_ops;
                o->lo_ops = &cmm_obj_ops;
		RETURN(o);
	} else
		RETURN(NULL);
}

int cmm_object_init(struct lu_context *ctx, struct lu_object *o)
{
	struct cmm_device *d = lu2cmm_dev(o->lo_dev);
	struct lu_device  *under;
	struct lu_object  *below;
        struct lu_fid     *fid = &o->lo_header->loh_fid;
        int mdsnum;
        ENTRY;

        /* under device can be MDD or MDC */
        mdsnum = cmm_fld_lookup(fid);
        under = cmm_get_child(d, mdsnum);
        if (under == NULL)
                RETURN(-ENOENT);

        below = under->ld_ops->ldo_object_alloc(ctx, under);
	if (below != NULL) {
                struct cmm_object *co = lu2cmm_obj(o);

		lu_object_add(o, below);
                co->cmo_num = mdsnum;
		RETURN(0);
	} else
		RETURN(-ENOMEM);
}

void cmm_object_free(struct lu_context *ctx, struct lu_object *o)
{
        struct cmm_object *mo = lu2cmm_obj(o);
	lu_object_fini(o);
        OBD_FREE_PTR(mo);
}

void cmm_object_release(struct lu_context *ctx, struct lu_object *o)
{
        return;
}

static int cmm_object_exists(struct lu_context *ctx, struct lu_object *o)
{
        return lu_object_exists(ctx, lu_object_next(o));
}

static int cmm_object_print(struct lu_context *ctx,
                            struct seq_file *f, const struct lu_object *o)
{
	return seq_printf(f, LUSTRE_CMM0_NAME"-object@%p", o);
}

/* Metadata API */
static int cmm_object_create(struct lu_context *ctx,
                             struct md_object *mo, struct lu_attr *attr)
{
        struct cmm_object *cmo = md2cmm_obj(mo);
        struct md_object  *nxo = cmm2child_obj(cmo);
        int rc;

        ENTRY;

        LASSERT (cmm_is_local_obj(cmo));

        rc = nxo->mo_ops->moo_object_create(ctx, nxo, attr);

        RETURN(rc);
}
int cmm_mkdir(struct lu_context *ctx, struct lu_attr *attr,
              struct md_object *p, const char *name, struct md_object *c)
{
	struct cmm_object *cmm_p = md2cmm_obj(p);
        struct cmm_object *cmm_c = md2cmm_obj(c);
        struct md_object  *local = cmm2child_obj(cmm_p);
        int rc;

        ENTRY;

        if (cmm_is_local_obj(cmm_c)) {
                /* fully local mkdir */
                rc = local->mo_dir_ops->mdo_mkdir(ctx, attr, local, name,
                                                      cmm2child_obj(cmm_c));
        } else {
                struct lu_fid *fid = &c->mo_lu.lo_header->loh_fid;
                struct md_object *remote = cmm2child_obj(cmm_c);

                /* remote object creation and local name insert */
                rc = remote->mo_ops->moo_object_create(ctx, remote, attr);
                if (rc == 0) {
                        rc = local->mo_dir_ops->mdo_name_insert(ctx, local,
                                                                name, fid,
                                                                attr);
                }
        }

        RETURN(rc);
}

int cmm_attr_get(struct lu_context *ctx, struct md_object *obj,
                 struct lu_attr *attr)
{
        struct md_object *next = cmm2child_obj(md2cmm_obj(obj));

        return next->mo_ops->moo_attr_get(ctx, next, attr);
}

static struct md_dir_operations cmm_dir_ops = {
        .mdo_mkdir         = cmm_mkdir,
};

static struct md_object_operations cmm_mo_ops = {
        .moo_attr_get      = cmm_attr_get,
        .moo_object_create = cmm_object_create,

};

static struct lu_object_operations cmm_obj_ops = {
	.loo_object_init    = cmm_object_init,
	.loo_object_release = cmm_object_release,
	.loo_object_print   = cmm_object_print,
	.loo_object_exists  = cmm_object_exists
};

