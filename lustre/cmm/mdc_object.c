/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/mdc_object.c
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

#include "mdc_internal.h"

static struct md_object_operations mdc_mo_ops;
static struct md_dir_operations mdc_dir_ops;
static struct lu_object_operations mdc_obj_ops;

struct lu_object *mdc_object_alloc(struct lu_context *ctx,
                                   struct lu_device *ld)
{
	struct mdc_object *mco;
        ENTRY;

	OBD_ALLOC_PTR(mco);
	if (mco != NULL) {
		struct lu_object *lo;

		lo = &mco->mco_obj.mo_lu;
                lu_object_init(lo, NULL, ld);
                mco->mco_obj.mo_ops = &mdc_mo_ops;
                mco->mco_obj.mo_dir_ops = &mdc_dir_ops;
                lo->lo_ops = &mdc_obj_ops;
                RETURN(lo);
	} else
		RETURN(NULL);
}

int mdc_object_init(struct lu_context *ctxt, struct lu_object *lo)
{
	//struct mdc_device *d = lu2mdc_dev(o->lo_dev);
	//struct lu_device  *under;
        //struct lu_fid     *fid = &o->lo_header->loh_fid;
       
        ENTRY;

        RETURN(0);
}

void mdc_object_free(struct lu_context *ctx, struct lu_object *lo)
{
        struct mdc_object *mco = lu2mdc_obj(lo);
	lu_object_fini(lo);
        OBD_FREE_PTR(mco);
}

void mdc_object_release(struct lu_context *ctxt, struct lu_object *lo)
{
        return;
}

static int mdc_object_exists(struct lu_context *ctx, struct lu_object *lo)
{
        return 0;
}

static int mdc_object_print(struct lu_context *ctx,
                            struct seq_file *f, const struct lu_object *lo)
{
	return seq_printf(f, LUSTRE_MDC0_NAME"-object@%p", lo);
}

static struct md_dir_operations mdc_dir_ops = {
};

static struct md_object_operations mdc_mo_ops = {
};

static struct lu_object_operations mdc_obj_ops = {
        .loo_object_init    = mdc_object_init,
	.loo_object_release = mdc_object_release,
	.loo_object_print   = mdc_object_print,
	.loo_object_exists  = mdc_object_exists
};

