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
#include <lustre/lustre_idl.h>
#include <obd_support.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <obd_class.h>
#include "mdc_internal.h"

static struct md_object_operations mdc_mo_ops;
static struct md_dir_operations mdc_dir_ops;
static struct lu_object_operations mdc_obj_ops;

struct lu_object *mdc_object_alloc(const struct lu_context *ctx,
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

int mdc_object_init(const struct lu_context *ctx, struct lu_object *lo)
{
	//struct mdc_device *d = lu2mdc_dev(o->lo_dev);
	//struct lu_device  *under;
        //const struct lu_fid     *fid = lu_object_fid(o);

        ENTRY;

        RETURN(0);
}

void mdc_object_free(const struct lu_context *ctx, struct lu_object *lo)
{
        struct mdc_object *mco = lu2mdc_obj(lo);
	lu_object_fini(lo);
        OBD_FREE_PTR(mco);
}

void mdc_object_release(const struct lu_context *ctx, struct lu_object *lo)
{
        return;
}

static int mdc_object_exists(const struct lu_context *ctx, struct lu_object *lo)
{
        return 0;
}

static int mdc_object_print(const struct lu_context *ctx,
                            struct seq_file *f, const struct lu_object *lo)
{
	return seq_printf(f, LUSTRE_MDC0_NAME"-object@%p", lo);
}

static int mdc_object_create(const struct lu_context *ctx,
                             struct md_object *mo, struct lu_attr *attr)
{
        struct mdc_device *mc = md2mdc_dev(md_device_get(mo));
        struct obd_export *exp = mc->mc_desc.cl_exp;
        struct ptlrpc_request *req;
        struct md_op_data op_data = {
                .fid1 = mo->mo_lu.lo_header->loh_fid,
                .fid2 = { 0 },
                .mod_time = attr->la_mtime,
                .name = NULL,
                .namelen = 0,
        };
        int rc;


#if 0
        req = ptlrpc_prep_req(mc->mc_desc.cl_import, LUSTRE_MDS_VERSION,
                              MDS_REINT, 1, &size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);
/*
        mdc_create_pack(req, MDS_REQ_REC_OFF, op_data, data, datalen, mode,
                        uid, gid, cap_effective, rdev);
*/
        rec = lustre_msg_buf(req->rq_reqmsg, MDS_REQ_REC_OFF, sizeof (*rec));
        rec->cr_opcode = REINT_CREATE;
        rec->cr_fsuid = attr->la_uid;
        rec->cr_fsgid = attr->la_gid;
        rec->cr_cap = 0;//cap_effective;
        rec->cr_fid1 = *lu_object_fid(&mo->mo_lu);
        memset(&rec->cr_fid2, 0, sizeof(rec->cr_fid2));
        rec->cr_mode = attr->la_mode;
        rec->cr_rdev = 0;//rdev;
        rec->cr_time = attr->la_mtime; //op_data->mod_time;
        rec->cr_suppgid = 0;//op_data->suppgids[0];


        size = sizeof(struct mdt_body);
        req->rq_replen = lustre_msg_size(1, &size);

        level = LUSTRE_IMP_FULL;
        req->rq_send_state = level;
        //mdc_get_rpc_lock(rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        //mdc_put_rpc_lock(rpc_lock, NULL);
        if (rc)
                CDEBUG(D_INFO, "error in handling %d\n", rc);
        else if (!lustre_swab_repbuf(req, 0, sizeof(struct mdt_body),
                                     lustre_swab_mdt_body)) {
                CERROR ("Can't unpack mdt_body\n");
                rc = -EPROTO;
        } else
                CDEBUG(D_INFO, "Done MDC req!\n");
#endif
        rc = md_create(exp, &op_data, NULL, 0, attr->la_mode, attr->la_uid,
                       attr->la_gid, 0, 0, &req);
        RETURN(rc);
}

static struct md_dir_operations mdc_dir_ops = {
};

static struct md_object_operations mdc_mo_ops = {
        .moo_object_create  = mdc_object_create
};

static struct lu_object_operations mdc_obj_ops = {
        .loo_object_init    = mdc_object_init,
	.loo_object_release = mdc_object_release,
	.loo_object_print   = mdc_object_print,
	.loo_object_exists  = mdc_object_exists
};

