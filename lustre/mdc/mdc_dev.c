/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017 Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_device, cl_req for MDC layer.
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDC

#include <obd_class.h>
#include <lustre_osc.h>

#include "mdc_internal.h"

int mdc_lock_init(const struct lu_env *env,
		  struct cl_object *obj, struct cl_lock *lock,
		  const struct cl_io *unused)
{
	return 0;
}

/**
 * IO operations.
 *
 * An implementation of cl_io_operations specific methods for MDC layer.
 *
 */
static int mdc_async_upcall(void *a, int rc)
{
	struct osc_async_cbargs *args = a;

	args->opc_rc = rc;
	complete(&args->opc_sync);
	return 0;
}

static int mdc_io_setattr_start(const struct lu_env *env,
				const struct cl_io_slice *slice)
{
	struct cl_io *io = slice->cis_io;
	struct osc_io *oio = cl2osc_io(env, slice);
	struct cl_object *obj = slice->cis_obj;
	struct lov_oinfo *loi = cl2osc(obj)->oo_oinfo;
	struct cl_attr *attr = &osc_env_info(env)->oti_attr;
	struct obdo *oa = &oio->oi_oa;
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	__u64 size = io->u.ci_setattr.sa_attr.lvb_size;
	unsigned int ia_valid = io->u.ci_setattr.sa_valid;
	int rc;

	/* silently ignore non-truncate setattr for Data-on-MDT object */
	if (cl_io_is_trunc(io)) {
		/* truncate cache dirty pages first */
		rc = osc_cache_truncate_start(env, cl2osc(obj), size,
					      &oio->oi_trunc);
		if (rc < 0)
			return rc;
	}

	if (oio->oi_lockless == 0) {
		cl_object_attr_lock(obj);
		rc = cl_object_attr_get(env, obj, attr);
		if (rc == 0) {
			struct ost_lvb *lvb = &io->u.ci_setattr.sa_attr;
			unsigned int cl_valid = 0;

			if (ia_valid & ATTR_SIZE) {
				attr->cat_size = attr->cat_kms = size;
				cl_valid = (CAT_SIZE | CAT_KMS);
			}
			if (ia_valid & ATTR_MTIME_SET) {
				attr->cat_mtime = lvb->lvb_mtime;
				cl_valid |= CAT_MTIME;
			}
			if (ia_valid & ATTR_ATIME_SET) {
				attr->cat_atime = lvb->lvb_atime;
				cl_valid |= CAT_ATIME;
			}
			if (ia_valid & ATTR_CTIME_SET) {
				attr->cat_ctime = lvb->lvb_ctime;
				cl_valid |= CAT_CTIME;
			}
			rc = cl_object_attr_update(env, obj, attr, cl_valid);
		}
		cl_object_attr_unlock(obj);
		if (rc < 0)
			return rc;
	}

	if (!(ia_valid & ATTR_SIZE))
		return 0;

	memset(oa, 0, sizeof(*oa));
	oa->o_oi = loi->loi_oi;
	oa->o_mtime = attr->cat_mtime;
	oa->o_atime = attr->cat_atime;
	oa->o_ctime = attr->cat_ctime;

	oa->o_size = size;
	oa->o_blocks = OBD_OBJECT_EOF;
	oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP | OBD_MD_FLATIME |
		      OBD_MD_FLCTIME | OBD_MD_FLMTIME | OBD_MD_FLSIZE |
		      OBD_MD_FLBLOCKS;
	if (oio->oi_lockless) {
		oa->o_flags = OBD_FL_SRVLOCK;
		oa->o_valid |= OBD_MD_FLFLAGS;
	}

	init_completion(&cbargs->opc_sync);

	rc = osc_punch_send(osc_export(cl2osc(obj)), oa,
			    mdc_async_upcall, cbargs);
	cbargs->opc_rpc_sent = rc == 0;
	return rc;
}

static struct cl_io_operations mdc_io_ops = {
	.op = {
		[CIT_READ] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start     = osc_io_read_start,
		},
		[CIT_WRITE] = {
			.cio_iter_init = osc_io_write_iter_init,
			.cio_iter_fini = osc_io_write_iter_fini,
			.cio_start     = osc_io_write_start,
			.cio_end       = osc_io_end,
		},
		[CIT_SETATTR] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start     = mdc_io_setattr_start,
			.cio_end       = osc_io_setattr_end,
		},
		/* no support for data version so far */
		[CIT_DATA_VERSION] = {
			.cio_start = NULL,
			.cio_end   = NULL,
		},
		[CIT_FAULT] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start     = osc_io_fault_start,
			.cio_end       = osc_io_end,
		},
		[CIT_FSYNC] = {
			.cio_start = osc_io_fsync_start,
			.cio_end   = osc_io_fsync_end,
		},
	},
	.cio_submit	  = osc_io_submit,
	.cio_commit_async = osc_io_commit_async,
};

int mdc_io_init(const struct lu_env *env, struct cl_object *obj,
		struct cl_io *io)
{
	struct osc_io *oio = osc_env_io(env);

	CL_IO_SLICE_CLEAN(oio, oi_cl);
	cl_io_slice_add(io, &oio->oi_cl, obj, &mdc_io_ops);
	return 0;
}

/**
 * Implementation of struct cl_req_operations::cro_attr_set() for MDC
 * layer. MDC is responsible for struct obdo::o_id and struct obdo::o_seq
 * fields.
 */
static void mdc_req_attr_set(const struct lu_env *env, struct cl_object *obj,
			     struct cl_req_attr *attr)
{
	u64 flags = attr->cra_flags;

	/* Copy object FID to cl_attr */
	attr->cra_oa->o_oi.oi_fid = *lu_object_fid(&obj->co_lu);

	if (flags & OBD_MD_FLGROUP)
		attr->cra_oa->o_valid |= OBD_MD_FLGROUP;

	if (flags & OBD_MD_FLID)
		attr->cra_oa->o_valid |= OBD_MD_FLID;
}

static const struct cl_object_operations mdc_ops = {
	.coo_page_init = osc_page_init,
	.coo_lock_init = mdc_lock_init,
	.coo_io_init = mdc_io_init,
	.coo_attr_get = osc_attr_get,
	.coo_attr_update = osc_attr_update,
	.coo_glimpse = osc_object_glimpse,
	.coo_req_attr_set = mdc_req_attr_set,
};

static int mdc_object_init(const struct lu_env *env, struct lu_object *obj,
			   const struct lu_object_conf *conf)
{
	struct osc_object *osc = lu2osc(obj);

	if (osc->oo_initialized)
		return 0;

	osc->oo_initialized = true;

	return osc_object_init(env, obj, conf);
}

static void mdc_object_free(const struct lu_env *env, struct lu_object *obj)
{
	osc_object_free(env, obj);
}

static const struct lu_object_operations mdc_lu_obj_ops = {
	.loo_object_init = mdc_object_init,
	.loo_object_delete = NULL,
	.loo_object_release = NULL,
	.loo_object_free = mdc_object_free,
	.loo_object_print = osc_object_print,
	.loo_object_invariant = NULL
};

struct lu_object *mdc_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *unused,
				   struct lu_device *dev)
{
	struct osc_object *osc;
	struct lu_object  *obj;

	OBD_SLAB_ALLOC_PTR_GFP(osc, osc_object_kmem, GFP_NOFS);
	if (osc != NULL) {
		obj = osc2lu(osc);
		lu_object_init(obj, NULL, dev);
		osc->oo_cl.co_ops = &mdc_ops;
		obj->lo_ops = &mdc_lu_obj_ops;
		osc->oo_initialized = false;
	} else {
		obj = NULL;
	}
	return obj;
}

static int mdc_cl_process_config(const struct lu_env *env,
				 struct lu_device *d, struct lustre_cfg *cfg)
{
	return mdc_process_config(d->ld_obd, 0, cfg);
}

const struct lu_device_operations mdc_lu_ops = {
	.ldo_object_alloc = mdc_object_alloc,
	.ldo_process_config = mdc_cl_process_config,
	.ldo_recovery_complete = NULL,
};

static struct lu_device *mdc_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct lu_device *d;
	struct osc_device *od;
	struct obd_device *obd;
	int rc;

	OBD_ALLOC_PTR(od);
	if (od == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	cl_device_init(&od->od_cl, t);
	d = osc2lu_dev(od);
	d->ld_ops = &mdc_lu_ops;

	/* Setup MDC OBD */
	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	if (obd == NULL)
		RETURN(ERR_PTR(-ENODEV));

	rc = mdc_setup(obd, cfg);
	if (rc < 0) {
		osc_device_free(env, d);
		RETURN(ERR_PTR(rc));
	}
	od->od_exp = obd->obd_self_export;
	RETURN(d);
}

static const struct lu_device_type_operations mdc_device_type_ops = {
	.ldto_device_alloc = mdc_device_alloc,
	.ldto_device_free = osc_device_free,
	.ldto_device_init = osc_device_init,
	.ldto_device_fini = osc_device_fini
};

struct lu_device_type mdc_device_type = {
	.ldt_tags = LU_DEVICE_CL,
	.ldt_name = LUSTRE_MDC_NAME,
	.ldt_ops = &mdc_device_type_ops,
	.ldt_ctx_tags = LCT_CL_THREAD
};

/** @} osc */
