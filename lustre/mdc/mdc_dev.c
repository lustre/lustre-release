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

int mdc_page_init(const struct lu_env *env, struct cl_object *obj,
		  struct cl_page *page, pgoff_t index)
{
	return -ENOTSUPP;
}

int mdc_lock_init(const struct lu_env *env,
		  struct cl_object *obj, struct cl_lock *lock,
		  const struct cl_io *unused)
{
	return -ENOTSUPP;
}

int mdc_io_init(const struct lu_env *env,
		struct cl_object *obj, struct cl_io *io)
{
	return -ENOTSUPP;
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
	.coo_page_init = mdc_page_init,
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
