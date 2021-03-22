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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_object for LOVSUB layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include "lov_cl_internal.h"

/** \addtogroup lov
 *  @{
 */

/*****************************************************************************
 *
 * Lovsub object operations.
 *
 */

static int lovsub_object_init(const struct lu_env *env, struct lu_object *obj,
			      const struct lu_object_conf *conf)
{
	struct lovsub_device *dev = lu2lovsub_dev(obj->lo_dev);
	struct lu_object *below;
	struct lu_device *under;
	int result;

	ENTRY;
	under = &dev->acid_next->cd_lu_dev;
	below = under->ld_ops->ldo_object_alloc(env, obj->lo_header, under);
	if (below) {
		lu_object_add(obj, below);
		cl_object_page_init(lu2cl(obj), 0);
		result = 0;
	} else
		result = -ENOMEM;
	RETURN(result);

}

static void lovsub_object_free_rcu(struct rcu_head *head)
{
	struct lovsub_object *los = container_of(head, struct lovsub_object,
						 lso_header.coh_lu.loh_rcu);

	kmem_cache_free(lovsub_object_kmem, los);
}

static void lovsub_object_free(const struct lu_env *env, struct lu_object *obj)
{
	struct lovsub_object *los = lu2lovsub(obj);
	struct lov_object *lov = los->lso_super;

	ENTRY;

	/*
	 * We can't assume lov was assigned here, because of the shadow
	 * object handling in lu_object_find.
	 */
	if (lov) {
		int index = lov_comp_entry(los->lso_index);
		int stripe = lov_comp_stripe(los->lso_index);
		struct lov_layout_raid0 *r0 = lov_r0(lov, index);

		LASSERT(lov->lo_type == LLT_COMP);
		LASSERT(r0->lo_sub[stripe] == los);
		spin_lock(&r0->lo_sub_lock);
		r0->lo_sub[stripe] = NULL;
		spin_unlock(&r0->lo_sub_lock);
	}

	lu_object_fini(obj);
	lu_object_header_fini(&los->lso_header.coh_lu);
	OBD_FREE_PRE(los, sizeof(*los), "slab-freed");
	call_rcu(&los->lso_header.coh_lu.loh_rcu, lovsub_object_free_rcu);
	EXIT;
}

static int lovsub_object_print(const struct lu_env *env, void *cookie,
			       lu_printer_t p, const struct lu_object *obj)
{
	struct lovsub_object *los = lu2lovsub(obj);

	return (*p)(env, cookie, "[%d]", los->lso_index);
}

static int lovsub_attr_update(const struct lu_env *env, struct cl_object *obj,
			      const struct cl_attr *attr, unsigned valid)
{
	struct lovsub_object *los = cl2lovsub(obj);
	struct lov_object *lov = cl2lovsub(obj)->lso_super;

	ENTRY;
	lov_r0(lov, lov_comp_entry(los->lso_index))->lo_attr_valid = 0;
	RETURN(0);
}

static int lovsub_object_glimpse(const struct lu_env *env,
				 const struct cl_object *obj,
				 struct ost_lvb *lvb)
{
	struct lovsub_object *los = cl2lovsub(obj);

	ENTRY;
	RETURN(cl_object_glimpse(env, &los->lso_super->lo_cl, lvb));
}

/**
 * Implementation of struct cl_object_operations::coo_req_attr_set() for lovsub
 * layer. Lov and lovsub are responsible only for struct obdo::o_stripe_idx
 * field, which is filled there.
 */
static void lovsub_req_attr_set(const struct lu_env *env, struct cl_object *obj,
				struct cl_req_attr *attr)
{
	struct lovsub_object *subobj = cl2lovsub(obj);
	struct lov_stripe_md *lsm = subobj->lso_super->lo_lsm;

	ENTRY;
	cl_req_attr_set(env, &subobj->lso_super->lo_cl, attr);

	/*
	 * There is no OBD_MD_* flag for obdo::o_stripe_idx, so set it
	 * unconditionally. It never changes anyway.
	 */
	attr->cra_oa->o_stripe_idx = lov_comp_stripe(subobj->lso_index);
	lov_lsm2layout(lsm, lsm->lsm_entries[lov_comp_entry(subobj->lso_index)],
		       &attr->cra_oa->o_layout);
	attr->cra_oa->o_valid |= OBD_MD_FLOSTLAYOUT;
	EXIT;
}

static const struct cl_object_operations lovsub_ops = {
	.coo_attr_update  = lovsub_attr_update,
	.coo_glimpse      = lovsub_object_glimpse,
	.coo_req_attr_set = lovsub_req_attr_set
};

static const struct lu_object_operations lovsub_lu_obj_ops = {
	.loo_object_init      = lovsub_object_init,
	.loo_object_delete    = NULL,
	.loo_object_release   = NULL,
	.loo_object_free      = lovsub_object_free,
	.loo_object_print     = lovsub_object_print,
	.loo_object_invariant = NULL
};

struct lu_object *lovsub_object_alloc(const struct lu_env *env,
				      const struct lu_object_header *unused,
				      struct lu_device *dev)
{
	struct lovsub_object *los;
	struct lu_object     *obj;

	ENTRY;
	OBD_SLAB_ALLOC_PTR_GFP(los, lovsub_object_kmem, GFP_NOFS);
	if (los) {
		struct cl_object_header *hdr;

		obj = lovsub2lu(los);
		hdr = &los->lso_header;
		cl_object_header_init(hdr);
		lu_object_init(obj, &hdr->coh_lu, dev);
		lu_object_add_top(&hdr->coh_lu, obj);
		los->lso_cl.co_ops = &lovsub_ops;
		obj->lo_ops = &lovsub_lu_obj_ops;
	} else
		obj = NULL;
	RETURN(obj);
}

/** @} lov */
