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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_page for LOV layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include "lov_cl_internal.h"

/** \addtogroup lov
 *  @{
 */

/*****************************************************************************
 *
 * Lov page operations.
 *
 */

static int lov_comp_page_print(const struct lu_env *env,
			       const struct cl_page_slice *slice,
			       void *cookie, lu_printer_t printer)
{
	struct lov_page *lp = cl2lov_page(slice);

	return (*printer)(env, cookie,
			  LUSTRE_LOV_NAME"-page@%p\n", lp);
}

static const struct cl_page_operations lov_comp_page_ops = {
	.cpo_print = lov_comp_page_print
};

int lov_page_init_composite(const struct lu_env *env, struct cl_object *obj,
			    struct cl_page *page, pgoff_t index)
{
	struct lov_object *loo = cl2lov(obj);
	struct lov_io *lio = lov_env_io(env);
	struct cl_object *subobj;
	struct cl_object *o;
	struct lov_io_sub *sub;
	struct lov_page *lpg = cl_object_page_slice(obj, page);
	struct lov_layout_raid0 *r0;
	loff_t offset;
	loff_t suboff;
	bool stripe_cached = false;
	int entry;
	int stripe;
	int rc;

	ENTRY;

	/* Direct i/o (CPT_TRANSIENT) is split strictly to stripes, so we can
	 * cache the stripe information.  Buffered i/o is differently
	 * organized, and stripe calculation isn't a significant cost for
	 * buffered i/o, so we only cache this for direct i/o.
	 */
	stripe_cached = lio->lis_cached_entry != LIS_CACHE_ENTRY_NONE &&
			page->cp_type == CPT_TRANSIENT;

	offset = cl_offset(obj, index);

	if (stripe_cached) {
		entry = lio->lis_cached_entry;
		stripe = lio->lis_cached_stripe;
		/* Offset can never go backwards in an i/o, so this is valid */
		suboff = lio->lis_cached_suboff + offset - lio->lis_cached_off;
	} else {
		entry = lov_io_layout_at(lio, offset);

		stripe = lov_stripe_number(loo->lo_lsm, entry, offset);
		rc = lov_stripe_offset(loo->lo_lsm, entry, offset, stripe,
				       &suboff);
		LASSERT(rc == 0);
		lio->lis_cached_entry = entry;
		lio->lis_cached_stripe = stripe;
		lio->lis_cached_off = offset;
		lio->lis_cached_suboff = suboff;
	}

	if (entry < 0 || !lsm_entry_inited(loo->lo_lsm, entry)) {
		/* non-existing layout component */
		lov_page_init_empty(env, obj, page, index);
		RETURN(0);
	}

	CDEBUG(D_PAGE, "offset %llu, entry %d, stripe %d, suboff %llu\n",
	       offset, entry, stripe, suboff);

	page->cp_lov_index = lov_comp_index(entry, stripe);
	cl_page_slice_add(page, &lpg->lps_cl, obj, &lov_comp_page_ops);

	if (!stripe_cached) {
		sub = lov_sub_get(env, lio, page->cp_lov_index);
		if (IS_ERR(sub))
			RETURN(PTR_ERR(sub));
	} else {
		sub = lio->lis_cached_sub;
	}

	lio->lis_cached_sub = sub;

	r0 = lov_r0(loo, entry);
	LASSERT(stripe < r0->lo_nr);

	subobj = lovsub2cl(r0->lo_sub[stripe]);
	cl_object_for_each(o, subobj) {
		if (o->co_ops->coo_page_init) {
			rc = o->co_ops->coo_page_init(sub->sub_env, o, page,
						      cl_index(subobj, suboff));
			if (rc != 0)
				break;
		}
	}

	RETURN(rc);
}

static int lov_empty_page_print(const struct lu_env *env,
				const struct cl_page_slice *slice,
				void *cookie, lu_printer_t printer)
{
	struct lov_page *lp = cl2lov_page(slice);

	return (*printer)(env, cookie, LUSTRE_LOV_NAME"-page@%p, empty.\n", lp);
}

static const struct cl_page_operations lov_empty_page_ops = {
	.cpo_print = lov_empty_page_print
};

int lov_page_init_empty(const struct lu_env *env, struct cl_object *obj,
			struct cl_page *page, pgoff_t index)
{
	struct lov_page *lpg = cl_object_page_slice(obj, page);
	void *addr;

	ENTRY;

	page->cp_lov_index = ~0;
	cl_page_slice_add(page, &lpg->lps_cl, obj, &lov_empty_page_ops);
	addr = kmap(page->cp_vmpage);
	memset(addr, 0, cl_page_size(obj));
	kunmap(page->cp_vmpage);
	cl_page_export(env, page, 1);
	RETURN(0);
}

int lov_page_init_foreign(const struct lu_env *env, struct cl_object *obj,
			struct cl_page *page, pgoff_t index)
{
	CDEBUG(D_PAGE, DFID" has no data\n", PFID(lu_object_fid(&obj->co_lu)));
	RETURN(-ENODATA);
}

bool lov_page_is_empty(const struct cl_page *page)
{
	const struct cl_page_slice *slice = cl_page_at(page, &lov_device_type);

	LASSERT(slice != NULL);
	return slice->cpl_ops == &lov_empty_page_ops;
}


/** @} lov */

