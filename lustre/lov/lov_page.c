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
 * Lustre is a trademark of Sun Microsystems, Inc.
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
			  LUSTRE_LOV_NAME"-page@%p, comp index: %x, gen: %u\n",
			  lp, lp->lps_index, lp->lps_layout_gen);
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
	int entry;
	int stripe;
	int rc;

	ENTRY;

	offset = cl_offset(obj, index);
	entry = lov_io_layout_at(lio, offset);
	if (entry < 0 || !lsm_entry_inited(loo->lo_lsm, entry)) {
		/* non-existing layout component */
		lov_page_init_empty(env, obj, page, index);
		RETURN(0);
	}

	r0 = lov_r0(loo, entry);
	stripe = lov_stripe_number(loo->lo_lsm, entry, offset);
	LASSERT(stripe < r0->lo_nr);
	rc = lov_stripe_offset(loo->lo_lsm, entry, offset, stripe, &suboff);
	LASSERT(rc == 0);

	lpg->lps_index = lov_comp_index(entry, stripe);
	lpg->lps_layout_gen = loo->lo_lsm->lsm_layout_gen;
	cl_page_slice_add(page, &lpg->lps_cl, obj, index, &lov_comp_page_ops);

	sub = lov_sub_get(env, lio, lpg->lps_index);
	if (IS_ERR(sub))
		RETURN(PTR_ERR(sub));

	subobj = lovsub2cl(r0->lo_sub[stripe]);
	list_for_each_entry(o, &subobj->co_lu.lo_header->loh_layers,
			    co_lu.lo_linkage) {
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

	lpg->lps_index = ~0;
	cl_page_slice_add(page, &lpg->lps_cl, obj, index, &lov_empty_page_ops);
	addr = kmap(page->cp_vmpage);
	memset(addr, 0, cl_page_size(obj));
	kunmap(page->cp_vmpage);
	cl_page_export(env, page, 1);
	RETURN(0);
}

bool lov_page_is_empty(const struct cl_page *page)
{
	const struct cl_page_slice *slice = cl_page_at(page, &lov_device_type);

	LASSERT(slice != NULL);
	return slice->cpl_ops == &lov_empty_page_ops;
}


/** @} lov */

