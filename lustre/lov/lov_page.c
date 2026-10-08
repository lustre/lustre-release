// SPDX-License-Identifier: GPL-2.0-only
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
#include <linux/bug.h>
#include <linux/compiler.h>

/** \addtogroup lov
 *  @{
 */

/**
 * lov_page_stripe_offset() - Stripe index and sub-object offset
 * @lio: current LOV IO (designated stripe)
 * @lsm: layout
 * @entry: component index; caller has checked lsm_entry_inited()
 * @offset: file offset
 * @suboff: sub-object offset (out)
 *
 * Shared by lov_dio_pages_init_composite() and lov_page_init_composite().
 *
 * Return: stripe index, or negative on error
 */
static int lov_page_stripe_offset(struct lov_io *lio, struct lov_stripe_md *lsm,
				  int entry, loff_t offset, loff_t *suboff)
{
	int stripe;
	int rc;

	stripe = lov_io_stripe_number(lio->lis_cl.cis_io, lsm, entry, offset);
	if (stripe < 0)
		return stripe;
	rc = lov_stripe_offset(lsm, entry, offset, stripe, suboff);
	LASSERT(rc == 0);
	return stripe;
}

/**
 * Lov page operations.
 */
int lov_dio_pages_init_composite(const struct lu_env *env,
				 struct cl_object *obj,
				 struct cl_dio_pages *cdp, pgoff_t index)
{
	struct lov_object *loo = cl2lov(obj);
	struct lov_io *lio = lov_env_io(env);
	struct cl_object *subobj;
	struct cl_object *o;
	struct lov_io_sub *sub;
	struct lov_layout_raid0 *r0;
	loff_t offset;
	loff_t suboff;
	int entry;
	int stripe;
	int rc;

	ENTRY;

	/* an append may have one page array per stripe chunk in the same IO
	 * (lov_dio_max_bytes()), so the cached stripe of the previous page
	 * array is not valid for this one
	 */
	lio->lis_cached_entry = LIS_CACHE_ENTRY_NONE;

	offset = index << PAGE_SHIFT;

	entry = lov_io_layout_at(lio, offset);
	if (entry < 0)
		RETURN(-ENODATA);
	if (!lsm_entry_inited(loo->lo_lsm, entry)) {
		lov_dio_pages_init_empty(env, obj, cdp, index);
		RETURN(0);
	}

	stripe = lov_page_stripe_offset(lio, loo->lo_lsm, entry, offset,
					&suboff);
	if (stripe < 0)
		RETURN(-EINVAL);

	CDEBUG(D_PAGE, "offset %llu, entry %d, stripe %d, suboff %llu\n",
	       offset, entry, stripe, suboff);

	cdp->cdp_lov_index = lov_comp_index(entry, stripe);
	LASSERT(cdp->cdp_lov_index != CP_LOV_INDEX_EMPTY);

	sub = lov_sub_get(env, lio, cdp->cdp_lov_index);
	if (IS_ERR(sub))
		RETURN(PTR_ERR(sub));

	r0 = lov_r0(loo, entry);
	LASSERT(stripe < r0->lo_nr);

	subobj = lovsub2cl(r0->lo_sub[stripe]);
	cl_object_for_each(o, subobj) {
		if (o->co_ops->coo_dio_pages_init) {
			rc = o->co_ops->coo_dio_pages_init(sub->sub_env, o, cdp,
							  suboff >> PAGE_SHIFT);
			if (rc != 0)
				break;
		}
	}

	RETURN(rc);
}

int lov_page_init_composite(const struct lu_env *env, struct cl_object *obj,
			    struct cl_page *page, pgoff_t index)
{
	struct lov_object *loo = cl2lov(obj);
	struct lov_io *lio = lov_env_io(env);
	struct cl_object *subobj;
	struct cl_object *o;
	struct lov_io_sub *sub;
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

	offset = index << PAGE_SHIFT;

	if (stripe_cached) {
		entry = lio->lis_cached_entry;
		/* if there's no layout at this offset, we'll end up here with
		 * a cached layout entry, so we must verify the layout includes
		 * this offset
		 */
		if (!lov_io_layout_at_confirm(lio, entry, offset))
			RETURN(-ENODATA);
		stripe = lio->lis_cached_stripe;
		/* Offset can never go backwards in an i/o, so this is valid */
		suboff = lio->lis_cached_suboff + offset - lio->lis_cached_off;
	} else {
		entry = lov_io_layout_at(lio, offset);
		if (entry < 0)
			RETURN(-ENODATA);
		if (!lsm_entry_inited(loo->lo_lsm, entry)) {
			lov_page_init_empty(env, obj, page, index);
			RETURN(0);
		}
		/* Designated parity (MIRROR/STRIPE scope, or
		 * LL_IOC_FLR_SET_MIRROR) must stay DIO: the page cache is
		 * shared, including RAID0|PARITY components.
		 */
		if (page->cp_type != CPT_TRANSIENT &&
		    lio->lis_cl.cis_io->ci_designated_mirror &&
		    lsm_entry_is_parity(loo->lo_lsm, entry))
			RETURN(-EINVAL);

		stripe = lov_page_stripe_offset(lio, loo->lo_lsm, entry, offset,
						&suboff);
		if (stripe < 0)
			RETURN(-EINVAL);
		lio->lis_cached_entry = entry;
		lio->lis_cached_stripe = stripe;
		lio->lis_cached_off = offset;
		lio->lis_cached_suboff = suboff;
	}

	CDEBUG(D_PAGE, "offset %llu, entry %d, stripe %d, suboff %llu\n",
	       offset, entry, stripe, suboff);

	page->cp_lov_index = lov_comp_index(entry, stripe);
	LASSERT(page->cp_lov_index != CP_LOV_INDEX_EMPTY);

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
						      suboff >> PAGE_SHIFT);
			if (rc != 0)
				break;
		}
	}

	RETURN(rc);
}

int lov_dio_pages_init_empty(const struct lu_env *env, struct cl_object *obj,
			     struct cl_dio_pages *cdp, pgoff_t index)
{
	cdp->cdp_lov_index = CP_LOV_INDEX_EMPTY;

	RETURN(0);
}

int lov_page_init_empty(const struct lu_env *env, struct cl_object *obj,
			struct cl_page *cl_page, pgoff_t index)
{
	void *addr;

	ENTRY;
	BUILD_BUG_ON(!__same_type(cl_page->cp_lov_index, CP_LOV_INDEX_EMPTY));
	cl_page->cp_lov_index = CP_LOV_INDEX_EMPTY;

	addr = cl_kmap_local(cl_page);
	memset(addr, 0, PAGE_SIZE);
	kunmap_local(addr);
	folio_mark_uptodate(cl_page->cp_folio);
	RETURN(0);
}

int lov_dio_pages_init_foreign(const struct lu_env *env, struct cl_object *obj,
			       struct cl_dio_pages *cdp, pgoff_t index)
{
	CDEBUG(D_PAGE, DFID" has no data\n", PFID(lu_object_fid(&obj->co_lu)));
	RETURN(-ENODATA);
}

int lov_page_init_foreign(const struct lu_env *env, struct cl_object *obj,
			struct cl_page *page, pgoff_t index)
{
	CDEBUG(D_PAGE, DFID" has no data\n", PFID(lu_object_fid(&obj->co_lu)));
	RETURN(-ENODATA);
}

/** @} lov */
