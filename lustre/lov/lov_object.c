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
 * Implementation of cl_object for LOV layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <linux/random.h>

#include "lov_cl_internal.h"

static inline struct lov_device *lov_object_dev(struct lov_object *obj)
{
	return lu2lov_dev(obj->lo_cl.co_lu.lo_dev);
}

/** \addtogroup lov
 *  @{
 */

/*****************************************************************************
 *
 * Layout operations.
 *
 */

struct lov_layout_operations {
	int (*llo_init)(const struct lu_env *env, struct lov_device *dev,
			struct lov_object *lov, struct lov_stripe_md *lsm,
			const struct cl_object_conf *conf,
			union lov_layout_state *state);
	int (*llo_delete)(const struct lu_env *env, struct lov_object *lov,
                           union lov_layout_state *state);
        void (*llo_fini)(const struct lu_env *env, struct lov_object *lov,
                         union lov_layout_state *state);
        int  (*llo_print)(const struct lu_env *env, void *cookie,
                          lu_printer_t p, const struct lu_object *o);
        int  (*llo_page_init)(const struct lu_env *env, struct cl_object *obj,
			      struct cl_page *page, pgoff_t index);
        int  (*llo_lock_init)(const struct lu_env *env,
                              struct cl_object *obj, struct cl_lock *lock,
                              const struct cl_io *io);
        int  (*llo_io_init)(const struct lu_env *env,
                            struct cl_object *obj, struct cl_io *io);
        int  (*llo_getattr)(const struct lu_env *env, struct cl_object *obj,
                            struct cl_attr *attr);
	int  (*llo_flush)(const struct lu_env *env, struct cl_object *obj,
			  struct ldlm_lock *lock);
};

static int lov_layout_wait(const struct lu_env *env, struct lov_object *lov);
static struct lov_stripe_md *lov_lsm_addref(struct lov_object *lov);

static void lov_lsm_put(struct lov_stripe_md *lsm)
{
	if (lsm != NULL)
		lov_free_memmd(&lsm);
}

/*****************************************************************************
 *
 * Lov object layout operations.
 *
 */

static struct cl_object *lov_sub_find(const struct lu_env *env,
				      struct cl_device *dev,
				      const struct lu_fid *fid,
				      const struct cl_object_conf *conf)
{
	struct lu_object *o;

	ENTRY;

	o = lu_object_find_at(env, cl2lu_dev(dev), fid, &conf->coc_lu);
	LASSERT(ergo(!IS_ERR(o), o->lo_dev->ld_type == &lovsub_device_type));
	RETURN(lu2cl(o));
}

static int lov_page_slice_fixup(struct lov_object *lov,
				struct cl_object *stripe)
{
	struct cl_object_header *hdr = cl_object_header(&lov->lo_cl);
	struct cl_object *o;

	if (stripe == NULL)
		return hdr->coh_page_bufsize - lov->lo_cl.co_slice_off -
		       cfs_size_round(sizeof(struct lov_page));

	cl_object_for_each(o, stripe)
		o->co_slice_off += hdr->coh_page_bufsize;

	return cl_object_header(stripe)->coh_page_bufsize;
}

static int lov_init_sub(const struct lu_env *env, struct lov_object *lov,
			struct cl_object *subobj, struct lov_oinfo *oinfo,
			int idx)
{
	struct cl_object_header *hdr;
	struct cl_object_header *subhdr;
	struct cl_object_header *parent;
	int entry = lov_comp_entry(idx);
	int stripe = lov_comp_stripe(idx);
	int result;

	if (OBD_FAIL_CHECK(OBD_FAIL_LOV_INIT)) {
		/* For sanity:test_206.
		 * Do not leave the object in cache to avoid accessing
		 * freed memory. This is because osc_object is referring to
		 * lov_oinfo of lsm_stripe_data which will be freed due to
		 * this failure. */
		cl_object_kill(env, subobj);
		cl_object_put(env, subobj);
		return -EIO;
	}

	hdr = cl_object_header(lov2cl(lov));
	subhdr = cl_object_header(subobj);

	CDEBUG(D_INODE, DFID"@%p[%d:%d] -> "DFID"@%p: ostid: "DOSTID
	       " ost idx: %d gen: %d\n",
	       PFID(lu_object_fid(&subobj->co_lu)), subhdr, entry, stripe,
	       PFID(lu_object_fid(lov2lu(lov))), hdr, POSTID(&oinfo->loi_oi),
	       oinfo->loi_ost_idx, oinfo->loi_ost_gen);

	/* reuse ->coh_attr_guard to protect coh_parent change */
	spin_lock(&subhdr->coh_attr_guard);
	parent = subhdr->coh_parent;
	if (parent == NULL) {
		struct lovsub_object *lso = cl2lovsub(subobj);

		subhdr->coh_parent = hdr;
		spin_unlock(&subhdr->coh_attr_guard);
		subhdr->coh_nesting = hdr->coh_nesting + 1;
		lu_object_ref_add(&subobj->co_lu, "lov-parent", lov);
		lso->lso_super = lov;
		lso->lso_index = idx;
		result = 0;
	} else {
		struct lu_object  *old_obj;
		struct lov_object *old_lov;
		unsigned int mask = D_INODE;

		spin_unlock(&subhdr->coh_attr_guard);
		old_obj = lu_object_locate(&parent->coh_lu, &lov_device_type);
		LASSERT(old_obj != NULL);
		old_lov = cl2lov(lu2cl(old_obj));
		if (test_bit(LO_LAYOUT_INVALID, &old_lov->lo_obj_flags)) {
			/* the object's layout has already changed but isn't
			 * refreshed */
			lu_object_unhash(env, &subobj->co_lu);
			result = -EAGAIN;
		} else {
			mask = D_ERROR;
			result = -EIO;
		}

		LU_OBJECT_DEBUG(mask, env, &subobj->co_lu,
				"stripe %d is already owned.", idx);
		LU_OBJECT_DEBUG(mask, env, old_obj, "owned.");
		LU_OBJECT_HEADER(mask, env, lov2lu(lov), "try to own.\n");
		cl_object_put(env, subobj);
	}
	return result;
}

static int lov_init_raid0(const struct lu_env *env, struct lov_device *dev,
			  struct lov_object *lov, unsigned int index,
			  const struct cl_object_conf *conf,
			  struct lov_layout_entry *lle)
{
	struct lov_layout_raid0 *r0 = &lle->lle_raid0;
	struct lov_thread_info *lti = lov_env_info(env);
	struct cl_object_conf *subconf = &lti->lti_stripe_conf;
	struct lu_fid *ofid = &lti->lti_fid;
	struct cl_object *stripe;
	struct lov_stripe_md_entry *lse  = lov_lse(lov, index);
	int result;
	int psz, sz;
	int i;

	ENTRY;

	spin_lock_init(&r0->lo_sub_lock);
	r0->lo_nr = lse->lsme_stripe_count;
	r0->lo_trunc_stripeno = -1;

	OBD_ALLOC_PTR_ARRAY_LARGE(r0->lo_sub, r0->lo_nr);
	if (r0->lo_sub == NULL)
		GOTO(out, result = -ENOMEM);

	psz = 0;
	result = 0;
	memset(subconf, 0, sizeof(*subconf));

	/*
	 * Create stripe cl_objects.
	 */
	for (i = 0; i < r0->lo_nr; ++i) {
		struct cl_device *subdev;
		struct lov_oinfo *oinfo = lse->lsme_oinfo[i];
		int ost_idx = oinfo->loi_ost_idx;

		if (lov_oinfo_is_dummy(oinfo))
			continue;

		result = ostid_to_fid(ofid, &oinfo->loi_oi, oinfo->loi_ost_idx);
		if (result != 0)
			GOTO(out, result);

		if (dev->ld_target[ost_idx] == NULL) {
			CERROR("%s: OST %04x is not initialized\n",
			       lov2obd(dev->ld_lov)->obd_name, ost_idx);
			GOTO(out, result = -EIO);
		}

		subdev = lovsub2cl_dev(dev->ld_target[ost_idx]);
		subconf->u.coc_oinfo = oinfo;
		LASSERTF(subdev != NULL, "not init ost %d\n", ost_idx);
		/* In the function below, .hs_keycmp resolves to
		 * lu_obj_hop_keycmp() */
		/* coverity[overrun-buffer-val] */
		stripe = lov_sub_find(env, subdev, ofid, subconf);
		if (IS_ERR(stripe))
			GOTO(out, result = PTR_ERR(stripe));

		result = lov_init_sub(env, lov, stripe, oinfo,
				      lov_comp_index(index, i));
		if (result == -EAGAIN) { /* try again */
			--i;
			result = 0;
			continue;
		}

		if (result == 0) {
			r0->lo_sub[i] = cl2lovsub(stripe);

			sz = lov_page_slice_fixup(lov, stripe);
			LASSERT(ergo(psz > 0, psz == sz));
			psz = sz;
		}
	}
	if (result == 0)
		result = psz;
out:
	RETURN(result);
}

static void lov_subobject_kill(const struct lu_env *env, struct lov_object *lov,
			       struct lov_layout_raid0 *r0,
			       struct lovsub_object *los, int idx)
{
	struct cl_object        *sub;
	struct lu_site          *site;
	wait_queue_head_t *wq;

        LASSERT(r0->lo_sub[idx] == los);

	sub = lovsub2cl(los);
	site = sub->co_lu.lo_dev->ld_site;
	wq = lu_site_wq_from_fid(site, &sub->co_lu.lo_header->loh_fid);

        cl_object_kill(env, sub);
        /* release a reference to the sub-object and ... */
        lu_object_ref_del(&sub->co_lu, "lov-parent", lov);
        cl_object_put(env, sub);

	/* ... wait until it is actually destroyed---sub-object clears its
	 * ->lo_sub[] slot in lovsub_object_free() */
	wait_event(*wq, r0->lo_sub[idx] != los);
	LASSERT(r0->lo_sub[idx] == NULL);
}

static void lov_delete_raid0(const struct lu_env *env, struct lov_object *lov,
			     struct lov_layout_entry *lle)
{
	struct lov_layout_raid0 *r0 = &lle->lle_raid0;

	ENTRY;

        if (r0->lo_sub != NULL) {
		int i;

		for (i = 0; i < r0->lo_nr; ++i) {
			struct lovsub_object *los = r0->lo_sub[i];

			if (los != NULL) {
				cl_object_prune(env, &los->lso_cl);
				/*
				 * If top-level object is to be evicted from
				 * the cache, so are its sub-objects.
				 */
				lov_subobject_kill(env, lov, r0, los, i);
			}
		}
	}

	EXIT;
}

static void lov_fini_raid0(const struct lu_env *env,
			   struct lov_layout_entry *lle)
{
	struct lov_layout_raid0 *r0 = &lle->lle_raid0;

	if (r0->lo_sub != NULL) {
		OBD_FREE_PTR_ARRAY_LARGE(r0->lo_sub, r0->lo_nr);
		r0->lo_sub = NULL;
	}
}

static int lov_print_raid0(const struct lu_env *env, void *cookie,
			   lu_printer_t p, const struct lov_layout_entry *lle)
{
	const struct lov_layout_raid0 *r0 = &lle->lle_raid0;
	int i;

	for (i = 0; i < r0->lo_nr; ++i) {
		struct lu_object *sub;

		if (r0->lo_sub[i] != NULL) {
			sub = lovsub2lu(r0->lo_sub[i]);
			lu_object_print(env, cookie, p, sub);
		} else {
			(*p)(env, cookie, "sub %d absent\n", i);
		}
	}
	return 0;
}

static int lov_attr_get_raid0(const struct lu_env *env, struct lov_object *lov,
			      unsigned int index, struct lov_layout_entry *lle,
			      struct cl_attr **lov_attr)
{
	struct lov_layout_raid0 *r0 = &lle->lle_raid0;
	struct lov_stripe_md *lsm = lov->lo_lsm;
	struct ost_lvb *lvb = &lov_env_info(env)->lti_lvb;
	struct cl_attr *attr = &r0->lo_attr;
	__u64 kms = 0;
	int result = 0;

	if (r0->lo_attr_valid) {
		*lov_attr = attr;
		return 0;
	}

	memset(lvb, 0, sizeof(*lvb));

	/* XXX: timestamps can be negative by sanity:test_39m,
	 * how can it be? */
	lvb->lvb_atime = LLONG_MIN;
	lvb->lvb_ctime = LLONG_MIN;
	lvb->lvb_mtime = LLONG_MIN;

	/*
	 * XXX that should be replaced with a loop over sub-objects,
	 * doing cl_object_attr_get() on them. But for now, let's
	 * reuse old lov code.
	 */

	/*
	 * XXX take lsm spin-lock to keep lov_merge_lvb_kms()
	 * happy. It's not needed, because new code uses
	 * ->coh_attr_guard spin-lock to protect consistency of
	 * sub-object attributes.
	 */
	lov_stripe_lock(lsm);
	result = lov_merge_lvb_kms(lsm, index, lvb, &kms);
	lov_stripe_unlock(lsm);
	if (result == 0) {
		cl_lvb2attr(attr, lvb);
		attr->cat_kms = kms;
		r0->lo_attr_valid = 1;
		*lov_attr = attr;
	}

	return result;
}

static struct lov_comp_layout_entry_ops raid0_ops = {
	.lco_init      = lov_init_raid0,
	.lco_fini      = lov_fini_raid0,
	.lco_getattr   = lov_attr_get_raid0,
};

static int lov_attr_get_dom(const struct lu_env *env, struct lov_object *lov,
			    unsigned int index, struct lov_layout_entry *lle,
			    struct cl_attr **lov_attr)
{
	struct lov_layout_dom *dom = &lle->lle_dom;
	struct lov_oinfo *loi = dom->lo_loi;
	struct cl_attr *attr = &dom->lo_dom_r0.lo_attr;

	if (dom->lo_dom_r0.lo_attr_valid) {
		*lov_attr = attr;
		return 0;
	}

	if (OST_LVB_IS_ERR(loi->loi_lvb.lvb_blocks))
		return OST_LVB_GET_ERR(loi->loi_lvb.lvb_blocks);

	cl_lvb2attr(attr, &loi->loi_lvb);

	/* DoM component size can be bigger than stripe size after
	 * client's setattr RPC, so do not count anything beyond
	 * component end. Alternatively, check that limit on server
	 * and do not allow size overflow there. */
	if (attr->cat_size > lle->lle_extent->e_end)
		attr->cat_size = lle->lle_extent->e_end;

	attr->cat_kms = attr->cat_size;

	dom->lo_dom_r0.lo_attr_valid = 1;
	*lov_attr = attr;

	return 0;
}

/**
 * Lookup FLD to get MDS index of the given DOM object FID.
 *
 * \param[in]  ld	LOV device
 * \param[in]  fid	FID to lookup
 * \param[out] nr	index in MDC array to return back
 *
 * \retval		0 and \a mds filled with MDS index if successful
 * \retval		negative value on error
 */
static int lov_fld_lookup(struct lov_device *ld, const struct lu_fid *fid,
			  __u32 *nr)
{
	__u32 mds_idx;
	int i, rc;

	ENTRY;

	rc = fld_client_lookup(&ld->ld_lmv->u.lmv.lmv_fld, fid_seq(fid),
			       &mds_idx, LU_SEQ_RANGE_MDT, NULL);
	if (rc) {
		CERROR("%s: error while looking for mds number. Seq %#llx"
		       ", err = %d\n", lu_dev_name(cl2lu_dev(&ld->ld_cl)),
		       fid_seq(fid), rc);
		RETURN(rc);
	}

	CDEBUG(D_INODE, "FLD lookup got mds #%x for fid="DFID"\n",
	       mds_idx, PFID(fid));

	/* find proper MDC device in the array */
	for (i = 0; i < ld->ld_md_tgts_nr; i++) {
		if (ld->ld_md_tgts[i].ldm_mdc != NULL &&
		    ld->ld_md_tgts[i].ldm_idx == mds_idx)
			break;
	}

	if (i == ld->ld_md_tgts_nr) {
		CERROR("%s: cannot find corresponding MDC device for mds #%x "
		       "for fid="DFID"\n", lu_dev_name(cl2lu_dev(&ld->ld_cl)),
		       mds_idx, PFID(fid));
		rc = -EINVAL;
	} else {
		*nr = i;
	}
	RETURN(rc);
}

/**
 * Implementation of lov_comp_layout_entry_ops::lco_init for DOM object.
 *
 * Init the DOM object for the first time. It prepares also RAID0 entry
 * for it to use in common methods with ordinary RAID0 layout entries.
 *
 * \param[in] env	execution environment
 * \param[in] dev	LOV device
 * \param[in] lov	LOV object
 * \param[in] index	Composite layout entry index in LSM
 * \param[in] lle	Composite LOV layout entry
 */
static int lov_init_dom(const struct lu_env *env, struct lov_device *dev,
			struct lov_object *lov, unsigned int index,
			const struct cl_object_conf *conf,
			struct lov_layout_entry *lle)
{
	struct lov_thread_info *lti = lov_env_info(env);
	struct lov_stripe_md_entry *lsme = lov_lse(lov, index);
	struct cl_object *clo;
	struct lu_object *o = lov2lu(lov);
	const struct lu_fid *fid = lu_object_fid(o);
	struct cl_device *mdcdev;
	struct lov_oinfo *loi = NULL;
	struct cl_object_conf *sconf = &lti->lti_stripe_conf;
	int rc;
	__u32 idx = 0;

	ENTRY;

	/* DOM entry may be not zero index due to FLR but must start from 0 */
	if (unlikely(lle->lle_extent->e_start != 0)) {
		CERROR("%s: DOM entry must be the first stripe in a mirror\n",
		       lov2obd(dev->ld_lov)->obd_name);
		dump_lsm(D_ERROR, lov->lo_lsm);
		RETURN(-EINVAL);
	}

	/* find proper MDS device */
	rc = lov_fld_lookup(dev, fid, &idx);
	if (rc)
		RETURN(rc);

	LASSERTF(dev->ld_md_tgts[idx].ldm_mdc != NULL,
		 "LOV md target[%u] is NULL\n", idx);

	/* check lsm is DOM, more checks are needed */
	LASSERT(lsme->lsme_stripe_count == 0);

	/*
	 * Create lower cl_objects.
	 */
	mdcdev = dev->ld_md_tgts[idx].ldm_mdc;

	LASSERTF(mdcdev != NULL, "non-initialized mdc subdev\n");

	/* DoM object has no oinfo in LSM entry, create it exclusively */
	OBD_SLAB_ALLOC_PTR_GFP(loi, lov_oinfo_slab, GFP_NOFS);
	if (loi == NULL)
		RETURN(-ENOMEM);

	fid_to_ostid(lu_object_fid(lov2lu(lov)), &loi->loi_oi);

	sconf->u.coc_oinfo = loi;
again:
	clo = lov_sub_find(env, mdcdev, fid, sconf);
	if (IS_ERR(clo))
		GOTO(out, rc = PTR_ERR(clo));

	rc = lov_init_sub(env, lov, clo, loi, lov_comp_index(index, 0));
	if (rc == -EAGAIN) /* try again */
		goto again;
	else if (rc != 0)
		GOTO(out, rc);

	lle->lle_dom.lo_dom = cl2lovsub(clo);
	spin_lock_init(&lle->lle_dom.lo_dom_r0.lo_sub_lock);
	lle->lle_dom.lo_dom_r0.lo_nr = 1;
	lle->lle_dom.lo_dom_r0.lo_sub = &lle->lle_dom.lo_dom;
	lle->lle_dom.lo_loi = loi;

	rc = lov_page_slice_fixup(lov, clo);
	RETURN(rc);

out:
	if (loi != NULL)
		OBD_SLAB_FREE_PTR(loi, lov_oinfo_slab);
	return rc;
}

/**
 * Implementation of lov_layout_operations::llo_fini for DOM object.
 *
 * Finish the DOM object and free related memory.
 *
 * \param[in] env	execution environment
 * \param[in] lov	LOV object
 * \param[in] state	LOV layout state
 */
static void lov_fini_dom(const struct lu_env *env,
			 struct lov_layout_entry *lle)
{
	if (lle->lle_dom.lo_dom != NULL)
		lle->lle_dom.lo_dom = NULL;
	if (lle->lle_dom.lo_loi != NULL)
		OBD_SLAB_FREE_PTR(lle->lle_dom.lo_loi, lov_oinfo_slab);
}

static struct lov_comp_layout_entry_ops dom_ops = {
	.lco_init = lov_init_dom,
	.lco_fini = lov_fini_dom,
	.lco_getattr = lov_attr_get_dom,
};

static int lov_init_composite(const struct lu_env *env, struct lov_device *dev,
			      struct lov_object *lov, struct lov_stripe_md *lsm,
			      const struct cl_object_conf *conf,
			      union lov_layout_state *state)
{
	struct lov_layout_composite *comp = &state->composite;
	struct lov_layout_entry *lle;
	struct lov_mirror_entry *lre;
	unsigned int entry_count;
	unsigned int psz = 0;
	unsigned int mirror_count;
	int flr_state = lsm->lsm_flags & LCM_FL_FLR_MASK;
	int result = 0;
	unsigned int seq;
	int i, j;
	bool dom_size = 0;

	ENTRY;

	LASSERT(lsm->lsm_entry_count > 0);
	LASSERT(lov->lo_lsm == NULL);
	lov->lo_lsm = lsm_addref(lsm);
	set_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags);

	dump_lsm(D_INODE, lsm);

	entry_count = lsm->lsm_entry_count;

	spin_lock_init(&comp->lo_write_lock);
	comp->lo_flags = lsm->lsm_flags;
	comp->lo_mirror_count = lsm->lsm_mirror_count + 1;
	comp->lo_entry_count = lsm->lsm_entry_count;
	comp->lo_preferred_mirror = -1;

	if (equi(flr_state == LCM_FL_NONE, comp->lo_mirror_count > 1))
		RETURN(-EINVAL);

	OBD_ALLOC_PTR_ARRAY(comp->lo_mirrors, comp->lo_mirror_count);
	if (comp->lo_mirrors == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC_PTR_ARRAY(comp->lo_entries, entry_count);
	if (comp->lo_entries == NULL)
		RETURN(-ENOMEM);

	/* Initiate all entry types and extents data at first */
	for (i = 0, j = 0, mirror_count = 1; i < entry_count; i++) {
		int mirror_id = 0;

		lle = &comp->lo_entries[i];

		lle->lle_lsme = lsm->lsm_entries[i];
		lle->lle_type = lov_entry_type(lle->lle_lsme);
		switch (lle->lle_type) {
		case LOV_PATTERN_RAID0:
			lle->lle_comp_ops = &raid0_ops;
			break;
		case LOV_PATTERN_MDT:
			/* Allowed to have several DOM stripes in different
			 * mirrors with the same DoM size.
			 */
			if (!dom_size) {
				dom_size = lle->lle_lsme->lsme_extent.e_end;
			} else if (dom_size !=
				   lle->lle_lsme->lsme_extent.e_end) {
				CERROR("%s: DOM entries with different sizes\n",
				       lov2obd(dev->ld_lov)->obd_name);
				dump_lsm(D_ERROR, lsm);
				RETURN(-EINVAL);
			}
			lle->lle_comp_ops = &dom_ops;
			break;
		case LOV_PATTERN_FOREIGN:
			lle->lle_comp_ops = NULL;
			break;
		default:
			CERROR("%s: unknown composite layout entry type %i\n",
			       lov2obd(dev->ld_lov)->obd_name,
			       lsm->lsm_entries[i]->lsme_pattern);
			dump_lsm(D_ERROR, lsm);
			RETURN(-EIO);
		}

		lle->lle_extent = &lle->lle_lsme->lsme_extent;
		lle->lle_valid = !(lle->lle_lsme->lsme_flags & LCME_FL_STALE);

		if (flr_state != LCM_FL_NONE)
			mirror_id = mirror_id_of(lle->lle_lsme->lsme_id);

		lre = &comp->lo_mirrors[j];
		if (i > 0) {
			if (mirror_id == lre->lre_mirror_id) {
				lre->lre_valid |= lle->lle_valid;
				lre->lre_stale |= !lle->lle_valid;
				lre->lre_foreign |=
					lsme_is_foreign(lle->lle_lsme);
				lre->lre_end = i;
				continue;
			}

			/* new mirror detected, assume that the mirrors
			 * are shorted in layout */
			++mirror_count;
			++j;
			if (j >= comp->lo_mirror_count)
				break;

			lre = &comp->lo_mirrors[j];
		}

		/* entries must be sorted by mirrors */
		lre->lre_mirror_id = mirror_id;
		lre->lre_start = lre->lre_end = i;
		lre->lre_preferred = !!(lle->lle_lsme->lsme_flags &
					LCME_FL_PREF_RD);
		lre->lre_valid = lle->lle_valid;
		lre->lre_stale = !lle->lle_valid;
		lre->lre_foreign = lsme_is_foreign(lle->lle_lsme);
	}

	/* sanity check for FLR */
	if (mirror_count != comp->lo_mirror_count) {
		CDEBUG(D_INODE, DFID
		       " doesn't have the # of mirrors it claims, %u/%u\n",
		       PFID(lu_object_fid(lov2lu(lov))), mirror_count,
		       comp->lo_mirror_count + 1);

		GOTO(out, result = -EINVAL);
	}

	lov_foreach_layout_entry(lov, lle) {
		int index = lov_layout_entry_index(lov, lle);

		/**
		 * If the component has not been init-ed on MDS side, for
		 * PFL layout, we'd know that the components beyond this one
		 * will be dynamically init-ed later on file write/trunc ops.
		 */
		if (!lsme_inited(lle->lle_lsme))
			continue;

		if (lsme_is_foreign(lle->lle_lsme))
			continue;

		result = lle->lle_comp_ops->lco_init(env, dev, lov, index,
						     conf, lle);
		if (result < 0)
			break;

		LASSERT(ergo(psz > 0, psz == result));
		psz = result;
	}

	if (psz > 0)
		cl_object_header(&lov->lo_cl)->coh_page_bufsize += psz;

	/* decide the preferred mirror. It uses the hash value of lov_object
	 * so that different clients would use different mirrors for read. */
	mirror_count = 0;
	seq = hash_long((unsigned long)lov, 8);
	for (i = 0; i < comp->lo_mirror_count; i++) {
		unsigned int idx = (i + seq) % comp->lo_mirror_count;

		lre = lov_mirror_entry(lov, idx);
		if (lre->lre_stale)
			continue;

		if (lre->lre_foreign)
			continue;

		mirror_count++; /* valid mirror */

		if (lre->lre_preferred || comp->lo_preferred_mirror < 0)
			comp->lo_preferred_mirror = idx;
	}
	if (!mirror_count) {
		CDEBUG(D_INODE, DFID
		       " doesn't have any valid mirrors\n",
		       PFID(lu_object_fid(lov2lu(lov))));

		comp->lo_preferred_mirror = 0;
	}

	LASSERT(comp->lo_preferred_mirror >= 0);

	EXIT;
out:
	return result > 0 ? 0 : result;
}

static int lov_init_empty(const struct lu_env *env, struct lov_device *dev,
			  struct lov_object *lov, struct lov_stripe_md *lsm,
			  const struct cl_object_conf *conf,
			  union lov_layout_state *state)
{
	return 0;
}

static int lov_init_released(const struct lu_env *env,
			     struct lov_device *dev, struct lov_object *lov,
			     struct lov_stripe_md *lsm,
			     const struct cl_object_conf *conf,
			     union lov_layout_state *state)
{
	LASSERT(lsm != NULL);
	LASSERT(lsm->lsm_is_released);
	LASSERT(lov->lo_lsm == NULL);

	lov->lo_lsm = lsm_addref(lsm);
	return 0;
}

static int lov_init_foreign(const struct lu_env *env,
			    struct lov_device *dev, struct lov_object *lov,
			    struct lov_stripe_md *lsm,
			    const struct cl_object_conf *conf,
			    union lov_layout_state *state)
{
	LASSERT(lsm != NULL);
	LASSERT(lov->lo_type == LLT_FOREIGN);
	LASSERT(lov->lo_lsm == NULL);

	lov->lo_lsm = lsm_addref(lsm);
	return 0;
}

static int lov_delete_empty(const struct lu_env *env, struct lov_object *lov,
			    union lov_layout_state *state)
{
	LASSERT(lov->lo_type == LLT_EMPTY || lov->lo_type == LLT_RELEASED ||
		lov->lo_type == LLT_FOREIGN);

	lov_layout_wait(env, lov);
	return 0;
}

static int lov_delete_composite(const struct lu_env *env,
				struct lov_object *lov,
				union lov_layout_state *state)
{
	struct lov_layout_entry *entry;
	struct lov_layout_composite *comp = &state->composite;

	ENTRY;

	dump_lsm(D_INODE, lov->lo_lsm);

	lov_layout_wait(env, lov);
	if (comp->lo_entries)
		lov_foreach_layout_entry(lov, entry) {
			if (entry->lle_lsme && lsme_is_foreign(entry->lle_lsme))
				continue;

			lov_delete_raid0(env, lov, entry);
	}

	RETURN(0);
}

static void lov_fini_empty(const struct lu_env *env, struct lov_object *lov,
                           union lov_layout_state *state)
{
	LASSERT(lov->lo_type == LLT_EMPTY || lov->lo_type == LLT_RELEASED);
}

static void lov_fini_composite(const struct lu_env *env,
			       struct lov_object *lov,
			       union lov_layout_state *state)
{
	struct lov_layout_composite *comp = &state->composite;
	ENTRY;

	if (comp->lo_entries != NULL) {
		struct lov_layout_entry *entry;

		lov_foreach_layout_entry(lov, entry)
			if (entry->lle_comp_ops)
				entry->lle_comp_ops->lco_fini(env, entry);

		OBD_FREE_PTR_ARRAY(comp->lo_entries, comp->lo_entry_count);
		comp->lo_entries = NULL;
	}

	if (comp->lo_mirrors != NULL) {
		OBD_FREE_PTR_ARRAY(comp->lo_mirrors, comp->lo_mirror_count);
		comp->lo_mirrors = NULL;
	}

	memset(comp, 0, sizeof(*comp));

	dump_lsm(D_INODE, lov->lo_lsm);
	lov_free_memmd(&lov->lo_lsm);

	EXIT;
}

static void lov_fini_released(const struct lu_env *env, struct lov_object *lov,
				union lov_layout_state *state)
{
	ENTRY;
	dump_lsm(D_INODE, lov->lo_lsm);
	lov_free_memmd(&lov->lo_lsm);
	EXIT;
}

static int lov_print_empty(const struct lu_env *env, void *cookie,
                           lu_printer_t p, const struct lu_object *o)
{
        (*p)(env, cookie, "empty %d\n",
	     test_bit(LO_LAYOUT_INVALID, &lu2lov(o)->lo_obj_flags));
        return 0;
}

static int lov_print_composite(const struct lu_env *env, void *cookie,
			       lu_printer_t p, const struct lu_object *o)
{
	struct lov_object *lov = lu2lov(o);
	struct lov_stripe_md *lsm = lov->lo_lsm;
	int i;

	(*p)(env, cookie, "entries: %d, %s, lsm{%p 0x%08X %d %u}:\n",
	     lsm->lsm_entry_count,
	     test_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags) ? "invalid" :
	     "valid", lsm, lsm->lsm_magic, atomic_read(&lsm->lsm_refc),
	     lsm->lsm_layout_gen);

	for (i = 0; i < lsm->lsm_entry_count; i++) {
		struct lov_stripe_md_entry *lse = lsm->lsm_entries[i];
		struct lov_layout_entry *lle = lov_entry(lov, i);

		(*p)(env, cookie,
		     DEXT ": { 0x%08X, %u, %#x, %u, %#x, %u, %u }\n",
		     PEXT(&lse->lsme_extent), lse->lsme_magic,
		     lse->lsme_id, lse->lsme_pattern, lse->lsme_layout_gen,
		     lse->lsme_flags, lse->lsme_stripe_count,
		     lse->lsme_stripe_size);

		if (!lsme_is_foreign(lse))
			lov_print_raid0(env, cookie, p, lle);
	}

	return 0;
}

static int lov_print_released(const struct lu_env *env, void *cookie,
				lu_printer_t p, const struct lu_object *o)
{
	struct lov_object	*lov = lu2lov(o);
	struct lov_stripe_md	*lsm = lov->lo_lsm;

	(*p)(env, cookie,
		"released: %s, lsm{%p 0x%08X %d %u}:\n",
		test_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags) ? "invalid" :
		"valid", lsm, lsm->lsm_magic, atomic_read(&lsm->lsm_refc),
		lsm->lsm_layout_gen);
	return 0;
}

static int lov_print_foreign(const struct lu_env *env, void *cookie,
				lu_printer_t p, const struct lu_object *o)
{
	struct lov_object	*lov = lu2lov(o);
	struct lov_stripe_md	*lsm = lov->lo_lsm;

	(*p)(env, cookie,
		"foreign: %s, lsm{%p 0x%08X %d %u}:\n",
		test_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags) ?
		"invalid" : "valid", lsm,
		lsm->lsm_magic, atomic_read(&lsm->lsm_refc),
		lsm->lsm_layout_gen);
	(*p)(env, cookie,
		"raw_ea_content '%.*s'\n",
		(int)lsm->lsm_foreign_size, (char *)lsm_foreign(lsm));
	return 0;
}

/**
 * Implements cl_object_operations::coo_attr_get() method for an object
 * without stripes (LLT_EMPTY layout type).
 *
 * The only attributes this layer is authoritative in this case is
 * cl_attr::cat_blocks---it's 0.
 */
static int lov_attr_get_empty(const struct lu_env *env, struct cl_object *obj,
                              struct cl_attr *attr)
{
        attr->cat_blocks = 0;
        return 0;
}

static int lov_attr_get_composite(const struct lu_env *env,
				  struct cl_object *obj,
				  struct cl_attr *attr)
{
	struct lov_object	*lov = cl2lov(obj);
	struct lov_layout_entry *entry;
	int			 result = 0;

	ENTRY;

	attr->cat_size = 0;
	attr->cat_blocks = 0;
	lov_foreach_layout_entry(lov, entry) {
		struct cl_attr *lov_attr = NULL;
		int index = lov_layout_entry_index(lov, entry);

		if (!entry->lle_valid)
			continue;

		/* PFL: This component has not been init-ed. */
		if (!lsm_entry_inited(lov->lo_lsm, index))
			continue;

		result = entry->lle_comp_ops->lco_getattr(env, lov, index,
							  entry, &lov_attr);
		if (result < 0)
			RETURN(result);

		if (lov_attr == NULL)
			continue;

		CDEBUG(D_INODE, "COMP ID #%i: s=%llu m=%llu a=%llu c=%llu "
		       "b=%llu\n", index - 1, lov_attr->cat_size,
		       lov_attr->cat_mtime, lov_attr->cat_atime,
		       lov_attr->cat_ctime, lov_attr->cat_blocks);

		/* merge results */
		attr->cat_blocks += lov_attr->cat_blocks;
		if (attr->cat_size < lov_attr->cat_size)
			attr->cat_size = lov_attr->cat_size;
		if (attr->cat_kms < lov_attr->cat_kms)
			attr->cat_kms = lov_attr->cat_kms;
		if (attr->cat_atime < lov_attr->cat_atime)
			attr->cat_atime = lov_attr->cat_atime;
		if (attr->cat_ctime < lov_attr->cat_ctime)
			attr->cat_ctime = lov_attr->cat_ctime;
		if (attr->cat_mtime < lov_attr->cat_mtime)
			attr->cat_mtime = lov_attr->cat_mtime;
	}

	RETURN(0);
}

static int lov_flush_composite(const struct lu_env *env,
			       struct cl_object *obj,
			       struct ldlm_lock *lock)
{
	struct lov_object *lov = cl2lov(obj);
	struct lov_layout_entry *lle;
	int rc = -ENODATA;

	ENTRY;

	lov_foreach_layout_entry(lov, lle) {
		if (!lsme_is_dom(lle->lle_lsme))
			continue;
		rc = cl_object_flush(env, lovsub2cl(lle->lle_dom.lo_dom), lock);
		break;
	}

	RETURN(rc);
}

static int lov_flush_empty(const struct lu_env *env, struct cl_object *obj,
			   struct ldlm_lock *lock)
{
	return 0;
}

const static struct lov_layout_operations lov_dispatch[] = {
	[LLT_EMPTY] = {
		.llo_init      = lov_init_empty,
		.llo_delete    = lov_delete_empty,
		.llo_fini      = lov_fini_empty,
		.llo_print     = lov_print_empty,
		.llo_page_init = lov_page_init_empty,
		.llo_lock_init = lov_lock_init_empty,
		.llo_io_init   = lov_io_init_empty,
		.llo_getattr   = lov_attr_get_empty,
		.llo_flush     = lov_flush_empty,
	},
	[LLT_RELEASED] = {
		.llo_init      = lov_init_released,
		.llo_delete    = lov_delete_empty,
		.llo_fini      = lov_fini_released,
		.llo_print     = lov_print_released,
		.llo_page_init = lov_page_init_empty,
		.llo_lock_init = lov_lock_init_empty,
		.llo_io_init   = lov_io_init_released,
		.llo_getattr   = lov_attr_get_empty,
		.llo_flush     = lov_flush_empty,
	},
	[LLT_COMP] = {
		.llo_init      = lov_init_composite,
		.llo_delete    = lov_delete_composite,
		.llo_fini      = lov_fini_composite,
		.llo_print     = lov_print_composite,
		.llo_page_init = lov_page_init_composite,
		.llo_lock_init = lov_lock_init_composite,
		.llo_io_init   = lov_io_init_composite,
		.llo_getattr   = lov_attr_get_composite,
		.llo_flush     = lov_flush_composite,
	},
	[LLT_FOREIGN] = {
		.llo_init      = lov_init_foreign,
		.llo_delete    = lov_delete_empty,
		.llo_fini      = lov_fini_released,
		.llo_print     = lov_print_foreign,
		.llo_page_init = lov_page_init_foreign,
		.llo_lock_init = lov_lock_init_empty,
		.llo_io_init   = lov_io_init_empty,
		.llo_getattr   = lov_attr_get_empty,
		.llo_flush     = lov_flush_empty,
	},
};

/**
 * Performs a double-dispatch based on the layout type of an object.
 */
#define LOV_2DISPATCH_NOLOCK(obj, op, ...)		\
({							\
	struct lov_object *__obj = (obj);		\
	enum lov_layout_type __llt;			\
							\
	__llt = __obj->lo_type;				\
	LASSERT(__llt < ARRAY_SIZE(lov_dispatch));	\
	lov_dispatch[__llt].op(__VA_ARGS__);		\
})

/**
 * Return lov_layout_type associated with a given lsm
 */
static enum lov_layout_type lov_type(struct lov_stripe_md *lsm)
{
	if (lsm == NULL)
		return LLT_EMPTY;

	if (lsm->lsm_is_released)
		return LLT_RELEASED;

	if (lsm->lsm_magic == LOV_MAGIC_V1 ||
	    lsm->lsm_magic == LOV_MAGIC_V3 ||
	    lsm->lsm_magic == LOV_MAGIC_COMP_V1)
		return LLT_COMP;

	if (lsm->lsm_magic == LOV_MAGIC_FOREIGN)
		return LLT_FOREIGN;

	return LLT_EMPTY;
}

static inline void lov_conf_freeze(struct lov_object *lov)
{
	CDEBUG(D_INODE, "To take share lov(%p) owner %p/%p\n",
		lov, lov->lo_owner, current);
	if (lov->lo_owner != current)
		down_read(&lov->lo_type_guard);
}

static inline void lov_conf_thaw(struct lov_object *lov)
{
	CDEBUG(D_INODE, "To release share lov(%p) owner %p/%p\n",
		lov, lov->lo_owner, current);
	if (lov->lo_owner != current)
		up_read(&lov->lo_type_guard);
}

#define LOV_2DISPATCH_MAYLOCK(obj, op, lock, ...)                       \
({                                                                      \
        struct lov_object                      *__obj = (obj);          \
        int                                     __lock = !!(lock);      \
        typeof(lov_dispatch[0].op(__VA_ARGS__)) __result;               \
                                                                        \
        if (__lock)                                                     \
                lov_conf_freeze(__obj);					\
        __result = LOV_2DISPATCH_NOLOCK(obj, op, __VA_ARGS__);          \
        if (__lock)                                                     \
                lov_conf_thaw(__obj);					\
        __result;                                                       \
})

/**
 * Performs a locked double-dispatch based on the layout type of an object.
 */
#define LOV_2DISPATCH(obj, op, ...)                     \
        LOV_2DISPATCH_MAYLOCK(obj, op, 1, __VA_ARGS__)

#define LOV_2DISPATCH_VOID(obj, op, ...)                                \
do {                                                                    \
        struct lov_object                      *__obj = (obj);          \
        enum lov_layout_type                    __llt;                  \
                                                                        \
	lov_conf_freeze(__obj);						\
        __llt = __obj->lo_type;                                         \
	LASSERT(__llt < ARRAY_SIZE(lov_dispatch));			\
        lov_dispatch[__llt].op(__VA_ARGS__);                            \
	lov_conf_thaw(__obj);						\
} while (0)

static void lov_conf_lock(struct lov_object *lov)
{
	LASSERT(lov->lo_owner != current);
	down_write(&lov->lo_type_guard);
	LASSERT(lov->lo_owner == NULL);
	lov->lo_owner = current;
	CDEBUG(D_INODE, "Took exclusive lov(%p) owner %p\n",
		lov, lov->lo_owner);
}

static void lov_conf_unlock(struct lov_object *lov)
{
	CDEBUG(D_INODE, "To release exclusive lov(%p) owner %p\n",
		lov, lov->lo_owner);
	lov->lo_owner = NULL;
	up_write(&lov->lo_type_guard);
}

static int lov_layout_wait(const struct lu_env *env, struct lov_object *lov)
{
	ENTRY;

	while (atomic_read(&lov->lo_active_ios) > 0) {
		CDEBUG(D_INODE, "file:"DFID" wait for active IO, now: %d.\n",
			PFID(lu_object_fid(lov2lu(lov))),
			atomic_read(&lov->lo_active_ios));

		wait_event_idle(lov->lo_waitq,
				atomic_read(&lov->lo_active_ios) == 0);
	}
	RETURN(0);
}

static int lov_layout_change(const struct lu_env *unused,
			     struct lov_object *lov, struct lov_stripe_md *lsm,
			     const struct cl_object_conf *conf)
{
	enum lov_layout_type llt = lov_type(lsm);
	union lov_layout_state *state = &lov->u;
	const struct lov_layout_operations *old_ops;
	const struct lov_layout_operations *new_ops;
	struct lov_device *lov_dev = lov_object_dev(lov);
	struct lu_env *env;
	__u16 refcheck;
	int rc;
	ENTRY;

	LASSERT(lov->lo_type < ARRAY_SIZE(lov_dispatch));

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	LASSERT(llt < ARRAY_SIZE(lov_dispatch));

	CDEBUG(D_INODE, DFID" from %s to %s\n",
	       PFID(lu_object_fid(lov2lu(lov))),
	       llt2str(lov->lo_type), llt2str(llt));

	old_ops = &lov_dispatch[lov->lo_type];
	new_ops = &lov_dispatch[llt];

	rc = cl_object_prune(env, &lov->lo_cl);
	if (rc != 0)
		GOTO(out, rc);

	rc = old_ops->llo_delete(env, lov, &lov->u);
	if (rc != 0)
		GOTO(out, rc);

	old_ops->llo_fini(env, lov, &lov->u);

	LASSERT(atomic_read(&lov->lo_active_ios) == 0);

	CDEBUG(D_INODE, DFID "Apply new layout lov %p, type %d\n",
	       PFID(lu_object_fid(lov2lu(lov))), lov, llt);

	/* page bufsize fixup */
	cl_object_header(&lov->lo_cl)->coh_page_bufsize -=
		lov_page_slice_fixup(lov, NULL);

	lov->lo_type = llt;
	rc = new_ops->llo_init(env, lov_dev, lov, lsm, conf, state);
	if (rc != 0) {
		struct obd_device *obd = lov2obd(lov_dev->ld_lov);

		CERROR("%s: cannot apply new layout on "DFID" : rc = %d\n",
		       obd->obd_name, PFID(lu_object_fid(lov2lu(lov))), rc);
		new_ops->llo_delete(env, lov, state);
		new_ops->llo_fini(env, lov, state);
		/* this file becomes an EMPTY file. */
		lov->lo_type = LLT_EMPTY;
		GOTO(out, rc);
	}

out:
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

/*****************************************************************************
 *
 * Lov object operations.
 *
 */
static int lov_object_init(const struct lu_env *env, struct lu_object *obj,
			   const struct lu_object_conf *conf)
{
	struct lov_object            *lov   = lu2lov(obj);
	struct lov_device            *dev   = lov_object_dev(lov);
	const struct cl_object_conf  *cconf = lu2cl_conf(conf);
	union lov_layout_state	     *set   = &lov->u;
	const struct lov_layout_operations *ops;
	struct lov_stripe_md *lsm = NULL;
	int rc;
	ENTRY;

	init_rwsem(&lov->lo_type_guard);
	atomic_set(&lov->lo_active_ios, 0);
	init_waitqueue_head(&lov->lo_waitq);
	cl_object_page_init(lu2cl(obj), sizeof(struct lov_page));

	lov->lo_type = LLT_EMPTY;
	if (cconf->u.coc_layout.lb_buf != NULL) {
		lsm = lov_unpackmd(dev->ld_lov,
				   cconf->u.coc_layout.lb_buf,
				   cconf->u.coc_layout.lb_len);
		if (IS_ERR(lsm))
			RETURN(PTR_ERR(lsm));

		dump_lsm(D_INODE, lsm);
	}

	/* no locking is necessary, as object is being created */
	lov->lo_type = lov_type(lsm);
	ops = &lov_dispatch[lov->lo_type];
	rc = ops->llo_init(env, dev, lov, lsm, cconf, set);
	if (rc != 0)
		GOTO(out_lsm, rc);

out_lsm:
	lov_lsm_put(lsm);

	RETURN(rc);
}

static int lov_conf_set(const struct lu_env *env, struct cl_object *obj,
                        const struct cl_object_conf *conf)
{
	struct lov_stripe_md	*lsm = NULL;
	struct lov_object	*lov = cl2lov(obj);
	int			 result = 0;
	ENTRY;

	if (conf->coc_opc == OBJECT_CONF_SET &&
	    conf->u.coc_layout.lb_buf != NULL) {
		lsm = lov_unpackmd(lov_object_dev(lov)->ld_lov,
				   conf->u.coc_layout.lb_buf,
				   conf->u.coc_layout.lb_len);
		if (IS_ERR(lsm))
			RETURN(PTR_ERR(lsm));
		dump_lsm(D_INODE, lsm);
	}

	if (conf->coc_opc == OBJECT_CONF_INVALIDATE) {
		set_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags);
		GOTO(out_lsm, result = 0);
	}

	lov_conf_lock(lov);
	if (conf->coc_opc == OBJECT_CONF_WAIT) {
		if (test_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags) &&
		    atomic_read(&lov->lo_active_ios) > 0) {
			lov_conf_unlock(lov);
			result = lov_layout_wait(env, lov);
			lov_conf_lock(lov);
		}
		GOTO(out, result);
	}

	LASSERT(conf->coc_opc == OBJECT_CONF_SET);

	if ((lsm == NULL && lov->lo_lsm == NULL) ||
	    ((lsm != NULL && lov->lo_lsm != NULL) &&
	     (lov->lo_lsm->lsm_layout_gen == lsm->lsm_layout_gen) &&
	     (lov->lo_lsm->lsm_flags == lsm->lsm_flags) &&
	     (lov->lo_lsm->lsm_entries[0]->lsme_pattern ==
	      lsm->lsm_entries[0]->lsme_pattern))) {
		/* same version of layout */
		clear_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags);
		GOTO(out, result = 0);
	}

	/* will change layout - check if there still exists active IO. */
	if (atomic_read(&lov->lo_active_ios) > 0) {
		set_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags);
		GOTO(out, result = -EBUSY);
	}

	result = lov_layout_change(env, lov, lsm, conf);
	if (result)
		set_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags);
	else
		clear_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags);
	EXIT;

out:
	lov_conf_unlock(lov);
out_lsm:
	lov_lsm_put(lsm);
	CDEBUG(D_INODE, DFID" lo_layout_invalid=%u\n",
	       PFID(lu_object_fid(lov2lu(lov))),
	       test_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags));
	RETURN(result);
}

static void lov_object_delete(const struct lu_env *env, struct lu_object *obj)
{
        struct lov_object *lov = lu2lov(obj);

        ENTRY;
        LOV_2DISPATCH_VOID(lov, llo_delete, env, lov, &lov->u);
        EXIT;
}

static void lov_object_free(const struct lu_env *env, struct lu_object *obj)
{
        struct lov_object *lov = lu2lov(obj);

        ENTRY;
        LOV_2DISPATCH_VOID(lov, llo_fini, env, lov, &lov->u);
        lu_object_fini(obj);
        OBD_SLAB_FREE_PTR(lov, lov_object_kmem);
        EXIT;
}

static int lov_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        return LOV_2DISPATCH_NOLOCK(lu2lov(o), llo_print, env, cookie, p, o);
}

static int lov_page_init(const struct lu_env *env, struct cl_object *obj,
			 struct cl_page *page, pgoff_t index)
{
	return LOV_2DISPATCH_NOLOCK(cl2lov(obj), llo_page_init, env, obj, page,
				    index);
}

/**
 * Implements cl_object_operations::clo_io_init() method for lov
 * layer. Dispatches to the appropriate layout io initialization method.
 */
static int lov_io_init(const struct lu_env *env, struct cl_object *obj,
		       struct cl_io *io)
{
	CL_IO_SLICE_CLEAN(lov_env_io(env), lis_preserved);

	CDEBUG(D_INODE, DFID "io %p type %d ignore/verify layout %d/%d\n",
	       PFID(lu_object_fid(&obj->co_lu)), io, io->ci_type,
	       io->ci_ignore_layout, io->ci_verify_layout);

	/* IO type CIT_MISC with ci_ignore_layout set are usually invoked from
	 * the OSC layer. It shouldn't take lov layout conf lock in that case,
	 * because as long as the OSC object exists, the layout can't be
	 * reconfigured. */
	return LOV_2DISPATCH_MAYLOCK(cl2lov(obj), llo_io_init,
			!(io->ci_ignore_layout && io->ci_type == CIT_MISC),
			env, obj, io);
}

/**
 * An implementation of cl_object_operations::clo_attr_get() method for lov
 * layer. For raid0 layout this collects and merges attributes of all
 * sub-objects.
 */
static int lov_attr_get(const struct lu_env *env, struct cl_object *obj,
                        struct cl_attr *attr)
{
        /* do not take lock, as this function is called under a
         * spin-lock. Layout is protected from changing by ongoing IO. */
        return LOV_2DISPATCH_NOLOCK(cl2lov(obj), llo_getattr, env, obj, attr);
}

static int lov_attr_update(const struct lu_env *env, struct cl_object *obj,
			   const struct cl_attr *attr, unsigned valid)
{
	/*
	 * No dispatch is required here, as no layout implements this.
	 */
	return 0;
}

static int lov_lock_init(const struct lu_env *env, struct cl_object *obj,
		  struct cl_lock *lock, const struct cl_io *io)
{
	/* No need to lock because we've taken one refcount of layout.  */
	return LOV_2DISPATCH_NOLOCK(cl2lov(obj), llo_lock_init, env, obj, lock,
				    io);
}

/**
 * We calculate on which OST the mapping will end. If the length of mapping
 * is greater than (stripe_size * stripe_count) then the last_stripe will
 * will be one just before start_stripe. Else we check if the mapping
 * intersects each OST and find last_stripe.
 * This function returns the last_stripe and also sets the stripe_count
 * over which the mapping is spread
 *
 * \param lsm [in]		striping information for the file
 * \param index [in]		stripe component index
 * \param ext [in]		logical extent of mapping
 * \param start_stripe [in]	starting stripe of the mapping
 * \param stripe_count [out]	the number of stripes across which to map is
 *				returned
 *
 * \retval last_stripe		return the last stripe of the mapping
 */
static int fiemap_calc_last_stripe(struct lov_stripe_md *lsm, int index,
				   struct lu_extent *ext,
				   int start_stripe, int *stripe_count)
{
	struct lov_stripe_md_entry *lsme = lsm->lsm_entries[index];
	int init_stripe;
	int last_stripe;
	int i, j;

	init_stripe = lov_stripe_number(lsm, index, ext->e_start);

	if (ext->e_end - ext->e_start >
	    lsme->lsme_stripe_size * lsme->lsme_stripe_count) {
		if (init_stripe == start_stripe) {
			last_stripe = (start_stripe < 1) ?
				lsme->lsme_stripe_count - 1 : start_stripe - 1;
			*stripe_count = lsme->lsme_stripe_count;
		} else if (init_stripe < start_stripe) {
			last_stripe = (init_stripe < 1) ?
				lsme->lsme_stripe_count - 1 : init_stripe - 1;
			*stripe_count = lsme->lsme_stripe_count -
					(start_stripe - init_stripe);
		} else {
			last_stripe = init_stripe - 1;
			*stripe_count = init_stripe - start_stripe;
		}
	} else {
		for (j = 0, i = start_stripe; j < lsme->lsme_stripe_count;
		     i = (i + 1) % lsme->lsme_stripe_count, j++) {
			if (!lov_stripe_intersects(lsm, index,  i, ext, NULL,
						   NULL))
				break;
			if ((start_stripe != init_stripe) && (i == init_stripe))
				break;
		}
		*stripe_count = j;
		last_stripe = (start_stripe + j - 1) % lsme->lsme_stripe_count;
	}

	return last_stripe;
}

/**
 * Set fe_device and copy extents from local buffer into main return buffer.
 *
 * \param fiemap [out]		fiemap to hold all extents
 * \param lcl_fm_ext [in]	array of fiemap extents get from OSC layer
 * \param ost_index [in]	OST index to be written into the fm_device
 *				field for each extent
 * \param ext_count [in]	number of extents to be copied
 * \param current_extent [in]	where to start copying in the extent array
 */
static void fiemap_prepare_and_copy_exts(struct fiemap *fiemap,
					 struct fiemap_extent *lcl_fm_ext,
					 int ost_index, unsigned int ext_count,
					 int current_extent, int abs_stripeno)
{
	char		*to;
	unsigned int	ext;

	for (ext = 0; ext < ext_count; ext++) {
		set_fe_device_stripenr(&lcl_fm_ext[ext], ost_index,
				       abs_stripeno);
		lcl_fm_ext[ext].fe_flags |= FIEMAP_EXTENT_NET;
	}

	/* Copy fm_extent's from fm_local to return buffer */
	to = (char *)fiemap + fiemap_count_to_size(current_extent);
	memcpy(to, lcl_fm_ext, ext_count * sizeof(struct fiemap_extent));
}

#define FIEMAP_BUFFER_SIZE 4096

/**
 * Non-zero fe_logical indicates that this is a continuation FIEMAP
 * call. The local end offset and the device are sent in the first
 * fm_extent. This function calculates the stripe number from the index.
 * This function returns a stripe_no on which mapping is to be restarted.
 *
 * This function returns fm_end_offset which is the in-OST offset at which
 * mapping should be restarted. If fm_end_offset=0 is returned then caller
 * will re-calculate proper offset in next stripe.
 * Note that the first extent is passed to lov_get_info via the value field.
 *
 * \param fiemap [in]		fiemap request header
 * \param lsm [in]		striping information for the file
 * \param index [in]		stripe component index
 * \param ext [in]		logical extent of mapping
 * \param start_stripe [out]	starting stripe will be returned in this
 */
static u64 fiemap_calc_fm_end_offset(struct fiemap *fiemap,
				     struct lov_stripe_md *lsm,
				     int index, struct lu_extent *ext,
				     int *start_stripe)
{
	struct lov_stripe_md_entry *lsme = lsm->lsm_entries[index];
	u64 local_end = fiemap->fm_extents[0].fe_logical;
	u64 lun_end;
	u64 fm_end_offset;
	int stripe_no = -1;

	if (fiemap->fm_extent_count == 0 ||
	    fiemap->fm_extents[0].fe_logical == 0)
		return 0;

	stripe_no = *start_stripe;

	if (stripe_no == -1)
		return -EINVAL;

	/* If we have finished mapping on previous device, shift logical
	 * offset to start of next device */
	if (lov_stripe_intersects(lsm, index, stripe_no, ext, NULL, &lun_end) &&
	    local_end < lun_end) {
		fm_end_offset = local_end;
	} else {
		/* This is a special value to indicate that caller should
		 * calculate offset in next stripe. */
		fm_end_offset = 0;
		*start_stripe = (stripe_no + 1) % lsme->lsme_stripe_count;
	}

	return fm_end_offset;
}

struct fiemap_state {
	struct fiemap		*fs_fm;
	struct lu_extent	fs_ext;		/* current entry extent */
	u64			fs_length;
	u64			fs_end_offset;	/* last iteration offset */
	int			fs_cur_extent;	/* collected exts so far */
	int			fs_cnt_need;	/* # of extents buf can hold */
	int			fs_start_stripe;
	int			fs_last_stripe;
	bool			fs_device_done;	/* enough for this OST */
	bool			fs_finish_stripe; /* reached fs_last_stripe */
	bool			fs_enough;	/* enough for this call */
};

static struct cl_object *lov_find_subobj(const struct lu_env *env,
					 struct lov_object *lov,
					 struct lov_stripe_md *lsm,
					 int index)
{
	struct lov_device	*dev = lu2lov_dev(lov2lu(lov)->lo_dev);
	struct lov_thread_info  *lti = lov_env_info(env);
	struct lu_fid		*ofid = &lti->lti_fid;
	struct lov_oinfo	*oinfo;
	struct cl_device	*subdev;
	int			entry = lov_comp_entry(index);
	int			stripe = lov_comp_stripe(index);
	int			ost_idx;
	int			rc;
	struct cl_object	*result;

	if (lov->lo_type != LLT_COMP)
		GOTO(out, result = NULL);

	if (entry >= lsm->lsm_entry_count ||
	    stripe >= lsm->lsm_entries[entry]->lsme_stripe_count)
		GOTO(out, result = NULL);

	oinfo = lsm->lsm_entries[entry]->lsme_oinfo[stripe];
	ost_idx = oinfo->loi_ost_idx;
	rc = ostid_to_fid(ofid, &oinfo->loi_oi, ost_idx);
	if (rc != 0)
		GOTO(out, result = NULL);

	subdev = lovsub2cl_dev(dev->ld_target[ost_idx]);
	result = lov_sub_find(env, subdev, ofid, NULL);
out:
	if (result == NULL)
		result = ERR_PTR(-EINVAL);
	return result;
}

static int fiemap_for_stripe(const struct lu_env *env, struct cl_object *obj,
			     struct lov_stripe_md *lsm, struct fiemap *fiemap,
			     size_t *buflen, struct ll_fiemap_info_key *fmkey,
			     int index, int stripe_last, int stripeno,
			     struct fiemap_state *fs)
{
	struct lov_stripe_md_entry *lsme = lsm->lsm_entries[index];
	struct cl_object *subobj;
	struct lov_obd *lov = lu2lov_dev(obj->co_lu.lo_dev)->ld_lov;
	struct fiemap_extent *fm_ext = &fs->fs_fm->fm_extents[0];
	u64 req_fm_len; /* max requested extent coverage */
	u64 len_mapped_single_call;
	u64 obd_start;
	u64 obd_end;
	unsigned int ext_count;
	/* EOF for object */
	bool ost_eof = false;
	/* done with required mapping for this OST? */
	bool ost_done = false;
	int ost_index;
	int rc = 0;

	fs->fs_device_done = false;
	/* Find out range of mapping on this stripe */
	if ((lov_stripe_intersects(lsm, index, stripeno, &fs->fs_ext,
				   &obd_start, &obd_end)) == 0)
		return 0;

	if (lov_oinfo_is_dummy(lsme->lsme_oinfo[stripeno]))
		return -EIO;

	/* If this is a continuation FIEMAP call and we are on
	 * starting stripe then obd_start needs to be set to
	 * end_offset */
	if (fs->fs_end_offset != 0 && stripeno == fs->fs_start_stripe)
		obd_start = fs->fs_end_offset;

	if (lov_size_to_stripe(lsm, index, fs->fs_ext.e_end, stripeno) ==
	    obd_start)
		return 0;

	req_fm_len = obd_end - obd_start + 1;
	fs->fs_fm->fm_length = 0;
	len_mapped_single_call = 0;

	/* find lobsub object */
	subobj = lov_find_subobj(env, cl2lov(obj), lsm,
				 lov_comp_index(index, stripeno));
	if (IS_ERR(subobj))
		return PTR_ERR(subobj);
	/* If the output buffer is very large and the objects have many
	 * extents we may need to loop on a single OST repeatedly */
	do {
		if (fiemap->fm_extent_count > 0) {
			/* Don't get too many extents. */
			if (fs->fs_cur_extent + fs->fs_cnt_need >
			    fiemap->fm_extent_count)
				fs->fs_cnt_need = fiemap->fm_extent_count -
						  fs->fs_cur_extent;
		}

		obd_start += len_mapped_single_call;
		fs->fs_fm->fm_length = req_fm_len - len_mapped_single_call;
		req_fm_len = fs->fs_fm->fm_length;
		/**
		 * If we've collected enough extent map, we'd request 1 more,
		 * to see whether we coincidentally finished all available
		 * extent map, so that FIEMAP_EXTENT_LAST would be set.
		 */
		fs->fs_fm->fm_extent_count = fs->fs_enough ?
					     1 : fs->fs_cnt_need;
		fs->fs_fm->fm_mapped_extents = 0;
		fs->fs_fm->fm_flags = fiemap->fm_flags;

		ost_index = lsme->lsme_oinfo[stripeno]->loi_ost_idx;

		if (ost_index < 0 || ost_index >= lov->desc.ld_tgt_count)
			GOTO(obj_put, rc = -EINVAL);
		/* If OST is inactive, return extent with UNKNOWN flag. */
		if (!lov->lov_tgts[ost_index]->ltd_active) {
			fs->fs_fm->fm_flags |= FIEMAP_EXTENT_LAST;
			fs->fs_fm->fm_mapped_extents = 1;

			fm_ext[0].fe_logical = obd_start;
			fm_ext[0].fe_length = obd_end - obd_start + 1;
			fm_ext[0].fe_flags |= FIEMAP_EXTENT_UNKNOWN;

			goto inactive_tgt;
		}

		fs->fs_fm->fm_start = obd_start;
		fs->fs_fm->fm_flags &= ~FIEMAP_FLAG_DEVICE_ORDER;
		memcpy(&fmkey->lfik_fiemap, fs->fs_fm, sizeof(*fs->fs_fm));
		*buflen = fiemap_count_to_size(fs->fs_fm->fm_extent_count);

		rc = cl_object_fiemap(env, subobj, fmkey, fs->fs_fm, buflen);
		if (rc != 0)
			GOTO(obj_put, rc);
inactive_tgt:
		ext_count = fs->fs_fm->fm_mapped_extents;
		if (ext_count == 0) {
			ost_done = true;
			fs->fs_device_done = true;
			/* If last stripe has hold at the end,
			 * we need to return */
			if (stripeno == fs->fs_last_stripe) {
				fiemap->fm_mapped_extents = 0;
				fs->fs_finish_stripe = true;
				GOTO(obj_put, rc);
			}
			break;
		} else if (fs->fs_enough) {
			/*
			 * We've collected enough extents and there are
			 * more extents after it.
			 */
			GOTO(obj_put, rc);
		}

		/* If we just need num of extents, got to next device */
		if (fiemap->fm_extent_count == 0) {
			fs->fs_cur_extent += ext_count;
			break;
		}

		/* prepare to copy retrived map extents */
		len_mapped_single_call = fm_ext[ext_count - 1].fe_logical +
					 fm_ext[ext_count - 1].fe_length -
					 obd_start;

		/* Have we finished mapping on this device? */
		if (req_fm_len <= len_mapped_single_call) {
			ost_done = true;
			fs->fs_device_done = true;
		}

		/* Clear the EXTENT_LAST flag which can be present on
		 * the last extent */
		if (fm_ext[ext_count - 1].fe_flags & FIEMAP_EXTENT_LAST)
			fm_ext[ext_count - 1].fe_flags &= ~FIEMAP_EXTENT_LAST;
		if (lov_stripe_size(lsm, index,
				    fm_ext[ext_count - 1].fe_logical +
				    fm_ext[ext_count - 1].fe_length,
				    stripeno) >= fmkey->lfik_oa.o_size) {
			ost_eof = true;
			fs->fs_device_done = true;
		}

		fiemap_prepare_and_copy_exts(fiemap, fm_ext, ost_index,
					     ext_count, fs->fs_cur_extent,
					     stripe_last + stripeno);
		fs->fs_cur_extent += ext_count;

		/* Ran out of available extents? */
		if (fs->fs_cur_extent >= fiemap->fm_extent_count)
			fs->fs_enough = true;
	} while (!ost_done && !ost_eof);

	if (stripeno == fs->fs_last_stripe)
		fs->fs_finish_stripe = true;
obj_put:
	cl_object_put(env, subobj);

	return rc;
}

/**
 * Break down the FIEMAP request and send appropriate calls to individual OSTs.
 * This also handles the restarting of FIEMAP calls in case mapping overflows
 * the available number of extents in single call.
 *
 * \param env [in]		lustre environment
 * \param obj [in]		file object
 * \param fmkey [in]		fiemap request header and other info
 * \param fiemap [out]		fiemap buffer holding retrived map extents
 * \param buflen [in/out]	max buffer length of @fiemap, when iterate
 *				each OST, it is used to limit max map needed
 * \retval 0	success
 * \retval < 0	error
 */
static int lov_object_fiemap(const struct lu_env *env, struct cl_object *obj,
			     struct ll_fiemap_info_key *fmkey,
			     struct fiemap *fiemap, size_t *buflen)
{
	struct lov_stripe_md_entry *lsme;
	struct lov_stripe_md *lsm;
	struct fiemap *fm_local = NULL;
	loff_t whole_start;
	loff_t whole_end;
	int entry;
	int start_entry = -1;
	int end_entry;
	int cur_stripe = 0;
	int stripe_count;
	unsigned int buffer_size = FIEMAP_BUFFER_SIZE;
	int rc = 0;
	struct fiemap_state fs = { 0 };
	struct lu_extent range;
	int cur_ext;
	int stripe_last;
	int start_stripe = 0;
	bool resume = false;
	ENTRY;

	lsm = lov_lsm_addref(cl2lov(obj));
	if (lsm == NULL) {
		/* no extent: there is no object for mapping */
		fiemap->fm_mapped_extents = 0;
		return 0;
	}

	if (!(fiemap->fm_flags & FIEMAP_FLAG_DEVICE_ORDER)) {
		/**
		 * If the entry count > 1 or stripe_count > 1 and the
		 * application does not understand DEVICE_ORDER flag,
		 * it cannot interpret the extents correctly.
		 */
		if (lsm->lsm_entry_count > 1 ||
		    (lsm->lsm_entry_count == 1 &&
		     lsm->lsm_entries[0]->lsme_stripe_count > 1))
			GOTO(out_lsm, rc = -ENOTSUPP);
	}

	/* No support for DOM layout yet. */
	if (lsme_is_dom(lsm->lsm_entries[0]))
		GOTO(out_lsm, rc = -ENOTSUPP);

	if (lsm->lsm_is_released) {
		if (fiemap->fm_start < fmkey->lfik_oa.o_size) {
			/**
			 * released file, return a minimal FIEMAP if
			 * request fits in file-size.
			 */
			fiemap->fm_mapped_extents = 1;
			fiemap->fm_extents[0].fe_logical = fiemap->fm_start;
			if (fiemap->fm_start + fiemap->fm_length <
			    fmkey->lfik_oa.o_size)
				fiemap->fm_extents[0].fe_length =
					fiemap->fm_length;
			else
				fiemap->fm_extents[0].fe_length =
					fmkey->lfik_oa.o_size -
					fiemap->fm_start;
			fiemap->fm_extents[0].fe_flags |=
				FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_LAST;
		}
		GOTO(out_lsm, rc = 0);
	}

	/* buffer_size is small to hold fm_extent_count of extents. */
	if (fiemap_count_to_size(fiemap->fm_extent_count) < buffer_size)
		buffer_size = fiemap_count_to_size(fiemap->fm_extent_count);

	OBD_ALLOC_LARGE(fm_local, buffer_size);
	if (fm_local == NULL)
		GOTO(out_lsm, rc = -ENOMEM);

	/**
	 * Requested extent count exceeds the fiemap buffer size, shrink our
	 * ambition.
	 */
	if (fiemap_count_to_size(fiemap->fm_extent_count) > *buflen)
		fiemap->fm_extent_count = fiemap_size_to_count(*buflen);

	fs.fs_enough = false;
	fs.fs_cur_extent = 0;
	fs.fs_fm = fm_local;
	fs.fs_cnt_need = fiemap_size_to_count(buffer_size);

	whole_start = fiemap->fm_start;
	/* whole_start is beyond the end of the file */
	if (whole_start > fmkey->lfik_oa.o_size)
		GOTO(out_fm_local, rc = -EINVAL);
	whole_end = (fiemap->fm_length == OBD_OBJECT_EOF) ?
					fmkey->lfik_oa.o_size + 1 :
					whole_start + fiemap->fm_length;
	/**
	 * If fiemap->fm_length != OBD_OBJECT_EOF but whole_end exceeds file
	 * size
	 */
	if (whole_end > fmkey->lfik_oa.o_size + 1)
		whole_end = fmkey->lfik_oa.o_size + 1;

	/**
	 * the high 16bits of fe_device remember which stripe the last
	 * call has been arrived, we'd continue from there in this call.
	 */
	if (fiemap->fm_extent_count && fiemap->fm_extents[0].fe_logical)
		resume = true;
	stripe_last = get_fe_stripenr(&fiemap->fm_extents[0]);
	/**
	 * stripe_last records stripe number we've been processed in the last
	 * call
	 */
	end_entry = lsm->lsm_entry_count - 1;
	cur_stripe = 0;
	for (entry = 0; entry <= end_entry; entry++) {
		lsme = lsm->lsm_entries[entry];
		if (cur_stripe + lsme->lsme_stripe_count >= stripe_last) {
			start_entry = entry;
			start_stripe = stripe_last - cur_stripe;
			break;
		}

		cur_stripe += lsme->lsme_stripe_count;
	}
	if (start_entry == -1) {
		CERROR(DFID": FIEMAP does not init start entry, cur_stripe=%d, "
		       "stripe_last=%d\n", PFID(lu_object_fid(&obj->co_lu)),
		       cur_stripe, stripe_last);
		GOTO(out_fm_local, rc = -EINVAL);
	}
	/**
	 * @start_entry & @start_stripe records the position of fiemap
	 * resumption @stripe_last keeps recording the absolution position
	 * we'are processing. @resume indicates we'd honor @start_stripe.
	 */

	range.e_start = whole_start;
	range.e_end = whole_end;

	for (entry = start_entry; entry <= end_entry; entry++) {
		/* remeber to update stripe_last accordingly */
		lsme = lsm->lsm_entries[entry];

		/* FLR could contain component holes between entries */
		if (!lsme_inited(lsme)) {
			stripe_last += lsme->lsme_stripe_count;
			resume = false;
			continue;
		}

		if (!lu_extent_is_overlapped(&range, &lsme->lsme_extent)) {
			stripe_last += lsme->lsme_stripe_count;
			resume = false;
			continue;
		}

		/* prepare for a component entry iteration */
		if (lsme->lsme_extent.e_start > whole_start)
			fs.fs_ext.e_start = lsme->lsme_extent.e_start;
		else
			fs.fs_ext.e_start = whole_start;
		if (lsme->lsme_extent.e_end > whole_end)
			fs.fs_ext.e_end = whole_end;
		else
			fs.fs_ext.e_end = lsme->lsme_extent.e_end;

		/* Calculate start stripe, last stripe and length of mapping */
		if (resume) {
			fs.fs_start_stripe = start_stripe;
			/* put stripe_last to the first stripe of the comp */
			stripe_last -= start_stripe;
			resume = false;
		} else {
			fs.fs_start_stripe = lov_stripe_number(lsm, entry,
							fs.fs_ext.e_start);
		}
		fs.fs_last_stripe = fiemap_calc_last_stripe(lsm, entry,
					&fs.fs_ext, fs.fs_start_stripe,
					&stripe_count);
		/**
		 * A new mirror component is under process, reset
		 * fs.fs_end_offset and then fiemap_for_stripe() starts from
		 * the overlapping extent, otherwise starts from
		 * fs.fs_end_offset.
		 */
		if (entry > start_entry && lsme->lsme_extent.e_start == 0) {
			/* new mirror */
			fs.fs_end_offset = 0;
		} else {
			fs.fs_end_offset = fiemap_calc_fm_end_offset(fiemap,
						lsm, entry, &fs.fs_ext,
						&fs.fs_start_stripe);
		}

		/* Check each stripe */
		for (cur_stripe = fs.fs_start_stripe; stripe_count > 0;
		     --stripe_count,
		     cur_stripe = (cur_stripe + 1) % lsme->lsme_stripe_count) {
			/* reset fs_finish_stripe */
			fs.fs_finish_stripe = false;
			rc = fiemap_for_stripe(env, obj, lsm, fiemap, buflen,
					       fmkey, entry, stripe_last,
					       cur_stripe, &fs);
			if (rc < 0)
				GOTO(out_fm_local, rc);
			if (fs.fs_enough) {
				stripe_last += cur_stripe;
				GOTO(finish, rc);
			}
			if (fs.fs_finish_stripe)
				break;
		} /* for each stripe */
		stripe_last += lsme->lsme_stripe_count;
	} /* for covering layout component entry */

finish:
	if (fs.fs_cur_extent > 0)
		cur_ext = fs.fs_cur_extent - 1;
	else
		cur_ext = 0;

	/* done all the processing */
	if (entry > end_entry)
		fiemap->fm_extents[cur_ext].fe_flags |= FIEMAP_EXTENT_LAST;

	/* Indicate that we are returning device offsets unless file just has
	 * single stripe */
	if (lsm->lsm_entry_count > 1 ||
	    (lsm->lsm_entry_count == 1 &&
	     lsm->lsm_entries[0]->lsme_stripe_count > 1))
		fiemap->fm_flags |= FIEMAP_FLAG_DEVICE_ORDER;

	if (fiemap->fm_extent_count == 0)
		goto skip_last_device_calc;

skip_last_device_calc:
	fiemap->fm_mapped_extents = fs.fs_cur_extent;
out_fm_local:
	OBD_FREE_LARGE(fm_local, buffer_size);

out_lsm:
	lov_lsm_put(lsm);
	return rc;
}

static int lov_object_getstripe(const struct lu_env *env, struct cl_object *obj,
				struct lov_user_md __user *lum, size_t size)
{
	struct lov_object	*lov = cl2lov(obj);
	struct lov_stripe_md	*lsm;
	int			rc = 0;
	ENTRY;

	lsm = lov_lsm_addref(lov);
	if (lsm == NULL)
		RETURN(-ENODATA);

	rc = lov_getstripe(env, cl2lov(obj), lsm, lum, size);
	lov_lsm_put(lsm);
	RETURN(rc);
}

static int lov_object_layout_get(const struct lu_env *env,
				 struct cl_object *obj,
				 struct cl_layout *cl)
{
	struct lov_object *lov = cl2lov(obj);
	struct lov_stripe_md *lsm = lov_lsm_addref(lov);
	struct lu_buf *buf = &cl->cl_buf;
	ssize_t rc;
	ENTRY;

	if (lsm == NULL) {
		cl->cl_size = 0;
		cl->cl_layout_gen = CL_LAYOUT_GEN_EMPTY;

		RETURN(0);
	}

	cl->cl_size = lov_comp_md_size(lsm);
	cl->cl_layout_gen = lsm->lsm_layout_gen;
	cl->cl_is_released = lsm->lsm_is_released;
	cl->cl_is_composite = lsm_is_composite(lsm->lsm_magic);

	rc = lov_lsm_pack(lsm, buf->lb_buf, buf->lb_len);
	lov_lsm_put(lsm);

	/* return error or number of bytes */
	RETURN(rc);
}

static loff_t lov_object_maxbytes(struct cl_object *obj)
{
	struct lov_object *lov = cl2lov(obj);
	struct lov_stripe_md *lsm = lov_lsm_addref(lov);
	loff_t maxbytes;

	if (lsm == NULL)
		return LLONG_MAX;

	maxbytes = lsm->lsm_maxbytes;

	lov_lsm_put(lsm);

	return maxbytes;
}

static int lov_object_flush(const struct lu_env *env, struct cl_object *obj,
			    struct ldlm_lock *lock)
{
	return LOV_2DISPATCH_MAYLOCK(cl2lov(obj), llo_flush, true, env, obj,
				     lock);
}

static const struct cl_object_operations lov_ops = {
	.coo_page_init    = lov_page_init,
	.coo_lock_init    = lov_lock_init,
	.coo_io_init      = lov_io_init,
	.coo_attr_get     = lov_attr_get,
	.coo_attr_update  = lov_attr_update,
	.coo_conf_set     = lov_conf_set,
	.coo_getstripe    = lov_object_getstripe,
	.coo_layout_get   = lov_object_layout_get,
	.coo_maxbytes     = lov_object_maxbytes,
	.coo_fiemap       = lov_object_fiemap,
	.coo_object_flush = lov_object_flush
};

static const struct lu_object_operations lov_lu_obj_ops = {
	.loo_object_init	= lov_object_init,
	.loo_object_delete	= lov_object_delete,
	.loo_object_release	= NULL,
	.loo_object_free	= lov_object_free,
	.loo_object_print	= lov_object_print,
	.loo_object_invariant	= NULL,
};

struct lu_object *lov_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *unused,
				   struct lu_device *dev)
{
	struct lov_object *lov;
	struct lu_object  *obj;

	ENTRY;
	OBD_SLAB_ALLOC_PTR_GFP(lov, lov_object_kmem, GFP_NOFS);
	if (lov != NULL) {
		obj = lov2lu(lov);
		lu_object_init(obj, NULL, dev);
		lov->lo_cl.co_ops = &lov_ops;
		lov->lo_type = -1; /* invalid, to catch uninitialized type */
		/*
		 * object io operation vector (cl_object::co_iop) is installed
		 * later in lov_object_init(), as different vectors are used
		 * for object with different layouts.
		 */
		obj->lo_ops = &lov_lu_obj_ops;
	} else
		obj = NULL;
	RETURN(obj);
}

static struct lov_stripe_md *lov_lsm_addref(struct lov_object *lov)
{
	struct lov_stripe_md *lsm = NULL;

	lov_conf_freeze(lov);
	if (lov->lo_lsm != NULL) {
		lsm = lsm_addref(lov->lo_lsm);
		CDEBUG(D_INODE, "lsm %p addref %d/%d by %p.\n",
			lsm, atomic_read(&lsm->lsm_refc),
			test_bit(LO_LAYOUT_INVALID, &lov->lo_obj_flags),
			current);
	}
	lov_conf_thaw(lov);
	return lsm;
}

int lov_read_and_clear_async_rc(struct cl_object *clob)
{
	struct lu_object *luobj;
	int rc = 0;
	ENTRY;

	luobj = lu_object_locate(&cl_object_header(clob)->coh_lu,
				 &lov_device_type);
	if (luobj != NULL) {
		struct lov_object *lov = lu2lov(luobj);

		lov_conf_freeze(lov);
		switch (lov->lo_type) {
		case LLT_COMP: {
			struct lov_stripe_md *lsm;
			int i;

			lsm = lov->lo_lsm;
			LASSERT(lsm != NULL);
			for (i = 0; i < lsm->lsm_entry_count; i++) {
				struct lov_stripe_md_entry *lse =
						lsm->lsm_entries[i];
				int j;

				if (!lsme_inited(lse))
					break;

				for (j = 0; j < lse->lsme_stripe_count; j++) {
					struct lov_oinfo *loi =
							lse->lsme_oinfo[j];

					if (lov_oinfo_is_dummy(loi))
						continue;

					if (loi->loi_ar.ar_rc && !rc)
						rc = loi->loi_ar.ar_rc;
					loi->loi_ar.ar_rc = 0;
				}
			}
		}
		case LLT_RELEASED:
		case LLT_EMPTY:
			/* fall through */
		case LLT_FOREIGN:
			break;
		default:
			LBUG();
		}
		lov_conf_thaw(lov);
	}
	RETURN(rc);
}
EXPORT_SYMBOL(lov_read_and_clear_async_rc);

/** @} lov */
