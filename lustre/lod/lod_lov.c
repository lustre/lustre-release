/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * lustre/lod/lod_lov.c
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com> 
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_class.h>
#include <obd_lov.h>

#include "lod_internal.h"

/*
 * Keep a refcount of lod->ltd_tgts usage to prevent racing with
 * addition/deletion. Any function that expects lov_tgts to remain stationary
 * must take a ref.
 *
 * \param lod - is the lod device from which we want to grab a reference
 */
void lod_getref(struct lod_tgt_descs *ltd)
{
	down_read(&ltd->ltd_rw_sem);
	mutex_lock(&ltd->ltd_mutex);
	ltd->ltd_refcount++;
	mutex_unlock(&ltd->ltd_mutex);
}

/*
 * Companion of lod_getref() to release a reference on the lod table.
 * If this is the last reference and the ost entry was scheduled for deletion,
 * the descriptor is removed from the array.
 *
 * \param lod - is the lod device from which we release a reference
 */
void lod_putref(struct lod_device *lod, struct lod_tgt_descs *ltd)
{
	mutex_lock(&ltd->ltd_mutex);
	ltd->ltd_refcount--;
	if (ltd->ltd_refcount == 0 && ltd->ltd_death_row) {
		struct lod_tgt_desc *tgt_desc, *tmp;
		int                  idx;
		CFS_LIST_HEAD(kill);

		CDEBUG(D_CONFIG, "destroying %d ltd desc\n",
		       ltd->ltd_death_row);

		cfs_foreach_bit(ltd->ltd_tgt_bitmap, idx) {
			tgt_desc = LTD_TGT(ltd, idx);
			LASSERT(tgt_desc);

			if (!tgt_desc->ltd_reap)
				continue;

			cfs_list_add(&tgt_desc->ltd_kill, &kill);
			LTD_TGT(ltd, idx) = NULL;
			/*FIXME: only support ost pool for now */
			if (ltd == &lod->lod_ost_descs) {
				lod_ost_pool_remove(&lod->lod_pool_info, idx);
				if (tgt_desc->ltd_active)
					lod->lod_desc.ld_active_tgt_count--;
			}
			ltd->ltd_tgtnr--;
			cfs_bitmap_clear(ltd->ltd_tgt_bitmap, idx);
			ltd->ltd_death_row--;
		}
		mutex_unlock(&ltd->ltd_mutex);
		up_read(&ltd->ltd_rw_sem);

		cfs_list_for_each_entry_safe(tgt_desc, tmp, &kill, ltd_kill) {
			int rc;
			cfs_list_del(&tgt_desc->ltd_kill);
			if (ltd == &lod->lod_ost_descs) {
				/* remove from QoS structures */
				rc = qos_del_tgt(lod, tgt_desc);
				if (rc)
					CERROR("%s: qos_del_tgt(%s) failed:"
					       "rc = %d\n",
					       lod2obd(lod)->obd_name,
					      obd_uuid2str(&tgt_desc->ltd_uuid),
					       rc);
			}
			rc = obd_disconnect(tgt_desc->ltd_exp);
			if (rc)
				CERROR("%s: failed to disconnect %s: rc = %d\n",
				       lod2obd(lod)->obd_name,
				       obd_uuid2str(&tgt_desc->ltd_uuid), rc);
			OBD_FREE_PTR(tgt_desc);
		}
	} else {
		mutex_unlock(&ltd->ltd_mutex);
		up_read(&ltd->ltd_rw_sem);
	}
}

static int ltd_bitmap_resize(struct lod_tgt_descs *ltd, __u32 newsize)
{
	cfs_bitmap_t *new_bitmap, *old_bitmap = NULL;
	int	      rc = 0;
	ENTRY;

	/* grab write reference on the lod. Relocating the array requires
	 * exclusive access */

	down_write(&ltd->ltd_rw_sem);
	if (newsize <= ltd->ltd_tgts_size)
		/* someone else has already resize the array */
		GOTO(out, rc = 0);

	/* allocate new bitmap */
	new_bitmap = CFS_ALLOCATE_BITMAP(newsize);
	if (!new_bitmap)
		GOTO(out, rc = -ENOMEM);

	if (ltd->ltd_tgts_size > 0) {
		/* the bitmap already exists, we need
		 * to copy data from old one */
		cfs_bitmap_copy(new_bitmap, ltd->ltd_tgt_bitmap);
		old_bitmap = ltd->ltd_tgt_bitmap;
	}

	ltd->ltd_tgts_size  = newsize;
	ltd->ltd_tgt_bitmap = new_bitmap;

	if (old_bitmap)
		CFS_FREE_BITMAP(old_bitmap);

	CDEBUG(D_CONFIG, "tgt size: %d\n", ltd->ltd_tgts_size);

	EXIT;
out:
	up_write(&ltd->ltd_rw_sem);
	return rc;
}

/*
 * Connect LOD to a new OSP and add it to the device table.
 *
 * \param env - is the environment passed by the caller
 * \param lod - is the LOD device to be connected to the new OSP
 * \param osp - is the name of OSP device name about to be added
 * \param index - is the OSP index
 * \param gen - is the generation number
 * \param tgt_index - is the group of the OSP.
 * \param type - is the type of device (mdc or osc)
 */
int lod_add_device(const struct lu_env *env, struct lod_device *lod,
		   char *osp, unsigned index, unsigned gen, int tgt_index,
		   char *type, int active)
{
	struct obd_connect_data *data = NULL;
	struct obd_export	*exp = NULL;
	struct obd_device	*obd;
	struct lu_device	*ldev;
	struct dt_device	*d;
	int			 rc;
	struct lod_tgt_desc     *tgt_desc;
	struct lod_tgt_descs    *ltd;
	struct obd_uuid		obd_uuid;
	ENTRY;

	CDEBUG(D_CONFIG, "osp:%s idx:%d gen:%d\n", osp, index, gen);

	if (gen <= 0) {
		CERROR("request to add OBD %s with invalid generation: %d\n",
		       osp, gen);
		RETURN(-EINVAL);
	}

	obd_str2uuid(&obd_uuid, osp);

	obd = class_find_client_obd(&obd_uuid, LUSTRE_OSP_NAME,
				&lod->lod_dt_dev.dd_lu_dev.ld_obd->obd_uuid);
	if (obd == NULL) {
		CERROR("can't find %s device\n", osp);
		RETURN(-EINVAL);
	}

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		RETURN(-ENOMEM);

	data->ocd_connect_flags = OBD_CONNECT_INDEX | OBD_CONNECT_VERSION;
	data->ocd_version = LUSTRE_VERSION_CODE;
	data->ocd_index = index;

	if (strcmp(LUSTRE_OSC_NAME, type) == 0) {
		data->ocd_connect_flags |= OBD_CONNECT_AT |
					   OBD_CONNECT_FULL20 |
					   OBD_CONNECT_INDEX |
#ifdef HAVE_LRU_RESIZE_SUPPORT
					   OBD_CONNECT_LRU_RESIZE |
#endif
					   OBD_CONNECT_MDS |
					   OBD_CONNECT_OSS_CAPA |
					   OBD_CONNECT_REQPORTAL |
					   OBD_CONNECT_SKIP_ORPHAN |
					   OBD_CONNECT_FID |
					   OBD_CONNECT_LVB_TYPE |
					   OBD_CONNECT_VERSION |
					   OBD_CONNECT_PINGLESS;

		data->ocd_group = tgt_index;
		ltd = &lod->lod_ost_descs;
	} else {
		struct obd_import *imp = obd->u.cli.cl_import;

		data->ocd_ibits_known = MDS_INODELOCK_UPDATE;
		data->ocd_connect_flags |= OBD_CONNECT_ACL |
					   OBD_CONNECT_MDS_CAPA |
					   OBD_CONNECT_OSS_CAPA |
					   OBD_CONNECT_IBITS |
					   OBD_CONNECT_MDS_MDS |
					   OBD_CONNECT_FID |
					   OBD_CONNECT_AT |
					   OBD_CONNECT_FULL20;
		/* XXX set MDS-MDS flags, remove this when running this
		 * on client*/
		data->ocd_connect_flags |= OBD_CONNECT_MDS_MDS;
		spin_lock(&imp->imp_lock);
		imp->imp_server_timeout = 1;
		spin_unlock(&imp->imp_lock);
		imp->imp_client->cli_request_portal = OUT_PORTAL;
		CDEBUG(D_OTHER, "%s: Set 'mds' portal and timeout\n",
		      obd->obd_name);
		ltd = &lod->lod_mdt_descs;
	}

	rc = obd_connect(env, &exp, obd, &obd->obd_uuid, data, NULL);
	OBD_FREE_PTR(data);
	if (rc) {
		CERROR("%s: cannot connect to next dev %s (%d)\n",
		       obd->obd_name, osp, rc);
		GOTO(out_free, rc);
	}

	LASSERT(obd->obd_lu_dev);
	LASSERT(obd->obd_lu_dev->ld_site == lod->lod_dt_dev.dd_lu_dev.ld_site);

	ldev = obd->obd_lu_dev;
	d = lu2dt_dev(ldev);

	/* Allocate ost descriptor and fill it */
	OBD_ALLOC_PTR(tgt_desc);
	if (!tgt_desc)
		GOTO(out_conn, rc = -ENOMEM);

	tgt_desc->ltd_tgt    = d;
	tgt_desc->ltd_exp    = exp;
	tgt_desc->ltd_uuid   = obd->u.cli.cl_target_uuid;
	tgt_desc->ltd_gen    = gen;
	tgt_desc->ltd_index  = index;
	tgt_desc->ltd_active = active;

	lod_getref(ltd);
	if (index >= ltd->ltd_tgts_size) {
		/* we have to increase the size of the lod_osts array */
		__u32  newsize;

		newsize = max(ltd->ltd_tgts_size, (__u32)2);
		while (newsize < index + 1)
			newsize = newsize << 1;

		/* lod_bitmap_resize() needs lod_rw_sem
		 * which we hold with th reference */
		lod_putref(lod, ltd);

		rc = ltd_bitmap_resize(ltd, newsize);
		if (rc)
			GOTO(out_desc, rc);

		lod_getref(ltd);
	}

	mutex_lock(&ltd->ltd_mutex);
	if (cfs_bitmap_check(ltd->ltd_tgt_bitmap, index)) {
		CERROR("%s: device %d is registered already\n", obd->obd_name,
		       index);
		GOTO(out_mutex, rc = -EEXIST);
	}

	if (ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK] == NULL) {
		OBD_ALLOC_PTR(ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK]);
		if (ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK] == NULL) {
			CERROR("can't allocate index to add %s\n",
			       obd->obd_name);
			GOTO(out_mutex, rc = -ENOMEM);
		}
	}

	if (!strcmp(LUSTRE_OSC_NAME, type)) {
		/* pool and qos are not supported for MDS stack yet */
		rc = lod_ost_pool_add(&lod->lod_pool_info, index,
				      lod->lod_osts_size);
		if (rc) {
			CERROR("%s: can't set up pool, failed with %d\n",
			       obd->obd_name, rc);
			GOTO(out_mutex, rc);
		}

		rc = qos_add_tgt(lod, tgt_desc);
		if (rc) {
			CERROR("%s: qos_add_tgt failed with %d\n",
				obd->obd_name, rc);
			GOTO(out_pool, rc);
		}

		/* The new OST is now a full citizen */
		if (index >= lod->lod_desc.ld_tgt_count)
			lod->lod_desc.ld_tgt_count = index + 1;
		if (active)
			lod->lod_desc.ld_active_tgt_count++;
	}

	LTD_TGT(ltd, index) = tgt_desc;
	cfs_bitmap_set(ltd->ltd_tgt_bitmap, index);
	ltd->ltd_tgtnr++;
	mutex_unlock(&ltd->ltd_mutex);
	lod_putref(lod, ltd);
	if (lod->lod_recovery_completed)
		ldev->ld_ops->ldo_recovery_complete(env, ldev);

	RETURN(0);

out_pool:
	lod_ost_pool_remove(&lod->lod_pool_info, index);
out_mutex:
	mutex_unlock(&ltd->ltd_mutex);
	lod_putref(lod, ltd);
out_desc:
	OBD_FREE_PTR(tgt_desc);
out_conn:
	obd_disconnect(exp);
out_free:
	return rc;
}

/*
 * helper function to schedule OST removal from the device table
 */
static void __lod_del_device(struct lod_tgt_descs *ltd,
			     unsigned idx)
{
	LASSERT(LTD_TGT(ltd, idx));
	if (LTD_TGT(ltd, idx)->ltd_reap == 0) {
		LTD_TGT(ltd, idx)->ltd_reap = 1;
		ltd->ltd_death_row++;
	}
}

int lod_fini_tgt(struct lod_device *lod, struct lod_tgt_descs *ltd)
{
	int idx;

	if (ltd->ltd_tgts_size <= 0)
		return 0;
	lod_getref(ltd);
	mutex_lock(&ltd->ltd_mutex);
	cfs_foreach_bit(ltd->ltd_tgt_bitmap, idx)
		__lod_del_device(ltd, idx);
	mutex_unlock(&ltd->ltd_mutex);
	lod_putref(lod, ltd);
	CFS_FREE_BITMAP(ltd->ltd_tgt_bitmap);
	for (idx = 0; idx < TGT_PTRS; idx++) {
		if (ltd->ltd_tgt_idx[idx])
			OBD_FREE_PTR(ltd->ltd_tgt_idx[idx]);
	}
	ltd->ltd_tgts_size = 0;
	return 0;
}

/*
 * Add support for administratively disabled OST (through the MGS).
 * Schedule a target for deletion.  Disconnection and real removal from the
 * table takes place in lod_putref() once the last table user release its
 * reference.
 *
 * \param env - is the environment passed by the caller
 * \param lod - is the lod device currently connected to the OSP about to be
 *              removed
 * \param osp - is the name of OSP device about to be removed
 * \param idx - is the OSP index
 * \param gen - is the generation number, not used currently
 */
int lod_del_device(const struct lu_env *env, struct lod_device *lod,
		   struct lod_tgt_descs *ltd, char *osp, unsigned idx,
		   unsigned gen)
{
	struct obd_device *obd;
	int                rc = 0;
	struct obd_uuid    uuid;
	ENTRY;

	CDEBUG(D_CONFIG, "osp:%s idx:%d gen:%d\n", osp, idx, gen);

	obd_str2uuid(&uuid, osp);

	obd = class_find_client_obd(&uuid, LUSTRE_OSP_NAME,
				   &lod->lod_dt_dev.dd_lu_dev.ld_obd->obd_uuid);
	if (obd == NULL) {
		CERROR("can't find %s device\n", osp);
		RETURN(-EINVAL);
	}

	if (gen <= 0) {
		CERROR("%s: request to remove OBD %s with invalid generation %d"
		       "\n", obd->obd_name, osp, gen);
		RETURN(-EINVAL);
	}

	obd_str2uuid(&uuid,  osp);

	lod_getref(ltd);
	mutex_lock(&ltd->ltd_mutex);
	/* check that the index is allocated in the bitmap */
	if (!cfs_bitmap_check(ltd->ltd_tgt_bitmap, idx) ||
	    !LTD_TGT(ltd, idx)) {
		CERROR("%s: device %d is not set up\n", obd->obd_name, idx);
		GOTO(out, rc = -EINVAL);
	}

	/* check that the UUID matches */
	if (!obd_uuid_equals(&uuid, &LTD_TGT(ltd, idx)->ltd_uuid)) {
		CERROR("%s: LOD target UUID %s at index %d does not match %s\n",
		       obd->obd_name, obd_uuid2str(&LTD_TGT(ltd,idx)->ltd_uuid),
		       idx, osp);
		GOTO(out, rc = -EINVAL);
	}

	__lod_del_device(ltd, idx);
	EXIT;
out:
	mutex_unlock(&ltd->ltd_mutex);
	lod_putref(lod, ltd);
	return(rc);
}

int lod_ea_store_resize(struct lod_thread_info *info, int size)
{
	int round = size_roundup_power2(size);

	LASSERT(round <= lov_mds_md_size(LOV_MAX_STRIPE_COUNT, LOV_MAGIC_V3));
	if (info->lti_ea_store) {
		LASSERT(info->lti_ea_store_size);
		LASSERT(info->lti_ea_store_size < round);
		CDEBUG(D_INFO, "EA store size %d is not enough, need %d\n",
		       info->lti_ea_store_size, round);
		OBD_FREE_LARGE(info->lti_ea_store, info->lti_ea_store_size);
		info->lti_ea_store = NULL;
		info->lti_ea_store_size = 0;
	}

	OBD_ALLOC_LARGE(info->lti_ea_store, round);
	if (info->lti_ea_store == NULL)
		RETURN(-ENOMEM);
	info->lti_ea_store_size = round;
	RETURN(0);
}

/*
 * generate and write LOV EA for given striped object
 */
int lod_generate_and_set_lovea(const struct lu_env *env,
			       struct lod_object *lo, struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct dt_object	*next = dt_object_child(&lo->ldo_obj);
	const struct lu_fid	*fid  = lu_object_fid(&lo->ldo_obj.do_lu);
	struct lov_mds_md_v1	*lmm;
	struct lov_ost_data_v1	*objs;
	__u32			 magic;
	int			 i, rc, lmm_size;
	int			 cplen = 0;
	ENTRY;

	LASSERT(lo);

	magic = lo->ldo_pool != NULL ? LOV_MAGIC_V3 : LOV_MAGIC_V1;
	lmm_size = lov_mds_md_size(lo->ldo_stripenr, magic);
	if (info->lti_ea_store_size < lmm_size) {
		rc = lod_ea_store_resize(info, lmm_size);
		if (rc)
			RETURN(rc);
	}

	if (lo->ldo_pattern == 0) /* default striping */
		lo->ldo_pattern = LOV_PATTERN_RAID0;

	lmm = info->lti_ea_store;

	lmm->lmm_magic = cpu_to_le32(magic);
	lmm->lmm_pattern = cpu_to_le32(lo->ldo_pattern);
	fid_to_lmm_oi(fid, &lmm->lmm_oi);
	lmm_oi_cpu_to_le(&lmm->lmm_oi, &lmm->lmm_oi);
	lmm->lmm_stripe_size = cpu_to_le32(lo->ldo_stripe_size);
	lmm->lmm_stripe_count = cpu_to_le16(lo->ldo_stripenr);
	if (lo->ldo_pattern & LOV_PATTERN_F_RELEASED)
		lmm->lmm_stripe_count = cpu_to_le16(lo->ldo_released_stripenr);
	lmm->lmm_layout_gen = 0;
	if (magic == LOV_MAGIC_V1) {
		objs = &lmm->lmm_objects[0];
	} else {
		struct lov_mds_md_v3 *v3 = (struct lov_mds_md_v3 *) lmm;
		cplen = strlcpy(v3->lmm_pool_name, lo->ldo_pool,
				sizeof(v3->lmm_pool_name));
		if (cplen >= sizeof(v3->lmm_pool_name))
			RETURN(-E2BIG);
		objs = &v3->lmm_objects[0];
	}

	for (i = 0; i < lo->ldo_stripenr; i++) {
		const struct lu_fid	*fid;
		struct lod_device	*lod;
		__u32			index;

		lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
		LASSERT(lo->ldo_stripe[i]);
		fid = lu_object_fid(&lo->ldo_stripe[i]->do_lu);

		rc = fid_to_ostid(fid, &info->lti_ostid);
		LASSERT(rc == 0);

		ostid_cpu_to_le(&info->lti_ostid, &objs[i].l_ost_oi);
		objs[i].l_ost_gen    = cpu_to_le32(0);
		rc = lod_fld_lookup(env, lod, fid, &index, LU_SEQ_RANGE_OST);
		if (rc < 0) {
			lod_object_free_striping(env, lo);
			CERROR("%s: Can not locate "DFID": rc = %d\n",
			       lod2obd(lod)->obd_name, PFID(fid), rc);
			RETURN(rc);
		}
		objs[i].l_ost_idx = cpu_to_le32(index);
	}

	info->lti_buf.lb_buf = lmm;
	info->lti_buf.lb_len = lmm_size;
	rc = dt_xattr_set(env, next, &info->lti_buf, XATTR_NAME_LOV, 0,
			  th, BYPASS_CAPA);
	if (rc < 0)
		lod_object_free_striping(env, lo);

	RETURN(rc);
}

int lod_get_lov_ea(const struct lu_env *env, struct lod_object *lo)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct dt_object       *next = dt_object_child(&lo->ldo_obj);
	int			rc;
	ENTRY;

	LASSERT(info);

	if (unlikely(info->lti_ea_store_size == 0)) {
		/* just to enter in allocation block below */
		rc = -ERANGE;
	} else {
repeat:
		info->lti_buf.lb_buf = info->lti_ea_store;
		info->lti_buf.lb_len = info->lti_ea_store_size;
		rc = dt_xattr_get(env, next, &info->lti_buf, XATTR_NAME_LOV,
				  BYPASS_CAPA);
	}
	/* if object is not striped or inaccessible */
	if (rc == -ENODATA)
		RETURN(0);

	if (rc == -ERANGE) {
		/* EA doesn't fit, reallocate new buffer */
		rc = dt_xattr_get(env, next, &LU_BUF_NULL, XATTR_NAME_LOV,
				  BYPASS_CAPA);
		if (rc == -ENODATA)
			RETURN(0);
		else if (rc < 0)
			RETURN(rc);

		LASSERT(rc > 0);
		rc = lod_ea_store_resize(info, rc);
		if (rc)
			RETURN(rc);
		goto repeat;
	}

	RETURN(rc);
}

int lod_store_def_striping(const struct lu_env *env, struct dt_object *dt,
			   struct thandle *th)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_object	*lo = lod_dt_obj(dt);
	struct dt_object	*next = dt_object_child(dt);
	struct lov_user_md_v3	*v3;
	int			 rc;
	int			 cplen = 0;
	ENTRY;

	LASSERT(S_ISDIR(dt->do_lu.lo_header->loh_attr));

	/*
	 * store striping defaults into new directory
	 * used to implement defaults inheritance
	 */

	/* probably nothing to inherite */
	if (lo->ldo_striping_cached == 0)
		RETURN(0);

	if (LOVEA_DELETE_VALUES(lo->ldo_def_stripe_size, lo->ldo_def_stripenr,
				lo->ldo_def_stripe_offset, lo->ldo_pool))
		RETURN(0);

	/* XXX: use thread info */
	OBD_ALLOC_PTR(v3);
	if (v3 == NULL)
		RETURN(-ENOMEM);

	v3->lmm_magic = cpu_to_le32(LOV_MAGIC_V3);
	v3->lmm_pattern = cpu_to_le32(LOV_PATTERN_RAID0);
	v3->lmm_stripe_size = cpu_to_le32(lo->ldo_def_stripe_size);
	v3->lmm_stripe_count = cpu_to_le16(lo->ldo_def_stripenr);
	v3->lmm_stripe_offset = cpu_to_le16(lo->ldo_def_stripe_offset);
	if (lo->ldo_pool) {
		cplen = strlcpy(v3->lmm_pool_name, lo->ldo_pool,
				sizeof(v3->lmm_pool_name));
		if (cplen >= sizeof(v3->lmm_pool_name)) {
			OBD_FREE_PTR(v3);
			RETURN(-E2BIG);
		}
	}

	info->lti_buf.lb_buf = v3;
	info->lti_buf.lb_len = sizeof(*v3);
	rc = dt_xattr_set(env, next, &info->lti_buf, XATTR_NAME_LOV, 0, th,
			BYPASS_CAPA);

	OBD_FREE_PTR(v3);

	RETURN(rc);
}

static int validate_lod_and_idx(struct lod_device *md, int idx)
{
	if (unlikely(idx >= md->lod_ost_descs.ltd_tgts_size ||
		     !cfs_bitmap_check(md->lod_ost_bitmap, idx))) {
		CERROR("%s: bad idx: %d of %d\n", lod2obd(md)->obd_name, idx,
		       md->lod_ost_descs.ltd_tgts_size);
		return -EINVAL;
	}

	if (unlikely(OST_TGT(md, idx) == NULL)) {
		CERROR("%s: bad lod_tgt_desc for idx: %d\n",
		       lod2obd(md)->obd_name, idx);
		return -EINVAL;
	}

	if (unlikely(OST_TGT(md, idx)->ltd_ost == NULL)) {
		CERROR("%s: invalid lod device, for idx: %d\n",
		       lod2obd(md)->obd_name , idx);
		return -EINVAL;
	}

	return 0;
}

/*
 * allocate array of objects pointers, find/create objects
 * stripenr and other fields should be initialized by this moment
 */
int lod_initialize_objects(const struct lu_env *env, struct lod_object *lo,
			   struct lov_ost_data_v1 *objs)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_device	*md = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct lu_object	*o, *n;
	struct lu_device	*nd;
	struct dt_object       **stripe;
	int			 stripe_len;
	int			 i, idx, rc = 0;
	ENTRY;

	LASSERT(lo != NULL);
	LASSERT(lo->ldo_stripe == NULL);
	LASSERT(lo->ldo_stripenr > 0);
	LASSERT(lo->ldo_stripe_size > 0);

	stripe_len = lo->ldo_stripenr;
	OBD_ALLOC(stripe, sizeof(stripe[0]) * stripe_len);
	if (stripe == NULL)
		RETURN(-ENOMEM);

	for (i = 0; i < lo->ldo_stripenr; i++) {
		ostid_le_to_cpu(&objs[i].l_ost_oi, &info->lti_ostid);
		idx = le64_to_cpu(objs[i].l_ost_idx);
		rc = ostid_to_fid(&info->lti_fid, &info->lti_ostid, idx);
		if (rc != 0)
			GOTO(out, rc);
		LASSERTF(fid_is_sane(&info->lti_fid), ""DFID" insane!\n",
			 PFID(&info->lti_fid));
		lod_getref(&md->lod_ost_descs);

		rc = validate_lod_and_idx(md, idx);
		if (unlikely(rc != 0)) {
			lod_putref(md, &md->lod_ost_descs);
			GOTO(out, rc);
		}

		nd = &OST_TGT(md,idx)->ltd_ost->dd_lu_dev;
		lod_putref(md, &md->lod_ost_descs);

		/* In the function below, .hs_keycmp resolves to
		 * u_obj_hop_keycmp() */
		/* coverity[overrun-buffer-val] */
		o = lu_object_find_at(env, nd, &info->lti_fid, NULL);
		if (IS_ERR(o))
			GOTO(out, rc = PTR_ERR(o));

		n = lu_object_locate(o->lo_header, nd->ld_type);
		LASSERT(n);

		stripe[i] = container_of(n, struct dt_object, do_lu);
	}

out:
	if (rc != 0) {
		for (i = 0; i < stripe_len; i++)
			if (stripe[i] != NULL)
				lu_object_put(env, &stripe[i]->do_lu);

		OBD_FREE(stripe, sizeof(stripe[0]) * stripe_len);
	} else {
		lo->ldo_stripe = stripe;
		lo->ldo_stripes_allocated = stripe_len;
	}

	RETURN(rc);
}

/*
 * Parse striping information stored in lti_ea_store
 */
int lod_parse_striping(const struct lu_env *env, struct lod_object *lo,
		       const struct lu_buf *buf)
{
	struct lov_mds_md_v1	*lmm;
	struct lov_ost_data_v1	*objs;
	__u32			 magic;
	__u32			 pattern;
	int			 rc = 0;
	ENTRY;

	LASSERT(buf);
	LASSERT(buf->lb_buf);
	LASSERT(buf->lb_len);

	lmm = (struct lov_mds_md_v1 *) buf->lb_buf;
	magic = le32_to_cpu(lmm->lmm_magic);
	pattern = le32_to_cpu(lmm->lmm_pattern);

	if (magic != LOV_MAGIC_V1 && magic != LOV_MAGIC_V3)
		GOTO(out, rc = -EINVAL);
	if (lov_pattern(pattern) != LOV_PATTERN_RAID0)
		GOTO(out, rc = -EINVAL);

	lo->ldo_pattern = pattern;
	lo->ldo_stripe_size = le32_to_cpu(lmm->lmm_stripe_size);
	lo->ldo_layout_gen = le16_to_cpu(lmm->lmm_layout_gen);
	lo->ldo_stripenr = le16_to_cpu(lmm->lmm_stripe_count);
	/* released file stripenr fixup. */
	if (pattern & LOV_PATTERN_F_RELEASED)
		lo->ldo_stripenr = 0;

	LASSERT(buf->lb_len >= lov_mds_md_size(lo->ldo_stripenr, magic));

	if (magic == LOV_MAGIC_V3) {
		struct lov_mds_md_v3 *v3 = (struct lov_mds_md_v3 *) lmm;
		objs = &v3->lmm_objects[0];
		lod_object_set_pool(lo, v3->lmm_pool_name);
	} else {
		objs = &lmm->lmm_objects[0];
	}

	if (lo->ldo_stripenr > 0)
		rc = lod_initialize_objects(env, lo, objs);

out:
	RETURN(rc);
}

/*
 * Load and parse striping information, create in-core representation for the
 * stripes
 */
int lod_load_striping(const struct lu_env *env, struct lod_object *lo)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct dt_object	*next = dt_object_child(&lo->ldo_obj);
	int			 rc;
	ENTRY;

	/*
	 * currently this code is supposed to be called from declaration
	 * phase only, thus the object is not expected to be locked by caller
	 */
	dt_write_lock(env, next, 0);
	/* already initialized? */
	if (lo->ldo_stripe != NULL)
		GOTO(out, rc = 0);

	if (!dt_object_exists(next))
		GOTO(out, rc = 0);

	/* only regular files can be striped */
	if (!(lu_object_attr(lod2lu_obj(lo)) & S_IFREG))
		GOTO(out, rc = 0);

	rc = lod_get_lov_ea(env, lo);
	if (rc <= 0)
		GOTO(out, rc);

	/*
	 * there is LOV EA (striping information) in this object
	 * let's parse it and create in-core objects for the stripes
	 */
	info->lti_buf.lb_buf = info->lti_ea_store;
	info->lti_buf.lb_len = info->lti_ea_store_size;
	rc = lod_parse_striping(env, lo, &info->lti_buf);
out:
	dt_write_unlock(env, next);
	RETURN(rc);
}

/* verify the striping information for directory */
int lod_verify_striping(struct lod_device *d, const struct lu_buf *buf,
			bool is_from_disk)
{
	struct lov_user_md_v1	*lum;
	struct lov_user_md_v3	*lum3;
	struct pool_desc	*pool = NULL;
	__u32			 magic;
	__u32			 stripe_size;
	__u16			 stripe_count;
	__u16			 stripe_offset;
	size_t			 lum_size;
	int			 rc = 0;
	ENTRY;

	lum = buf->lb_buf;

	LASSERT(sizeof(*lum) < sizeof(*lum3));

	if (buf->lb_len < sizeof(*lum)) {
		CDEBUG(D_IOCTL, "buf len %zd too small for lov_user_md\n",
		       buf->lb_len);
		GOTO(out, rc = -EINVAL);
	}

	magic = le32_to_cpu(lum->lmm_magic);
	if (magic != LOV_USER_MAGIC_V1 &&
	    magic != LOV_USER_MAGIC_V3 &&
	    magic != LOV_MAGIC_V1_DEF &&
	    magic != LOV_MAGIC_V3_DEF) {
		CDEBUG(D_IOCTL, "bad userland LOV MAGIC: %#x\n", magic);
		GOTO(out, rc = -EINVAL);
	}

	/* the user uses "0" for default stripe pattern normally. */
	if (!is_from_disk && lum->lmm_pattern == 0)
		lum->lmm_pattern = cpu_to_le32(LOV_PATTERN_RAID0);

	if (le32_to_cpu(lum->lmm_pattern) != LOV_PATTERN_RAID0) {
		CDEBUG(D_IOCTL, "bad userland stripe pattern: %#x\n",
		       le32_to_cpu(lum->lmm_pattern));
		GOTO(out, rc = -EINVAL);
	}

	/* 64kB is the largest common page size we see (ia64), and matches the
	 * check in lfs */
	stripe_size = le32_to_cpu(lum->lmm_stripe_size);
	if (stripe_size & (LOV_MIN_STRIPE_SIZE - 1)) {
		CDEBUG(D_IOCTL, "stripe size %u not a multiple of %u\n",
		       stripe_size, LOV_MIN_STRIPE_SIZE);
		GOTO(out, rc = -EINVAL);
	}

	/* an offset of -1 is treated as a "special" valid offset */
	stripe_offset = le16_to_cpu(lum->lmm_stripe_offset);
	if (stripe_offset != (typeof(stripe_offset))-1) {
		/* if offset is not within valid range [0, osts_size) */
		if (stripe_offset >= d->lod_osts_size) {
			CDEBUG(D_IOCTL, "stripe offset %u >= bitmap size %u\n",
			       stripe_offset, d->lod_osts_size);
			GOTO(out, rc = -EINVAL);
		}

		/* if lmm_stripe_offset is *not* in bitmap */
		if (!cfs_bitmap_check(d->lod_ost_bitmap, stripe_offset)) {
			CDEBUG(D_IOCTL, "stripe offset %u not in bitmap\n",
			       stripe_offset);
			GOTO(out, rc = -EINVAL);
		}
	}

	if (magic == LOV_USER_MAGIC_V1 || magic == LOV_MAGIC_V1_DEF)
		lum_size = offsetof(struct lov_user_md_v1,
				    lmm_objects[0]);
	else if (magic == LOV_USER_MAGIC_V3 || magic == LOV_MAGIC_V3_DEF)
		lum_size = offsetof(struct lov_user_md_v3,
				    lmm_objects[0]);
	else
		GOTO(out, rc = -EINVAL);

	stripe_count = le16_to_cpu(lum->lmm_stripe_count);
	if (buf->lb_len != lum_size) {
		CDEBUG(D_IOCTL, "invalid buf len %zd for lov_user_md with "
		       "magic %#x and stripe_count %u\n",
		       buf->lb_len, magic, stripe_count);
		GOTO(out, rc = -EINVAL);
	}

	if (!(magic == LOV_USER_MAGIC_V3 || magic == LOV_MAGIC_V3_DEF))
		goto out;

	lum3 = buf->lb_buf;
	if (buf->lb_len < sizeof(*lum3)) {
		CDEBUG(D_IOCTL, "buf len %zd too small for lov_user_md_v3\n",
		       buf->lb_len);
		GOTO(out, rc = -EINVAL);
	}

	/* In the function below, .hs_keycmp resolves to
	 * pool_hashkey_keycmp() */
	/* coverity[overrun-buffer-val] */
	pool = lod_find_pool(d, lum3->lmm_pool_name);
	if (pool == NULL)
		goto out;

	if (stripe_offset != (typeof(stripe_offset))-1) {
		rc = lod_check_index_in_pool(stripe_offset, pool);
		if (rc < 0)
			GOTO(out, rc = -EINVAL);
	}

	if (is_from_disk && stripe_count > pool_tgt_count(pool)) {
		CDEBUG(D_IOCTL,
		       "stripe count %u > # OSTs %u in the pool\n",
		       stripe_count, pool_tgt_count(pool));
		GOTO(out, rc = -EINVAL);
	}

out:
	if (pool != NULL)
		lod_pool_putref(pool);

	RETURN(rc);
}

void lod_fix_desc_stripe_size(__u64 *val)
{
	if (*val < LOV_MIN_STRIPE_SIZE) {
		if (*val != 0)
			LCONSOLE_INFO("Increasing default stripe size to "
				      "minimum value %u\n",
				      LOV_DEFAULT_STRIPE_SIZE);
		*val = LOV_DEFAULT_STRIPE_SIZE;
	} else if (*val & (LOV_MIN_STRIPE_SIZE - 1)) {
		*val &= ~(LOV_MIN_STRIPE_SIZE - 1);
		LCONSOLE_WARN("Changing default stripe size to "LPU64" (a "
			      "multiple of %u)\n",
			      *val, LOV_MIN_STRIPE_SIZE);
	}
}

void lod_fix_desc_stripe_count(__u32 *val)
{
	if (*val == 0)
		*val = 1;
}

void lod_fix_desc_pattern(__u32 *val)
{
	/* from lov_setstripe */
	if ((*val != 0) && (*val != LOV_PATTERN_RAID0)) {
		LCONSOLE_WARN("Unknown stripe pattern: %#x\n", *val);
		*val = 0;
	}
}

void lod_fix_desc_qos_maxage(__u32 *val)
{
	/* fix qos_maxage */
	if (*val == 0)
		*val = QOS_DEFAULT_MAXAGE;
}

void lod_fix_desc(struct lov_desc *desc)
{
	lod_fix_desc_stripe_size(&desc->ld_default_stripe_size);
	lod_fix_desc_stripe_count(&desc->ld_default_stripe_count);
	lod_fix_desc_pattern(&desc->ld_pattern);
	lod_fix_desc_qos_maxage(&desc->ld_qos_maxage);
}

int lod_pools_init(struct lod_device *lod, struct lustre_cfg *lcfg)
{
	struct obd_device	   *obd;
	struct lov_desc		   *desc;
	int			    rc;
	ENTRY;

	obd = class_name2obd(lustre_cfg_string(lcfg, 0));
	LASSERT(obd != NULL);
	obd->obd_lu_dev = &lod->lod_dt_dev.dd_lu_dev;

	if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
		CERROR("LOD setup requires a descriptor\n");
		RETURN(-EINVAL);
	}

	desc = (struct lov_desc *)lustre_cfg_buf(lcfg, 1);

	if (sizeof(*desc) > LUSTRE_CFG_BUFLEN(lcfg, 1)) {
		CERROR("descriptor size wrong: %d > %d\n",
		       (int)sizeof(*desc), LUSTRE_CFG_BUFLEN(lcfg, 1));
		RETURN(-EINVAL);
	}

	if (desc->ld_magic != LOV_DESC_MAGIC) {
		if (desc->ld_magic == __swab32(LOV_DESC_MAGIC)) {
			CDEBUG(D_OTHER, "%s: Swabbing lov desc %p\n",
			       obd->obd_name, desc);
			lustre_swab_lov_desc(desc);
		} else {
			CERROR("%s: Bad lov desc magic: %#x\n",
			       obd->obd_name, desc->ld_magic);
			RETURN(-EINVAL);
		}
	}

	lod_fix_desc(desc);

	desc->ld_active_tgt_count = 0;
	lod->lod_desc = *desc;

	lod->lod_sp_me = LUSTRE_SP_CLI;

	/* Set up allocation policy (QoS and RR) */
	CFS_INIT_LIST_HEAD(&lod->lod_qos.lq_oss_list);
	init_rwsem(&lod->lod_qos.lq_rw_sem);
	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_rr.lqr_dirty = 1;
	lod->lod_qos.lq_reset = 1;
	/* Default priority is toward free space balance */
	lod->lod_qos.lq_prio_free = 232;
	/* Default threshold for rr (roughly 17%) */
	lod->lod_qos.lq_threshold_rr = 43;
	/* Init statfs fields */
	OBD_ALLOC_PTR(lod->lod_qos.lq_statfs_data);
	if (NULL == lod->lod_qos.lq_statfs_data)
		RETURN(-ENOMEM);
	init_waitqueue_head(&lod->lod_qos.lq_statfs_waitq);

	/* Set up OST pool environment */
	lod->lod_pools_hash_body = cfs_hash_create("POOLS", HASH_POOLS_CUR_BITS,
						   HASH_POOLS_MAX_BITS,
						   HASH_POOLS_BKT_BITS, 0,
						   CFS_HASH_MIN_THETA,
						   CFS_HASH_MAX_THETA,
						   &pool_hash_operations,
						   CFS_HASH_DEFAULT);
	if (!lod->lod_pools_hash_body)
		GOTO(out_statfs, rc = -ENOMEM);
	CFS_INIT_LIST_HEAD(&lod->lod_pool_list);
	lod->lod_pool_count = 0;
	rc = lod_ost_pool_init(&lod->lod_pool_info, 0);
	if (rc)
		GOTO(out_hash, rc);
	rc = lod_ost_pool_init(&lod->lod_qos.lq_rr.lqr_pool, 0);
	if (rc)
		GOTO(out_pool_info, rc);

	RETURN(0);

out_pool_info:
	lod_ost_pool_free(&lod->lod_pool_info);
out_hash:
	cfs_hash_putref(lod->lod_pools_hash_body);
out_statfs:
	OBD_FREE_PTR(lod->lod_qos.lq_statfs_data);
	return rc;
}

int lod_pools_fini(struct lod_device *lod)
{
	struct obd_device   *obd = lod2obd(lod);
	cfs_list_t	    *pos, *tmp;
	struct pool_desc    *pool;
	ENTRY;

	cfs_list_for_each_safe(pos, tmp, &lod->lod_pool_list) {
		pool = cfs_list_entry(pos, struct pool_desc, pool_list);
		/* free pool structs */
		CDEBUG(D_INFO, "delete pool %p\n", pool);
		/* In the function below, .hs_keycmp resolves to
		 * pool_hashkey_keycmp() */
		/* coverity[overrun-buffer-val] */
		lod_pool_del(obd, pool->pool_name);
	}

	cfs_hash_putref(lod->lod_pools_hash_body);
	lod_ost_pool_free(&(lod->lod_qos.lq_rr.lqr_pool));
	lod_ost_pool_free(&lod->lod_pool_info);
	OBD_FREE_PTR(lod->lod_qos.lq_statfs_data);
	RETURN(0);
}

