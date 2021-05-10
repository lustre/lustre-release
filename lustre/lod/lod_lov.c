/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * lustre/lod/lod_lov.c
 *
 * A set of helpers to maintain Logical Object Volume (LOV)
 * Extended Attribute (EA) and known OST targets
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_class.h>
#include <lustre_lfsck.h>
#include <lustre_lmv.h>
#include <lustre_swab.h>

#include "lod_internal.h"

/**
 * Increase reference count on the target table.
 *
 * Increase reference count on the target table usage to prevent racing with
 * addition/deletion. Any function that expects the table to remain
 * stationary must take a ref.
 *
 * \param[in] ltd	target table (lod_ost_descs or lod_mdt_descs)
 */
void lod_getref(struct lod_tgt_descs *ltd)
{
	down_read(&ltd->ltd_rw_sem);
	mutex_lock(&ltd->ltd_mutex);
	ltd->ltd_refcount++;
	mutex_unlock(&ltd->ltd_mutex);
}

/**
 * Decrease reference count on the target table.
 *
 * Companion of lod_getref() to release a reference on the target table.
 * If this is the last reference and the OST entry was scheduled for deletion,
 * the descriptor is removed from the table.
 *
 * \param[in] lod	LOD device from which we release a reference
 * \param[in] ltd	target table (lod_ost_descs or lod_mdt_descs)
 */
void lod_putref(struct lod_device *lod, struct lod_tgt_descs *ltd)
{
	mutex_lock(&ltd->ltd_mutex);
	ltd->ltd_refcount--;
	if (ltd->ltd_refcount == 0 && ltd->ltd_death_row) {
		struct lod_tgt_desc *tgt_desc, *tmp;
		LIST_HEAD(kill);

		CDEBUG(D_CONFIG, "destroying %d ltd desc\n",
		       ltd->ltd_death_row);

		ltd_foreach_tgt_safe(ltd, tgt_desc, tmp) {
			LASSERT(tgt_desc);
			if (!tgt_desc->ltd_reap)
				continue;

			list_add(&tgt_desc->ltd_kill, &kill);
			lu_tgt_pool_remove(&ltd->ltd_tgt_pool,
					   tgt_desc->ltd_index);
			ltd_del_tgt(ltd, tgt_desc);
			ltd->ltd_death_row--;
		}
		mutex_unlock(&ltd->ltd_mutex);
		up_read(&ltd->ltd_rw_sem);

		list_for_each_entry_safe(tgt_desc, tmp, &kill, ltd_kill) {
			int rc;

			list_del(&tgt_desc->ltd_kill);
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

/**
 * Connect LOD to a new OSP and add it to the target table.
 *
 * Connect to the OSP device passed, initialize all the internal
 * structures related to the device and add it to the target table.
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lod		LOD device to be connected to the new OSP
 * \param[in] osp		name of OSP device name to be added
 * \param[in] index		index of the new target
 * \param[in] gen		target's generation number
 * \param[in] tgt_index		OSP's group
 * \param[in] type		type of device (mdc or osc)
 * \param[in] active		state of OSP: 0 - inactive, 1 - active
 *
 * \retval			0 if added successfully
 * \retval			negative error number on failure
 */
int lod_add_device(const struct lu_env *env, struct lod_device *lod,
		   char *osp, unsigned index, unsigned gen, int tgt_index,
		   char *type, int active)
{
	struct obd_connect_data *data = NULL;
	struct obd_export	*exp = NULL;
	struct obd_device	*obd;
	struct lu_device	*lu_dev;
	struct dt_device	*dt_dev;
	int			 rc;
	struct lod_tgt_desc     *tgt_desc;
	struct lod_tgt_descs    *ltd;
	struct lustre_cfg	*lcfg;
	struct obd_uuid		obd_uuid;
	bool			for_ost;
	bool connected = false;
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

	LASSERT(obd->obd_lu_dev != NULL);
	LASSERT(obd->obd_lu_dev->ld_site == lod->lod_dt_dev.dd_lu_dev.ld_site);

	lu_dev = obd->obd_lu_dev;
	dt_dev = lu2dt_dev(lu_dev);

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		GOTO(out_cleanup, rc = -ENOMEM);

	data->ocd_connect_flags = OBD_CONNECT_INDEX | OBD_CONNECT_VERSION;
	data->ocd_version = LUSTRE_VERSION_CODE;
	data->ocd_index = index;

	if (strcmp(LUSTRE_OSC_NAME, type) == 0) {
		for_ost = true;
		data->ocd_connect_flags |= OBD_CONNECT_AT |
					   OBD_CONNECT_FULL20 |
					   OBD_CONNECT_INDEX |
#ifdef HAVE_LRU_RESIZE_SUPPORT
					   OBD_CONNECT_LRU_RESIZE |
#endif
					   OBD_CONNECT_MDS |
					   OBD_CONNECT_REQPORTAL |
					   OBD_CONNECT_SKIP_ORPHAN |
					   OBD_CONNECT_FID |
					   OBD_CONNECT_LVB_TYPE |
					   OBD_CONNECT_VERSION |
					   OBD_CONNECT_PINGLESS |
					   OBD_CONNECT_LFSCK |
					   OBD_CONNECT_BULK_MBITS;

		data->ocd_group = tgt_index;
		ltd = &lod->lod_ost_descs;
	} else {
		struct obd_import *imp = obd->u.cli.cl_import;

		for_ost = false;
		data->ocd_ibits_known = MDS_INODELOCK_UPDATE;
		data->ocd_connect_flags |= OBD_CONNECT_ACL |
					   OBD_CONNECT_IBITS |
					   OBD_CONNECT_MDS_MDS |
					   OBD_CONNECT_FID |
					   OBD_CONNECT_AT |
					   OBD_CONNECT_FULL20 |
					   OBD_CONNECT_LFSCK |
					   OBD_CONNECT_BULK_MBITS;
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
		GOTO(out_cleanup, rc);
	}
	connected = true;

	/* Allocate ost descriptor and fill it */
	OBD_ALLOC_PTR(tgt_desc);
	if (!tgt_desc)
		GOTO(out_cleanup, rc = -ENOMEM);

	tgt_desc->ltd_tgt    = dt_dev;
	tgt_desc->ltd_exp    = exp;
	tgt_desc->ltd_uuid   = obd->u.cli.cl_target_uuid;
	tgt_desc->ltd_gen    = gen;
	tgt_desc->ltd_index  = index;
	tgt_desc->ltd_active = active;

	down_write(&ltd->ltd_rw_sem);
	mutex_lock(&ltd->ltd_mutex);
	rc = ltd_add_tgt(ltd, tgt_desc);
	if (rc)
		GOTO(out_mutex, rc);

	rc = lu_qos_add_tgt(&ltd->ltd_qos, tgt_desc);
	if (rc)
		GOTO(out_del_tgt, rc);

	rc = lu_tgt_pool_add(&ltd->ltd_tgt_pool, index,
			  ltd->ltd_lov_desc.ld_tgt_count);
	if (rc) {
		CERROR("%s: can't set up pool, failed with %d\n",
		       obd->obd_name, rc);
		GOTO(out_del_tgt, rc);
	}

	mutex_unlock(&ltd->ltd_mutex);
	up_write(&ltd->ltd_rw_sem);

	if (lod->lod_recovery_completed)
		lu_dev->ld_ops->ldo_recovery_complete(env, lu_dev);

	if (!for_ost && lod->lod_initialized) {
		rc = lod_sub_init_llog(env, lod, tgt_desc->ltd_tgt);
		if (rc != 0) {
			CERROR("%s: cannot start llog on %s:rc = %d\n",
			       lod2obd(lod)->obd_name, osp, rc);
			GOTO(out_ltd, rc);
		}
	}

	rc = lfsck_add_target(env, lod->lod_child, dt_dev, exp, index, for_ost);
	if (rc != 0) {
		CERROR("Fail to add LFSCK target: name = %s, type = %s, "
		       "index = %u, rc = %d\n", osp, type, index, rc);
		GOTO(out_fini_llog, rc);
	}
	RETURN(rc);
out_fini_llog:
	lod_sub_fini_llog(env, tgt_desc->ltd_tgt,
			  &tgt_desc->ltd_recovery_task);
out_ltd:
	down_write(&ltd->ltd_rw_sem);
	mutex_lock(&ltd->ltd_mutex);
	lu_tgt_pool_remove(&ltd->ltd_tgt_pool, index);
out_del_tgt:
	ltd_del_tgt(ltd, tgt_desc);
out_mutex:
	mutex_unlock(&ltd->ltd_mutex);
	up_write(&ltd->ltd_rw_sem);
	OBD_FREE_PTR(tgt_desc);
out_cleanup:
	/* XXX OSP needs us to send down LCFG_CLEANUP because it uses
	 * objects from the MDT stack. See LU-7184. */
	lcfg = &lod_env_info(env)->lti_lustre_cfg;
	memset(lcfg, 0, sizeof(*lcfg));
	lcfg->lcfg_version = LUSTRE_CFG_VERSION;
	lcfg->lcfg_command = LCFG_CLEANUP;
	lu_dev->ld_ops->ldo_process_config(env, lu_dev, lcfg);

	if (connected)
		obd_disconnect(exp);

	return rc;
}

/**
 * Schedule target removal from the target table.
 *
 * Mark the device as dead. The device is not removed here because it may
 * still be in use. The device will be removed in lod_putref() when the
 * last reference is released.
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lod		LOD device the target table belongs to
 * \param[in] ltd		target table
 * \param[in] tgt		target
 */
static void __lod_del_device(const struct lu_env *env, struct lod_device *lod,
			     struct lod_tgt_descs *ltd, struct lu_tgt_desc *tgt)
{
	lfsck_del_target(env, lod->lod_child, tgt->ltd_tgt, tgt->ltd_index,
			 !ltd->ltd_is_mdt);

	if (!tgt->ltd_reap) {
		tgt->ltd_reap = 1;
		ltd->ltd_death_row++;
	}
}

/**
 * Schedule removal of all the targets from the given target table.
 *
 * See more details in the description for __lod_del_device()
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lod		LOD device the target table belongs to
 * \param[in] ltd		target table
 *
 * \retval			0 always
 */
int lod_fini_tgt(const struct lu_env *env, struct lod_device *lod,
		 struct lod_tgt_descs *ltd)
{
	struct lu_tgt_desc *tgt;

	if (ltd->ltd_tgts_size <= 0)
		return 0;

	lod_getref(ltd);
	mutex_lock(&ltd->ltd_mutex);
	ltd_foreach_tgt(ltd, tgt)
		__lod_del_device(env, lod, ltd, tgt);
	mutex_unlock(&ltd->ltd_mutex);
	lod_putref(lod, ltd);

	lu_tgt_descs_fini(ltd);

	return 0;
}

/**
 * Remove device by name.
 *
 * Remove a device identified by \a osp from the target table. Given
 * the device can be in use, the real deletion happens in lod_putref().
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lod		LOD device to be connected to the new OSP
 * \param[in] ltd		target table
 * \param[in] osp		name of OSP device to be removed
 * \param[in] idx		index of the target
 * \param[in] gen		generation number, not used currently
 *
 * \retval			0 if the device was scheduled for removal
 * \retval			-EINVAL if no device was found
 */
int lod_del_device(const struct lu_env *env, struct lod_device *lod,
		   struct lod_tgt_descs *ltd, char *osp, unsigned int idx,
		   unsigned int gen)
{
	struct obd_device *obd;
	struct lu_tgt_desc *tgt;
	struct obd_uuid uuid;
	int rc = 0;

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
	tgt = LTD_TGT(ltd, idx);
	/* check that the index is allocated in the bitmap */
	if (!test_bit(idx, ltd->ltd_tgt_bitmap) || !tgt) {
		CERROR("%s: device %d is not set up\n", obd->obd_name, idx);
		GOTO(out, rc = -EINVAL);
	}

	/* check that the UUID matches */
	if (!obd_uuid_equals(&uuid, &tgt->ltd_uuid)) {
		CERROR("%s: LOD target UUID %s at index %d does not match %s\n",
		       obd->obd_name, obd_uuid2str(&tgt->ltd_uuid), idx, osp);
		GOTO(out, rc = -EINVAL);
	}

	__lod_del_device(env, lod, ltd, tgt);
	EXIT;
out:
	mutex_unlock(&ltd->ltd_mutex);
	lod_putref(lod, ltd);
	return(rc);
}

/**
 * Resize per-thread storage to hold specified size.
 *
 * A helper function to resize per-thread temporary storage. This storage
 * is used to process LOV/LVM EAs and may be quite large. We do not want to
 * allocate/release it every time, so instead we put it into the env and
 * reallocate on demand. The memory is released when the correspondent thread
 * is finished.
 *
 * \param[in] info		LOD-specific storage in the environment
 * \param[in] size		new size to grow the buffer to

 * \retval			0 on success, -ENOMEM if reallocation failed
 */
int lod_ea_store_resize(struct lod_thread_info *info, size_t size)
{
	__u32 round = size_roundup_power2(size);

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

static void lod_free_comp_buffer(struct lod_layout_component *entries,
				 __u16 count, __u32 bufsize)
{
	struct lod_layout_component *entry;
	int i;

	for (i = 0; i < count; i++) {
		entry = &entries[i];
		if (entry->llc_pool != NULL)
			lod_set_pool(&entry->llc_pool, NULL);
		if (entry->llc_ostlist.op_array)
			OBD_FREE(entry->llc_ostlist.op_array,
				 entry->llc_ostlist.op_size);
		LASSERT(entry->llc_stripe == NULL);
		LASSERT(entry->llc_stripes_allocated == 0);
	}

	if (bufsize != 0)
		OBD_FREE_LARGE(entries, bufsize);
}

void lod_free_def_comp_entries(struct lod_default_striping *lds)
{
	lod_free_comp_buffer(lds->lds_def_comp_entries,
			     lds->lds_def_comp_size_cnt,
			     size_roundup_power2(
				     sizeof(*lds->lds_def_comp_entries) *
				     lds->lds_def_comp_size_cnt));
	lds->lds_def_comp_entries = NULL;
	lds->lds_def_comp_cnt = 0;
	lds->lds_def_striping_is_composite = 0;
	lds->lds_def_comp_size_cnt = 0;
}

/**
 * Resize per-thread storage to hold default striping component entries
 *
 * A helper function to resize per-thread temporary storage. This storage
 * is used to hold default LOV/LVM EAs and may be quite large. We do not want
 * to allocate/release it every time, so instead we put it into the env and
 * reallocate it on demand. The memory is released when the correspondent
 * thread is finished.
 *
 * \param[in,out] lds		default striping
 * \param[in] count		new component count to grow the buffer to

 * \retval			0 on success, -ENOMEM if reallocation failed
 */
int lod_def_striping_comp_resize(struct lod_default_striping *lds, __u16 count)
{
	struct lod_layout_component *entries;
	__u32 new = size_roundup_power2(sizeof(*lds->lds_def_comp_entries) *
					count);
	__u32 old = size_roundup_power2(sizeof(*lds->lds_def_comp_entries) *
					lds->lds_def_comp_size_cnt);

	if (new <= old)
		return 0;

	OBD_ALLOC_LARGE(entries, new);
	if (entries == NULL)
		return -ENOMEM;

	if (lds->lds_def_comp_entries != NULL) {
		CDEBUG(D_INFO, "default striping component size %d is not "
		       "enough, need %d\n", old, new);
		lod_free_def_comp_entries(lds);
	}

	lds->lds_def_comp_entries = entries;
	lds->lds_def_comp_size_cnt = count;

	RETURN(0);
}

void lod_free_comp_entries(struct lod_object *lo)
{
	if (lo->ldo_mirrors) {
		OBD_FREE_PTR_ARRAY(lo->ldo_mirrors, lo->ldo_mirror_count);
		lo->ldo_mirrors = NULL;
		lo->ldo_mirror_count = 0;
	}
	lod_free_comp_buffer(lo->ldo_comp_entries,
			     lo->ldo_comp_cnt,
			     sizeof(*lo->ldo_comp_entries) * lo->ldo_comp_cnt);
	lo->ldo_comp_entries = NULL;
	lo->ldo_comp_cnt = 0;
	lo->ldo_is_composite = 0;
}

int lod_alloc_comp_entries(struct lod_object *lo,
			   int mirror_count, int comp_count)
{
	LASSERT(comp_count != 0);
	LASSERT(lo->ldo_comp_cnt == 0 && lo->ldo_comp_entries == NULL);

	if (mirror_count > 0) {
		OBD_ALLOC_PTR_ARRAY(lo->ldo_mirrors, mirror_count);
		if (!lo->ldo_mirrors)
			return -ENOMEM;

		lo->ldo_mirror_count = mirror_count;
	}

	OBD_ALLOC_LARGE(lo->ldo_comp_entries,
			sizeof(*lo->ldo_comp_entries) * comp_count);
	if (lo->ldo_comp_entries == NULL) {
		OBD_FREE_PTR_ARRAY(lo->ldo_mirrors, mirror_count);
		lo->ldo_mirror_count = 0;
		return -ENOMEM;
	}

	lo->ldo_comp_cnt = comp_count;
	return 0;
}

int lod_fill_mirrors(struct lod_object *lo)
{
	struct lod_layout_component *lod_comp;
	int mirror_idx = -1;
	__u16 mirror_id = 0xffff;
	int i;
	ENTRY;

	LASSERT(equi(!lo->ldo_is_composite, lo->ldo_mirror_count == 0));

	if (!lo->ldo_is_composite)
		RETURN(0);

	lod_comp = &lo->ldo_comp_entries[0];
	for (i = 0; i < lo->ldo_comp_cnt; i++, lod_comp++) {
		int stale = !!(lod_comp->llc_flags & LCME_FL_STALE);
		int preferred = !!(lod_comp->llc_flags & LCME_FL_PREF_WR);

		if (mirror_id_of(lod_comp->llc_id) == mirror_id) {
			lo->ldo_mirrors[mirror_idx].lme_stale |= stale;
			lo->ldo_mirrors[mirror_idx].lme_prefer |= preferred;
			lo->ldo_mirrors[mirror_idx].lme_end = i;
			continue;
		}

		/* new mirror */
		++mirror_idx;
		if (mirror_idx >= lo->ldo_mirror_count)
			RETURN(-EINVAL);

		mirror_id = mirror_id_of(lod_comp->llc_id);

		lo->ldo_mirrors[mirror_idx].lme_id = mirror_id;
		lo->ldo_mirrors[mirror_idx].lme_stale = stale;
		lo->ldo_mirrors[mirror_idx].lme_prefer = preferred;
		lo->ldo_mirrors[mirror_idx].lme_start = i;
		lo->ldo_mirrors[mirror_idx].lme_end = i;
	}
	if (mirror_idx != lo->ldo_mirror_count - 1)
		RETURN(-EINVAL);

	RETURN(0);
}

/**
 * Generate on-disk lov_mds_md structure for each layout component based on
 * the information in lod_object->ldo_comp_entries[i].
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lo		LOD object
 * \param[in] comp_idx		index of ldo_comp_entries
 * \param[in] lmm		buffer to cotain the on-disk lov_mds_md
 * \param[in|out] lmm_size	buffer size/lmm size
 * \param[in] is_dir		generate lov ea for dir or file? For dir case,
 *				the stripe info is from the default stripe
 *				template, which is collected in lod_ah_init(),
 *				either from parent object or root object; for
 *				file case, it's from the @lo object
 *
 * \retval			0 if on disk structure is created successfully
 * \retval			negative error number on failure
 */
static int lod_gen_component_ea(const struct lu_env *env,
				struct lod_object *lo, int comp_idx,
				struct lov_mds_md *lmm, int *lmm_size,
				bool is_dir)
{
	struct lod_thread_info	*info = lod_env_info(env);
	const struct lu_fid	*fid  = lu_object_fid(&lo->ldo_obj.do_lu);
	struct lod_device	*lod;
	struct lov_ost_data_v1	*objs;
	struct lod_layout_component *lod_comp;
	__u32	magic;
	__u16 stripe_count;
	int	i, rc = 0;
	ENTRY;

	LASSERT(lo);
	if (is_dir)
		lod_comp =
			&lo->ldo_def_striping->lds_def_comp_entries[comp_idx];
	else
		lod_comp = &lo->ldo_comp_entries[comp_idx];

	magic = lod_comp->llc_pool != NULL ? LOV_MAGIC_V3 : LOV_MAGIC_V1;
	if (lod_comp->llc_pattern == 0) /* default striping */
		lod_comp->llc_pattern = LOV_PATTERN_RAID0;

	lmm->lmm_magic = cpu_to_le32(magic);
	lmm->lmm_pattern = cpu_to_le32(lod_comp->llc_pattern);
	fid_to_lmm_oi(fid, &lmm->lmm_oi);
	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_LMMOI))
		lmm->lmm_oi.oi.oi_id++;
	lmm_oi_cpu_to_le(&lmm->lmm_oi, &lmm->lmm_oi);

	lmm->lmm_stripe_size = cpu_to_le32(lod_comp->llc_stripe_size);
	lmm->lmm_stripe_count = cpu_to_le16(lod_comp->llc_stripe_count);
	/**
	 * for dir and uninstantiated component, lmm_layout_gen stores
	 * default stripe offset.
	 */
	lmm->lmm_layout_gen =
		(is_dir || !lod_comp_inited(lod_comp)) ?
			cpu_to_le16(lod_comp->llc_stripe_offset) :
			cpu_to_le16(lod_comp->llc_layout_gen);

	if (magic == LOV_MAGIC_V1) {
		objs = &lmm->lmm_objects[0];
	} else {
		struct lov_mds_md_v3 *v3 = (struct lov_mds_md_v3 *)lmm;
		size_t cplen = strlcpy(v3->lmm_pool_name,
				       lod_comp->llc_pool,
				       sizeof(v3->lmm_pool_name));
		if (cplen >= sizeof(v3->lmm_pool_name))
			RETURN(-E2BIG);
		objs = &v3->lmm_objects[0];
	}
	stripe_count = lod_comp_entry_stripe_count(lo, comp_idx, is_dir);
	if (stripe_count == 0 && !is_dir &&
	    !(lod_comp->llc_pattern & LOV_PATTERN_F_RELEASED) &&
	    !(lod_comp->llc_pattern & LOV_PATTERN_MDT))
		RETURN(-E2BIG);

	if (!is_dir && lo->ldo_is_composite)
		lod_comp_shrink_stripe_count(lod_comp, &stripe_count);

	if (is_dir || lod_comp->llc_pattern & LOV_PATTERN_F_RELEASED)
		GOTO(done, rc = 0);

	/* generate ost_idx of this component stripe */
	lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	for (i = 0; i < stripe_count; i++) {
		struct dt_object *object;
		__u32 ost_idx = (__u32)-1UL;
		int type = LU_SEQ_RANGE_OST;

		if (lod_comp->llc_stripe && lod_comp->llc_stripe[i]) {
			object = lod_comp->llc_stripe[i];
			/* instantiated component */
			info->lti_fid = *lu_object_fid(&object->do_lu);

			if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_MULTIPLE_REF) &&
			    comp_idx == 0) {
				if (cfs_fail_val == 0)
					cfs_fail_val = info->lti_fid.f_oid;
				else if (i == 0)
					info->lti_fid.f_oid = cfs_fail_val;
			}

			rc = fid_to_ostid(&info->lti_fid, &info->lti_ostid);
			LASSERT(rc == 0);

			ostid_cpu_to_le(&info->lti_ostid, &objs[i].l_ost_oi);
			objs[i].l_ost_gen = cpu_to_le32(0);
			if (OBD_FAIL_CHECK(OBD_FAIL_MDS_FLD_LOOKUP))
				rc = -ENOENT;
			else
				rc = lod_fld_lookup(env, lod, &info->lti_fid,
						    &ost_idx, &type);
			if (rc < 0) {
				CERROR("%s: Can not locate "DFID": rc = %d\n",
				       lod2obd(lod)->obd_name,
				       PFID(&info->lti_fid), rc);
				RETURN(rc);
			}
		} else if (lod_comp->llc_ostlist.op_array &&
			   lod_comp->llc_ostlist.op_count) {
			/* user specified ost list */
			ost_idx = lod_comp->llc_ostlist.op_array[i];
		}
		/*
		 * with un-instantiated or with no specified ost list
		 * component, its l_ost_idx does not matter.
		 */
		objs[i].l_ost_idx = cpu_to_le32(ost_idx);
	}
done:
	if (lmm_size != NULL)
		*lmm_size = lov_mds_md_size(stripe_count, magic);
	RETURN(rc);
}

/**
 * Generate on-disk lov_mds_md structure based on the information in
 * the lod_object->ldo_comp_entries.
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lo		LOD object
 * \param[in] lmm		buffer to cotain the on-disk lov_mds_md
 * \param[in|out] lmm_size	buffer size/lmm size
 * \param[in] is_dir		generate lov ea for dir or file? For dir case,
 *				the stripe info is from the default stripe
 *				template, which is collected in lod_ah_init(),
 *				either from parent object or root object; for
 *				file case, it's from the @lo object
 *
 * \retval			0 if on disk structure is created successfully
 * \retval			negative error number on failure
 */
int lod_generate_lovea(const struct lu_env *env, struct lod_object *lo,
		       struct lov_mds_md *lmm, int *lmm_size, bool is_dir)
{
	struct lov_comp_md_entry_v1 *lcme;
	struct lov_comp_md_v1 *lcm;
	struct lod_layout_component *comp_entries;
	__u16 comp_cnt, mirror_cnt;
	bool is_composite, is_foreign = false;
	int i, rc = 0, offset;
	ENTRY;

	if (is_dir) {
		comp_cnt = lo->ldo_def_striping->lds_def_comp_cnt;
		mirror_cnt = lo->ldo_def_striping->lds_def_mirror_cnt;
		comp_entries = lo->ldo_def_striping->lds_def_comp_entries;
		is_composite =
			lo->ldo_def_striping->lds_def_striping_is_composite;
	} else {
		comp_cnt = lo->ldo_comp_cnt;
		mirror_cnt = lo->ldo_mirror_count;
		comp_entries = lo->ldo_comp_entries;
		is_composite = lo->ldo_is_composite;
		is_foreign = lo->ldo_is_foreign;
	}

	LASSERT(lmm_size != NULL);

	if (is_foreign) {
		struct lov_foreign_md *lfm;

		lfm = (struct lov_foreign_md *)lmm;
		memcpy(lfm, lo->ldo_foreign_lov, lo->ldo_foreign_lov_size);
		/* need to store little-endian */
		if (cpu_to_le32(LOV_MAGIC_FOREIGN) != LOV_MAGIC_FOREIGN) {
			__swab32s(&lfm->lfm_magic);
			__swab32s(&lfm->lfm_length);
			__swab32s(&lfm->lfm_type);
			__swab32s(&lfm->lfm_flags);
		}
		*lmm_size = lo->ldo_foreign_lov_size;
		RETURN(0);
	}

	LASSERT(comp_cnt != 0 && comp_entries != NULL);

	if (!is_composite) {
		rc = lod_gen_component_ea(env, lo, 0, lmm, lmm_size, is_dir);
		RETURN(rc);
	}

	lcm = (struct lov_comp_md_v1 *)lmm;
	memset(lcm, 0, sizeof(*lcm));

	lcm->lcm_magic = cpu_to_le32(LOV_MAGIC_COMP_V1);
	lcm->lcm_entry_count = cpu_to_le16(comp_cnt);
	lcm->lcm_mirror_count = cpu_to_le16(mirror_cnt - 1);
	lcm->lcm_flags = cpu_to_le16(lo->ldo_flr_state);

	offset = sizeof(*lcm) + sizeof(*lcme) * comp_cnt;
	LASSERT(offset % sizeof(__u64) == 0);

	for (i = 0; i < comp_cnt; i++) {
		struct lod_layout_component *lod_comp;
		struct lov_mds_md *sub_md;
		int size;

		lod_comp = &comp_entries[i];
		lcme = &lcm->lcm_entries[i];

		LASSERT(ergo(!is_dir, lod_comp->llc_id != LCME_ID_INVAL));
		lcme->lcme_id = cpu_to_le32(lod_comp->llc_id);

		/* component could be un-inistantiated */
		lcme->lcme_flags = cpu_to_le32(lod_comp->llc_flags);
		if (lod_comp->llc_flags & LCME_FL_NOSYNC)
			lcme->lcme_timestamp =
				cpu_to_le64(lod_comp->llc_timestamp);
		if (lod_comp->llc_flags & LCME_FL_EXTENSION && !is_dir)
			lcm->lcm_magic = cpu_to_le32(LOV_MAGIC_SEL);

		lcme->lcme_extent.e_start =
			cpu_to_le64(lod_comp->llc_extent.e_start);
		lcme->lcme_extent.e_end =
			cpu_to_le64(lod_comp->llc_extent.e_end);
		lcme->lcme_offset = cpu_to_le32(offset);

		sub_md = (struct lov_mds_md *)((char *)lcm + offset);
		rc = lod_gen_component_ea(env, lo, i, sub_md, &size, is_dir);
		if (rc)
			GOTO(out, rc);
		lcme->lcme_size = cpu_to_le32(size);
		offset += size;
		LASSERTF((offset <= *lmm_size) && (offset % sizeof(__u64) == 0),
			 "offset:%d lmm_size:%d\n", offset, *lmm_size);
	}
	lcm->lcm_size = cpu_to_le32(offset);
	lcm->lcm_layout_gen = cpu_to_le32(is_dir ? 0 : lo->ldo_layout_gen);

	lustre_print_user_md(D_LAYOUT, (struct lov_user_md *)lmm,
			     "generate lum");
out:
	if (rc == 0)
		*lmm_size = offset;
	RETURN(rc);
}

/**
 * Get LOV EA.
 *
 * Fill lti_ea_store buffer in the environment with a value for the given
 * EA. The buffer is reallocated if the value doesn't fit.
 *
 * \param[in,out] env		execution environment for this thread
 *				.lti_ea_store buffer is filled with EA's value
 * \param[in] lo		LOD object
 * \param[in] name		name of the EA
 *
 * \retval			> 0 if EA is fetched successfully
 * \retval			0 if EA is empty
 * \retval			negative error number on failure
 */
int lod_get_ea(const struct lu_env *env, struct lod_object *lo,
	       const char *name)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct dt_object	*next = dt_object_child(&lo->ldo_obj);
	int			rc;
	ENTRY;

	LASSERT(info);

	if (unlikely(info->lti_ea_store == NULL)) {
		/* just to enter in allocation block below */
		rc = -ERANGE;
	} else {
repeat:
		info->lti_buf.lb_buf = info->lti_ea_store;
		info->lti_buf.lb_len = info->lti_ea_store_size;
		rc = dt_xattr_get(env, next, &info->lti_buf, name);
	}

	/* if object is not striped or inaccessible */
	if (rc == -ENODATA || rc == -ENOENT)
		RETURN(0);

	if (rc == -ERANGE) {
		/* EA doesn't fit, reallocate new buffer */
		rc = dt_xattr_get(env, next, &LU_BUF_NULL, name);
		if (rc == -ENODATA || rc == -ENOENT)
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

/**
 * Verify the target index is present in the current configuration.
 *
 * \param[in] md		LOD device where the target table is stored
 * \param[in] idx		target's index
 *
 * \retval			0 if the index is present
 * \retval			-EINVAL if not
 */
int validate_lod_and_idx(struct lod_device *md, __u32 idx)
{
	if (unlikely(idx >= md->lod_ost_descs.ltd_tgts_size ||
		     !test_bit(idx, md->lod_ost_bitmap))) {
		CERROR("%s: bad idx: %d of %d\n", lod2obd(md)->obd_name, idx,
		       md->lod_ost_descs.ltd_tgts_size);
		return -EINVAL;
	}

	if (unlikely(OST_TGT(md, idx) == NULL)) {
		CERROR("%s: bad lod_tgt_desc for idx: %d\n",
		       lod2obd(md)->obd_name, idx);
		return -EINVAL;
	}

	if (unlikely(OST_TGT(md, idx)->ltd_tgt == NULL)) {
		CERROR("%s: invalid lod device, for idx: %d\n",
		       lod2obd(md)->obd_name , idx);
		return -EINVAL;
	}

	return 0;
}

/**
 * Instantiate objects for stripes.
 *
 * Allocate and initialize LU-objects representing the stripes. The number
 * of the stripes (ldo_stripe_count) must be initialized already. The caller
 * must ensure nobody else is calling the function on the object at the same
 * time. FLDB service must be running to be able to map a FID to the targets
 * and find appropriate device representing that target.
 *
 * \param[in] env		execution environment for this thread
 * \param[in,out] lo		LOD object
 * \param[in] objs		an array of IDs to creates the objects from
 * \param[in] comp_idx		index of ldo_comp_entries
 *
 * \retval			0 if the objects are instantiated successfully
 * \retval			negative error number on failure
 */
int lod_initialize_objects(const struct lu_env *env, struct lod_object *lo,
			   struct lov_ost_data_v1 *objs, int comp_idx)
{
	struct lod_layout_component *lod_comp;
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_device *md;
	struct lu_object *o, *n;
	struct lu_device *nd;
	struct dt_object **stripe = NULL;
	__u32 *ost_indices = NULL;
	int stripe_len;
	int i, rc = 0;
	__u32 idx;
	ENTRY;

	LASSERT(lo != NULL);
	md = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);

	LASSERT(lo->ldo_comp_cnt != 0 && lo->ldo_comp_entries != NULL);
	lod_comp = &lo->ldo_comp_entries[comp_idx];

	LASSERT(lod_comp->llc_stripe == NULL);
	LASSERT(lod_comp->llc_stripe_count > 0);
	LASSERT(lod_comp->llc_stripe_size > 0);

	stripe_len = lod_comp->llc_stripe_count;
	OBD_ALLOC_PTR_ARRAY(stripe, stripe_len);
	if (stripe == NULL)
		RETURN(-ENOMEM);
	OBD_ALLOC_PTR_ARRAY(ost_indices, stripe_len);
	if (!ost_indices)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < lod_comp->llc_stripe_count; i++) {
		if (unlikely(lovea_slot_is_dummy(&objs[i])))
			continue;

		ostid_le_to_cpu(&objs[i].l_ost_oi, &info->lti_ostid);
		idx = le32_to_cpu(objs[i].l_ost_idx);
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

		nd = &OST_TGT(md, idx)->ltd_tgt->dd_lu_dev;
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
		ost_indices[i] = idx;
	}

out:
	if (rc != 0) {
		for (i = 0; i < stripe_len; i++)
			if (stripe[i] != NULL)
				dt_object_put(env, stripe[i]);

		OBD_FREE_PTR_ARRAY(stripe, stripe_len);
		lod_comp->llc_stripe_count = 0;
		if (ost_indices)
			OBD_FREE_PTR_ARRAY(ost_indices, stripe_len);
	} else {
		lod_comp->llc_stripe = stripe;
		lod_comp->llc_ost_indices = ost_indices;
		lod_comp->llc_stripes_allocated = stripe_len;
	}

	RETURN(rc);
}

/**
 * Instantiate objects for striping.
 *
 * Parse striping information in \a buf and instantiate the objects
 * representing the stripes.
 *
 * \param[in] env		execution environment for this thread
 * \param[in] lo		LOD object
 * \param[in] buf		buffer storing LOV EA to parse
 *
 * \retval			0 if parsing and objects creation succeed
 * \retval			negative error number on failure
 */
int lod_parse_striping(const struct lu_env *env, struct lod_object *lo,
		       const struct lu_buf *buf)
{
	struct lov_mds_md_v1 *lmm;
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_foreign_md *foreign = NULL;
	struct lov_ost_data_v1 *objs;
	__u32 magic, pattern;
	__u16 mirror_cnt = 0;
	__u16 comp_cnt;
	int i, rc;
	ENTRY;

	LASSERT(buf);
	LASSERT(buf->lb_buf);
	LASSERT(buf->lb_len);
	LASSERT(mutex_is_locked(&lo->ldo_layout_mutex));

	lmm = (struct lov_mds_md_v1 *)buf->lb_buf;
	magic = le32_to_cpu(lmm->lmm_magic);

	if (magic != LOV_MAGIC_V1 && magic != LOV_MAGIC_V3 &&
	    magic != LOV_MAGIC_COMP_V1 && magic != LOV_MAGIC_FOREIGN &&
	    magic != LOV_MAGIC_SEL)
		GOTO(out, rc = -EINVAL);

	lod_striping_free_nolock(env, lo);

	if (magic == LOV_MAGIC_COMP_V1 || magic == LOV_MAGIC_SEL) {
		comp_v1 = (struct lov_comp_md_v1 *)lmm;
		comp_cnt = le16_to_cpu(comp_v1->lcm_entry_count);
		if (comp_cnt == 0)
			GOTO(out, rc = -EINVAL);
		lo->ldo_layout_gen = le32_to_cpu(comp_v1->lcm_layout_gen);
		lo->ldo_is_composite = 1;
		mirror_cnt = le16_to_cpu(comp_v1->lcm_mirror_count) + 1;
		if (mirror_cnt > 1)
			lo->ldo_flr_state = le16_to_cpu(comp_v1->lcm_flags) &
							LCM_FL_FLR_MASK;
		else
			lo->ldo_flr_state = LCM_FL_NONE;
	} else if (magic == LOV_MAGIC_FOREIGN) {
		size_t length;

		foreign = (struct lov_foreign_md *)buf->lb_buf;
		length = offsetof(typeof(*foreign), lfm_value);
		if (buf->lb_len < length ||
		    buf->lb_len < (length + le32_to_cpu(foreign->lfm_length))) {
			CDEBUG(D_LAYOUT,
			       "buf len %zu too small for lov_foreign_md\n",
			       buf->lb_len);
			GOTO(out, rc = -EINVAL);
		}

		/* just cache foreign LOV EA raw */
		rc = lod_alloc_foreign_lov(lo, length);
		if (rc)
			GOTO(out, rc);
		memcpy(lo->ldo_foreign_lov, buf->lb_buf, length);
		GOTO(out, rc);
	} else {
		comp_cnt = 1;
		lo->ldo_layout_gen = le16_to_cpu(lmm->lmm_layout_gen);
		lo->ldo_is_composite = 0;
	}

	rc = lod_alloc_comp_entries(lo, mirror_cnt, comp_cnt);
	if (rc)
		GOTO(out, rc);

	for (i = 0; i < comp_cnt; i++) {
		struct lod_layout_component *lod_comp;
		struct lu_extent *ext;
		__u32 offs;

		lod_comp = &lo->ldo_comp_entries[i];
		if (lo->ldo_is_composite) {
			offs = le32_to_cpu(comp_v1->lcm_entries[i].lcme_offset);
			lmm = (struct lov_mds_md_v1 *)((char *)comp_v1 + offs);

			ext = &comp_v1->lcm_entries[i].lcme_extent;
			lod_comp->llc_extent.e_start =
				le64_to_cpu(ext->e_start);
			if (lod_comp->llc_extent.e_start &
			    (LOV_MIN_STRIPE_SIZE - 1)) {
				CDEBUG(D_LAYOUT,
				       "extent start %llu is not a multiple of min size %u\n",
				       lod_comp->llc_extent.e_start,
				       LOV_MIN_STRIPE_SIZE);
				GOTO(out, rc = -EINVAL);
			}

			lod_comp->llc_extent.e_end = le64_to_cpu(ext->e_end);
			if (lod_comp->llc_extent.e_end != LUSTRE_EOF &&
			    lod_comp->llc_extent.e_end &
			    (LOV_MIN_STRIPE_SIZE - 1)) {
				CDEBUG(D_LAYOUT,
				       "extent end %llu is not a multiple of min size %u\n",
				       lod_comp->llc_extent.e_end,
				       LOV_MIN_STRIPE_SIZE);
				GOTO(out, rc = -EINVAL);
			}

			lod_comp->llc_flags =
				le32_to_cpu(comp_v1->lcm_entries[i].lcme_flags);
			if (lod_comp->llc_flags & LCME_FL_NOSYNC)
				lod_comp->llc_timestamp = le64_to_cpu(
					comp_v1->lcm_entries[i].lcme_timestamp);
			lod_comp->llc_id =
				le32_to_cpu(comp_v1->lcm_entries[i].lcme_id);
			if (lod_comp->llc_id == LCME_ID_INVAL)
				GOTO(out, rc = -EINVAL);

			if ((lod_comp->llc_flags & LCME_FL_EXTENSION) &&
			    comp_v1->lcm_magic != cpu_to_le32(LOV_MAGIC_SEL)) {
				struct lod_device *d =
					lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);

				CWARN("%s: EXTENSION flags=%x set on component[%u]=%x of non-SEL file "DFID" with magic=%#08x\n",
				      lod2obd(d)->obd_name,
				      lod_comp->llc_flags, lod_comp->llc_id, i,
				      PFID(lod_object_fid(lo)),
				      le32_to_cpu(comp_v1->lcm_magic));
			}
		} else {
			lod_comp_set_init(lod_comp);
		}

		pattern = le32_to_cpu(lmm->lmm_pattern);
		if (!lov_pattern_supported(lov_pattern(pattern)))
			GOTO(out, rc = -EINVAL);

		lod_comp->llc_pattern = pattern;
		lod_comp->llc_stripe_size = le32_to_cpu(lmm->lmm_stripe_size);
		lod_comp->llc_stripe_count = le16_to_cpu(lmm->lmm_stripe_count);
		lod_comp->llc_layout_gen = le16_to_cpu(lmm->lmm_layout_gen);

		if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V3)) {
			struct lov_mds_md_v3 *v3 = (struct lov_mds_md_v3 *)lmm;

			lod_set_pool(&lod_comp->llc_pool, v3->lmm_pool_name);
			objs = &v3->lmm_objects[0];
		} else {
			lod_set_pool(&lod_comp->llc_pool, NULL);
			objs = &lmm->lmm_objects[0];
		}

		/**
		 * If uninstantiated template component has valid l_ost_idx,
		 * then user has specified ost list for this component.
		 */
		if (!lod_comp_inited(lod_comp)) {
			__u16 stripe_count;

			if (objs[0].l_ost_idx != (__u32)-1UL) {
				int j;

				stripe_count = lod_comp_entry_stripe_count(
							lo, i, false);
				if (stripe_count == 0 &&
				    !(lod_comp->llc_pattern & LOV_PATTERN_F_RELEASED) &&
				    !(lod_comp->llc_pattern & LOV_PATTERN_MDT))
					GOTO(out, rc = -E2BIG);
				/**
				 * load the user specified ost list, when this
				 * component is instantiated later, it will be
				 * used in lod_alloc_ost_list().
				 */
				lod_comp->llc_ostlist.op_count = stripe_count;
				lod_comp->llc_ostlist.op_size =
					stripe_count * sizeof(__u32);
				OBD_ALLOC(lod_comp->llc_ostlist.op_array,
					  lod_comp->llc_ostlist.op_size);
				if (!lod_comp->llc_ostlist.op_array)
					GOTO(out, rc = -ENOMEM);

				for (j = 0; j < stripe_count; j++)
					lod_comp->llc_ostlist.op_array[j] =
						le32_to_cpu(objs[j].l_ost_idx);

				/**
				 * this component OST objects starts from the
				 * first ost_idx, lod_alloc_ost_list() will
				 * check this.
				 */
				lod_comp->llc_stripe_offset = objs[0].l_ost_idx;
			} else {
				/**
				 * for uninstantiated component,
				 * lmm_layout_gen stores default stripe offset.
				 */
				lod_comp->llc_stripe_offset =
							lmm->lmm_layout_gen;
			}
		}

		/* skip un-instantiated component object initialization */
		if (!lod_comp_inited(lod_comp))
			continue;

		if (!(lod_comp->llc_pattern & LOV_PATTERN_F_RELEASED) &&
		    !(lod_comp->llc_pattern & LOV_PATTERN_MDT)) {
			rc = lod_initialize_objects(env, lo, objs, i);
			if (rc)
				GOTO(out, rc);
		}
	}

	rc = lod_fill_mirrors(lo);
	if (rc)
		GOTO(out, rc);

out:
	if (rc)
		lod_striping_free_nolock(env, lo);
	RETURN(rc);
}

/**
 * Check whether the striping (LOVEA for regular file, LMVEA for directory)
 * is already cached.
 *
 * \param[in] lo	LOD object
 *
 * \retval		True if the striping is cached, otherwise
 *			return false.
 */
static bool lod_striping_loaded(struct lod_object *lo)
{
	if (S_ISREG(lod2lu_obj(lo)->lo_header->loh_attr) &&
	    lo->ldo_comp_cached)
		return true;

	if (S_ISDIR(lod2lu_obj(lo)->lo_header->loh_attr)) {
		if (lo->ldo_dir_stripe_loaded)
			return true;

		/* Never load LMV stripe for slaves of striped dir */
		if (lo->ldo_dir_slave_stripe)
			return true;
	}

	return false;
}

/**
 * A generic function to initialize the stripe objects.
 *
 * A protected version of lod_striping_load_locked() - load the striping
 * information from storage, parse that and instantiate LU objects to
 * represent the stripes.  The LOD object \a lo supplies a pointer to the
 * next sub-object in the LU stack so we can lock it. Also use \a lo to
 * return an array of references to the newly instantiated objects.
 *
 * \param[in] env		execution environment for this thread
 * \param[in,out] lo		LOD object, where striping is stored and
 *				which gets an array of references
 *
 * \retval			0 if parsing and object creation succeed
 * \retval			negative error number on failure
 **/
int lod_striping_load(const struct lu_env *env, struct lod_object *lo)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct dt_object *next = dt_object_child(&lo->ldo_obj);
	struct lu_buf *buf = &info->lti_buf;
	int rc = 0;

	ENTRY;

	if (!dt_object_exists(next))
		RETURN(0);

	if (lod_striping_loaded(lo))
		RETURN(0);

	mutex_lock(&lo->ldo_layout_mutex);
	if (lod_striping_loaded(lo))
		GOTO(unlock, rc = 0);

	if (S_ISREG(lod2lu_obj(lo)->lo_header->loh_attr)) {
		rc = lod_get_lov_ea(env, lo);
		if (rc <= 0)
			GOTO(unlock, rc);

		/*
		 * there is LOV EA (striping information) in this object
		 * let's parse it and create in-core objects for the stripes
		 */
		buf->lb_buf = info->lti_ea_store;
		buf->lb_len = info->lti_ea_store_size;
		rc = lod_parse_striping(env, lo, buf);
		if (rc == 0)
			lo->ldo_comp_cached = 1;
	} else if (S_ISDIR(lod2lu_obj(lo)->lo_header->loh_attr)) {
		rc = lod_get_lmv_ea(env, lo);
		if (rc > sizeof(struct lmv_foreign_md)) {
			struct lmv_foreign_md *lfm = info->lti_ea_store;

			if (le32_to_cpu(lfm->lfm_magic) == LMV_MAGIC_FOREIGN) {
				lo->ldo_foreign_lmv = info->lti_ea_store;
				lo->ldo_foreign_lmv_size =
					info->lti_ea_store_size;
				info->lti_ea_store = NULL;
				info->lti_ea_store_size = 0;

				lo->ldo_dir_stripe_loaded = 1;
				lo->ldo_dir_is_foreign = 1;
				GOTO(unlock, rc = 0);
			}
		}

		if (rc < (int)sizeof(struct lmv_mds_md_v1)) {
			/* Let's set stripe_loaded to avoid further
			 * stripe loading especially for non-stripe directory,
			 * which can hurt performance. (See LU-9840)
			 */
			if (rc == 0)
				lo->ldo_dir_stripe_loaded = 1;
			GOTO(unlock, rc = rc > 0 ? -EINVAL : rc);
		}
		buf->lb_buf = info->lti_ea_store;
		buf->lb_len = info->lti_ea_store_size;
		if (rc == sizeof(struct lmv_mds_md_v1)) {
			rc = lod_load_lmv_shards(env, lo, buf, true);
			if (buf->lb_buf != info->lti_ea_store) {
				OBD_FREE_LARGE(info->lti_ea_store,
					       info->lti_ea_store_size);
				info->lti_ea_store = buf->lb_buf;
				info->lti_ea_store_size = buf->lb_len;
			}

			if (rc < 0)
				GOTO(unlock, rc);
		}

		/*
		 * there is LMV EA (striping information) in this object
		 * let's parse it and create in-core objects for the stripes
		 */
		rc = lod_parse_dir_striping(env, lo, buf);
		if (rc == 0)
			lo->ldo_dir_stripe_loaded = 1;
	}
	EXIT;
unlock:
	mutex_unlock(&lo->ldo_layout_mutex);

	return rc;
}

int lod_striping_reload(const struct lu_env *env, struct lod_object *lo,
			 const struct lu_buf *buf)
{
	int rc;

	ENTRY;

	mutex_lock(&lo->ldo_layout_mutex);
	rc = lod_parse_striping(env, lo, buf);
	mutex_unlock(&lo->ldo_layout_mutex);

	RETURN(rc);
}

/**
 * Verify lov_user_md_v1/v3 striping.
 *
 * Check the validity of all fields including the magic, stripe size,
 * stripe count, stripe offset and that the pool is present.  Also check
 * that each target index points to an existing target. The additional
 * \a is_from_disk turns additional checks. In some cases zero fields
 * are allowed (like pattern=0).
 *
 * \param[in] d			LOD device
 * \param[in] buf		buffer with LOV EA to verify
 * \param[in] is_from_disk	0 - from user, allow some fields to be 0
 *				1 - from disk, do not allow
 *
 * \retval			0 if the striping is valid
 * \retval			-EINVAL if striping is invalid
 */
static int lod_verify_v1v3(struct lod_device *d, const struct lu_buf *buf,
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

	if (buf->lb_len < sizeof(*lum)) {
		CDEBUG(D_LAYOUT, "buf len %zu too small for lov_user_md\n",
		       buf->lb_len);
		GOTO(out, rc = -EINVAL);
	}

	magic = le32_to_cpu(lum->lmm_magic) & ~LOV_MAGIC_DEFINED;
	if (magic != LOV_USER_MAGIC_V1 &&
	    magic != LOV_USER_MAGIC_V3 &&
	    magic != LOV_USER_MAGIC_SPECIFIC) {
		CDEBUG(D_LAYOUT, "bad userland LOV MAGIC: %#x\n",
		       le32_to_cpu(lum->lmm_magic));
		GOTO(out, rc = -EINVAL);
	}

	/* the user uses "0" for default stripe pattern normally. */
	if (!is_from_disk && lum->lmm_pattern == LOV_PATTERN_NONE)
		lum->lmm_pattern = cpu_to_le32(LOV_PATTERN_RAID0);

	if (!lov_pattern_supported(le32_to_cpu(lum->lmm_pattern))) {
		CDEBUG(D_LAYOUT, "bad userland stripe pattern: %#x\n",
		       le32_to_cpu(lum->lmm_pattern));
		GOTO(out, rc = -EINVAL);
	}

	/* a released lum comes from creating orphan on hsm release,
	 * doesn't make sense to verify it. */
	if (le32_to_cpu(lum->lmm_pattern) & LOV_PATTERN_F_RELEASED)
		GOTO(out, rc = 0);

	/* 64kB is the largest common page size we see (ia64), and matches the
	 * check in lfs */
	stripe_size = le32_to_cpu(lum->lmm_stripe_size);
	if (stripe_size & (LOV_MIN_STRIPE_SIZE - 1)) {
		CDEBUG(D_LAYOUT, "stripe size %u not a multiple of %u\n",
		       stripe_size, LOV_MIN_STRIPE_SIZE);
		GOTO(out, rc = -EINVAL);
	}

	stripe_offset = le16_to_cpu(lum->lmm_stripe_offset);
	if (!is_from_disk && stripe_offset != LOV_OFFSET_DEFAULT &&
	    lov_pattern(le32_to_cpu(lum->lmm_pattern)) != LOV_PATTERN_MDT) {
		/* if offset is not within valid range [0, osts_size) */
		if (stripe_offset >= d->lod_ost_descs.ltd_tgts_size) {
			CDEBUG(D_LAYOUT, "stripe offset %u >= bitmap size %u\n",
			       stripe_offset, d->lod_ost_descs.ltd_tgts_size);
			GOTO(out, rc = -EINVAL);
		}

		/* if lmm_stripe_offset is *not* in bitmap */
		if (!test_bit(stripe_offset, d->lod_ost_bitmap)) {
			CDEBUG(D_LAYOUT, "stripe offset %u not in bitmap\n",
			       stripe_offset);
			GOTO(out, rc = -EINVAL);
		}
	}

	if (magic == LOV_USER_MAGIC_V1)
		lum_size = offsetof(struct lov_user_md_v1,
				    lmm_objects[0]);
	else if (magic == LOV_USER_MAGIC_V3 || magic == LOV_USER_MAGIC_SPECIFIC)
		lum_size = offsetof(struct lov_user_md_v3,
				    lmm_objects[0]);
	else
		GOTO(out, rc = -EINVAL);

	stripe_count = le16_to_cpu(lum->lmm_stripe_count);
	if (buf->lb_len < lum_size) {
		CDEBUG(D_LAYOUT, "invalid buf len %zu/%zu for lov_user_md with "
		       "magic %#x and stripe_count %u\n",
		       buf->lb_len, lum_size, magic, stripe_count);
		GOTO(out, rc = -EINVAL);
	}

	if (!(magic == LOV_USER_MAGIC_V3 || magic == LOV_USER_MAGIC_SPECIFIC))
		goto out;

	lum3 = buf->lb_buf;
	/* In the function below, .hs_keycmp resolves to
	 * pool_hashkey_keycmp() */
	/* coverity[overrun-buffer-val] */
	pool = lod_find_pool(d, lum3->lmm_pool_name);
	if (pool == NULL)
		goto out;

	if (!is_from_disk && stripe_offset != LOV_OFFSET_DEFAULT) {
		rc = lod_check_index_in_pool(stripe_offset, pool);
		if (rc < 0)
			GOTO(out, rc = -EINVAL);
	}

	if (is_from_disk && stripe_count > pool_tgt_count(pool)) {
		CDEBUG(D_LAYOUT, "stripe count %u > # OSTs %u in the pool\n",
		       stripe_count, pool_tgt_count(pool));
		GOTO(out, rc = -EINVAL);
	}

out:
	if (pool != NULL)
		lod_pool_putref(pool);

	RETURN(rc);
}

static inline
struct lov_comp_md_entry_v1 *comp_entry_v1(struct lov_comp_md_v1 *comp, int i)
{
	LASSERTF((le32_to_cpu(comp->lcm_magic) & ~LOV_MAGIC_DEFINED) ==
		 LOV_USER_MAGIC_COMP_V1, "Wrong magic %x\n",
		 le32_to_cpu(comp->lcm_magic));
	LASSERTF(i >= 0 && i < le16_to_cpu(comp->lcm_entry_count),
		 "bad index %d, max = %d\n",
		 i, le16_to_cpu(comp->lcm_entry_count));

	return &comp->lcm_entries[i];
}

#define for_each_comp_entry_v1(comp, entry) \
	for (entry = comp_entry_v1(comp, 0); \
	     entry <= comp_entry_v1(comp, \
				   le16_to_cpu(comp->lcm_entry_count) - 1); \
	     entry++)

int lod_erase_dom_stripe(struct lov_comp_md_v1 *comp_v1,
			 struct lov_comp_md_entry_v1 *dom_ent)
{
	struct lov_comp_md_entry_v1 *ent;
	__u16 entries;
	__u32 dom_off, dom_size, comp_size, off;
	void *src, *dst;
	unsigned int size, shift;

	entries = le16_to_cpu(comp_v1->lcm_entry_count) - 1;
	LASSERT(entries > 0);
	comp_v1->lcm_entry_count = cpu_to_le16(entries);

	comp_size = le32_to_cpu(comp_v1->lcm_size);
	dom_off = le32_to_cpu(dom_ent->lcme_offset);
	dom_size = le32_to_cpu(dom_ent->lcme_size);

	/* all entries offsets are shifted by entry size at least */
	shift = sizeof(*dom_ent);
	for_each_comp_entry_v1(comp_v1, ent) {
		off = le32_to_cpu(ent->lcme_offset);
		if (off == dom_off) {
			/* Entry deletion creates two holes in layout data:
			 * - hole in entries array
			 * - hole in layout data at dom_off with dom_size
			 *
			 * First memmove is one entry shift from next entry
			 * start with size up to dom_off in blob
			 */
			dst = (void *)ent;
			src = (void *)(ent + 1);
			size = (unsigned long)((void *)comp_v1 + dom_off - src);
			memmove(dst, src, size);
			/* take 'off' from just moved entry */
			off = le32_to_cpu(ent->lcme_offset);
			/* second memmove is blob tail after 'off' up to
			 * component end
			 */
			dst = (void *)comp_v1 + dom_off - sizeof(*ent);
			src = (void *)comp_v1 + off;
			size = (unsigned long)(comp_size - off);
			memmove(dst, src, size);
			/* all entries offsets after DoM entry are shifted by
			 * dom_size additionally
			 */
			shift += dom_size;
		}
		ent->lcme_offset = cpu_to_le32(off - shift);
	}
	comp_v1->lcm_size = cpu_to_le32(comp_size - shift);

	/* notify a caller to re-check entry */
	return -ERESTART;
}

void lod_dom_stripesize_recalc(struct lod_device *d)
{
	__u64 threshold_mb = d->lod_dom_threshold_free_mb;
	__u32 max_size = d->lod_dom_stripesize_max_kb;
	__u32 def_size = d->lod_dom_stripesize_cur_kb;

	/* use maximum allowed value if free space is above threshold */
	if (d->lod_lsfs_free_mb >= threshold_mb) {
		def_size = max_size;
	} else if (!d->lod_lsfs_free_mb || max_size <= LOD_DOM_MIN_SIZE_KB) {
		def_size = 0;
	} else {
		/* recalc threshold like it would be with def_size as max */
		threshold_mb = mult_frac(threshold_mb, def_size, max_size);
		if (d->lod_lsfs_free_mb < threshold_mb)
			def_size = rounddown(def_size / 2, LOD_DOM_MIN_SIZE_KB);
		else if (d->lod_lsfs_free_mb > threshold_mb * 2)
			def_size = max_t(unsigned int, def_size * 2,
					 LOD_DOM_MIN_SIZE_KB);
	}

	if (d->lod_dom_stripesize_cur_kb != def_size) {
		CDEBUG(D_LAYOUT, "Change default DOM stripe size %d->%d\n",
		       d->lod_dom_stripesize_cur_kb, def_size);
		d->lod_dom_stripesize_cur_kb = def_size;
	}
}

static __u32 lod_dom_stripesize_limit(const struct lu_env *env,
				      struct lod_device *d)
{
	int rc;

	/* set bfree as fraction of total space */
	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_SPOOF)) {
		spin_lock(&d->lod_lsfs_lock);
		d->lod_lsfs_free_mb = mult_frac(d->lod_lsfs_total_mb,
					min_t(int, cfs_fail_val, 100), 100);
		GOTO(recalc, rc = 0);
	}

	if (d->lod_lsfs_age < ktime_get_seconds() - LOD_DOM_SFS_MAX_AGE) {
		struct obd_statfs sfs;

		spin_lock(&d->lod_lsfs_lock);
		if (d->lod_lsfs_age > ktime_get_seconds() - LOD_DOM_SFS_MAX_AGE)
			GOTO(unlock, rc = 0);

		d->lod_lsfs_age = ktime_get_seconds();
		spin_unlock(&d->lod_lsfs_lock);
		rc = dt_statfs(env, d->lod_child, &sfs);
		if (rc) {
			CDEBUG(D_LAYOUT,
			       "%s: failed to get OSD statfs: rc = %d\n",
			       lod2obd(d)->obd_name, rc);
			GOTO(out, rc);
		}
		/* udpate local OSD cached statfs data */
		spin_lock(&d->lod_lsfs_lock);
		d->lod_lsfs_total_mb = (sfs.os_blocks * sfs.os_bsize) >> 20;
		d->lod_lsfs_free_mb = (sfs.os_bfree * sfs.os_bsize) >> 20;
recalc:
		lod_dom_stripesize_recalc(d);
unlock:
		spin_unlock(&d->lod_lsfs_lock);
	}
out:
	return d->lod_dom_stripesize_cur_kb << 10;
}

int lod_dom_stripesize_choose(const struct lu_env *env, struct lod_device *d,
			      struct lov_comp_md_v1 *comp_v1,
			      struct lov_comp_md_entry_v1 *dom_ent,
			      __u32 stripe_size)
{
	struct lov_comp_md_entry_v1 *ent;
	struct lu_extent *dom_ext, *ext;
	struct lov_user_md_v1 *lum;
	__u32 max_stripe_size;
	__u16 mid, dom_mid;
	int rc = 0;
	bool dom_next_entry = false;

	dom_ext = &dom_ent->lcme_extent;
	dom_mid = mirror_id_of(le32_to_cpu(dom_ent->lcme_id));
	max_stripe_size = lod_dom_stripesize_limit(env, d);

	/* Check stripe size againts current per-MDT limit */
	if (stripe_size <= max_stripe_size)
		return 0;

	lum = (void *)comp_v1 + le32_to_cpu(dom_ent->lcme_offset);
	CDEBUG(D_LAYOUT, "overwrite DoM component size %u with MDT limit %u\n",
	       stripe_size, max_stripe_size);
	lum->lmm_stripe_size = cpu_to_le32(max_stripe_size);

	/* In common case the DoM stripe is first entry in a mirror and
	 * can be deleted only if it is not single entry in layout or
	 * mirror, otherwise error should be returned.
	 */
	for_each_comp_entry_v1(comp_v1, ent) {
		if (ent == dom_ent)
			continue;

		mid = mirror_id_of(le32_to_cpu(ent->lcme_id));
		if (mid != dom_mid)
			continue;

		ext = &ent->lcme_extent;
		if (ext->e_start != dom_ext->e_end)
			continue;

		/* Found next component after the DoM one with the same
		 * mirror_id and adjust its start with DoM component end.
		 *
		 * NOTE: we are considering here that there can be only one
		 * DoM component in a file, all replicas are located on OSTs
		 * always and don't need adjustment since use own layouts.
		 */
		ext->e_start = cpu_to_le64(max_stripe_size);
		dom_next_entry = true;
		break;
	}

	if (max_stripe_size == 0) {
		/* DoM component size is zero due to server setting, remove
		 * it from the layout but only if next component exists in
		 * the same mirror. That must be checked prior calling the
		 * lod_erase_dom_stripe().
		 */
		if (!dom_next_entry)
			return -EFBIG;

		rc = lod_erase_dom_stripe(comp_v1, dom_ent);
	} else {
		/* Update DoM extent end finally */
		dom_ext->e_end = cpu_to_le64(max_stripe_size);
	}

	return rc;
}

/**
 * Verify LOV striping.
 *
 * \param[in] d			LOD device
 * \param[in] buf		buffer with LOV EA to verify
 * \param[in] is_from_disk	0 - from user, allow some fields to be 0
 *				1 - from disk, do not allow
 * \param[in] start		extent start for composite layout
 *
 * \retval			0 if the striping is valid
 * \retval			-EINVAL if striping is invalid
 */
int lod_verify_striping(const struct lu_env *env, struct lod_device *d,
			struct lod_object *lo, const struct lu_buf *buf,
			bool is_from_disk)
{
	struct lov_user_md_v1   *lum;
	struct lov_comp_md_v1   *comp_v1;
	struct lov_comp_md_entry_v1     *ent;
	struct lu_extent        *ext;
	struct lu_buf   tmp;
	__u64   prev_end = 0;
	__u32   stripe_size = 0;
	__u16   prev_mid = -1, mirror_id = -1;
	__u32   mirror_count;
	__u32   magic;
	int     rc = 0;
	ENTRY;

	if (buf->lb_len < sizeof(lum->lmm_magic)) {
		CDEBUG(D_LAYOUT, "invalid buf len %zu\n", buf->lb_len);
		RETURN(-EINVAL);
	}

	lum = buf->lb_buf;

	magic = le32_to_cpu(lum->lmm_magic) & ~LOV_MAGIC_DEFINED;
	/* treat foreign LOV EA/object case first
	 * XXX is it expected to try setting again a foreign?
	 * XXX should we care about different current vs new layouts ?
	 */
	if (unlikely(magic == LOV_USER_MAGIC_FOREIGN)) {
		struct lov_foreign_md *lfm = buf->lb_buf;

		if (buf->lb_len < offsetof(typeof(*lfm), lfm_value)) {
			CDEBUG(D_LAYOUT,
			       "buf len %zu < min lov_foreign_md size (%zu)\n",
			       buf->lb_len, offsetof(typeof(*lfm),
			       lfm_value));
			RETURN(-EINVAL);
		}

		if (foreign_size_le(lfm) > buf->lb_len) {
			CDEBUG(D_LAYOUT,
			       "buf len %zu < this lov_foreign_md size (%zu)\n",
			       buf->lb_len, foreign_size_le(lfm));
			RETURN(-EINVAL);
		}
		/* Don't do anything with foreign layouts */
		RETURN(0);
	}

	/* normal LOV/layout cases */

	if (buf->lb_len < sizeof(*lum)) {
		CDEBUG(D_LAYOUT, "buf len %zu too small for lov_user_md\n",
		       buf->lb_len);
		RETURN(-EINVAL);
	}

	if (magic != LOV_USER_MAGIC_V1 &&
	    magic != LOV_USER_MAGIC_V3 &&
	    magic != LOV_USER_MAGIC_SPECIFIC &&
	    magic != LOV_USER_MAGIC_COMP_V1) {
		CDEBUG(D_LAYOUT, "bad userland LOV MAGIC: %#x\n",
		       le32_to_cpu(lum->lmm_magic));
		RETURN(-EINVAL);
	}

	if (magic != LOV_USER_MAGIC_COMP_V1)
		RETURN(lod_verify_v1v3(d, buf, is_from_disk));

	/* magic == LOV_USER_MAGIC_COMP_V1 */
	comp_v1 = buf->lb_buf;
	if (buf->lb_len < le32_to_cpu(comp_v1->lcm_size)) {
		CDEBUG(D_LAYOUT, "buf len %zu is less than %u\n",
		       buf->lb_len, le32_to_cpu(comp_v1->lcm_size));
		RETURN(-EINVAL);
	}

recheck:
	mirror_count = 0;
	if (le16_to_cpu(comp_v1->lcm_entry_count) == 0) {
		CDEBUG(D_LAYOUT, "entry count is zero\n");
		RETURN(-EINVAL);
	}

	if (S_ISREG(lod2lu_obj(lo)->lo_header->loh_attr) &&
	    lo->ldo_comp_cnt > 0) {
		/* could be called from lustre.lov.add */
		__u32 cnt = lo->ldo_comp_cnt;

		ext = &lo->ldo_comp_entries[cnt - 1].llc_extent;
		prev_end = ext->e_end;

		++mirror_count;
	}

	for_each_comp_entry_v1(comp_v1, ent) {
		ext = &ent->lcme_extent;

		if (le64_to_cpu(ext->e_start) > le64_to_cpu(ext->e_end) ||
		    le64_to_cpu(ext->e_start) & (LOV_MIN_STRIPE_SIZE - 1) ||
		    (le64_to_cpu(ext->e_end) != LUSTRE_EOF &&
		    le64_to_cpu(ext->e_end) & (LOV_MIN_STRIPE_SIZE - 1))) {
			CDEBUG(D_LAYOUT, "invalid extent "DEXT"\n",
			       le64_to_cpu(ext->e_start),
			       le64_to_cpu(ext->e_end));
			RETURN(-EINVAL);
		}

		if (is_from_disk) {
			/* lcme_id contains valid value */
			if (le32_to_cpu(ent->lcme_id) == 0 ||
			    le32_to_cpu(ent->lcme_id) > LCME_ID_MAX) {
				CDEBUG(D_LAYOUT, "invalid id %u\n",
				       le32_to_cpu(ent->lcme_id));
				RETURN(-EINVAL);
			}

			if (le16_to_cpu(comp_v1->lcm_mirror_count) > 0) {
				mirror_id = mirror_id_of(
						le32_to_cpu(ent->lcme_id));

				/* first component must start with 0 */
				if (mirror_id != prev_mid &&
				    le64_to_cpu(ext->e_start) != 0) {
					CDEBUG(D_LAYOUT,
					       "invalid start:%llu, expect:0\n",
					       le64_to_cpu(ext->e_start));
					RETURN(-EINVAL);
				}

				prev_mid = mirror_id;
			}
		}

		if (le64_to_cpu(ext->e_start) == 0) {
			++mirror_count;
			prev_end = 0;
		}

		/* the next must be adjacent with the previous one */
		if (le64_to_cpu(ext->e_start) != prev_end) {
			CDEBUG(D_LAYOUT,
			       "invalid start actual:%llu, expect:%llu\n",
			       le64_to_cpu(ext->e_start), prev_end);
			RETURN(-EINVAL);
		}

		tmp.lb_buf = (char *)comp_v1 + le32_to_cpu(ent->lcme_offset);
		tmp.lb_len = le32_to_cpu(ent->lcme_size);

		/* Check DoM entry is always the first one */
		lum = tmp.lb_buf;
		if (lov_pattern(le32_to_cpu(lum->lmm_pattern)) ==
		    LOV_PATTERN_MDT) {
			/* DoM component must be the first in a mirror */
			if (le64_to_cpu(ext->e_start) > 0) {
				CDEBUG(D_LAYOUT, "invalid DoM component "
				       "with %llu extent start\n",
				       le64_to_cpu(ext->e_start));
				RETURN(-EINVAL);
			}
			stripe_size = le32_to_cpu(lum->lmm_stripe_size);
			/* There is just one stripe on MDT and it must
			 * cover whole component size. */
			if (stripe_size != le64_to_cpu(ext->e_end)) {
				CDEBUG(D_LAYOUT, "invalid DoM layout "
				       "stripe size %u != %llu "
				       "(component size)\n",
				       stripe_size, prev_end);
				RETURN(-EINVAL);
			}
			/* Check and adjust stripe size by per-MDT limit */
			rc = lod_dom_stripesize_choose(env, d, comp_v1, ent,
						       stripe_size);
			/* DoM entry was removed, re-check layout from start */
			if (rc == -ERESTART)
				goto recheck;
			else if (rc)
				RETURN(rc);

			/* Any stripe count is forbidden on DoM component */
			if (lum->lmm_stripe_count) {
				CDEBUG(D_LAYOUT,
				       "invalid DoM layout stripe count %u, must be 0\n",
				       le16_to_cpu(lum->lmm_stripe_count));
				RETURN(-EINVAL);
			}

			/* Any pool is forbidden on DoM component */
			if (lum->lmm_magic == LOV_USER_MAGIC_V3) {
				struct lov_user_md_v3 *v3 = (void *)lum;

				if (v3->lmm_pool_name[0] != '\0') {
					CDEBUG(D_LAYOUT,
					       "DoM component cannot have pool assigned\n");
					RETURN(-EINVAL);
				}
			}
		}

		prev_end = le64_to_cpu(ext->e_end);

		rc = lod_verify_v1v3(d, &tmp, is_from_disk);
		if (rc)
			RETURN(rc);

		if (prev_end == LUSTRE_EOF || ext->e_start == prev_end)
			continue;

		/* extent end must be aligned with the stripe_size */
		stripe_size = le32_to_cpu(lum->lmm_stripe_size);
		if (stripe_size && prev_end % stripe_size) {
			CDEBUG(D_LAYOUT, "stripe size isn't aligned, "
			       "stripe_sz: %u, [%llu, %llu)\n",
			       stripe_size, ext->e_start, prev_end);
			RETURN(-EINVAL);
		}
	}

	/* make sure that the mirror_count is telling the truth */
	if (mirror_count != le16_to_cpu(comp_v1->lcm_mirror_count) + 1)
		RETURN(-EINVAL);

	RETURN(0);
}

/**
 * set the default stripe size, if unset.
 *
 * \param[in,out] val	number of bytes per OST stripe
 *
 * The minimum stripe size is 64KB to ensure that a single stripe is an
 * even multiple of a client PAGE_SIZE (IA64, PPC, etc).  Otherwise, it
 * is difficult to split dirty pages across OSCs during writes.
 */
void lod_fix_desc_stripe_size(__u64 *val)
{
	if (*val < LOV_MIN_STRIPE_SIZE) {
		if (*val != 0)
			LCONSOLE_INFO("Increasing default stripe size to "
				      "minimum value %u\n",
				      LOV_DESC_STRIPE_SIZE_DEFAULT);
		*val = LOV_DESC_STRIPE_SIZE_DEFAULT;
	} else if (*val & (LOV_MIN_STRIPE_SIZE - 1)) {
		*val &= ~(LOV_MIN_STRIPE_SIZE - 1);
		LCONSOLE_WARN("Changing default stripe size to %llu (a "
			      "multiple of %u)\n",
			      *val, LOV_MIN_STRIPE_SIZE);
	}
}

/**
 * set the filesystem default number of stripes, if unset.
 *
 * \param[in,out] val	number of stripes
 *
 * A value of "0" means "use the system-wide default stripe count", which
 * has either been inherited by now, or falls back to 1 stripe per file.
 * A value of "-1" (0xffffffff) means "stripe over all available OSTs",
 * and is a valid value, so is left unchanged here.
 */
void lod_fix_desc_stripe_count(__u32 *val)
{
	if (*val == 0)
		*val = 1;
}

/**
 * set the filesystem default layout pattern
 *
 * \param[in,out] val	LOV_PATTERN_* layout
 *
 * A value of "0" means "use the system-wide default layout type", which
 * has either been inherited by now, or falls back to plain RAID0 striping.
 */
void lod_fix_desc_pattern(__u32 *val)
{
	/* from lov_setstripe */
	if ((*val != 0) && !lov_pattern_supported_normal_comp(*val)) {
		LCONSOLE_WARN("lod: Unknown stripe pattern: %#x\n", *val);
		*val = 0;
	}
}

void lod_fix_lmv_desc_pattern(__u32 *val)
{
	if ((*val) && !lmv_is_known_hash_type(*val)) {
		LCONSOLE_WARN("lod: Unknown md stripe pattern: %#x\n", *val);
		*val = 0;
	}
}

void lod_fix_desc_qos_maxage(__u32 *val)
{
	/* fix qos_maxage */
	if (*val == 0)
		*val = LOV_DESC_QOS_MAXAGE_DEFAULT;
}

/**
 * Used to fix insane default striping.
 *
 * \param[in] desc	striping description
 */
void lod_fix_desc(struct lov_desc *desc)
{
	lod_fix_desc_stripe_size(&desc->ld_default_stripe_size);
	lod_fix_desc_stripe_count(&desc->ld_default_stripe_count);
	lod_fix_desc_pattern(&desc->ld_pattern);
	lod_fix_desc_qos_maxage(&desc->ld_qos_maxage);
}

static void lod_fix_lmv_desc(struct lmv_desc *desc)
{
	desc->ld_active_tgt_count = 0;
	lod_fix_desc_stripe_count(&desc->ld_default_stripe_count);
	lod_fix_lmv_desc_pattern(&desc->ld_pattern);
	lod_fix_desc_qos_maxage(&desc->ld_qos_maxage);
}

/**
 * Initialize the structures used to store pools and default striping.
 *
 * \param[in] lod	LOD device
 * \param[in] lcfg	configuration structure storing default striping.
 *
 * \retval		0 if initialization succeeds
 * \retval		negative error number on failure
 */
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
	lod->lod_ost_descs.ltd_lov_desc = *desc;

	/* NB: config doesn't contain lmv_desc, alter it via sysfs. */
	lod_fix_lmv_desc(&lod->lod_mdt_descs.ltd_lmv_desc);

	lod->lod_sp_me = LUSTRE_SP_CLI;

	/* Set up OST pool environment */
	lod->lod_pool_count = 0;
	rc = lod_pool_hash_init(&lod->lod_pools_hash_body);
	if (rc)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&lod->lod_pool_list);
	lod->lod_pool_count = 0;
	rc = lu_tgt_pool_init(&lod->lod_mdt_descs.ltd_tgt_pool, 0);
	if (rc)
		GOTO(out_hash, rc);

	rc = lu_tgt_pool_init(&lod->lod_mdt_descs.ltd_qos.lq_rr.lqr_pool, 0);
	if (rc)
		GOTO(out_mdt_pool, rc);

	rc = lu_tgt_pool_init(&lod->lod_ost_descs.ltd_tgt_pool, 0);
	if (rc)
		GOTO(out_mdt_rr_pool, rc);

	rc = lu_tgt_pool_init(&lod->lod_ost_descs.ltd_qos.lq_rr.lqr_pool, 0);
	if (rc)
		GOTO(out_ost_pool, rc);

	RETURN(0);

out_ost_pool:
	lu_tgt_pool_free(&lod->lod_ost_descs.ltd_tgt_pool);
out_mdt_rr_pool:
	lu_tgt_pool_free(&lod->lod_mdt_descs.ltd_qos.lq_rr.lqr_pool);
out_mdt_pool:
	lu_tgt_pool_free(&lod->lod_mdt_descs.ltd_tgt_pool);
out_hash:
	lod_pool_hash_destroy(&lod->lod_pools_hash_body);

	return rc;
}

/**
 * Release the structures describing the pools.
 *
 * \param[in] lod	LOD device from which we release the structures
 *
 * \retval		0 always
 */
int lod_pools_fini(struct lod_device *lod)
{
	struct obd_device   *obd = lod2obd(lod);
	struct pool_desc    *pool, *tmp;
	ENTRY;

	list_for_each_entry_safe(pool, tmp, &lod->lod_pool_list, pool_list) {
		/* free pool structs */
		CDEBUG(D_INFO, "delete pool %p\n", pool);
		/* In the function below, .hs_keycmp resolves to
		 * pool_hashkey_keycmp() */
		/* coverity[overrun-buffer-val] */
		lod_pool_del(obd, pool->pool_name);
	}

	lod_pool_hash_destroy(&lod->lod_pools_hash_body);
	lu_tgt_pool_free(&lod->lod_ost_descs.ltd_qos.lq_rr.lqr_pool);
	lu_tgt_pool_free(&lod->lod_ost_descs.ltd_tgt_pool);
	lu_tgt_pool_free(&lod->lod_mdt_descs.ltd_qos.lq_rr.lqr_pool);
	lu_tgt_pool_free(&lod->lod_mdt_descs.ltd_tgt_pool);

	RETURN(0);
}
