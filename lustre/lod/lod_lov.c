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
 */
/*
 * lustre/lod/lod_lov.c
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com> 
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <obd_class.h>
#include <obd_lov.h>

#include "lod_internal.h"

/*
 * Keep a refcount of lod->lod_osts usage to prevent racing with
 * addition/deletion. Any function that expects lov_tgts to remain stationary
 * must take a ref.
 *
 * \param lod - is the lod device from which we want to grab a reference
 */
void lod_getref(struct lod_device *lod)
{
	cfs_down_read(&lod->lod_rw_sem);
	cfs_mutex_lock(&lod->lod_mutex);
	lod->lod_refcount++;
	cfs_mutex_unlock(&lod->lod_mutex);
}

/*
 * Companion of lod_getref() to release a reference on the lod table.
 * If this is the last reference and the ost entry was scheduled for deletion,
 * the descriptor is removed from the array.
 *
 * \param lod - is the lod device from which we release a reference
 */
void lod_putref(struct lod_device *lod)
{
	cfs_mutex_lock(&lod->lod_mutex);
	lod->lod_refcount--;
	if (lod->lod_refcount == 0 && lod->lod_death_row) {
		struct lod_ost_desc *ost_desc, *tmp;
		int                  idx;
		CFS_LIST_HEAD(kill);

		CDEBUG(D_CONFIG, "destroying %d lod desc\n",
		       lod->lod_death_row);

		cfs_foreach_bit(lod->lod_ost_bitmap, idx) {
			ost_desc = OST_TGT(lod, idx);
			LASSERT(ost_desc);

			if (!ost_desc->ltd_reap)
				continue;

			cfs_list_add(&ost_desc->ltd_kill, &kill);

			lod_ost_pool_remove(&lod->lod_pool_info, idx);
			OST_TGT(lod, idx) = NULL;
			lod->lod_ostnr--;
			cfs_bitmap_clear(lod->lod_ost_bitmap, idx);
			if (ost_desc->ltd_active)
				lod->lod_desc.ld_active_tgt_count--;
			lod->lod_death_row--;
		}
		cfs_mutex_unlock(&lod->lod_mutex);
		cfs_up_read(&lod->lod_rw_sem);

		cfs_list_for_each_entry_safe(ost_desc, tmp, &kill, ltd_kill) {
			int rc;
			cfs_list_del(&ost_desc->ltd_kill);
			/* XXX: remove from QoS structures */
			/* disconnect from OSP */
			rc = obd_disconnect(ost_desc->ltd_exp);
			if (rc)
				CERROR("%s: failed to disconnect %s (%d)\n",
				       lod2obd(lod)->obd_name,
				       obd_uuid2str(&ost_desc->ltd_uuid), rc);
			OBD_FREE_PTR(ost_desc);
		}
	} else {
		cfs_mutex_unlock(&lod->lod_mutex);
		cfs_up_read(&lod->lod_rw_sem);
	}
}

static int lod_bitmap_resize(struct lod_device *lod, __u32 newsize)
{
	cfs_bitmap_t *new_bitmap, *old_bitmap = NULL;
	int	      rc = 0;
	ENTRY;

	/* grab write reference on the lod. Relocating the array requires
	 * exclusive access */
	cfs_down_write(&lod->lod_rw_sem);

	if (newsize <= lod->lod_osts_size)
		/* someone else has already resize the array */
		GOTO(out, rc = 0);

	/* allocate new bitmap */
	new_bitmap = CFS_ALLOCATE_BITMAP(newsize);
	if (!new_bitmap)
		GOTO(out, rc = -ENOMEM);

	if (lod->lod_osts_size > 0) {
		/* the bitmap already exists, we need
		 * to copy data from old one */
		cfs_bitmap_copy(new_bitmap, lod->lod_ost_bitmap);
		old_bitmap = lod->lod_ost_bitmap;
	}

	lod->lod_osts_size  = newsize;
	lod->lod_ost_bitmap = new_bitmap;

	if (old_bitmap)
		CFS_FREE_BITMAP(old_bitmap);

	CDEBUG(D_CONFIG, "ost size: %d\n", lod->lod_osts_size);

	EXIT;
out:
	cfs_up_write(&lod->lod_rw_sem);
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
 */
int lod_add_device(const struct lu_env *env, struct lod_device *lod,
		   char *osp, unsigned index, unsigned gen, int active)
{
	struct obd_connect_data *data = NULL;
	struct obd_export	*exp = NULL;
	struct obd_device	*obd;
	struct lu_device	*ldev;
	struct dt_device	*d;
	int			 rc;
	struct lod_ost_desc	*ost_desc;
	struct obd_uuid		 obd_uuid;

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

	rc = obd_connect(env, &exp, obd, &obd->obd_uuid, data, NULL);
	OBD_FREE_PTR(data);
	if (rc) {
		CERROR("%s: cannot connect to next dev %s (%d)\n",
		       obd->obd_name, osp, rc);
		GOTO(out_free, rc);
	}

	LASSERT(obd->obd_lu_dev);
	LASSERT(obd->obd_lu_dev->ld_site = lod->lod_dt_dev.dd_lu_dev.ld_site);

	ldev = obd->obd_lu_dev;
	d = lu2dt_dev(ldev);

	/* Allocate ost descriptor and fill it */
	OBD_ALLOC_PTR(ost_desc);
	if (!ost_desc)
		GOTO(out_conn, rc = -ENOMEM);

	ost_desc->ltd_ost    = d;
	ost_desc->ltd_exp    = exp;
	ost_desc->ltd_uuid   = obd->u.cli.cl_target_uuid;
	ost_desc->ltd_gen    = gen;
	ost_desc->ltd_index  = index;
	ost_desc->ltd_active = active;

	lod_getref(lod);
	if (index >= lod->lod_osts_size) {
		/* we have to increase the size of the lod_osts array */
		__u32  newsize;

		newsize = max(lod->lod_osts_size, (__u32)2);
		while (newsize < index + 1)
			newsize = newsize << 1;

		/* lod_bitmap_resize() needs lod_rw_sem
		 * which we hold with th reference */
		lod_putref(lod);

		rc = lod_bitmap_resize(lod, newsize);
		if (rc)
			GOTO(out_desc, rc);

		lod_getref(lod);
	}

	cfs_mutex_lock(&lod->lod_mutex);
	if (cfs_bitmap_check(lod->lod_ost_bitmap, index)) {
		CERROR("%s: device %d is registered already\n", obd->obd_name,
		       index);
		GOTO(out_mutex, rc = -EEXIST);
	}

	if (lod->lod_ost_idx[index / OST_PTRS_PER_BLOCK] == NULL) {
		OBD_ALLOC_PTR(lod->lod_ost_idx[index / OST_PTRS_PER_BLOCK]);
		if (lod->lod_ost_idx[index / OST_PTRS_PER_BLOCK] == NULL) {
			CERROR("can't allocate index to add %s\n",
			       obd->obd_name);
			GOTO(out_mutex, rc = -ENOMEM);
		}
	}

	rc = lod_ost_pool_add(&lod->lod_pool_info, index, lod->lod_osts_size);
	if (rc) {
		CERROR("%s: can't set up pool, failed with %d\n",
		       obd->obd_name, rc);
		GOTO(out_mutex, rc);
	}

	/* The new OST is now a full citizen */
	if (index >= lod->lod_desc.ld_tgt_count)
		lod->lod_desc.ld_tgt_count = index + 1;
	if (active)
		lod->lod_desc.ld_active_tgt_count++;
	OST_TGT(lod, index) = ost_desc;
	cfs_bitmap_set(lod->lod_ost_bitmap, index);
	lod->lod_ostnr++;
	cfs_mutex_unlock(&lod->lod_mutex);
	lod_putref(lod);

	if (lod->lod_recovery_completed)
		ldev->ld_ops->ldo_recovery_complete(env, ldev);

	RETURN(0);

	lod_ost_pool_remove(&lod->lod_pool_info, index);
out_mutex:
	cfs_mutex_unlock(&lod->lod_mutex);
	lod_putref(lod);
out_desc:
	OBD_FREE_PTR(ost_desc);
out_conn:
	obd_disconnect(exp);
out_free:
	return rc;
}

/*
 * helper function to schedule OST removal from the device table
 */
static void __lod_del_device(struct lod_device *lod, unsigned idx)
{
	LASSERT(OST_TGT(lod,idx));
	if (OST_TGT(lod,idx)->ltd_reap == 0) {
		OST_TGT(lod,idx)->ltd_reap = 1;
		lod->lod_death_row++;
	}
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
		   char *osp, unsigned idx, unsigned gen)
{
	struct obd_device *obd;
	int                rc = 0;
	struct obd_uuid    uuid;
	ENTRY;

	CDEBUG(D_CONFIG, "osp:%s idx:%d gen:%d\n", osp, idx, gen);

	obd = class_name2obd(osp);
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

	lod_getref(lod);
	cfs_mutex_lock(&lod->lod_mutex);
	/* check that the index is allocated in the bitmap */
	if (!cfs_bitmap_check(lod->lod_ost_bitmap, idx) || !OST_TGT(lod,idx)) {
		CERROR("%s: device %d is not set up\n", obd->obd_name, idx);
		GOTO(out, rc = -EINVAL);
	}

	/* check that the UUID matches */
	if (!obd_uuid_equals(&uuid, &OST_TGT(lod,idx)->ltd_uuid)) {
		CERROR("%s: LOD target UUID %s at index %d does not match %s\n",
		       obd->obd_name, obd_uuid2str(&OST_TGT(lod,idx)->ltd_uuid),
		       idx, osp);
		GOTO(out, rc = -EINVAL);
	}

	__lod_del_device(lod, idx);
	EXIT;
out:
	cfs_mutex_unlock(&lod->lod_mutex);
	lod_putref(lod);
	return(rc);
}

void lod_fix_desc_stripe_size(__u64 *val)
{
	if (*val < PTLRPC_MAX_BRW_SIZE) {
		LCONSOLE_WARN("Increasing default stripe size to min %u\n",
			      PTLRPC_MAX_BRW_SIZE);
		*val = PTLRPC_MAX_BRW_SIZE;
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
	struct lprocfs_static_vars  lvars = { 0 };
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
	cfs_init_rwsem(&lod->lod_qos.lq_rw_sem);
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
	cfs_waitq_init(&lod->lod_qos.lq_statfs_waitq);

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

	/* the OST array and bitmap are allocated/grown dynamically as OSTs are
	 * added to the LOD, see lod_add_device() */
	lod->lod_ost_bitmap = NULL;
	lod->lod_osts_size  = 0;
	lod->lod_ostnr      = 0;

	lod->lod_death_row = 0;
	lod->lod_refcount  = 0;

	lprocfs_lod_init_vars(&lvars);
	lprocfs_obd_setup(obd, lvars.obd_vars);

#ifdef LPROCFS
	rc = lprocfs_seq_create(obd->obd_proc_entry, "target_obd",
				0444, &lod_proc_target_fops, obd);
	if (rc) {
		CWARN("%s: Error adding the target_obd file %d\n",
		      obd->obd_name, rc);
		GOTO(out_lproc, rc);
	}
	lod->lod_pool_proc_entry = lprocfs_register("pools",
						    obd->obd_proc_entry,
						    NULL, NULL);
	if (IS_ERR(lod->lod_pool_proc_entry)) {
		int ret = PTR_ERR(lod->lod_pool_proc_entry);
		lod->lod_pool_proc_entry = NULL;
		CWARN("%s: Failed to create pool proc file %d\n",
		      obd->obd_name, ret);
		rc = lod_pools_fini(lod);
		RETURN(ret);
	}
#endif

	RETURN(0);

out_lproc:
	lprocfs_obd_cleanup(obd);
	lod_ost_pool_free(&lod->lod_qos.lq_rr.lqr_pool);
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
		lod_pool_del(obd, pool->pool_name);
	}

	if (lod->lod_osts_size > 0) {
		int idx;
		lod_getref(lod);
		cfs_mutex_lock(&lod->lod_mutex);
		cfs_foreach_bit(lod->lod_ost_bitmap, idx)
			__lod_del_device(lod, idx);
		cfs_mutex_unlock(&lod->lod_mutex);
		lod_putref(lod);
		CFS_FREE_BITMAP(lod->lod_ost_bitmap);
		for (idx = 0; idx < OST_PTRS; idx++) {
			if (lod->lod_ost_idx[idx])
				OBD_FREE_PTR(lod->lod_ost_idx[idx]);
		}
		lod->lod_osts_size = 0;
	}

	cfs_hash_putref(lod->lod_pools_hash_body);
	lod_ost_pool_free(&(lod->lod_qos.lq_rr.lqr_pool));
	lod_ost_pool_free(&lod->lod_pool_info);

	/* clear pools parent proc entry only after all pools are killed */
	if (lod->lod_pool_proc_entry) {
		lprocfs_remove(&lod->lod_pool_proc_entry);
		lod->lod_pool_proc_entry = NULL;
	}

	lprocfs_obd_cleanup(obd);

	OBD_FREE_PTR(lod->lod_qos.lq_statfs_data);
	RETURN(0);
}

