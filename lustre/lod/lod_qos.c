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
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lod/lod_qos.c
 *
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <libcfs/libcfs.h>
#include <obd_class.h>
#include <obd_lov.h>
#include <lustre/lustre_idl.h>
#include "lod_internal.h"

/*
 * force QoS policy (not RR) to be used for testing purposes
 */
#define FORCE_QOS_

#define D_QOS   D_OTHER

#if 0
#define QOS_DEBUG(fmt, ...)     CDEBUG(D_OTHER, fmt, ## __VA_ARGS__)
#define QOS_CONSOLE(fmt, ...)   LCONSOLE(D_OTHER, fmt, ## __VA_ARGS__)
#else
#define QOS_DEBUG(fmt, ...)
#define QOS_CONSOLE(fmt, ...)
#endif

#define TGT_BAVAIL(i) (OST_TGT(lod,i)->ltd_statfs.os_bavail * \
		       OST_TGT(lod,i)->ltd_statfs.os_bsize)

int qos_add_tgt(struct lod_device *lod, struct lod_tgt_desc *ost_desc)
{
	struct lov_qos_oss *oss = NULL, *temposs;
	struct obd_export  *exp = ost_desc->ltd_exp;
	int		    rc = 0, found = 0;
	cfs_list_t	   *list;
	ENTRY;

	down_write(&lod->lod_qos.lq_rw_sem);
	/*
	 * a bit hacky approach to learn NID of corresponding connection
	 * but there is no official API to access information like this
	 * with OSD API.
	 */
	cfs_list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list) {
		if (obd_uuid_equals(&oss->lqo_uuid,
				    &exp->exp_connection->c_remote_uuid)) {
			found++;
			break;
		}
	}

	if (!found) {
		OBD_ALLOC_PTR(oss);
		if (!oss)
			GOTO(out, rc = -ENOMEM);
		memcpy(&oss->lqo_uuid, &exp->exp_connection->c_remote_uuid,
		       sizeof(oss->lqo_uuid));
	} else {
		/* Assume we have to move this one */
		cfs_list_del(&oss->lqo_oss_list);
	}

	oss->lqo_ost_count++;
	ost_desc->ltd_qos.ltq_oss = oss;

	CDEBUG(D_QOS, "add tgt %s to OSS %s (%d OSTs)\n",
	       obd_uuid2str(&ost_desc->ltd_uuid), obd_uuid2str(&oss->lqo_uuid),
	       oss->lqo_ost_count);

	/* Add sorted by # of OSTs.  Find the first entry that we're
	   bigger than... */
	list = &lod->lod_qos.lq_oss_list;
	cfs_list_for_each_entry(temposs, list, lqo_oss_list) {
		if (oss->lqo_ost_count > temposs->lqo_ost_count)
			break;
	}
	/* ...and add before it.  If we're the first or smallest, temposs
	   points to the list head, and we add to the end. */
	cfs_list_add_tail(&oss->lqo_oss_list, &temposs->lqo_oss_list);

	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_rr.lqr_dirty = 1;

out:
	up_write(&lod->lod_qos.lq_rw_sem);
	RETURN(rc);
}

int qos_del_tgt(struct lod_device *lod, struct lod_tgt_desc *ost_desc)
{
	struct lov_qos_oss *oss;
	int                 rc = 0;
	ENTRY;

	down_write(&lod->lod_qos.lq_rw_sem);
	oss = ost_desc->ltd_qos.ltq_oss;
	if (!oss)
		GOTO(out, rc = -ENOENT);

	oss->lqo_ost_count--;
	if (oss->lqo_ost_count == 0) {
		CDEBUG(D_QOS, "removing OSS %s\n",
		       obd_uuid2str(&oss->lqo_uuid));
		cfs_list_del(&oss->lqo_oss_list);
		ost_desc->ltd_qos.ltq_oss = NULL;
		OBD_FREE_PTR(oss);
	}

	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_rr.lqr_dirty = 1;
out:
	up_write(&lod->lod_qos.lq_rw_sem);
	RETURN(rc);
}

static int lod_statfs_and_check(const struct lu_env *env, struct lod_device *d,
				int index, struct obd_statfs *sfs)
{
	struct lod_tgt_desc *ost;
	int		     rc;
	ENTRY;

	LASSERT(d);
	ost = OST_TGT(d,index);
	LASSERT(ost);

	rc = dt_statfs(env, ost->ltd_ost, sfs);
	if (rc && rc != -ENOTCONN)
		CERROR("%s: statfs: rc = %d\n", lod2obd(d)->obd_name, rc);

	/* check whether device has changed state (active, inactive) */
	if (rc != 0 && ost->ltd_active) {
		/* turned inactive? */
		spin_lock(&d->lod_desc_lock);
		if (ost->ltd_active) {
			ost->ltd_active = 0;
			LASSERT(d->lod_desc.ld_active_tgt_count > 0);
			d->lod_desc.ld_active_tgt_count--;
			d->lod_qos.lq_dirty = 1;
			d->lod_qos.lq_rr.lqr_dirty = 1;
			CDEBUG(D_CONFIG, "%s: turns inactive\n",
			       ost->ltd_exp->exp_obd->obd_name);
		}
		spin_unlock(&d->lod_desc_lock);
	} else if (rc == 0 && ost->ltd_active == 0) {
		/* turned active? */
		LASSERTF(d->lod_desc.ld_active_tgt_count < d->lod_ostnr,
			 "active tgt count %d, ost nr %d\n",
			 d->lod_desc.ld_active_tgt_count, d->lod_ostnr);
		spin_lock(&d->lod_desc_lock);
		if (ost->ltd_active == 0) {
			ost->ltd_active = 1;
			d->lod_desc.ld_active_tgt_count++;
			d->lod_qos.lq_dirty = 1;
			d->lod_qos.lq_rr.lqr_dirty = 1;
			CDEBUG(D_CONFIG, "%s: turns active\n",
			       ost->ltd_exp->exp_obd->obd_name);
		}
		spin_unlock(&d->lod_desc_lock);
	}

	RETURN(rc);
}

static void lod_qos_statfs_update(const struct lu_env *env,
				  struct lod_device *lod)
{
	struct obd_device *obd = lod2obd(lod);
	struct ost_pool   *osts = &(lod->lod_pool_info);
	int		   i, idx;
	__u64		   max_age, avail;
	ENTRY;

	max_age = cfs_time_shift_64(-2 * lod->lod_desc.ld_qos_maxage);

	if (cfs_time_beforeq_64(max_age, obd->obd_osfs_age))
		/* statfs data are quite recent, don't need to refresh it */
		RETURN_EXIT;

	down_write(&lod->lod_qos.lq_rw_sem);
	if (cfs_time_beforeq_64(max_age, obd->obd_osfs_age))
		goto out;

	for (i = 0; i < osts->op_count; i++) {
		idx = osts->op_array[i];
		avail = OST_TGT(lod,idx)->ltd_statfs.os_bavail;
		if (lod_statfs_and_check(env, lod, idx,
					 &OST_TGT(lod, idx)->ltd_statfs))
			continue;
		if (OST_TGT(lod,idx)->ltd_statfs.os_bavail != avail)
			/* recalculate weigths */
			lod->lod_qos.lq_dirty = 1;
	}
	obd->obd_osfs_age = cfs_time_current_64();

out:
	up_write(&lod->lod_qos.lq_rw_sem);
	EXIT;
}

/* Recalculate per-object penalties for OSSs and OSTs,
   depends on size of each ost in an oss */
static int lod_qos_calc_ppo(struct lod_device *lod)
{
	struct lov_qos_oss *oss;
	__u64		    ba_max, ba_min, temp;
	__u32		    num_active;
	int		    rc, i, prio_wide;
	time_t		    now, age;
	ENTRY;

	if (!lod->lod_qos.lq_dirty)
		GOTO(out, rc = 0);

	num_active = lod->lod_desc.ld_active_tgt_count - 1;
	if (num_active < 1)
		GOTO(out, rc = -EAGAIN);

	/* find bavail on each OSS */
	cfs_list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list)
				oss->lqo_bavail = 0;
	lod->lod_qos.lq_active_oss_count = 0;

	/*
	 * How badly user wants to select OSTs "widely" (not recently chosen
	 * and not on recent OSS's).  As opposed to "freely" (free space
	 * avail.) 0-256
	 */
	prio_wide = 256 - lod->lod_qos.lq_prio_free;

	ba_min = (__u64)(-1);
	ba_max = 0;
	now = cfs_time_current_sec();
	/* Calculate OST penalty per object
	 * (lod ref taken in lod_qos_prep_create()) */
	cfs_foreach_bit(lod->lod_ost_bitmap, i) {
		LASSERT(OST_TGT(lod,i));
		temp = TGT_BAVAIL(i);
		if (!temp)
			continue;
		ba_min = min(temp, ba_min);
		ba_max = max(temp, ba_max);

		/* Count the number of usable OSS's */
		if (OST_TGT(lod,i)->ltd_qos.ltq_oss->lqo_bavail == 0)
			lod->lod_qos.lq_active_oss_count++;
		OST_TGT(lod,i)->ltd_qos.ltq_oss->lqo_bavail += temp;

		/* per-OST penalty is prio * TGT_bavail / (num_ost - 1) / 2 */
		temp >>= 1;
		lov_do_div64(temp, num_active);
		OST_TGT(lod,i)->ltd_qos.ltq_penalty_per_obj =
			(temp * prio_wide) >> 8;

		age = (now - OST_TGT(lod,i)->ltd_qos.ltq_used) >> 3;
		if (lod->lod_qos.lq_reset ||
		    age > 32 * lod->lod_desc.ld_qos_maxage)
			OST_TGT(lod,i)->ltd_qos.ltq_penalty = 0;
		else if (age > lod->lod_desc.ld_qos_maxage)
			/* Decay the penalty by half for every 8x the update
			 * interval that the device has been idle.  That gives
			 * lots of time for the statfs information to be
			 * updated (which the penalty is only a proxy for),
			 * and avoids penalizing OSS/OSTs under light load. */
			OST_TGT(lod,i)->ltd_qos.ltq_penalty >>=
				(age / lod->lod_desc.ld_qos_maxage);
	}

	num_active = lod->lod_qos.lq_active_oss_count - 1;
	if (num_active < 1) {
		/* If there's only 1 OSS, we can't penalize it, so instead
		   we have to double the OST penalty */
		num_active = 1;
		cfs_foreach_bit(lod->lod_ost_bitmap, i)
			OST_TGT(lod,i)->ltd_qos.ltq_penalty_per_obj <<= 1;
	}

	/* Per-OSS penalty is prio * oss_avail / oss_osts / (num_oss - 1) / 2 */
	cfs_list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list) {
		temp = oss->lqo_bavail >> 1;
		lov_do_div64(temp, oss->lqo_ost_count * num_active);
		oss->lqo_penalty_per_obj = (temp * prio_wide) >> 8;

		age = (now - oss->lqo_used) >> 3;
		if (lod->lod_qos.lq_reset ||
		    age > 32 * lod->lod_desc.ld_qos_maxage)
			oss->lqo_penalty = 0;
		else if (age > lod->lod_desc.ld_qos_maxage)
			/* Decay the penalty by half for every 8x the update
			 * interval that the device has been idle.  That gives
			 * lots of time for the statfs information to be
			 * updated (which the penalty is only a proxy for),
			 * and avoids penalizing OSS/OSTs under light load. */
			oss->lqo_penalty >>= age / lod->lod_desc.ld_qos_maxage;
	}

	lod->lod_qos.lq_dirty = 0;
	lod->lod_qos.lq_reset = 0;

	/* If each ost has almost same free space,
	 * do rr allocation for better creation performance */
	lod->lod_qos.lq_same_space = 0;
	if ((ba_max * (256 - lod->lod_qos.lq_threshold_rr)) >> 8 < ba_min) {
		lod->lod_qos.lq_same_space = 1;
		/* Reset weights for the next time we enter qos mode */
		lod->lod_qos.lq_reset = 1;
	}
	rc = 0;

out:
#ifndef FORCE_QOS
	if (!rc && lod->lod_qos.lq_same_space)
		RETURN(-EAGAIN);
#endif
	RETURN(rc);
}

static int lod_qos_calc_weight(struct lod_device *lod, int i)
{
	__u64 temp, temp2;

	/* Final ost weight = TGT_BAVAIL - ost_penalty - oss_penalty */
	temp = TGT_BAVAIL(i);
	temp2 = OST_TGT(lod,i)->ltd_qos.ltq_penalty +
		OST_TGT(lod,i)->ltd_qos.ltq_oss->lqo_penalty;
	if (temp < temp2)
		OST_TGT(lod,i)->ltd_qos.ltq_weight = 0;
	else
		OST_TGT(lod,i)->ltd_qos.ltq_weight = temp - temp2;
	return 0;
}

/* We just used this index for a stripe; adjust everyone's weights */
static int lod_qos_used(struct lod_device *lod, struct ost_pool *osts,
			__u32 index, __u64 *total_wt)
{
	struct lod_tgt_desc *ost;
	struct lov_qos_oss  *oss;
	int j;
	ENTRY;

	ost = OST_TGT(lod,index);
	LASSERT(ost);

	/* Don't allocate on this devuce anymore, until the next alloc_qos */
	ost->ltd_qos.ltq_usable = 0;

	oss = ost->ltd_qos.ltq_oss;

	/* Decay old penalty by half (we're adding max penalty, and don't
	   want it to run away.) */
	ost->ltd_qos.ltq_penalty >>= 1;
	oss->lqo_penalty >>= 1;

	/* mark the OSS and OST as recently used */
	ost->ltd_qos.ltq_used = oss->lqo_used = cfs_time_current_sec();

	/* Set max penalties for this OST and OSS */
	ost->ltd_qos.ltq_penalty +=
		ost->ltd_qos.ltq_penalty_per_obj * lod->lod_ostnr;
	oss->lqo_penalty += oss->lqo_penalty_per_obj *
		lod->lod_qos.lq_active_oss_count;

	/* Decrease all OSS penalties */
	cfs_list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list) {
		if (oss->lqo_penalty < oss->lqo_penalty_per_obj)
			oss->lqo_penalty = 0;
		else
			oss->lqo_penalty -= oss->lqo_penalty_per_obj;
	}

	*total_wt = 0;
	/* Decrease all OST penalties */
	for (j = 0; j < osts->op_count; j++) {
		int i;

		i = osts->op_array[j];
		if (!cfs_bitmap_check(lod->lod_ost_bitmap, i))
			continue;

		ost = OST_TGT(lod,i);
		LASSERT(ost);

		if (ost->ltd_qos.ltq_penalty <
				ost->ltd_qos.ltq_penalty_per_obj)
			ost->ltd_qos.ltq_penalty = 0;
		else
			ost->ltd_qos.ltq_penalty -=
				ost->ltd_qos.ltq_penalty_per_obj;

		lod_qos_calc_weight(lod, i);

		/* Recalc the total weight of usable osts */
		if (ost->ltd_qos.ltq_usable)
			*total_wt += ost->ltd_qos.ltq_weight;

		QOS_DEBUG("recalc tgt %d usable=%d avail="LPU64
			  " ostppo="LPU64" ostp="LPU64" ossppo="LPU64
			  " ossp="LPU64" wt="LPU64"\n",
			  i, ost->ltd_qos.ltq_usable, TGT_BAVAIL(i) >> 10,
			  ost->ltd_qos.ltq_penalty_per_obj >> 10,
			  ost->ltd_qos.ltq_penalty >> 10,
			  ost->ltd_qos.ltq_oss->lqo_penalty_per_obj >> 10,
			  ost->ltd_qos.ltq_oss->lqo_penalty >> 10,
			  ost->ltd_qos.ltq_weight >> 10);
	}

	RETURN(0);
}

#define LOV_QOS_EMPTY ((__u32)-1)
/* compute optimal round-robin order, based on OSTs per OSS */
static int lod_qos_calc_rr(struct lod_device *lod, struct ost_pool *src_pool,
			   struct lov_qos_rr *lqr)
{
	struct lov_qos_oss  *oss;
	struct lod_tgt_desc *ost;
	unsigned placed, real_count;
	int i, rc;
	ENTRY;

	if (!lqr->lqr_dirty) {
		LASSERT(lqr->lqr_pool.op_size);
		RETURN(0);
	}

	/* Do actual allocation. */
	down_write(&lod->lod_qos.lq_rw_sem);

	/*
	 * Check again. While we were sleeping on @lq_rw_sem something could
	 * change.
	 */
	if (!lqr->lqr_dirty) {
		LASSERT(lqr->lqr_pool.op_size);
		up_write(&lod->lod_qos.lq_rw_sem);
		RETURN(0);
	}

	real_count = src_pool->op_count;

	/* Zero the pool array */
	/* alloc_rr is holding a read lock on the pool, so nobody is adding/
	   deleting from the pool. The lq_rw_sem insures that nobody else
	   is reading. */
	lqr->lqr_pool.op_count = real_count;
	rc = lod_ost_pool_extend(&lqr->lqr_pool, real_count);
	if (rc) {
		up_write(&lod->lod_qos.lq_rw_sem);
		RETURN(rc);
	}
	for (i = 0; i < lqr->lqr_pool.op_count; i++)
		lqr->lqr_pool.op_array[i] = LOV_QOS_EMPTY;

	/* Place all the OSTs from 1 OSS at the same time. */
	placed = 0;
	cfs_list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list) {
		int j = 0;

		for (i = 0; i < lqr->lqr_pool.op_count; i++) {
			int next;

			if (!cfs_bitmap_check(lod->lod_ost_bitmap,
						src_pool->op_array[i]))
				continue;

			ost = OST_TGT(lod,src_pool->op_array[i]);
			LASSERT(ost && ost->ltd_ost);
			if (ost->ltd_qos.ltq_oss != oss)
				continue;

			/* Evenly space these OSTs across arrayspace */
			next = j * lqr->lqr_pool.op_count / oss->lqo_ost_count;
			while (lqr->lqr_pool.op_array[next] != LOV_QOS_EMPTY)
				next = (next + 1) % lqr->lqr_pool.op_count;

			lqr->lqr_pool.op_array[next] = src_pool->op_array[i];
			j++;
			placed++;
		}
	}

	lqr->lqr_dirty = 0;
	up_write(&lod->lod_qos.lq_rw_sem);

	if (placed != real_count) {
		/* This should never happen */
		LCONSOLE_ERROR_MSG(0x14e, "Failed to place all OSTs in the "
				   "round-robin list (%d of %d).\n",
				   placed, real_count);
		for (i = 0; i < lqr->lqr_pool.op_count; i++) {
			LCONSOLE(D_WARNING, "rr #%d ost idx=%d\n", i,
				 lqr->lqr_pool.op_array[i]);
		}
		lqr->lqr_dirty = 1;
		RETURN(-EAGAIN);
	}

#if 0
	for (i = 0; i < lqr->lqr_pool.op_count; i++)
		QOS_CONSOLE("rr #%d ost idx=%d\n", i, lqr->lqr_pool.op_array[i]);
#endif

	RETURN(0);
}

/**
 * A helper function to:
 *   create in-core lu object on the specified OSP
 *   declare creation of the object
 * IMPORTANT: at this stage object is anonymouos - it has no fid assigned
 *            this is a workaround till we have natural FIDs on OST
 *
 *            at this point we want to declare (reserve) object for us as
 *            we can't block at execution (when create method is called).
 *            otherwise we'd block whole transaction batch
 */
static struct dt_object *lod_qos_declare_object_on(const struct lu_env *env,
						   struct lod_device *d,
						   int ost_idx,
						   struct thandle *th)
{
	struct lod_tgt_desc *ost;
	struct lu_object *o, *n;
	struct lu_device *nd;
	struct dt_object *dt;
	int               rc;
	ENTRY;

	LASSERT(d);
	LASSERT(ost_idx >= 0);
	LASSERT(ost_idx < d->lod_osts_size);
	ost = OST_TGT(d,ost_idx);
	LASSERT(ost);
	LASSERT(ost->ltd_ost);

	nd = &ost->ltd_ost->dd_lu_dev;

	/*
	 * allocate anonymous object with zero fid, real fid
	 * will be assigned by OSP within transaction
	 * XXX: to be fixed with fully-functional OST fids
	 */
	o = lu_object_anon(env, nd, NULL);
	if (IS_ERR(o))
		GOTO(out, dt = ERR_PTR(PTR_ERR(o)));

	n = lu_object_locate(o->lo_header, nd->ld_type);
	if (unlikely(n == NULL)) {
		CERROR("can't find slice\n");
		lu_object_put(env, o);
		GOTO(out, dt = ERR_PTR(-EINVAL));
	}

	dt = container_of(n, struct dt_object, do_lu);

	rc = dt_declare_create(env, dt, NULL, NULL, NULL, th);
	if (rc) {
		CDEBUG(D_OTHER, "can't declare creation on #%u: %d\n",
		       ost_idx, rc);
		lu_object_put(env, o);
		dt = ERR_PTR(rc);
	}

out:
	RETURN(dt);
}

static int min_stripe_count(int stripe_cnt, int flags)
{
	return (flags & LOV_USES_DEFAULT_STRIPE ?
			stripe_cnt - (stripe_cnt / 4) : stripe_cnt);
}

#define LOV_CREATE_RESEED_MULT 30
#define LOV_CREATE_RESEED_MIN  2000

static int inline lod_qos_dev_is_full(struct obd_statfs *msfs)
{
	__u64 used;
	int   bs = msfs->os_bsize;

	LASSERT(((bs - 1) & bs) == 0);

	/* the minimum of 0.1% used blocks and 1GB bytes. */
	used = min_t(__u64, (msfs->os_blocks - msfs->os_bfree) >> 10,
			1 << (31 - ffs(bs)));
	return (msfs->os_bavail < used);
}

int lod_ea_store_resize(struct lod_thread_info *info, int size);

static inline int lod_qos_ost_in_use_clear(const struct lu_env *env, int stripes)
{
	struct lod_thread_info *info = lod_env_info(env);

	if (info->lti_ea_store_size < sizeof(int) * stripes)
		lod_ea_store_resize(info, stripes * sizeof(int));
	if (info->lti_ea_store_size < sizeof(int) * stripes) {
		CERROR("can't allocate memory for ost-in-use array\n");
		return -ENOMEM;
	}
	memset(info->lti_ea_store, -1, sizeof(int) * stripes);
	return 0;
}

static inline void lod_qos_ost_in_use(const struct lu_env *env, int idx, int ost)
{
	struct lod_thread_info *info = lod_env_info(env);
	int *osts = info->lti_ea_store;

	LASSERT(info->lti_ea_store_size >= idx * sizeof(int));
	osts[idx] = ost;
}

static int lod_qos_is_ost_used(const struct lu_env *env, int ost, int stripes)
{
	struct lod_thread_info *info = lod_env_info(env);
	int *osts = info->lti_ea_store;
	int j;

	for (j = 0; j < stripes; j++) {
		if (osts[j] == ost)
			return 1;
	}
	return 0;
}

/* Allocate objects on OSTs with round-robin algorithm */
static int lod_alloc_rr(const struct lu_env *env, struct lod_object *lo,
			struct dt_object **stripe, int flags,
			struct thandle *th)
{
	struct lod_device *m = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct obd_statfs *sfs = &lod_env_info(env)->lti_osfs;
	struct pool_desc  *pool = NULL;
	struct ost_pool   *osts;
	struct lov_qos_rr *lqr;
	struct dt_object  *o;
	unsigned	   array_idx;
	int		   i, rc;
	int		   ost_start_idx_temp;
	int		   speed = 0;
	int		   stripe_idx = 0;
	int		   stripe_cnt = lo->ldo_stripenr;
	int		   stripe_cnt_min = min_stripe_count(stripe_cnt, flags);
	__u32		   ost_idx;
	ENTRY;

	if (lo->ldo_pool)
		pool = lod_find_pool(m, lo->ldo_pool);

	if (pool != NULL) {
		down_read(&pool_tgt_rw_sem(pool));
		osts = &(pool->pool_obds);
		lqr = &(pool->pool_rr);
	} else {
		osts = &(m->lod_pool_info);
		lqr = &(m->lod_qos.lq_rr);
	}

	rc = lod_qos_calc_rr(m, osts, lqr);
	if (rc)
		GOTO(out, rc);

	rc = lod_qos_ost_in_use_clear(env, lo->ldo_stripenr);
	if (rc)
		GOTO(out, rc);

	if (--lqr->lqr_start_count <= 0) {
		lqr->lqr_start_idx = cfs_rand() % osts->op_count;
		lqr->lqr_start_count =
			(LOV_CREATE_RESEED_MIN / max(osts->op_count, 1U) +
			 LOV_CREATE_RESEED_MULT) * max(osts->op_count, 1U);
	} else if (stripe_cnt_min >= osts->op_count ||
			lqr->lqr_start_idx > osts->op_count) {
		/* If we have allocated from all of the OSTs, slowly
		 * precess the next start if the OST/stripe count isn't
		 * already doing this for us. */
		lqr->lqr_start_idx %= osts->op_count;
		if (stripe_cnt > 1 && (osts->op_count % stripe_cnt) != 1)
			++lqr->lqr_offset_idx;
	}
	down_read(&m->lod_qos.lq_rw_sem);
	ost_start_idx_temp = lqr->lqr_start_idx;

repeat_find:
	array_idx = (lqr->lqr_start_idx + lqr->lqr_offset_idx) %
			osts->op_count;

	QOS_DEBUG("pool '%s' want %d startidx %d startcnt %d offset %d "
		  "active %d count %d arrayidx %d\n",
		  lo->ldo_pool ? lo->ldo_pool : "",
		  stripe_cnt, lqr->lqr_start_idx, lqr->lqr_start_count,
		  lqr->lqr_offset_idx, osts->op_count, osts->op_count,
		  array_idx);

	for (i = 0; i < osts->op_count && stripe_idx < lo->ldo_stripenr;
	     i++, array_idx = (array_idx + 1) % osts->op_count) {
		++lqr->lqr_start_idx;
		ost_idx = lqr->lqr_pool.op_array[array_idx];

		QOS_DEBUG("#%d strt %d act %d strp %d ary %d idx %d\n",
			  i, lqr->lqr_start_idx, /* XXX: active*/ 0,
			  stripe_idx, array_idx, ost_idx);

		if ((ost_idx == LOV_QOS_EMPTY) ||
		    !cfs_bitmap_check(m->lod_ost_bitmap, ost_idx))
			continue;

		/* Fail Check before osc_precreate() is called
		   so we can only 'fail' single OSC. */
		if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OSC_PRECREATE) && ost_idx == 0)
			continue;

		rc = lod_statfs_and_check(env, m, ost_idx, sfs);
		if (rc) {
			/* this OSP doesn't feel well */
			continue;
		}

		/*
		 * skip full devices
		 */
		if (lod_qos_dev_is_full(sfs)) {
			QOS_DEBUG("#%d is full\n", ost_idx);
			continue;
		}

		/*
		 * We expect number of precreated objects in f_ffree at
		 * the first iteration, skip OSPs with no objects ready
		 */
		if (sfs->os_fprecreated == 0 && speed == 0) {
			QOS_DEBUG("#%d: precreation is empty\n", ost_idx);
			continue;
		}

		/*
		 * try to use another OSP if this one is degraded
		 */
		if (sfs->os_state == OS_STATE_DEGRADED && speed < 2) {
			QOS_DEBUG("#%d: degraded\n", ost_idx);
			continue;
		}

		/*
		 * do not put >1 objects on a single OST
		 */
		if (speed && lod_qos_is_ost_used(env, ost_idx, stripe_idx))
			continue;

		o = lod_qos_declare_object_on(env, m, ost_idx, th);
		if (IS_ERR(o)) {
			CDEBUG(D_OTHER, "can't declare new object on #%u: %d\n",
			       ost_idx, (int) PTR_ERR(o));
			rc = PTR_ERR(o);
			continue;
		}

		/*
		 * We've successfuly declared (reserved) an object
		 */
		lod_qos_ost_in_use(env, stripe_idx, ost_idx);
		stripe[stripe_idx] = o;
		stripe_idx++;

	}
	if ((speed < 2) && (stripe_idx < stripe_cnt_min)) {
		/* Try again, allowing slower OSCs */
		speed++;
		lqr->lqr_start_idx = ost_start_idx_temp;
		goto repeat_find;
	}

	up_read(&m->lod_qos.lq_rw_sem);

	if (stripe_idx) {
		lo->ldo_stripenr = stripe_idx;
		/* at least one stripe is allocated */
		rc = 0;
	} else {
		/* nobody provided us with a single object */
		rc = -ENOSPC;
	}

out:
	if (pool != NULL) {
		up_read(&pool_tgt_rw_sem(pool));
		/* put back ref got by lod_find_pool() */
		lod_pool_putref(pool);
	}

	RETURN(rc);
}

/* alloc objects on osts with specific stripe offset */
static int lod_alloc_specific(const struct lu_env *env, struct lod_object *lo,
			      struct dt_object **stripe, int flags,
			      struct thandle *th)
{
	struct lod_device *m = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct obd_statfs *sfs = &lod_env_info(env)->lti_osfs;
	struct dt_object  *o;
	unsigned	   ost_idx, array_idx, ost_count;
	int		   i, rc, stripe_num = 0;
	int		   speed = 0;
	struct pool_desc  *pool = NULL;
	struct ost_pool   *osts;
	ENTRY;

	rc = lod_qos_ost_in_use_clear(env, lo->ldo_stripenr);
	if (rc)
		GOTO(out, rc);

	if (lo->ldo_pool)
		pool = lod_find_pool(m, lo->ldo_pool);

	if (pool != NULL) {
		down_read(&pool_tgt_rw_sem(pool));
		osts = &(pool->pool_obds);
	} else {
		osts = &(m->lod_pool_info);
	}

	ost_count = osts->op_count;

repeat_find:
	/* search loi_ost_idx in ost array */
	array_idx = 0;
	for (i = 0; i < ost_count; i++) {
		if (osts->op_array[i] == lo->ldo_def_stripe_offset) {
			array_idx = i;
			break;
		}
	}
	if (i == ost_count) {
		CERROR("Start index %d not found in pool '%s'\n",
		       lo->ldo_def_stripe_offset,
		       lo->ldo_pool ? lo->ldo_pool : "");
		GOTO(out, rc = -EINVAL);
	}

	for (i = 0; i < ost_count;
			i++, array_idx = (array_idx + 1) % ost_count) {
		ost_idx = osts->op_array[array_idx];

		if (!cfs_bitmap_check(m->lod_ost_bitmap, ost_idx))
			continue;

		/* Fail Check before osc_precreate() is called
		   so we can only 'fail' single OSC. */
		if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OSC_PRECREATE) && ost_idx == 0)
			continue;

		/*
		 * do not put >1 objects on a single OST
		 */
		if (lod_qos_is_ost_used(env, ost_idx, stripe_num))
			continue;

		/* Drop slow OSCs if we can, but not for requested start idx.
		 *
		 * This means "if OSC is slow and it is not the requested
		 * start OST, then it can be skipped, otherwise skip it only
		 * if it is inactive/recovering/out-of-space." */

		rc = lod_statfs_and_check(env, m, ost_idx, sfs);
		if (rc) {
			/* this OSP doesn't feel well */
			continue;
		}

		/*
		 * We expect number of precreated objects in f_ffree at
		 * the first iteration, skip OSPs with no objects ready
		 * don't apply this logic to OST specified with stripe_offset
		 */
		if (i != 0 && sfs->os_fprecreated == 0 && speed == 0)
			continue;

		o = lod_qos_declare_object_on(env, m, ost_idx, th);
		if (IS_ERR(o)) {
			CDEBUG(D_OTHER, "can't declare new object on #%u: %d\n",
			       ost_idx, (int) PTR_ERR(o));
			continue;
		}

		/*
		 * We've successfuly declared (reserved) an object
		 */
		lod_qos_ost_in_use(env, stripe_num, ost_idx);
		stripe[stripe_num] = o;
		stripe_num++;

		/* We have enough stripes */
		if (stripe_num == lo->ldo_stripenr)
			GOTO(out, rc = 0);
	}
	if (speed < 2) {
		/* Try again, allowing slower OSCs */
		speed++;
		goto repeat_find;
	}

	/* If we were passed specific striping params, then a failure to
	 * meet those requirements is an error, since we can't reallocate
	 * that memory (it might be part of a larger array or something).
	 *
	 * We can only get here if lsm_stripe_count was originally > 1.
	 */
	CERROR("can't lstripe objid "DFID": have %d want %u\n",
	       PFID(lu_object_fid(lod2lu_obj(lo))), stripe_num,
	       lo->ldo_stripenr);
	rc = -EFBIG;
out:
	if (pool != NULL) {
		up_read(&pool_tgt_rw_sem(pool));
		/* put back ref got by lod_find_pool() */
		lod_pool_putref(pool);
	}

	RETURN(rc);
}

static inline int lod_qos_is_usable(struct lod_device *lod)
{
#ifdef FORCE_QOS
	/* to be able to debug QoS code */
	return 1;
#endif

	/* Detect -EAGAIN early, before expensive lock is taken. */
	if (!lod->lod_qos.lq_dirty && lod->lod_qos.lq_same_space)
		return 0;

	if (lod->lod_desc.ld_active_tgt_count < 2)
		return 0;

	return 1;
}

/* Alloc objects on OSTs with optimization based on:
   - free space
   - network resources (shared OSS's)
 */
static int lod_alloc_qos(const struct lu_env *env, struct lod_object *lo,
			 struct dt_object **stripe, int flags,
			 struct thandle *th)
{
	struct lod_device   *m = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct obd_statfs   *sfs = &lod_env_info(env)->lti_osfs;
	struct lod_tgt_desc *ost;
	struct dt_object    *o;
	__u64		     total_weight = 0;
	int		     nfound, good_osts, i, rc = 0;
	int		     stripe_cnt = lo->ldo_stripenr;
	int		     stripe_cnt_min;
	struct pool_desc    *pool = NULL;
	struct ost_pool    *osts;
	ENTRY;

	stripe_cnt_min = min_stripe_count(stripe_cnt, flags);
	if (stripe_cnt_min < 1)
		RETURN(-EINVAL);

	if (lo->ldo_pool)
		pool = lod_find_pool(m, lo->ldo_pool);

	if (pool != NULL) {
		down_read(&pool_tgt_rw_sem(pool));
		osts = &(pool->pool_obds);
	} else {
		osts = &(m->lod_pool_info);
	}

	/* Detect -EAGAIN early, before expensive lock is taken. */
	if (!lod_qos_is_usable(m))
		GOTO(out_nolock, rc = -EAGAIN);

	/* Do actual allocation, use write lock here. */
	down_write(&m->lod_qos.lq_rw_sem);

	/*
	 * Check again, while we were sleeping on @lq_rw_sem things could
	 * change.
	 */
	if (!lod_qos_is_usable(m))
		GOTO(out, rc = -EAGAIN);

	rc = lod_qos_calc_ppo(m);
	if (rc)
		GOTO(out, rc);

	rc = lod_qos_ost_in_use_clear(env, lo->ldo_stripenr);
	if (rc)
		GOTO(out, rc);

	good_osts = 0;
	/* Find all the OSTs that are valid stripe candidates */
	for (i = 0; i < osts->op_count; i++) {
		if (!cfs_bitmap_check(m->lod_ost_bitmap, osts->op_array[i]))
			continue;

		rc = lod_statfs_and_check(env, m, osts->op_array[i], sfs);
		if (rc) {
			/* this OSP doesn't feel well */
			continue;
		}

		/*
		 * skip full devices
		 */
		if (lod_qos_dev_is_full(sfs))
			continue;

		/* Fail Check before osc_precreate() is called
		   so we can only 'fail' single OSC. */
		if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OSC_PRECREATE) &&
				   osts->op_array[i] == 0)
			continue;

		ost = OST_TGT(m,osts->op_array[i]);
		ost->ltd_qos.ltq_usable = 1;
		lod_qos_calc_weight(m, osts->op_array[i]);
		total_weight += ost->ltd_qos.ltq_weight;

		good_osts++;
	}

	QOS_DEBUG("found %d good osts\n", good_osts);

	if (good_osts < stripe_cnt_min)
		GOTO(out, rc = -EAGAIN);

	/* We have enough osts */
	if (good_osts < stripe_cnt)
		stripe_cnt = good_osts;

	/* Find enough OSTs with weighted random allocation. */
	nfound = 0;
	while (nfound < stripe_cnt) {
		__u64 rand, cur_weight;

		cur_weight = 0;
		rc = -ENOSPC;

		if (total_weight) {
#if BITS_PER_LONG == 32
			rand = cfs_rand() % (unsigned)total_weight;
			/* If total_weight > 32-bit, first generate the high
			 * 32 bits of the random number, then add in the low
			 * 32 bits (truncated to the upper limit, if needed) */
			if (total_weight > 0xffffffffULL)
				rand = (__u64)(cfs_rand() %
					(unsigned)(total_weight >> 32)) << 32;
			else
				rand = 0;

			if (rand == (total_weight & 0xffffffff00000000ULL))
				rand |= cfs_rand() % (unsigned)total_weight;
			else
				rand |= cfs_rand();

#else
			rand = ((__u64)cfs_rand() << 32 | cfs_rand()) %
				total_weight;
#endif
		} else {
			rand = 0;
		}

		/* On average, this will hit larger-weighted osts more often.
		   0-weight osts will always get used last (only when rand=0) */
		for (i = 0; i < osts->op_count; i++) {
			int idx = osts->op_array[i];

			if (!cfs_bitmap_check(m->lod_ost_bitmap, idx))
				continue;

			ost = OST_TGT(m,idx);

			if (!ost->ltd_qos.ltq_usable)
				continue;

			cur_weight += ost->ltd_qos.ltq_weight;
			QOS_DEBUG("stripe_cnt=%d nfound=%d cur_weight="LPU64
				  " rand="LPU64" total_weight="LPU64"\n",
				  stripe_cnt, nfound, cur_weight, rand,
				  total_weight);

			if (cur_weight < rand)
				continue;

			QOS_DEBUG("stripe=%d to idx=%d\n", nfound, idx);

			/*
			 * do not put >1 objects on a single OST
			 */
			if (lod_qos_is_ost_used(env, idx, nfound))
				continue;
			lod_qos_ost_in_use(env, nfound, idx);

			o = lod_qos_declare_object_on(env, m, idx, th);
			if (IS_ERR(o)) {
				QOS_DEBUG("can't declare object on #%u: %d\n",
					  idx, (int) PTR_ERR(o));
				continue;
			}
			stripe[nfound++] = o;
			lod_qos_used(m, osts, idx, &total_weight);
			rc = 0;
			break;
		}

		if (rc) {
			/* no OST found on this iteration, give up */
			break;
		}
	}

	if (unlikely(nfound != stripe_cnt)) {
		/*
		 * when the decision to use weighted algorithm was made
		 * we had enough appropriate OSPs, but this state can
		 * change anytime (no space on OST, broken connection, etc)
		 * so it's possible OSP won't be able to provide us with
		 * an object due to just changed state
		 */
		LCONSOLE_INFO("wanted %d, found %d\n", stripe_cnt, nfound);
		for (i = 0; i < nfound; i++) {
			LASSERT(stripe[i] != NULL);
			lu_object_put(env, &stripe[i]->do_lu);
			stripe[i] = NULL;
		}

		/* makes sense to rebalance next time */
		m->lod_qos.lq_dirty = 1;
		m->lod_qos.lq_same_space = 0;

		rc = -EAGAIN;
	}

out:
	up_write(&m->lod_qos.lq_rw_sem);

out_nolock:
	if (pool != NULL) {
		up_read(&pool_tgt_rw_sem(pool));
		/* put back ref got by lod_find_pool() */
		lod_pool_putref(pool);
	}

	RETURN(rc);
}

/* Find the max stripecount we should use */
static __u16 lod_get_stripecnt(struct lod_device *lod, __u32 magic,
			       __u16 stripe_count)
{
	__u32 max_stripes = LOV_MAX_STRIPE_COUNT_OLD;

	if (!stripe_count)
		stripe_count = lod->lod_desc.ld_default_stripe_count;
	if (stripe_count > lod->lod_desc.ld_active_tgt_count)
		stripe_count = lod->lod_desc.ld_active_tgt_count;
	if (!stripe_count)
		stripe_count = 1;

	/* stripe count is based on whether OSD can handle larger EA sizes */
	if (lod->lod_osd_max_easize > 0)
		max_stripes = lov_mds_md_stripecnt(lod->lod_osd_max_easize,
						   magic);

	return (stripe_count < max_stripes) ? stripe_count : max_stripes;
}

static int lod_use_defined_striping(const struct lu_env *env,
				    struct lod_object *mo,
				    const struct lu_buf *buf)
{
	struct lov_mds_md_v1   *v1 = buf->lb_buf;
	struct lov_mds_md_v3   *v3 = buf->lb_buf;
	struct lov_ost_data_v1 *objs;
	__u32			magic;
	int			rc = 0;
	ENTRY;

	magic = le32_to_cpu(v1->lmm_magic);
	if (magic == LOV_MAGIC_V1_DEF) {
		magic = LOV_MAGIC_V1;
		objs = &v1->lmm_objects[0];
	} else if (magic == LOV_MAGIC_V3_DEF) {
		magic = LOV_MAGIC_V3;
		objs = &v3->lmm_objects[0];
		lod_object_set_pool(mo, v3->lmm_pool_name);
	} else {
		GOTO(out, rc = -EINVAL);
	}

	mo->ldo_pattern = le32_to_cpu(v1->lmm_pattern);
	mo->ldo_stripe_size = le32_to_cpu(v1->lmm_stripe_size);
	mo->ldo_stripenr = le16_to_cpu(v1->lmm_stripe_count);
	mo->ldo_layout_gen = le16_to_cpu(v1->lmm_layout_gen);

	/* fixup for released file before object initialization */
	if (mo->ldo_pattern & LOV_PATTERN_F_RELEASED) {
		mo->ldo_released_stripenr = mo->ldo_stripenr;
		mo->ldo_stripenr = 0;
	}

	LASSERT(buf->lb_len >= lov_mds_md_size(mo->ldo_stripenr, magic));

	if (mo->ldo_stripenr > 0)
		rc = lod_initialize_objects(env, mo, objs);

out:
	RETURN(rc);
}

static int lod_qos_parse_config(const struct lu_env *env,
				struct lod_object *lo,
				const struct lu_buf *buf)
{
	struct lod_device     *d = lu2lod_dev(lod2lu_obj(lo)->lo_dev);
	struct lov_user_md_v1 *v1 = NULL;
	struct lov_user_md_v3 *v3 = NULL;
	struct pool_desc      *pool;
	__u32		       magic;
	int		       rc;
	ENTRY;

	if (buf == NULL || buf->lb_buf == NULL || buf->lb_len == 0)
		RETURN(0);

	v1 = buf->lb_buf;
	magic = v1->lmm_magic;

	if (magic == __swab32(LOV_USER_MAGIC_V1)) {
		lustre_swab_lov_user_md_v1(v1);
		magic = v1->lmm_magic;
	} else if (magic == __swab32(LOV_USER_MAGIC_V3)) {
		v3 = buf->lb_buf;
		lustre_swab_lov_user_md_v3(v3);
		magic = v3->lmm_magic;
	}

	if (unlikely(magic != LOV_MAGIC_V1 && magic != LOV_MAGIC_V3)) {
		/* try to use as fully defined striping */
		rc = lod_use_defined_striping(env, lo, buf);
		RETURN(rc);
	}

	if (unlikely(buf->lb_len < sizeof(*v1))) {
		CERROR("wrong size: %u\n", (unsigned) buf->lb_len);
		RETURN(-EINVAL);
	}

	v1->lmm_magic = magic;
	if (v1->lmm_pattern == 0)
		v1->lmm_pattern = LOV_PATTERN_RAID0;
	if (lov_pattern(v1->lmm_pattern) != LOV_PATTERN_RAID0) {
		CERROR("invalid pattern: %x\n", v1->lmm_pattern);
		RETURN(-EINVAL);
	}
	lo->ldo_pattern = v1->lmm_pattern;

	if (v1->lmm_stripe_size)
		lo->ldo_stripe_size = v1->lmm_stripe_size;
	if (lo->ldo_stripe_size & (LOV_MIN_STRIPE_SIZE - 1))
		lo->ldo_stripe_size = LOV_MIN_STRIPE_SIZE;

	if (v1->lmm_stripe_count)
		lo->ldo_stripenr = v1->lmm_stripe_count;

	if ((v1->lmm_stripe_offset >= d->lod_desc.ld_tgt_count) &&
	    (v1->lmm_stripe_offset != (typeof(v1->lmm_stripe_offset))(-1))) {
		CERROR("invalid offset: %x\n", v1->lmm_stripe_offset);
		RETURN(-EINVAL);
	}
	lo->ldo_def_stripe_offset = v1->lmm_stripe_offset;

	CDEBUG(D_OTHER, "lsm: %u size, %u stripes, %u offset\n",
	       v1->lmm_stripe_size, v1->lmm_stripe_count,
	       v1->lmm_stripe_offset);

	if (v1->lmm_magic == LOV_MAGIC_V3) {
		if (buf->lb_len < sizeof(*v3)) {
			CERROR("wrong size: %u\n", (unsigned) buf->lb_len);
			RETURN(-EINVAL);
		}

		v3 = buf->lb_buf;
		lod_object_set_pool(lo, v3->lmm_pool_name);

		/* In the function below, .hs_keycmp resolves to
		 * pool_hashkey_keycmp() */
		/* coverity[overrun-buffer-val] */
		pool = lod_find_pool(d, v3->lmm_pool_name);
		if (pool != NULL) {
			if (lo->ldo_def_stripe_offset !=
			    (typeof(v1->lmm_stripe_offset))(-1)) {
				rc = lo->ldo_def_stripe_offset;
				rc = lod_check_index_in_pool(rc, pool);
				if (rc < 0) {
					lod_pool_putref(pool);
					CERROR("invalid offset\n");
					RETURN(-EINVAL);
				}
			}

			if (lo->ldo_stripenr > pool_tgt_count(pool))
				lo->ldo_stripenr= pool_tgt_count(pool);

			lod_pool_putref(pool);
		}
	} else
		lod_object_set_pool(lo, NULL);

	/* fixup for released file */
	if (lo->ldo_pattern & LOV_PATTERN_F_RELEASED) {
		lo->ldo_released_stripenr = lo->ldo_stripenr;
		lo->ldo_stripenr = 0;
	}

	RETURN(0);
}

/*
 * buf should be NULL or contain striping settings
 */
int lod_qos_prep_create(const struct lu_env *env, struct lod_object *lo,
			struct lu_attr *attr, const struct lu_buf *buf,
			struct thandle *th)
{
	struct lod_device      *d = lu2lod_dev(lod2lu_obj(lo)->lo_dev);
	struct dt_object      **stripe;
	int			stripe_len;
	int			flag = LOV_USES_ASSIGNED_STRIPE;
	int			i, rc;
	ENTRY;

	LASSERT(lo);

	/* no OST available */
	/* XXX: should we be waiting a bit to prevent failures during
	 * cluster initialization? */
	if (d->lod_ostnr == 0)
		GOTO(out, rc = -EIO);

	/*
	 * by this time, the object's ldo_stripenr and ldo_stripe_size
	 * contain default value for striping: taken from the parent
	 * or from filesystem defaults
	 *
	 * in case the caller is passing lovea with new striping config,
	 * we may need to parse lovea and apply new configuration
	 */
	rc = lod_qos_parse_config(env, lo, buf);
	if (rc)
		GOTO(out, rc);

	/* A released file is being created */
	if (lo->ldo_stripenr == 0)
		GOTO(out, rc = 0);

	if (likely(lo->ldo_stripe == NULL)) {
		/*
		 * no striping has been created so far
		 */
		LASSERT(lo->ldo_stripenr > 0);
		/*
		 * statfs and check OST targets now, since ld_active_tgt_count
		 * could be changed if some OSTs are [de]activated manually.
		 */
		lod_qos_statfs_update(env, d);
		lo->ldo_stripenr = lod_get_stripecnt(d, LOV_MAGIC,
				lo->ldo_stripenr);

		stripe_len = lo->ldo_stripenr;
		OBD_ALLOC(stripe, sizeof(stripe[0]) * stripe_len);
		if (stripe == NULL)
			GOTO(out, rc = -ENOMEM);

		lod_getref(&d->lod_ost_descs);
		/* XXX: support for non-0 files w/o objects */
		CDEBUG(D_OTHER, "tgt_count %d stripenr %d\n",
				d->lod_desc.ld_tgt_count, stripe_len);
		if (lo->ldo_def_stripe_offset >= d->lod_desc.ld_tgt_count) {
			rc = lod_alloc_qos(env, lo, stripe, flag, th);
			if (rc == -EAGAIN)
				rc = lod_alloc_rr(env, lo, stripe, flag, th);
		} else {
			rc = lod_alloc_specific(env, lo, stripe, flag, th);
		}
		lod_putref(d, &d->lod_ost_descs);

		if (rc < 0) {
			for (i = 0; i < stripe_len; i++)
				if (stripe[i] != NULL)
					lu_object_put(env, &stripe[i]->do_lu);

			OBD_FREE(stripe, sizeof(stripe[0]) * stripe_len);
		} else {
			lo->ldo_stripe = stripe;
			lo->ldo_stripes_allocated = stripe_len;
		}
	} else {
		/*
		 * lod_qos_parse_config() found supplied buf as a predefined
		 * striping (not a hint), so it allocated all the object
		 * now we need to create them
		 */
		for (i = 0; i < lo->ldo_stripenr; i++) {
			struct dt_object  *o;

			o = lo->ldo_stripe[i];
			LASSERT(o);

			rc = dt_declare_create(env, o, attr, NULL, NULL, th);
			if (rc) {
				CERROR("can't declare create: %d\n", rc);
				break;
			}
		}
	}

out:
	RETURN(rc);
}

