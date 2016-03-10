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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lod/lod_qos.c
 *
 * Implementation of different allocation algorithm used
 * to distribute objects and data among OSTs.
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <asm/div64.h>
#include <libcfs/libcfs.h>
#include <lustre/lustre_idl.h>
#include <lustre_swab.h>
#include <obd_class.h>

#include "lod_internal.h"

/*
 * force QoS policy (not RR) to be used for testing purposes
 */
#define FORCE_QOS_

#define D_QOS   D_OTHER

#define QOS_DEBUG(fmt, ...)     CDEBUG(D_QOS, fmt, ## __VA_ARGS__)
#define QOS_CONSOLE(fmt, ...)   LCONSOLE(D_QOS, fmt, ## __VA_ARGS__)

#define TGT_BAVAIL(i) (OST_TGT(lod,i)->ltd_statfs.os_bavail * \
		       OST_TGT(lod,i)->ltd_statfs.os_bsize)

/**
 * Add a new target to Quality of Service (QoS) target table.
 *
 * Add a new OST target to the structure representing an OSS. Resort the list
 * of known OSSs by the number of OSTs attached to each OSS. The OSS list is
 * protected internally and no external locking is required.
 *
 * \param[in] lod		LOD device
 * \param[in] ost_desc		OST description
 *
 * \retval 0			on success
 * \retval -ENOMEM		on error
 */
int qos_add_tgt(struct lod_device *lod, struct lod_tgt_desc *ost_desc)
{
	struct lod_qos_oss *oss = NULL, *temposs;
	struct obd_export  *exp = ost_desc->ltd_exp;
	int		    rc = 0, found = 0;
	struct list_head   *list;
	ENTRY;

	down_write(&lod->lod_qos.lq_rw_sem);
	/*
	 * a bit hacky approach to learn NID of corresponding connection
	 * but there is no official API to access information like this
	 * with OSD API.
	 */
	list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list) {
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
		list_del(&oss->lqo_oss_list);
	}

	oss->lqo_ost_count++;
	ost_desc->ltd_qos.ltq_oss = oss;

	CDEBUG(D_QOS, "add tgt %s to OSS %s (%d OSTs)\n",
	       obd_uuid2str(&ost_desc->ltd_uuid), obd_uuid2str(&oss->lqo_uuid),
	       oss->lqo_ost_count);

	/* Add sorted by # of OSTs.  Find the first entry that we're
	   bigger than... */
	list = &lod->lod_qos.lq_oss_list;
	list_for_each_entry(temposs, list, lqo_oss_list) {
		if (oss->lqo_ost_count > temposs->lqo_ost_count)
			break;
	}
	/* ...and add before it.  If we're the first or smallest, temposs
	   points to the list head, and we add to the end. */
	list_add_tail(&oss->lqo_oss_list, &temposs->lqo_oss_list);

	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_rr.lqr_dirty = 1;

out:
	up_write(&lod->lod_qos.lq_rw_sem);
	RETURN(rc);
}

/**
 * Remove OST target from QoS table.
 *
 * Removes given OST target from QoS table and releases related OSS structure
 * if no OSTs remain on the OSS.
 *
 * \param[in] lod		LOD device
 * \param[in] ost_desc		OST description
 *
 * \retval 0			on success
 * \retval -ENOENT		if no OSS was found
 */
int qos_del_tgt(struct lod_device *lod, struct lod_tgt_desc *ost_desc)
{
	struct lod_qos_oss *oss;
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
		list_del(&oss->lqo_oss_list);
		ost_desc->ltd_qos.ltq_oss = NULL;
		OBD_FREE_PTR(oss);
	}

	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_rr.lqr_dirty = 1;
out:
	up_write(&lod->lod_qos.lq_rw_sem);
	RETURN(rc);
}

/**
 * Check whether the target is available for new OST objects.
 *
 * Request statfs data from the given target and verify it's active and not
 * read-only. If so, then it can be used to place new OST objects. This
 * function also maintains the number of active/inactive targets and sets
 * dirty flags if those numbers change so others can run re-balance procedures.
 * No external locking is required.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] d		LOD device
 * \param[in] index	index of OST target to check
 * \param[out] sfs	buffer for statfs data
 *
 * \retval 0		if the target is good
 * \retval negative	negated errno on error

 */
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

	if (rc == 0 && ((sfs->os_state & OS_STATE_ENOSPC) ||
	    (sfs->os_state & OS_STATE_ENOINO && sfs->os_fprecreated == 0)))
		RETURN(-ENOSPC);

	if (rc && rc != -ENOTCONN)
		CERROR("%s: statfs: rc = %d\n", lod2obd(d)->obd_name, rc);

	/* If the OST is readonly then we can't allocate objects there */
	if (sfs->os_state & OS_STATE_READONLY)
		rc = -EROFS;

	/* check whether device has changed state (active, inactive) */
	if (rc != 0 && ost->ltd_active) {
		/* turned inactive? */
		spin_lock(&d->lod_lock);
		if (ost->ltd_active) {
			ost->ltd_active = 0;
			if (rc == -ENOTCONN)
				ost->ltd_connecting = 1;

			LASSERT(d->lod_desc.ld_active_tgt_count > 0);
			d->lod_desc.ld_active_tgt_count--;
			d->lod_qos.lq_dirty = 1;
			d->lod_qos.lq_rr.lqr_dirty = 1;
			CDEBUG(D_CONFIG, "%s: turns inactive\n",
			       ost->ltd_exp->exp_obd->obd_name);
		}
		spin_unlock(&d->lod_lock);
	} else if (rc == 0 && ost->ltd_active == 0) {
		/* turned active? */
		LASSERTF(d->lod_desc.ld_active_tgt_count < d->lod_ostnr,
			 "active tgt count %d, ost nr %d\n",
			 d->lod_desc.ld_active_tgt_count, d->lod_ostnr);
		spin_lock(&d->lod_lock);
		if (ost->ltd_active == 0) {
			ost->ltd_active = 1;
			ost->ltd_connecting = 0;
			d->lod_desc.ld_active_tgt_count++;
			d->lod_qos.lq_dirty = 1;
			d->lod_qos.lq_rr.lqr_dirty = 1;
			CDEBUG(D_CONFIG, "%s: turns active\n",
			       ost->ltd_exp->exp_obd->obd_name);
		}
		spin_unlock(&d->lod_lock);
	}

	RETURN(rc);
}

/**
 * Maintain per-target statfs data.
 *
 * The function refreshes statfs data for all the targets every N seconds.
 * The actual N is controlled via procfs and set to LOV_DESC_QOS_MAXAGE_DEFAULT
 * initially.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] lod	LOD device
 */
static void lod_qos_statfs_update(const struct lu_env *env,
				  struct lod_device *lod)
{
	struct obd_device *obd = lod2obd(lod);
	struct ost_pool   *osts = &(lod->lod_pool_info);
	unsigned int	   i;
	int		   idx;
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

/**
 * Calculate per-OST and per-OSS penalties
 *
 * Re-calculate penalties when the configuration changes, active targets
 * change and after statfs refresh (all these are reflected by lq_dirty flag).
 * On every OST and OSS: decay the penalty by half for every 8x the update
 * interval that the device has been idle. That gives lots of time for the
 * statfs information to be updated (which the penalty is only a proxy for),
 * and avoids penalizing OSS/OSTs under light load.
 * See lod_qos_calc_weight() for how penalties are factored into the weight.
 *
 * \param[in] lod	LOD device
 *
 * \retval 0		on success
 * \retval -EAGAIN	the number of OSTs isn't enough
 */
static int lod_qos_calc_ppo(struct lod_device *lod)
{
	struct lod_qos_oss *oss;
	__u64		    ba_max, ba_min, temp;
	__u32		    num_active;
	unsigned int	    i;
	int		    rc, prio_wide;
	time_t		    now, age;
	ENTRY;

	if (!lod->lod_qos.lq_dirty)
		GOTO(out, rc = 0);

	num_active = lod->lod_desc.ld_active_tgt_count - 1;
	if (num_active < 1)
		GOTO(out, rc = -EAGAIN);

	/* find bavail on each OSS */
	list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list)
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
		do_div(temp, num_active);
		OST_TGT(lod,i)->ltd_qos.ltq_penalty_per_obj =
			(temp * prio_wide) >> 8;

		age = (now - OST_TGT(lod,i)->ltd_qos.ltq_used) >> 3;
		if (lod->lod_qos.lq_reset ||
		    age > 32 * lod->lod_desc.ld_qos_maxage)
			OST_TGT(lod,i)->ltd_qos.ltq_penalty = 0;
		else if (age > lod->lod_desc.ld_qos_maxage)
			/* Decay OST penalty. */
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
	list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list) {
		temp = oss->lqo_bavail >> 1;
		do_div(temp, oss->lqo_ost_count * num_active);
		oss->lqo_penalty_per_obj = (temp * prio_wide) >> 8;

		age = (now - oss->lqo_used) >> 3;
		if (lod->lod_qos.lq_reset ||
		    age > 32 * lod->lod_desc.ld_qos_maxage)
			oss->lqo_penalty = 0;
		else if (age > lod->lod_desc.ld_qos_maxage)
			/* Decay OSS penalty. */
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

/**
 * Calculate weight for a given OST target.
 *
 * The final OST weight is the number of bytes available minus the OST and
 * OSS penalties.  See lod_qos_calc_ppo() for how penalties are calculated.
 *
 * \param[in] lod	LOD device, where OST targets are listed
 * \param[in] i		OST target index
 *
 * \retval		0
 */
static int lod_qos_calc_weight(struct lod_device *lod, int i)
{
	__u64 temp, temp2;

	temp = TGT_BAVAIL(i);
	temp2 = OST_TGT(lod,i)->ltd_qos.ltq_penalty +
		OST_TGT(lod,i)->ltd_qos.ltq_oss->lqo_penalty;
	if (temp < temp2)
		OST_TGT(lod,i)->ltd_qos.ltq_weight = 0;
	else
		OST_TGT(lod,i)->ltd_qos.ltq_weight = temp - temp2;
	return 0;
}

/**
 * Re-calculate weights.
 *
 * The function is called when some OST target was used for a new object. In
 * this case we should re-calculate all the weights to keep new allocations
 * balanced well.
 *
 * \param[in] lod	LOD device
 * \param[in] osts	OST pool where a new object was placed
 * \param[in] index	OST target where a new object was placed
 * \param[out] total_wt	new total weight for the pool
 *
 * \retval		0
 */
static int lod_qos_used(struct lod_device *lod, struct ost_pool *osts,
			__u32 index, __u64 *total_wt)
{
	struct lod_tgt_desc *ost;
	struct lod_qos_oss  *oss;
	unsigned int j;
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
	list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list) {
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

		QOS_DEBUG("recalc tgt %d usable=%d avail=%llu"
			  " ostppo=%llu ostp=%llu ossppo=%llu"
			  " ossp=%llu wt=%llu\n",
			  i, ost->ltd_qos.ltq_usable, TGT_BAVAIL(i) >> 10,
			  ost->ltd_qos.ltq_penalty_per_obj >> 10,
			  ost->ltd_qos.ltq_penalty >> 10,
			  ost->ltd_qos.ltq_oss->lqo_penalty_per_obj >> 10,
			  ost->ltd_qos.ltq_oss->lqo_penalty >> 10,
			  ost->ltd_qos.ltq_weight >> 10);
	}

	RETURN(0);
}

void lod_qos_rr_init(struct lod_qos_rr *lqr)
{
	spin_lock_init(&lqr->lqr_alloc);
	lqr->lqr_dirty = 1;
}


#define LOV_QOS_EMPTY ((__u32)-1)

/**
 * Calculate optimal round-robin order with regard to OSSes.
 *
 * Place all the OSTs from pool \a src_pool in a special array to be used for
 * round-robin (RR) stripe allocation.  The placement algorithm interleaves
 * OSTs from the different OSSs so that RR allocation can balance OSSs evenly.
 * Resorts the targets when the number of active targets changes (because of
 * a new target or activation/deactivation).
 *
 * \param[in] lod	LOD device
 * \param[in] src_pool	OST pool
 * \param[in] lqr	round-robin list
 *
 * \retval 0		on success
 * \retval -ENOMEM	fails to allocate the array
 */
static int lod_qos_calc_rr(struct lod_device *lod, struct ost_pool *src_pool,
			   struct lod_qos_rr *lqr)
{
	struct lod_qos_oss  *oss;
	struct lod_tgt_desc *ost;
	unsigned placed, real_count;
	unsigned int i;
	int rc;
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
	list_for_each_entry(oss, &lod->lod_qos.lq_oss_list, lqo_oss_list) {
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
 * Instantiate and declare creation of a new object.
 *
 * The function instantiates LU representation for a new object on the
 * specified device. Also it declares an intention to create that
 * object on the storage target.
 *
 * Note lu_object_anon() is used which is a trick with regard to LU/OSD
 * infrastructure - in the existing precreation framework we can't assign FID
 * at this moment, we do this later once a transaction is started. So the
 * special method instantiates FID-less object in the cache and later it
 * will get a FID and proper placement in LU cache.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] d		LOD device
 * \param[in] ost_idx	OST target index where the object is being created
 * \param[in] th	transaction handle
 *
 * \retval		object ptr on success, ERR_PTR() otherwise
 */
static struct dt_object *lod_qos_declare_object_on(const struct lu_env *env,
						   struct lod_device *d,
						   __u32 ost_idx,
						   struct thandle *th)
{
	struct lod_tgt_desc *ost;
	struct lu_object *o, *n;
	struct lu_device *nd;
	struct dt_object *dt;
	int               rc;
	ENTRY;

	LASSERT(d);
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

	rc = lod_sub_declare_create(env, dt, NULL, NULL, NULL, th);
	if (rc < 0) {
		CDEBUG(D_OTHER, "can't declare creation on #%u: %d\n",
		       ost_idx, rc);
		lu_object_put(env, o);
		dt = ERR_PTR(rc);
	}

out:
	RETURN(dt);
}

/**
 * Calculate a minimum acceptable stripe count.
 *
 * Return an acceptable stripe count depending on flag LOV_USES_DEFAULT_STRIPE:
 * all stripes or 3/4 of stripes.
 *
 * \param[in] stripe_cnt	number of stripes requested
 * \param[in] flags		0 or LOV_USES_DEFAULT_STRIPE
 *
 * \retval			acceptable stripecount
 */
static int min_stripe_count(__u32 stripe_cnt, int flags)
{
	return (flags & LOV_USES_DEFAULT_STRIPE ?
			stripe_cnt - (stripe_cnt / 4) : stripe_cnt);
}

#define LOV_CREATE_RESEED_MULT 30
#define LOV_CREATE_RESEED_MIN  2000

/**
 * Initialize temporary OST-in-use array.
 *
 * Allocate or extend the array used to mark targets already assigned to a new
 * striping so they are not used more than once.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] stripes	number of items needed in the array
 *
 * \retval 0		on success
 * \retval -ENOMEM	on error
 */
static inline int lod_qos_ost_in_use_clear(const struct lu_env *env,
					   __u32 stripes)
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

/**
 * Remember a target in the array of used targets.
 *
 * Mark the given target as used for a new striping being created. The status
 * of an OST in a striping can be checked with lod_qos_is_ost_used().
 *
 * \param[in] env	execution environment for this thread
 * \param[in] idx	index in the array
 * \param[in] ost	OST target index to mark as used
 */
static inline void lod_qos_ost_in_use(const struct lu_env *env,
				      int idx, int ost)
{
	struct lod_thread_info *info = lod_env_info(env);
	int *osts = info->lti_ea_store;

	LASSERT(info->lti_ea_store_size >= idx * sizeof(int));
	osts[idx] = ost;
}

/**
 * Check is OST used in a striping.
 *
 * Checks whether OST with the given index is marked as used in the temporary
 * array (see lod_qos_ost_in_use()).
 *
 * \param[in] env	execution environment for this thread
 * \param[in] ost	OST target index to check
 * \param[in] stripes	the number of items used in the array already
 *
 * \retval 0		not used
 * \retval 1		used
 */
static int lod_qos_is_ost_used(const struct lu_env *env, int ost, __u32 stripes)
{
	struct lod_thread_info *info = lod_env_info(env);
	int *osts = info->lti_ea_store;
	__u32 j;

	for (j = 0; j < stripes; j++) {
		if (osts[j] == ost)
			return 1;
	}
	return 0;
}

/**
 * Check is OST used in a composite layout
 *
 * \param[in] inuse	all inuse ost indexs
 * \param[in] ost	OST target index to check
 *
 * \retval 0		not used
 * \retval 1		used
 */
static inline int lod_comp_is_ost_used(struct ost_pool *inuse, int ost)
{
	__u32 j;
	LASSERT(inuse != NULL);

	if (inuse->op_size == 0)
		return 0;

	LASSERT(inuse->op_count * sizeof(inuse->op_array[0]) <= inuse->op_size);
	for (j = 0; j < inuse->op_count; j++) {
		if (inuse->op_array[j] == ost)
			return 1;
	}
	return 0;
}

/**
 * Mark the given target as used for a composite layout
 *
 * \param[in] inuse	inuse ost index array
 * \param[in] idx	index in the array
 */
static inline void lod_comp_ost_in_use(struct ost_pool *inuse, int ost)
{
	LASSERT(inuse != NULL);
	if (inuse->op_size && !lod_comp_is_ost_used(inuse, ost)) {
		LASSERT(inuse->op_count * sizeof(inuse->op_array[0]) <
			inuse->op_size);
		inuse->op_array[inuse->op_count] = ost;
		inuse->op_count++;
	}
}

static int lod_check_and_reserve_ost(const struct lu_env *env,
				     struct lod_device *m,
				     struct obd_statfs *sfs, __u32 ost_idx,
				     __u32 speed, __u32 *s_idx,
				     struct dt_object **stripe,
				     struct thandle *th,
				     struct ost_pool *inuse)
{
	struct dt_object   *o;
	__u32 stripe_idx = *s_idx;
	int rc;

	rc = lod_statfs_and_check(env, m, ost_idx, sfs);
	if (rc) {
		/* this OSP doesn't feel well */
		goto out_return;
	}

	/*
	 * We expect number of precreated objects in f_ffree at
	 * the first iteration, skip OSPs with no objects ready
	 */
	if (sfs->os_fprecreated == 0 && speed == 0) {
		QOS_DEBUG("#%d: precreation is empty\n", ost_idx);
		goto out_return;
	}

	/*
	 * try to use another OSP if this one is degraded
	 */
	if (sfs->os_state & OS_STATE_DEGRADED && speed < 2) {
		QOS_DEBUG("#%d: degraded\n", ost_idx);
		goto out_return;
	}

	/*
	 * try not allocate on OST which has been used by other
	 * component
	 */
	if (speed == 0 && lod_comp_is_ost_used(inuse, ost_idx)) {
		QOS_DEBUG("#%d: used by other component\n", ost_idx);
		goto out_return;
	}

	/*
	 * do not put >1 objects on a single OST
	 */
	if (lod_qos_is_ost_used(env, ost_idx, stripe_idx))
		goto out_return;

	o = lod_qos_declare_object_on(env, m, ost_idx, th);
	if (IS_ERR(o)) {
		CDEBUG(D_OTHER, "can't declare new object on #%u: %d\n",
		       ost_idx, (int) PTR_ERR(o));
		rc = PTR_ERR(o);
		goto out_return;
	}

	/*
	 * We've successfully declared (reserved) an object
	 */
	lod_qos_ost_in_use(env, stripe_idx, ost_idx);
	lod_comp_ost_in_use(inuse, ost_idx);
	stripe[stripe_idx] = o;
	OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_LOV_CREATE_RACE, 2);
	stripe_idx++;
	*s_idx = stripe_idx;

out_return:
	return rc;
}

/**
 * Allocate a striping using round-robin algorithm.
 *
 * Allocates a new striping using round-robin algorithm. The function refreshes
 * all the internal structures (statfs cache, array of available OSTs sorted
 * with regard to OSS, etc). The number of stripes required is taken from the
 * object (must be prepared by the caller), but can change if the flag
 * LOV_USES_DEFAULT_STRIPE is supplied. The caller should ensure nobody else
 * is trying to create a striping on the object in parallel. All the internal
 * structures (like pools, etc) are protected and no additional locking is
 * required. The function succeeds even if a single stripe is allocated. To save
 * time we give priority to targets which already have objects precreated.
 * Full OSTs are skipped (see lod_qos_dev_is_full() for the details).
 *
 * \param[in] env	execution environment for this thread
 * \param[in] lo	LOD object
 * \param[out] stripe	striping created
 * \param[in] flags	allocation flags (0 or LOV_USES_DEFAULT_STRIPE)
 * \param[in] th	transaction handle
 * \param[in] comp_idx	index of ldo_comp_entries
 * \param[in|out] inuse	array of inuse ost index
 *
 * \retval 0		on success
 * \retval -ENOSPC	if not enough OSTs are found
 * \retval negative	negated errno for other failures
 */
static int lod_alloc_rr(const struct lu_env *env, struct lod_object *lo,
			struct dt_object **stripe, int flags,
			struct thandle *th, int comp_idx,
			struct ost_pool *inuse)
{
	struct lod_layout_component *lod_comp;
	struct lod_device *m = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct obd_statfs *sfs = &lod_env_info(env)->lti_osfs;
	struct pool_desc  *pool = NULL;
	struct ost_pool   *osts;
	struct lod_qos_rr *lqr;
	unsigned int	i, array_idx;
	__u32	ost_start_idx_temp;
	__u32	stripe_idx = 0;
	__u32	stripe_cnt, stripe_cnt_min, ost_idx;
	int	rc, speed = 0, ost_connecting = 0;
	ENTRY;

	LASSERT(lo->ldo_comp_cnt > comp_idx && lo->ldo_comp_entries != NULL);
	lod_comp = &lo->ldo_comp_entries[comp_idx];
	stripe_cnt = lod_comp->llc_stripenr;
	stripe_cnt_min = min_stripe_count(stripe_cnt, flags);

	if (lod_comp->llc_pool != NULL)
		pool = lod_find_pool(m, lod_comp->llc_pool);

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

	rc = lod_qos_ost_in_use_clear(env, stripe_cnt);
	if (rc)
		GOTO(out, rc);

	down_read(&m->lod_qos.lq_rw_sem);
	spin_lock(&lqr->lqr_alloc);
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
	ost_start_idx_temp = lqr->lqr_start_idx;

repeat_find:

	QOS_DEBUG("pool '%s' want %d startidx %d startcnt %d offset %d "
		  "active %d count %d\n",
		  lod_comp->llc_pool ? lod_comp->llc_pool : "",
		  stripe_cnt, lqr->lqr_start_idx, lqr->lqr_start_count,
		  lqr->lqr_offset_idx, osts->op_count, osts->op_count);

	for (i = 0; i < osts->op_count && stripe_idx < stripe_cnt; i++) {
		array_idx = (lqr->lqr_start_idx + lqr->lqr_offset_idx) %
				osts->op_count;
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

		spin_unlock(&lqr->lqr_alloc);
		rc = lod_check_and_reserve_ost(env, m, sfs, ost_idx, speed,
					       &stripe_idx, stripe, th, inuse);
		spin_lock(&lqr->lqr_alloc);

		if (rc != 0 && OST_TGT(m, ost_idx)->ltd_connecting)
			ost_connecting = 1;
	}
	if ((speed < 2) && (stripe_idx < stripe_cnt_min)) {
		/* Try again, allowing slower OSCs */
		speed++;
		lqr->lqr_start_idx = ost_start_idx_temp;

		ost_connecting = 0;
		goto repeat_find;
	}

	spin_unlock(&lqr->lqr_alloc);
	up_read(&m->lod_qos.lq_rw_sem);

	if (stripe_idx) {
		lod_comp->llc_stripenr = stripe_idx;
		/* at least one stripe is allocated */
		rc = 0;
	} else {
		/* nobody provided us with a single object */
		if (ost_connecting)
			rc = -EINPROGRESS;
		else
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

/**
 * Allocate a specific striping layout on a user defined set of OSTs.
 *
 * Allocates new striping using the OST index range provided by the data from
 * the lmm_obejcts contained in the lov_user_md passed to this method. Full
 * OSTs are not considered. The exact order of OSTs requested by the user
 * is respected as much as possible depending on OST status. The number of
 * stripes needed and stripe offset are taken from the object. If that number
 * can not be met, then the function returns a failure and then it's the
 * caller's responsibility to release the stripes allocated. All the internal
 * structures are protected, but no concurrent allocation is allowed on the
 * same objects.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] lo	LOD object
 * \param[out] stripe	striping created
 * \param[in] th	transaction handle
 * \param[in] comp_idx	index of ldo_comp_entries
 * \param[in|out] inuse	array of inuse ost index
 *
 * \retval 0		on success
 * \retval -ENODEV	OST index does not exist on file system
 * \retval -EINVAL	requested OST index is invalid
 * \retval negative	negated errno on error
 */
static int lod_alloc_ost_list(const struct lu_env *env, struct lod_object *lo,
			      struct dt_object **stripe, struct thandle *th,
			      int comp_idx, struct ost_pool *inuse)
{
	struct lod_layout_component *lod_comp;
	struct lod_device	*m = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct obd_statfs	*sfs = &lod_env_info(env)->lti_osfs;
	struct dt_object	*o;
	unsigned int		array_idx = 0;
	int			stripe_count = 0;
	int			i;
	int			rc = -EINVAL;
	ENTRY;

	/* for specific OSTs layout */
	LASSERT(lo->ldo_comp_cnt > comp_idx && lo->ldo_comp_entries != NULL);
	lod_comp = &lo->ldo_comp_entries[comp_idx];
	LASSERT(lod_comp->llc_ostlist.op_array);

	rc = lod_qos_ost_in_use_clear(env, lod_comp->llc_stripenr);
	if (rc < 0)
		RETURN(rc);

	for (i = 0; i < lod_comp->llc_stripenr; i++) {
		if (lod_comp->llc_ostlist.op_array[i] ==
		    lod_comp->llc_stripe_offset) {
			array_idx = i;
			break;
		}
	}
	if (i == lod_comp->llc_stripenr) {
		CDEBUG(D_OTHER,
		       "%s: start index %d not in the specified list of OSTs\n",
		       lod2obd(m)->obd_name, lod_comp->llc_stripe_offset);
		RETURN(-EINVAL);
	}

	for (i = 0; i < lod_comp->llc_stripenr;
	     i++, array_idx = (array_idx + 1) % lod_comp->llc_stripenr) {
		__u32 ost_idx = lod_comp->llc_ostlist.op_array[array_idx];

		if (!cfs_bitmap_check(m->lod_ost_bitmap, ost_idx)) {
			rc = -ENODEV;
			break;
		}

		/*
		 * do not put >1 objects on a single OST
		 */
		if (lod_qos_is_ost_used(env, ost_idx, stripe_count)) {
			rc = -EINVAL;
			break;
		}

		rc = lod_statfs_and_check(env, m, ost_idx, sfs);
		if (rc < 0) /* this OSP doesn't feel well */
			break;

		o = lod_qos_declare_object_on(env, m, ost_idx, th);
		if (IS_ERR(o)) {
			rc = PTR_ERR(o);
			CDEBUG(D_OTHER,
			       "%s: can't declare new object on #%u: %d\n",
			       lod2obd(m)->obd_name, ost_idx, rc);
			break;
		}

		/*
		 * We've successfully declared (reserved) an object
		 */
		lod_qos_ost_in_use(env, stripe_count, ost_idx);
		lod_comp_ost_in_use(inuse, ost_idx);
		stripe[stripe_count] = o;
		stripe_count++;
	}

	RETURN(rc);
}

/**
 * Allocate a striping on a predefined set of OSTs.
 *
 * Allocates new layout starting from OST index in lo->ldo_stripe_offset.
 * Full OSTs are not considered. The exact order of OSTs is not important and
 * varies depending on OST status. The allocation procedure prefers the targets
 * with precreated objects ready. The number of stripes needed and stripe
 * offset are taken from the object. If that number cannot be met, then the
 * function returns an error and then it's the caller's responsibility to
 * release the stripes allocated. All the internal structures are protected,
 * but no concurrent allocation is allowed on the same objects.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] lo	LOD object
 * \param[out] stripe	striping created
 * \param[in] flags	not used
 * \param[in] th	transaction handle
 * \param[in] comp_idx	index of ldo_comp_entries
 * \param[in|out]inuse	array of inuse ost index
 *
 * \retval 0		on success
 * \retval -ENOSPC	if no OST objects are available at all
 * \retval -EFBIG	if not enough OST objects are found
 * \retval -EINVAL	requested offset is invalid
 * \retval negative	errno on failure
 */
static int lod_alloc_specific(const struct lu_env *env, struct lod_object *lo,
			      struct dt_object **stripe, int flags,
			      struct thandle *th, int comp_idx,
			      struct ost_pool *inuse)
{
	struct lod_layout_component *lod_comp;
	struct lod_device *m = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct obd_statfs *sfs = &lod_env_info(env)->lti_osfs;
	struct dt_object  *o;
	__u32		   ost_idx;
	unsigned int	   i, array_idx, ost_count;
	int		   rc, stripe_num = 0;
	int		   speed = 0;
	struct pool_desc  *pool = NULL;
	struct ost_pool   *osts;
	ENTRY;

	LASSERT(lo->ldo_comp_cnt > comp_idx && lo->ldo_comp_entries != NULL);
	lod_comp = &lo->ldo_comp_entries[comp_idx];

	rc = lod_qos_ost_in_use_clear(env, lod_comp->llc_stripenr);
	if (rc)
		GOTO(out, rc);

	if (lod_comp->llc_pool != NULL)
		pool = lod_find_pool(m, lod_comp->llc_pool);

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
		if (osts->op_array[i] == lod_comp->llc_stripe_offset) {
			array_idx = i;
			break;
		}
	}
	if (i == ost_count) {
		CERROR("Start index %d not found in pool '%s'\n",
		       lod_comp->llc_stripe_offset,
		       lod_comp->llc_pool ? lod_comp->llc_pool : "");
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

		/*
		 * try not allocate on the OST used by other component
		 */
		if (speed == 0 && i != 0 &&
		    lod_comp_is_ost_used(inuse, ost_idx))
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
		 * We've successfully declared (reserved) an object
		 */
		lod_qos_ost_in_use(env, stripe_num, ost_idx);
		lod_comp_ost_in_use(inuse, ost_idx);
		stripe[stripe_num] = o;
		stripe_num++;

		/* We have enough stripes */
		if (stripe_num == lod_comp->llc_stripenr)
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
	 */
	CERROR("can't lstripe objid "DFID": have %d want %u\n",
	       PFID(lu_object_fid(lod2lu_obj(lo))), stripe_num,
	       lod_comp->llc_stripenr);
	rc = stripe_num == 0 ? -ENOSPC : -EFBIG;
out:
	if (pool != NULL) {
		up_read(&pool_tgt_rw_sem(pool));
		/* put back ref got by lod_find_pool() */
		lod_pool_putref(pool);
	}

	RETURN(rc);
}

/**
 * Check whether QoS allocation should be used.
 *
 * A simple helper to decide when QoS allocation should be used:
 * if it's just a single available target or the used space is
 * evenly distributed among the targets at the moment, then QoS
 * allocation algorithm should not be used.
 *
 * \param[in] lod	LOD device
 *
 * \retval 0		should not be used
 * \retval 1		should be used
 */
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

/**
 * Allocate a striping using an algorithm with weights.
 *
 * The function allocates OST objects to create a striping. The algorithm
 * used is based on weights (currently only using the free space), and it's
 * trying to ensure the space is used evenly by OSTs and OSSs. The striping
 * configuration (# of stripes, offset, pool) is taken from the object and
 * is prepared by the caller.
 *
 * If LOV_USES_DEFAULT_STRIPE is not passed and prepared configuration can't
 * be met due to too few OSTs, then allocation fails. If the flag is passed
 * fewer than 3/4 of the requested number of stripes can be allocated, then
 * allocation fails.
 *
 * No concurrent allocation is allowed on the object and this must be ensured
 * by the caller. All the internal structures are protected by the function.
 *
 * The algorithm has two steps: find available OSTs and calculate their
 * weights, then select the OSTs with their weights used as the probability.
 * An OST with a higher weight is proportionately more likely to be selected
 * than one with a lower weight.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] lo	LOD object
 * \param[out] stripe	striping created
 * \param[in] flags	0 or LOV_USES_DEFAULT_STRIPE
 * \param[in] th	transaction handle
 * \param[in] comp_idx	index of ldo_comp_entries
 * \param[in|out]inuse	array of inuse ost index
 *
 * \retval 0		on success
 * \retval -EAGAIN	not enough OSTs are found for specified stripe count
 * \retval -EINVAL	requested OST index is invalid
 * \retval negative	errno on failure
 */
static int lod_alloc_qos(const struct lu_env *env, struct lod_object *lo,
			 struct dt_object **stripe, int flags,
			 struct thandle *th, int comp_idx,
			 struct ost_pool *inuse)
{
	struct lod_layout_component *lod_comp;
	struct lod_device *lod = lu2lod_dev(lo->ldo_obj.do_lu.lo_dev);
	struct obd_statfs *sfs = &lod_env_info(env)->lti_osfs;
	struct lod_tgt_desc *ost;
	struct dt_object *o;
	__u64 total_weight = 0;
	struct pool_desc *pool = NULL;
	struct ost_pool *osts;
	unsigned int i;
	__u32	nfound, good_osts, stripe_cnt, stripe_cnt_min;
	int rc = 0;
	ENTRY;

	LASSERT(lo->ldo_comp_cnt > comp_idx && lo->ldo_comp_entries != NULL);
	lod_comp = &lo->ldo_comp_entries[comp_idx];
	stripe_cnt = lod_comp->llc_stripenr;
	stripe_cnt_min = min_stripe_count(stripe_cnt, flags);
	if (stripe_cnt_min < 1)
		RETURN(-EINVAL);

	if (lod_comp->llc_pool != NULL)
		pool = lod_find_pool(lod, lod_comp->llc_pool);

	if (pool != NULL) {
		down_read(&pool_tgt_rw_sem(pool));
		osts = &(pool->pool_obds);
	} else {
		osts = &(lod->lod_pool_info);
	}

	/* Detect -EAGAIN early, before expensive lock is taken. */
	if (!lod_qos_is_usable(lod))
		GOTO(out_nolock, rc = -EAGAIN);

	/* Do actual allocation, use write lock here. */
	down_write(&lod->lod_qos.lq_rw_sem);

	/*
	 * Check again, while we were sleeping on @lq_rw_sem things could
	 * change.
	 */
	if (!lod_qos_is_usable(lod))
		GOTO(out, rc = -EAGAIN);

	rc = lod_qos_calc_ppo(lod);
	if (rc)
		GOTO(out, rc);

	rc = lod_qos_ost_in_use_clear(env, lod_comp->llc_stripenr);
	if (rc)
		GOTO(out, rc);

	good_osts = 0;
	/* Find all the OSTs that are valid stripe candidates */
	for (i = 0; i < osts->op_count; i++) {
		if (!cfs_bitmap_check(lod->lod_ost_bitmap, osts->op_array[i]))
			continue;

		ost = OST_TGT(lod, osts->op_array[i]);
		ost->ltd_qos.ltq_usable = 0;

		rc = lod_statfs_and_check(env, lod, osts->op_array[i], sfs);
		if (rc) {
			/* this OSP doesn't feel well */
			continue;
		}

		if (sfs->os_state & OS_STATE_DEGRADED)
			continue;

		/* Fail Check before osc_precreate() is called
		   so we can only 'fail' single OSC. */
		if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OSC_PRECREATE) &&
				   osts->op_array[i] == 0)
			continue;

		ost->ltd_qos.ltq_usable = 1;
		lod_qos_calc_weight(lod, osts->op_array[i]);
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

		/* On average, this will hit larger-weighted OSTs more often.
		 * 0-weight OSTs will always get used last (only when rand=0) */
		for (i = 0; i < osts->op_count; i++) {
			__u32 idx = osts->op_array[i];

			if (!cfs_bitmap_check(lod->lod_ost_bitmap, idx))
				continue;

			ost = OST_TGT(lod, idx);

			if (!ost->ltd_qos.ltq_usable)
				continue;

			cur_weight += ost->ltd_qos.ltq_weight;
			QOS_DEBUG("stripe_cnt=%d nfound=%d cur_weight=%llu"
				  " rand=%llu total_weight=%llu\n",
				  stripe_cnt, nfound, cur_weight, rand,
				  total_weight);

			if (cur_weight < rand)
				continue;

			QOS_DEBUG("stripe=%d to idx=%d\n", nfound, idx);
			/*
			 * do not put >1 objects on a single OST
			 */
			if (lod_qos_is_ost_used(env, idx, nfound) ||
			    lod_comp_is_ost_used(inuse, idx))
				continue;

			o = lod_qos_declare_object_on(env, lod, idx, th);
			if (IS_ERR(o)) {
				QOS_DEBUG("can't declare object on #%u: %d\n",
					  idx, (int) PTR_ERR(o));
				continue;
			}

			lod_qos_ost_in_use(env, nfound, idx);
			lod_comp_ost_in_use(inuse, idx);
			stripe[nfound++] = o;
			lod_qos_used(lod, osts, idx, &total_weight);
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
		QOS_DEBUG("%s: wanted %d objects, found only %d\n",
			  lod2obd(lod)->obd_name, stripe_cnt, nfound);
		for (i = 0; i < nfound; i++) {
			LASSERT(stripe[i] != NULL);
			dt_object_put(env, stripe[i]);
			stripe[i] = NULL;
		}
		LASSERTF(nfound <= inuse->op_count,
			 "nfound:%d, op_count:%u\n", nfound, inuse->op_count);
		inuse->op_count -= nfound;

		/* makes sense to rebalance next time */
		lod->lod_qos.lq_dirty = 1;
		lod->lod_qos.lq_same_space = 0;

		rc = -EAGAIN;
	}

out:
	up_write(&lod->lod_qos.lq_rw_sem);

out_nolock:
	if (pool != NULL) {
		up_read(&pool_tgt_rw_sem(pool));
		/* put back ref got by lod_find_pool() */
		lod_pool_putref(pool);
	}

	RETURN(rc);
}

/**
 * Find largest stripe count the caller can use.
 *
 * Find the maximal possible stripe count not greater than \a stripe_count.
 * Sometimes suggested stripecount can't be reached for a number of reasons:
 * lack of enough active OSTs or the backend does not support EAs that large.
 * If the passed one is 0, then the filesystem's default one is used.
 *
 * \param[in] lod	LOD device
 * \param[in] lo	The lod_object
 * \param[in] stripe_count	count the caller would like to use
 *
 * \retval		the maximum usable stripe count
 */
__u16 lod_get_stripecnt(struct lod_device *lod, struct lod_object *lo,
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
	if (lod->lod_osd_max_easize > 0) {
		unsigned int easize = lod->lod_osd_max_easize;
		int i;

		if (lo->ldo_is_composite) {
			struct lod_layout_component *lod_comp;
			unsigned int header_sz = sizeof(struct lov_comp_md_v1);

			header_sz += sizeof(struct lov_comp_md_entry_v1) *
					lo->ldo_comp_cnt;
			for (i = 0; i < lo->ldo_comp_cnt; i++) {
				lod_comp = &lo->ldo_comp_entries[i];
				if (lod_comp->llc_flags & LCME_FL_INIT)
					header_sz += lov_mds_md_size(
					lod_comp->llc_stripenr, LOV_MAGIC_V3);
			}
			if (easize > header_sz)
				easize -= header_sz;
			else
				easize = 0;
		}

		max_stripes = lov_mds_md_max_stripe_count(easize, LOV_MAGIC_V3);
	}

	return (stripe_count < max_stripes) ? stripe_count : max_stripes;
}

/**
 * Create in-core respresentation for a fully-defined striping
 *
 * When the caller passes a fully-defined striping (i.e. everything including
 * OST object FIDs are defined), then we still need to instantiate LU-cache
 * with the objects representing the stripes defined. This function completes
 * that task.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] mo	LOD object
 * \param[in] buf	buffer containing the striping
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
int lod_use_defined_striping(const struct lu_env *env,
			     struct lod_object *mo,
			     const struct lu_buf *buf)
{
	struct lod_layout_component *lod_comp;
	struct lov_mds_md_v1   *v1 = buf->lb_buf;
	struct lov_mds_md_v3   *v3 = buf->lb_buf;
	struct lov_comp_md_v1  *comp_v1 = NULL;
	struct lov_ost_data_v1 *objs;
	__u32	magic;
	__u16	comp_cnt;
	int	rc = 0, i;
	ENTRY;

	magic = le32_to_cpu(v1->lmm_magic) & ~LOV_MAGIC_DEF;

	if (magic != LOV_MAGIC_V1 && magic != LOV_MAGIC_V3 &&
	    magic != LOV_MAGIC_COMP_V1)
		RETURN(-EINVAL);

	if (magic == LOV_MAGIC_COMP_V1) {
		comp_v1 = buf->lb_buf;
		comp_cnt = le16_to_cpu(comp_v1->lcm_entry_count);
		if (comp_cnt == 0)
			RETURN(-EINVAL);
		mo->ldo_is_composite = 1;
	} else {
		mo->ldo_is_composite = 0;
		comp_cnt = 1;
	}

	rc = lod_alloc_comp_entries(mo, comp_cnt);
	if (rc)
		RETURN(rc);

	for (i = 0; i < comp_cnt; i++) {
		struct lu_extent *ext;
		char	*pool_name;
		__u32	offs;

		lod_comp = &mo->ldo_comp_entries[i];

		if (mo->ldo_is_composite) {
			offs = le32_to_cpu(comp_v1->lcm_entries[i].lcme_offset);
			v1 = (struct lov_mds_md_v1 *)((char *)comp_v1 + offs);
			magic = le32_to_cpu(v1->lmm_magic);

			ext = &comp_v1->lcm_entries[i].lcme_extent;
			lod_comp->llc_extent.e_start =
				le64_to_cpu(ext->e_start);
			lod_comp->llc_extent.e_end = le64_to_cpu(ext->e_end);
			lod_comp->llc_flags =
				le32_to_cpu(comp_v1->lcm_entries[i].lcme_flags);
			lod_comp->llc_id =
				le32_to_cpu(comp_v1->lcm_entries[i].lcme_id);
			if (lod_comp->llc_id == LCME_ID_INVAL)
				GOTO(out, rc = -EINVAL);
		}

		pool_name = NULL;
		if (magic == LOV_MAGIC_V1) {
			objs = &v1->lmm_objects[0];
		} else if (magic == LOV_MAGIC_V3) {
			objs = &v3->lmm_objects[0];
			if (v3->lmm_pool_name[0] != '\0')
				pool_name = v3->lmm_pool_name;
		} else {
			CDEBUG(D_LAYOUT, "Invalid magic %x\n", magic);
			GOTO(out, rc = -EINVAL);
		}

		lod_comp->llc_pattern = le32_to_cpu(v1->lmm_pattern);
		lod_comp->llc_stripe_size = le32_to_cpu(v1->lmm_stripe_size);
		lod_comp->llc_stripenr = le16_to_cpu(v1->lmm_stripe_count);
		lod_comp->llc_layout_gen = le16_to_cpu(v1->lmm_layout_gen);
		/**
		 * The stripe_offset of an uninit-ed component is stored in
		 * the lmm_layout_gen
		 */
		if (mo->ldo_is_composite && !lod_comp_inited(lod_comp))
			lod_comp->llc_stripe_offset = lod_comp->llc_layout_gen;
		lod_obj_set_pool(mo, i, pool_name);

		if ((!mo->ldo_is_composite || lod_comp_inited(lod_comp)) &&
		    !(lod_comp->llc_pattern & LOV_PATTERN_F_RELEASED)) {
			rc = lod_initialize_objects(env, mo, objs, i);
			if (rc)
				GOTO(out, rc);
		}
	}
out:
	if (rc)
		lod_object_free_striping(env, mo);

	RETURN(rc);
}

/**
 * Parse suggested striping configuration.
 *
 * The caller gets a suggested striping configuration from a number of sources
 * including per-directory default and applications. Then it needs to verify
 * the suggested striping is valid, apply missing bits and store the resulting
 * configuration in the object to be used by the allocator later. Must not be
 * called concurrently against the same object. It's OK to provide a
 * fully-defined striping.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] lo	LOD object
 * \param[in] buf	buffer containing the striping
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
int lod_qos_parse_config(const struct lu_env *env, struct lod_object *lo,
			 const struct lu_buf *buf)
{
	struct lod_layout_component *lod_comp;
	struct lod_device	*d = lu2lod_dev(lod2lu_obj(lo)->lo_dev);
	struct lov_desc		*desc = &d->lod_desc;
	struct lov_user_md_v1	*v1 = NULL;
	struct lov_user_md_v3	*v3 = NULL;
	struct lov_comp_md_v1	*comp_v1 = NULL;
	__u32	magic;
	__u16	comp_cnt;
	int	i, rc;
	ENTRY;

	if (buf == NULL || buf->lb_buf == NULL || buf->lb_len == 0)
		RETURN(0);

	rc = lod_verify_striping(d, buf, false, 0);
	if (rc)
		RETURN(-EINVAL);

	lod_free_comp_entries(lo);

	v3 = buf->lb_buf;
	v1 = buf->lb_buf;
	comp_v1 = buf->lb_buf;
	magic = v1->lmm_magic;

	if (unlikely(le32_to_cpu(magic) & LOV_MAGIC_DEF)) {
		/* try to use as fully defined striping */
		rc = lod_use_defined_striping(env, lo, buf);
		RETURN(rc);
	}

	switch (magic) {
	case __swab32(LOV_USER_MAGIC_V1):
		lustre_swab_lov_user_md_v1(v1);
		magic = v1->lmm_magic;
		/* fall through */
	case LOV_USER_MAGIC_V1:
		break;
	case __swab32(LOV_USER_MAGIC_V3):
		lustre_swab_lov_user_md_v3(v3);
		magic = v3->lmm_magic;
		/* fall through */
	case LOV_USER_MAGIC_V3:
		break;
	case __swab32(LOV_USER_MAGIC_SPECIFIC):
		lustre_swab_lov_user_md_v3(v3);
		lustre_swab_lov_user_md_objects(v3->lmm_objects,
						v3->lmm_stripe_count);
		magic = v3->lmm_magic;
		/* fall through */
	case LOV_USER_MAGIC_SPECIFIC:
		break;
	case __swab32(LOV_USER_MAGIC_COMP_V1):
		lustre_swab_lov_comp_md_v1(comp_v1);
		magic = comp_v1->lcm_magic;
		/* fall trhough */
	case LOV_USER_MAGIC_COMP_V1:
		break;
	default:
		CERROR("%s: unrecognized magic %X\n",
		       lod2obd(d)->obd_name, magic);
		RETURN(-EINVAL);
	}

	lustre_print_user_md(D_OTHER, v1, "parse config");

	if (magic == LOV_USER_MAGIC_COMP_V1) {
		comp_cnt = comp_v1->lcm_entry_count;
		if (comp_cnt == 0)
			RETURN(-EINVAL);
		lo->ldo_is_composite = 1;
	} else {
		comp_cnt = 1;
		lo->ldo_is_composite = 0;
	}

	rc = lod_alloc_comp_entries(lo, comp_cnt);
	if (rc)
		RETURN(rc);

	for (i = 0; i < comp_cnt; i++) {
		struct pool_desc	*pool;
		struct lu_extent	*ext;
		char	*pool_name;

		lod_comp = &lo->ldo_comp_entries[i];

		if (lo->ldo_is_composite) {
			v1 = (struct lov_user_md *)((char *)comp_v1 +
					comp_v1->lcm_entries[i].lcme_offset);
			ext = &comp_v1->lcm_entries[i].lcme_extent;
			lod_comp->llc_extent = *ext;
		}

		pool_name = NULL;
		if (v1->lmm_magic == LOV_USER_MAGIC_V3 ||
		    v1->lmm_magic == LOV_USER_MAGIC_SPECIFIC) {
			int j;

			v3 = (struct lov_user_md_v3 *)v1;
			if (v3->lmm_pool_name[0] != '\0')
				pool_name = v3->lmm_pool_name;

			if (v3->lmm_magic == LOV_USER_MAGIC_SPECIFIC) {
				if (v3->lmm_stripe_offset == LOV_OFFSET_DEFAULT)
					v3->lmm_stripe_offset =
						v3->lmm_objects[0].l_ost_idx;

				/* copy ost list from lmm */
				lod_comp->llc_ostlist.op_count =
					v3->lmm_stripe_count;
				lod_comp->llc_ostlist.op_size =
					v3->lmm_stripe_count * sizeof(__u32);
				OBD_ALLOC(lod_comp->llc_ostlist.op_array,
					  lod_comp->llc_ostlist.op_size);
				if (!lod_comp->llc_ostlist.op_array)
					GOTO(free_comp, rc = -ENOMEM);

				for (j = 0; j < v3->lmm_stripe_count; j++)
					lod_comp->llc_ostlist.op_array[j] =
						v3->lmm_objects[j].l_ost_idx;
			}
		}

		if (v1->lmm_pattern == 0)
			v1->lmm_pattern = LOV_PATTERN_RAID0;
		if (lov_pattern(v1->lmm_pattern) != LOV_PATTERN_RAID0) {
			CDEBUG(D_LAYOUT, "%s: invalid pattern: %x\n",
			       lod2obd(d)->obd_name, v1->lmm_pattern);
			GOTO(free_comp, rc = -EINVAL);
		}

		lod_comp->llc_pattern = v1->lmm_pattern;

		lod_comp->llc_stripe_size = desc->ld_default_stripe_size;
		if (v1->lmm_stripe_size)
			lod_comp->llc_stripe_size = v1->lmm_stripe_size;

		lod_comp->llc_stripenr = desc->ld_default_stripe_count;
		if (v1->lmm_stripe_count)
			lod_comp->llc_stripenr = v1->lmm_stripe_count;

		lod_comp->llc_stripe_offset = v1->lmm_stripe_offset;
		lod_obj_set_pool(lo, i, pool_name);

		if (pool_name == NULL)
			continue;

		/* In the function below, .hs_keycmp resolves to
		 * pool_hashkey_keycmp() */
		/* coverity[overrun-buffer-val] */
		pool = lod_find_pool(d, pool_name);
		if (pool == NULL)
			continue;

		if (lod_comp->llc_stripe_offset != LOV_OFFSET_DEFAULT) {
			rc = lod_check_index_in_pool(
					lod_comp->llc_stripe_offset, pool);
			if (rc < 0) {
				lod_pool_putref(pool);
				CDEBUG(D_LAYOUT, "%s: invalid offset, %u\n",
				       lod2obd(d)->obd_name,
				       lod_comp->llc_stripe_offset);
				GOTO(free_comp, rc = -EINVAL);
			}
		}

		if (lod_comp->llc_stripenr > pool_tgt_count(pool))
			lod_comp->llc_stripenr = pool_tgt_count(pool);

		lod_pool_putref(pool);
	}

	RETURN(0);

free_comp:
	lod_free_comp_entries(lo);
	RETURN(rc);
}

/**
 * Create a striping for an obejct.
 *
 * The function creates a new striping for the object. The function tries QoS
 * algorithm first unless free space is distributed evenly among OSTs, but
 * by default RR algorithm is preferred due to internal concurrency (QoS is
 * serialized). The caller must ensure no concurrent calls to the function
 * are made against the same object.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] lo	LOD object
 * \param[in] attr	attributes OST objects will be declared with
 * \param[in] th	transaction handle
 * \param[in] comp_idx	index of ldo_comp_entries
 * \param[in|out] inuse	array of inuse ost index
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
int lod_qos_prep_create(const struct lu_env *env, struct lod_object *lo,
			struct lu_attr *attr, struct thandle *th,
			int comp_idx, struct ost_pool *inuse)
{
	struct lod_layout_component *lod_comp;
	struct lod_device      *d = lu2lod_dev(lod2lu_obj(lo)->lo_dev);
	struct dt_object      **stripe;
	int			stripe_len;
	int			flag = LOV_USES_ASSIGNED_STRIPE;
	int			i, rc = 0;
	ENTRY;

	LASSERT(lo);
	LASSERT(lo->ldo_comp_cnt > comp_idx && lo->ldo_comp_entries != NULL);
	lod_comp = &lo->ldo_comp_entries[comp_idx];

	/* A released component is being created */
	if (lod_comp->llc_pattern & LOV_PATTERN_F_RELEASED)
		RETURN(0);

	if (likely(lod_comp->llc_stripe == NULL)) {
		/*
		 * no striping has been created so far
		 */
		LASSERT(lod_comp->llc_stripenr);
		/*
		 * statfs and check OST targets now, since ld_active_tgt_count
		 * could be changed if some OSTs are [de]activated manually.
		 */
		lod_qos_statfs_update(env, d);
		stripe_len = lod_get_stripecnt(d, lo, lod_comp->llc_stripenr);
		if (stripe_len == 0)
			GOTO(out, rc = -ERANGE);
		lod_comp->llc_stripenr = stripe_len;
		OBD_ALLOC(stripe, sizeof(stripe[0]) * stripe_len);
		if (stripe == NULL)
			GOTO(out, rc = -ENOMEM);

		lod_getref(&d->lod_ost_descs);
		/* XXX: support for non-0 files w/o objects */
		CDEBUG(D_OTHER, "tgt_count %d stripenr %d\n",
				d->lod_desc.ld_tgt_count, stripe_len);

		if (lod_comp->llc_ostlist.op_array) {
			rc = lod_alloc_ost_list(env, lo, stripe, th, comp_idx,
						inuse);
		} else if (lod_comp->llc_stripe_offset == LOV_OFFSET_DEFAULT) {
			rc = lod_alloc_qos(env, lo, stripe, flag, th,
					   comp_idx, inuse);
			if (rc == -EAGAIN)
				rc = lod_alloc_rr(env, lo, stripe, flag, th,
						  comp_idx, inuse);
		} else {
			rc = lod_alloc_specific(env, lo, stripe, flag, th,
						comp_idx, inuse);
		}
		lod_putref(d, &d->lod_ost_descs);

		if (rc < 0) {
			for (i = 0; i < stripe_len; i++)
				if (stripe[i] != NULL)
					dt_object_put(env, stripe[i]);

			OBD_FREE(stripe, sizeof(stripe[0]) * stripe_len);
			lod_comp->llc_stripenr = 0;
		} else {
			lod_comp->llc_stripe = stripe;
			lod_comp->llc_stripes_allocated = stripe_len;
		}
	} else {
		/*
		 * lod_qos_parse_config() found supplied buf as a predefined
		 * striping (not a hint), so it allocated all the object
		 * now we need to create them
		 */
		for (i = 0; i < lod_comp->llc_stripenr; i++) {
			struct dt_object  *o;

			o = lod_comp->llc_stripe[i];
			LASSERT(o);

			rc = lod_sub_declare_create(env, o, attr, NULL,
						    NULL, th);
			if (rc < 0) {
				CERROR("can't declare create: %d\n", rc);
				break;
			}
		}
		/**
		 * Clear LCME_FL_INIT for the component so that
		 * lod_striping_create() can create the striping objects
		 * in replay.
		 */
		lod_comp_unset_init(lod_comp);
	}

out:
	RETURN(rc);
}

int lod_obj_stripe_set_inuse_cb(const struct lu_env *env,
				struct lod_object *lo,
				struct dt_object *dt, struct thandle *th,
				int stripe_idx,
				struct lod_obj_stripe_cb_data *data)
{
	struct lod_thread_info	*info = lod_env_info(env);
	struct lod_device	*d = lu2lod_dev(lod2lu_obj(lo)->lo_dev);
	struct lu_fid	*fid = &info->lti_fid;
	__u32	index;
	int	rc, type = LU_SEQ_RANGE_OST;

	*fid = *lu_object_fid(&dt->do_lu);
	rc = lod_fld_lookup(env, d, fid, &index, &type);
	if (rc < 0) {
		CERROR("%s: fail to locate "DFID": rc = %d\n",
		       lod2obd(d)->obd_name, PFID(fid), rc);
		return rc;
	}
	lod_comp_ost_in_use(data->locd_inuse, index);
	return 0;
}

/**
 * Resize per-thread ost list to hold OST target index list already used.
 *
 * \param[in,out] inuse		structure contains ost list array
 * \param[in] cnt		total stripe count of all components
 * \param[in] max		array's max size if @max > 0
 *
 * \retval 0		on success
 * \retval -ENOMEM	reallocation failed
 */
static int lod_inuse_resize(struct ost_pool *inuse, __u16 cnt, __u16 max)
{
	__u32 *array;
	__u32 new = cnt * sizeof(inuse->op_array[0]);

	inuse->op_count = 0;

	if (new <= inuse->op_size)
		return 0;

	if (max)
		new = min_t(__u32, new, max);

	OBD_ALLOC(array, new);
	if (!array)
		return -ENOMEM;

	if (inuse->op_array)
		OBD_FREE(inuse->op_array, inuse->op_size);

	inuse->op_array = array;
	inuse->op_size = new;

	return 0;
}

int lod_prepare_inuse(const struct lu_env *env, struct lod_object *lo)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_device *d = lu2lod_dev(lod2lu_obj(lo)->lo_dev);
	struct ost_pool *inuse = &info->lti_inuse_osts;
	struct lod_obj_stripe_cb_data data;
	__u32 stripe_cnt = 0;
	int i;
	int rc;

	for (i = 0; i < lo->ldo_comp_cnt; i++)
		stripe_cnt += lod_comp_entry_stripecnt(lo,
					&lo->ldo_comp_entries[i], false);
	rc = lod_inuse_resize(inuse, stripe_cnt, d->lod_osd_max_easize);
	if (rc)
		return rc;

	data.locd_inuse = inuse;
	return lod_obj_for_each_stripe(env, lo, NULL,
				       lod_obj_stripe_set_inuse_cb, &data);
}

int lod_prepare_create(const struct lu_env *env, struct lod_object *lo,
		       struct lu_attr *attr, const struct lu_buf *buf,
		       struct thandle *th)

{
	struct lod_thread_info *info = lod_env_info(env);
	struct lod_device *d = lu2lod_dev(lod2lu_obj(lo)->lo_dev);
	struct ost_pool inuse_osts = { 0 };
	struct ost_pool *inuse = &inuse_osts;
	uint64_t size = 0;
	int i;
	int rc;
	ENTRY;

	LASSERT(lo);

	/* no OST available */
	/* XXX: should we be waiting a bit to prevent failures during
	 * cluster initialization? */
	if (d->lod_ostnr == 0)
		RETURN(-EIO);

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
		RETURN(rc);

	if (attr->la_valid & LA_SIZE)
		size = attr->la_size;

	/* only prepare inuse if multiple components to be created */
	if (size && lo->ldo_is_composite) {
		rc = lod_prepare_inuse(env, lo);
		if (rc)
			RETURN(rc);
		inuse = &info->lti_inuse_osts;
	}

	/**
	 * prepare OST object creation for the component covering file's
	 * size, the 1st component (including plain layout file) is always
	 * instantiated.
	 */
	for (i = 0; i < lo->ldo_comp_cnt; i++) {
		struct lod_layout_component *lod_comp;
		struct lu_extent *extent;

		lod_comp = &lo->ldo_comp_entries[i];
		extent = &lod_comp->llc_extent;
		CDEBUG(D_QOS, "%lld [%lld, %lld)\n",
		       size, extent->e_start, extent->e_end);
		if (!lo->ldo_is_composite || size >= extent->e_start) {
			rc = lod_qos_prep_create(env, lo, attr, th, i, inuse);
			if (rc)
				break;
		}
	}

	RETURN(rc);
}
