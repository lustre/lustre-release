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
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/lmv/lmv_qos.c
 *
 * LMV QoS.
 * These are the only exported functions, they provide some generic
 * infrastructure for object allocation QoS
 *
 */

#define DEBUG_SUBSYSTEM S_LMV

#include <asm/div64.h>
#include <linux/random.h>

#include <libcfs/libcfs.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_swab.h>
#include <obd_class.h>

#include "lmv_internal.h"

static inline __u64 tgt_statfs_bavail(struct lu_tgt_desc *tgt)
{
	struct obd_statfs *statfs = &tgt->ltd_statfs;

	return statfs->os_bavail * statfs->os_bsize;
}

static inline __u64 tgt_statfs_iavail(struct lu_tgt_desc *tgt)
{
	return tgt->ltd_statfs.os_ffree;
}

/**
 * Calculate penalties per-tgt and per-server
 *
 * Re-calculate penalties when the configuration changes, active targets
 * change and after statfs refresh (all these are reflected by lq_dirty flag).
 * On every MDT and MDS: decay the penalty by half for every 8x the update
 * interval that the device has been idle. That gives lots of time for the
 * statfs information to be updated (which the penalty is only a proxy for),
 * and avoids penalizing MDS/MDTs under light load.
 * See lmv_qos_calc_weight() for how penalties are factored into the weight.
 *
 * \param[in] lmv	LMV device
 *
 * \retval 0		on success
 * \retval -EAGAIN	the number of MDTs isn't enough or all MDT spaces are
 *			almost the same
 */
static int lmv_qos_calc_ppts(struct lmv_obd *lmv)
{
	struct lu_qos *qos = &lmv->lmv_qos;
	struct lu_tgt_desc *tgt;
	struct lu_svr_qos *svr;
	__u64 ba_max, ba_min, ba;
	__u64 ia_max, ia_min, ia;
	__u32 num_active;
	unsigned int i;
	int prio_wide;
	time64_t now, age;
	__u32 maxage = lmv->desc.ld_qos_maxage;
	int rc;

	ENTRY;

	if (!qos->lq_dirty)
		GOTO(out, rc = 0);

	num_active = lmv->desc.ld_active_tgt_count;
	if (num_active < 2)
		GOTO(out, rc = -EAGAIN);

	/* find bavail on each server */
	list_for_each_entry(svr, &qos->lq_svr_list, lsq_svr_list) {
		svr->lsq_bavail = 0;
		svr->lsq_iavail = 0;
	}
	qos->lq_active_svr_count = 0;

	/*
	 * How badly user wants to select targets "widely" (not recently chosen
	 * and not on recent MDS's).  As opposed to "freely" (free space avail.)
	 * 0-256
	 */
	prio_wide = 256 - qos->lq_prio_free;

	ba_min = (__u64)(-1);
	ba_max = 0;
	ia_min = (__u64)(-1);
	ia_max = 0;
	now = ktime_get_real_seconds();

	/* Calculate server penalty per object */
	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		tgt = lmv->tgts[i];
		if (!tgt || !tgt->ltd_exp || !tgt->ltd_active)
			continue;

		/* bavail >> 16 to avoid overflow */
		ba = tgt_statfs_bavail(tgt) >> 16;
		if (!ba)
			continue;

		ba_min = min(ba, ba_min);
		ba_max = max(ba, ba_max);

		/* iavail >> 8 to avoid overflow */
		ia = tgt_statfs_iavail(tgt) >> 8;
		if (!ia)
			continue;

		ia_min = min(ia, ia_min);
		ia_max = max(ia, ia_max);

		/* Count the number of usable MDS's */
		if (tgt->ltd_qos.ltq_svr->lsq_bavail == 0)
			qos->lq_active_svr_count++;
		tgt->ltd_qos.ltq_svr->lsq_bavail += ba;
		tgt->ltd_qos.ltq_svr->lsq_iavail += ia;

		/*
		 * per-MDT penalty is
		 * prio * bavail * iavail / (num_tgt - 1) / 2
		 */
		tgt->ltd_qos.ltq_penalty_per_obj = prio_wide * ba * ia;
		do_div(tgt->ltd_qos.ltq_penalty_per_obj, num_active - 1);
		tgt->ltd_qos.ltq_penalty_per_obj >>= 1;

		age = (now - tgt->ltd_qos.ltq_used) >> 3;
		if (qos->lq_reset || age > 32 * maxage)
			tgt->ltd_qos.ltq_penalty = 0;
		else if (age > maxage)
			/* Decay tgt penalty. */
			tgt->ltd_qos.ltq_penalty >>= (age / maxage);
	}

	num_active = qos->lq_active_svr_count;
	if (num_active < 2) {
		/*
		 * If there's only 1 MDS, we can't penalize it, so instead
		 * we have to double the MDT penalty
		 */
		num_active = 2;
		for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
			tgt = lmv->tgts[i];
			if (!tgt || !tgt->ltd_exp || !tgt->ltd_active)
				continue;

			tgt->ltd_qos.ltq_penalty_per_obj <<= 1;
		}
	}

	/*
	 * Per-MDS penalty is
	 * prio * bavail * iavail / server_tgts / (num_svr - 1) / 2
	 */
	list_for_each_entry(svr, &qos->lq_svr_list, lsq_svr_list) {
		ba = svr->lsq_bavail;
		ia = svr->lsq_iavail;
		svr->lsq_penalty_per_obj = prio_wide * ba  * ia;
		do_div(ba, svr->lsq_tgt_count * (num_active - 1));
		svr->lsq_penalty_per_obj >>= 1;

		age = (now - svr->lsq_used) >> 3;
		if (qos->lq_reset || age > 32 * maxage)
			svr->lsq_penalty = 0;
		else if (age > maxage)
			/* Decay server penalty. */
			svr->lsq_penalty >>= age / maxage;
	}

	qos->lq_dirty = 0;
	qos->lq_reset = 0;

	/*
	 * If each MDT has almost same free space, do rr allocation for better
	 * creation performance
	 */
	qos->lq_same_space = 0;
	if ((ba_max * (256 - qos->lq_threshold_rr)) >> 8 < ba_min &&
	    (ia_max * (256 - qos->lq_threshold_rr)) >> 8 < ia_min) {
		qos->lq_same_space = 1;
		/* Reset weights for the next time we enter qos mode */
		qos->lq_reset = 1;
	}
	rc = 0;

out:
	if (!rc && qos->lq_same_space)
		RETURN(-EAGAIN);

	RETURN(rc);
}

static inline bool lmv_qos_is_usable(struct lmv_obd *lmv)
{
	if (!lmv->lmv_qos.lq_dirty && lmv->lmv_qos.lq_same_space)
		return false;

	if (lmv->desc.ld_active_tgt_count < 2)
		return false;

	return true;
}

/**
 * Calculate weight for a given MDT.
 *
 * The final MDT weight is bavail >> 16 * iavail >> 8 minus the MDT and MDS
 * penalties.  See lmv_qos_calc_ppts() for how penalties are calculated.
 *
 * \param[in] tgt	MDT target descriptor
 */
static void lmv_qos_calc_weight(struct lu_tgt_desc *tgt)
{
	struct lu_tgt_qos *ltq = &tgt->ltd_qos;
	__u64 temp, temp2;

	temp = (tgt_statfs_bavail(tgt) >> 16) * (tgt_statfs_iavail(tgt) >> 8);
	temp2 = ltq->ltq_penalty + ltq->ltq_svr->lsq_penalty;
	if (temp < temp2)
		ltq->ltq_weight = 0;
	else
		ltq->ltq_weight = temp - temp2;
}

/**
 * Re-calculate weights.
 *
 * The function is called when some target was used for a new object. In
 * this case we should re-calculate all the weights to keep new allocations
 * balanced well.
 *
 * \param[in] lmv	LMV device
 * \param[in] tgt	target where a new object was placed
 * \param[out] total_wt	new total weight for the pool
 *
 * \retval		0
 */
static int lmv_qos_used(struct lmv_obd *lmv, struct lu_tgt_desc *tgt,
			__u64 *total_wt)
{
	struct lu_tgt_qos *ltq;
	struct lu_svr_qos *svr;
	unsigned int i;

	ENTRY;

	ltq = &tgt->ltd_qos;
	LASSERT(ltq);

	/* Don't allocate on this device anymore, until the next alloc_qos */
	ltq->ltq_usable = 0;

	svr = ltq->ltq_svr;

	/*
	 * Decay old penalty by half (we're adding max penalty, and don't
	 * want it to run away.)
	 */
	ltq->ltq_penalty >>= 1;
	svr->lsq_penalty >>= 1;

	/* mark the MDS and MDT as recently used */
	ltq->ltq_used = svr->lsq_used = ktime_get_real_seconds();

	/* Set max penalties for this MDT and MDS */
	ltq->ltq_penalty += ltq->ltq_penalty_per_obj *
			    lmv->desc.ld_active_tgt_count;
	svr->lsq_penalty += svr->lsq_penalty_per_obj *
		lmv->lmv_qos.lq_active_svr_count;

	/* Decrease all MDS penalties */
	list_for_each_entry(svr, &lmv->lmv_qos.lq_svr_list, lsq_svr_list) {
		if (svr->lsq_penalty < svr->lsq_penalty_per_obj)
			svr->lsq_penalty = 0;
		else
			svr->lsq_penalty -= svr->lsq_penalty_per_obj;
	}

	*total_wt = 0;
	/* Decrease all MDT penalties */
	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		ltq = &lmv->tgts[i]->ltd_qos;
		if (!tgt || !tgt->ltd_exp || !tgt->ltd_active)
			continue;

		if (ltq->ltq_penalty < ltq->ltq_penalty_per_obj)
			ltq->ltq_penalty = 0;
		else
			ltq->ltq_penalty -= ltq->ltq_penalty_per_obj;

		lmv_qos_calc_weight(lmv->tgts[i]);

		/* Recalc the total weight of usable osts */
		if (ltq->ltq_usable)
			*total_wt += ltq->ltq_weight;

		CDEBUG(D_OTHER, "recalc tgt %d usable=%d avail=%llu"
			  " tgtppo=%llu tgtp=%llu svrppo=%llu"
			  " svrp=%llu wt=%llu\n",
			  i, ltq->ltq_usable,
			  tgt_statfs_bavail(tgt) >> 10,
			  ltq->ltq_penalty_per_obj >> 10,
			  ltq->ltq_penalty >> 10,
			  ltq->ltq_svr->lsq_penalty_per_obj >> 10,
			  ltq->ltq_svr->lsq_penalty >> 10,
			  ltq->ltq_weight >> 10);
	}

	RETURN(0);
}

struct lu_tgt_desc *lmv_locate_tgt_qos(struct lmv_obd *lmv, __u32 *mdt)
{
	struct lu_tgt_desc *tgt;
	__u64 total_weight = 0;
	__u64 cur_weight = 0;
	__u64 rand;
	int i;
	int rc;

	ENTRY;

	if (!lmv_qos_is_usable(lmv))
		RETURN(ERR_PTR(-EAGAIN));

	down_write(&lmv->lmv_qos.lq_rw_sem);

	if (!lmv_qos_is_usable(lmv))
		GOTO(unlock, tgt = ERR_PTR(-EAGAIN));

	rc = lmv_qos_calc_ppts(lmv);
	if (rc)
		GOTO(unlock, tgt = ERR_PTR(rc));

	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		tgt = lmv->tgts[i];
		if (!tgt)
			continue;

		tgt->ltd_qos.ltq_usable = 0;
		if (!tgt->ltd_exp || !tgt->ltd_active)
			continue;

		tgt->ltd_qos.ltq_usable = 1;
		lmv_qos_calc_weight(tgt);
		total_weight += tgt->ltd_qos.ltq_weight;
	}

	rand = lu_prandom_u64_max(total_weight);

	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		tgt = lmv->tgts[i];

		if (!tgt || !tgt->ltd_qos.ltq_usable)
			continue;

		cur_weight += tgt->ltd_qos.ltq_weight;
		if (cur_weight < rand)
			continue;

		*mdt = tgt->ltd_index;
		lmv_qos_used(lmv, tgt, &total_weight);
		GOTO(unlock, rc = 0);
	}

	/* no proper target found */
	GOTO(unlock, tgt = ERR_PTR(-EAGAIN));
unlock:
	up_write(&lmv->lmv_qos.lq_rw_sem);

	return tgt;
}

struct lu_tgt_desc *lmv_locate_tgt_rr(struct lmv_obd *lmv, __u32 *mdt)
{
	struct lu_tgt_desc *tgt;
	int i;

	ENTRY;

	spin_lock(&lmv->lmv_qos.lq_rr.lqr_alloc);
	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		tgt = lmv->tgts[(i + lmv->lmv_qos_rr_index) %
				lmv->desc.ld_tgt_count];
		if (tgt && tgt->ltd_exp && tgt->ltd_active) {
			*mdt = tgt->ltd_index;
			lmv->lmv_qos_rr_index =
				(i + lmv->lmv_qos_rr_index + 1) %
				lmv->desc.ld_tgt_count;
			spin_unlock(&lmv->lmv_qos.lq_rr.lqr_alloc);

			RETURN(tgt);
		}
	}
	spin_unlock(&lmv->lmv_qos.lq_rr.lqr_alloc);

	RETURN(ERR_PTR(-ENODEV));
}
