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
 * lustre/obdclass/lu_qos.c
 *
 * Lustre QoS.
 * These are the only exported functions, they provide some generic
 * infrastructure for object allocation QoS
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/list.h>
#include <linux/random.h>
#include <libcfs/libcfs.h>
#include <libcfs/libcfs_hash.h> /* hash_long() */
#include <libcfs/linux/linux-mem.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_disk.h>
#include <lustre_fid.h>
#include <lu_object.h>

void lu_qos_rr_init(struct lu_qos_rr *lqr)
{
	spin_lock_init(&lqr->lqr_alloc);
	lqr->lqr_dirty = 1;
}
EXPORT_SYMBOL(lu_qos_rr_init);

/**
 * Add a new target to Quality of Service (QoS) target table.
 *
 * Add a new MDT/OST target to the structure representing an OSS. Resort the
 * list of known MDSs/OSSs by the number of MDTs/OSTs attached to each MDS/OSS.
 * The MDS/OSS list is protected internally and no external locking is required.
 *
 * \param[in] qos		lu_qos data
 * \param[in] ltd		target description
 *
 * \retval 0			on success
 * \retval -ENOMEM		on error
 */
int lqos_add_tgt(struct lu_qos *qos, struct lu_tgt_desc *ltd)
{
	struct lu_svr_qos *svr = NULL;
	struct lu_svr_qos *tempsvr;
	struct obd_export *exp = ltd->ltd_exp;
	int found = 0;
	__u32 id = 0;
	int rc = 0;

	ENTRY;

	down_write(&qos->lq_rw_sem);
	/*
	 * a bit hacky approach to learn NID of corresponding connection
	 * but there is no official API to access information like this
	 * with OSD API.
	 */
	list_for_each_entry(svr, &qos->lq_svr_list, lsq_svr_list) {
		if (obd_uuid_equals(&svr->lsq_uuid,
				    &exp->exp_connection->c_remote_uuid)) {
			found++;
			break;
		}
		if (svr->lsq_id > id)
			id = svr->lsq_id;
	}

	if (!found) {
		OBD_ALLOC_PTR(svr);
		if (!svr)
			GOTO(out, rc = -ENOMEM);
		memcpy(&svr->lsq_uuid, &exp->exp_connection->c_remote_uuid,
		       sizeof(svr->lsq_uuid));
		++id;
		svr->lsq_id = id;
	} else {
		/* Assume we have to move this one */
		list_del(&svr->lsq_svr_list);
	}

	svr->lsq_tgt_count++;
	ltd->ltd_qos.ltq_svr = svr;

	CDEBUG(D_OTHER, "add tgt %s to server %s (%d targets)\n",
	       obd_uuid2str(&ltd->ltd_uuid), obd_uuid2str(&svr->lsq_uuid),
	       svr->lsq_tgt_count);

	/*
	 * Add sorted by # of tgts.  Find the first entry that we're
	 * bigger than...
	 */
	list_for_each_entry(tempsvr, &qos->lq_svr_list, lsq_svr_list) {
		if (svr->lsq_tgt_count > tempsvr->lsq_tgt_count)
			break;
	}
	/*
	 * ...and add before it.  If we're the first or smallest, tempsvr
	 * points to the list head, and we add to the end.
	 */
	list_add_tail(&svr->lsq_svr_list, &tempsvr->lsq_svr_list);

	qos->lq_dirty = 1;
	qos->lq_rr.lqr_dirty = 1;

out:
	up_write(&qos->lq_rw_sem);
	RETURN(rc);
}
EXPORT_SYMBOL(lqos_add_tgt);

/**
 * Remove MDT/OST target from QoS table.
 *
 * Removes given MDT/OST target from QoS table and releases related
 * MDS/OSS structure if no target remain on the MDS/OSS.
 *
 * \param[in] qos		lu_qos data
 * \param[in] ltd		target description
 *
 * \retval 0			on success
 * \retval -ENOENT		if no server was found
 */
int lqos_del_tgt(struct lu_qos *qos, struct lu_tgt_desc *ltd)
{
	struct lu_svr_qos *svr;
	int rc = 0;

	ENTRY;

	down_write(&qos->lq_rw_sem);
	svr = ltd->ltd_qos.ltq_svr;
	if (!svr)
		GOTO(out, rc = -ENOENT);

	svr->lsq_tgt_count--;
	if (svr->lsq_tgt_count == 0) {
		CDEBUG(D_OTHER, "removing server %s\n",
		       obd_uuid2str(&svr->lsq_uuid));
		list_del(&svr->lsq_svr_list);
		ltd->ltd_qos.ltq_svr = NULL;
		OBD_FREE_PTR(svr);
	}

	qos->lq_dirty = 1;
	qos->lq_rr.lqr_dirty = 1;
out:
	up_write(&qos->lq_rw_sem);
	RETURN(rc);
}
EXPORT_SYMBOL(lqos_del_tgt);

/**
 * lu_prandom_u64_max - returns a pseudo-random u64 number in interval
 * [0, ep_ro)
 *
 * \param[in] ep_ro	right open interval endpoint
 *
 * \retval a pseudo-random 64-bit number that is in interval [0, ep_ro).
 */
u64 lu_prandom_u64_max(u64 ep_ro)
{
	u64 rand = 0;

	if (ep_ro) {
#if BITS_PER_LONG == 32
		/*
		 * If ep_ro > 32-bit, first generate the high
		 * 32 bits of the random number, then add in the low
		 * 32 bits (truncated to the upper limit, if needed)
		 */
		if (ep_ro > 0xffffffffULL)
			rand = prandom_u32_max((u32)(ep_ro >> 32)) << 32;

		if (rand == (ep_ro & 0xffffffff00000000ULL))
			rand |= prandom_u32_max((u32)ep_ro);
		else
			rand |= prandom_u32();
#else
		rand = ((u64)prandom_u32() << 32 | prandom_u32()) % ep_ro;
#endif
	}

	return rand;
}
EXPORT_SYMBOL(lu_prandom_u64_max);

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
 * On every tgt and server: decay the penalty by half for every 8x the update
 * interval that the device has been idle. That gives lots of time for the
 * statfs information to be updated (which the penalty is only a proxy for),
 * and avoids penalizing server/tgt under light load.
 * See lqos_calc_weight() for how penalties are factored into the weight.
 *
 * \param[in] qos		lu_qos
 * \param[in] ltd		lu_tgt_descs
 * \param[in] active_tgt_nr	active tgt number
 * \param[in] maxage		qos max age
 * \param[in] is_mdt		MDT will count inode usage
 *
 * \retval 0		on success
 * \retval -EAGAIN	the number of tgt isn't enough or all tgt spaces are
 *			almost the same
 */
int lqos_calc_penalties(struct lu_qos *qos, struct lu_tgt_descs *ltd,
			__u32 active_tgt_nr, __u32 maxage, bool is_mdt)
{
	struct lu_tgt_desc *tgt;
	struct lu_svr_qos *svr;
	__u64 ba_max, ba_min, ba;
	__u64 ia_max, ia_min, ia = 1;
	__u32 num_active;
	int prio_wide;
	time64_t now, age;
	int rc;

	ENTRY;

	if (!qos->lq_dirty)
		GOTO(out, rc = 0);

	num_active = active_tgt_nr - 1;
	if (num_active < 1)
		GOTO(out, rc = -EAGAIN);

	/* find bavail on each server */
	list_for_each_entry(svr, &qos->lq_svr_list, lsq_svr_list) {
		svr->lsq_bavail = 0;
		/* if inode is not counted, set to 1 to ignore */
		svr->lsq_iavail = is_mdt ? 0 : 1;
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
	ltd_foreach_tgt(ltd, tgt) {
		if (!tgt->ltd_active)
			continue;

		/* when inode is counted, bavail >> 16 to avoid overflow */
		ba = tgt_statfs_bavail(tgt);
		if (is_mdt)
			ba >>= 16;
		else
			ba >>= 8;
		if (!ba)
			continue;

		ba_min = min(ba, ba_min);
		ba_max = max(ba, ba_max);

		/* Count the number of usable servers */
		if (tgt->ltd_qos.ltq_svr->lsq_bavail == 0)
			qos->lq_active_svr_count++;
		tgt->ltd_qos.ltq_svr->lsq_bavail += ba;

		if (is_mdt) {
			/* iavail >> 8 to avoid overflow */
			ia = tgt_statfs_iavail(tgt) >> 8;
			if (!ia)
				continue;

			ia_min = min(ia, ia_min);
			ia_max = max(ia, ia_max);

			tgt->ltd_qos.ltq_svr->lsq_iavail += ia;
		}

		/*
		 * per-tgt penalty is
		 * prio * bavail * iavail / (num_tgt - 1) / 2
		 */
		tgt->ltd_qos.ltq_penalty_per_obj = prio_wide * ba * ia >> 8;
		do_div(tgt->ltd_qos.ltq_penalty_per_obj, num_active);
		tgt->ltd_qos.ltq_penalty_per_obj >>= 1;

		age = (now - tgt->ltd_qos.ltq_used) >> 3;
		if (qos->lq_reset || age > 32 * maxage)
			tgt->ltd_qos.ltq_penalty = 0;
		else if (age > maxage)
			/* Decay tgt penalty. */
			tgt->ltd_qos.ltq_penalty >>= (age / maxage);
	}

	num_active = qos->lq_active_svr_count - 1;
	if (num_active < 1) {
		/*
		 * If there's only 1 server, we can't penalize it, so instead
		 * we have to double the tgt penalty
		 */
		num_active = 1;
		ltd_foreach_tgt(ltd, tgt) {
			if (!tgt->ltd_active)
				continue;

			tgt->ltd_qos.ltq_penalty_per_obj <<= 1;
		}
	}

	/*
	 * Per-server penalty is
	 * prio * bavail * iavail / server_tgts / (num_svr - 1) / 2
	 */
	list_for_each_entry(svr, &qos->lq_svr_list, lsq_svr_list) {
		ba = svr->lsq_bavail;
		ia = svr->lsq_iavail;
		svr->lsq_penalty_per_obj = prio_wide * ba  * ia >> 8;
		do_div(ba, svr->lsq_tgt_count * num_active);
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
	 * If each tgt has almost same free space, do rr allocation for better
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
EXPORT_SYMBOL(lqos_calc_penalties);

bool lqos_is_usable(struct lu_qos *qos, __u32 active_tgt_nr)
{
	if (!qos->lq_dirty && qos->lq_same_space)
		return false;

	if (active_tgt_nr < 2)
		return false;

	return true;
}
EXPORT_SYMBOL(lqos_is_usable);

/**
 * Calculate weight for a given tgt.
 *
 * The final tgt weight is bavail >> 16 * iavail >> 8 minus the tgt and server
 * penalties.  See lqos_calc_ppts() for how penalties are calculated.
 *
 * \param[in] tgt	target descriptor
 */
void lqos_calc_weight(struct lu_tgt_desc *tgt)
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
EXPORT_SYMBOL(lqos_calc_weight);

/**
 * Re-calculate weights.
 *
 * The function is called when some target was used for a new object. In
 * this case we should re-calculate all the weights to keep new allocations
 * balanced well.
 *
 * \param[in] qos		lu_qos
 * \param[in] ltd		lu_tgt_descs
 * \param[in] tgt		target where a new object was placed
 * \param[in] active_tgt_nr	active tgt number
 * \param[out] total_wt	new total weight for the pool
 *
 * \retval		0
 */
int lqos_recalc_weight(struct lu_qos *qos, struct lu_tgt_descs *ltd,
		       struct lu_tgt_desc *tgt, __u32 active_tgt_nr,
		       __u64 *total_wt)
{
	struct lu_tgt_qos *ltq;
	struct lu_svr_qos *svr;

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

	/* mark the server and tgt as recently used */
	ltq->ltq_used = svr->lsq_used = ktime_get_real_seconds();

	/* Set max penalties for this tgt and server */
	ltq->ltq_penalty += ltq->ltq_penalty_per_obj * active_tgt_nr;
	svr->lsq_penalty += svr->lsq_penalty_per_obj * active_tgt_nr;

	/* Decrease all MDS penalties */
	list_for_each_entry(svr, &qos->lq_svr_list, lsq_svr_list) {
		if (svr->lsq_penalty < svr->lsq_penalty_per_obj)
			svr->lsq_penalty = 0;
		else
			svr->lsq_penalty -= svr->lsq_penalty_per_obj;
	}

	*total_wt = 0;
	/* Decrease all tgt penalties */
	ltd_foreach_tgt(ltd, tgt) {
		if (!tgt->ltd_active)
			continue;

		if (ltq->ltq_penalty < ltq->ltq_penalty_per_obj)
			ltq->ltq_penalty = 0;
		else
			ltq->ltq_penalty -= ltq->ltq_penalty_per_obj;

		lqos_calc_weight(tgt);

		/* Recalc the total weight of usable osts */
		if (ltq->ltq_usable)
			*total_wt += ltq->ltq_weight;

		CDEBUG(D_OTHER, "recalc tgt %d usable=%d avail=%llu"
			  " tgtppo=%llu tgtp=%llu svrppo=%llu"
			  " svrp=%llu wt=%llu\n",
			  tgt->ltd_index, ltq->ltq_usable,
			  tgt_statfs_bavail(tgt) >> 10,
			  ltq->ltq_penalty_per_obj >> 10,
			  ltq->ltq_penalty >> 10,
			  ltq->ltq_svr->lsq_penalty_per_obj >> 10,
			  ltq->ltq_svr->lsq_penalty >> 10,
			  ltq->ltq_weight >> 10);
	}

	RETURN(0);
}
EXPORT_SYMBOL(lqos_recalc_weight);
