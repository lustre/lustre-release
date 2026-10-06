// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre target descriptions
 * These are the only exported functions, they provide some generic
 * infrastructure for target description management used by LOD/LMV
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <linux/module.h>
#include <linux/list.h>
#include <linux/random.h>
#include <linux/sort.h>

#include <lustre_compat/linux/mm.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_disk.h>
#include <lustre_fid.h>
#include <lu_object.h>
#ifdef CONFIG_LUSTRE_FS_SERVER
#include <lu_tgt_alloc.h>
#endif

/**
 * lu_prandom_u64_max() - returns pseudo-rand u64 number in interval [0, ep_ro)
 * @ep_ro: right open interval endpoint
 *
 * Returns a pseudo-random 64-bit number that is in interval [0, ep_ro).
 */
u64 lu_prandom_u64_max(u64 ep_ro)
{
	u64 rand = 0;

	if (ep_ro) {
#ifdef HAVE_GET_RANDOM_U32_AND_U64
		rand = get_random_u64() % ep_ro;
#elif BITS_PER_LONG == 32
		/*
		 * If ep_ro > 32-bit, first generate the high
		 * 32 bits of the random number, then add in the low
		 * 32 bits (truncated to the upper limit, if needed)
		 */
		if (ep_ro > 0xffffffffULL)
			rand = (u64)get_random_u32_below((u32)(ep_ro >> 32)) << 32;

		if (rand == (ep_ro & 0xffffffff00000000ULL))
			rand |= get_random_u32_below((u32)ep_ro);
		else
			rand |= get_random_u32();
#else
		rand = ((u64)get_random_u32() << 32 | get_random_u32()) % ep_ro;
#endif
	}

	return rand;
}
EXPORT_SYMBOL(lu_prandom_u64_max);

/**
 * lu_qos_add_tgt() - Add a new target to Quality of Service (QoS) target table.
 * @qos: lu_qos data
 * @tgt: target description
 *
 * Add a new MDT/OST target to the structure representing an OSS. Resort the
 * list of known MDSs/OSSs by the number of MDTs/OSTs attached to each MDS/OSS.
 * The MDS/OSS list is protected internally and no external locking is required.
 *
 * Return:
 * * %0 on success
 * * %-ENOMEM on error
 */
int lu_qos_add_tgt(struct lu_qos *qos, struct lu_tgt_desc *tgt)
{
	struct lu_svr_qos *svr = NULL;
	struct lu_svr_qos *tempsvr;
	struct obd_export *exp = tgt->ltd_exp;
	struct obd_uuid tmp;
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
		obd_str2uuid(&tmp,
			     libcfs_nidstr(&exp->exp_connection->c_peer.nid));
		if (obd_uuid_equals(&svr->lsq_uuid, &tmp)) {
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

		memcpy(&svr->lsq_uuid,
		       libcfs_nidstr(&exp->exp_connection->c_peer.nid),
		       sizeof(svr->lsq_uuid));
		++id;
		svr->lsq_id = id;
	} else {
		/* Assume we have to move this one */
		list_del(&svr->lsq_svr_list);
	}

	svr->lsq_tgt_count++;
	tgt->ltd_qos.ltq_svr = svr;

	CDEBUG(D_OTHER, "add tgt %s to server %s (%d targets)\n",
	       obd_uuid2str(&tgt->ltd_uuid), obd_uuid2str(&svr->lsq_uuid),
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

	set_bit(LQ_DIRTY, &qos->lq_flags);
#ifdef CONFIG_LUSTRE_FS_SERVER
	set_bit(LQ_DIRTY, &qos->lq_rr.lqr_flags);
#endif
out:
	up_write(&qos->lq_rw_sem);
	RETURN(rc);
}
EXPORT_SYMBOL(lu_qos_add_tgt);

/**
 * lu_qos_del_tgt() - Remove MDT/OST target from QoS table.
 * @qos: lu_qos data
 * @ltd: target description
 *
 * Removes given MDT/OST target from QoS table and releases related
 * MDS/OSS structure if no target remain on the MDS/OSS.
 *
 * Return:
 * * %0 on success
 * * %-ENOENT if no server was found
 */
int lu_qos_del_tgt(struct lu_qos *qos, struct lu_tgt_desc *ltd)
{
	struct lu_svr_qos *svr;
	int rc = 0;

	ENTRY;

	down_write(&qos->lq_rw_sem);
	svr = ltd->ltd_qos.ltq_svr;
	if (!svr)
		GOTO(out, rc = -ENOENT);

	ltd->ltd_qos.ltq_svr = NULL;
	svr->lsq_tgt_count--;
	if (svr->lsq_tgt_count == 0) {
		CDEBUG(D_OTHER, "removing server %s\n",
		       obd_uuid2str(&svr->lsq_uuid));
		list_del(&svr->lsq_svr_list);
		OBD_FREE_PTR(svr);
	}

	set_bit(LQ_DIRTY, &qos->lq_flags);
#ifdef CONFIG_LUSTRE_FS_SERVER
	set_bit(LQ_DIRTY, &qos->lq_rr.lqr_flags);
#endif
out:
	up_write(&qos->lq_rw_sem);
	RETURN(rc);
}
EXPORT_SYMBOL(lu_qos_del_tgt);

#ifdef CONFIG_LUSTRE_FS_SERVER
/**
 * lu_qos_rr_init() - Initialize round-robin allocation state
 * @lqr: round-robin state
 *
 * Return:
 * * %0 on success
 * * %-ENOMEM if the round-robin array could not be allocated
 */
int lu_qos_rr_init(struct lu_qos_rr *lqr)
{
	spin_lock_init(&lqr->lqr_alloc);
	set_bit(LQ_DIRTY, &lqr->lqr_flags);

	return lu_tgt_pool_init(&lqr->lqr_pool, 0);
}
EXPORT_SYMBOL(lu_qos_rr_init);

/**
 * lu_qos_rr_fini() - Free a round-robin array and its failure domains
 * @lqr: round-robin state
 */
void lu_qos_rr_fini(struct lu_qos_rr *lqr)
{
	lu_tgt_pool_free(&lqr->lqr_pool);
	OBD_FREE_LARGE(lqr->lqr_fdoms, lqr->lqr_fdoms_size);
	lqr->lqr_fdoms = NULL;
}
EXPORT_SYMBOL(lu_qos_rr_fini);

/* compare NIDs by network, then address */
static int ltd_nid_cmp(const struct lnet_nid *a, const struct lnet_nid *b)
{
	return memcmp(&a->nid_type, &b->nid_type,
		      sizeof(*a) - offsetof(struct lnet_nid, nid_type));
}

/* lowest NID of @tgt, the same for all targets that fail over together */
static void ltd_tgt_failover_nid(struct lu_tgt_desc *tgt,
				 struct lnet_nid *nid)
{
	struct obd_export *exp = tgt->ltd_exp;
	struct obd_import *imp = exp->exp_obd->u.cli.cl_import;
	struct obd_import_conn *conn;

	/* sort targets without a connection last, del_conn can clear it */
	memset(nid, 0xff, sizeof(*nid));
	if (!imp)
		return;

	/* the current connection is also on imp_conn_list */
	spin_lock(&imp->imp_lock);
	list_for_each_entry(conn, &imp->imp_conn_list, oic_item)
		if (conn->oic_conn &&
		    ltd_nid_cmp(&conn->oic_conn->c_peer.nid, nid) < 0)
			*nid = conn->oic_conn->c_peer.nid;
	spin_unlock(&imp->imp_lock);
}

struct ltd_rr_nid {
	struct lnet_nid	lrn_nid;
	unsigned int	lrn_idx;
	__u32		lrn_svr;
};

static int ltd_rr_nid_cmp(const void *a, const void *b)
{
	return ltd_nid_cmp(&((const struct ltd_rr_nid *)a)->lrn_nid,
			   &((const struct ltd_rr_nid *)b)->lrn_nid);
}

static int ltd_rr_svr_nid_cmp(const void *pa, const void *pb)
{
	const struct ltd_rr_nid *a = pa, *b = pb;

	if (a->lrn_svr != b->lrn_svr)
		return a->lrn_svr < b->lrn_svr ? -1 : 1;
	return ltd_nid_cmp(&a->lrn_nid, &b->lrn_nid);
}

/**
 * ltd_rr_failover_order() - Order the round-robin array by failover group
 * @ltd: target table
 * @tgts: targets to place with lu_rr_fill()
 * @count: number of targets in @tgts
 *
 * Group the targets without a failure domain by failover group, the
 * targets with the same lowest NID of their primary and failover NIDs, so
 * that lu_rr_fill() spreads the targets that can fail over together over
 * the array, and spreads the groups by NID.  The targets of a server are
 * all put in the group of its lowest NID, since lu_rr_fill() only orders
 * the array by server if any server is in several groups.  This assumes
 * that every target of a group lists the same failover NIDs, as for HA
 * pairs.  It only orders the array, and does not limit where the stripes
 * of a layout go.
 *
 * Context: caller holds lq_rw_sem for write.
 */
void ltd_rr_failover_order(struct lu_tgt_descs *ltd, struct lu_rr_tgt *tgts,
			   unsigned int count)
{
	unsigned int groups, rank, unset, i;
	struct ltd_rr_nid *nids;

	OBD_ALLOC_PTR_ARRAY_LARGE(nids, count);
	if (!nids)
		return;

	for (unset = 0, i = 0; i < count; i++) {
		if (tgts[i].lrrt_fdom)
			continue;
		ltd_tgt_failover_nid(LTD_TGT(ltd, tgts[i].lrrt_idx),
				     &nids[unset].lrn_nid);
		nids[unset].lrn_svr = tgts[i].lrrt_svr;
		nids[unset++].lrn_idx = i;
	}
	/* e.g. if one target of a server has a different failover NID */
	sort(nids, unset, sizeof(*nids), ltd_rr_svr_nid_cmp, NULL);
	for (i = 1; i < unset; i++)
		if (nids[i].lrn_svr == nids[i - 1].lrn_svr)
			nids[i].lrn_nid = nids[i - 1].lrn_nid;
	sort(nids, unset, sizeof(*nids), ltd_rr_nid_cmp, NULL);

	for (groups = 1, i = 1; i < unset; i++)
		if (ltd_nid_cmp(&nids[i - 1].lrn_nid, &nids[i].lrn_nid))
			groups++;
	for (rank = 0, i = 0; i < unset; i++) {
		if (i && ltd_nid_cmp(&nids[i - 1].lrn_nid, &nids[i].lrn_nid))
			rank++;
		tgts[nids[i].lrn_idx].lrrt_fdom =
			lu_rr_group_order(rank, groups) + 1;
		tgts[nids[i].lrn_idx].lrrt_inferred = true;
	}
	OBD_FREE_PTR_ARRAY_LARGE(nids, count);
}
EXPORT_SYMBOL(ltd_rr_failover_order);
#endif /* CONFIG_LUSTRE_FS_SERVER */

/**
 * lu_tgt_qos_weight_calc() - Calculate weight for a given tgt.
 * @tgt: target descriptor
 * @is_mdt: target table is for MDT selection (use inodes)
 *
 * The final tgt weight uses only free space for OSTs, but combines
 * both free space and inodes for MDTs, minus tgt and server penalties.
 * See ltd_qos_penalties_calc() for how penalties are calculated.
 */
void lu_tgt_qos_weight_calc(struct lu_tgt_desc *tgt, bool is_mdt)
{
	struct lu_tgt_qos *ltq = &tgt->ltd_qos;
	__u64 penalty;

	if (is_mdt)
		ltq->ltq_avail = (tgt_statfs_bavail(tgt) >> 16) *
				 (tgt_statfs_iavail(tgt) >> 8);
	else
		ltq->ltq_avail = tgt_statfs_bavail(tgt) >> 8;
	penalty = ltq->ltq_penalty + ltq->ltq_svr->lsq_penalty;
	CDEBUG(D_OTHER, "ltq_penalty: %llu lsq_penalty: %llu tgt_bavail: %llu\n",
		  ltq->ltq_penalty, ltq->ltq_svr->lsq_penalty, ltq->ltq_avail);
	if (ltq->ltq_avail < penalty)
		ltq->ltq_weight = 0;
	else
		ltq->ltq_weight = ltq->ltq_avail - penalty;
}
EXPORT_SYMBOL(lu_tgt_qos_weight_calc);

/**
 * lu_tgt_descs_init() - Allocate and initialize target table.
 * @ltd: target's table to initialize
 * @is_mdt: target table for MDTs
 *
 * A helper function to initialize the target table and allocate
 * a bitmap of the available targets.
 *
 * Return:
 * * %0 on success
 * * %negative negated errno on error
 */
int lu_tgt_descs_init(struct lu_tgt_descs *ltd, bool is_mdt)
{
	mutex_init(&ltd->ltd_mutex);
	init_rwsem(&ltd->ltd_rw_sem);

	/*
	 * the tgt array and bitmap are allocated/grown dynamically as tgts are
	 * added to the LOD/LMV, see lu_tgt_descs_add()
	 */
	ltd->ltd_tgt_bitmap = bitmap_zalloc(BITS_PER_LONG, GFP_NOFS);
	if (!ltd->ltd_tgt_bitmap)
		return -ENOMEM;

	ltd->ltd_tgts_size  = BITS_PER_LONG;
	ltd->ltd_death_row = 0;
	atomic_set(&ltd->ltd_refcount, 0);

	/* Set up allocation policy (QoS and RR) */
	INIT_LIST_HEAD(&ltd->ltd_qos.lq_svr_list);
	init_rwsem(&ltd->ltd_qos.lq_rw_sem);
	set_bit(LQ_DIRTY, &ltd->ltd_qos.lq_flags);
	set_bit(LQ_RESET, &ltd->ltd_qos.lq_flags);
	ltd->ltd_is_mdt = is_mdt;
	/* MDT imbalance threshold is low to balance across MDTs
	 * relatively quickly, because each directory may result
	 * in a large number of files/subdirs created therein.
	 */
	if (is_mdt) {
		ltd->ltd_lmv_desc.ld_pattern = LMV_HASH_TYPE_DEFAULT;
		ltd->ltd_qos.lq_prio_free = LMV_QOS_DEF_PRIO_FREE * 256 / 100;
		ltd->ltd_qos.lq_threshold_rr =
			LMV_QOS_DEF_THRESHOLD_RR_PCT *
			QOS_THRESHOLD_MAX / 100;
	} else {
		ltd->ltd_qos.lq_prio_free = LOV_QOS_DEF_PRIO_FREE * 256 / 100;
		ltd->ltd_qos.lq_threshold_rr =
			LOV_QOS_DEF_THRESHOLD_RR_PCT *
			QOS_THRESHOLD_MAX / 100;
	}

	return 0;
}
EXPORT_SYMBOL(lu_tgt_descs_init);

/**
 * lu_tgt_descs_fini() - Free bitmap and target table pages.
 * @ltd: target table
 */
void lu_tgt_descs_fini(struct lu_tgt_descs *ltd)
{
	int i;

	bitmap_free(ltd->ltd_tgt_bitmap);
	for (i = 0; i < ARRAY_SIZE(ltd->ltd_tgt_idx); i++) {
		OBD_FREE_PTR(ltd->ltd_tgt_idx[i]);
		ltd->ltd_tgt_idx[i] = NULL;
	}
	ltd->ltd_tgts_size = 0;
}
EXPORT_SYMBOL(lu_tgt_descs_fini);

/**
 * lu_tgt_descs_resize() - Expand size of target table.
 * @ltd: target table
 * @newsize: new size of the table
 *
 * When the target table is full, we have to extend the table. To do so,
 * we allocate new memory with some reserve, move data from the old table
 * to the new one and release memory consumed by the old table.
 *
 * Return:
 * * %0 on success
 * * %-ENOMEM if reallocation failed
 */
static int lu_tgt_descs_resize(struct lu_tgt_descs *ltd, __u32 newsize)
{
	unsigned long *new_bitmap, *old_bitmap = NULL;

	/* someone else has already resize the array */
	if (newsize <= ltd->ltd_tgts_size)
		return 0;

	new_bitmap = bitmap_zalloc(newsize, GFP_NOFS);
	if (!new_bitmap)
		return -ENOMEM;

	if (ltd->ltd_tgts_size > 0) {
		/* the bitmap already exists, copy data from old one */
		bitmap_copy(new_bitmap, ltd->ltd_tgt_bitmap,
			    ltd->ltd_tgts_size);
		old_bitmap = ltd->ltd_tgt_bitmap;
	}

	ltd->ltd_tgts_size  = newsize;
	ltd->ltd_tgt_bitmap = new_bitmap;

	bitmap_free(old_bitmap);

	CDEBUG(D_CONFIG, "tgt size: %d\n", ltd->ltd_tgts_size);

	return 0;
}

/**
 * ltd_add_tgt() - Add new target to target table.
 * @ltd: target table
 * @tgt: new target desc
 *
 * Extend target table if it's full, update target table and bitmap.
 * Notice we need to take ltd_rw_sem exclusively before entry to ensure
 * atomic switch.
 *
 * Return:
 * * %0 on success
 * * %-ENOMEM if reallocation failed or %-EEXIST if target existed
 */
int ltd_add_tgt(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt)
{
	__u32 index = tgt->ltd_index;
	int rc;

	ENTRY;

	if (index >= ltd->ltd_tgts_size) {
		__u32 newsize = 1;

		if (index > TGT_PTRS * TGT_PTRS_PER_BLOCK)
			RETURN(-ENFILE);

		while (newsize < index + 1)
			newsize = newsize << 1;

		rc = lu_tgt_descs_resize(ltd, newsize);
		if (rc)
			RETURN(rc);
	} else if (test_bit(index, ltd->ltd_tgt_bitmap)) {
		RETURN(-EEXIST);
	}

	if (ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK] == NULL) {
		OBD_ALLOC_PTR(ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK]);
		if (ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK] == NULL)
			RETURN(-ENOMEM);
	}

	LTD_TGT(ltd, tgt->ltd_index) = tgt;
	set_bit(tgt->ltd_index, ltd->ltd_tgt_bitmap);

	ltd->ltd_lov_desc.ld_tgt_count++;
	if (tgt->ltd_active)
		ltd->ltd_lov_desc.ld_active_tgt_count++;

	RETURN(0);
}
EXPORT_SYMBOL(ltd_add_tgt);

/**
 * ltd_del_tgt() - Delete target from target table
 * @ltd: target table
 * @tgt: target desc to be deleted
 */
void ltd_del_tgt(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt)
{
	lu_qos_del_tgt(&ltd->ltd_qos, tgt);
	LTD_TGT(ltd, tgt->ltd_index) = NULL;
	clear_bit(tgt->ltd_index, ltd->ltd_tgt_bitmap);
	ltd->ltd_lov_desc.ld_tgt_count--;
	if (tgt->ltd_active)
		ltd->ltd_lov_desc.ld_active_tgt_count--;
}
EXPORT_SYMBOL(ltd_del_tgt);

/**
 * ltd_qos_penalties_calc() - Calculate penalties per-tgt and per-server
 * @ltd: lu_tgt_descs
 *
 * Re-calculate penalties when the configuration changes, active targets
 * change and after statfs refresh (all these are reflected by LQ_DIRTY flag).
 * On every tgt and server: decay the penalty by half for every 8x the update
 * interval that the device has been idle. That gives lots of time for the
 * statfs information to be updated (which the penalty is only a proxy for),
 * and avoids penalizing server/tgt under light load.
 * See lu_qos_tgt_weight_calc() for how penalties are factored into the weight.
 *
 * Return:
 * * %0 on success
 * * %-EAGAIN number of tgt isn't enough or all tgt spaces are almost the same
 */
int ltd_qos_penalties_calc(struct lu_tgt_descs *ltd)
{
	struct lu_qos *qos = &ltd->ltd_qos;
	struct lov_desc *desc = &ltd->ltd_lov_desc;
	struct lu_tgt_desc *tgt;
	struct lu_svr_qos *svr;
	__u64 ba_max, ba_min, ba;
	__u64 ia_max, ia_min, ia = 1;
	__u32 num_active;
	int prio_wide;
	time64_t now, age;
	int rc;

	ENTRY;

	if (!test_bit(LQ_DIRTY, &qos->lq_flags))
		GOTO(out, rc = 0);

	num_active = desc->ld_active_tgt_count - 1;
	if (num_active < 1)
		GOTO(out, rc = -EAGAIN);

	/* find bavail on each server */
	list_for_each_entry(svr, &qos->lq_svr_list, lsq_svr_list) {
		svr->lsq_bavail = 0;
		/* if inode is not counted, set to 1 to ignore */
		svr->lsq_iavail = ltd->ltd_is_mdt ? 0 : 1;
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
		if (ltd->ltd_is_mdt)
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

		if (ltd->ltd_is_mdt) {
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
		 * prio * bavail * iavail / (num_tgt - 1) / prio_max / 2
		 */
		tgt->ltd_qos.ltq_penalty_per_obj = prio_wide * ba * ia >> 9;
		do_div(tgt->ltd_qos.ltq_penalty_per_obj, num_active);

		age = (now - tgt->ltd_qos.ltq_used) >> 3;
		if (test_bit(LQ_RESET, &qos->lq_flags) ||
		    age > 32 * desc->ld_qos_maxage)
			tgt->ltd_qos.ltq_penalty = 0;
		else if (age > desc->ld_qos_maxage)
			/* Decay tgt penalty. */
			tgt->ltd_qos.ltq_penalty >>= age / desc->ld_qos_maxage;
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
		do_div(svr->lsq_penalty_per_obj,
		       svr->lsq_tgt_count * num_active);
		svr->lsq_penalty_per_obj >>= 1;

		age = (now - svr->lsq_used) >> 3;
		if (test_bit(LQ_RESET, &qos->lq_flags) ||
		    age > 32 * desc->ld_qos_maxage)
			svr->lsq_penalty = 0;
		else if (age > desc->ld_qos_maxage)
			/* Decay server penalty. */
			svr->lsq_penalty >>= age / desc->ld_qos_maxage;
	}


	/*
	 * If each tgt has almost same free space, do rr allocation for better
	 * creation performance
	 */
	if (((ba_max * (QOS_THRESHOLD_MAX - qos->lq_threshold_rr)) /
	    QOS_THRESHOLD_MAX) < ba_min &&
	    ((ia_max * (QOS_THRESHOLD_MAX - qos->lq_threshold_rr)) /
	    QOS_THRESHOLD_MAX) < ia_min) {
		set_bit(LQ_SAME_SPACE, &qos->lq_flags);
		/* Reset weights for the next time we enter qos mode */
		set_bit(LQ_RESET, &qos->lq_flags);
	} else {
		clear_bit(LQ_SAME_SPACE, &qos->lq_flags);
		clear_bit(LQ_RESET, &qos->lq_flags);
	}
	clear_bit(LQ_DIRTY, &qos->lq_flags);
	rc = 0;

out:
	if (!rc && test_bit(LQ_SAME_SPACE, &qos->lq_flags))
		RETURN(-EAGAIN);

	RETURN(rc);
}
EXPORT_SYMBOL(ltd_qos_penalties_calc);

/**
 * ltd_qos_update() - Re-calculate penalties and weights of all tgts.
 * @ltd: lu_tgt_descs
 * @tgt: recently used tgt
 * @total_wt: new total weight for the pool [out]
 *
 * The function is called when some target was used for a new object. In
 * this case we should re-calculate all the weights to keep new allocations
 * balanced well.
 *
 * Return 0 always
 */
int ltd_qos_update(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt,
		   __u64 *total_wt)
{
	struct lu_qos *qos = &ltd->ltd_qos;
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
	ltq->ltq_penalty += ltq->ltq_penalty_per_obj *
			    ltd->ltd_lov_desc.ld_active_tgt_count;
	CDEBUG(D_OTHER, "ltq_penalty: %llu per_obj: %llu tgt_count: %d\n",
	       ltq->ltq_penalty, ltq->ltq_penalty_per_obj,
	       ltd->ltd_lov_desc.ld_active_tgt_count);
	svr->lsq_penalty += svr->lsq_penalty_per_obj *
			    qos->lq_active_svr_count;
	CDEBUG(D_OTHER, "lsq_penalty: %llu per_obj: %llu srv_count: %d\n",
	       svr->lsq_penalty, svr->lsq_penalty_per_obj,
	       qos->lq_active_svr_count);


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

		ltq = &tgt->ltd_qos;
		if (ltq->ltq_penalty < ltq->ltq_penalty_per_obj)
			ltq->ltq_penalty = 0;
		else
			ltq->ltq_penalty -= ltq->ltq_penalty_per_obj;

		lu_tgt_qos_weight_calc(tgt, ltd->ltd_is_mdt);

		/* Recalc the total weight of usable osts */
		if (ltq->ltq_usable)
			*total_wt += ltq->ltq_weight;

		CDEBUG(D_OTHER, "recalc tgt %d usable=%d bavail=%llu ffree=%llu tgtppo=%llu tgtp=%llu svrppo=%llu svrp=%llu wt=%llu\n",
			  tgt->ltd_index, ltq->ltq_usable,
			  tgt_statfs_bavail(tgt) >> 16,
			  tgt_statfs_iavail(tgt) >> 8,
			  ltq->ltq_penalty_per_obj >> 10,
			  ltq->ltq_penalty >> 10,
			  ltq->ltq_svr->lsq_penalty_per_obj >> 10,
			  ltq->ltq_svr->lsq_penalty >> 10,
			  ltq->ltq_weight >> 10);
	}

	RETURN(0);
}
EXPORT_SYMBOL(ltd_qos_update);
