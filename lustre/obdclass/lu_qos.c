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
