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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2016, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include "qmt_internal.h"

/*
 * Initialize qmt-specific fields of quota entry.
 *
 * \param lqe - is the quota entry to initialize
 * \param arg - is the pointer to the qmt_pool_info structure
 */
static void qmt_lqe_init(struct lquota_entry *lqe, void *arg)
{
	LASSERT(lqe_is_master(lqe));

	lqe->lqe_revoke_time = 0;
	init_rwsem(&lqe->lqe_sem);
}

/*
 * Update a lquota entry. This is done by reading quota settings from the global
 * index. The lquota entry must be write locked.
 *
 * \param env - the environment passed by the caller
 * \param lqe - is the quota entry to refresh
 * \param arg - is the pointer to the qmt_pool_info structure
 */
static int qmt_lqe_read(const struct lu_env *env, struct lquota_entry *lqe,
			void *arg)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct qmt_pool_info	*pool = (struct qmt_pool_info *)arg;
	int			 rc;
	ENTRY;

	LASSERT(lqe_is_master(lqe));

	/* read record from disk */
	rc = lquota_disk_read(env, pool->qpi_glb_obj[lqe->lqe_site->lqs_qtype],
			      &lqe->lqe_id, (struct dt_rec *)&qti->qti_glb_rec);

	switch (rc) {
	case -ENOENT:
		/* no such entry, assume quota isn't enforced for this user */
		lqe->lqe_enforced = false;
		break;
	case 0:
		/* copy quota settings from on-disk record */
		lqe->lqe_granted   = qti->qti_glb_rec.qbr_granted;
		lqe->lqe_hardlimit = qti->qti_glb_rec.qbr_hardlimit;
		lqe->lqe_softlimit = qti->qti_glb_rec.qbr_softlimit;
		lqe->lqe_gracetime = qti->qti_glb_rec.qbr_time;

		if (lqe->lqe_hardlimit == 0 && lqe->lqe_softlimit == 0)
			/* {hard,soft}limit=0 means no quota enforced */
			lqe->lqe_enforced = false;
		else
			lqe->lqe_enforced  = true;

		break;
	default:
		LQUOTA_ERROR(lqe, "failed to read quota entry from disk, rc:%d",
			     rc);
		RETURN(rc);
	}

	LQUOTA_DEBUG(lqe, "read");
	RETURN(0);
}

/*
 * Print lqe information for debugging.
 *
 * \param lqe - is the quota entry to debug
 * \param arg - is the pointer to the qmt_pool_info structure
 * \param msgdata - debug message
 * \param fmt     - format of debug message
 */
static void qmt_lqe_debug(struct lquota_entry *lqe, void *arg,
			  struct libcfs_debug_msg_data *msgdata,
			  const char *fmt, va_list args)
{
	struct qmt_pool_info	*pool = (struct qmt_pool_info *)arg;

	libcfs_debug_vmsg2(msgdata, fmt, args,
			   "qmt:%s pool:%d-%s id:%llu enforced:%d hard:%llu"
			   " soft:%llu granted:%llu time:%llu qunit:"
			   "%llu edquot:%d may_rel:%llu revoke:%lld\n",
			   pool->qpi_qmt->qmt_svname,
			   pool->qpi_key & 0x0000ffff,
			   RES_NAME(pool->qpi_key >> 16),
			   lqe->lqe_id.qid_uid, lqe->lqe_enforced,
			   lqe->lqe_hardlimit, lqe->lqe_softlimit,
			   lqe->lqe_granted, lqe->lqe_gracetime,
			   lqe->lqe_qunit, lqe->lqe_edquot, lqe->lqe_may_rel,
			   lqe->lqe_revoke_time);
}

/*
 * Vector of quota entry operations supported on the master
 */
struct lquota_entry_operations qmt_lqe_ops = {
	.lqe_init	= qmt_lqe_init,
	.lqe_read	= qmt_lqe_read,
	.lqe_debug	= qmt_lqe_debug,
};

/*
 * Reserve enough credits to update records in both the global index and
 * the slave index identified by \slv_obj
 *
 * \param env     - is the environment passed by the caller
 * \param lqe     - is the quota entry associated with the identifier
 *                  subject to the change
 * \param slv_obj - is the dt_object associated with the index file
 * \param restore - is a temporary storage for current quota settings which will
 *                  be restored if something goes wrong at index update time.
 */
struct thandle *qmt_trans_start_with_slv(const struct lu_env *env,
					 struct lquota_entry *lqe,
					 struct dt_object *slv_obj,
					 struct qmt_lqe_restore *restore)
{
	struct qmt_device	*qmt;
	struct thandle		*th;
	int			 rc;
	ENTRY;

	LASSERT(lqe != NULL);
	LASSERT(lqe_is_master(lqe));

	qmt = lqe2qpi(lqe)->qpi_qmt;

	if (slv_obj != NULL)
		LQUOTA_DEBUG(lqe, "declare write for slv "DFID,
			     PFID(lu_object_fid(&slv_obj->do_lu)));

	/* start transaction */
	th = dt_trans_create(env, qmt->qmt_child);
	if (IS_ERR(th))
		RETURN(th);

	if (slv_obj == NULL)
		/* quota settings on master are updated synchronously for the
		 * time being */
		th->th_sync = 1;

	/* reserve credits for global index update */
	rc = lquota_disk_declare_write(env, th, LQE_GLB_OBJ(lqe), &lqe->lqe_id);
	if (rc)
		GOTO(out, rc);

	if (slv_obj != NULL) {
		/* reserve credits for slave index update */
		rc = lquota_disk_declare_write(env, th, slv_obj, &lqe->lqe_id);
		if (rc)
			GOTO(out, rc);
	}

	/* start transaction */
	rc = dt_trans_start_local(env, qmt->qmt_child, th);
	if (rc)
		GOTO(out, rc);

	EXIT;
out:
	if (rc) {
		dt_trans_stop(env, qmt->qmt_child, th);
		th = ERR_PTR(rc);
		LQUOTA_ERROR(lqe, "failed to slv declare write for "DFID
			     ", rc:%d", PFID(lu_object_fid(&slv_obj->do_lu)),
			     rc);
	} else {
		restore->qlr_hardlimit = lqe->lqe_hardlimit;
		restore->qlr_softlimit = lqe->lqe_softlimit;
		restore->qlr_gracetime = lqe->lqe_gracetime;
		restore->qlr_granted   = lqe->lqe_granted;
		restore->qlr_qunit     = lqe->lqe_qunit;
	}
	return th;
}

/*
 * Reserve enough credits to update a record in the global index
 *
 * \param env     - is the environment passed by the caller
 * \param lqe     - is the quota entry to be modified in the global index
 * \param restore - is a temporary storage for current quota settings which will
 *                  be restored if something goes wrong at index update time.
 */
struct thandle *qmt_trans_start(const struct lu_env *env,
				struct lquota_entry *lqe,
				struct qmt_lqe_restore *restore)
{
	LQUOTA_DEBUG(lqe, "declare write");
	return qmt_trans_start_with_slv(env, lqe, NULL, restore);
}

/*
 * Update record associated with a quota entry in the global index.
 * If LQUOTA_BUMP_VER is set, then the global index version must also be
 * bumped.
 * The entry must be at least read locked, dirty and up-to-date.
 *
 * \param env   - the environment passed by the caller
 * \param th    - is the transaction handle to be used for the disk writes
 * \param lqe   - is the quota entry to udpate
 * \param obj   - is the dt_object associated with the index file
 * \param flags - can be LQUOTA_BUMP_VER or LQUOTA_SET_VER.
 * \param ver   - is used to return the new version of the index.
 *
 * \retval      - 0 on success and lqe dirty flag cleared,
 *                appropriate error on failure and uptodate flag cleared.
 */
int qmt_glb_write(const struct lu_env *env, struct thandle *th,
		  struct lquota_entry *lqe, __u32 flags, __u64 *ver)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_glb_rec	*rec;
	int			 rc;
	ENTRY;

	LASSERT(lqe != NULL);
	LASSERT(lqe_is_master(lqe));
	LASSERT(lqe_is_locked(lqe));
	LASSERT(lqe->lqe_uptodate);
	LASSERT((flags & ~(LQUOTA_BUMP_VER | LQUOTA_SET_VER)) == 0);

	LQUOTA_DEBUG(lqe, "write glb");

	/* never delete the entry even when the id isn't enforced and
	 * no any guota granted, otherwise, this entry will not be
	 * synced to slave during the reintegration. */
	rec = &qti->qti_glb_rec;

	/* fill global index with updated quota settings */
	rec->qbr_granted   = lqe->lqe_granted;
	rec->qbr_hardlimit = lqe->lqe_hardlimit;
	rec->qbr_softlimit = lqe->lqe_softlimit;
	rec->qbr_time      = lqe->lqe_gracetime;

	/* write new quota settings */
	rc = lquota_disk_write(env, th, LQE_GLB_OBJ(lqe), &lqe->lqe_id,
			       (struct dt_rec *)rec, flags, ver);
	if (rc)
		/* we failed to write the new quota settings to disk, report
		 * error to caller who will restore the initial value */
		LQUOTA_ERROR(lqe, "failed to update global index, rc:%d", rc);

	RETURN(rc);
}

/*
 * Read from disk how much quota space is allocated to a slave.
 * This is done by reading records from the dedicated slave index file.
 * Return in \granted how much quota space is currently allocated to the
 * slave.
 * The entry must be at least read locked.
 *
 * \param env - the environment passed by the caller
 * \param lqe - is the quota entry associated with the identifier to look-up
 *              in the slave index
 * \param slv_obj - is the dt_object associated with the slave index
 * \param granted - is the output parameter where to return how much space
 *                  is granted to the slave.
 *
 * \retval    - 0 on success, appropriate error on failure
 */
int qmt_slv_read(const struct lu_env *env, struct lquota_entry *lqe,
		 struct dt_object *slv_obj, __u64 *granted)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_slv_rec	*slv_rec = &qti->qti_slv_rec;
	int			 rc;
	ENTRY;

	LASSERT(lqe != NULL);
	LASSERT(lqe_is_master(lqe));
	LASSERT(lqe_is_locked(lqe));

	LQUOTA_DEBUG(lqe, "read slv "DFID,
		     PFID(lu_object_fid(&slv_obj->do_lu)));

	/* read slave record from disk */
	rc = lquota_disk_read(env, slv_obj, &lqe->lqe_id,
			      (struct dt_rec *)slv_rec);
	switch (rc) {
	case -ENOENT:
		*granted = 0;
		break;
	case 0:
		/* extract granted from on-disk record */
		*granted = slv_rec->qsr_granted;
		break;
	default:
		LQUOTA_ERROR(lqe, "failed to read slave record "DFID,
			     PFID(lu_object_fid(&slv_obj->do_lu)));
		RETURN(rc);
	}

	LQUOTA_DEBUG(lqe, "successful slv read %llu", *granted);

	RETURN(0);
}

/*
 * Update record in slave index file.
 * The entry must be at least read locked.
 *
 * \param env - the environment passed by the caller
 * \param th  - is the transaction handle to be used for the disk writes
 * \param lqe - is the dirty quota entry which will be updated at the same time
 *              as the slave index
 * \param slv_obj - is the dt_object associated with the slave index
 * \param flags - can be LQUOTA_BUMP_VER or LQUOTA_SET_VER.
 * \param ver   - is used to return the new version of the index.
 * \param granted - is the new amount of quota space owned by the slave
 *
 * \retval    - 0 on success, appropriate error on failure
 */
int qmt_slv_write(const struct lu_env *env, struct thandle *th,
		  struct lquota_entry *lqe, struct dt_object *slv_obj,
		  __u32 flags, __u64 *ver, __u64 granted)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_slv_rec	*rec;
	int			 rc;
	ENTRY;

	LASSERT(lqe != NULL);
	LASSERT(lqe_is_master(lqe));
	LASSERT(lqe_is_locked(lqe));

	LQUOTA_DEBUG(lqe, "write slv "DFID" granted:%llu",
		     PFID(lu_object_fid(&slv_obj->do_lu)), granted);

	/* never delete the entry, otherwise, it'll not be transferred
	 * to slave during reintegration. */
	rec = &qti->qti_slv_rec;

	/* updated space granted to this slave */
	rec->qsr_granted = granted;

	/* write new granted space */
	rc = lquota_disk_write(env, th, slv_obj, &lqe->lqe_id,
			       (struct dt_rec *)rec, flags, ver);
	if (rc) {
		LQUOTA_ERROR(lqe, "failed to update slave index "DFID" granted:"
			     "%llu", PFID(lu_object_fid(&slv_obj->do_lu)),
			     granted);
		RETURN(rc);
	}

	RETURN(0);
}

/*
 * Check whether new limits are valid for this pool
 *
 * \param lqe  - is the quota entry subject to the setquota
 * \param hard - is the new hard limit
 * \param soft - is the new soft limit
 */
int qmt_validate_limits(struct lquota_entry *lqe, __u64 hard, __u64 soft)
{
	ENTRY;

	if (hard != 0 && soft > hard)
		/* soft limit must be less than hard limit */
		RETURN(-EINVAL);
	RETURN(0);
}

/*
 * Set/clear edquot flag after quota space allocation/release or settings
 * change. Slaves will be notified of changes via glimpse on per-ID lock
 *
 * \param lqe - is the quota entry to check
 * \param now - is the current time in second used for grace time managment
 */
void qmt_adjust_edquot(struct lquota_entry *lqe, __u64 now)
{
	struct qmt_pool_info	*pool = lqe2qpi(lqe);
	ENTRY;

	if (!lqe->lqe_enforced || lqe->lqe_id.qid_uid == 0)
		RETURN_EXIT;

	if (!lqe->lqe_edquot) {
		/* space exhausted flag not set, let's check whether it is time
		 * to set the flag */

		if (!qmt_space_exhausted(lqe, now))
			/* the qmt still has available space */
			RETURN_EXIT;

		/* See comment in qmt_adjust_qunit(). LU-4139 */
		if (qmt_hard_exhausted(lqe) ||
		    pool->qpi_key >> 16 != LQUOTA_RES_DT) {
			time64_t lapse;

			/* we haven't reached the minimal qunit yet so there is
			 * still hope that the rebalancing process might free
			 * up some quota space */
			if (lqe->lqe_qunit != pool->qpi_least_qunit)
				RETURN_EXIT;

			/* least qunit value not sent to all slaves yet */
			if (lqe->lqe_revoke_time == 0)
				RETURN_EXIT;

			/* Let's give more time to slave to release space */
			lapse = ktime_get_seconds() - QMT_REBA_TIMEOUT;
			if (lqe->lqe_may_rel != 0 && lqe->lqe_revoke_time > lapse)
				RETURN_EXIT;
		} else {
			if (lqe->lqe_qunit > pool->qpi_soft_least_qunit)
				RETURN_EXIT;
		}

		/* set edquot flag */
		lqe->lqe_edquot = true;
	} else {
		/* space exhausted flag set, let's check whether it is time to
		 * clear it */

		if (qmt_space_exhausted(lqe, now))
			/* the qmt still has not space */
			RETURN_EXIT;

		if (lqe->lqe_hardlimit != 0 &&
		    lqe->lqe_granted + pool->qpi_least_qunit >
							lqe->lqe_hardlimit)
			/* we clear the flag only once at least one least qunit
			 * is available */
			RETURN_EXIT;

		/* clear edquot flag */
		lqe->lqe_edquot = false;
	}

	LQUOTA_DEBUG(lqe, "changing edquot flag");

	/* let's notify slave by issuing glimpse on per-ID lock.
	 * the rebalance thread will take care of this */
	qmt_id_lock_notify(pool->qpi_qmt, lqe);
	EXIT;
}

/* Using least_qunit when over block softlimit will seriously impact the
 * write performance, we need to do some special tweaking on that. */
static __u64 qmt_calc_softlimit(struct lquota_entry *lqe, bool *oversoft)
{
	struct qmt_pool_info *pool = lqe2qpi(lqe);

	LASSERT(lqe->lqe_softlimit != 0);
	*oversoft = false;
	/* No need to do special tweaking for inode limit */
	if (pool->qpi_key >> 16 != LQUOTA_RES_DT)
		return lqe->lqe_softlimit;

	if (lqe->lqe_granted <= lqe->lqe_softlimit +
				pool->qpi_soft_least_qunit) {
		return lqe->lqe_softlimit;
	} else if (lqe->lqe_hardlimit != 0) {
		*oversoft = true;
		return lqe->lqe_hardlimit;
	} else {
		*oversoft = true;
		return 0;
	}
}

/*
 * Try to grant more quota space back to slave.
 *
 * \param lqe     - is the quota entry for which we would like to allocate more
 *                  space
 * \param granted - is how much was already granted as part of the request
 *                  processing
 * \param spare   - is how much unused quota space the slave already owns
 *
 * \retval return how additional space can be granted to the slave
 */
__u64 qmt_alloc_expand(struct lquota_entry *lqe, __u64 granted, __u64 spare)
{
	struct qmt_pool_info	*pool = lqe2qpi(lqe);
	__u64			 remaining, qunit;
	int			 slv_cnt;

	LASSERT(lqe->lqe_enforced && lqe->lqe_qunit != 0);

	slv_cnt = lqe2qpi(lqe)->qpi_slv_nr[lqe->lqe_site->lqs_qtype];
	qunit   = lqe->lqe_qunit;

	/* See comment in qmt_adjust_qunit(). LU-4139. */
	if (lqe->lqe_softlimit != 0) {
		bool oversoft;
		remaining = qmt_calc_softlimit(lqe, &oversoft);
		if (remaining == 0)
			remaining = lqe->lqe_granted +
				    pool->qpi_soft_least_qunit;
	} else {
		remaining = lqe->lqe_hardlimit;
	}

	if (lqe->lqe_granted >= remaining)
		RETURN(0);

	remaining -= lqe->lqe_granted;

	do {
		if (spare >= qunit)
			break;

		granted &= (qunit - 1);

		if (remaining > (slv_cnt * qunit) >> 1) {
			/* enough room to grant more space w/o additional
			 * shrinking ... at least for now */
			remaining -= (slv_cnt * qunit) >> 1;
		} else if (qunit != pool->qpi_least_qunit) {
			qunit >>= 2;
			continue;
		}

		granted &= (qunit - 1);
		if (spare > 0)
			RETURN(min_t(__u64, qunit - spare, remaining));
		else
			RETURN(min_t(__u64, qunit - granted, remaining));
	} while (qunit >= pool->qpi_least_qunit);

	RETURN(0);
}

/*
 * Adjust qunit size according to quota limits and total granted count.
 * The caller must have locked the lqe.
 *
 * \param env - the environment passed by the caller
 * \param lqe - is the qid entry to be adjusted
 */
void qmt_adjust_qunit(const struct lu_env *env, struct lquota_entry *lqe)
{
	struct qmt_pool_info	*pool = lqe2qpi(lqe);
	int			 slv_cnt;
	__u64			 qunit, limit, qunit2 = 0;
	ENTRY;

	LASSERT(lqe_is_locked(lqe));

	if (!lqe->lqe_enforced || lqe->lqe_id.qid_uid == 0)
		/* no quota limits */
		RETURN_EXIT;

	/* record how many slaves have already registered */
	slv_cnt = pool->qpi_slv_nr[lqe->lqe_site->lqs_qtype];
	if (slv_cnt == 0)
		/* wait for at least one slave to join */
		RETURN_EXIT;

	/* Qunit calculation is based on soft limit, if any, hard limit
	 * otherwise. This means that qunit is shrunk to the minimum when
	 * beyond the soft limit. This will impact performance, but that's the
	 * price of an accurate grace time management. */
	if (lqe->lqe_softlimit != 0) {
		bool oversoft;
		/* As a compromise of write performance and the grace time
		 * accuracy, the block qunit size will be shrunk to
		 * qpi_soft_least_qunit when over softlimit. LU-4139. */
		limit = qmt_calc_softlimit(lqe, &oversoft);
		if (oversoft)
			qunit2 = pool->qpi_soft_least_qunit;
		if (limit == 0)
			GOTO(done, qunit = qunit2);
	} else if (lqe->lqe_hardlimit != 0) {
		limit = lqe->lqe_hardlimit;
	} else {
		LQUOTA_ERROR(lqe, "enforced bit set, but neither hard nor soft "
			     "limit are set");
		RETURN_EXIT;
	}

	qunit = lqe->lqe_qunit == 0 ? pool->qpi_least_qunit : lqe->lqe_qunit;

	/* The qunit value is computed as follows: limit / (2 * slv_cnt).
	 * Then 75% of the quota space can be granted with current qunit value.
	 * The remaining 25% are then used with reduced qunit size (by a factor
	 * of 4) which is then divided in a similar manner.
	 *
	 * |---------------------limit---------------------|
	 * |-------limit / 2-------|-limit / 4-|-limit / 4-|
	 * |qunit|qunit|qunit|qunit|           |           |
	 * |----slv_cnt * qunit----|           |           |
	 * |-grow limit-|          |           |           |
	 * |--------------shrink limit---------|           |
	 * |---space granted in qunit chunks---|-remaining-|
	 *                                    /             \
	 *                                   /               \
	 *                                  /                 \
	 *                                 /                   \
	 *                                /                     \
	 *     qunit >>= 2;            |qunit*slv_cnt|qunit*slv_cnt|
	 *                             |---space in qunit---|remain|
	 *                                  ...                               */
	if (qunit == pool->qpi_least_qunit ||
	    limit >= lqe->lqe_granted + ((slv_cnt * qunit) >> 1)) {
		/* current qunit value still fits, let's see if we can afford to
		 * increase qunit now ...
		 * To increase qunit again, we have to be under 25% */
		while (qunit && limit >= lqe->lqe_granted + 6 * qunit * slv_cnt)
			qunit <<= 2;

		if (!qunit) {
			qunit = limit;
			do_div(qunit, 2 * slv_cnt);
		}

	} else {
		/* shrink qunit until we find a suitable value */
		while (qunit > pool->qpi_least_qunit &&
		       limit < lqe->lqe_granted + ((slv_cnt * qunit) >> 1))
			qunit >>= 2;
	}

	if (qunit2 && qunit > qunit2)
		qunit = qunit2;
done:
	if (lqe->lqe_qunit == qunit)
		/* keep current qunit */
		RETURN_EXIT;

	LQUOTA_DEBUG(lqe, "%s qunit to %llu",
		     lqe->lqe_qunit < qunit ? "increasing" : "decreasing",
		     qunit);

	/* store new qunit value */
	swap(lqe->lqe_qunit, qunit);

	/* reset revoke time */
	lqe->lqe_revoke_time = 0;

	if (lqe->lqe_qunit < qunit)
		/* let's notify slave of qunit shrinking */
		qmt_id_lock_notify(pool->qpi_qmt, lqe);
	else if (lqe->lqe_qunit == pool->qpi_least_qunit)
		/* initial qunit value is the smallest one */
		lqe->lqe_revoke_time = ktime_get_seconds();
	EXIT;
}

/*
 * Adjust qunit & edquot flag in case it wasn't initialized already (e.g.
 * limit set while no slaves were connected yet)
 */
void qmt_revalidate(const struct lu_env *env, struct lquota_entry *lqe)
{
	if (lqe->lqe_qunit == 0) {
		/* lqe was read from disk, but neither qunit, nor edquot flag
		 * were initialized */
		qmt_adjust_qunit(env, lqe);
		if (lqe->lqe_qunit != 0)
			qmt_adjust_edquot(lqe, ktime_get_real_seconds());
	}
}
