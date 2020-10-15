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

/* Apply the default quota setting to the specified quota entry
 *
 * \param env		- is the environment passed by the caller
 * \param pool		- is the quota pool of the quota entry
 * \param lqe		- is the lquota_entry object to apply default quota on
 * \param create_record	- if true, an global quota record will be created and
 *                        write to the disk.
 *
 * \retval 0		: success
 * \retval -ve		: other appropriate errors
 */
int qmt_lqe_set_default(const struct lu_env *env, struct qmt_pool_info *pool,
			struct lquota_entry *lqe, bool create_record)
{
	struct lquota_entry	*lqe_def;
	int			rc = 0;

	ENTRY;

	if (lqe->lqe_id.qid_uid == 0)
		RETURN(0);

	lqe_def = pool->qpi_grace_lqe[lqe_qtype(lqe)];

	LQUOTA_DEBUG(lqe, "inherit default quota");

	lqe->lqe_is_default = true;
	lqe->lqe_hardlimit = lqe_def->lqe_hardlimit;
	lqe->lqe_softlimit = lqe_def->lqe_softlimit;

	if (create_record) {
		lqe->lqe_uptodate = true;
		rc = qmt_set_with_lqe(env, pool->qpi_qmt, lqe, 0, 0,
				      LQUOTA_GRACE_FLAG(0, LQUOTA_FLAG_DEFAULT),
				      QIF_TIMES, true, false);

		if (rc != 0)
			LQUOTA_ERROR(lqe, "failed to create the global quota"
				     " record: %d", rc);
	}

	if (lqe->lqe_hardlimit == 0 && lqe->lqe_softlimit == 0)
		lqe->lqe_enforced = false;
	else
		lqe->lqe_enforced = true;

	RETURN(rc);
}

/*
 * Update a lquota entry. This is done by reading quota settings from the global
 * index. The lquota entry must be write locked.
 *
 * \param env - the environment passed by the caller
 * \param lqe - is the quota entry to refresh
 * \param arg - is the pointer to the qmt_pool_info structure
 * \param find - don't create lqe on disk in case of ENOENT if true
 */
static int qmt_lqe_read(const struct lu_env *env, struct lquota_entry *lqe,
			void *arg, bool find)
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
		if (find)
			RETURN(-ENOENT);
		qmt_lqe_set_default(env, pool, lqe, true);
		break;
	case 0:
		/* copy quota settings from on-disk record */
		lqe->lqe_granted   = qti->qti_glb_rec.qbr_granted;
		lqe->lqe_hardlimit = qti->qti_glb_rec.qbr_hardlimit;
		lqe->lqe_softlimit = qti->qti_glb_rec.qbr_softlimit;
		lqe->lqe_gracetime = LQUOTA_GRACE(qti->qti_glb_rec.qbr_time);

		if (lqe->lqe_hardlimit == 0 && lqe->lqe_softlimit == 0 &&
		    (LQUOTA_FLAG(qti->qti_glb_rec.qbr_time) &
		     LQUOTA_FLAG_DEFAULT))
			qmt_lqe_set_default(env, pool, lqe, false);
		break;
	default:
		LQUOTA_ERROR(lqe, "failed to read quota entry from disk, rc:%d",
			     rc);
		RETURN(rc);
	}

	if (lqe->lqe_id.qid_uid == 0 ||
	    (lqe->lqe_hardlimit == 0 && lqe->lqe_softlimit == 0))
		/* {hard,soft}limit=0 means no quota enforced */
		lqe->lqe_enforced = false;
	else
		lqe->lqe_enforced  = true;

	if (qmt_pool_global(pool))
		lqe->lqe_is_global = 1;

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
			  struct va_format *vaf)
{
	struct qmt_pool_info	*pool = (struct qmt_pool_info *)arg;

	libcfs_debug_msg(msgdata,
			 "%pV qmt:%s pool:%s-%s id:%llu enforced:%d hard:%llu soft:%llu granted:%llu time:%llu qunit: %llu edquot:%d may_rel:%llu revoke:%lld default:%s\n",
			 vaf, pool->qpi_qmt->qmt_svname,
			 RES_NAME(pool->qpi_rtype),
			 pool->qpi_name,
			 lqe->lqe_id.qid_uid, lqe->lqe_enforced,
			 lqe->lqe_hardlimit, lqe->lqe_softlimit,
			 lqe->lqe_granted, lqe->lqe_gracetime,
			 lqe->lqe_qunit, lqe->lqe_edquot, lqe->lqe_may_rel,
			 lqe->lqe_revoke_time,
			 lqe->lqe_is_default ? "yes" : "no");
}

/*
 * Vector of quota entry operations supported on the master
 */
const struct lquota_entry_operations qmt_lqe_ops = {
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
 *                  subject to the change. If it is NULL lqes array is
 *                  taken from env with qti_lqes_env(env).
 * \param slv_obj - is the dt_object associated with the index file
 * \param sync    - make transaction sync if true
 */
struct thandle *qmt_trans_start_with_slv(const struct lu_env *env,
					 struct lquota_entry *lqe,
					 struct dt_object *slv_obj,
					 bool sync)
{
	struct qmt_device	*qmt;
	struct thandle		*th;
	struct lquota_entry	**lqes;
	struct qmt_lqe_restore	*restore;
	int			 rc, i, lqes_cnt;
	ENTRY;

	restore = qti_lqes_rstr(env);
	if (!lqe) {
		lqes_cnt = qti_lqes_cnt(env);
		lqes = qti_lqes(env);
	} else {
		lqes_cnt = 1;
		lqes = &lqe;
	}

	/* qmt is the same for all lqes, so take it from the 1st */
	qmt = lqe2qpi(lqes[0])->qpi_qmt;

	if (slv_obj != NULL)
		LQUOTA_DEBUG(lqes[0], "declare write for slv "DFID,
			     PFID(lu_object_fid(&slv_obj->do_lu)));

	/* start transaction */
	th = dt_trans_create(env, qmt->qmt_child);
	if (IS_ERR(th))
		RETURN(th);

	if (sync)
		/* quota settings on master are updated synchronously for the
		 * time being */
		th->th_sync = 1;

	/* reserve credits for global index update */
	for (i = 0; i < lqes_cnt; i++) {
		rc = lquota_disk_declare_write(env, th,
					       LQE_GLB_OBJ(lqes[i]),
					       &lqes[i]->lqe_id);
		if (rc)
			GOTO(out, rc);
	}

	if (slv_obj != NULL) {
		/* reserve credits for slave index update */
		rc = lquota_disk_declare_write(env, th, slv_obj,
					       &lqes[0]->lqe_id);
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
		LQUOTA_ERROR(lqes[0], "failed to slv declare write for "DFID
			     ", rc:%d", PFID(lu_object_fid(&slv_obj->do_lu)),
			     rc);
	} else {
		for (i = 0; i < lqes_cnt; i++) {
			restore[i].qlr_hardlimit = lqes[i]->lqe_hardlimit;
			restore[i].qlr_softlimit = lqes[i]->lqe_softlimit;
			restore[i].qlr_gracetime = lqes[i]->lqe_gracetime;
			restore[i].qlr_granted   = lqes[i]->lqe_granted;
			restore[i].qlr_qunit     = lqes[i]->lqe_qunit;
		}
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
				struct lquota_entry *lqe)
{
	LQUOTA_DEBUG(lqe, "declare write");
	return qmt_trans_start_with_slv(env, lqe, NULL, true);
}

int qmt_glb_write_lqes(const struct lu_env *env, struct thandle *th,
		       __u32 flags, __u64 *ver)
{
	int i, rc;
	rc = 0;

	for (i = 0; i < qti_lqes_cnt(env); i++) {
		rc = qmt_glb_write(env, th, qti_lqes(env)[i], flags, ver);
		if (rc)
			break;
	}
	return rc;
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
	if (lqe->lqe_is_default) {
		rec->qbr_hardlimit = 0;
		rec->qbr_softlimit = 0;
		rec->qbr_time      = LQUOTA_GRACE_FLAG(0, LQUOTA_FLAG_DEFAULT);
	} else {
		rec->qbr_hardlimit = lqe->lqe_hardlimit;
		rec->qbr_softlimit = lqe->lqe_softlimit;
		rec->qbr_time      = lqe->lqe_gracetime;
	}

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
 * \param lqe_id - is the quota id associated with the identifier to look-up
 *              in the slave index
 * \param slv_obj - is the dt_object associated with the slave index
 * \param granted - is the output parameter where to return how much space
 *                  is granted to the slave.
 *
 * \retval    - 0 on success, appropriate error on failure
 */
int qmt_slv_read(const struct lu_env *env, union lquota_id *qid,
		 struct dt_object *slv_obj, __u64 *granted)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_slv_rec	*slv_rec = &qti->qti_slv_rec;
	int			 rc;
	ENTRY;

	CDEBUG(D_QUOTA, "read id:%llu form slv "DFID"\n",
	       qid->qid_uid, PFID(lu_object_fid(&slv_obj->do_lu)));

	/* read slave record from disk */
	rc = lquota_disk_read(env, slv_obj, qid,
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
		CERROR("Failed to read slave record for %llu from "DFID"\n",
		       qid->qid_uid, PFID(lu_object_fid(&slv_obj->do_lu)));
		RETURN(rc);
	}

	CDEBUG(D_QUOTA, "Successful slv read %llu\n", *granted);

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
		LQUOTA_ERROR(lqe,
			     "failed to update slave index "DFID" granted:%llu",
			     PFID(lu_object_fid(&slv_obj->do_lu)),
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
bool qmt_adjust_edquot(struct lquota_entry *lqe, __u64 now)
{
	struct qmt_pool_info	*pool = lqe2qpi(lqe);
	ENTRY;

	if (!lqe->lqe_enforced || lqe->lqe_id.qid_uid == 0)
		RETURN(false);

	if (!lqe->lqe_edquot) {
		/* space exhausted flag not set, let's check whether it is time
		 * to set the flag */

		if (!qmt_space_exhausted(lqe, now))
			/* the qmt still has available space */
			RETURN(false);

		/* See comment in qmt_adjust_qunit(). LU-4139 */
		if (qmt_hard_exhausted(lqe) ||
		    pool->qpi_rtype != LQUOTA_RES_DT) {
			time64_t lapse;

			/* we haven't reached the minimal qunit yet so there is
			 * still hope that the rebalancing process might free
			 * up some quota space */
			if (lqe->lqe_qunit != pool->qpi_least_qunit)
				RETURN(false);

			/* least qunit value not sent to all slaves yet */
			if (lqe->lqe_revoke_time == 0)
				RETURN(false);

			/* Let's give more time to slave to release space */
			lapse = ktime_get_seconds() - QMT_REBA_TIMEOUT;
			if (lqe->lqe_may_rel != 0 && lqe->lqe_revoke_time > lapse)
				RETURN(false);
		} else {
			if (lqe->lqe_qunit > pool->qpi_soft_least_qunit)
				RETURN(false);
		}

		/* set edquot flag */
		lqe->lqe_edquot = true;
	} else {
		/* space exhausted flag set, let's check whether it is time to
		 * clear it */

		if (qmt_space_exhausted(lqe, now))
			/* the qmt still has not space */
			RETURN(false);

		if (lqe->lqe_hardlimit != 0 &&
		    lqe->lqe_granted + pool->qpi_least_qunit >
							lqe->lqe_hardlimit)
			/* we clear the flag only once at least one least qunit
			 * is available */
			RETURN(false);

		/* clear edquot flag */
		lqe->lqe_edquot = false;
	}

	LQUOTA_DEBUG(lqe, "changing edquot flag");

	/* let's notify slave by issuing glimpse on per-ID lock.
	 * the rebalance thread will take care of this */
	RETURN(true);
}

/* Using least_qunit when over block softlimit will seriously impact the
 * write performance, we need to do some special tweaking on that. */
static __u64 qmt_calc_softlimit(struct lquota_entry *lqe, bool *oversoft)
{
	struct qmt_pool_info *pool = lqe2qpi(lqe);

	LASSERT(lqe->lqe_softlimit != 0);
	*oversoft = false;
	/* No need to do special tweaking for inode limit */
	if (pool->qpi_rtype != LQUOTA_RES_DT)
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

	slv_cnt = qpi_slv_nr(lqe2qpi(lqe), lqe_qtype(lqe));
	qunit = lqe->lqe_qunit;

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
 * \retval true - need reseed glbe array
 */
bool qmt_adjust_qunit(const struct lu_env *env, struct lquota_entry *lqe)
{
	struct qmt_pool_info	*pool = lqe2qpi(lqe);
	bool			 need_reseed = false;
	int			 slv_cnt;
	__u64			 qunit, limit, qunit2 = 0;
	ENTRY;

	LASSERT(lqe_is_locked(lqe));

	if (!lqe->lqe_enforced || lqe->lqe_id.qid_uid == 0)
		/* no quota limits */
		RETURN(need_reseed);

	/* record how many slaves have already registered */
	slv_cnt = qpi_slv_nr(pool, lqe_qtype(lqe));
	if (slv_cnt == 0) {
		/* Pool hasn't slaves anymore. Qunit will be adjusted
		 * again when new slaves would be added. */
		if (lqe->lqe_qunit) {
			qunit = 0;
			GOTO(done, qunit);
		}
		/* wait for at least one slave to join */
		RETURN(need_reseed);
	}

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
		RETURN(need_reseed);
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
		RETURN(need_reseed);

	LQUOTA_DEBUG(lqe, "%s qunit to %llu",
		     lqe->lqe_qunit < qunit ? "increasing" : "decreasing",
		     qunit);

	/* store new qunit value */
	swap(lqe->lqe_qunit, qunit);

	/* reseed glbe array and notify
	 * slave if qunit was shrinked */
	need_reseed = true;
	/* reset revoke time */
	lqe->lqe_revoke_time = 0;

	if (lqe->lqe_qunit >= qunit &&
	    (lqe->lqe_qunit == pool->qpi_least_qunit)) {
		/* initial qunit value is the smallest one */
		lqe->lqe_revoke_time = ktime_get_seconds();
	}
	RETURN(need_reseed);
}

bool qmt_adjust_edquot_qunit_notify(const struct lu_env *env,
				    struct qmt_device *qmt,
				    __u64 now, bool edquot,
				    bool qunit, __u32 qb_flags)
{
	struct lquota_entry *lqe_gl, *lqe;
	bool need_reseed = false;
	int i;

	lqe_gl = qti_lqes_glbl(env);

	for (i = 0; i < qti_lqes_cnt(env); i++) {
		lqe = qti_lqes(env)[i];
		if (qunit)
			need_reseed |= qmt_adjust_qunit(env, lqe);
		if (edquot)
			need_reseed |= qmt_adjust_edquot(lqe, now);
	}

	LASSERT(lqe_gl);
	if (!lqe_gl->lqe_glbl_data &&
	    (req_has_rep(qb_flags) || req_is_rel(qb_flags))) {
		if (need_reseed)
			CDEBUG(D_QUOTA,
			       "%s: can not notify - lge_glbl_data is not set\n",
			       qmt->qmt_svname);
		return need_reseed;
	}

	if (lqe_gl->lqe_glbl_data && need_reseed) {
		qmt_seed_glbe_all(env, lqe_gl->lqe_glbl_data, qunit, edquot);
		qmt_id_lock_notify(qmt, lqe_gl);
	}
	return need_reseed;
}


/*
 * Adjust qunit & edquot flag in case it wasn't initialized already (e.g.
 * limit set while no slaves were connected yet)
 */
bool qmt_revalidate(const struct lu_env *env, struct lquota_entry *lqe)
{
	bool need_notify = false;

	if (lqe->lqe_qunit == 0) {
		/* lqe was read from disk, but neither qunit, nor edquot flag
		 * were initialized */
		need_notify = qmt_adjust_qunit(env, lqe);
		if (lqe->lqe_qunit != 0)
			need_notify |= qmt_adjust_edquot(lqe,
						ktime_get_real_seconds());
	}

	return need_notify;
}

void qmt_revalidate_lqes(const struct lu_env *env,
			 struct qmt_device *qmt, __u32 qb_flags)
{
	struct lquota_entry *lqe_gl = qti_lqes_glbl(env);
	bool need_notify = false;
	int i;

	for (i = 0; i < qti_lqes_cnt(env); i++)
		need_notify |= qmt_revalidate(env, qti_lqes(env)[i]);

	/* There could be no ID lock to the moment of reconciliation.
	 * As a result lqe global data is not initialised yet. It is ok
	 * for release and report requests. */
	if (!lqe_gl->lqe_glbl_data &&
	    (req_is_rel(qb_flags) || req_has_rep(qb_flags)))
		return;

	if (need_notify) {
		qmt_seed_glbe(env, lqe_gl->lqe_glbl_data);
		qmt_id_lock_notify(qmt, lqe_gl);
	}
}

void qti_lqes_init(const struct lu_env *env)
{
	struct qmt_thread_info	*qti = qmt_info(env);

	qti->qti_lqes_cnt = 0;
	qti->qti_glbl_lqe_idx = 0;
	qti->qti_lqes_num = QMT_MAX_POOL_NUM;
}

int qti_lqes_add(const struct lu_env *env, struct lquota_entry *lqe)
{
	struct qmt_thread_info	*qti = qmt_info(env);

	if (qti->qti_lqes_cnt > qti->qti_lqes_num) {
		struct lquota_entry	**lqes;
		lqes = qti->qti_lqes;
		OBD_ALLOC(lqes, sizeof(lqe) * qti->qti_lqes_num * 2);
		if (!lqes)
			return -ENOMEM;
		memcpy(lqes, qti_lqes(env), qti->qti_lqes_cnt * sizeof(lqe));
		/* Don't need to free, if it is the very 1st allocation */
		if (qti->qti_lqes_num > QMT_MAX_POOL_NUM)
			OBD_FREE(qti->qti_lqes,
				 qti->qti_lqes_num * sizeof(lqe));
		qti->qti_lqes = lqes;
		qti->qti_lqes_num *= 2;
	}

	if (lqe->lqe_is_global)
		qti->qti_glbl_lqe_idx = qti->qti_lqes_cnt;
	qti_lqes(env)[qti->qti_lqes_cnt++] = lqe;

	/* The pool could be accessed directly from lqe, so take
	 * extra reference that is put in qti_lqes_fini */
	qpi_getref(lqe2qpi(lqe));

	CDEBUG(D_QUOTA, "LQE %p %lu is added, lqe_cnt %d lqes_num %d\n",
			 lqe, (long unsigned)lqe->lqe_id.qid_uid,
			 qti->qti_lqes_cnt, qti->qti_lqes_num);
	LASSERT(qti->qti_lqes_num != 0);

	return 0;
}

void qti_lqes_del(const struct lu_env *env, int index)
{
	struct lquota_entry	**lqes;
	int lqes_cnt = qti_lqes_cnt(env);
	int lqep_size = sizeof(struct lquota_entry *);

	if (index == 0) {
		/* We can't handle non global lqes correctly without
		 * global lqe located at index 0. If we try to do so,
		 * something goes wrong. */
		LQUOTA_ERROR(qti_lqes_glbl(env),
			     "quota: cannot remove lqe at index 0 as it is global");
		LASSERT(qti_lqes_glbl(env)->lqe_is_global);
		return;
	}
	lqes = qti_lqes(env);
	qpi_putref(env, lqe2qpi(lqes[index]));
	lqe_putref(lqes[index]);
	memcpy((unsigned char *)lqes + index * lqep_size,
	       (unsigned char *)lqes + (index + 1) * lqep_size,
	       (lqes_cnt - index - 1) * lqep_size);
	qti_lqes_cnt(env)--;
}

void qti_lqes_fini(const struct lu_env *env)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_entry	**lqes = qti->qti_lqes;
	int i;

	lqes = qti_lqes(env);
	for (i = 0; i < qti->qti_lqes_cnt; i++) {
		qpi_putref(env, lqe2qpi(lqes[i]));
		lqe_putref(lqes[i]);
	}

	if (qti->qti_lqes_num > QMT_MAX_POOL_NUM)
		OBD_FREE(qti->qti_lqes,
			 qti->qti_lqes_num * sizeof(struct lquota_entry *));
}

int qti_lqes_min_qunit(const struct lu_env *env)
{
	int i, min, qunit;

	for (i = 1, min = qti_lqe_qunit(env, 0); i < qti_lqes_cnt(env); i++) {
		qunit = qti_lqe_qunit(env, i);
		if (qunit < min)
			min = qunit;
	}

	return min;
}

int qti_lqes_edquot(const struct lu_env *env)
{
	int i;

	for (i = 0; i < qti_lqes_cnt(env); i++) {
		if (qti_lqes(env)[i]->lqe_edquot)
			return 1;
	}

	return 0;
}

int qti_lqes_restore_init(const struct lu_env *env)
{
	int rc = 0;

	if (qti_lqes_cnt(env) > QMT_MAX_POOL_NUM) {
		OBD_ALLOC(qmt_info(env)->qti_lqes_rstr,
			  qti_lqes_cnt(env) * sizeof(struct qmt_lqe_restore));
		if (!qti_lqes_rstr(env))
			rc = -ENOMEM;
	}

	return rc;
}

void qti_lqes_restore_fini(const struct lu_env *env)
{
	if (qti_lqes_cnt(env) > QMT_MAX_POOL_NUM)
		OBD_FREE(qmt_info(env)->qti_lqes_rstr,
			 qti_lqes_cnt(env) * sizeof(struct qmt_lqe_restore));
}

void qti_lqes_write_lock(const struct lu_env *env)
{
	int i;

	for (i = 0; i < qti_lqes_cnt(env); i++)
		lqe_write_lock(qti_lqes(env)[i]);
}

void qti_lqes_write_unlock(const struct lu_env *env)
{
	int i;

	for (i = 0; i < qti_lqes_cnt(env); i++)
		lqe_write_unlock(qti_lqes(env)[i]);
}

#define QMT_INIT_SLV_CNT	64
struct lqe_glbl_data *qmt_alloc_lqe_gd(struct qmt_pool_info *pool, int qtype)
{
	struct lqe_glbl_data	*lgd;
	struct lqe_glbl_entry	*lqeg_arr;
	int			 slv_cnt, glbe_num;

	OBD_ALLOC(lgd, sizeof(struct lqe_glbl_data));
	if (!lgd)
		RETURN(NULL);

	slv_cnt = qpi_slv_nr_by_rtype(pool, qtype);

	glbe_num = slv_cnt < QMT_INIT_SLV_CNT ? QMT_INIT_SLV_CNT : slv_cnt;
	OBD_ALLOC(lqeg_arr, sizeof(struct lqe_glbl_entry) * glbe_num);
	if (!lqeg_arr) {
		OBD_FREE(lgd, sizeof(struct lqe_glbl_data));
		RETURN(NULL);
	}

	CDEBUG(D_QUOTA, "slv_cnt %d glbe_num %d\n", slv_cnt, glbe_num);

	lgd->lqeg_num_used = slv_cnt;
	lgd->lqeg_num_alloc = glbe_num;
	lgd->lqeg_arr = lqeg_arr;

	RETURN(lgd);
}

void qmt_free_lqe_gd(struct lqe_glbl_data *lgd)
{
	OBD_FREE(lgd->lqeg_arr,
		 sizeof(struct lqe_glbl_entry) * lgd->lqeg_num_alloc);
	OBD_FREE(lgd, sizeof(struct lqe_glbl_data));
}

void qmt_seed_glbe_all(const struct lu_env *env, struct lqe_glbl_data *lgd,
		       bool qunit, bool edquot)
{
	struct rw_semaphore	*sem = NULL;
	struct qmt_pool_info	*qpi;
	int			 i, j, idx;
	ENTRY;

	/* lqes array is sorted by qunit - the first entry has minimum qunit.
	 * Thus start seeding global qunit's array beginning from the 1st lqe
	 * and appropriate pool. If pools overlapped, slaves from this
	 * overlapping get minimum qunit value.
	 * user1: pool1, pool2, pool_glbl;
	 * pool1: OST1; user1_qunit = 10M;
	 * pool2: OST0, OST1, OST2; user1_qunit = 30M;
	 * pool_glbl: OST0, OST1, OST2, OST3; user1_qunit = 160M;
	 * qunit array after seeding should be:
	 * OST0: 30M; OST1: 10M; OST2: 30M; OST3: 160M; */

	/* edquot resetup algorythm works fine
	 * with not sorted lqes */
	if (qunit)
		qmt_lqes_sort(env);

	for (i = 0; i < lgd->lqeg_num_used; i++) {
		lgd->lqeg_arr[i].lge_qunit_set = 0;
		lgd->lqeg_arr[i].lge_qunit_nu = 0;
		lgd->lqeg_arr[i].lge_edquot_nu = 0;
	}

	for (i = 0; i < qti_lqes_cnt(env); i++) {
		struct lquota_entry *lqe = qti_lqes(env)[i];
		int slaves_cnt;

		CDEBUG(D_QUOTA, "lqes_cnt %d, i %d\n", qti_lqes_cnt(env), i);
		qpi = lqe2qpi(lqe);
		if (qmt_pool_global(qpi)) {
			slaves_cnt = qpi_slv_nr_by_rtype(lqe2qpi(lqe),
							 lqe_qtype(lqe));
		} else {
			sem = qmt_sarr_rwsem(qpi);
			down_read(sem);
			slaves_cnt = qmt_sarr_count(qpi);
		}

		for (j = 0; j < slaves_cnt; j++) {
			idx = qmt_sarr_get_idx(qpi, j);
			LASSERT(idx >= 0);

			if (edquot) {
				int lge_edquot, new_edquot, edquot_nu;

				lge_edquot = lgd->lqeg_arr[idx].lge_edquot;
				edquot_nu = lgd->lqeg_arr[idx].lge_edquot_nu;
				new_edquot = lqe->lqe_edquot;

				if (lge_edquot == new_edquot ||
				    (edquot_nu && lge_edquot == 1))
					goto qunit_lbl;
				lgd->lqeg_arr[idx].lge_edquot = new_edquot;
				/* it is needed for the following case:
				 * initial values for idx i -
				 * lqe_edquot = 1, lqe_edquot_nu == 0;
				 * 1: new_edquot == 0 ->
				 *	lqe_edquot = 0, lqe_edquot_nu = 1;
				 * 2: new_edquot == 1 ->
				 *	lqe_edquot = 1, lqe_edquot_nu = 0;
				 * At the 2nd iteration lge_edquot comes back
				 * to 1, so no changes and we don't need
				 * to notify slave. */
				lgd->lqeg_arr[idx].lge_edquot_nu = !edquot_nu;
			}
qunit_lbl:
			if (qunit) {
				__u64 lge_qunit, new_qunit;

				CDEBUG(D_QUOTA,
				       "idx %d lge_qunit_set %d lge_qunit %llu new_qunit %llu\n",
				       idx, lgd->lqeg_arr[idx].lge_qunit_set,
				       lgd->lqeg_arr[idx].lge_qunit,
				       lqe->lqe_qunit);
				/* lge for this idx is already set
				 * on previous iteration */
				if (lgd->lqeg_arr[idx].lge_qunit_set)
					continue;
				lge_qunit = lgd->lqeg_arr[idx].lge_qunit;
				new_qunit = lqe->lqe_qunit;
				/* qunit could be not set,
				 * so use global lqe's qunit */
				if (!new_qunit)
					continue;

				if (lge_qunit != new_qunit)
					lgd->lqeg_arr[idx].lge_qunit =
								new_qunit;

				/* TODO: initially slaves notification was done
				 * only for qunit shrinking. Should we always
				 * notify slaves with new qunit ? */
				if (lge_qunit > new_qunit)
					lgd->lqeg_arr[idx].lge_qunit_nu = 1;
				lgd->lqeg_arr[idx].lge_qunit_set = 1;
			}
		}

		if (!qmt_pool_global(qpi))
			up_read(sem);
	}
	/* TODO: only for debug purposes - remove it later */
	for (i = 0; i < lgd->lqeg_num_used; i++)
		CDEBUG(D_QUOTA,
			"lgd ost %d, qunit %lu nu %d;  edquot %d nu %d\n",
			i, (long unsigned)lgd->lqeg_arr[i].lge_qunit,
			lgd->lqeg_arr[i].lge_qunit_nu,
			lgd->lqeg_arr[i].lge_edquot,
			lgd->lqeg_arr[i].lge_edquot_nu);

	EXIT;
}

void qmt_setup_lqe_gd(const struct lu_env *env, struct qmt_device *qmt,
		      struct lquota_entry *lqe, struct lqe_glbl_data *lgd,
		      int pool_type)
{
	__u64			 qunit;
	bool			 edquot;
	int			 i;

	qunit = lqe->lqe_qunit;
	edquot = lqe->lqe_edquot;

	/* Firstly set all elements in array with
	 * qunit and edquot of global pool */
	for (i = 0; i < lgd->lqeg_num_used; i++) {
		lgd->lqeg_arr[i].lge_qunit = qunit;
		lgd->lqeg_arr[i].lge_edquot = edquot;
		/* It is the very first lvb setup - qunit and other flags
		 * will be sent to slaves during qmt_lvbo_fill. */
		lgd->lqeg_arr[i].lge_qunit_nu = 0;
		lgd->lqeg_arr[i].lge_edquot_nu = 0;
	}

	qmt_pool_lqes_lookup_spec(env, qmt, pool_type,
				  lqe_qtype(lqe), &lqe->lqe_id);
	qmt_seed_glbe(env, lgd);

	lqe->lqe_glbl_data = lgd;
	qmt_id_lock_notify(qmt, lqe);

	qti_lqes_fini(env);
}
