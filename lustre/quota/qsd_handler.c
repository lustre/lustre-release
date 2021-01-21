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
 * Copyright (c) 2012, 2017, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include "qsd_internal.h"

/**
 * helper function bumping lqe_pending_req if there is no quota request in
 * flight for the lquota entry \a lqe. Otherwise, EBUSY is returned.
 */
static inline int qsd_request_enter(struct lquota_entry *lqe)
{
	/* is there already a quota request in flight? */
	if (lqe->lqe_pending_req != 0) {
		LQUOTA_DEBUG(lqe, "already a request in flight");
		return -EBUSY;
	}

	if (lqe->lqe_pending_rel != 0) {
		LQUOTA_ERROR(lqe, "no request in flight with pending_rel=%llu",
			     lqe->lqe_pending_rel);
		LBUG();
	}

	lqe->lqe_pending_req++;
	return 0;
}

/**
 * Companion of qsd_request_enter() dropping lqe_pending_req to 0.
 */
static inline void qsd_request_exit(struct lquota_entry *lqe)
{
	if (lqe->lqe_pending_req != 1) {
		LQUOTA_ERROR(lqe, "lqe_pending_req != 1!!!");
		LBUG();
	}
	lqe->lqe_pending_req--;
	lqe->lqe_pending_rel = 0;
	wake_up(&lqe->lqe_waiters);
}

/**
 * Check whether a qsd instance is all set to send quota request to master.
 * This includes checking whether:
 * - the connection to master is set up and usable,
 * - the qsd isn't stopping
 * - reintegration has been successfully completed and all indexes are
 *   up-to-date
 *
 * \param lqe - is the lquota entry for which we would like to send an quota
 *              request
 * \param lockh - is the remote handle of the global lock returned on success
 *
 * \retval 0 on success, appropriate error on failure
 */
static int qsd_ready(struct lquota_entry *lqe, struct lustre_handle *lockh)
{
	struct qsd_qtype_info	*qqi = lqe2qqi(lqe);
	struct qsd_instance	*qsd = qqi->qqi_qsd;
	struct obd_import	*imp = NULL;
	struct ldlm_lock	*lock;
	ENTRY;

	read_lock(&qsd->qsd_lock);
	/* is the qsd about to shut down? */
	if (qsd->qsd_stopping) {
		read_unlock(&qsd->qsd_lock);
		LQUOTA_DEBUG(lqe, "dropping quota req since qsd is stopping");
		/* Target is about to shut down, client will retry */
		RETURN(-EINPROGRESS);
	}

	/* is the connection to the quota master ready? */
	if (qsd->qsd_exp_valid)
		imp = class_exp2cliimp(qsd->qsd_exp);
	if (imp == NULL || imp->imp_invalid) {
		read_unlock(&qsd->qsd_lock);
		LQUOTA_DEBUG(lqe, "connection to master not ready");
		RETURN(-ENOTCONN);
	}

	/* In most case, reintegration must have been triggered (when enable
	 * quota or on OST start), however, in rare race condition (enabling
	 * quota when starting OSTs), we might miss triggering reintegration
	 * for some qqi.
	 *
	 * If the previous reintegration failed for some reason, we'll
	 * re-trigger it here as well. */
	if (!qqi->qqi_glb_uptodate || !qqi->qqi_slv_uptodate) {
		read_unlock(&qsd->qsd_lock);
		LQUOTA_DEBUG(lqe, "not up-to-date, dropping request and "
			     "kicking off reintegration");
		qsd_start_reint_thread(qqi);
		RETURN(-EINPROGRESS);
	}

	/* Fill the remote global lock handle, master will check this handle
	 * to see if the slave is sending request with stale lock */
	lustre_handle_copy(lockh, &qqi->qqi_lockh);
	read_unlock(&qsd->qsd_lock);

	if (!lustre_handle_is_used(lockh))
		RETURN(-ENOLCK);

	lock = ldlm_handle2lock(lockh);
	if (lock == NULL)
		RETURN(-ENOLCK);

	/* return remote lock handle to be packed in quota request */
	lustre_handle_copy(lockh, &lock->l_remote_handle);
	LDLM_LOCK_PUT(lock);

	RETURN(0);
}

/**
 * Check whether any quota space adjustment (pre-acquire/release/report) is
 * needed for a given quota ID. If a non-null \a qbody is passed, then the
 * \a qbody structure (qb_count/flags/usage) is filled with appropriate data
 * to be packed in the quota request.
 *
 * \param lqe   - is the lquota entry for which we would like to adjust quota
 *                space.
 * \param qbody - is the quota body to fill, if not NULL.
 *
 * \retval true  - space adjustment is required and \a qbody is filled, if not
 *                 NULL
 * \retval false - no space adjustment required
 */
static bool qsd_calc_adjust(struct lquota_entry *lqe, struct quota_body *qbody)
{
	__u64	usage, granted;
	ENTRY;

	usage   = lqe->lqe_usage;
	usage  += lqe->lqe_pending_write + lqe->lqe_waiting_write;
	granted = lqe->lqe_granted;

	if (qbody != NULL)
		qbody->qb_flags = 0;

	if (!lqe->lqe_enforced) {
		/* quota not enforced any more for this ID */
		if (granted != 0) {
			/* release all quota space unconditionally */
			LQUOTA_DEBUG(lqe, "not enforced, releasing all space");
			if (qbody != NULL) {
				qbody->qb_count = granted;
				qbody->qb_flags = QUOTA_DQACQ_FL_REL;
			}
			RETURN(true);
		}
		RETURN(false);
	}

	if (!lustre_handle_is_used(&lqe->lqe_lockh)) {
		/* No valid per-ID lock
		 * When reporting quota (during reintegration or on setquota
		 * glimpse), we should release granted space if usage is 0.
		 * Otherwise, if the usage is less than granted, we need to
		 * acquire the per-ID lock to make sure the unused grant can be
		 * reclaimed by per-ID lock glimpse. */
		if (usage == 0) {
			/* no on-disk usage and no outstanding activity, release
			 * space */
			if (granted != 0) {
				LQUOTA_DEBUG(lqe, "no usage, releasing all "
					     "space");
				if (qbody != NULL) {
					qbody->qb_count = granted;
					qbody->qb_flags = QUOTA_DQACQ_FL_REL;
				}
				RETURN(true);
			}
			LQUOTA_DEBUG(lqe, "no usage + no granted, nothing to "
				     "do");
			RETURN(false);
		}

		if (lqe->lqe_usage < lqe->lqe_granted) {
			/* holding quota space w/o any lock, enqueue per-ID lock
			 * again */
			LQUOTA_DEBUG(lqe, "(re)acquiring per-ID lock");
			if (qbody != NULL) {
				qbody->qb_count = 0;
				qbody->qb_flags = QUOTA_DQACQ_FL_ACQ;
			}
			RETURN(true);
		}

		if (lqe->lqe_usage > lqe->lqe_granted) {
			/* quota overrun, report usage */
			LQUOTA_DEBUG(lqe, "overrun, reporting usage");
			if (qbody != NULL) {
				qbody->qb_usage = lqe->lqe_usage;
				qbody->qb_flags = QUOTA_DQACQ_FL_REPORT;
			}
			RETURN(true);
		}
		LQUOTA_DEBUG(lqe, "granted matches usage, nothing to do");
		RETURN(false);
	}

	/* valid per-ID lock
	 * Apply good old quota qunit adjustment logic which has been around
	 * since lustre 1.4:
	 * 1. release spare quota space? */
	if (granted > usage + lqe->lqe_qunit) {
		/* pre-release quota space */
		if (qbody == NULL)
			RETURN(true);
		qbody->qb_count = granted - usage;
		/* if usage == 0, release all granted space */
		if (usage) {
			/* try to keep one qunit of quota space */
			qbody->qb_count -= lqe->lqe_qunit;
			/* but don't release less than qtune to avoid releasing
			 * space too often */
			if (qbody->qb_count < lqe->lqe_qtune)
				qbody->qb_count = lqe->lqe_qtune;
		}
		qbody->qb_flags = QUOTA_DQACQ_FL_REL;
		RETURN(true);
	}

	/* 2. Any quota overrun? */
	if (lqe->lqe_usage > lqe->lqe_granted) {
		/* we overconsumed quota space, we report usage in request so
		 * that master can adjust it unconditionally */
		if (qbody == NULL)
			RETURN(true);
		qbody->qb_usage = lqe->lqe_usage;
		granted         = lqe->lqe_usage;
		qbody->qb_flags = QUOTA_DQACQ_FL_REPORT;
	}

	/* 3. Time to pre-acquire? */
	if (!lqe->lqe_edquot && !lqe->lqe_nopreacq && usage > 0 &&
	    lqe->lqe_qunit != 0 && granted < usage + lqe->lqe_qtune) {
		/* To pre-acquire quota space, we report how much spare quota
		 * space the slave currently owns, then the master will grant us
		 * back how much we can pretend given the current state of
		 * affairs */
		if (qbody == NULL)
			RETURN(true);
		if (granted <= usage)
			qbody->qb_count = 0;
		else
			qbody->qb_count = granted - usage;
		qbody->qb_flags |= QUOTA_DQACQ_FL_PREACQ;
		RETURN(true);
	}

	if (qbody != NULL)
		RETURN(qbody->qb_flags != 0);
	else
		RETURN(false);
}

/**
 * Helper function returning true when quota space need to be adjusted (some
 * unused space should be free or pre-acquire) and false otherwise.
 */
static inline bool qsd_adjust_needed(struct lquota_entry *lqe)
{
	return qsd_calc_adjust(lqe, NULL);
}

/**
 * Callback function called when an acquire/release request sent to the master
 * is completed
 */
static void qsd_req_completion(const struct lu_env *env,
			       struct qsd_qtype_info *qqi,
			       struct quota_body *reqbody,
			       struct quota_body *repbody,
			       struct lustre_handle *lockh,
			       struct lquota_lvb *lvb,
			       void *arg, int ret)
{
	struct lquota_entry	*lqe = (struct lquota_entry *)arg;
	struct qsd_thread_info	*qti;
	int			 rc;
	bool			 adjust = false, cancel = false;
	ENTRY;

	LASSERT(qqi != NULL && lqe != NULL);

	/* environment passed by ptlrpcd is mostly used by CLIO and hasn't the
	 * DT tags set. */
	rc = lu_env_refill_by_tags((struct lu_env *)env, LCT_DT_THREAD, 0);
	if (rc) {
		LQUOTA_ERROR(lqe, "failed to refill environmnent %d", rc);
		lqe_write_lock(lqe);
		/* can't afford to adjust quota space with no suitable lu_env */
		GOTO(out_noadjust, rc);
	}
	qti = qsd_info(env);

	lqe_write_lock(lqe);
	LQUOTA_DEBUG(lqe, "DQACQ returned %d, flags:0x%x", ret,
		     reqbody->qb_flags);

	/* despite -EDQUOT & -EINPROGRESS errors, the master might still
	 * grant us back quota space to adjust quota overrun */
	if (ret != 0 && ret != -EDQUOT && ret != -EINPROGRESS) {
		if (ret != -ETIMEDOUT && ret != -ENOTCONN &&
		   ret != -ESHUTDOWN && ret != -EAGAIN)
			/* print errors only if return code is unexpected */
			LQUOTA_ERROR(lqe, "DQACQ failed with %d, flags:0x%x",
				     ret, reqbody->qb_flags);
		GOTO(out, ret);
	}

	/* Set the lqe_lockh */
	if (lustre_handle_is_used(lockh) &&
	    !lustre_handle_equal(lockh, &lqe->lqe_lockh))
		lustre_handle_copy(&lqe->lqe_lockh, lockh);

	/* If the replied qb_count is zero, it means master didn't process
	 * the DQACQ since the limit for this ID has been removed, so we
	 * should not update quota entry & slave index copy neither. */
	if (repbody != NULL && repbody->qb_count != 0) {
		LQUOTA_DEBUG(lqe, "DQACQ qb_count:%llu", repbody->qb_count);

		if (req_is_rel(reqbody->qb_flags)) {
			if (lqe->lqe_granted < repbody->qb_count) {
				LQUOTA_ERROR(lqe, "can't release more space "
					     "than owned %llu<%llu",
					     lqe->lqe_granted,
					     repbody->qb_count);
				lqe->lqe_granted = 0;
			} else {
				lqe->lqe_granted -= repbody->qb_count;
			}
			/* Cancel the per-ID lock initiatively when there
			 * isn't any usage & grant, which can avoid master
			 * sending glimpse unnecessarily to this slave on
			 * quota revoking */
			if (!lqe->lqe_pending_write && !lqe->lqe_granted &&
			    !lqe->lqe_waiting_write && !lqe->lqe_usage)
				cancel = true;
		} else {
			lqe->lqe_granted += repbody->qb_count;
		}
		qti->qti_rec.lqr_slv_rec.qsr_granted = lqe->lqe_granted;
		lqe_write_unlock(lqe);

		/* Update the slave index file in the dedicated thread. So far,
		 * We don't update the version of slave index copy on DQACQ.
		 * No locking is necessary since nobody can change
		 * lqe->lqe_granted while lqe->lqe_pending_req > 0 */
		qsd_upd_schedule(qqi, lqe, &lqe->lqe_id, &qti->qti_rec, 0,
				 false);
		lqe_write_lock(lqe);
	}

	/* extract information from lvb */
	if (ret == 0 && lvb != NULL) {
		if (lvb->lvb_id_qunit != 0)
			qsd_set_qunit(lqe, lvb->lvb_id_qunit);
		qsd_set_edquot(lqe, !!(lvb->lvb_flags & LQUOTA_FL_EDQUOT));
	} else if (repbody != NULL && repbody->qb_qunit != 0) {
		qsd_set_qunit(lqe, repbody->qb_qunit);
	}

	/* turn off pre-acquire if it failed with -EDQUOT. This is done to avoid
	 * flooding the master with acquire request. Pre-acquire will be turned
	 * on again as soon as qunit is modified */
	if (req_is_preacq(reqbody->qb_flags) && ret == -EDQUOT)
		lqe->lqe_nopreacq = true;
out:
	adjust = qsd_adjust_needed(lqe);
	if (reqbody && req_is_acq(reqbody->qb_flags) && ret != -EDQUOT) {
		lqe->lqe_acq_rc = ret;
		lqe->lqe_acq_time = ktime_get_seconds();
	}
out_noadjust:
	qsd_request_exit(lqe);
	lqe_write_unlock(lqe);

	/* release reference on per-ID lock */
	if (lustre_handle_is_used(lockh))
		ldlm_lock_decref(lockh, qsd_id_einfo.ei_mode);

	if (cancel) {
		qsd_adjust_schedule(lqe, false, true);
	} else if (adjust) {
		if (!ret || ret == -EDQUOT)
			qsd_adjust_schedule(lqe, false, false);
		else
			qsd_adjust_schedule(lqe, true, false);
	}
	lqe_putref(lqe);

	if (lvb)
		OBD_FREE_PTR(lvb);
	EXIT;
}

/**
 * Try to consume local quota space.
 *
 * \param lqe   - is the qid entry to be processed
 * \param space - is the amount of quota space needed to complete the operation
 *
 * \retval 0       - success
 * \retval -EDQUOT - out of quota
 * \retval -EAGAIN - need to acquire space from master
 */
static int qsd_acquire_local(struct lquota_entry *lqe, __u64 space)
{
	__u64	usage;
	int	rc;
	ENTRY;

	if (!lqe->lqe_enforced)
		/* not enforced any more, we are good */
		RETURN(-ESRCH);

	lqe_write_lock(lqe);
	/* use latest usage */
	usage = lqe->lqe_usage;
	/* take pending write into account */
	usage += lqe->lqe_pending_write;

	if (space + usage <= lqe->lqe_granted - lqe->lqe_pending_rel) {
		/* Yay! we got enough space */
		lqe->lqe_pending_write += space;
		lqe->lqe_waiting_write -= space;
		rc = 0;
	/* lqe_edquot flag is used to avoid flooding dqacq requests when
	 * the user is over quota, however, the lqe_edquot could be stale
	 * sometimes due to the race reply of dqacq vs. id lock glimpse
	 * (see LU-4505), so we revalidate it every 5 seconds. */
	} else if (lqe->lqe_edquot &&
		   (lqe->lqe_edquot_time > ktime_get_seconds() - 5)) {
		rc = -EDQUOT;
	}else {
		rc = -EAGAIN;
	}
	lqe_write_unlock(lqe);

	RETURN(rc);
}

/**
 * Compute how much quota space should be acquire from the master based
 * on how much is currently granted to this slave and pending/waiting
 * operations.
 *
 * \param lqe - is the lquota entry for which we would like to adjust quota
 *              space.
 * \param qbody - is the quota body of the acquire request to fill
 *
 * \retval true  - space acquisition is needed and qbody is filled
 * \retval false - no space acquisition required
 */
static inline bool qsd_calc_acquire(struct lquota_entry *lqe,
				    struct quota_body *qbody)
{
	__u64	usage, granted;

	usage   = lqe->lqe_usage;
	usage  += lqe->lqe_pending_write + lqe->lqe_waiting_write;
	granted = lqe->lqe_granted;

	qbody->qb_flags = 0;

	/* if we overconsumed quota space, we report usage in request so that
	 * master can adjust it unconditionally */
	if (lqe->lqe_usage > lqe->lqe_granted) {
		qbody->qb_usage = lqe->lqe_usage;
		qbody->qb_flags = QUOTA_DQACQ_FL_REPORT;
		granted = lqe->lqe_usage;
	}

	/* acquire as much as needed, but not more */
	if (usage > granted) {
		qbody->qb_count  = usage - granted;
		qbody->qb_flags |= QUOTA_DQACQ_FL_ACQ;
	}

	return qbody->qb_flags != 0;
}

/**
 * Acquire quota space from master.
 * There are at most 1 in-flight dqacq/dqrel.
 *
 * \param env    - the environment passed by the caller
 * \param lqe    - is the qid entry to be processed
 *
 * \retval 0            - success
 * \retval -EDQUOT      - out of quota
 * \retval -EINPROGRESS - inform client to retry write/create
 * \retval -EBUSY       - already a quota request in flight
 * \retval -ve          - other appropriate errors
 */
static int qsd_acquire_remote(const struct lu_env *env,
			      struct lquota_entry *lqe)
{
	struct qsd_thread_info	*qti = qsd_info(env);
	struct quota_body	*qbody = &qti->qti_body;
	struct qsd_instance	*qsd;
	struct qsd_qtype_info	*qqi;
	int			 rc;
	ENTRY;

	memset(qbody, 0, sizeof(*qbody));
	rc = qsd_ready(lqe, &qbody->qb_glb_lockh);
	if (rc)
		RETURN(rc);

	qqi = lqe2qqi(lqe);
	qsd = qqi->qqi_qsd;

	lqe_write_lock(lqe);

	/* is quota really enforced for this id? */
	if (!lqe->lqe_enforced) {
		lqe_write_unlock(lqe);
		LQUOTA_DEBUG(lqe, "quota not enforced any more");
		RETURN(0);
	}

	/* fill qb_count & qb_flags */
	if (!qsd_calc_acquire(lqe, qbody)) {
		lqe_write_unlock(lqe);
		LQUOTA_DEBUG(lqe, "No acquire required");
		RETURN(0);
	}

	/* check whether an acquire request completed recently */
	if (lqe->lqe_acq_rc != 0 &&
	    lqe->lqe_acq_time > ktime_get_seconds() - 1) {
		lqe_write_unlock(lqe);
		LQUOTA_DEBUG(lqe, "using cached return code %d", lqe->lqe_acq_rc);
		RETURN(lqe->lqe_acq_rc);
	}

	/* only 1 quota request in flight for a given ID is allowed */
	rc = qsd_request_enter(lqe);
	if (rc) {
		lqe_write_unlock(lqe);
		RETURN(rc);
	}

	lustre_handle_copy(&qti->qti_lockh, &lqe->lqe_lockh);
	lqe_write_unlock(lqe);

	/* hold a refcount until completion */
	lqe_getref(lqe);

	/* fill other quota body fields */
	qbody->qb_fid = qqi->qqi_fid;
	qbody->qb_id  = lqe->lqe_id;

	/* check whether we already own a valid lock for this ID */
	rc = qsd_id_lock_match(&qti->qti_lockh, &qbody->qb_lockh);
	if (rc) {
		struct lquota_lvb *lvb;

		OBD_ALLOC_PTR(lvb);
		if (lvb == NULL) {
			rc = -ENOMEM;
			qsd_req_completion(env, qqi, qbody, NULL,
					   &qti->qti_lockh, NULL, lqe, rc);
			RETURN(rc);
		}
		/* no lock found, should use intent */
		rc = qsd_intent_lock(env, qsd->qsd_exp, qbody, true,
				     IT_QUOTA_DQACQ, qsd_req_completion,
				     qqi, lvb, (void *)lqe);
	} else {
		/* lock found, should use regular dqacq */
		rc = qsd_send_dqacq(env, qsd->qsd_exp, qbody, true,
				    qsd_req_completion, qqi, &qti->qti_lockh,
				    lqe);
	}

	/* the completion function will be called by qsd_send_dqacq or
	 * qsd_intent_lock */
	RETURN(rc);
}

/**
 * Acquire \a space of quota space in order to complete an operation.
 * Try to consume local quota space first and send acquire request to quota
 * master if required.
 *
 * \param env   - the environment passed by the caller
 * \param lqe   - is the qid entry to be processed
 * \param space - is the amount of quota required for the operation
 * \param ret   - is the return code (-EDQUOT, -EINPROGRESS, ...)
 *
 * \retval true  - stop waiting in wait_event_idle_timeout,
 *                 and real return value in \a ret
 * \retval false - continue waiting
 */
static bool qsd_acquire(const struct lu_env *env, struct lquota_entry *lqe,
			long long space, int *ret)
{
	int rc = 0, count;
	int wait_pending = 0;
	struct qsd_qtype_info *qqi = lqe2qqi(lqe);

	ENTRY;

	for (count = 0; rc == 0; count++) {
		LQUOTA_DEBUG(lqe, "acquiring:%lld count=%d", space, count);
again:
		if (lqe2qqi(lqe)->qqi_qsd->qsd_stopping) {
			rc = -EINPROGRESS;
			break;
		}

		/* refresh disk usage */
		rc = qsd_refresh_usage(env, lqe);
		if (rc)
			break;

		/* try to consume local quota space first */
		rc = qsd_acquire_local(lqe, space);
		if (rc != -EAGAIN)
			/* rc == 0, Wouhou! enough local quota space
			 * rc < 0, something bad happened */
			 break;
		/*
		 * There might be a window that commit transaction
		 * have updated usage but pending write doesn't change
		 * wait for it before acquiring remotely.
		 */
		if (lqe->lqe_pending_write >= space && !wait_pending) {
			wait_pending = 1;
			dt_sync(env, qqi->qqi_qsd->qsd_dev);
			goto again;
		}

		/* if we have gotten some quota and stil wait more quota,
		 * it's better to give QMT some time to reclaim from clients */
		if (count > 0)
			schedule_timeout_interruptible(cfs_time_seconds(1));

		/* need to acquire more quota space from master */
		rc = qsd_acquire_remote(env, lqe);
	}

	if (rc == -EBUSY)
		/* already a request in flight, continue waiting */
		RETURN(false);
	*ret = rc;
	RETURN(true);
}

/**
 * Quota enforcement handler. If local quota can satisfy this operation,
 * return success, otherwise, acquire more quota from master.
 * (for write operation, if master isn't available at this moment, return
 * -EINPROGRESS to inform client to retry the write)
 *
 * \param env   - the environment passed by the caller
 * \param qsd   - is the qsd instance associated with the device in charge
 *                of the operation.
 * \param qid   - is the qid information attached in the transaction handle
 * \param space - is the space required by the operation
 * \param flags - if the operation is write, return caller no user/group
 *                and sync commit flags
 *
 * \retval 0            - success
 * \retval -EDQUOT      - out of quota
 * \retval -EINPROGRESS - inform client to retry write
 * \retval -ve          - other appropriate errors
 */
static int qsd_op_begin0(const struct lu_env *env, struct qsd_qtype_info *qqi,
			 struct lquota_id_info *qid, long long space,
			 enum osd_quota_local_flags *local_flags)
{
	struct lquota_entry *lqe;
	enum osd_quota_local_flags qtype_flag = 0;
	int rc, ret = -EINPROGRESS;
	ENTRY;

	if (qid->lqi_qentry != NULL) {
		/* we already had to deal with this id for this transaction */
		lqe = qid->lqi_qentry;
		if (!lqe->lqe_enforced)
			RETURN(0);
	} else {
		/* look up lquota entry associated with qid */
		lqe = lqe_locate(env, qqi->qqi_site, &qid->lqi_id);
		if (IS_ERR(lqe))
			RETURN(PTR_ERR(lqe));
		if (!lqe->lqe_enforced) {
			lqe_putref(lqe);
			RETURN(0);
		}
		qid->lqi_qentry = lqe;
		/* lqe will be released in qsd_op_end() */
	}

	if (space <= 0) {
		/* when space is negative or null, we don't need to consume
		 * quota space. That said, we still want to perform space
		 * adjustments in qsd_op_end, so we return here, but with
		 * a reference on the lqe */
		if (local_flags != NULL) {
			rc = qsd_refresh_usage(env, lqe);
			GOTO(out_flags, rc);
		}
		RETURN(0);
	}

	LQUOTA_DEBUG(lqe, "op_begin space:%lld", space);

	lqe_write_lock(lqe);
	lqe->lqe_waiting_write += space;
	lqe_write_unlock(lqe);

	/* acquire quota space for the operation, cap overall wait time to
	 * prevent a service thread from being stuck for too long */
	rc = wait_event_idle_timeout(
		lqe->lqe_waiters, qsd_acquire(env, lqe, space, &ret),
		cfs_time_seconds(qsd_wait_timeout(qqi->qqi_qsd)));

	if (rc > 0 && ret == 0) {
		qid->lqi_space += space;
		rc = 0;
	} else {
		if (rc > 0)
			rc = ret;
		else if (rc == 0)
			rc = -ETIMEDOUT;

		LQUOTA_DEBUG(lqe, "acquire quota failed:%d", rc);

		lqe_write_lock(lqe);
		lqe->lqe_waiting_write -= space;

		if (local_flags && lqe->lqe_pending_write != 0)
			/* Inform OSD layer that there are pending writes.
			 * It might want to retry after a sync if appropriate */
			 *local_flags |= QUOTA_FL_SYNC;
		lqe_write_unlock(lqe);

		/* convert recoverable error into -EINPROGRESS, client will
		 * retry */
		if (rc == -ETIMEDOUT || rc == -ENOTCONN || rc == -ENOLCK ||
		    rc == -EAGAIN || rc == -EINTR) {
			rc = -EINPROGRESS;
		} else if (rc == -ESRCH) {
			rc = 0;
			LQUOTA_ERROR(lqe, "ID isn't enforced on master, it "
				     "probably due to a legeal race, if this "
				     "message is showing up constantly, there "
				     "could be some inconsistence between "
				     "master & slave, and quota reintegration "
				     "needs be re-triggered.");
		}
	}

	if (local_flags != NULL) {
out_flags:
		LASSERT(qid->lqi_is_blk);
		if (rc != 0) {
			*local_flags |= lquota_over_fl(qqi->qqi_qtype);
		} else {
			__u64	usage;

			lqe_read_lock(lqe);
			usage = lqe->lqe_pending_write;
			usage += lqe->lqe_waiting_write;
			/* There is a chance to successfully grant more quota
			 * but get edquot flag through glimpse. */
			if (lqe->lqe_edquot || (lqe->lqe_qunit != 0 &&
			   (usage % lqe->lqe_qunit >
			    qqi->qqi_qsd->qsd_sync_threshold)))
				usage += qqi->qqi_qsd->qsd_sync_threshold;

			usage += lqe->lqe_usage;

			qtype_flag = lquota_over_fl(qqi->qqi_qtype);
			/* if we should notify client to start sync write */
			if (usage >= lqe->lqe_granted - lqe->lqe_pending_rel)
				*local_flags |= qtype_flag;
			else
				*local_flags &= ~qtype_flag;
			lqe_read_unlock(lqe);
		}
	}
	RETURN(rc);
}

/**
 * helper function comparing two lquota_id_info structures
 */
static inline bool qid_equal(struct lquota_id_info *q1,
			     struct lquota_id_info *q2)
{
	if (q1->lqi_is_blk != q2->lqi_is_blk || q1->lqi_type != q2->lqi_type)
		return false;
	return (q1->lqi_id.qid_uid == q2->lqi_id.qid_uid) ? true : false;
}

/**
 * Enforce quota, it's called in the declaration of each operation.
 * qsd_op_end() will then be called later once all the operations have been
 * completed in order to release/adjust the quota space.
 *
 * \param env   - the environment passed by the caller
 * \param qsd   - is the qsd instance associated with the device in charge of
 *                the operation.
 * \param trans - is the quota transaction information
 * \param qi    - qid & space required by current operation
 * \param flags - if the operation is write, return caller no user/group and
 *                sync commit flags
 *
 * \retval 0            - success
 * \retval -EDQUOT      - out of quota
 * \retval -EINPROGRESS - inform client to retry write
 * \retval -ve          - other appropriate errors
 */
int qsd_op_begin(const struct lu_env *env, struct qsd_instance *qsd,
		 struct lquota_trans *trans, struct lquota_id_info *qi,
		 enum osd_quota_local_flags *local_flags)
{
	int	i, rc;
	bool	found = false;
	ENTRY;

	if (unlikely(qsd == NULL))
		RETURN(0);

	if (qsd->qsd_dev->dd_rdonly)
		RETURN(0);

	/* We don't enforce quota until the qsd_instance is started */
	read_lock(&qsd->qsd_lock);
	if (!qsd->qsd_started) {
		read_unlock(&qsd->qsd_lock);
		RETURN(0);
	}
	read_unlock(&qsd->qsd_lock);

	/* ignore block quota on MDTs, ignore inode quota on OSTs */
	if ((!qsd->qsd_is_md && !qi->lqi_is_blk) ||
	    (qsd->qsd_is_md && qi->lqi_is_blk))
		RETURN(0);

	/* ignore quota enforcement request when:
	 *    - quota isn't enforced for this quota type
	 * or - the user/group is root
	 * or - quota accounting isn't enabled */
	if (!qsd_type_enabled(qsd, qi->lqi_type) || qi->lqi_id.qid_uid == 0 ||
	    (qsd->qsd_type_array[qi->lqi_type])->qqi_acct_failed)
		RETURN(0);

	LASSERTF(trans->lqt_id_cnt <= QUOTA_MAX_TRANSIDS, "id_cnt=%d\n",
		 trans->lqt_id_cnt);
	/* check whether we already allocated a slot for this id */
	for (i = 0; i < trans->lqt_id_cnt; i++) {
		if (qid_equal(qi, &trans->lqt_ids[i])) {
			found = true;
			break;
		}
	}

	if (!found) {
		if (unlikely(i >= QUOTA_MAX_TRANSIDS)) {
			CERROR("%s: more than %d qids enforced for a "
			       "transaction?\n", qsd->qsd_svname, i);
			RETURN(-EINVAL);
		}

		/* fill new slot */
		trans->lqt_ids[i].lqi_id     = qi->lqi_id;
		trans->lqt_ids[i].lqi_type   = qi->lqi_type;
		trans->lqt_ids[i].lqi_is_blk = qi->lqi_is_blk;
		trans->lqt_id_cnt++;
	}

	/* manage quota enforcement for this ID */
	rc = qsd_op_begin0(env, qsd->qsd_type_array[qi->lqi_type],
			   &trans->lqt_ids[i], qi->lqi_space, local_flags);
	RETURN(rc);
}
EXPORT_SYMBOL(qsd_op_begin);

/**
 * Adjust quota space (by acquiring or releasing) hold by the quota slave.
 * This function is called after each quota request completion and during
 * reintegration in order to report usage or re-acquire quota locks.
 * Space adjustment is aborted if there is already a quota request in flight
 * for this ID.
 *
 * \param env    - the environment passed by the caller
 * \param lqe    - is the qid entry to be processed
 *
 * \retval 0 on success, appropriate errors on failure
 */
int qsd_adjust(const struct lu_env *env, struct lquota_entry *lqe)
{
	struct qsd_thread_info	*qti = qsd_info(env);
	struct quota_body	*qbody = &qti->qti_body;
	struct qsd_instance	*qsd;
	struct qsd_qtype_info	*qqi;
	int			 rc;
	bool			 intent = false;
	ENTRY;

	memset(qbody, 0, sizeof(*qbody));
	rc = qsd_ready(lqe, &qbody->qb_glb_lockh);
	if (rc) {
		/* add to adjust list again to trigger adjustment later when
		 * slave is ready */
		LQUOTA_DEBUG(lqe, "delaying adjustment since qsd isn't ready");
		qsd_adjust_schedule(lqe, true, false);
		RETURN(0);
	}

	qqi = lqe2qqi(lqe);
	qsd = qqi->qqi_qsd;

	if (qsd->qsd_dev->dd_rdonly)
		RETURN(0);

	lqe_write_lock(lqe);

	/* fill qb_count & qb_flags */
	if (!qsd_calc_adjust(lqe, qbody)) {
		lqe_write_unlock(lqe);
		LQUOTA_DEBUG(lqe, "no adjustment required");
		RETURN(0);
	}

	/* only 1 quota request in flight for a given ID is allowed */
	rc = qsd_request_enter(lqe);
	if (rc) {
		/* already a request in flight, space adjustment will be run
		 * again on request completion */
		lqe_write_unlock(lqe);
		RETURN(0);
	}

	if (req_is_rel(qbody->qb_flags))
		lqe->lqe_pending_rel = qbody->qb_count;
	lustre_handle_copy(&qti->qti_lockh, &lqe->lqe_lockh);
	lqe_write_unlock(lqe);

	/* hold a refcount until completion */
	lqe_getref(lqe);

	/* fill other quota body fields */
	qbody->qb_fid = qqi->qqi_fid;
	qbody->qb_id  = lqe->lqe_id;

	if (req_is_acq(qbody->qb_flags) || req_is_preacq(qbody->qb_flags)) {
		/* check whether we own a valid lock for this ID */
		rc = qsd_id_lock_match(&qti->qti_lockh, &qbody->qb_lockh);
		if (rc) {
			memset(&qti->qti_lockh, 0, sizeof(qti->qti_lockh));
			if (req_is_preacq(qbody->qb_flags)) {
				if (req_has_rep(qbody->qb_flags))
					/* still want to report usage */
					qbody->qb_flags = QUOTA_DQACQ_FL_REPORT;
				else
					/* no pre-acquire if no per-ID lock */
					GOTO(out, rc = -ENOLCK);
			} else {
				/* no lock found, should use intent */
				intent = true;
			}
		} else if (req_is_acq(qbody->qb_flags) &&
			   qbody->qb_count == 0) {
			/* found cached lock, no need to acquire */
			GOTO(out, rc = 0);
		}
	} else {
		/* release and report don't need a per-ID lock */
		memset(&qti->qti_lockh, 0, sizeof(qti->qti_lockh));
	}

	if (!intent) {
		rc = qsd_send_dqacq(env, qsd->qsd_exp, qbody, false,
				    qsd_req_completion, qqi, &qti->qti_lockh,
				    lqe);
	} else {
		struct lquota_lvb *lvb;

		OBD_ALLOC_PTR(lvb);
		if (lvb == NULL)
			GOTO(out, rc = -ENOMEM);

		rc = qsd_intent_lock(env, qsd->qsd_exp, qbody, false,
				     IT_QUOTA_DQACQ, qsd_req_completion,
				     qqi, lvb, (void *)lqe);
	}
	/* the completion function will be called by qsd_send_dqacq or
	 * qsd_intent_lock */
	RETURN(rc);
out:
	qsd_req_completion(env, qqi, qbody, NULL, &qti->qti_lockh, NULL, lqe,
			   rc);
	return rc;
}

/**
 * Post quota operation, pre-acquire/release quota from master.
 *
 * \param  env  - the environment passed by the caller
 * \param  qsd  - is the qsd instance attached to the OSD device which
 *                is handling the operation.
 * \param  qqi  - is the qsd_qtype_info structure associated with the quota ID
 *                subject to the operation
 * \param  qid  - stores information related to his ID for the operation
 *                which has just completed
 *
 * \retval 0    - success
 * \retval -ve  - failure
 */
static void qsd_op_end0(const struct lu_env *env, struct qsd_qtype_info *qqi,
			struct lquota_id_info *qid)
{
	struct lquota_entry	*lqe;
	bool			 adjust;
	ENTRY;

	lqe = qid->lqi_qentry;
	if (lqe == NULL)
		RETURN_EXIT;
	qid->lqi_qentry = NULL;

	/* refresh cached usage if a suitable environment is passed */
	if (env != NULL)
		qsd_refresh_usage(env, lqe);

	lqe_write_lock(lqe);
	if (qid->lqi_space > 0)
		lqe->lqe_pending_write -= qid->lqi_space;
	if (env != NULL)
		adjust = qsd_adjust_needed(lqe);
	else
		adjust = true;
	lqe_write_unlock(lqe);

	if (adjust) {
		/* pre-acquire/release quota space is needed */
		if (env != NULL)
			qsd_adjust(env, lqe);
		else
			/* no suitable environment, handle adjustment in
			 * separate thread context */
			qsd_adjust_schedule(lqe, false, false);
	}
	lqe_putref(lqe);
	EXIT;
}

/**
 * Post quota operation. It's called after each operation transaction stopped.
 *
 * \param  env   - the environment passed by the caller
 * \param  qsd   - is the qsd instance associated with device which is handling
 *                 the operation.
 * \param  qids  - all qids information attached in the transaction handle
 * \param  count - is the number of qid entries in the qids array.
 *
 * \retval 0     - success
 * \retval -ve   - failure
 */
void qsd_op_end(const struct lu_env *env, struct qsd_instance *qsd,
		struct lquota_trans *trans)
{
	int i;
	ENTRY;

	if (unlikely(qsd == NULL))
		RETURN_EXIT;

	if (qsd->qsd_dev->dd_rdonly)
		RETURN_EXIT;

	/* We don't enforce quota until the qsd_instance is started */
	read_lock(&qsd->qsd_lock);
	if (!qsd->qsd_started) {
		read_unlock(&qsd->qsd_lock);
		RETURN_EXIT;
	}
	read_unlock(&qsd->qsd_lock);

	LASSERT(trans != NULL);

	for (i = 0; i < trans->lqt_id_cnt; i++) {
		struct qsd_qtype_info *qqi;

		if (trans->lqt_ids[i].lqi_qentry == NULL)
			continue;

		qqi = qsd->qsd_type_array[trans->lqt_ids[i].lqi_type];
		qsd_op_end0(env, qqi, &trans->lqt_ids[i]);
	}

	/* reset id_count to 0 so that a second accidental call to qsd_op_end()
	 * does not result in failure */
	trans->lqt_id_cnt = 0;
	EXIT;
}
EXPORT_SYMBOL(qsd_op_end);

/**
 * Trigger pre-acquire/release if necessary.
 * It's only used by ldiskfs osd so far. When unlink a file in ldiskfs, the
 * quota accounting isn't updated when the transaction stopped. Instead, it'll
 * be updated on the final iput, so qsd_op_adjust() will be called then (in
 * osd_object_delete()) to trigger quota release if necessary.
 *
 * \param env - the environment passed by the caller
 * \param qsd - is the qsd instance associated with the device in charge
 *              of the operation.
 * \param qid - is the lquota ID of the user/group for which to trigger
 *              quota space adjustment
 * \param qtype - is the quota type (USRQUOTA or GRPQUOTA)
 */
void qsd_op_adjust(const struct lu_env *env, struct qsd_instance *qsd,
		   union lquota_id *qid, int qtype)
{
	struct lquota_entry    *lqe;
	struct qsd_qtype_info  *qqi;
	bool			adjust;
	ENTRY;

	if (unlikely(qsd == NULL))
		RETURN_EXIT;

	/* We don't enforce quota until the qsd_instance is started */
	read_lock(&qsd->qsd_lock);
	if (!qsd->qsd_started) {
		read_unlock(&qsd->qsd_lock);
		RETURN_EXIT;
	}
	read_unlock(&qsd->qsd_lock);

	qqi = qsd->qsd_type_array[qtype];
	LASSERT(qqi);

	if (!qsd_type_enabled(qsd, qtype) || qqi->qqi_acct_obj == NULL ||
	    qid->qid_uid == 0)
		RETURN_EXIT;

	read_lock(&qsd->qsd_lock);
	if (!qsd->qsd_started) {
		read_unlock(&qsd->qsd_lock);
		RETURN_EXIT;
	}
	read_unlock(&qsd->qsd_lock);

	lqe = lqe_locate(env, qqi->qqi_site, qid);
	if (IS_ERR(lqe)) {
		CERROR("%s: fail to locate lqe for id:%llu, type:%d\n",
		       qsd->qsd_svname, qid->qid_uid, qtype);
		RETURN_EXIT;
	}

	qsd_refresh_usage(env, lqe);

	lqe_read_lock(lqe);
	adjust = qsd_adjust_needed(lqe);
	lqe_read_unlock(lqe);

	if (adjust)
		qsd_adjust(env, lqe);

	lqe_putref(lqe);
	EXIT;
}
EXPORT_SYMBOL(qsd_op_adjust);
