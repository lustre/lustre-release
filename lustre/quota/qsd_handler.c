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
 * Copyright (c) 2012 Intel, Inc.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>
#include <linux/quotaops.h>
#include <linux/init.h>

#include <obd_class.h>
#include <lustre_param.h>
#include <lprocfs_status.h>

#include "qsd_internal.h"

/*
 * helper function returning how much space is currently reserved for requests
 * in flight.
 */
static inline int lqe_pending_dqacq(struct lquota_entry *lqe)
{
	int	pending;

	lqe_read_lock(lqe);
	pending = lqe->lqe_pending_req;
	lqe_read_unlock(lqe);

	return pending;
}

/*
 * helper function returning true when the connection to master is ready to be
 * used.
 */
static inline int qsd_ready(struct qsd_instance *qsd)
{
	struct obd_import	*imp = NULL;

	cfs_read_lock(&qsd->qsd_lock);
	if (qsd->qsd_exp_valid)
		imp = class_exp2cliimp(qsd->qsd_exp);
	cfs_read_unlock(&qsd->qsd_lock);

	return (imp == NULL || imp->imp_invalid) ? false : true;
}

/*
 * Helper function returning true when quota space need to be adjusted (some
 * unused space should be free or pre-acquire) and false otherwise.
 */
static bool qsd_adjust_needed(struct lquota_entry *lqe)
{
	struct qsd_qtype_info	*qqi;
	__u64			 usage, granted;

	qqi = lqe2qqi(lqe);

	if (!lqe->lqe_enforced || qqi->qqi_qsd->qsd_stopping)
		/* if quota isn't enforced for this id, no need to adjust
		 * Similarly, no need to perform adjustment if the target is in
		 * the process of shutting down. */
		return false;

	usage  = lqe->lqe_usage;
	usage += lqe->lqe_pending_write + lqe->lqe_waiting_write;
	granted = lqe->lqe_granted - lqe->lqe_pending_rel;

	/* need to re-acquire per-ID lock or release all grant */
	if (!lustre_handle_is_used(&lqe->lqe_lockh) &&
	    lqe->lqe_granted > lqe->lqe_usage)
		return true;

	/* good old quota qunit adjustment logic which has been around since
	 * lustre 1.4:
	 * 1. Need to release some space? */
	if (granted > usage + lqe->lqe_qunit)
		return true;

	/* 2. Any quota overrun? */
	if (lqe->lqe_usage > lqe->lqe_granted)
		/* we ended up consuming more than we own, we need to have this
		 * fixed ASAP */
		return true;

	/* 3. Time to pre-acquire? */
	if (!lqe->lqe_edquot && !lqe->lqe_nopreacq && lqe->lqe_qunit != 0 &&
	    granted < usage + lqe->lqe_qtune)
		/* need to pre-acquire some space if we don't want to block
		 * client's requests */
		return true;

	return false;
}

/*
 * Callback function called when an acquire/release request sent to the master
 * is completed
 */
static void qsd_dqacq_completion(const struct lu_env *env,
				 struct qsd_qtype_info *qqi,
				 struct quota_body *reqbody,
				 struct quota_body *repbody,
				 struct lustre_handle *lockh,
				 union ldlm_wire_lvb *lvb,
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

	LQUOTA_DEBUG(lqe, "DQACQ returned %d, flags:%x", ret,
		     reqbody->qb_flags);

	/* despite -EDQUOT & -EINPROGRESS errors, the master might still
	 * grant us back quota space to adjust quota overrun */
	if (ret != 0 && ret != -EDQUOT && ret != -EINPROGRESS) {
		if (ret != -ETIMEDOUT && ret != -ENOTCONN &&
		   ret != -ESHUTDOWN && ret != -EAGAIN)
			/* print errors only if return code is unexpected */
			LQUOTA_ERROR(lqe, "DQACQ failed with %d, flags:%x", ret,
				     reqbody->qb_flags);
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
		LQUOTA_DEBUG(lqe, "DQACQ qb_count:"LPU64, repbody->qb_count);

		if (req_is_rel(reqbody->qb_flags)) {
			if (lqe->lqe_granted < repbody->qb_count) {
				LQUOTA_ERROR(lqe, "can't release more space "
					     "than owned "LPU64"<"LPU64,
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
	if (ret == 0 && lvb != 0) {
		if (lvb->l_lquota.lvb_id_qunit != 0)
			qsd_set_qunit(lqe, lvb->l_lquota.lvb_id_qunit);
		if (lvb->l_lquota.lvb_flags & LQUOTA_FL_EDQUOT)
			lqe->lqe_edquot = true;
		else
			lqe->lqe_edquot = false;
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
out_noadjust:
	lqe->lqe_pending_req--;
	lqe->lqe_pending_rel = 0;
	lqe_write_unlock(lqe);

	cfs_waitq_broadcast(&lqe->lqe_waiters);

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

	if (lvb)
		/* free lvb allocated in qsd_dqacq */
		OBD_FREE_PTR(lvb);

	lqe_putref(lqe);
	EXIT;
}

static int qsd_acquire_local(struct lquota_entry *lqe, __u64 space)
{
	__u64	usage;
	int	rc;
	ENTRY;

	if (!lqe->lqe_enforced)
		/* not enforced any more, we are good */
		RETURN(0);

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
	} else if (lqe->lqe_edquot) {
		rc = -EDQUOT;
	} else {
		rc = -EAGAIN;
	}
	lqe_write_unlock(lqe);

	RETURN(rc);
}

static bool qsd_calc_space(struct lquota_entry *lqe, enum qsd_ops op,
			   struct quota_body *qbody)
{
	struct qsd_qtype_info	*qqi;
	__u64			 usage, granted;

	if (!lqe->lqe_enforced && op != QSD_REL)
		return 0;

	qqi = lqe2qqi(lqe);

	LASSERT(lqe->lqe_pending_rel == 0);
	usage   = lqe->lqe_usage;
	usage  += lqe->lqe_pending_write + lqe->lqe_waiting_write;
	granted = lqe->lqe_granted;

	qbody->qb_flags = 0;
again:
	switch (op) {
	case QSD_ACQ:
		/* if we overconsumed quota space, we report usage in request
		 * so that master can adjust it unconditionally */
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
		break;
	case QSD_REP:
		/* When reporting quota (during reintegration or on setquota
		 * glimpse), we should release granted space if usage is 0.
		 * Otherwise, if the usage is less than granted, we need to
		 * acquire the per-ID lock to make sure the unused grant can be
		 * reclaimed by per-ID lock glimpse. */
		if (lqe->lqe_usage == 0 && lqe->lqe_granted != 0) {
			LQUOTA_DEBUG(lqe, "Release on report!");
			GOTO(again, op = QSD_REL);
		} else if (lqe->lqe_usage == lqe->lqe_granted) {
			LQUOTA_DEBUG(lqe, "Usage matches granted, needn't do "
				     "anything on report!");
		} else if (lqe->lqe_usage < lqe->lqe_granted) {
			LQUOTA_DEBUG(lqe, "Acquire per-ID lock on report!");
			qbody->qb_count = 0;
			qbody->qb_flags = QUOTA_DQACQ_FL_ACQ;
		} else {
			LASSERT(lqe->lqe_usage > lqe->lqe_granted);
			LQUOTA_DEBUG(lqe, "Reporting usage");
			qbody->qb_usage = lqe->lqe_usage;
			qbody->qb_flags = QUOTA_DQACQ_FL_REPORT;
		}
		break;
	case QSD_REL:
		/* release unused quota space unconditionally */
		if (lqe->lqe_granted > lqe->lqe_usage) {
			qbody->qb_count = lqe->lqe_granted - lqe->lqe_usage;
			qbody->qb_flags = QUOTA_DQACQ_FL_REL;
		}
		break;
	case QSD_ADJ: {
		/* need to re-acquire per-ID lock or release all grant */
		if (!lustre_handle_is_used(&lqe->lqe_lockh) &&
		    lqe->lqe_granted > lqe->lqe_usage)
			GOTO(again, op = QSD_REP);

		/* release spare grant */
		if (granted > usage + lqe->lqe_qunit) {
			/* pre-release quota space */
			qbody->qb_count  = granted - usage;
			/* if usage == 0, release all granted space */
			if (usage) {
				/* try to keep one qunit of quota space */
				qbody->qb_count -= lqe->lqe_qunit;
				/* but don't release less than qtune to avoid
				 * releasing space too often */
				if (qbody->qb_count < lqe->lqe_qtune)
					qbody->qb_count = lqe->lqe_qtune;
			}
			qbody->qb_flags = QUOTA_DQACQ_FL_REL;
			break;
		}

		/* if we overconsumed quota space, we report usage in request
		 * so that master can adjust it unconditionally */
		if (lqe->lqe_usage > lqe->lqe_granted) {
			qbody->qb_usage = lqe->lqe_usage;
			qbody->qb_flags = QUOTA_DQACQ_FL_REPORT;
			granted         = lqe->lqe_usage;
		}

		if (!lqe->lqe_edquot && !lqe->lqe_nopreacq &&
		    lustre_handle_is_used(&lqe->lqe_lockh) &&
		    lqe->lqe_qunit != 0 && granted < usage + lqe->lqe_qtune) {
			/* To pre-acquire quota space, we report how much spare
			 * quota space the slave currently owns, then the master
			 * will grant us back how much we can pretend given the
			 * current state of affairs */
			if (granted <= usage)
				qbody->qb_count = 0;
			else
				qbody->qb_count = granted - usage;
			qbody->qb_flags |= QUOTA_DQACQ_FL_PREACQ;
		}
		break;
	}
	default:
		CERROR("Invalid qsd operation:%u\n", op);
		LBUG();
		break;
	}
	return qbody->qb_flags != 0;
}

/*
 * Acquire/release quota space from master.
 * There are at most 1 in-flight dqacq/dqrel.
 *
 * \param env    - the environment passed by the caller
 * \param lqe    - is the qid entry to be processed
 * \param op     - operation that want to be performed by the caller
 *
 * \retval 0     - success
 * \retval -EDQUOT      : out of quota
 *         -EINPROGRESS : inform client to retry write/create
 *         -ve          : other appropriate errors
 */
int qsd_dqacq(const struct lu_env *env, struct lquota_entry *lqe,
	      enum qsd_ops op)
{
	struct qsd_thread_info	*qti = qsd_info(env);
	struct quota_body	*qbody = &qti->qti_body;
	struct qsd_instance	*qsd;
	struct qsd_qtype_info	*qqi;
	struct ldlm_lock	*lock;
	int			 rc;
	bool			 intent = false, sync;
	ENTRY;

	qqi = lqe2qqi(lqe);
	qsd = qqi->qqi_qsd;

	if (qsd->qsd_stopping) {
		LQUOTA_DEBUG(lqe, "Dropping quota req since qsd is stopping");
		/* Target is about to shut down, client will retry */
		RETURN(-EINPROGRESS);
	}

	if (!qsd_ready(qsd)) {
		LQUOTA_DEBUG(lqe, "Connection to master not ready");
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
		LQUOTA_DEBUG(lqe, "Not up-to-date, dropping request and kicking"
			     " off reintegration");
		qsd_start_reint_thread(qqi);
		RETURN(-EINPROGRESS);
	}

	LQUOTA_DEBUG(lqe, "DQACQ starts op=%u", op);

	/* Fill the remote global lock handle, master will check this handle
	 * to see if the slave is sending request with stale lock */
	cfs_read_lock(&qsd->qsd_lock);
	lustre_handle_copy(&qbody->qb_glb_lockh, &qqi->qqi_lockh);
	cfs_read_unlock(&qsd->qsd_lock);

	if (!lustre_handle_is_used(&qbody->qb_glb_lockh))
		RETURN(-ENOLCK);

	lock = ldlm_handle2lock(&qbody->qb_glb_lockh);
	if (lock == NULL)
		RETURN(-ENOLCK);
	lustre_handle_copy(&qbody->qb_glb_lockh, &lock->l_remote_handle);
	LDLM_LOCK_PUT(lock);

	/* We allow only one in-flight dqacq/dqrel for specified qid, if
	 * there is already in-flight dqacq/dqrel:
	 *
	 * - For QSD_ADJ: we should just abort it, since local limit is going
	 *   to be changed soon;
	 * - For QSD_ACQ & QSD_REL: we just wait for the in-flight dqacq/dqrel
	 *   finished, and return success to the caller. The caller is
	 *   responsible for retrying;
	 * - For QSD_REP: we should just abort it, since slave has already
	 *   acquired/released grant; */
	sync = (op == QSD_ACQ || op == QSD_REL) ? true : false;
	LASSERTF(lqe->lqe_pending_req <= 1, "pending dqacq/dqrel:%d",
		 lqe->lqe_pending_req);

	lqe_write_lock(lqe);
	if (lqe->lqe_pending_req != 0) {
		struct l_wait_info lwi = { 0 };

		lqe_write_unlock(lqe);
		if (!sync) {
			LQUOTA_DEBUG(lqe, "Abort DQACQ, op=%d", op);
			RETURN(0);
		}

		LQUOTA_DEBUG(lqe, "waiting for in-flight dqacq/dqrel");
		l_wait_event(lqe->lqe_waiters,
			     !lqe_pending_dqacq(lqe) || qsd->qsd_stopping,
			     &lwi);
		RETURN(0);
	}

	/* fill qb_count & qb_flags */
	if (!qsd_calc_space(lqe, op, qbody)) {
		lqe_write_unlock(lqe);
		LQUOTA_DEBUG(lqe, "No DQACQ required, op=%u", op);
		RETURN(0);
	}
	lqe->lqe_pending_req++;
	lqe_write_unlock(lqe);

	/* fill other quota body fields */
	qbody->qb_fid = qqi->qqi_fid;
	qbody->qb_id  = lqe->lqe_id;
	memset(&qbody->qb_lockh, 0, sizeof(qbody->qb_lockh));
	memset(&qti->qti_lockh, 0, sizeof(qti->qti_lockh));

	/* hold a refcount until completion */
	lqe_getref(lqe);

	if (req_is_acq(qbody->qb_flags) || req_is_preacq(qbody->qb_flags)) {
		/* check whether we already own a lock for this ID */
		lqe_read_lock(lqe);
		lustre_handle_copy(&qti->qti_lockh, &lqe->lqe_lockh);
		lqe_read_unlock(lqe);

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
	}

	if (!intent) {
		rc = qsd_send_dqacq(env, qsd->qsd_exp, qbody, sync,
				    qsd_dqacq_completion, qqi, &qti->qti_lockh,
				    lqe);
        } else {
		union ldlm_wire_lvb *lvb;

		OBD_ALLOC_PTR(lvb);
		if (lvb == NULL)
			GOTO(out, rc = -ENOMEM);

		rc = qsd_intent_lock(env, qsd->qsd_exp, qbody, sync,
				     IT_QUOTA_DQACQ, qsd_dqacq_completion,
				     qqi, lvb, (void *)lqe);
	}
	/* the completion function will be called by qsd_send_dqacq or
	 * qsd_intent_lock */
	RETURN(rc);
out:
	qsd_dqacq_completion(env, qqi, qbody, NULL, &qti->qti_lockh, NULL, lqe,
			     rc);
	return rc;
}

/*
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
 * \retval 0        - success
 * \retval -EDQUOT      : out of quota
 *         -EINPROGRESS : inform client to retry write
 *         -ve          : other appropriate errors
 */
static int qsd_op_begin0(const struct lu_env *env, struct qsd_qtype_info *qqi,
			 struct lquota_id_info *qid, long long space,
			 int *flags)
{
	struct lquota_entry *lqe;
	int                  rc = 0, retry_cnt;
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
		if (flags != NULL) {
			rc = qsd_refresh_usage(env, lqe);
			GOTO(out_flags, rc);
		}
		RETURN(0);
	}

	LQUOTA_DEBUG(lqe, "op_begin space:"LPD64, space);

	lqe_write_lock(lqe);
	lqe->lqe_waiting_write += space;
	lqe_write_unlock(lqe);

	for (retry_cnt = 0; rc == 0; retry_cnt++) {
		/* refresh disk usage if required */
		rc = qsd_refresh_usage(env, lqe);
		if (rc)
			break;

		/* try to consume local quota space */
		rc = qsd_acquire_local(lqe, space);
		if (rc != -EAGAIN)
			/* rc == 0, Wouhou! enough local quota space
			 * rc < 0, something bad happened */
			break;

		/* need to acquire more quota space from master, this is done
		 * synchronously */
		rc = qsd_dqacq(env, lqe, QSD_ACQ);
		LQUOTA_DEBUG(lqe, "Acquired quota space, retry cnt:%d rc:%d",
			     retry_cnt, rc);
	}

	if (rc == 0) {
		qid->lqi_space += space;
	} else {
		LQUOTA_DEBUG(lqe, "Acquire quota failed:%d", rc);

		lqe_write_lock(lqe);
		lqe->lqe_waiting_write -= space;

		if (flags && lqe->lqe_pending_write != 0)
			/* Inform OSD layer that there are pending writes.
			 * It might want to retry after a sync if appropriate */
			 *flags |= QUOTA_FL_SYNC;
		lqe_write_unlock(lqe);

		/* convert recoverable error into -EINPROGRESS, and client will
		 * retry write on -EINPROGRESS. */
		if (rc == -ETIMEDOUT || rc == -ENOTCONN || rc == -ENOLCK ||
		    rc == -EAGAIN || rc == -EINTR)
			rc = -EINPROGRESS;
	}

	if (flags != NULL) {
out_flags:
		LASSERT(qid->lqi_is_blk);
		if (rc != 0) {
			*flags |= LQUOTA_OVER_FL(qqi->qqi_qtype);
		} else {
			__u64	usage;

			lqe_read_lock(lqe);
			usage  = lqe->lqe_usage;
			usage += lqe->lqe_pending_write;
			usage += lqe->lqe_waiting_write;
			usage += qqi->qqi_qsd->qsd_sync_threshold;

			/* if we should notify client to start sync write */
			if (usage >= lqe->lqe_granted - lqe->lqe_pending_rel)
				*flags |= LQUOTA_OVER_FL(qqi->qqi_qtype);
			else
				*flags &= ~LQUOTA_OVER_FL(qqi->qqi_qtype);
			lqe_read_unlock(lqe);
		}
	}
	RETURN(rc);
}

static inline bool qid_equal(struct lquota_id_info *q1,
			     struct lquota_id_info *q2)
{
	if (q1->lqi_type != q2->lqi_type)
		return false;
	return (q1->lqi_id.qid_uid == q2->lqi_id.qid_uid) ? true : false;
}

/*
 * Enforce quota, it's called in the declaration of each operation.
 * qsd_op_end() will then be called later once all the operations have been
 * completed in order to release/adjust the quota space.
 *
 * \param env        - the environment passed by the caller
 * \param qsd        - is the qsd instance associated with the device in charge
 *                     of the operation.
 * \param trans      - is the quota transaction information
 * \param qi         - qid & space required by current operation
 * \param flags      - if the operation is write, return caller no user/group
 *                     and sync commit flags
 *
 * \retval 0        - success
 * \retval -EDQUOT      : out of quota
 *         -EINPROGRESS : inform client to retry write
 *         -ve          : other appropriate errors
 */
int qsd_op_begin(const struct lu_env *env, struct qsd_instance *qsd,
		 struct lquota_trans *trans, struct lquota_id_info *qi,
		 int *flags)
{
	int	i, rc;
	bool	found = false;
	ENTRY;

	if (unlikely(qsd == NULL))
		RETURN(0);

	/* We don't enforce quota until the qsd_instance is started */
	cfs_read_lock(&qsd->qsd_lock);
	if (!qsd->qsd_started) {
		cfs_read_unlock(&qsd->qsd_lock);
		RETURN(0);
	}
	cfs_read_unlock(&qsd->qsd_lock);

	/* ignore block quota on MDTs, ignore inode quota on OSTs */
	if ((!qsd->qsd_is_md && !qi->lqi_is_blk) ||
	    (qsd->qsd_is_md && qi->lqi_is_blk))
		RETURN(0);

	/* ignore quota enforcement request when:
	 *    - quota isn't enforced for this quota type
	 * or - the user/group is root */
	if (!qsd_type_enabled(qsd, qi->lqi_type) || qi->lqi_id.qid_uid == 0)
		RETURN(0);

	LASSERTF(trans->lqt_id_cnt <= QUOTA_MAX_TRANSIDS, "id_cnt=%d",
		 trans->lqt_id_cnt);
	/* check whether we already allocated a slot for this id */
	for (i = 0; i < trans->lqt_id_cnt; i++) {
		if (qid_equal(qi, &trans->lqt_ids[i])) {
			found = true;
			/* make sure we are not mixing inodes & blocks */
			LASSERT(trans->lqt_ids[i].lqi_is_blk == qi->lqi_is_blk);
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
			   &trans->lqt_ids[i], qi->lqi_space, flags);
	RETURN(rc);
}
EXPORT_SYMBOL(qsd_op_begin);

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
			qsd_dqacq(env, lqe, QSD_ADJ);
		else
			/* no suitable environment, handle adjustment in
			 * separate thread context */
			qsd_adjust_schedule(lqe, false, false);
	}
	lqe_putref(lqe);
	EXIT;
}

/*
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

	/* We don't enforce quota until the qsd_instance is started */
	cfs_read_lock(&qsd->qsd_lock);
	if (!qsd->qsd_started) {
		cfs_read_unlock(&qsd->qsd_lock);
		RETURN_EXIT;
	}
	cfs_read_unlock(&qsd->qsd_lock);

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

void qsd_adjust_quota(const struct lu_env *env, struct qsd_instance *qsd,
		      union lquota_id *qid, int qtype)
{
	struct lquota_entry    *lqe;
	struct qsd_qtype_info  *qqi;
	bool			adjust;
	ENTRY;

	if (unlikely(qsd == NULL))
		RETURN_EXIT;

	/* We don't enforce quota until the qsd_instance is started */
	cfs_read_lock(&qsd->qsd_lock);
	if (!qsd->qsd_started) {
		cfs_read_unlock(&qsd->qsd_lock);
		RETURN_EXIT;
	}
	cfs_read_unlock(&qsd->qsd_lock);

	qqi = qsd->qsd_type_array[qtype];
	LASSERT(qqi);

	if (!qsd_type_enabled(qsd, qtype) || qqi->qqi_acct_obj == NULL ||
	    qid->qid_uid == 0)
		RETURN_EXIT;

	cfs_read_lock(&qsd->qsd_lock);
	if (!qsd->qsd_started) {
		cfs_read_unlock(&qsd->qsd_lock);
		RETURN_EXIT;
	}
	cfs_read_unlock(&qsd->qsd_lock);

	lqe = lqe_locate(env, qqi->qqi_site, qid);
	if (IS_ERR(lqe)) {
		CERROR("%s: fail to locate lqe for id:"LPU64", type:%d\n",
		       qsd->qsd_svname, qid->qid_uid, qtype);
		RETURN_EXIT;
	}

	qsd_refresh_usage(env, lqe);

	lqe_read_lock(lqe);
	adjust = qsd_adjust_needed(lqe);
	lqe_read_unlock(lqe);

	if (adjust)
		qsd_dqacq(env, lqe, QSD_ADJ);

	lqe_putref(lqe);
	EXIT;
}
EXPORT_SYMBOL(qsd_adjust_quota);
