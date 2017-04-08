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
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <obd_class.h>
#include "qmt_internal.h"

/*
 * Retrieve quota settings for a given identifier.
 *
 * \param env     - is the environment passed by the caller
 * \param qmt     - is the quota master target
 * \param pool_id - is the 16-bit pool identifier
 * \param restype - is the pool type, either block (i.e. LQUOTA_RES_DT) or inode
 *                  (i.e. LQUOTA_RES_MD)
 * \param qtype   - is the quota type
 * \param id      - is the quota indentifier for which we want to acces quota
 *                  settings.
 * \param hard    - is the output variable where to copy the hard limit
 * \param soft    - is the output variable where to copy the soft limit
 * \param time    - is the output variable where to copy the grace time
 */
static int qmt_get(const struct lu_env *env, struct qmt_device *qmt,
		   __u16 pool_id, __u8 restype, __u8 qtype, union lquota_id *id,
		   __u64 *hard, __u64 *soft, __u64 *time)
{
	struct lquota_entry	*lqe;
	ENTRY;

	/* look-up lqe structure containing quota settings */
	lqe = qmt_pool_lqe_lookup(env, qmt, pool_id, restype, qtype, id);
	if (IS_ERR(lqe))
		RETURN(PTR_ERR(lqe));

	/* copy quota settings */
	lqe_read_lock(lqe);
	LQUOTA_DEBUG(lqe, "fetch settings");
	if (hard != NULL)
		*hard = lqe->lqe_hardlimit;
	if (soft != NULL)
		*soft = lqe->lqe_softlimit;
	if (time != NULL)
		*time = lqe->lqe_gracetime;
	lqe_read_unlock(lqe);

	lqe_putref(lqe);
	RETURN(0);
}

/*
 * Update quota settings for a given identifier.
 *
 * \param env     - is the environment passed by the caller
 * \param qmt     - is the quota master target
 * \param pool_id - is the 16-bit pool identifier
 * \param restype - is the pool type, either block (i.e. LQUOTA_RES_DT) or inode
 *                  (i.e. LQUOTA_RES_MD)
 * \param qtype   - is the quota type
 * \param id      - is the quota indentifier for which we want to modify quota
 *                  settings.
 * \param hard    - is the new hard limit
 * \param soft    - is the new soft limit
 * \param time    - is the new grace time
 * \param valid   - is the list of settings to change
 */
static int qmt_set(const struct lu_env *env, struct qmt_device *qmt,
		   __u16 pool_id, __u8 restype, __u8 qtype,
		   union lquota_id *id, __u64 hard, __u64 soft, __u64 time,
		   __u32 valid)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_entry	*lqe;
	struct thandle		*th = NULL;
	time64_t now;
	__u64			 ver;
	bool			 dirtied = false;
	int			 rc = 0;
	ENTRY;

	/* look-up quota entry associated with this ID */
	lqe = qmt_pool_lqe_lookup(env, qmt, pool_id, restype, qtype, id);
	if (IS_ERR(lqe))
		RETURN(PTR_ERR(lqe));

	/* allocate & start transaction with enough credits to update quota
	 * settings in the global index file */
	th = qmt_trans_start(env, lqe, &qti->qti_restore);
	if (IS_ERR(th))
		GOTO(out_nolock, rc = PTR_ERR(th));

	now = ktime_get_real_seconds();

	lqe_write_lock(lqe);
	LQUOTA_DEBUG(lqe, "changing quota settings valid:%x hard:%llu soft:"
		     "%llu time:%llu", valid, hard, soft, time);

	if ((valid & QIF_TIMES) != 0 && lqe->lqe_gracetime != time) {
		/* change time settings */
		lqe->lqe_gracetime = time;
		dirtied            = true;
	}

	if ((valid & QIF_LIMITS) != 0 &&
	    (lqe->lqe_hardlimit != hard || lqe->lqe_softlimit != soft)) {
		rc = qmt_validate_limits(lqe, hard, soft);
		if (rc)
			GOTO(out, rc);

		/* recompute qunit in case it was never initialized */
		qmt_revalidate(env, lqe);

		/* change quota limits */
		lqe->lqe_hardlimit = hard;
		lqe->lqe_softlimit = soft;

		/* clear grace time */
		if (lqe->lqe_softlimit == 0 ||
		    lqe->lqe_granted <= lqe->lqe_softlimit)
			/* no soft limit or below soft limit, let's clear grace
			 * time */
			lqe->lqe_gracetime = 0;
		else if ((valid & QIF_TIMES) == 0)
			/* set grace only if user hasn't provided his own */
			 lqe->lqe_gracetime = now + qmt_lqe_grace(lqe);

		/* change enforced status based on new parameters */
		if (lqe->lqe_hardlimit == 0 && lqe->lqe_softlimit == 0)
			lqe->lqe_enforced = false;
		else
			lqe->lqe_enforced = true;

		dirtied = true;
	}

	if (dirtied) {
		/* write new quota settings to disk */
		rc = qmt_glb_write(env, th, lqe, LQUOTA_BUMP_VER, &ver);
		if (rc) {
			/* restore initial quota settings */
			qmt_restore(lqe, &qti->qti_restore);
			GOTO(out, rc);
		}

		/* compute new qunit value now that we have modified the quota
		 * settings */
		qmt_adjust_qunit(env, lqe);

		/* clear/set edquot flag as needed */
		qmt_adjust_edquot(lqe, now);
	}
	EXIT;
out:
	lqe_write_unlock(lqe);
out_nolock:
	lqe_putref(lqe);

	if (th != NULL && !IS_ERR(th))
		dt_trans_stop(env, qmt->qmt_child, th);

	if (rc == 0 && dirtied)
		qmt_glb_lock_notify(env, lqe, ver);

	return rc;
}

/*
 * Handle quotactl request.
 *
 * \param env   - is the environment passed by the caller
 * \param ld    - is the lu device associated with the qmt
 * \param oqctl - is the quotactl request
 */
static int qmt_quotactl(const struct lu_env *env, struct lu_device *ld,
			struct obd_quotactl *oqctl)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	union lquota_id		*id  = &qti->qti_id;
	struct qmt_device	*qmt = lu2qmt_dev(ld);
	struct obd_dqblk	*dqb = &oqctl->qc_dqblk;
	int			 rc = 0;
	ENTRY;

	LASSERT(qmt != NULL);

	if (oqctl->qc_type >= LL_MAXQUOTAS)
		/* invalid quota type */
		RETURN(-EINVAL);

	switch (oqctl->qc_cmd) {

	case Q_GETINFO:  /* read grace times */
		/* Global grace time is stored in quota settings of ID 0. */
		id->qid_uid = 0;

		/* read inode grace time */
		rc = qmt_get(env, qmt, 0, LQUOTA_RES_MD, oqctl->qc_type, id,
			     NULL, NULL, &oqctl->qc_dqinfo.dqi_igrace);
		if (rc)
			break;

		/* read block grace time */
		rc = qmt_get(env, qmt, 0, LQUOTA_RES_DT, oqctl->qc_type, id,
			     NULL, NULL, &oqctl->qc_dqinfo.dqi_bgrace);
		break;

	case Q_SETINFO:  /* modify grace times */
		/* setinfo should be using dqi->dqi_valid, but lfs incorrectly
		 * sets the valid flags in dqb->dqb_valid instead, try to live
		 * with that ... */

		/* Global grace time is stored in quota settings of ID 0. */
		id->qid_uid = 0;

		if ((dqb->dqb_valid & QIF_ITIME) != 0) {
			/* set inode grace time */
			rc = qmt_set(env, qmt, 0, LQUOTA_RES_MD, oqctl->qc_type,
				     id, 0, 0, oqctl->qc_dqinfo.dqi_igrace,
				     QIF_TIMES);
			if (rc)
				break;
		}

		if ((dqb->dqb_valid & QIF_BTIME) != 0)
			/* set block grace time */
			rc = qmt_set(env, qmt, 0, LQUOTA_RES_DT, oqctl->qc_type,
				     id, 0, 0, oqctl->qc_dqinfo.dqi_bgrace,
				     QIF_TIMES);
		break;

	case Q_GETQUOTA: /* consult quota limit */
		/* There is no quota limit for root user & group */
		if (oqctl->qc_id == 0) {
			memset(dqb, 0, sizeof(*dqb));
			dqb->dqb_valid = QIF_LIMITS | QIF_TIMES;
			break;
		}
		/* extract quota ID from quotactl request */
		id->qid_uid = oqctl->qc_id;

		/* look-up inode quota settings */
		rc = qmt_get(env, qmt, 0, LQUOTA_RES_MD, oqctl->qc_type, id,
			     &dqb->dqb_ihardlimit, &dqb->dqb_isoftlimit,
			     &dqb->dqb_itime);
		if (rc)
			break;

		dqb->dqb_valid |= QIF_ILIMITS | QIF_ITIME;
		/* master isn't aware of actual inode usage */
		dqb->dqb_curinodes = 0;

		/* look-up block quota settings */
		rc = qmt_get(env, qmt, 0, LQUOTA_RES_DT, oqctl->qc_type, id,
			     &dqb->dqb_bhardlimit, &dqb->dqb_bsoftlimit,
			     &dqb->dqb_btime);
		if (rc)
			break;

		dqb->dqb_valid |= QIF_BLIMITS | QIF_BTIME;
		/* master doesn't know the actual block usage */
		dqb->dqb_curspace = 0;
		break;

	case Q_SETQUOTA: /* change quota limits */
		if (oqctl->qc_id == 0)
			/* can't enforce a quota limit for root user & group */
			RETURN(-EPERM);
		/* extract quota ID from quotactl request */
		id->qid_uid = oqctl->qc_id;

		if ((dqb->dqb_valid & QIF_IFLAGS) != 0) {
			/* update inode quota settings */
			rc = qmt_set(env, qmt, 0, LQUOTA_RES_MD, oqctl->qc_type,
				     id, dqb->dqb_ihardlimit,
				     dqb->dqb_isoftlimit, dqb->dqb_itime,
				     dqb->dqb_valid & QIF_IFLAGS);
			if (rc)
				break;
		}

		if ((dqb->dqb_valid & QIF_BFLAGS) != 0)
			/* update block quota settings */
			rc = qmt_set(env, qmt, 0, LQUOTA_RES_DT, oqctl->qc_type,
				     id, dqb->dqb_bhardlimit,
				     dqb->dqb_bsoftlimit, dqb->dqb_btime,
				     dqb->dqb_valid & QIF_BFLAGS);
		break;

	default:
		CERROR("%s: unsupported quotactl command: %d\n",
		       qmt->qmt_svname, oqctl->qc_cmd);
		RETURN(-ENOTSUPP);
	}

	RETURN(rc);
}

/*
 * Helper function to handle quota request from slave.
 *
 * \param env     - is the environment passed by the caller
 * \param lqe     - is the lquota_entry subject to the quota request
 * \param qmt     - is the master device
 * \param uuid    - is the uuid associated with the slave
 * \param qb_flags - are the quota request flags as packed in the quota_body
 * \param qb_count - is the amount of quota space the slave wants to
 *                   acquire/release
 * \param qb_usage - is the current space usage on the slave
 * \param repbody - is the quota_body of reply
 *
 * \retval 0            : success
 * \retval -EDQUOT      : out of quota
 *         -EINPROGRESS : inform client to retry write/create
 *         -ve          : other appropriate errors
 */
int qmt_dqacq0(const struct lu_env *env, struct lquota_entry *lqe,
	       struct qmt_device *qmt, struct obd_uuid *uuid, __u32 qb_flags,
	       __u64 qb_count, __u64 qb_usage, struct quota_body *repbody)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	__u64			 now, count;
	struct dt_object	*slv_obj = NULL;
	__u64			 slv_granted, slv_granted_bck;
	struct thandle		*th = NULL;
	int			 rc, ret;
	ENTRY;

	LASSERT(uuid != NULL);

	/* initialize reply */
	memset(repbody, 0, sizeof(*repbody));
	memcpy(&repbody->qb_id, &lqe->lqe_id, sizeof(repbody->qb_id));

	if (OBD_FAIL_CHECK(OBD_FAIL_QUOTA_RECOVERABLE_ERR))
		RETURN(-cfs_fail_val);

	/* look-up index file associated with acquiring slave */
	slv_obj = lquota_disk_slv_find(env, qmt->qmt_child, LQE_ROOT(lqe),
				       lu_object_fid(&LQE_GLB_OBJ(lqe)->do_lu),
				       uuid);
	if (IS_ERR(slv_obj))
		GOTO(out, rc = PTR_ERR(slv_obj));

	/* pack slave fid in reply just for sanity check */
	memcpy(&repbody->qb_slv_fid, lu_object_fid(&slv_obj->do_lu),
	       sizeof(struct lu_fid));

	/* allocate & start transaction with enough credits to update
	 * global & slave indexes */
	th = qmt_trans_start_with_slv(env, lqe, slv_obj, &qti->qti_restore);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	lqe_write_lock(lqe);
	LQUOTA_DEBUG(lqe, "dqacq starts uuid:%s flags:0x%x wanted:%llu"
		     " usage:%llu", obd_uuid2str(uuid), qb_flags, qb_count,
		     qb_usage);

	/* Legal race, limits have been removed on master, but slave didn't
	 * receive the change yet. Just return EINPROGRESS until the slave gets
	 * notified. */
	if (!lqe->lqe_enforced && !req_is_rel(qb_flags))
		GOTO(out_locked, rc = -ESRCH);

	/* recompute qunit in case it was never initialized */
	qmt_revalidate(env, lqe);

	/* slave just wants to acquire per-ID lock */
	if (req_is_acq(qb_flags) && qb_count == 0)
		GOTO(out_locked, rc = 0);

	/* fetch how much quota space is already granted to this slave */
	rc = qmt_slv_read(env, lqe, slv_obj, &slv_granted);
	if (rc) {
		LQUOTA_ERROR(lqe, "Failed to get granted for slave %s, rc=%d",
			     obd_uuid2str(uuid), rc);
		GOTO(out_locked, rc);
	}
	/* recall how much space this slave currently owns in order to restore
	 * it in case of failure */
	slv_granted_bck = slv_granted;

	/* record current time for soft limit & grace time management */
	now = ktime_get_real_seconds();

	if (req_is_rel(qb_flags)) {
		/* Slave would like to release quota space */
		if (slv_granted < qb_count ||
		    lqe->lqe_granted < qb_count) {
			/* can't release more than granted */
			LQUOTA_ERROR(lqe, "Release too much! uuid:%s release:"
				     "%llu granted:%llu, total:%llu",
				     obd_uuid2str(uuid), qb_count,
				     slv_granted, lqe->lqe_granted);
			GOTO(out_locked, rc = -EINVAL);
		}

		repbody->qb_count = qb_count;
		/* put released space back to global pool */
		QMT_REL(lqe, slv_granted, qb_count);
		GOTO(out_write, rc = 0);
	}

	if (req_has_rep(qb_flags) && slv_granted < qb_usage) {
		/* Slave is reporting space usage in quota request and it turns
		 * out to be using more quota space than owned, so we adjust
		 * granted space regardless of the current state of affairs */
		repbody->qb_count = qb_usage - slv_granted;
		QMT_GRANT(lqe, slv_granted, repbody->qb_count);
	}

	if (!req_is_acq(qb_flags) && !req_is_preacq(qb_flags))
		GOTO(out_write, rc = 0);

	qmt_adjust_edquot(lqe, now);
	if (lqe->lqe_edquot)
		/* no hope to claim further space back */
		GOTO(out_write, rc = -EDQUOT);

	if (qmt_space_exhausted(lqe, now)) {
		/* might have some free space once rebalancing is completed */
		rc = req_is_acq(qb_flags) ? -EINPROGRESS : -EDQUOT;
		GOTO(out_write, rc);
	}

	if (req_is_preacq(qb_flags)) {
		/* slave would like to pre-acquire quota space. To do so, it
		 * reports in qb_count how much spare quota space it owns and we
		 * can grant back quota space which is consistent with qunit
		 * value. */

		if (qb_count >= lqe->lqe_qunit)
			/* slave already own the maximum it should */
			GOTO(out_write, rc = 0);

		count = qmt_alloc_expand(lqe, slv_granted, qb_count);
		if (count == 0)
			GOTO(out_write, rc = -EDQUOT);

		repbody->qb_count += count;
		QMT_GRANT(lqe, slv_granted, count);
		GOTO(out_write, rc = 0);
	}

	/* processing acquire request with clients waiting */
	if (lqe->lqe_hardlimit != 0 &&
	    lqe->lqe_granted + qb_count > lqe->lqe_hardlimit) {
		/* cannot grant as much as asked, but can still afford to grant
		 * some quota space back */
		count = lqe->lqe_hardlimit - lqe->lqe_granted;
		repbody->qb_count += count;
		QMT_GRANT(lqe, slv_granted, count);
		GOTO(out_write, rc = 0);
	}

	/* Whouhou! we can satisfy the slave request! */
	repbody->qb_count += qb_count;
	QMT_GRANT(lqe, slv_granted, qb_count);

	/* Try to expand the acquired count for DQACQ */
	count = qmt_alloc_expand(lqe, slv_granted, 0);
	if (count != 0) {
		/* can even grant more than asked, it is like xmas ... */
		repbody->qb_count += count;
		QMT_GRANT(lqe, slv_granted, count);
		GOTO(out_write, rc = 0);
	}

	GOTO(out_write, rc = 0);
out_write:
	if (repbody->qb_count == 0)
		GOTO(out_locked, rc);

	/* start/stop grace timer if required */
	if (lqe->lqe_softlimit != 0) {
		if (lqe->lqe_granted > lqe->lqe_softlimit &&
		    lqe->lqe_gracetime == 0)
			/* first time over soft limit, let's start grace
			 * timer */
			lqe->lqe_gracetime = now + qmt_lqe_grace(lqe);
		else if (lqe->lqe_granted <= lqe->lqe_softlimit &&
			 lqe->lqe_gracetime != 0)
			/* Clear grace timer */
			lqe->lqe_gracetime = 0;
	}

	/* Update slave index first since it is easier to roll back */
	ret = qmt_slv_write(env, th, lqe, slv_obj, LQUOTA_BUMP_VER,
			    &repbody->qb_slv_ver, slv_granted);
	if (ret) {
		/* restore initial quota settings */
		qmt_restore(lqe, &qti->qti_restore);
		/* reset qb_count */
		repbody->qb_count = 0;
		GOTO(out_locked, rc = ret);
	}

	/* Update global index, no version bump needed */
	ret = qmt_glb_write(env, th, lqe, 0, NULL);
	if (ret) {
		rc = ret;
		/* restore initial quota settings */
		qmt_restore(lqe, &qti->qti_restore);
		/* reset qb_count */
		repbody->qb_count = 0;

		/* restore previous granted value */
		ret = qmt_slv_write(env, th, lqe, slv_obj, 0, NULL,
				    slv_granted_bck);
		if (ret) {
			LQUOTA_ERROR(lqe, "failed to restore initial slave "
				     "value rc:%d ret%d", rc, ret);
			LBUG();
		}
		qmt_adjust_edquot(lqe, now);
		GOTO(out_locked, rc);
	}

	/* Total granted has been changed, let's try to adjust the qunit
	 * size according to the total granted & limits. */
	qmt_adjust_qunit(env, lqe);

	/* clear/set edquot flag and notify slaves via glimpse if needed */
	qmt_adjust_edquot(lqe, now);
out_locked:
	LQUOTA_DEBUG(lqe, "dqacq ends count:%llu ver:%llu rc:%d",
		     repbody->qb_count, repbody->qb_slv_ver, rc);
	lqe_write_unlock(lqe);
out:
	if (th != NULL && !IS_ERR(th))
		dt_trans_stop(env, qmt->qmt_child, th);

	if (slv_obj != NULL && !IS_ERR(slv_obj))
		dt_object_put(env, slv_obj);

	if ((req_is_acq(qb_flags) || req_is_preacq(qb_flags)) &&
	    OBD_FAIL_CHECK(OBD_FAIL_QUOTA_EDQUOT)) {
		/* introduce inconsistency between granted value in slave index
		 * and slave index copy of slave */
		repbody->qb_count = 0;
		rc = -EDQUOT;
	}

	RETURN(rc);
}

/*
 * Handle quota request from slave.
 *
 * \param env  - is the environment passed by the caller
 * \param ld   - is the lu device associated with the qmt
 * \param req  - is the quota acquire request
 */
static int qmt_dqacq(const struct lu_env *env, struct lu_device *ld,
		     struct ptlrpc_request *req)
{
	struct qmt_device	*qmt = lu2qmt_dev(ld);
	struct quota_body	*qbody, *repbody;
	struct obd_uuid		*uuid;
	struct ldlm_lock	*lock;
	struct lquota_entry	*lqe;
	int			 pool_id, pool_type, qtype;
	int			 rc;
	ENTRY;

	qbody = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_BODY);
	if (qbody == NULL)
		RETURN(err_serious(-EPROTO));

	repbody = req_capsule_server_get(&req->rq_pill, &RMF_QUOTA_BODY);
	if (repbody == NULL)
		RETURN(err_serious(-EFAULT));

	/* verify if global lock is stale */
	if (!lustre_handle_is_used(&qbody->qb_glb_lockh))
		RETURN(-ENOLCK);

	lock = ldlm_handle2lock(&qbody->qb_glb_lockh);
	if (lock == NULL)
		RETURN(-ENOLCK);
	LDLM_LOCK_PUT(lock);

	uuid = &req->rq_export->exp_client_uuid;

	if (req_is_rel(qbody->qb_flags) + req_is_acq(qbody->qb_flags) +
	    req_is_preacq(qbody->qb_flags) > 1) {
		CERROR("%s: malformed quota request with conflicting flags set "
		       "(%x) from slave %s\n", qmt->qmt_svname,
		       qbody->qb_flags, obd_uuid2str(uuid));
		RETURN(-EPROTO);
	}

	if (req_is_acq(qbody->qb_flags) || req_is_preacq(qbody->qb_flags)) {
		/* acquire and pre-acquire should use a valid ID lock */

		if (!lustre_handle_is_used(&qbody->qb_lockh))
			RETURN(-ENOLCK);

		lock = ldlm_handle2lock(&qbody->qb_lockh);
		if (lock == NULL)
			/* no lock associated with this handle */
			RETURN(-ENOLCK);

		LDLM_DEBUG(lock, "%sacquire request",
			   req_is_preacq(qbody->qb_flags) ? "pre" : "");

		if (!obd_uuid_equals(&lock->l_export->exp_client_uuid, uuid)) {
			/* sorry, no way to cheat ... */
			LDLM_LOCK_PUT(lock);
			RETURN(-ENOLCK);
		}

		if (ldlm_is_ast_sent(lock)) {
			struct ptlrpc_service_part	*svc;
			unsigned int			 timeout;

			svc = req->rq_rqbd->rqbd_svcpt;
			timeout = at_est2timeout(at_get(&svc->scp_at_estimate));
			timeout += (ldlm_bl_timeout(lock) >> 1);

			/* lock is being cancelled, prolong timeout */
			ldlm_refresh_waiting_lock(lock, timeout);
		}
		LDLM_LOCK_PUT(lock);
	}

	/* extract pool & quota information from global index FID packed in the
	 * request */
	rc = lquota_extract_fid(&qbody->qb_fid, &pool_id, &pool_type, &qtype);
	if (rc)
		RETURN(-EINVAL);

	/* Find the quota entry associated with the quota id */
	lqe = qmt_pool_lqe_lookup(env, qmt, pool_id, pool_type, qtype,
				  &qbody->qb_id);
	if (IS_ERR(lqe))
		RETURN(PTR_ERR(lqe));

	/* process quota request */
	rc = qmt_dqacq0(env, lqe, qmt, uuid, qbody->qb_flags, qbody->qb_count,
			qbody->qb_usage, repbody);

	if (lustre_handle_is_used(&qbody->qb_lockh))
		/* return current qunit value only to slaves owning an per-ID
		 * quota lock. For enqueue, the qunit value will be returned in
		 * the LVB */
		 repbody->qb_qunit = lqe->lqe_qunit;
	lqe_putref(lqe);
	RETURN(rc);
}

/* Vector of quota request handlers. This vector is used by the MDT to forward
 * requests to the quota master. */
struct qmt_handlers qmt_hdls = {
	/* quota request handlers */
	.qmth_quotactl		= qmt_quotactl,
	.qmth_dqacq		= qmt_dqacq,

	/* ldlm handlers */
	.qmth_intent_policy	= qmt_intent_policy,
	.qmth_lvbo_init		= qmt_lvbo_init,
	.qmth_lvbo_update	= qmt_lvbo_update,
	.qmth_lvbo_size		= qmt_lvbo_size,
	.qmth_lvbo_fill		= qmt_lvbo_fill,
	.qmth_lvbo_free		= qmt_lvbo_free,
};
EXPORT_SYMBOL(qmt_hdls);
