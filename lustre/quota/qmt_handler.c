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

#include <obd_class.h>
#include "qmt_internal.h"

/*
 * Fetch grace time for either inode or block.
 *
 * \param env     - is the environment passed by the caller
 * \param qmt     - is the quota master target
 * \param pool_id - is the 16-bit pool identifier
 * \param restype - is the pool type, either block (i.e. LQUOTA_RES_DT) or inode
 *                  (i.e. LQUOTA_RES_MD)
 * \param qtype   - is the quota type
 * \param time    - is the output variable where to copy the grace time
 */
static int qmt_getinfo(const struct lu_env *env, struct qmt_device *qmt,
		       __u16 pool_id, __u8 restype, __u8 qtype, __u64 *time)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	union lquota_id		*id  = &qti->qti_id_bis;
	struct lquota_entry	*lqe;
	ENTRY;

	/* Global grace time is stored in quota settings of ID 0. */
	id->qid_uid = 0;

	/* look-up quota entry storing grace time */
	lqe = qmt_pool_lqe_lookup(env, qmt, pool_id, restype, qtype, id);
	if (IS_ERR(lqe))
		RETURN(PTR_ERR(lqe));

	lqe_read_lock(lqe);
	LQUOTA_DEBUG(lqe, "getinfo");
	/* copy grace time */
	*time = lqe->lqe_gracetime;
	lqe_read_unlock(lqe);

	lqe_putref(lqe);
	RETURN(0);
}

/*
 * Update grace time for either inode or block.
 * Global grace time is stored in quota settings of ID 0.
 *
 * \param env     - is the environment passed by the caller
 * \param qmt     - is the quota master target
 * \param pool_id - is the 16-bit pool identifier
 * \param restype - is the pool type, either block (i.e. LQUOTA_RES_DT) or inode
 *                  (i.e. LQUOTA_RES_MD)
 * \param qtype   - is the quota type
 * \param time    - is the new grace time
 */
static int qmt_setinfo(const struct lu_env *env, struct qmt_device *qmt,
		       __u16 pool_id, __u8 restype, __u8 qtype, __u64 time)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	union lquota_id		*id  = &qti->qti_id_bis;
	struct lquota_entry	*lqe;
	struct thandle		*th = NULL;
	int			 rc;
	ENTRY;

	/* Global grace time is stored in quota settings of ID 0. */
	id->qid_uid = 0;

	/* look-up quota entry storing the global grace time */
	lqe = qmt_pool_lqe_lookup(env, qmt, pool_id, restype, qtype, id);
	if (IS_ERR(lqe))
		RETURN(PTR_ERR(lqe));

	/* allocate & start transaction with enough credits to update grace
	 * time in the global index file */
	th = qmt_trans_start(env, lqe, &qti->qti_restore);
	if (IS_ERR(th))
		GOTO(out_nolock, rc = PTR_ERR(th));

	/* write lock quota entry storing the grace time */
	lqe_write_lock(lqe);
	if (lqe->lqe_gracetime == time)
		/* grace time is the same */
		GOTO(out, rc = 0);

	LQUOTA_DEBUG(lqe, "setinfo time:"LPU64, time);

	/* set new grace time */
	lqe->lqe_gracetime = time;
	/* always set enforced bit for ID 0 to make sure it does not go away */
	lqe->lqe_enforced  = true;

	/* write new grace time to disk, no need for version bump */
	rc = qmt_glb_write(env, th, lqe, 0, NULL);
	if (rc) {
		/* restore initial grace time */
		qmt_restore(lqe, &qti->qti_restore);
		GOTO(out, rc);
	}
	EXIT;
out:
	lqe_write_unlock(lqe);
out_nolock:
	lqe_putref(lqe);
	if (th != NULL && !IS_ERR(th))
		dt_trans_stop(env, qmt->qmt_child, th);
	return rc;
}

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
static int qmt_getquota(const struct lu_env *env, struct qmt_device *qmt,
			__u16 pool_id, __u8 restype, __u8 qtype,
			union lquota_id *id, __u64 *hard, __u64 *soft,
			__u64 *time)
{
	struct lquota_entry	*lqe;
	ENTRY;

	/* look-up lqe structure containing quota settings */
	lqe = qmt_pool_lqe_lookup(env, qmt, pool_id, restype, qtype, id);
	if (IS_ERR(lqe))
		RETURN(PTR_ERR(lqe));

	/* copy quota settings */
	lqe_read_lock(lqe);
	LQUOTA_DEBUG(lqe, "getquota");
	*hard = lqe->lqe_hardlimit;
	*soft = lqe->lqe_softlimit;
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
static int qmt_setquota(const struct lu_env *env, struct qmt_device *qmt,
			__u16 pool_id, __u8 restype, __u8 qtype,
			union lquota_id *id, __u64 hard, __u64 soft, __u64 time,
			__u32 valid)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_entry	*lqe;
	struct thandle		*th = NULL;
	__u64			 grace, ver;
	bool			 dirtied = false, bump_version = false;
	int			 rc = 0;
	ENTRY;

	/* fetch global grace time */
	rc = qmt_getinfo(env, qmt, pool_id, restype, qtype, &grace);
	if (rc)
		RETURN(rc);

	/* look-up quota entry associated with this ID */
	lqe = qmt_pool_lqe_lookup(env, qmt, pool_id, restype, qtype, id);
	if (IS_ERR(lqe))
		RETURN(PTR_ERR(lqe));

	/* allocate & start transaction with enough credits to update quota
	 * settings in the global index file */
	th = qmt_trans_start(env, lqe, &qti->qti_restore);
	if (IS_ERR(th))
		GOTO(out_nolock, rc = PTR_ERR(th));

	lqe_write_lock(lqe);
	LQUOTA_DEBUG(lqe, "setquota valid:%x hard:"LPU64" soft:"LPU64
		     " time:"LPU64, valid, hard, soft, time);

	if ((valid & QIF_TIMES) != 0 && lqe->lqe_gracetime != time) {
		/* change time settings */
		lqe->lqe_gracetime = time;
		dirtied            = true;
	}

	if ((valid & QIF_LIMITS) != 0 &&
	    (lqe->lqe_hardlimit != hard || lqe->lqe_softlimit != soft)) {
		bool enforced = lqe->lqe_enforced;

		rc = qmt_validate_limits(lqe, hard, soft);
		if (rc)
			GOTO(out, rc);

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
			 lqe->lqe_gracetime = cfs_time_current_sec() + grace;

		/* change enforced status based on new parameters */
		if (lqe->lqe_hardlimit == 0 && lqe->lqe_softlimit == 0)
			lqe->lqe_enforced = false;
		else
			lqe->lqe_enforced = true;

		if ((enforced && !lqe->lqe_enforced) ||
		    (!enforced && lqe->lqe_enforced))
			/* if enforced status has changed, we need to inform
			 * slave, therefore we need to bump the version */
			 bump_version = true;

		dirtied = true;
	}

	if (dirtied) {
		/* write new quota settings to disk */
		rc = qmt_glb_write(env, th, lqe,
				   bump_version ? LQUOTA_BUMP_VER : 0, &ver);
		if (rc) {
			/* restore initial quota settings */
			qmt_restore(lqe, &qti->qti_restore);
			GOTO(out, rc);
		}
	}
	EXIT;
out:
	lqe_write_unlock(lqe);
out_nolock:
	lqe_putref(lqe);

	if (th != NULL && !IS_ERR(th))
		dt_trans_stop(env, qmt->qmt_child, th);

	if (rc == 0 && bump_version)
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

	if (oqctl->qc_type >= MAXQUOTAS)
		/* invalid quota type */
		RETURN(-EINVAL);

	switch (oqctl->qc_cmd) {

	case Q_GETINFO:  /* read grace times */
		/* read inode grace time */
		rc = qmt_getinfo(env, qmt, 0, LQUOTA_RES_MD, oqctl->qc_type,
				 &oqctl->qc_dqinfo.dqi_igrace);
		if (rc)
			break;

		/* read block grace time */
		rc = qmt_getinfo(env, qmt, 0, LQUOTA_RES_DT, oqctl->qc_type,
				 &oqctl->qc_dqinfo.dqi_bgrace);
		break;

	case Q_SETINFO:  /* modify grace times */
		/* setinfo should be using dqi->dqi_valid, but lfs incorrectly
		 * sets the valid flags in dqb->dqb_valid instead, try to live
		 * with that ... */
		if ((dqb->dqb_valid & QIF_ITIME) != 0) {
			/* set inode grace time */
			rc = qmt_setinfo(env, qmt, 0, LQUOTA_RES_MD,
					 oqctl->qc_type,
					 oqctl->qc_dqinfo.dqi_igrace);
			if (rc)
				break;
		}

		if ((dqb->dqb_valid & QIF_BTIME) != 0)
			/* set block grace time */
			rc = qmt_setinfo(env, qmt, 0, LQUOTA_RES_DT,
					 oqctl->qc_type,
					 oqctl->qc_dqinfo.dqi_bgrace);
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
		rc = qmt_getquota(env, qmt, 0, LQUOTA_RES_MD, oqctl->qc_type,
				  id, &dqb->dqb_ihardlimit,
				  &dqb->dqb_isoftlimit, &dqb->dqb_itime);
		if (rc)
			break;

		dqb->dqb_valid |= QIF_ILIMITS | QIF_ITIME;
		/* master isn't aware of actual inode usage */
		dqb->dqb_curinodes = 0;

		/* look-up block quota settings */
		rc = qmt_getquota(env, qmt, 0, LQUOTA_RES_DT, oqctl->qc_type,
				  id, &dqb->dqb_bhardlimit,
				  &dqb->dqb_bsoftlimit, &dqb->dqb_btime);
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
			rc = qmt_setquota(env, qmt, 0, LQUOTA_RES_MD,
					  oqctl->qc_type, id,
					  dqb->dqb_ihardlimit,
					  dqb->dqb_isoftlimit, dqb->dqb_itime,
					  dqb->dqb_valid & QIF_IFLAGS);
			if (rc)
				break;
		}

		if ((dqb->dqb_valid & QIF_BFLAGS) != 0)
			/* update block quota settings */
			rc = qmt_setquota(env, qmt, 0, LQUOTA_RES_DT,
					  oqctl->qc_type, id,
					  dqb->dqb_bhardlimit,
					  dqb->dqb_bsoftlimit, dqb->dqb_btime,
					  dqb->dqb_valid & QIF_BFLAGS);
		break;

	case Q_QUOTAON:
	case Q_QUOTAOFF:   /* quota is always turned on on the master */
		RETURN(0);

	case LUSTRE_Q_INVALIDATE: /* not supported any more */
		RETURN(-ENOTSUPP);

	default:
		CERROR("%s: unsupported quotactl command: %d\n",
		       qmt->qmt_svname, oqctl->qc_cmd);
		RETURN(-ENOTSUPP);
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
	struct quota_body	*qbody, *repbody;
	ENTRY;

	qbody = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_BODY);
	if (qbody == NULL)
		RETURN(err_serious(-EPROTO));

	repbody = req_capsule_server_get(&req->rq_pill, &RMF_QUOTA_BODY);
	if (repbody == NULL)
		RETURN(err_serious(-EFAULT));

	/* XXX: to be implemented */

	RETURN(0);
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
