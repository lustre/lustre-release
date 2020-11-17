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

#include <lustre_dlm.h>
#include <obd_class.h>
#include <lustre_swab.h>

#include "qsd_internal.h"

typedef int (enqi_bl_cb_t)(struct ldlm_lock *lock,
			   struct ldlm_lock_desc *desc, void *data,
			   int flag);
static enqi_bl_cb_t qsd_glb_blocking_ast, qsd_id_blocking_ast;

typedef int (enqi_gl_cb_t)(struct ldlm_lock *lock, void *data);
static enqi_gl_cb_t qsd_glb_glimpse_ast, qsd_id_glimpse_ast;

struct ldlm_enqueue_info qsd_glb_einfo = {
	.ei_type	= LDLM_PLAIN,
	.ei_mode	= LCK_CR,
	.ei_cb_bl	= qsd_glb_blocking_ast,
	.ei_cb_cp	= ldlm_completion_ast,
	.ei_cb_gl	= qsd_glb_glimpse_ast,
};

struct ldlm_enqueue_info qsd_id_einfo = {
	.ei_type	= LDLM_PLAIN,
	.ei_mode	= LCK_CR,
	.ei_cb_bl	= qsd_id_blocking_ast,
	.ei_cb_cp	= ldlm_completion_ast,
	.ei_cb_gl	= qsd_id_glimpse_ast,
};

/*
 * Return qsd_qtype_info structure associated with a global lock
 *
 * \param lock - is the global lock from which we should extract the qqi
 * \param reset - whether lock->l_ast_data should be cleared
 */
static struct qsd_qtype_info *qsd_glb_ast_data_get(struct ldlm_lock *lock,
						   bool reset)
{
	struct qsd_qtype_info *qqi;

	ENTRY;

	lock_res_and_lock(lock);
	qqi = lock->l_ast_data;
	if (qqi) {
		qqi_getref(qqi);
		if (reset)
			lock->l_ast_data = NULL;
	}
	unlock_res_and_lock(lock);

	if (qqi)
		/* it is not safe to call lu_ref_add() under spinlock */
		lu_ref_add(&qqi->qqi_reference, "ast_data_get", lock);

	if (reset && qqi) {
		/* release qqi reference hold for the lock */
		lu_ref_del(&qqi->qqi_reference, "glb_lock", lock);
		qqi_putref(qqi);
	}
	RETURN(qqi);
}

/*
 * Return lquota entry structure associated with a per-ID lock
 *
 * \param lock - is the per-ID lock from which we should extract the lquota
 *               entry
 * \param reset - whether lock->l_ast_data should be cleared
 */
static struct lquota_entry *qsd_id_ast_data_get(struct ldlm_lock *lock,
						bool reset)
{
	struct lquota_entry *lqe;

	ENTRY;

	lock_res_and_lock(lock);
	lqe = lock->l_ast_data;
	if (lqe) {
		lqe_getref(lqe);
		if (reset)
			lock->l_ast_data = NULL;
	}
	unlock_res_and_lock(lock);

	if (reset && lqe)
		/* release lqe reference hold for the lock */
		lqe_putref(lqe);
	RETURN(lqe);
}

/*
 * Glimpse callback handler for all quota locks. This function extracts
 * information from the glimpse request.
 *
 * \param lock - is the lock targeted by the glimpse
 * \param data - is a pointer to the glimpse ptlrpc request
 * \param req  - is the glimpse request
 * \param desc - is the glimpse descriptor describing the purpose of the glimpse
 *               request.
 * \param lvb  - is the pointer to the lvb in the reply buffer
 *
 * \retval 0 on success and \desc, \lvb & \arg point to a valid structures,
 *         appropriate error on failure
 */
static int qsd_common_glimpse_ast(struct ptlrpc_request *req,
				  struct ldlm_gl_lquota_desc **desc, void **lvb)
{
	int rc;

	ENTRY;

	LASSERT(lustre_msg_get_opc(req->rq_reqmsg) == LDLM_GL_CALLBACK);

	/* glimpse on quota locks always packs a glimpse descriptor */
	req_capsule_extend(&req->rq_pill, &RQF_LDLM_GL_CALLBACK_DESC);

	/* extract glimpse descriptor */
	*desc = req_capsule_client_get(&req->rq_pill, &RMF_DLM_GL_DESC);
	if (!*desc)
		RETURN(-EFAULT);

	if (req_capsule_req_need_swab(&req->rq_pill))
		lustre_swab_gl_lquota_desc(*desc);

	/* prepare reply */
	req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
			     sizeof(struct lquota_lvb));
	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc != 0) {
		CERROR("Can't pack response, rc %d\n", rc);
		RETURN(rc);
	}

	/* extract lvb */
	*lvb = req_capsule_server_get(&req->rq_pill, &RMF_DLM_LVB);

	RETURN(0);
}

/*
 * Blocking callback handler for global index lock
 *
 * \param lock - is the lock for which ast occurred.
 * \param desc - is the description of a conflicting lock in case of blocking
 *               ast.
 * \param data - is the value of lock->l_ast_data
 * \param flag - LDLM_CB_BLOCKING or LDLM_CB_CANCELING. Used to distinguish
 *               cancellation and blocking ast's.
 */
static int qsd_glb_blocking_ast(struct ldlm_lock *lock,
				struct ldlm_lock_desc *desc, void *data,
				int flag)
{
	int rc = 0;

	ENTRY;

	switch (flag) {
	case LDLM_CB_BLOCKING: {
		struct lustre_handle lockh;

		LDLM_DEBUG(lock, "blocking AST on global quota lock");
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		break;
	}
	case LDLM_CB_CANCELING: {
		struct qsd_qtype_info *qqi;

		LDLM_DEBUG(lock, "canceling global quota lock");

		qqi = qsd_glb_ast_data_get(lock, true);
		if (!qqi)
			break;

		/*
		 * we are losing the global index lock, so let's mark the
		 * global & slave indexes as not up-to-date any more
		 */
		write_lock(&qqi->qqi_qsd->qsd_lock);
		qqi->qqi_glb_uptodate = false;
		qqi->qqi_slv_uptodate = false;
		if (lock->l_handle.h_cookie == qqi->qqi_lockh.cookie)
			memset(&qqi->qqi_lockh, 0, sizeof(qqi->qqi_lockh));
		write_unlock(&qqi->qqi_qsd->qsd_lock);

		CDEBUG(D_QUOTA, "%s: losing global index lock for %s type\n",
		       qqi->qqi_qsd->qsd_svname, qtype_name((qqi->qqi_qtype)));

		/*
		 * kick off reintegration thread if not running already, if
		 * it's just local cancel (for stack clean up or eviction),
		 * don't re-trigger the reintegration.
		 */
		if (!ldlm_is_local_only(lock))
			qsd_start_reint_thread(qqi);

		lu_ref_del(&qqi->qqi_reference, "ast_data_get", lock);
		qqi_putref(qqi);
		break;
	}
	default:
		LASSERTF(0, "invalid flags for blocking ast %d\n", flag);
	}

	RETURN(rc);
}

static int qsd_entry_def_iter_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				 struct hlist_node *hnode, void *data)
{
	struct qsd_qtype_info *qqi = (struct qsd_qtype_info *)data;
	struct lquota_entry *lqe;

	lqe = hlist_entry(hnode, struct lquota_entry, lqe_hash);
	LASSERT(atomic_read(&lqe->lqe_ref) > 0);

	if (lqe->lqe_id.qid_uid == 0 || !lqe->lqe_is_default)
		return 0;

	lqe_write_lock(lqe);
	if (qqi->qqi_default_hardlimit == 0 && qqi->qqi_default_softlimit == 0)
		lqe->lqe_enforced = false;
	else
		lqe->lqe_enforced = true;
	lqe_write_unlock(lqe);

	return 0;
}

/* Update the quota entries after receiving default quota update
 *
 * \param qqi       - is the qsd_qtype_info associated with the quota entries
 * \param hardlimit - new hardlimit of default quota
 * \param softlimit - new softlimit of default quota
 * \param gracetime - new gracetime of default quota
 */
void qsd_update_default_quota(struct qsd_qtype_info *qqi, __u64 hardlimit,
			      __u64 softlimit, __u64 gracetime)
{
	CDEBUG(D_QUOTA, "%s: update default quota setting from QMT.\n",
	       qqi->qqi_qsd->qsd_svname);

	qqi->qqi_default_hardlimit = hardlimit;
	qqi->qqi_default_softlimit = softlimit;
	qqi->qqi_default_gracetime = gracetime;

	cfs_hash_for_each_safe(qqi->qqi_site->lqs_hash,
			       qsd_entry_def_iter_cb, qqi);
}

/*
 * Glimpse callback handler for global quota lock.
 *
 * \param lock - is the lock targeted by the glimpse
 * \param data - is a pointer to the glimpse ptlrpc request
 */
static int qsd_glb_glimpse_ast(struct ldlm_lock *lock, void *data)
{
	struct ptlrpc_request *req = data;
	struct qsd_qtype_info *qqi;
	struct ldlm_gl_lquota_desc *desc;
	struct lquota_lvb *lvb;
	struct lquota_glb_rec rec;
	int rc;

	ENTRY;

	rc = qsd_common_glimpse_ast(req, &desc, (void **)&lvb);
	if (rc)
		GOTO(out, rc);

	qqi = qsd_glb_ast_data_get(lock, false);
	if (!qqi)
		/* valid race */
		GOTO(out, rc = -ELDLM_NO_LOCK_DATA);

	CDEBUG(D_QUOTA,
	       "%s: glimpse on glb quota locks, id:%llu ver:%llu hard:%llu soft:%llu\n",
	       qqi->qqi_qsd->qsd_svname,
	       desc->gl_id.qid_uid, desc->gl_ver, desc->gl_hardlimit,
	       desc->gl_softlimit);

	if (desc->gl_ver == 0) {
		CERROR("%s: invalid global index version %llu\n",
		       qqi->qqi_qsd->qsd_svname, desc->gl_ver);
		GOTO(out_qqi, rc = -EINVAL);
	}

	/* extract new hard & soft limits from the glimpse descriptor */
	rec.qbr_hardlimit = desc->gl_hardlimit;
	rec.qbr_softlimit = desc->gl_softlimit;
	rec.qbr_time      = desc->gl_time;
	rec.qbr_granted   = 0;

	if (desc->gl_id.qid_uid == 0)
		qsd_update_default_quota(qqi, desc->gl_hardlimit,
					 desc->gl_softlimit, desc->gl_time);

	/*
	 * We can't afford disk io in the context of glimpse callback handling
	 * thread, so the on-disk global limits update has to be deferred.
	 */
	qsd_upd_schedule(qqi, NULL, &desc->gl_id, (union lquota_rec *)&rec,
			 desc->gl_ver, true);
	EXIT;
out_qqi:
	lu_ref_del(&qqi->qqi_reference, "ast_data_get", lock);
	qqi_putref(qqi);
out:
	req->rq_status = rc;
	return rc;
}

/**
 * Blocking callback handler for per-ID lock
 *
 * \param lock - is the lock for which ast occurred.
 * \param desc - is the description of a conflicting lock in case of blocking
 *               ast.
 * \param data - is the value of lock->l_ast_data
 * \param flag - LDLM_CB_BLOCKING or LDLM_CB_CANCELING. Used to distinguish
 *               cancellation and blocking ast's.
 */
static int qsd_id_blocking_ast(struct ldlm_lock *lock,
			       struct ldlm_lock_desc *desc,
			       void *data, int flag)
{
	struct lustre_handle lockh;
	int rc = 0;

	ENTRY;

	switch (flag) {
	case LDLM_CB_BLOCKING: {

		LDLM_DEBUG(lock, "blocking AST on ID quota lock");
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		break;
	}
	case LDLM_CB_CANCELING: {
		struct lu_env *env;
		struct lquota_entry *lqe;

		LDLM_DEBUG(lock, "canceling ID quota lock");
		lqe = qsd_id_ast_data_get(lock, true);
		if (!lqe)
			break;

		LQUOTA_DEBUG(lqe, "losing ID lock");

		ldlm_lock2handle(lock, &lockh);
		lqe_write_lock(lqe);
		if (lustre_handle_equal(&lockh, &lqe->lqe_lockh)) {
			/* Clear lqe_lockh & reset qunit to 0 */
			qsd_set_qunit(lqe, 0);
			memset(&lqe->lqe_lockh, 0, sizeof(lqe->lqe_lockh));
			qsd_set_edquot(lqe, false);
		}
		lqe_write_unlock(lqe);

		/*
		 * If there is dqacq inflight, the release will be skipped
		 * at this time, and triggered on dqacq completion later,
		 * which means there could be a short window that slave is
		 * holding spare grant wihtout per-ID lock.
		 */

		/*
		 * don't release quota space for local cancel (stack clean
		 * up or eviction)
		 */
		if (!ldlm_is_local_only(lock)) {
			/* allocate environment */
			OBD_ALLOC_PTR(env);
			if (!env) {
				lqe_putref(lqe);
				rc = -ENOMEM;
				break;
			}

			/* initialize environment */
			rc = lu_env_init(env, LCT_DT_THREAD);
			if (rc) {
				OBD_FREE_PTR(env);
				lqe_putref(lqe);
				break;
			}

			rc = qsd_adjust(env, lqe);

			lu_env_fini(env);
			OBD_FREE_PTR(env);
		}

		/* release lqe reference grabbed by qsd_id_ast_data_get() */
		lqe_putref(lqe);
		break;
	}
	default:
		LASSERTF(0, "invalid flags for blocking ast %d\n", flag);
	}

	RETURN(rc);
}

/*
 * Glimpse callback handler for per-ID quota locks.
 *
 * \param lock - is the lock targeted by the glimpse
 * \param data - is a pointer to the glimpse ptlrpc request
 */
static int qsd_id_glimpse_ast(struct ldlm_lock *lock, void *data)
{
	struct ptlrpc_request *req = data;
	struct lquota_entry *lqe;
	struct ldlm_gl_lquota_desc *desc;
	struct lquota_lvb *lvb;
	int rc;
	bool wakeup = false;

	ENTRY;

	rc = qsd_common_glimpse_ast(req, &desc, (void **)&lvb);
	if (rc)
		GOTO(out, rc);

	lqe = qsd_id_ast_data_get(lock, false);
	if (!lqe)
		/* valid race */
		GOTO(out, rc = -ELDLM_NO_LOCK_DATA);

	LQUOTA_DEBUG(lqe, "glimpse on quota locks, new qunit:%llu, edquot:%d",
		     desc->gl_qunit, !!(desc->gl_flags & LQUOTA_FL_EDQUOT));

	lqe_write_lock(lqe);
	lvb->lvb_id_rel = 0;
	if (desc->gl_qunit != 0 && desc->gl_qunit != lqe->lqe_qunit) {
		long long space;

		/* extract new qunit from glimpse request */
		qsd_set_qunit(lqe, desc->gl_qunit);

		space  = lqe->lqe_granted - lqe->lqe_pending_rel;
		space -= lqe->lqe_usage;
		space -= lqe->lqe_pending_write + lqe->lqe_waiting_write;
		space -= lqe->lqe_qunit;

		if (space > 0) {
			if (lqe->lqe_pending_req > 0) {
				LQUOTA_DEBUG(lqe,
					     "request in flight, postpone release of %lld",
					     space);
				lvb->lvb_id_may_rel = space;
			} else {
				lqe->lqe_pending_req++;

				/* release quota space in glimpse reply */
				LQUOTA_DEBUG(lqe, "releasing %lld", space);
				lqe->lqe_granted -= space;
				lvb->lvb_id_rel   = space;

				lqe_write_unlock(lqe);
				/* change the lqe_granted */
				qsd_upd_schedule(lqe2qqi(lqe), lqe,
						 &lqe->lqe_id,
						 (union lquota_rec *)
						  &lqe->lqe_granted, 0, false);
				lqe_write_lock(lqe);

				lqe->lqe_pending_req--;
				wakeup = true;
			}
		}
	}

	qsd_set_edquot(lqe, !!(desc->gl_flags & LQUOTA_FL_EDQUOT));
	lqe_write_unlock(lqe);

	if (wakeup)
		wake_up(&lqe->lqe_waiters);
	lqe_putref(lqe);
out:
	req->rq_status = rc;
	RETURN(rc);
}

/**
 * Check whether a slave already own a ldlm lock for the quota identifier \qid.
 *
 * \param lockh  - is the local lock handle from lquota entry.
 * \param rlockh - is the remote lock handle of the matched lock, if any.
 *
 * \retval 0      : on successful look up and \lockh contains the lock handle.
 * \retval -ENOENT: no lock found
 */
int qsd_id_lock_match(struct lustre_handle *lockh, struct lustre_handle *rlockh)
{
	struct ldlm_lock *lock;
	int rc;

	ENTRY;

	LASSERT(lockh);

	if (!lustre_handle_is_used(lockh))
		RETURN(-ENOENT);

	rc = ldlm_lock_addref_try(lockh, qsd_id_einfo.ei_mode);
	if (rc)
		RETURN(-ENOENT);

	LASSERT(lustre_handle_is_used(lockh));
	ldlm_lock_dump_handle(D_QUOTA, lockh);

	if (!rlockh)
		/* caller not interested in remote handle */
		RETURN(0);

	/*
	 * look up lock associated with local handle and extract remote handle
	 * to be packed in quota request
	 */
	lock = ldlm_handle2lock(lockh);
	LASSERT(lock != NULL);
	lustre_handle_copy(rlockh, &lock->l_remote_handle);
	LDLM_LOCK_PUT(lock);

	RETURN(0);
}

int qsd_id_lock_cancel(const struct lu_env *env, struct lquota_entry *lqe)
{
	struct qsd_thread_info *qti = qsd_info(env);
	int rc;

	ENTRY;

	lqe_write_lock(lqe);
	if (lqe->lqe_pending_write || lqe->lqe_waiting_write ||
	    lqe->lqe_usage || lqe->lqe_granted) {
		lqe_write_unlock(lqe);
		RETURN(0);
	}

	lustre_handle_copy(&qti->qti_lockh, &lqe->lqe_lockh);
	if (lustre_handle_is_used(&qti->qti_lockh)) {
		memset(&lqe->lqe_lockh, 0, sizeof(lqe->lqe_lockh));
		qsd_set_qunit(lqe, 0);
		qsd_set_edquot(lqe, false);
	}
	lqe_write_unlock(lqe);

	rc = qsd_id_lock_match(&qti->qti_lockh, NULL);
	if (rc)
		RETURN(rc);

	ldlm_lock_decref_and_cancel(&qti->qti_lockh, qsd_id_einfo.ei_mode);
	RETURN(0);
}
