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

#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <obd_class.h>

#include "qsd_internal.h"

struct qsd_async_args {
	struct obd_export     *aa_exp;
	struct qsd_qtype_info *aa_qqi;
	void		      *aa_arg;
	struct lquota_lvb     *aa_lvb;
	struct lustre_handle   aa_lockh;
	qsd_req_completion_t   aa_completion;
};

/*
 * non-intent quota request interpret callback.
 *
 * \param env    - the environment passed by the caller
 * \param req    - the non-intent quota request
 * \param arg    - qsd_async_args
 * \param rc     - request status
 *
 * \retval 0     - success
 * \retval -ve   - appropriate errors
 */
static int qsd_dqacq_interpret(const struct lu_env *env,
			       struct ptlrpc_request *req, void *arg, int rc)
{
	struct quota_body     *rep_qbody = NULL, *req_qbody;
	struct qsd_async_args *aa = (struct qsd_async_args *)arg;
	ENTRY;

	req_qbody = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_BODY);
	if (rc == 0 || rc == -EDQUOT || rc == -EINPROGRESS)
		rep_qbody = req_capsule_server_get(&req->rq_pill,
						   &RMF_QUOTA_BODY);
	aa->aa_completion(env, aa->aa_qqi, req_qbody, rep_qbody, &aa->aa_lockh,
			  NULL, aa->aa_arg, rc);
	RETURN(rc);
}

/*
 * Send non-intent quota request to master.
 *
 * \param env    - the environment passed by the caller
 * \param exp    - is the export to use to send the acquire RPC
 * \param qbody  - quota body to be packed in request
 * \param sync   - synchronous or asynchronous
 * \param completion - completion callback
 * \param qqi    - is the qsd_qtype_info structure to pass to the completion
 *                 function
 * \param lqe    - is the qid entry to be processed
 *
 * \retval 0     - success
 * \retval -ve   - appropriate errors
 */
int qsd_send_dqacq(const struct lu_env *env, struct obd_export *exp,
		   struct quota_body *qbody, bool sync,
		   qsd_req_completion_t completion, struct qsd_qtype_info *qqi,
		   struct lustre_handle *lockh, struct lquota_entry *lqe)
{
	struct ptlrpc_request	*req;
	struct quota_body	*req_qbody;
	struct qsd_async_args	*aa;
	int			 rc;
	ENTRY;

	LASSERT(exp);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_QUOTA_DQACQ);
	if (req == NULL)
		GOTO(out, rc = -ENOMEM);

	req->rq_no_resend = req->rq_no_delay = 1;
	req->rq_no_retry_einprogress = 1;
	rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, QUOTA_DQACQ);
	if (rc) {
		ptlrpc_request_free(req);
		GOTO(out, rc);
	}

	req->rq_request_portal = MDS_READPAGE_PORTAL;
	req_qbody = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_BODY);
	*req_qbody = *qbody;

	ptlrpc_request_set_replen(req);

	CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
	aa = ptlrpc_req_async_args(req);
	aa->aa_exp = exp;
	aa->aa_qqi = qqi;
	aa->aa_arg = (void *)lqe;
	aa->aa_completion = completion;
	lustre_handle_copy(&aa->aa_lockh, lockh);

	if (sync) {
		rc = ptlrpc_queue_wait(req);
		rc = qsd_dqacq_interpret(env, req, aa, rc);
		ptlrpc_req_finished(req);
	} else {
		req->rq_interpret_reply = qsd_dqacq_interpret;
		ptlrpcd_add_req(req);
	}

	RETURN(rc);
out:
	completion(env, qqi, qbody, NULL, lockh, NULL, lqe, rc);
	return rc;
}

/*
 * intent quota request interpret callback.
 *
 * \param env    - the environment passed by the caller
 * \param req    - the intent quota request
 * \param arg    - qsd_async_args
 * \param rc     - request status
 *
 * \retval 0     - success
 * \retval -ve   - appropriate errors
 */
static int qsd_intent_interpret(const struct lu_env *env,
				struct ptlrpc_request *req, void *arg, int rc)
{
	struct lustre_handle	 *lockh;
	struct quota_body	 *rep_qbody = NULL, *req_qbody;
	struct qsd_async_args	 *aa = (struct qsd_async_args *)arg;
	struct ldlm_reply	 *lockrep;
	__u64			  flags = LDLM_FL_HAS_INTENT;
	ENTRY;

	LASSERT(aa->aa_exp);
	lockh = &aa->aa_lockh;
	req_qbody = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_BODY);
	req_capsule_client_get(&req->rq_pill, &RMF_LDLM_INTENT);

	rc = ldlm_cli_enqueue_fini(aa->aa_exp, req, LDLM_PLAIN, 0, LCK_CR,
				   &flags, (void *)aa->aa_lvb,
				   sizeof(struct lquota_lvb), lockh, rc);
	if (rc < 0) {
		/* the lock has been destroyed, forget about the lock handle */
		memset(lockh, 0, sizeof(*lockh));
		/*
		 * To avoid the server being fullfilled by LDLM locks, server
		 * may reject the locking request by returning -EINPROGRESS,
		 * this is different from the -EINPROGRESS returned by quota
		 * code.
		 */
		if (rc == -EINPROGRESS)
			rc = -EAGAIN;
		GOTO(out, rc);
	}

	lockrep = req_capsule_server_get(&req->rq_pill, &RMF_DLM_REP);
	LASSERT(lockrep != NULL);
	rc = ptlrpc_status_ntoh(lockrep->lock_policy_res2);

	if (rc == 0 || rc == -EDQUOT || rc == -EINPROGRESS)
		rep_qbody = req_capsule_server_get(&req->rq_pill,
						   &RMF_QUOTA_BODY);
out:
	aa->aa_completion(env, aa->aa_qqi, req_qbody, rep_qbody, lockh,
			  aa->aa_lvb, aa->aa_arg, rc);
	RETURN(rc);
}

/*
 * Get intent per-ID lock or global-index lock from master.
 *
 * \param env    - the environment passed by the caller
 * \param exp    - is the export to use to send the intent RPC
 * \param qbody  - quota body to be packed in request
 * \param sync   - synchronous or asynchronous (pre-acquire)
 * \param it_op  - IT_QUOTA_DQACQ or IT_QUOTA_CONN
 * \param completion - completion callback
 * \param qqi    - is the qsd_qtype_info structure to pass to the completion
 *                 function
 * \param lvb    - is the lvb associated with the lock and returned by the
 *                 server
 * \param arg    - is an opaq argument passed to the completion callback
 *
 * \retval 0     - success
 * \retval -ve   - appropriate errors
 */
int qsd_intent_lock(const struct lu_env *env, struct obd_export *exp,
		    struct quota_body *qbody, bool sync, int it_op,
		    qsd_req_completion_t completion, struct qsd_qtype_info *qqi,
		    struct lquota_lvb *lvb, void *arg)
{
	struct qsd_thread_info	*qti = qsd_info(env);
	struct ptlrpc_request	*req;
	struct qsd_async_args	*aa = NULL;
	struct ldlm_intent	*lit;
	struct quota_body	*req_qbody;
	__u64			 flags = LDLM_FL_HAS_INTENT;
	int			 rc;
	ENTRY;

	LASSERT(exp != NULL);
	LASSERT(!lustre_handle_is_used(&qbody->qb_lockh));

	memset(&qti->qti_lockh, 0, sizeof(qti->qti_lockh));

	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
				   &RQF_LDLM_INTENT_QUOTA);
	if (req == NULL)
		GOTO(out, rc = -ENOMEM);

	req->rq_no_retry_einprogress = 1;
	rc = ldlm_prep_enqueue_req(exp, req, NULL, 0);
	if (rc) {
		ptlrpc_request_free(req);
		GOTO(out, rc);
	}
	req->rq_request_portal = MDS_READPAGE_PORTAL;

	lit = req_capsule_client_get(&req->rq_pill, &RMF_LDLM_INTENT);
	lit->opc = (__u64)it_op;

	req_qbody = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_BODY);
	*req_qbody = *qbody;

	req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
			     sizeof(*lvb));
	ptlrpc_request_set_replen(req);

	switch(it_op) {
	case IT_QUOTA_CONN:
		/* build resource name associated with global index */
		fid_build_reg_res_name(&qbody->qb_fid, &qti->qti_resid);

		/* copy einfo template and fill ei_cbdata with qqi pointer */
		memcpy(&qti->qti_einfo, &qsd_glb_einfo, sizeof(qti->qti_einfo));
		qti->qti_einfo.ei_cbdata = qqi;

		/* don't cancel global lock on memory pressure */
		flags |= LDLM_FL_NO_LRU;
		break;
	case IT_QUOTA_DQACQ:
		/* build resource name associated for per-ID quota lock */
		fid_build_quota_res_name(&qbody->qb_fid, &qbody->qb_id,
					 &qti->qti_resid);

		/* copy einfo template and fill ei_cbdata with lqe pointer */
		memcpy(&qti->qti_einfo, &qsd_id_einfo, sizeof(qti->qti_einfo));
		qti->qti_einfo.ei_cbdata = arg;
		break;
	default:
		LASSERTF(0, "invalid it_op %d\n", it_op);
	}

	/* build lock enqueue request */
	rc = ldlm_cli_enqueue(exp, &req, &qti->qti_einfo, &qti->qti_resid, NULL,
			      &flags, (void *)lvb, sizeof(*lvb), LVB_T_LQUOTA,
			      &qti->qti_lockh, 1);
	if (rc < 0) {
		ptlrpc_req_finished(req);
		GOTO(out, rc);
	}

	/* grab reference on backend structure for the new lock */
	switch(it_op) {
	case IT_QUOTA_CONN:
		/* grab reference on qqi for new lock */
#ifdef USE_LU_REF
	{
		struct ldlm_lock	*lock;

		lock = ldlm_handle2lock(&qti->qti_lockh);
		if (lock == NULL) {
			ptlrpc_req_finished(req);
			GOTO(out, rc = -ENOLCK);
		}
		lu_ref_add(&qqi->qqi_reference, "glb_lock", lock);
		LDLM_LOCK_PUT(lock);
	}
#endif
		qqi_getref(qqi);
		break;
	case IT_QUOTA_DQACQ:
		/* grab reference on lqe for new lock */
		lqe_getref((struct lquota_entry *)arg);
		/* all acquire/release request are sent with no_resend and
		 * no_delay flag */
		req->rq_no_resend = req->rq_no_delay = 1;
		break;
	default:
		break;
	}

	CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
	aa = ptlrpc_req_async_args(req);
	aa->aa_exp = exp;
	aa->aa_qqi = qqi;
	aa->aa_arg = arg;
	aa->aa_lvb = lvb;
	aa->aa_completion = completion;
	lustre_handle_copy(&aa->aa_lockh, &qti->qti_lockh);

	if (sync) {
		/* send lock enqueue request and wait for completion */
		rc = ptlrpc_queue_wait(req);
		rc = qsd_intent_interpret(env, req, aa, rc);
		ptlrpc_req_finished(req);
	} else {
		/* queue lock request and return */
		req->rq_interpret_reply = qsd_intent_interpret;
		ptlrpcd_add_req(req);
	}

	RETURN(rc);
out:
	completion(env, qqi, qbody, NULL, &qti->qti_lockh, lvb, arg, rc);
	return rc;
}

/*
 * Fetch a global or slave index from the QMT.
 *
 * \param env    - the environment passed by the caller
 * \param exp    - is the export to use to issue the OBD_IDX_READ RPC
 * \param ii     - is the index information to be packed in the request
 *                 on success, the index information returned by the server
 *                 is copied there.
 * \param npages - is the number of pages in the pages array
 * \param pages  - is an array of @npages pages
 *
 * \retval 0     - success
 * \retval -ve   - appropriate errors
 */
int qsd_fetch_index(const struct lu_env *env, struct obd_export *exp,
		    struct idx_info *ii, unsigned int npages,
		    struct page **pages, bool *need_swab)
{
	struct ptlrpc_request	*req;
	struct idx_info		*req_ii;
	struct ptlrpc_bulk_desc *desc;
	int			 rc, i;
	ENTRY;

	LASSERT(exp);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OBD_IDX_READ);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OBD_VERSION, OBD_IDX_READ);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	req->rq_request_portal = MDS_READPAGE_PORTAL;
	ptlrpc_at_set_req_timeout(req);

	/* allocate bulk descriptor */
	desc = ptlrpc_prep_bulk_imp(req, npages, 1,
				    PTLRPC_BULK_PUT_SINK | PTLRPC_BULK_BUF_KIOV,
				    MDS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_pin_ops);
	if (desc == NULL)
		GOTO(out, rc = -ENOMEM);

	/* req now owns desc and will free it when it gets freed */
	for (i = 0; i < npages; i++)
		desc->bd_frag_ops->add_kiov_frag(desc, pages[i], 0,
						 PAGE_SIZE);

	/* pack index information in request */
	req_ii = req_capsule_client_get(&req->rq_pill, &RMF_IDX_INFO);
	*req_ii = *ii;

	ptlrpc_request_set_replen(req);

	/* send request to master and wait for RPC to complete */
	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(out, rc);

	rc = sptlrpc_cli_unwrap_bulk_read(req, req->rq_bulk,
					  req->rq_bulk->bd_nob_transferred);
	if (rc < 0)
		GOTO(out, rc);
	else
		/* sptlrpc_cli_unwrap_bulk_read() returns the number of bytes
		 * transferred*/
		rc = 0;

	req_ii = req_capsule_server_get(&req->rq_pill, &RMF_IDX_INFO);
	*ii = *req_ii;

	*need_swab = ptlrpc_rep_need_swab(req);

	EXIT;
out:
	ptlrpc_req_finished(req);
	return rc;
}
