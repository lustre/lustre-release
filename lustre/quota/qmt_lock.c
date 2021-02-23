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

#include <linux/kthread.h>

#include <lustre_dlm.h>
#include <lustre_swab.h>
#include <obd_class.h>

#include "qmt_internal.h"

/* intent policy function called from mdt_intent_opc() when the intent is of
 * quota type */
int qmt_intent_policy(const struct lu_env *env, struct lu_device *ld,
		      struct ptlrpc_request *req, struct ldlm_lock **lockp,
		      int flags)
{
	struct qmt_device	*qmt = lu2qmt_dev(ld);
	struct ldlm_intent	*it;
	struct quota_body	*reqbody;
	struct quota_body	*repbody;
	struct obd_uuid		*uuid;
	struct lquota_lvb	*lvb;
	struct ldlm_resource	*res = (*lockp)->l_resource;
	struct ldlm_reply	*ldlm_rep;
	int			 rc, lvb_len;
	ENTRY;

	req_capsule_extend(&req->rq_pill, &RQF_LDLM_INTENT_QUOTA);
	req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
			     ldlm_lvbo_size(*lockp));

	/* extract quota body and intent opc */
	it = req_capsule_client_get(&req->rq_pill, &RMF_LDLM_INTENT);
	if (it == NULL)
		RETURN(err_serious(-EFAULT));

	reqbody = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_BODY);
	if (reqbody == NULL)
		RETURN(err_serious(-EFAULT));

	/* prepare reply */
	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc != 0) {
		CERROR("Can't pack response, rc %d\n", rc);
		RETURN(err_serious(rc));
	}

	repbody = req_capsule_server_get(&req->rq_pill, &RMF_QUOTA_BODY);
	if (repbody == NULL)
		RETURN(err_serious(-EFAULT));

	ldlm_rep = req_capsule_server_get(&req->rq_pill, &RMF_DLM_REP);
	if (ldlm_rep == NULL)
		RETURN(err_serious(-EFAULT));

	uuid = &(*lockp)->l_export->exp_client_uuid;
	switch (it->opc) {

	case IT_QUOTA_DQACQ: {
		struct lquota_entry	*lqe;
		struct ldlm_lock	*lock;
		int idx;

		if (res->lr_name.name[LUSTRE_RES_ID_QUOTA_SEQ_OFF] == 0)
			/* acquire on global lock? something is wrong ... */
			GOTO(out, rc = -EPROTO);

		/* verify global lock isn't stale */
		if (!lustre_handle_is_used(&reqbody->qb_glb_lockh))
			GOTO(out, rc = -ENOLCK);

		lock = ldlm_handle2lock(&reqbody->qb_glb_lockh);
		if (lock == NULL)
			GOTO(out, rc = -ENOLCK);
		LDLM_LOCK_PUT(lock);

		rc = qmt_uuid2idx(uuid, &idx);
		if (rc < 0)
			GOTO(out, rc = -EINVAL);

		/* TODO: it seems we don't need to get lqe from
		 * lq_lvb_data anymore ... And do extra get
		 * and put on it */
		lqe = res->lr_lvb_data;
		LASSERT(lqe != NULL);
		lqe_getref(lqe);

		rc = qmt_pool_lqes_lookup(env, qmt, lqe_rtype(lqe), rc,
					  lqe_qtype(lqe), &reqbody->qb_id,
					  NULL, idx);
		if (rc) {
			lqe_putref(lqe);
			GOTO(out, rc);
		}

		/* acquire quota space */
		rc = qmt_dqacq0(env, qmt, uuid,
				reqbody->qb_flags, reqbody->qb_count,
				reqbody->qb_usage, repbody);
		lqe_putref(lqe);
		qti_lqes_fini(env);
		if (rc)
			GOTO(out, rc);
		break;
	}

	case IT_QUOTA_CONN:
		/* new connection from slave */

		if (res->lr_name.name[LUSTRE_RES_ID_QUOTA_SEQ_OFF] != 0)
			/* connection on per-ID lock? something is wrong ... */
			GOTO(out, rc = -EPROTO);

		rc = qmt_pool_new_conn(env, qmt, &reqbody->qb_fid,
				       &repbody->qb_slv_fid,
				       &repbody->qb_slv_ver, uuid);
		if (rc)
			GOTO(out, rc);
		break;

	default:
		CERROR("%s: invalid intent opcode: %llu\n", qmt->qmt_svname,
		       it->opc);
		GOTO(out, rc = -EINVAL);
	}

	/* on success, pack lvb in reply */
	lvb = req_capsule_server_get(&req->rq_pill, &RMF_DLM_LVB);
	lvb_len = ldlm_lvbo_size(*lockp);
	lvb_len = ldlm_lvbo_fill(*lockp, lvb, &lvb_len);
	if (lvb_len < 0)
		GOTO(out, rc = lvb_len);

	req_capsule_shrink(&req->rq_pill, &RMF_DLM_LVB, lvb_len, RCL_SERVER);
out:
	ldlm_rep->lock_policy_res2 = clear_serious(rc);
	EXIT;
	return ELDLM_OK;
}

/*
 * Initialize quota LVB associated with quota indexes.
 * Called with res->lr_lvb_sem held
 */
int qmt_lvbo_init(struct lu_device *ld, struct ldlm_resource *res)
{
	struct lu_env		*env;
	struct qmt_thread_info	*qti;
	struct qmt_device	*qmt = lu2qmt_dev(ld);
	int			 pool_type, qtype;
	int			 rc;
	ENTRY;

	LASSERT(res != NULL);

	if (res->lr_type != LDLM_PLAIN)
		RETURN(-ENOTSUPP);

	if (res->lr_lvb_data ||
	    res->lr_name.name[LUSTRE_RES_ID_SEQ_OFF] != FID_SEQ_QUOTA_GLB)
		RETURN(0);

	env = lu_env_find();
	LASSERT(env);
	qti = qmt_info(env);

	/* extract global index FID and quota identifier */
	fid_extract_from_quota_res(&qti->qti_fid, &qti->qti_id, &res->lr_name);

	/* sanity check the global index FID */
	rc = lquota_extract_fid(&qti->qti_fid, &pool_type, &qtype);
	if (rc) {
		CERROR("can't extract glb index information from FID "DFID"\n",
		       PFID(&qti->qti_fid));
		GOTO(out, rc);
	}

	if (res->lr_name.name[LUSTRE_RES_ID_QUOTA_SEQ_OFF] != 0) {
		/* no ID quota lock associated with UID/GID 0 or with a seq 0,
		 * we are thus dealing with an ID lock. */
		struct qmt_pool_info	*pool;
		struct lquota_entry	*lqe;
		struct lqe_glbl_data	*lgd;

		pool = qmt_pool_lookup_glb(env, qmt, pool_type);
		if (IS_ERR(pool))
			GOTO(out, rc = -ENOMEM);

		/* Find the quota entry associated with the quota id */
		lqe = qmt_pool_lqe_lookup(env, qmt, pool_type, qtype,
					  &qti->qti_id, NULL);
		if (IS_ERR(lqe)) {
			qpi_putref(env, pool);
			GOTO(out, rc = PTR_ERR(lqe));
		}

		/* TODO: need something like qmt_extend_lqe_gd that has
		 * to be calledeach time when qpi_slv_nr is incremented */
		lgd = qmt_alloc_lqe_gd(pool, qtype);
		if (!lgd) {
			lqe_putref(lqe);
			qpi_putref(env, pool);
			GOTO(out, rc = -ENOMEM);
		}

		qmt_setup_lqe_gd(env, qmt, lqe, lgd, pool_type);

		/* store reference to lqe in lr_lvb_data */
		res->lr_lvb_data = lqe;
		qpi_putref(env, pool);
		LQUOTA_DEBUG(lqe, "initialized res lvb");
	} else {
		struct dt_object	*obj;

		/* lookup global index */
		obj = dt_locate(env, qmt->qmt_child, &qti->qti_fid);
		if (IS_ERR(obj))
			GOTO(out, rc = PTR_ERR(obj));
		if (!dt_object_exists(obj)) {
			dt_object_put(env, obj);
			GOTO(out, rc = -ENOENT);
		}

		/* store reference to global index object in lr_lvb_data */
		res->lr_lvb_data = obj;
		CDEBUG(D_QUOTA, DFID" initialized lvb\n", PFID(&qti->qti_fid));
	}

	res->lr_lvb_len = sizeof(struct lquota_lvb);
	EXIT;
out:
	return rc;
}

/* clear lge_qunit/edquot_nu flags -
 * slave recieved new qunit and edquot.
 *
 * \retval	true if revoke is needed - qunit
 *		for this slave reaches least_qunit
 */
static bool qmt_clear_lgeg_arr_nu(struct lquota_entry *lqe, int stype, int idx)
{
	unsigned long least_qunit = lqe2qpi(lqe)->qpi_least_qunit;
	struct lqe_glbl_data *lgd = lqe->lqe_glbl_data;

	/* There is no array to store lge for the case of DOM.
	 * Ignore it until MDT pools will be ready. */
	if (!(lqe_rtype(lqe) == LQUOTA_RES_DT && stype == QMT_STYPE_MDT)) {
		lqe->lqe_glbl_data->lqeg_arr[idx].lge_qunit_nu = 0;
		lqe->lqe_glbl_data->lqeg_arr[idx].lge_edquot_nu = 0;

		/* We shouldn't call revoke for DOM case, it will be updated
		 * at qmt_id_lock_glimpse. */
		return (lgd->lqeg_arr[idx].lge_qunit == least_qunit);
	}

	return false;
}

static void qmt_set_revoke(struct lu_env *env, struct lquota_entry *lqe,
			  int stype, int idx)
{
	unsigned long least_qunit = lqe2qpi(lqe)->qpi_least_qunit;
	struct lqe_glbl_data *lgd = lqe->lqe_glbl_data;

	if (lgd->lqeg_arr[idx].lge_qunit == least_qunit) {
		int i;

		qti_lqes_write_lock(env);
		for (i = 0; i < qti_lqes_cnt(env); i++) {
			LQUOTA_DEBUG(qti_lqes(env)[i],
				     "idx %d lge_qunit %llu least_qunit %lu\n",
				     idx, lgd->lqeg_arr[idx].lge_qunit,
				     least_qunit);
			if (qti_lqes(env)[i]->lqe_qunit == least_qunit) {
				qti_lqes(env)[i]->lqe_revoke_time =
							ktime_get_seconds();
				qmt_adjust_edquot(qti_lqes(env)[i],
						  ktime_get_real_seconds());
			}
		}
		qti_lqes_write_unlock(env);
	}
}

/*
 * Update LVB associated with the global quota index.
 * This function is called from the DLM itself after a glimpse callback, in this
 * case valid ptlrpc request is passed.
 */
int qmt_lvbo_update(struct lu_device *ld, struct ldlm_resource *res,
		    struct ptlrpc_request *req, int increase_only)
{
	struct lu_env		*env;
	struct qmt_thread_info	*qti;
	struct qmt_device	*qmt = lu2qmt_dev(ld);
	struct lquota_entry	*lqe;
	struct lquota_lvb	*lvb;
	struct ldlm_lock	*lock;
	struct obd_export	*exp;
	bool			 need_revoke;
	int			 rc = 0, idx;
	ENTRY;

	LASSERT(res != NULL);

	if (req == NULL)
		RETURN(0);

	if (res->lr_name.name[LUSTRE_RES_ID_QUOTA_SEQ_OFF] == 0)
		/* no need to update lvb for global quota locks */
		RETURN(0);

	lvb = req_capsule_server_swab_get(&req->rq_pill, &RMF_DLM_LVB,
					  lustre_swab_lquota_lvb);
	if (lvb == NULL) {
		CERROR("%s: failed to extract lvb from request\n",
		       qmt->qmt_svname);
		RETURN(-EFAULT);
	}

	lqe = res->lr_lvb_data;
	LASSERT(lqe != NULL);
	lqe_getref(lqe);

	/* allocate environement */
	env = lu_env_find();
	LASSERT(env);
	qti = qmt_info(env);

	/* The request is a glimpse callback which was sent via the
	 * reverse import to the slave. What we care about here is the
	 * export associated with the slave and req->rq_export is
	 * definitely not what we are looking for (it is actually set to
	 * NULL here).
	 * Therefore we extract the lock from the request argument
	 * and use lock->l_export. */
	lock = ldlm_request_lock(req);
	if (IS_ERR(lock)) {
		CERROR("%s: failed to get lock from request!\n",
		       qmt->qmt_svname);
		GOTO(out, rc = PTR_ERR(lock));
	}

	exp = class_export_get(lock->l_export);
	if (exp == NULL) {
		CERROR("%s: failed to get export from lock!\n",
		       qmt->qmt_svname);
		GOTO(out, rc = -EFAULT);
	}

	rc = qmt_uuid2idx(&exp->exp_client_uuid, &idx);
	if (rc < 0)
		GOTO(out_exp, rc);

	need_revoke = qmt_clear_lgeg_arr_nu(lqe, rc, idx);
	if (lvb->lvb_id_rel == 0) {
		/* nothing to release */
		if (lvb->lvb_id_may_rel != 0)
			/* but might still release later ... */
			lqe->lqe_may_rel += lvb->lvb_id_may_rel;
	}

	if (!need_revoke && lvb->lvb_id_rel == 0)
		GOTO(out_exp, rc = 0);

	rc = qmt_pool_lqes_lookup(env, qmt, lqe_rtype(lqe), rc, lqe_qtype(lqe),
				  &lqe->lqe_id, NULL, idx);
	if (rc)
		GOTO(out_exp, rc);

	if (need_revoke)
		qmt_set_revoke(env, lqe, rc, idx);

	if (lvb->lvb_id_rel) {
		LQUOTA_DEBUG(lqe, "releasing:%llu may release:%llu",
			     lvb->lvb_id_rel, lvb->lvb_id_may_rel);

		/* release quota space */
		rc = qmt_dqacq0(env, qmt, &exp->exp_client_uuid,
				QUOTA_DQACQ_FL_REL, lvb->lvb_id_rel,
				0, &qti->qti_body);
		if (rc || qti->qti_body.qb_count != lvb->lvb_id_rel)
			LQUOTA_ERROR(lqe,
				     "failed to release quota space on glimpse %llu!=%llu : rc = %d\n",
				     qti->qti_body.qb_count,
				     lvb->lvb_id_rel, rc);
	}
	qti_lqes_fini(env);
	if (rc)
		GOTO(out_exp, rc);
	EXIT;
out_exp:
	class_export_put(exp);
out:
	lqe_putref(lqe);
	return rc;
}

/*
 * Report size of lvb to ldlm layer in order to allocate lvb buffer
 * As far as quota locks are concerned, the size is static and is the same
 * for both global and per-ID locks which shares the same lvb format.
 */
int qmt_lvbo_size(struct lu_device *ld, struct ldlm_lock *lock)
{
	return sizeof(struct lquota_lvb);
}

/*
 * Fill request buffer with quota lvb
 */
int qmt_lvbo_fill(struct lu_device *ld, struct ldlm_lock *lock, void *lvb,
		  int lvblen)
{
	struct ldlm_resource *res = lock->l_resource;
	struct lquota_lvb *qlvb = lvb;
	struct lu_env *env;
	int rc;
	ENTRY;

	LASSERT(res != NULL);
	rc = 0;

	if (res->lr_type != LDLM_PLAIN || res->lr_lvb_data == NULL ||
	    res->lr_name.name[LUSTRE_RES_ID_SEQ_OFF] != FID_SEQ_QUOTA_GLB)
		RETURN(-EINVAL);

	env = lu_env_find();
	LASSERT(env);

	if (res->lr_name.name[LUSTRE_RES_ID_QUOTA_SEQ_OFF] != 0) {
		/* no ID quota lock associated with UID/GID 0 or with a seq 0,
		 * we are thus dealing with an ID lock. */
		struct lquota_entry *lqe = res->lr_lvb_data;
		struct qmt_device *qmt;
		struct obd_uuid	*uuid;
		int idx;

		uuid = &(lock)->l_export->exp_client_uuid;
		rc = qmt_uuid2idx(uuid, &idx);
		if (rc < 0)
			RETURN(rc);
		qmt = lu2qmt_dev(ld);
		/* return current qunit value & edquot flags in lvb */
		lqe_getref(lqe);
		rc = qmt_pool_lqes_lookup(env, qmt, lqe_rtype(lqe), rc,
					  lqe_qtype(lqe), &lqe->lqe_id,
					  NULL, idx);
		if (!rc) {
			qlvb->lvb_id_qunit = qti_lqes_min_qunit(env);
			qlvb->lvb_flags = 0;
			if (qti_lqes_edquot(env))
				qlvb->lvb_flags = LQUOTA_FL_EDQUOT;
			qti_lqes_fini(env);
		}
		CDEBUG(D_QUOTA, "uuid %s lqe_id %lu, edquot %llu qunit %llu\n",
		       (char *)uuid, (unsigned long)lqe->lqe_id.qid_uid,
		       qlvb->lvb_flags, qlvb->lvb_id_qunit);
		lqe_putref(lqe);
	} else {
		/* global quota lock */
		struct dt_object	*obj = res->lr_lvb_data;

		/* return current version of global index */
		qlvb->lvb_glb_ver = dt_version_get(env, obj);
	}

	RETURN(rc = rc ?: sizeof(struct lquota_lvb));
}

/*
 * Free lvb associated with a given ldlm resource
 * we don't really allocate a lvb, lr_lvb_data just points to
 * the appropriate backend structures.
 */
int qmt_lvbo_free(struct lu_device *ld, struct ldlm_resource *res)
{
	ENTRY;

	if (res->lr_lvb_data == NULL)
		RETURN(0);

	if (res->lr_name.name[LUSTRE_RES_ID_QUOTA_SEQ_OFF] != 0) {
		struct lquota_entry *lqe = res->lr_lvb_data;
		struct lqe_glbl_data *lgd = lqe->lqe_glbl_data;

		/* release lqe reference */
		lqe->lqe_glbl_data = NULL;
		lqe_putref(lqe);
		qmt_free_lqe_gd(lgd);
	} else {
		struct dt_object *obj = res->lr_lvb_data;
		/* release object reference */
		dt_object_put(lu_env_find(), obj);
	}

	res->lr_lvb_data = NULL;
	res->lr_lvb_len  = 0;

	RETURN(0);
}

typedef int (*qmt_glimpse_cb_t)(struct ldlm_lock *, struct lquota_entry *);

struct qmt_gl_lock_array {
	unsigned long		  q_max;
	unsigned long		  q_cnt;
	struct ldlm_lock	**q_locks;
};

static void qmt_free_lock_array(struct qmt_gl_lock_array *array)
{
	int i;

	if (array->q_max == 0) {
		LASSERT(array->q_locks == NULL);
		return;
	}

	for (i = 0; i < array->q_cnt; i++) {
		LASSERT(array->q_locks[i]);
		LDLM_LOCK_RELEASE(array->q_locks[i]);
		array->q_locks[i] = NULL;
	}
	array->q_cnt = 0;
	OBD_FREE_PTR_ARRAY(array->q_locks, array->q_max);
	array->q_locks = NULL;
	array->q_max = 0;
}

static int qmt_alloc_lock_array(struct ldlm_resource *res,
				struct qmt_gl_lock_array *array,
				qmt_glimpse_cb_t cb, void *arg)
{
	struct list_head *pos;
	unsigned long count = 0;
	int fail_cnt = 0;
	ENTRY;

	LASSERT(!array->q_max && !array->q_cnt && !array->q_locks);
again:
	lock_res(res);
	/* scan list of granted locks */
	list_for_each(pos, &res->lr_granted) {
		struct ldlm_lock *lock;
		int rc;

		lock = list_entry(pos, struct ldlm_lock, l_res_link);
		LASSERT(lock->l_export);

		if (cb != NULL) {
			rc = cb(lock, arg);
			/* slave should not be notified */
			if (rc == 0)
				continue;
		}

		count++;
		if (array->q_max != 0 && array->q_cnt < array->q_max) {
			array->q_locks[array->q_cnt] = LDLM_LOCK_GET(lock);
			array->q_cnt++;
		}
	}
	unlock_res(res);

	if (count > array->q_max) {
		qmt_free_lock_array(array);
		if (++fail_cnt > 5)
			RETURN(-EAGAIN);
		/*
		 * allocate more slots in case of more qualified locks are
		 * found during next loop
		 */
		array->q_max = count + count / 2 + 10;
		count = 0;
		LASSERT(array->q_locks == NULL && array->q_cnt == 0);
		OBD_ALLOC_PTR_ARRAY(array->q_locks, array->q_max);
		if (array->q_locks == NULL) {
			array->q_max = 0;
			RETURN(-ENOMEM);
		}

		goto again;
	}
	RETURN(0);
}

void qmt_setup_id_desc(struct ldlm_lock *lock, union ldlm_gl_desc *desc,
		       struct lquota_entry *lqe)
{
	struct obd_uuid *uuid = &(lock)->l_export->exp_client_uuid;
	struct lqe_glbl_data *lgd = lqe->lqe_glbl_data;
	int idx, stype;
	__u64 qunit;
	bool edquot;

	stype = qmt_uuid2idx(uuid, &idx);
	LASSERT(stype >= 0);

	/* DOM case - set global lqe settings */
	if (lqe_rtype(lqe) == LQUOTA_RES_DT && stype == QMT_STYPE_MDT) {
		edquot = lqe->lqe_edquot;
		qunit = lqe->lqe_qunit;
	} else {
		edquot = lgd->lqeg_arr[idx].lge_edquot;
		qunit = lgd->lqeg_arr[idx].lge_qunit;
	}

	/* fill glimpse descriptor with lqe settings */
	desc->lquota_desc.gl_flags = edquot ? LQUOTA_FL_EDQUOT : 0;
	desc->lquota_desc.gl_qunit = qunit;
	CDEBUG(D_QUOTA, "setup desc: stype %d idx %d, edquot %llu qunit %llu\n",
			 stype, idx, desc->lquota_desc.gl_flags,
			 desc->lquota_desc.gl_qunit);
}

/*
 * Send glimpse callback to slaves holding a lock on resource \res.
 * This is used to notify slaves of new quota settings or to claim quota space
 * back.
 *
 * \param env  - is the environment passed by the caller
 * \param qmt  - is the quota master target
 * \param res  - is the dlm resource associated with the quota object
 * \param desc - is the glimpse descriptor to pack in glimpse callback
 * \param cb   - is the callback function called on every lock and determine
 *               whether a glimpse should be issued
 * \param arg  - is an opaq parameter passed to the callback function
 */
static int qmt_glimpse_lock(const struct lu_env *env, struct qmt_device *qmt,
			    struct ldlm_resource *res, union ldlm_gl_desc *desc,
			    qmt_glimpse_cb_t cb, struct lquota_entry *lqe)
{
	union ldlm_gl_desc *descs = NULL;
	struct lqe_glbl_data *gld;
	struct list_head *tmp, *pos;
	LIST_HEAD(gl_list);
	struct qmt_gl_lock_array locks;
	unsigned long i, locks_count;
	int rc = 0;
	ENTRY;

	gld = lqe ? lqe->lqe_glbl_data : NULL;
	memset(&locks, 0, sizeof(locks));
	rc = qmt_alloc_lock_array(res, &locks, cb, lqe);
	if (rc) {
		CERROR("%s: failed to allocate glimpse lock array (%d)\n",
		       qmt->qmt_svname, rc);
		RETURN(rc);
	}
	if (!locks.q_cnt) {
		CDEBUG(D_QUOTA, "%s: no granted locks to send glimpse\n",
		       qmt->qmt_svname);
		RETURN(0);
	}
	CDEBUG(D_QUOTA, "found granted locks %lu\n", locks.q_cnt);
	locks_count = locks.q_cnt;

	/* Use one desc for all works, when called from qmt_glb_lock_notify */
	if (gld && locks.q_cnt > 1) {
		/* TODO: think about to store this preallocated descs
		 * in lqe_global in lqeg_arr as a part of lqe_glbl_entry.
		 * The benefit is that we don't need to allocate/free
		 * and setup this descs each time. But the drawback is
		 * memory use (sizeof ldlm_gl_desc * OST_COUNT * user_number).
		 * for examfple it could be 88 * 256 * 10 000 about 225 MB. */
		OBD_ALLOC(descs,
			  sizeof(struct ldlm_gl_lquota_desc) * locks.q_cnt);
		if (!descs) {
			CERROR("%s: alloc glimpse lock array failed: rc = %d\n",
			       qmt->qmt_svname, rc);
			qmt_free_lock_array(&locks);
			RETURN(-ENOMEM);
		}
	}

	for (i = locks.q_cnt; i > 0; i--) {
		struct ldlm_glimpse_work *work;

		OBD_ALLOC_PTR(work);
		if (work == NULL) {
			CERROR("%s: failed to notify a lock.\n",
			       qmt->qmt_svname);
			continue;
		}

		if (gld) {
			if (descs)
				desc = &descs[i - 1];
			qmt_setup_id_desc(locks.q_locks[i - 1], desc, lqe);
			work->gl_interpret_data = lqe;
		}

		list_add_tail(&work->gl_list, &gl_list);
		work->gl_lock  = locks.q_locks[i - 1];
		work->gl_flags = 0;
		work->gl_desc  = desc;

		locks.q_locks[i - 1] = NULL;
		locks.q_cnt--;
	}

	qmt_free_lock_array(&locks);

	if (list_empty(&gl_list)) {
		CDEBUG(D_QUOTA, "%s: nobody to notify\n", qmt->qmt_svname);
		GOTO(out, rc = 0);
	}

	/* issue glimpse callbacks to all connected slaves */
	rc = ldlm_glimpse_locks(res, &gl_list);

	list_for_each_safe(pos, tmp, &gl_list) {
		struct ldlm_glimpse_work *work;

		work = list_entry(pos, struct ldlm_glimpse_work, gl_list);

		list_del(&work->gl_list);
		CERROR("%s: failed to notify %s of new quota settings\n",
		       qmt->qmt_svname,
		       obd_uuid2str(&work->gl_lock->l_export->exp_client_uuid));
		LDLM_LOCK_RELEASE(work->gl_lock);
		OBD_FREE_PTR(work);
	}
out:
	if (descs)
		OBD_FREE(descs,
			 sizeof(struct ldlm_gl_lquota_desc) * locks_count);

	RETURN(rc);
}

/*
 * Send glimpse request to all global quota locks to push new quota setting to
 * slaves.
 *
 * \param env - is the environment passed by the caller
 * \param lqe - is the lquota entry which has new settings
 * \param ver - is the version associated with the setting change
 */
void qmt_glb_lock_notify(const struct lu_env *env, struct lquota_entry *lqe,
			 __u64 ver)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct qmt_pool_info	*pool = lqe2qpi(lqe);
	struct ldlm_resource	*res = NULL;
	ENTRY;

	lquota_generate_fid(&qti->qti_fid, pool->qpi_rtype, lqe_qtype(lqe));

	/* send glimpse callback to notify slaves of new quota settings */
	qti->qti_gl_desc.lquota_desc.gl_id        = lqe->lqe_id;
	qti->qti_gl_desc.lquota_desc.gl_flags     = 0;
	if (lqe->lqe_is_default) {
		qti->qti_gl_desc.lquota_desc.gl_hardlimit = 0;
		qti->qti_gl_desc.lquota_desc.gl_softlimit = 0;
		qti->qti_gl_desc.lquota_desc.gl_time = LQUOTA_GRACE_FLAG(0,
							LQUOTA_FLAG_DEFAULT);

	} else {
		qti->qti_gl_desc.lquota_desc.gl_hardlimit = lqe->lqe_hardlimit;
		qti->qti_gl_desc.lquota_desc.gl_softlimit = lqe->lqe_softlimit;
		qti->qti_gl_desc.lquota_desc.gl_time = lqe->lqe_gracetime;
	}
	qti->qti_gl_desc.lquota_desc.gl_ver       = ver;

	/* look up ldlm resource associated with global index */
	fid_build_reg_res_name(&qti->qti_fid, &qti->qti_resid);
	res = ldlm_resource_get(pool->qpi_qmt->qmt_ns, NULL, &qti->qti_resid,
				LDLM_PLAIN, 0);
	if (IS_ERR(res)) {
		/* this might happen if no slaves have enqueued global quota
		 * locks yet */
		LQUOTA_DEBUG(lqe, "failed to lookup ldlm resource associated "
			     "with "DFID, PFID(&qti->qti_fid));
		RETURN_EXIT;
	}

	qmt_glimpse_lock(env, pool->qpi_qmt, res, &qti->qti_gl_desc,
			 NULL, NULL);
	ldlm_resource_putref(res);
	EXIT;
}

/* Callback function used to select locks that should be glimpsed when
 * broadcasting the new qunit value */
static int qmt_id_lock_cb(struct ldlm_lock *lock, struct lquota_entry *lqe)
{
	struct obd_uuid	*uuid = &(lock)->l_export->exp_client_uuid;
	struct lqe_glbl_data *lgd = lqe->lqe_glbl_data;
	int idx;
	int stype = qmt_uuid2idx(uuid, &idx);

	LASSERT(stype == QMT_STYPE_OST || stype == QMT_STYPE_MDT);

	/* Quota pools support only OSTs, despite MDTs also could be registered
	 * as LQUOTA_RES_DT devices(DOM). */
	if (lqe_rtype(lqe) == LQUOTA_RES_DT && stype == QMT_STYPE_MDT)
		return 1;
	else
		return lgd->lqeg_arr[idx].lge_edquot_nu ||
		       lgd->lqeg_arr[idx].lge_qunit_nu;
}


/*
 * Send glimpse request on per-ID lock to push new qunit value to slave.
 *
 * \param env  - is the environment passed by the caller
 * \param qmt  - is the quota master target device
 * \param lqe  - is the lquota entry with the new qunit value
 * \param uuid - is the uuid of the slave acquiring space, if any
 */
static void qmt_id_lock_glimpse(const struct lu_env *env,
				struct qmt_device *qmt,
				struct lquota_entry *lqe, struct obd_uuid *uuid)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct qmt_pool_info	*pool = lqe2qpi(lqe);
	struct ldlm_resource	*res = NULL;
	ENTRY;

	if (!lqe->lqe_enforced)
		RETURN_EXIT;

	lquota_generate_fid(&qti->qti_fid, pool->qpi_rtype, lqe_qtype(lqe));
	fid_build_quota_res_name(&qti->qti_fid, &lqe->lqe_id, &qti->qti_resid);
	res = ldlm_resource_get(qmt->qmt_ns, NULL, &qti->qti_resid, LDLM_PLAIN,
				0);
	if (IS_ERR(res)) {
		/* this might legitimately happens if slaves haven't had the
		 * opportunity to enqueue quota lock yet. */
		LQUOTA_DEBUG(lqe, "failed to lookup ldlm resource for per-ID "
			     "lock "DFID, PFID(&qti->qti_fid));
		lqe_write_lock(lqe);
		if (lqe->lqe_revoke_time == 0 &&
		    lqe->lqe_qunit == pool->qpi_least_qunit)
			lqe->lqe_revoke_time = ktime_get_seconds();
		lqe_write_unlock(lqe);
		RETURN_EXIT;
	}

	lqe_write_lock(lqe);
	/* The purpose of glimpse callback on per-ID lock is twofold:
	 * - notify slaves of new qunit value and hope they will release some
	 *   spare quota space in return
	 * - notify slaves that master ran out of quota space and there is no
	 *   need to send acquire request any more until further notice */

	/* TODO: it is not clear how to implement below case for all lqes
	 * from where slaves will be notified in qmt_glimpse_lock. Because
	 * here we have just global lqe with an array of OSTs that should
	 * be notified. Theoretically we can find all lqes that includes
	 * these OSTs, but it is not trivial. So I would propose to move
	 * this case to another place ... */
	if (lqe->lqe_revoke_time == 0 &&
	    lqe->lqe_qunit == pool->qpi_least_qunit)
		/* reset lqe_may_rel, it will be updated on glimpse callback
		 * replies if needed */
		lqe->lqe_may_rel = 0;

	/* The rebalance thread is the only thread which can issue glimpses */
	LASSERT(!lqe->lqe_gl);
	lqe->lqe_gl = true;
	lqe_write_unlock(lqe);

	/* issue glimpse callback to slaves */
	qmt_glimpse_lock(env, qmt, res, &qti->qti_gl_desc,
			 qmt_id_lock_cb, lqe);

	lqe_write_lock(lqe);
	if (lqe->lqe_revoke_time == 0 &&
	    lqe->lqe_qunit == pool->qpi_least_qunit) {
		lqe->lqe_revoke_time = ktime_get_seconds();
		qmt_adjust_edquot(lqe, ktime_get_real_seconds());
	}
	LASSERT(lqe->lqe_gl);
	lqe->lqe_gl = false;
	lqe_write_unlock(lqe);

	ldlm_resource_putref(res);
	EXIT;
}

/*
 * Schedule a glimpse request on per-ID locks to push new qunit value or
 * edquot flag to quota slaves.
 *
 * \param qmt  - is the quota master target device
 * \param lqe  - is the lquota entry with the new qunit value
 */
void qmt_id_lock_notify(struct qmt_device *qmt, struct lquota_entry *lqe)
{
	bool	added = false;
	ENTRY;

	LASSERT(lqe->lqe_is_global);
	lqe_getref(lqe);
	spin_lock(&qmt->qmt_reba_lock);
	if (!qmt->qmt_stopping && list_empty(&lqe->lqe_link)) {
		list_add_tail(&lqe->lqe_link, &qmt->qmt_reba_list);
		added = true;
		if (qmt->qmt_reba_task)
			wake_up_process(qmt->qmt_reba_task);
	}
	spin_unlock(&qmt->qmt_reba_lock);

	if (!added)
		lqe_putref(lqe);
	EXIT;
}

struct qmt_reba_args {
	struct qmt_device	*qra_dev;
	struct lu_env		 qra_env;
	struct completion	*qra_started;
};

#ifndef TASK_IDLE
#define TASK_IDLE TASK_INTERRUPTIBLE
#endif

/*
 * The rebalance thread is in charge of sending glimpse callbacks on per-ID
 * quota locks owned by slaves in order to notify them of:
 * - a qunit shrink in which case slaves might release quota space back in
 *   glimpse reply.
 * - set/clear edquot flag used to cache the "quota exhausted" state of the
 *   master. When the flag is set, slaves know that there is no need to
 *   try to acquire quota from the master since this latter has already
 *   distributed all the space.
 */
static int qmt_reba_thread(void *_args)
{
	struct qmt_reba_args	*args = _args;
	struct qmt_device	*qmt = args->qra_dev;
	struct lu_env		*env = &args->qra_env;
	struct lquota_entry	*lqe, *tmp;
	ENTRY;

	complete(args->qra_started);
	while (({set_current_state(TASK_IDLE);
		 !kthread_should_stop(); })) {

		spin_lock(&qmt->qmt_reba_lock);
		list_for_each_entry_safe(lqe, tmp, &qmt->qmt_reba_list,
					 lqe_link) {
			__set_current_state(TASK_RUNNING);
			list_del_init(&lqe->lqe_link);
			spin_unlock(&qmt->qmt_reba_lock);

			if (!kthread_should_stop())
				qmt_id_lock_glimpse(env, qmt, lqe, NULL);

			lqe_putref(lqe);
			spin_lock(&qmt->qmt_reba_lock);
		}
		spin_unlock(&qmt->qmt_reba_lock);
		schedule();
	}
	__set_current_state(TASK_RUNNING);

	lu_env_remove(env);
	lu_env_fini(env);
	OBD_FREE_PTR(args);
	RETURN(0);
}

/*
 * Start rebalance thread. Called when the QMT is being setup
 */
int qmt_start_reba_thread(struct qmt_device *qmt)
{
	struct task_struct *task;
	struct qmt_reba_args *args;
	DECLARE_COMPLETION_ONSTACK(started);
	int rc;
	ENTRY;

	OBD_ALLOC_PTR(args);
	if (args == NULL)
		RETURN(-ENOMEM);
	args->qra_dev = qmt;
	args->qra_started = &started;

	rc = lu_env_init(&args->qra_env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: failed to init env.\n", qmt->qmt_svname);
		GOTO(out_env, rc);
	}

	task = kthread_create(qmt_reba_thread, args,
			      "qmt_reba_%s", qmt->qmt_svname);
	if (IS_ERR(task)) {
		CERROR("%s: failed to start rebalance thread (%ld)\n",
		       qmt->qmt_svname, PTR_ERR(task));
		GOTO(out_env_fini, rc = PTR_ERR(task));
	}

	rc = lu_env_add_task(&args->qra_env, task);
	if (rc) {
		kthread_stop(task);
		GOTO(out_env_fini, rc);
	}
	qmt->qmt_reba_task = task;
	wake_up_process(task);
	wait_for_completion(&started);

	RETURN(0);
out_env_fini:
	lu_env_fini(&args->qra_env);
out_env:
	OBD_FREE_PTR(args);
	RETURN(rc);
}

/*
 * Stop rebalance thread. Called when the QMT is about to shutdown.
 */
void qmt_stop_reba_thread(struct qmt_device *qmt)
{
	struct task_struct *task;

	spin_lock(&qmt->qmt_reba_lock);
	task = qmt->qmt_reba_task;
	qmt->qmt_reba_task = NULL;
	spin_unlock(&qmt->qmt_reba_lock);

	if (task)
		kthread_stop(task);

	LASSERT(list_empty(&qmt->qmt_reba_list));
}
