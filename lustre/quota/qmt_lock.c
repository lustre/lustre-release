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

		lqe = res->lr_lvb_data;
		LASSERT(lqe != NULL);
		lqe_getref(lqe);

		/* acquire quota space */
		rc = qmt_dqacq0(env, lqe, qmt, uuid, reqbody->qb_flags,
				reqbody->qb_count, reqbody->qb_usage,
				repbody);
		lqe_putref(lqe);
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
	lvb_len = ldlm_lvbo_fill(*lockp, lvb, lvb_len);
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
	int			 pool_id, pool_type, qtype;
	int			 rc;
	ENTRY;

	LASSERT(res != NULL);

	if (res->lr_type != LDLM_PLAIN)
		RETURN(-ENOTSUPP);

	if (res->lr_lvb_data ||
	    res->lr_name.name[LUSTRE_RES_ID_SEQ_OFF] != FID_SEQ_QUOTA_GLB)
		RETURN(0);

	OBD_ALLOC_PTR(env);
	if (env == NULL)
		RETURN(-ENOMEM);

	/* initialize environment */
	rc = lu_env_init(env, LCT_MD_THREAD);
	if (rc != 0)
		GOTO(out_free, rc);
	qti = qmt_info(env);

	/* extract global index FID and quota identifier */
	fid_extract_from_quota_res(&qti->qti_fid, &qti->qti_id, &res->lr_name);

	/* sanity check the global index FID */
	rc = lquota_extract_fid(&qti->qti_fid, &pool_id, &pool_type, &qtype);
	if (rc) {
		CERROR("can't extract pool information from FID "DFID"\n",
		       PFID(&qti->qti_fid));
		GOTO(out, rc);
	}

	if (res->lr_name.name[LUSTRE_RES_ID_QUOTA_SEQ_OFF] != 0) {
		/* no ID quota lock associated with UID/GID 0 or with a seq 0,
		 * we are thus dealing with an ID lock. */
		struct lquota_entry	*lqe;

		/* Find the quota entry associated with the quota id */
		lqe = qmt_pool_lqe_lookup(env, qmt, pool_id, pool_type, qtype,
					  &qti->qti_id);
		if (IS_ERR(lqe))
			GOTO(out, rc = PTR_ERR(lqe));

		/* store reference to lqe in lr_lvb_data */
		res->lr_lvb_data = lqe;
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
	lu_env_fini(env);
out_free:
	OBD_FREE_PTR(env);
	return rc;
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
	int			 rc = 0;
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

	LQUOTA_DEBUG(lqe, "releasing:%llu may release:%llu",
		     lvb->lvb_id_rel, lvb->lvb_id_may_rel);

	if (lvb->lvb_id_rel == 0) {
		/* nothing to release */
		if (lvb->lvb_id_may_rel != 0)
			/* but might still release later ... */
			lqe->lqe_may_rel += lvb->lvb_id_may_rel;
		GOTO(out_lqe, rc = 0);
	}

	/* allocate environement */
	OBD_ALLOC_PTR(env);
	if (env == NULL)
		GOTO(out_lqe, rc = -ENOMEM);

	/* initialize environment */
	rc = lu_env_init(env, LCT_MD_THREAD);
	if (rc)
		GOTO(out_env, rc);
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
		GOTO(out_env_init, rc = PTR_ERR(lock));
	}

	exp = class_export_get(lock->l_export);
	if (exp == NULL) {
		CERROR("%s: failed to get export from lock!\n",
		       qmt->qmt_svname);
		GOTO(out_env_init, rc = -EFAULT);
	}

	/* release quota space */
	rc = qmt_dqacq0(env, lqe, qmt, &exp->exp_client_uuid,
			QUOTA_DQACQ_FL_REL, lvb->lvb_id_rel, 0, &qti->qti_body);
	if (rc || qti->qti_body.qb_count != lvb->lvb_id_rel)
		LQUOTA_ERROR(lqe, "failed to release quota space on glimpse "
			     "%llu!=%llu : rc = %d\n", qti->qti_body.qb_count,
			     lvb->lvb_id_rel, rc);
	class_export_put(exp);
	if (rc)
		GOTO(out_env_init, rc);
	EXIT;
out_env_init:
	lu_env_fini(env);
out_env:
	OBD_FREE_PTR(env);
out_lqe:
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
	struct ldlm_resource	*res = lock->l_resource;
	struct lquota_lvb	*qlvb = lvb;
	ENTRY;

	LASSERT(res != NULL);

	if (res->lr_type != LDLM_PLAIN || res->lr_lvb_data == NULL ||
	    res->lr_name.name[LUSTRE_RES_ID_SEQ_OFF] != FID_SEQ_QUOTA_GLB)
		RETURN(-EINVAL);

	if (res->lr_name.name[LUSTRE_RES_ID_QUOTA_SEQ_OFF] != 0) {
		/* no ID quota lock associated with UID/GID 0 or with a seq 0,
		 * we are thus dealing with an ID lock. */
		struct lquota_entry	*lqe = res->lr_lvb_data;

		/* return current qunit value & edquot flags in lvb */
		lqe_getref(lqe);
		qlvb->lvb_id_qunit = lqe->lqe_qunit;
		qlvb->lvb_flags = 0;
		if (lqe->lqe_edquot)
			qlvb->lvb_flags = LQUOTA_FL_EDQUOT;
		lqe_putref(lqe);
	} else {
		/* global quota lock */
		struct lu_env		*env;
		int			 rc;
		struct dt_object	*obj = res->lr_lvb_data;

		OBD_ALLOC_PTR(env);
		if (env == NULL)
			RETURN(-ENOMEM);

		/* initialize environment */
		rc = lu_env_init(env, LCT_LOCAL);
		if (rc) {
			OBD_FREE_PTR(env);
			RETURN(rc);
		}

		/* return current version of global index */
		qlvb->lvb_glb_ver = dt_version_get(env, obj);

		lu_env_fini(env);
		OBD_FREE_PTR(env);
	}

	RETURN(sizeof(struct lquota_lvb));
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
		struct lquota_entry	*lqe = res->lr_lvb_data;

		/* release lqe reference */
		lqe_putref(lqe);
	} else {
		struct dt_object	*obj = res->lr_lvb_data;
		struct lu_env		*env;
		int			 rc;

		OBD_ALLOC_PTR(env);
		if (env == NULL)
			RETURN(-ENOMEM);

		/* initialize environment */
		rc = lu_env_init(env, LCT_LOCAL);
		if (rc) {
			OBD_FREE_PTR(env);
			RETURN(rc);
		}

		/* release object reference */
		dt_object_put(env, obj);
		lu_env_fini(env);
		OBD_FREE_PTR(env);
	}

	res->lr_lvb_data = NULL;
	res->lr_lvb_len  = 0;

	RETURN(0);
}

typedef int (*qmt_glimpse_cb_t)(struct ldlm_lock *, void *);

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
	OBD_FREE(array->q_locks, array->q_max * sizeof(*array->q_locks));
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
		OBD_ALLOC(array->q_locks,
			  sizeof(*array->q_locks) * array->q_max);
		if (array->q_locks == NULL) {
			array->q_max = 0;
			RETURN(-ENOMEM);
		}

		goto again;
	}
	RETURN(0);
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
			    qmt_glimpse_cb_t cb, void *arg)
{
	struct list_head *tmp, *pos;
	struct list_head gl_list = LIST_HEAD_INIT(gl_list);
	struct qmt_gl_lock_array locks;
	unsigned long i;
	int rc = 0;
	ENTRY;

	memset(&locks, 0, sizeof(locks));
	rc = qmt_alloc_lock_array(res, &locks, cb, arg);
	if (rc) {
		CERROR("%s: failed to allocate glimpse lock array (%d)\n",
		       qmt->qmt_svname, rc);
		RETURN(rc);
	}

	for (i = locks.q_cnt; i > 0; i--) {
		struct ldlm_glimpse_work *work;

		OBD_ALLOC_PTR(work);
		if (work == NULL) {
			CERROR("%s: failed to notify a lock.\n",
			       qmt->qmt_svname);
			continue;
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
		RETURN(0);
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

	lquota_generate_fid(&qti->qti_fid, pool->qpi_key & 0x0000ffff,
			    pool->qpi_key >> 16, lqe->lqe_site->lqs_qtype);

	/* send glimpse callback to notify slaves of new quota settings */
	qti->qti_gl_desc.lquota_desc.gl_id        = lqe->lqe_id;
	qti->qti_gl_desc.lquota_desc.gl_flags     = 0;
	qti->qti_gl_desc.lquota_desc.gl_hardlimit = lqe->lqe_hardlimit;
	qti->qti_gl_desc.lquota_desc.gl_softlimit = lqe->lqe_softlimit;
	qti->qti_gl_desc.lquota_desc.gl_time      = lqe->lqe_gracetime;
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
static int qmt_id_lock_cb(struct ldlm_lock *lock, void *arg)
{
	struct obd_uuid *slv_uuid = arg;
	struct obd_uuid *uuid = &lock->l_export->exp_client_uuid;

	if (slv_uuid != NULL && obd_uuid_equals(uuid, slv_uuid))
		RETURN(0);
	RETURN(+1);
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

	lquota_generate_fid(&qti->qti_fid, pool->qpi_key & 0x0000ffff,
			    pool->qpi_key >> 16, lqe->lqe_site->lqs_qtype);
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

	/* fill glimpse descriptor with lqe settings */
	if (lqe->lqe_edquot)
		qti->qti_gl_desc.lquota_desc.gl_flags = LQUOTA_FL_EDQUOT;
	else
		qti->qti_gl_desc.lquota_desc.gl_flags = 0;
	qti->qti_gl_desc.lquota_desc.gl_qunit = lqe->lqe_qunit;

	if (lqe->lqe_revoke_time == 0 &&
	    qti->qti_gl_desc.lquota_desc.gl_qunit == pool->qpi_least_qunit)
		/* reset lqe_may_rel, it will be updated on glimpse callback
		 * replies if needed */
		lqe->lqe_may_rel = 0;

	/* The rebalance thread is the only thread which can issue glimpses */
	LASSERT(!lqe->lqe_gl);
	lqe->lqe_gl = true;
	lqe_write_unlock(lqe);

	/* issue glimpse callback to slaves */
	qmt_glimpse_lock(env, qmt, res, &qti->qti_gl_desc,
			 uuid ? qmt_id_lock_cb : NULL, (void *)uuid);

	lqe_write_lock(lqe);
	if (lqe->lqe_revoke_time == 0 &&
	    qti->qti_gl_desc.lquota_desc.gl_qunit == pool->qpi_least_qunit &&
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

	lqe_getref(lqe);
	spin_lock(&qmt->qmt_reba_lock);
	if (!qmt->qmt_stopping && list_empty(&lqe->lqe_link)) {
		list_add_tail(&lqe->lqe_link, &qmt->qmt_reba_list);
		added = true;
	}
	spin_unlock(&qmt->qmt_reba_lock);

	if (added)
		wake_up(&qmt->qmt_reba_thread.t_ctl_waitq);
	else
		lqe_putref(lqe);
	EXIT;
}

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
static int qmt_reba_thread(void *arg)
{
	struct qmt_device	*qmt = (struct qmt_device *)arg;
	struct ptlrpc_thread	*thread = &qmt->qmt_reba_thread;
	struct l_wait_info	 lwi = { 0 };
	struct lu_env		*env;
	struct lquota_entry	*lqe, *tmp;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(env);
	if (env == NULL)
		RETURN(-ENOMEM);

	rc = lu_env_init(env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: failed to init env.", qmt->qmt_svname);
		OBD_FREE_PTR(env);
		RETURN(rc);
	}

	thread_set_flags(thread, SVC_RUNNING);
	wake_up(&thread->t_ctl_waitq);

	while (1) {
		l_wait_event(thread->t_ctl_waitq,
			     !list_empty(&qmt->qmt_reba_list) ||
			     !thread_is_running(thread), &lwi);

		spin_lock(&qmt->qmt_reba_lock);
		list_for_each_entry_safe(lqe, tmp, &qmt->qmt_reba_list,
					 lqe_link) {
			list_del_init(&lqe->lqe_link);
			spin_unlock(&qmt->qmt_reba_lock);

			if (thread_is_running(thread))
				qmt_id_lock_glimpse(env, qmt, lqe, NULL);

			lqe_putref(lqe);
			spin_lock(&qmt->qmt_reba_lock);
		}
		spin_unlock(&qmt->qmt_reba_lock);

		if (!thread_is_running(thread))
			break;
	}
	lu_env_fini(env);
	OBD_FREE_PTR(env);
	thread_set_flags(thread, SVC_STOPPED);
	wake_up(&thread->t_ctl_waitq);
	RETURN(rc);
}

/*
 * Start rebalance thread. Called when the QMT is being setup
 */
int qmt_start_reba_thread(struct qmt_device *qmt)
{
	struct ptlrpc_thread	*thread = &qmt->qmt_reba_thread;
	struct l_wait_info	 lwi    = { 0 };
	struct task_struct		*task;
	ENTRY;

	task = kthread_run(qmt_reba_thread, (void *)qmt,
			       "qmt_reba_%s", qmt->qmt_svname);
	if (IS_ERR(task)) {
		CERROR("%s: failed to start rebalance thread (%ld)\n",
		       qmt->qmt_svname, PTR_ERR(task));
		thread_set_flags(thread, SVC_STOPPED);
		RETURN(PTR_ERR(task));
	}

	l_wait_event(thread->t_ctl_waitq,
		     thread_is_running(thread) || thread_is_stopped(thread),
		     &lwi);

	RETURN(0);
}

/*
 * Stop rebalance thread. Called when the QMT is about to shutdown.
 */
void qmt_stop_reba_thread(struct qmt_device *qmt)
{
	struct ptlrpc_thread *thread = &qmt->qmt_reba_thread;

	if (!thread_is_stopped(thread)) {
		struct l_wait_info lwi = { 0 };

		thread_set_flags(thread, SVC_STOPPING);
		wake_up(&thread->t_ctl_waitq);

		l_wait_event(thread->t_ctl_waitq, thread_is_stopped(thread),
			     &lwi);
	}
	LASSERT(list_empty(&qmt->qmt_reba_list));
}
