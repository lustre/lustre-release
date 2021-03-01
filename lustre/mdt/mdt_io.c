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
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, Intel Corporation.
 */
/*
 * lustre/mdt/mdt_io.c
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <dt_object.h>
#include "mdt_internal.h"

/* functions below are stubs for now, they will be implemented with
 * grant support on MDT */
static inline void mdt_dom_read_lock(struct mdt_object *mo)
{
	down_read(&mo->mot_dom_sem);
}

static inline void mdt_dom_read_unlock(struct mdt_object *mo)
{
	up_read(&mo->mot_dom_sem);
}

static inline void mdt_dom_write_lock(struct mdt_object *mo)
{
	down_write(&mo->mot_dom_sem);
}

static inline void mdt_dom_write_unlock(struct mdt_object *mo)
{
	up_write(&mo->mot_dom_sem);
}

static void mdt_dom_resource_prolong(struct ldlm_prolong_args *arg)
{
	struct ldlm_resource *res;
	struct ldlm_lock *lock;

	ENTRY;

	res = ldlm_resource_get(arg->lpa_export->exp_obd->obd_namespace, NULL,
				&arg->lpa_resid, LDLM_IBITS, 0);
	if (IS_ERR(res)) {
		CDEBUG(D_DLMTRACE,
		       "Failed to get resource for resid %llu/%llu\n",
		       arg->lpa_resid.name[0], arg->lpa_resid.name[1]);
		RETURN_EXIT;
	}

	lock_res(res);
	list_for_each_entry(lock, &res->lr_granted, l_res_link) {
		if (ldlm_has_dom(lock)) {
			LDLM_DEBUG(lock, "DOM lock to prolong ");
			ldlm_lock_prolong_one(lock, arg);
			/* only one PW or EX lock can be granted,
			 * no need to continue search
			 */
			if (lock->l_granted_mode & (LCK_PW | LCK_EX))
				break;
		}
	}
	unlock_res(res);
	ldlm_resource_putref(res);

	EXIT;
}

static void mdt_prolong_dom_lock(struct tgt_session_info *tsi,
				 struct ldlm_prolong_args *data)
{
	struct obdo *oa = &tsi->tsi_ost_body->oa;
	struct ldlm_lock *lock;

	ENTRY;

	data->lpa_timeout = prolong_timeout(tgt_ses_req(tsi));
	data->lpa_export = tsi->tsi_exp;
	data->lpa_resid = tsi->tsi_resid;

	CDEBUG(D_RPCTRACE, "Prolong DOM lock for req %p with x%llu\n",
	       tgt_ses_req(tsi), tgt_ses_req(tsi)->rq_xid);

	if (oa->o_valid & OBD_MD_FLHANDLE) {
		/* mostly a request should be covered by only one lock, try
		 * fast path. */
		lock = ldlm_handle2lock(&oa->o_handle);
		if (lock != NULL) {
			LASSERT(lock->l_export == data->lpa_export);
			ldlm_lock_prolong_one(lock, data);
			lock->l_last_used = ktime_get();
			LDLM_LOCK_PUT(lock);
			if (data->lpa_locks_cnt > 0)
				RETURN_EXIT;
		}
	}
	mdt_dom_resource_prolong(data);
	EXIT;
}

static int mdt_rw_hpreq_lock_match(struct ptlrpc_request *req,
				   struct ldlm_lock *lock)
{
	struct obd_ioobj *ioo;
	enum ldlm_mode mode;
	__u32 opc = lustre_msg_get_opc(req->rq_reqmsg);

	ENTRY;

	if (!(lock->l_policy_data.l_inodebits.bits & MDS_INODELOCK_DOM))
		RETURN(0);

	ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
	LASSERT(ioo != NULL);

	LASSERT(lock->l_resource != NULL);
	if (!fid_res_name_eq(&ioo->ioo_oid.oi_fid, &lock->l_resource->lr_name))
		RETURN(0);

	/* a bulk write can only hold a reference on a PW extent lock. */
	mode = LCK_PW | LCK_GROUP;
	if (opc == OST_READ)
		/* whereas a bulk read can be protected by either a PR or PW
		 * extent lock */
		mode |= LCK_PR;

	if (!(lock->l_granted_mode & mode))
		RETURN(0);

	RETURN(1);
}

static int mdt_rw_hpreq_check(struct ptlrpc_request *req)
{
	struct tgt_session_info *tsi;
	struct obd_ioobj *ioo;
	struct niobuf_remote *rnb;
	int opc;
	struct ldlm_prolong_args pa = { 0 };

	ENTRY;

	/* Don't use tgt_ses_info() to get session info, because lock_match()
	 * can be called while request has no processing thread yet. */
	tsi = lu_context_key_get(&req->rq_session, &tgt_session_key);

	/*
	 * Use LASSERT below because malformed RPCs should have
	 * been filtered out in tgt_hpreq_handler().
	 */
	opc = lustre_msg_get_opc(req->rq_reqmsg);
	LASSERT(opc == OST_READ || opc == OST_WRITE);

	ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
	LASSERT(ioo != NULL);

	rnb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
	LASSERT(rnb != NULL);
	LASSERT(!(rnb->rnb_flags & OBD_BRW_SRVLOCK));

	pa.lpa_mode = LCK_PW | LCK_GROUP;
	if (opc == OST_READ)
		pa.lpa_mode |= LCK_PR;

	DEBUG_REQ(D_RPCTRACE, req, "%s %s: refresh rw locks for " DFID,
		  tgt_name(tsi->tsi_tgt), current->comm, PFID(&tsi->tsi_fid));

	mdt_prolong_dom_lock(tsi, &pa);

	if (pa.lpa_blocks_cnt > 0) {
		CDEBUG(D_DLMTRACE,
		       "%s: refreshed %u locks timeout for req %p\n",
		       tgt_name(tsi->tsi_tgt), pa.lpa_blocks_cnt, req);
		RETURN(1);
	}

	RETURN(pa.lpa_locks_cnt > 0 ? 0 : -ESTALE);
}

static void mdt_rw_hpreq_fini(struct ptlrpc_request *req)
{
	mdt_rw_hpreq_check(req);
}

static struct ptlrpc_hpreq_ops mdt_hpreq_rw = {
	.hpreq_lock_match = mdt_rw_hpreq_lock_match,
	.hpreq_check = mdt_rw_hpreq_check,
	.hpreq_fini = mdt_rw_hpreq_fini
};

/**
 * Assign high priority operations to an IO request.
 *
 * Check if the incoming request is a candidate for
 * high-priority processing. If it is, assign it a high
 * priority operations table.
 *
 * \param[in] tsi	target session environment for this request
 */
void mdt_hp_brw(struct tgt_session_info *tsi)
{
	struct niobuf_remote	*rnb;
	struct obd_ioobj	*ioo;

	ENTRY;

	ioo = req_capsule_client_get(tsi->tsi_pill, &RMF_OBD_IOOBJ);
	LASSERT(ioo != NULL); /* must exist after request preprocessing */
	if (ioo->ioo_bufcnt > 0) {
		rnb = req_capsule_client_get(tsi->tsi_pill, &RMF_NIOBUF_REMOTE);
		LASSERT(rnb != NULL); /* must exist after preprocessing */

		/* no high priority if server lock is needed */
		if (rnb->rnb_flags & OBD_BRW_SRVLOCK ||
		    (lustre_msg_get_flags(tgt_ses_req(tsi)->rq_reqmsg) &
		     MSG_REPLAY))
			return;
	}
	tgt_ses_req(tsi)->rq_ops = &mdt_hpreq_rw;
}

static int mdt_punch_hpreq_lock_match(struct ptlrpc_request *req,
				      struct ldlm_lock *lock)
{
	struct tgt_session_info *tsi;
	struct obdo *oa;

	ENTRY;

	/* Don't use tgt_ses_info() to get session info, because lock_match()
	 * can be called while request has no processing thread yet. */
	tsi = lu_context_key_get(&req->rq_session, &tgt_session_key);

	/*
	 * Use LASSERT below because malformed RPCs should have
	 * been filtered out in tgt_hpreq_handler().
	 */
	LASSERT(tsi->tsi_ost_body != NULL);
	if (tsi->tsi_ost_body->oa.o_valid & OBD_MD_FLHANDLE &&
	    tsi->tsi_ost_body->oa.o_handle.cookie == lock->l_handle.h_cookie)
		RETURN(1);

	oa = &tsi->tsi_ost_body->oa;

	LASSERT(lock->l_resource != NULL);
	if (!fid_res_name_eq(&oa->o_oi.oi_fid, &lock->l_resource->lr_name))
		RETURN(0);

	if (!(lock->l_granted_mode & (LCK_PW | LCK_GROUP)))
		RETURN(0);

	RETURN(1);
}

/**
 * Implementation of ptlrpc_hpreq_ops::hpreq_lock_check for OST_PUNCH request.
 *
 * High-priority queue request check for whether the given punch request
 * (\a req) is blocking an LDLM lock cancel. Also checks whether the request is
 * covered by an LDLM lock.
 *

 *
 * \param[in] req	the incoming request
 *
 * \retval		1 if \a req is blocking an LDLM lock cancel
 * \retval		0 if it is not
 * \retval		-ESTALE if lock is not found
 */
static int mdt_punch_hpreq_check(struct ptlrpc_request *req)
{
	struct tgt_session_info *tsi;
	struct obdo *oa;
	struct ldlm_prolong_args pa = { 0 };

	ENTRY;

	/* Don't use tgt_ses_info() to get session info, because lock_match()
	 * can be called while request has no processing thread yet. */
	tsi = lu_context_key_get(&req->rq_session, &tgt_session_key);
	LASSERT(tsi != NULL);
	oa = &tsi->tsi_ost_body->oa;

	LASSERT(!(oa->o_valid & OBD_MD_FLFLAGS &&
		  oa->o_flags & OBD_FL_SRVLOCK));

	pa.lpa_mode = LCK_PW | LCK_GROUP;

	CDEBUG(D_DLMTRACE, "%s: refresh DOM lock for "DFID"\n",
	       tgt_name(tsi->tsi_tgt), PFID(&tsi->tsi_fid));

	mdt_prolong_dom_lock(tsi, &pa);

	if (pa.lpa_blocks_cnt > 0) {
		CDEBUG(D_DLMTRACE,
		       "%s: refreshed %u locks timeout for req %p.\n",
		       tgt_name(tsi->tsi_tgt), pa.lpa_blocks_cnt, req);
		RETURN(1);
	}

	RETURN(pa.lpa_locks_cnt > 0 ? 0 : -ESTALE);
}

/**
 * Implementation of ptlrpc_hpreq_ops::hpreq_lock_fini for OST_PUNCH request.
 *
 * Called after the request has been handled. It refreshes lock timeout again
 * so that client has more time to send lock cancel RPC.
 *
 * \param[in] req	request which is being processed.
 */
static void mdt_punch_hpreq_fini(struct ptlrpc_request *req)
{
	mdt_punch_hpreq_check(req);
}

static struct ptlrpc_hpreq_ops mdt_hpreq_punch = {
	.hpreq_lock_match = mdt_punch_hpreq_lock_match,
	.hpreq_check = mdt_punch_hpreq_check,
	.hpreq_fini = mdt_punch_hpreq_fini
};

void mdt_hp_punch(struct tgt_session_info *tsi)
{
	LASSERT(tsi->tsi_ost_body != NULL); /* must exists if we are here */
	/* no high-priority if server lock is needed */
	if ((tsi->tsi_ost_body->oa.o_valid & OBD_MD_FLFLAGS &&
	     tsi->tsi_ost_body->oa.o_flags & OBD_FL_SRVLOCK) ||
	    tgt_conn_flags(tsi) & OBD_CONNECT_MDS ||
	    lustre_msg_get_flags(tgt_ses_req(tsi)->rq_reqmsg) & MSG_REPLAY)
		return;
	tgt_ses_req(tsi)->rq_ops = &mdt_hpreq_punch;
}

static int mdt_preprw_read(const struct lu_env *env, struct obd_export *exp,
			   struct mdt_device *mdt, struct mdt_object *mo,
			   struct lu_attr *la, int niocount,
			   struct niobuf_remote *rnb, int *nr_local,
			   struct niobuf_local *lnb, char *jobid)
{
	struct tgt_session_info *tsi = tgt_ses_info(env);
	struct ptlrpc_request *req = tgt_ses_req(tsi);
	struct dt_object *dob;
	int i, j, rc, tot_bytes = 0;
	int maxlnb = *nr_local;
	int level;

	ENTRY;

	mdt_dom_read_lock(mo);
	*nr_local = 0;
	/* the only valid case when READ can find object is missing or stale
	 * when export is just evicted and open files are closed forcefully
	 * on server while client's READ can be in progress.
	 * This should not happen on healthy export, object can't be missing
	 * or dying because both states means it was finally destroyed.
	 */
	level = exp->exp_failed ? D_INFO : D_ERROR;
	if (!mdt_object_exists(mo)) {
		CDEBUG_LIMIT(level,
			     "%s: READ IO to missing obj "DFID": rc = %d\n",
			     exp->exp_obd->obd_name, PFID(mdt_object_fid(mo)),
			     -ENOENT);
		/* return 0 and continue with empty commit to skip such READ
		 * without more BRW errors.
		 */
		RETURN(0);
	}
	if (lu_object_is_dying(&mo->mot_header)) {
		CDEBUG_LIMIT(level,
			     "%s: READ IO to stale obj "DFID": rc = %d\n",
			     exp->exp_obd->obd_name, PFID(mdt_object_fid(mo)),
			     -ESTALE);
		/* return 0 and continue with empty commit to skip such READ
		 * without more BRW errors.
		 */
		RETURN(0);
	}

	dob = mdt_obj2dt(mo);
	/* parse remote buffers to local buffers and prepare the latter */
	for (i = 0, j = 0; i < niocount; i++) {
		rc = dt_bufs_get(env, dob, rnb + i, lnb + j, maxlnb, 0);
		if (unlikely(rc < 0))
			GOTO(buf_put, rc);
		/* correct index for local buffers to continue with */
		j += rc;
		maxlnb -= rc;
		*nr_local += rc;
		tot_bytes += rnb[i].rnb_len;
	}

	rc = dt_attr_get(env, dob, la);
	if (unlikely(rc))
		GOTO(buf_put, rc);

	rc = dt_read_prep(env, dob, lnb, *nr_local);
	if (unlikely(rc))
		GOTO(buf_put, rc);

	mdt_counter_incr(req, LPROC_MDT_IO_READ, tot_bytes);
	RETURN(0);
buf_put:
	dt_bufs_put(env, dob, lnb, *nr_local);
	mdt_dom_read_unlock(mo);
	return rc;
}

static int mdt_preprw_write(const struct lu_env *env, struct obd_export *exp,
			    struct mdt_device *mdt, struct mdt_object *mo,
			    struct lu_attr *la, struct obdo *oa,
			    int objcount, struct obd_ioobj *obj,
			    struct niobuf_remote *rnb, int *nr_local,
			    struct niobuf_local *lnb, char *jobid)
{
	struct tgt_session_info *tsi = tgt_ses_info(env);
	struct ptlrpc_request *req = tgt_ses_req(tsi);
	struct dt_object *dob;
	int i, j, k, rc = 0, tot_bytes = 0;
	int maxlnb = *nr_local;

	ENTRY;

	/* Process incoming grant info, set OBD_BRW_GRANTED flag and grant some
	 * space back if possible */
	tgt_grant_prepare_write(env, exp, oa, rnb, obj->ioo_bufcnt);

	mdt_dom_read_lock(mo);
	*nr_local = 0;
	/* don't report error in cases with failed export */
	if (!mdt_object_exists(mo)) {
		int level = exp->exp_failed ? D_INFO : D_ERROR;

		rc = -ENOENT;
		CDEBUG_LIMIT(level,
			     "%s: WRITE IO to missing obj "DFID": rc = %d\n",
			     exp->exp_obd->obd_name, PFID(mdt_object_fid(mo)),
			     rc);
		/* exit with no data written, note nr_local = 0 above */
		GOTO(unlock, rc);
	}
	if (lu_object_is_dying(&mo->mot_header)) {
		/* This is possible race between object destroy followed by
		 * discard BL AST and client cache flushing. Object is
		 * referenced until discard finish.
		 */
		CDEBUG(D_INODE, "WRITE IO to stale object "DFID"\n",
		       PFID(mdt_object_fid(mo)));
		/* Note: continue with no error here to don't cause BRW errors
		 * but skip transaction in commitrw silently so no data is
		 * written.
		 */
	}

	dob = mdt_obj2dt(mo);
	/* parse remote buffers to local buffers and prepare the latter */
	for (i = 0, j = 0; i < obj->ioo_bufcnt; i++) {
		rc = dt_bufs_get(env, dob, rnb + i, lnb + j, maxlnb, 1);
		if (unlikely(rc < 0))
			GOTO(err, rc);
		/* correct index for local buffers to continue with */
		for (k = 0; k < rc; k++) {
			lnb[j + k].lnb_flags = rnb[i].rnb_flags;
			if (!(rnb[i].rnb_flags & OBD_BRW_GRANTED))
				lnb[j + k].lnb_rc = -ENOSPC;
		}
		j += rc;
		maxlnb -= rc;
		*nr_local += rc;
		tot_bytes += rnb[i].rnb_len;
	}

	rc = dt_write_prep(env, dob, lnb, *nr_local);
	if (likely(rc))
		GOTO(err, rc);

	mdt_counter_incr(req, LPROC_MDT_IO_WRITE, tot_bytes);
	RETURN(0);
err:
	dt_bufs_put(env, dob, lnb, *nr_local);
unlock:
	mdt_dom_read_unlock(mo);
	/* tgt_grant_prepare_write() was called, so we must commit */
	tgt_grant_commit(exp, oa->o_grant_used, rc);
	/* let's still process incoming grant information packed in the oa,
	 * but without enforcing grant since we won't proceed with the write.
	 * Just like a read request actually. */
	tgt_grant_prepare_read(env, exp, oa);
	return rc;
}

int mdt_obd_preprw(const struct lu_env *env, int cmd, struct obd_export *exp,
		   struct obdo *oa, int objcount, struct obd_ioobj *obj,
		   struct niobuf_remote *rnb, int *nr_local,
		   struct niobuf_local *lnb)
{
	struct tgt_session_info *tsi = tgt_ses_info(env);
	struct mdt_thread_info *info = tsi2mdt_info(tsi);
	struct lu_attr *la = &info->mti_attr.ma_attr;
	struct mdt_device *mdt = mdt_dev(exp->exp_obd->obd_lu_dev);
	struct mdt_object *mo;
	char *jobid;
	int rc = 0;

	/* The default value PTLRPC_MAX_BRW_PAGES is set in tgt_brw_write()
	 * but for MDT it is different, correct it here. */
	if (*nr_local > MD_MAX_BRW_PAGES)
		*nr_local = MD_MAX_BRW_PAGES;

	jobid = tsi->tsi_jobid;

	if (!oa || objcount != 1 || obj->ioo_bufcnt == 0) {
		CERROR("%s: bad parameters %p/%i/%i\n",
		       exp->exp_obd->obd_name, oa, objcount, obj->ioo_bufcnt);
		rc = -EPROTO;
	}

	mo = mdt_object_find(env, mdt, &tsi->tsi_fid);
	if (IS_ERR(mo))
		GOTO(out, rc = PTR_ERR(mo));

	LASSERT(info->mti_object == NULL);
	info->mti_object = mo;

	if (cmd == OBD_BRW_WRITE) {
		la_from_obdo(la, oa, OBD_MD_FLGETATTR);
		rc = mdt_preprw_write(env, exp, mdt, mo, la, oa,
				      objcount, obj, rnb, nr_local, lnb,
				      jobid);
	} else if (cmd == OBD_BRW_READ) {
		tgt_grant_prepare_read(env, exp, oa);
		rc = mdt_preprw_read(env, exp, mdt, mo, la,
				     obj->ioo_bufcnt, rnb, nr_local, lnb,
				     jobid);
		obdo_from_la(oa, la, LA_ATIME);
	} else {
		CERROR("%s: wrong cmd %d received!\n",
		       exp->exp_obd->obd_name, cmd);
		rc = -EPROTO;
	}
	if (rc) {
		lu_object_put(env, &mo->mot_obj);
		info->mti_object = NULL;
	}
out:
	RETURN(rc);
}

static int mdt_commitrw_read(const struct lu_env *env, struct mdt_device *mdt,
			     struct mdt_object *mo, int objcount, int niocount,
			     struct niobuf_local *lnb)
{
	struct dt_object *dob;
	int rc = 0;

	ENTRY;

	dob = mdt_obj2dt(mo);

	if (niocount)
		dt_bufs_put(env, dob, lnb, niocount);

	mdt_dom_read_unlock(mo);
	RETURN(rc);
}

static int mdt_commitrw_write(const struct lu_env *env, struct obd_export *exp,
			      struct mdt_device *mdt, struct mdt_object *mo,
			      struct lu_attr *la, struct obdo *oa, int objcount,
			      int niocount, struct niobuf_local *lnb,
			      unsigned long granted, int old_rc)
{
	struct dt_device *dt = mdt->mdt_bottom;
	struct dt_object *dob;
	struct thandle *th;
	int rc = 0;
	int retries = 0;
	int i, restart = 0;

	ENTRY;

	dob = mdt_obj2dt(mo);

	if (old_rc)
		GOTO(out, rc = old_rc);

	la->la_valid &= LA_ATIME | LA_MTIME | LA_CTIME;
retry:
	if (!dt_object_exists(dob))
		GOTO(out, rc = -ENOENT);

	if (niocount == 0) {
		rc = -EPROTO;
		DEBUG_REQ(D_WARNING, tgt_ses_req(tgt_ses_info(env)),
			  "%s: commit with no pages for "DFID": rc = %d\n",
			  exp->exp_obd->obd_name, PFID(mdt_object_fid(mo)), rc);
		GOTO(out, rc);
	}

	CFS_FAIL_TIMEOUT(OBD_FAIL_MDS_COMMITRW_DELAY, cfs_fail_val);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	for (i = 0; i < niocount; i++) {
		if (!(lnb[i].lnb_flags & OBD_BRW_ASYNC)) {
			th->th_sync = 1;
			break;
		}
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_DQACQ_NET))
		GOTO(out_stop, rc = -EINPROGRESS);

	rc = dt_declare_write_commit(env, dob, lnb, niocount, th);
	if (rc)
		GOTO(out_stop, rc);

	if (la->la_valid) {
		/* update [mac]time if needed */
		rc = dt_declare_attr_set(env, dob, la, th);
		if (rc)
			GOTO(out_stop, rc);
	}

	tgt_vbr_obj_set(env, dob);
	rc = dt_trans_start(env, dt, th);
	if (rc)
		GOTO(out_stop, rc);

	dt_write_lock(env, dob, 0);
	if (lu_object_is_dying(&mo->mot_header)) {
		/* Commit to stale object can be just skipped silently. */
		CDEBUG(D_INODE, "skip commit to stale object "DFID"\n",
			PFID(mdt_object_fid(mo)));
		GOTO(unlock, rc = 0);
	}
	rc = dt_write_commit(env, dob, lnb, niocount, th, oa->o_size);
	if (rc) {
		restart = th->th_restart_tran;
		GOTO(unlock, rc);
	}

	if (la->la_valid) {
		rc = dt_attr_set(env, dob, la, th);
		if (rc)
			GOTO(unlock, rc);
	}
	/* get attr to return */
	rc = dt_attr_get(env, dob, la);
unlock:
	dt_write_unlock(env, dob);

out_stop:
	/* Force commit to make the just-deleted blocks
	 * reusable. LU-456 */
	if (rc == -ENOSPC)
		th->th_sync = 1;


	if (rc == 0 && granted > 0) {
		if (tgt_grant_commit_cb_add(th, exp, granted) == 0)
			granted = 0;
	}

	th->th_result = restart ? 0 : rc;
	dt_trans_stop(env, dt, th);
	if (rc == -ENOSPC && retries++ < 3) {
		CDEBUG(D_INODE, "retry after force commit, retries:%d\n",
		       retries);
		goto retry;
	}
	if (restart) {
		retries++;
		restart = 0;
		if (retries % 10000 == 0)
			CERROR("%s: restart IO write too many times: %d\n",
			       exp->exp_obd->obd_name, retries);
		CDEBUG(D_INODE, "retry transaction, retries:%d\n",
		       retries);
		goto retry;
	}

out:
	dt_bufs_put(env, dob, lnb, niocount);
	mdt_dom_read_unlock(mo);
	if (granted > 0)
		tgt_grant_commit(exp, granted, old_rc);
	RETURN(rc);
}

void mdt_dom_obj_lvb_update(const struct lu_env *env, struct mdt_object *mo,
			    bool increase_only)
{
	struct mdt_device *mdt = mdt_dev(mo->mot_obj.lo_dev);
	struct ldlm_res_id resid;
	struct ldlm_resource *res;

	fid_build_reg_res_name(mdt_object_fid(mo), &resid);
	res = ldlm_resource_get(mdt->mdt_namespace, NULL, &resid,
				LDLM_IBITS, 1);
	if (IS_ERR(res))
		return;

	/* Update lvbo data if exists. */
	if (mdt_dom_lvb_is_valid(res))
		mdt_dom_disk_lvbo_update(env, mo, res, increase_only);
	ldlm_resource_putref(res);
}

int mdt_obd_commitrw(const struct lu_env *env, int cmd, struct obd_export *exp,
		     struct obdo *oa, int objcount, struct obd_ioobj *obj,
		     struct niobuf_remote *rnb, int npages,
		     struct niobuf_local *lnb, int old_rc)
{
	struct mdt_thread_info *info = mdt_th_info(env);
	struct mdt_device *mdt = mdt_dev(exp->exp_obd->obd_lu_dev);
	struct mdt_object *mo = info->mti_object;
	struct lu_attr *la = &info->mti_attr.ma_attr;
	__u64 valid;
	int rc = 0;

	LASSERT(mo);

	if (cmd == OBD_BRW_WRITE) {
		/* Don't update timestamps if this write is older than a
		 * setattr which modifies the timestamps. b=10150 */

		/* XXX when we start having persistent reservations this needs
		 * to be changed to ofd_fmd_get() to create the fmd if it
		 * doesn't already exist so we can store the reservation handle
		 * there. */
		valid = OBD_MD_FLUID | OBD_MD_FLGID;
		if (tgt_fmd_check(exp, mdt_object_fid(mo),
				  mdt_info_req(info)->rq_xid))
			valid |= OBD_MD_FLATIME | OBD_MD_FLMTIME |
				 OBD_MD_FLCTIME;

		la_from_obdo(la, oa, valid);

		rc = mdt_commitrw_write(env, exp, mdt, mo, la, oa, objcount,
					npages, lnb, oa->o_grant_used, old_rc);
		if (rc == 0)
			obdo_from_la(oa, la, VALID_FLAGS | LA_GID | LA_UID);
		else
			obdo_from_la(oa, la, LA_GID | LA_UID);

		mdt_dom_obj_lvb_update(env, mo, false);
		/* don't report overquota flag if we failed before reaching
		 * commit */
		if (old_rc == 0 && (rc == 0 || rc == -EDQUOT)) {
			/* return the overquota flags to client */
			if (lnb[0].lnb_flags & OBD_BRW_OVER_USRQUOTA) {
				if (oa->o_valid & OBD_MD_FLFLAGS)
					oa->o_flags |= OBD_FL_NO_USRQUOTA;
				else
					oa->o_flags = OBD_FL_NO_USRQUOTA;
			}

			if (lnb[0].lnb_flags & OBD_BRW_OVER_GRPQUOTA) {
				if (oa->o_valid & OBD_MD_FLFLAGS)
					oa->o_flags |= OBD_FL_NO_GRPQUOTA;
				else
					oa->o_flags = OBD_FL_NO_GRPQUOTA;
			}

			if (lnb[0].lnb_flags & OBD_BRW_OVER_PRJQUOTA) {
				if (oa->o_valid & OBD_MD_FLFLAGS)
					oa->o_flags |= OBD_FL_NO_PRJQUOTA;
				else
					oa->o_flags = OBD_FL_NO_PRJQUOTA;
			}

			oa->o_valid |= OBD_MD_FLFLAGS | OBD_MD_FLUSRQUOTA |
				       OBD_MD_FLGRPQUOTA | OBD_MD_FLPRJQUOTA;
		}
	} else if (cmd == OBD_BRW_READ) {
		/* If oa != NULL then mdt_preprw_read updated the inode
		 * atime and we should update the lvb so that other glimpses
		 * will also get the updated value. bug 5972 */
		if (oa)
			mdt_dom_obj_lvb_update(env, mo, true);
		rc = mdt_commitrw_read(env, mdt, mo, objcount, npages, lnb);
		if (old_rc)
			rc = old_rc;
	} else {
		rc = -EPROTO;
	}
	mdt_thread_info_fini(info);
	RETURN(rc);
}

int mdt_object_punch(const struct lu_env *env, struct dt_device *dt,
		     struct dt_object *dob, __u64 start, __u64 end,
		     struct lu_attr *la)
{
	struct thandle *th;
	int rc;

	ENTRY;

	/* we support truncate, not punch yet */
	LASSERT(end == OBD_OBJECT_EOF);

	if (!dt_object_exists(dob))
		RETURN(-ENOENT);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_attr_set(env, dob, la, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_declare_punch(env, dob, start, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(stop, rc);

	tgt_vbr_obj_set(env, dob);
	rc = dt_trans_start(env, dt, th);
	if (rc)
		GOTO(stop, rc);

	dt_write_lock(env, dob, 0);
	rc = dt_punch(env, dob, start, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(unlock, rc);
	rc = dt_attr_set(env, dob, la, th);
	if (rc)
		GOTO(unlock, rc);
unlock:
	dt_write_unlock(env, dob);
stop:
	th->th_result = rc;
	dt_trans_stop(env, dt, th);
	RETURN(rc);
}

int mdt_punch_hdl(struct tgt_session_info *tsi)
{
	const struct obdo *oa = &tsi->tsi_ost_body->oa;
	struct ptlrpc_request *req = tgt_ses_req(tsi);
	struct ost_body *repbody;
	struct mdt_thread_info *info;
	struct lu_attr *la;
	struct ldlm_namespace *ns = tsi->tsi_tgt->lut_obd->obd_namespace;
	struct obd_export *exp = tsi->tsi_exp;
	struct mdt_device *mdt = mdt_dev(exp->exp_obd->obd_lu_dev);
	struct mdt_object *mo;
	struct dt_object *dob;
	__u64 flags = 0;
	struct lustre_handle lh = { 0, };
	ktime_t kstart = ktime_get();
	__u64 start, end;
	int rc;
	bool srvlock;

	ENTRY;

	/* check that we do support OBD_CONNECT_TRUNCLOCK. */
	BUILD_BUG_ON(!(OST_CONNECT_SUPPORTED & OBD_CONNECT_TRUNCLOCK));

	if ((oa->o_valid & (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS)) !=
	    (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS))
		RETURN(err_serious(-EPROTO));

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(err_serious(-ENOMEM));

	/* punch start,end are passed in o_size,o_blocks throught wire */
	start = oa->o_size;
	end = oa->o_blocks;

	if (end != OBD_OBJECT_EOF) /* Only truncate is supported */
		RETURN(-EPROTO);

	info = tsi2mdt_info(tsi);
	la = &info->mti_attr.ma_attr;
	/* standard truncate optimization: if file body is completely
	 * destroyed, don't send data back to the server. */
	if (start == 0)
		flags |= LDLM_FL_AST_DISCARD_DATA;

	repbody->oa.o_oi = oa->o_oi;
	repbody->oa.o_valid = OBD_MD_FLID;

	srvlock = (exp_connect_flags(exp) & OBD_CONNECT_SRVLOCK) &&
		  oa->o_valid & OBD_MD_FLFLAGS &&
		  oa->o_flags & OBD_FL_SRVLOCK;

	if (srvlock) {
		rc = tgt_mdt_data_lock(ns, &tsi->tsi_resid, &lh, LCK_PW,
				       &flags);
		if (rc != 0)
			GOTO(out, rc);
	}

	CDEBUG(D_INODE, "calling punch for object "DFID", valid = %#llx"
	       ", start = %lld, end = %lld\n", PFID(&tsi->tsi_fid),
	       oa->o_valid, start, end);

	mo = mdt_object_find(tsi->tsi_env, mdt, &tsi->tsi_fid);
	if (IS_ERR(mo))
		GOTO(out_unlock, rc = PTR_ERR(mo));

	if (!mdt_object_exists(mo))
		GOTO(out_put, rc = -ENOENT);

	/* Shouldn't happen on dirs */
	if (S_ISDIR(lu_object_attr(&mo->mot_obj))) {
		rc = -EPERM;
		CERROR("%s: Truncate on dir "DFID": rc = %d\n",
		       exp->exp_obd->obd_name, PFID(&tsi->tsi_fid), rc);
		GOTO(out_put, rc);
	}

	mdt_dom_write_lock(mo);
	dob = mdt_obj2dt(mo);

	la_from_obdo(la, oa, OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME);
	la->la_size = start;
	la->la_valid |= LA_SIZE;

	/* MDT supports FMD for Data-on-MDT needs */
	if (la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME))
		tgt_fmd_update(tsi->tsi_exp, &tsi->tsi_fid,
			       tgt_ses_req(tsi)->rq_xid);

	rc = mdt_object_punch(tsi->tsi_env, mdt->mdt_bottom, dob,
			      start, end, la);
	mdt_dom_write_unlock(mo);
	if (rc)
		GOTO(out_put, rc);

	mdt_dom_obj_lvb_update(tsi->tsi_env, mo, false);
	mdt_counter_incr(req, LPROC_MDT_IO_PUNCH,
			 ktime_us_delta(ktime_get(), kstart));
	EXIT;
out_put:
	lu_object_put(tsi->tsi_env, &mo->mot_obj);
out_unlock:
	if (srvlock)
		tgt_data_unlock(&lh, LCK_PW);
out:
	mdt_thread_info_fini(info);
	return rc;
}

/**
 * MDT glimpse for Data-on-MDT
 *
 * If there is write lock on client then function issues glimpse_ast to get
 * an actual size from that client.
 *
 */
int mdt_do_glimpse(const struct lu_env *env, struct ldlm_namespace *ns,
		   struct ldlm_resource *res)
{
	union ldlm_policy_data policy;
	struct lustre_handle lockh;
	enum ldlm_mode mode;
	struct ldlm_lock *lock;
	struct ldlm_glimpse_work *gl_work;
	LIST_HEAD(gl_list);
	int rc;

	ENTRY;

	/* There can be only one write lock covering data, try to match it. */
	policy.l_inodebits.bits = MDS_INODELOCK_DOM;
	mode = ldlm_lock_match(ns, LDLM_FL_TEST_LOCK,
			       &res->lr_name, LDLM_IBITS, &policy,
			       LCK_PW, &lockh);

	/* There is no PW lock on this object; finished. */
	if (mode == 0)
		RETURN(0);

	lock = ldlm_handle2lock(&lockh);
	if (lock == NULL)
		RETURN(0);

	/*
	 * This check is for lock taken in mdt_reint_unlink() that does
	 * not have l_glimpse_ast set. So the logic is: if there is a lock
	 * with no l_glimpse_ast set, this object is being destroyed already.
	 * Hence, if you are grabbing DLM locks on the server, always set
	 * non-NULL glimpse_ast (e.g., ldlm_request.c::ldlm_glimpse_ast()).
	 */
	if (lock->l_glimpse_ast == NULL) {
		LDLM_DEBUG(lock, "no l_glimpse_ast");
		GOTO(out, rc = -ENOENT);
	}

	OBD_SLAB_ALLOC_PTR_GFP(gl_work, ldlm_glimpse_work_kmem, GFP_ATOMIC);
	if (!gl_work)
		GOTO(out, rc = -ENOMEM);

	/* Populate the gl_work structure.
	 * Grab additional reference on the lock which will be released in
	 * ldlm_work_gl_ast_lock() */
	gl_work->gl_lock = LDLM_LOCK_GET(lock);
	/* The glimpse callback is sent to one single IO lock. As a result,
	 * the gl_work list is just composed of one element */
	list_add_tail(&gl_work->gl_list, &gl_list);
	/* There is actually no need for a glimpse descriptor when glimpsing
	 * IO locks */
	gl_work->gl_desc = NULL;
	/* the ldlm_glimpse_work structure is allocated on the stack */
	gl_work->gl_flags = LDLM_GL_WORK_SLAB_ALLOCATED;

	ldlm_glimpse_locks(res, &gl_list); /* this will update the LVB */

	/* If the list is not empty, we failed to glimpse a lock and
	 * must clean it up. Usually due to a race with unlink.*/
	if (!list_empty(&gl_list)) {
		LDLM_LOCK_RELEASE(lock);
		OBD_SLAB_FREE_PTR(gl_work, ldlm_glimpse_work_kmem);
	}
	rc = 0;
	EXIT;
out:
	LDLM_LOCK_PUT(lock);
	return rc;
}

static void mdt_lvb2reply(struct ldlm_resource *res, struct mdt_body *mb,
			  struct ost_lvb *lvb)
{
	struct ost_lvb *res_lvb;

	lock_res(res);
	res_lvb = res->lr_lvb_data;
	if (lvb)
		*lvb = *res_lvb;

	if (mb) {
		mb->mbo_dom_size = res_lvb->lvb_size;
		mb->mbo_dom_blocks = res_lvb->lvb_blocks;
		mb->mbo_mtime = res_lvb->lvb_mtime;
		mb->mbo_ctime = res_lvb->lvb_ctime;
		mb->mbo_atime = res_lvb->lvb_atime;
		mb->mbo_valid |= OBD_MD_FLATIME | OBD_MD_FLCTIME |
				 OBD_MD_FLMTIME | OBD_MD_DOM_SIZE;
	}
	CDEBUG(D_DLMTRACE, "size %llu\n", res_lvb->lvb_size);
	unlock_res(res);
}

/**
 * MDT glimpse for Data-on-MDT
 *
 * This function is called when MDT get attributes for the DoM object.
 * If there is write lock on client then function issues glimpse_ast to get
 * an actual size from that client.
 */
int mdt_dom_object_size(const struct lu_env *env, struct mdt_device *mdt,
			const struct lu_fid *fid, struct mdt_body *mb,
			bool dom_lock)
{
	struct ldlm_res_id resid;
	struct ldlm_resource *res;
	int rc = 0;

	ENTRY;

	fid_build_reg_res_name(fid, &resid);
	res = ldlm_resource_get(mdt->mdt_namespace, NULL, &resid,
				LDLM_IBITS, 1);
	if (IS_ERR(res))
		RETURN(-ENOENT);

	/* Update lvbo data if DoM lock returned or if LVB is not yet valid. */
	if (dom_lock || !mdt_dom_lvb_is_valid(res))
		mdt_dom_lvbo_update(res, NULL, NULL, false);

	mdt_lvb2reply(res, mb, NULL);
	ldlm_resource_putref(res);
	RETURN(rc);
}

/**
 * MDT DoM lock intent policy (glimpse)
 *
 * Intent policy is called when lock has an intent, for DoM file that
 * means glimpse lock and policy fills Lock Value Block (LVB).
 *
 * If already granted lock is found it will be placed in \a lockp and
 * returned back to caller function.
 *
 * \param[in] tsi	 session info
 * \param[in,out] lockp	 pointer to the lock
 * \param[in] flags	 LDLM flags
 *
 * \retval		ELDLM_LOCK_REPLACED if already granted lock was found
 *			and placed in \a lockp
 * \retval		ELDLM_LOCK_ABORTED in other cases except error
 * \retval		negative value on error
 */
int mdt_glimpse_enqueue(struct mdt_thread_info *mti, struct ldlm_namespace *ns,
			struct ldlm_lock **lockp, __u64 flags)
{
	struct ldlm_lock *lock = *lockp;
	struct ldlm_resource *res = lock->l_resource;
	ldlm_processing_policy policy;
	struct ldlm_reply *rep;
	struct mdt_body *mbo;
	struct ost_lvb *lvb;
	bool old_client = !exp_connect_dom_lvb(mti->mti_exp);
	int rc;

	ENTRY;

	policy = ldlm_get_processing_policy(res);
	LASSERT(policy != NULL);

	if (unlikely(old_client)) {
		req_capsule_set_size(mti->mti_pill, &RMF_MDT_MD, RCL_SERVER, 0);
		req_capsule_set_size(mti->mti_pill, &RMF_ACL, RCL_SERVER, 0);
	} else {
		req_capsule_set_size(mti->mti_pill, &RMF_DLM_LVB, RCL_SERVER,
				     sizeof(*lvb));
	}
	rc = req_capsule_server_pack(mti->mti_pill);
	if (rc)
		RETURN(err_serious(rc));

	rep = req_capsule_server_get(mti->mti_pill, &RMF_DLM_REP);

	if (unlikely(old_client)) {
		mbo = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
		LASSERT(mbo);
		lvb = NULL;
	} else {
		lvb = req_capsule_server_get(mti->mti_pill, &RMF_DLM_LVB);
		LASSERT(lvb);
		mbo = NULL;
	}

	lock_res(res);
	/* Check if this is a resend case (MSG_RESENT is set on RPC) and a
	 * lock was found by ldlm_handle_enqueue(); if so no need to grant
	 * it again. */
	if (flags & LDLM_FL_RESENT) {
		rc = LDLM_ITER_CONTINUE;
	} else {
		__u64 tmpflags = LDLM_FL_BLOCK_NOWAIT;
		enum ldlm_error err;

		rc = policy(lock, &tmpflags, LDLM_PROCESS_RESCAN, &err, NULL);
		check_res_locked(res);
	}
	unlock_res(res);

	/* The lock met with no resistance; we're finished. */
	if (rc == LDLM_ITER_CONTINUE) {
		GOTO(fill_mbo, rc = ELDLM_LOCK_REPLACED);
	} else if (flags & LDLM_FL_BLOCK_NOWAIT) {
		/* LDLM_FL_BLOCK_NOWAIT means it is for AGL. Do not send glimpse
		 * callback for glimpse size. The real size user will trigger
		 * the glimpse callback when necessary. */
		GOTO(fill_mbo, rc = ELDLM_LOCK_ABORTED);
	}

	rc = mdt_do_glimpse(mti->mti_env, ns, res);
	if (rc == -ENOENT) {
		/* We are racing with unlink(); just return -ENOENT */
		rep->lock_policy_res2 = ptlrpc_status_hton(-ENOENT);
	} else if (rc == -EINVAL) {
		/* this is possible is client lock has been cancelled but
		 * still exists on server. If that lock was found on server
		 * as only conflicting lock then the client has already
		 * size authority and glimpse is not needed. */
		CDEBUG(D_DLMTRACE, "Glimpse from the client owning lock\n");
	} else if (rc < 0) {
		RETURN(rc);
	}
	rc = ELDLM_LOCK_ABORTED;
fill_mbo:
	/* LVB can be without valid data in case of DOM */
	if (!mdt_dom_lvb_is_valid(res))
		mdt_dom_lvbo_update(res, lock, NULL, false);
	mdt_lvb2reply(res, mbo, lvb);

	RETURN(rc);
}

int mdt_brw_enqueue(struct mdt_thread_info *mti, struct ldlm_namespace *ns,
		    struct ldlm_lock **lockp, __u64 flags)
{
	struct tgt_session_info *tsi = tgt_ses_info(mti->mti_env);
	struct lu_fid *fid = &tsi->tsi_fid;
	struct ldlm_lock *lock = *lockp;
	struct ldlm_resource *res = lock->l_resource;
	struct ldlm_reply *rep;
	struct mdt_body *mbo;
	struct mdt_lock_handle *lhc = &mti->mti_lh[MDT_LH_RMT];
	struct mdt_object *mo;
	int rc = 0;

	ENTRY;

	req_capsule_set_size(mti->mti_pill, &RMF_MDT_MD, RCL_SERVER, 0);
	req_capsule_set_size(mti->mti_pill, &RMF_ACL, RCL_SERVER, 0);
	rc = req_capsule_server_pack(mti->mti_pill);
	if (rc)
		RETURN(err_serious(rc));

	rep = req_capsule_server_get(mti->mti_pill, &RMF_DLM_REP);
	if (rep == NULL)
		RETURN(-EPROTO);

	mbo = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
	if (mbo == NULL)
		RETURN(-EPROTO);

	fid_extract_from_res_name(fid, &res->lr_name);
	mo = mdt_object_find(mti->mti_env, mti->mti_mdt, fid);
	if (unlikely(IS_ERR(mo)))
		RETURN(PTR_ERR(mo));

	if (!mdt_object_exists(mo))
		GOTO(out, rc = -ENOENT);

	if (mdt_object_remote(mo))
		GOTO(out, rc = -EPROTO);

	/* Get lock from request for possible resent case. */
	mdt_intent_fixup_resent(mti, *lockp, lhc, flags);
	/* resent case */
	if (!lustre_handle_is_used(&lhc->mlh_reg_lh)) {
		mdt_lock_handle_init(lhc);
		mdt_lh_reg_init(lhc, *lockp);

		/* This will block MDT thread but it should be fine until
		 * client caches small amount of data for DoM, which should be
		 * smaller than one BRW RPC and should be able to be
		 * piggybacked by lock cancel RPC.
		 * If the client could hold the lock too long, this code can be
		 * revised to call mdt_object_lock_try(). And if fails, it will
		 * return ELDLM_OK here and fall back into normal lock enqueue
		 * process.
		 */
		rc = mdt_object_lock(mti, mo, lhc, MDS_INODELOCK_DOM);
		if (rc)
			GOTO(out, rc);
	}

	if (!mdt_dom_lvb_is_valid(res)) {
		rc = mdt_dom_lvb_alloc(res);
		if (rc)
			GOTO(out_fail, rc);
		mdt_dom_disk_lvbo_update(mti->mti_env, mo, res, false);
	}
	mdt_lvb2reply(res, mbo, NULL);
out_fail:
	rep->lock_policy_res2 = clear_serious(rc);
	if (rep->lock_policy_res2) {
		lhc->mlh_reg_lh.cookie = 0ull;
		GOTO(out, rc = ELDLM_LOCK_ABORTED);
	}

	rc = mdt_intent_lock_replace(mti, lockp, lhc, flags, rc);
out:
	if (rc < 0)
		lhc->mlh_reg_lh.cookie = 0ull;
	mdt_object_put(mti->mti_env, mo);
	RETURN(rc);
}

/* check if client has already DoM lock for given resource */
bool mdt_dom_client_has_lock(struct mdt_thread_info *info,
			     const struct lu_fid *fid)
{
	struct mdt_device *mdt = info->mti_mdt;
	union ldlm_policy_data *policy = &info->mti_policy;
	struct ldlm_res_id *res_id = &info->mti_res_id;
	__u64 open_flags = info->mti_spec.sp_cr_flags;
	struct lustre_handle lockh;
	enum ldlm_mode mode;
	struct ldlm_lock *lock;
	enum ldlm_mode lm;
	bool rc;

	policy->l_inodebits.bits = MDS_INODELOCK_DOM;
	fid_build_reg_res_name(fid, res_id);


	lm = (open_flags & MDS_FMODE_WRITE) ? LCK_PW : LCK_PR | LCK_PW;
	mode = ldlm_lock_match(mdt->mdt_namespace, LDLM_FL_BLOCK_GRANTED |
			       LDLM_FL_TEST_LOCK, res_id, LDLM_IBITS, policy,
			       lm, &lockh);

	/* There is no other PW lock on this object; finished. */
	if (mode == 0)
		return false;

	lock = ldlm_handle2lock(&lockh);
	if (lock == 0)
		return false;

	/* check if lock from the same client */
	rc = (lock->l_export->exp_handle.h_cookie ==
	      info->mti_exp->exp_handle.h_cookie);
	LDLM_LOCK_PUT(lock);
	return rc;
}

/**
 * MDT request handler for OST_GETATTR RPC.
 *
 * This is data-specific request to get object and layout versions under
 * IO lock. It is reliable only for Data-on-MDT files.
 *
 * \param[in] tsi target session environment for this request
 *
 * \retval 0 if successful
 * \retval negative value on error
 */
int mdt_data_version_get(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *mti = mdt_th_info(tsi->tsi_env);
	struct mdt_device *mdt = mti->mti_mdt;
	struct mdt_body *repbody;
	struct mdt_object *mo = mti->mti_object;
	struct lov_comp_md_v1 *comp;
	struct lustre_handle lh = { 0 };
	__u64 flags = 0;
	__s64 version;
	enum ldlm_mode lock_mode = LCK_PR;
	bool srvlock;
	int rc;

	ENTRY;

	req_capsule_set_size(tsi->tsi_pill, &RMF_MDT_MD, RCL_SERVER, 0);
	req_capsule_set_size(tsi->tsi_pill, &RMF_ACL, RCL_SERVER, 0);
	rc = req_capsule_server_pack(tsi->tsi_pill);
	if (unlikely(rc != 0))
		RETURN(err_serious(rc));

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_MDT_BODY);
	if (repbody == NULL)
		RETURN(-ENOMEM);

	srvlock = tsi->tsi_mdt_body->mbo_valid & OBD_MD_FLFLAGS &&
		  tsi->tsi_mdt_body->mbo_flags & OBD_FL_SRVLOCK;

	if (srvlock) {
		if (unlikely(tsi->tsi_mdt_body->mbo_flags & OBD_FL_FLUSH))
			lock_mode = LCK_PW;

		fid_build_reg_res_name(&tsi->tsi_fid, &tsi->tsi_resid);
		rc = tgt_mdt_data_lock(mdt->mdt_namespace, &tsi->tsi_resid,
				       &lh, lock_mode, &flags);
		if (rc != 0)
			RETURN(rc);
	}

	if (!mdt_object_exists(mo))
		GOTO(out, rc = -ENOENT);
	if (mdt_object_remote(mo))
		GOTO(out, rc = -EREMOTE);
	if (!S_ISREG(lu_object_attr(&mo->mot_obj)))
		GOTO(out, rc = -EBADF);

	/* Get version first */
	version = dt_version_get(tsi->tsi_env, mdt_obj2dt(mo));
	if (version && version != -EOPNOTSUPP) {
		repbody->mbo_valid |= OBD_MD_FLDATAVERSION;
		/* re-use mbo_ioepoch to transfer version */
		repbody->mbo_version = version;
	}

	/* Read layout to get its version */
	rc = mdt_big_xattr_get(mti, mo, XATTR_NAME_LOV);
	if (rc == -ENODATA) /* File has no layout yet */
		GOTO(out, rc = 0);
	else if (rc < 0)
		GOTO(out, rc);

	comp = mti->mti_buf.lb_buf;
	if (le32_to_cpu(comp->lcm_magic) != LOV_MAGIC_COMP_V1) {
		CDEBUG(D_INFO, DFID" has no composite layout",
		       PFID(&tsi->tsi_fid));
		GOTO(out, rc = -ESTALE);
	}

	CDEBUG(D_INODE, DFID": layout version: %u\n",
	       PFID(&tsi->tsi_fid), le32_to_cpu(comp->lcm_layout_gen));

	repbody->mbo_valid |= OBD_MD_LAYOUT_VERSION;
	/* re-use mbo_rdev for that */
	repbody->mbo_layout_gen = le32_to_cpu(comp->lcm_layout_gen);
	rc = 0;
out:
	if (srvlock)
		tgt_data_unlock(&lh, lock_mode);

	repbody->mbo_valid |= OBD_MD_FLFLAGS;
	repbody->mbo_flags = OBD_FL_FLUSH;
	RETURN(rc);
}

/* read file data to the buffer */
int mdt_dom_read_on_open(struct mdt_thread_info *mti, struct mdt_device *mdt,
			 struct lustre_handle *lh)
{
	const struct lu_env *env = mti->mti_env;
	struct tgt_session_info *tsi = tgt_ses_info(env);
	struct req_capsule *pill = tsi->tsi_pill;
	const struct lu_fid *fid;
	struct ptlrpc_request *req = tgt_ses_req(tsi);
	struct mdt_body *mbo;
	struct dt_device *dt = mdt->mdt_bottom;
	struct dt_object *mo;
	void *buf;
	struct niobuf_remote *rnb = NULL;
	struct niobuf_local *lnb;
	int rc;
	loff_t offset;
	unsigned int len, copied = 0;
	__u64 real_dom_size;
	int lnbs, nr_local, i;
	bool dom_lock = false;

	ENTRY;

	if (!req_capsule_field_present(pill, &RMF_NIOBUF_INLINE, RCL_SERVER)) {
		/* There is no reply buffers for this field, this means that
		 * client has no support for data in reply.
		 */
		RETURN(0);
	}

	mbo = req_capsule_server_get(pill, &RMF_MDT_BODY);
	if (!(mbo->mbo_valid & OBD_MD_DOM_SIZE))
		RETURN(0);

	if (!mbo->mbo_dom_size)
		RETURN(0);

	if (lustre_handle_is_used(lh)) {
		struct ldlm_lock *lock;

		lock = ldlm_handle2lock(lh);
		if (lock) {
			dom_lock = ldlm_has_dom(lock) && ldlm_has_layout(lock);
			LDLM_LOCK_PUT(lock);
		}
	}

	/* return data along with open only along with DoM lock */
	if (!dom_lock || !mdt->mdt_opts.mo_dom_read_open)
		RETURN(0);

	/* if DoM object holds encrypted content, we need to make sure we
	 * send whole encryption units, or client will read corrupted content
	 */
	if (mbo->mbo_valid & LA_FLAGS && mbo->mbo_flags & LUSTRE_ENCRYPT_FL &&
	    mbo->mbo_dom_size & ~LUSTRE_ENCRYPTION_MASK)
		real_dom_size = (mbo->mbo_dom_size & LUSTRE_ENCRYPTION_MASK) +
				LUSTRE_ENCRYPTION_UNIT_SIZE;
	else
		real_dom_size = mbo->mbo_dom_size;

	CDEBUG(D_INFO, "File size %llu, reply sizes %d/%d\n",
	       real_dom_size, req->rq_reqmsg->lm_repsize, req->rq_replen);
	len = req->rq_reqmsg->lm_repsize - req->rq_replen;

	/* NB: at this moment we have the following sizes:
	 * - req->rq_replen: used data in reply
	 * - req->rq_reqmsg->lm_repsize: total allocated reply buffer at client
	 *
	 * Ideal case when file size fits in allocated reply buffer,
	 * that mean we can return whole data in reply. We can also fit more
	 * data up to max_reply_size in total reply size, but this will cause
	 * re-allocation on client and resend with larger buffer. This is still
	 * faster than separate READ IO.
	 * Third case if file is too big to fit even in maximum size, in that
	 * case we return just tail to optimize possible append.
	 *
	 * At the moment the following strategy is used:
	 * 1) try to fit into the buffer we have
	 * 2) return just file tail otherwise.
	 */
	if (real_dom_size <= len) {
		/* can fit whole data */
		len = real_dom_size;
		offset = 0;
	} else if (real_dom_size <
		   mdt_lmm_dom_stripesize(mti->mti_attr.ma_lmm)) {
		int tail, pgbits;

		/* File tail offset must be aligned with larger page size
		 * between client and server, so the maximum page size is
		 * used here to align offset.
		 *
		 * NB: DOM feature was introduced when server supports pagebits
		 * already, so it should be always non-zero value. Report error
		 * if it is not for some reason.
		 */
		if (!req->rq_export->exp_target_data.ted_pagebits) {
			CERROR("%s: client page bits are not saved on server\n",
			       mdt_obd_name(mdt));
			RETURN(0);
		}
		pgbits = max_t(int, PAGE_SHIFT,
			       req->rq_export->exp_target_data.ted_pagebits);
		tail = real_dom_size % (1 << pgbits);

		/* no partial tail or tail can't fit in reply */
		if (tail == 0 || len < tail)
			RETURN(0);

		len = tail;
		offset = real_dom_size - len;
	} else {
		/* DOM stripe is fully written, so don't expect its tail
		 * will be used by append.
		 */
		RETURN(0);
	}

	LASSERT((offset & ~PAGE_MASK) == 0);
	rc = req_capsule_server_grow(pill, &RMF_NIOBUF_INLINE,
				     sizeof(*rnb) + len);
	if (rc != 0) {
		/* failed to grow data buffer, just exit */
		GOTO(out, rc = -E2BIG);
	}

	/* re-take MDT_BODY and NIOBUF_INLINE buffers after the buffer grow */
	mbo = req_capsule_server_get(pill, &RMF_MDT_BODY);
	fid = &mbo->mbo_fid1;
	if (!fid_is_sane(fid))
		GOTO(out, rc = -EINVAL);

	rnb = req_capsule_server_get(tsi->tsi_pill, &RMF_NIOBUF_INLINE);
	if (rnb == NULL)
		GOTO(out, rc = -EPROTO);

	buf = (char *)rnb + sizeof(*rnb);
	rnb->rnb_len = len;
	rnb->rnb_offset = offset;

	mo = dt_locate(env, dt, fid);
	if (IS_ERR(mo))
		GOTO(out_rnb, rc = PTR_ERR(mo));
	LASSERT(mo != NULL);

	dt_read_lock(env, mo, 0);
	if (!dt_object_exists(mo))
		GOTO(unlock, rc = -ENOENT);

	/* parse remote buffers to local buffers and prepare the latter */
	lnbs = (len >> PAGE_SHIFT) + 1;
	OBD_ALLOC_PTR_ARRAY(lnb, lnbs);
	if (lnb == NULL)
		GOTO(unlock, rc = -ENOMEM);

	rc = dt_bufs_get(env, mo, rnb, lnb, lnbs, 0);
	if (unlikely(rc < 0))
		GOTO(free, rc);
	LASSERT(rc <= lnbs);
	nr_local = rc;
	rc = dt_read_prep(env, mo, lnb, nr_local);
	if (unlikely(rc))
		GOTO(buf_put, rc);
	/* copy data to the buffer finally */
	for (i = 0; i < nr_local; i++) {
		char *p = kmap(lnb[i].lnb_page);
		long off;

		LASSERT(lnb[i].lnb_page_offset == 0);
		off = lnb[i].lnb_len & ~PAGE_MASK;
		if (off > 0)
			memset(p + off, 0, PAGE_SIZE - off);

		memcpy(buf + (i << PAGE_SHIFT), p, lnb[i].lnb_len);
		kunmap(lnb[i].lnb_page);
		copied += lnb[i].lnb_len;
		LASSERT(rc <= len);
	}
	CDEBUG(D_INFO, "Read %i (wanted %u) bytes from %llu\n", copied,
	       len, offset);
	if (copied < len) {
		CWARN("%s: read %i bytes for "DFID
		      " but wanted %u, is size wrong?\n",
		      tsi->tsi_exp->exp_obd->obd_name, copied,
		      PFID(&tsi->tsi_fid), len);
		/* Ignore partially copied data */
		copied = 0;
	}
	EXIT;
buf_put:
	dt_bufs_put(env, mo, lnb, nr_local);
free:
	OBD_FREE_PTR_ARRAY(lnb, lnbs);
unlock:
	dt_read_unlock(env, mo);
	lu_object_put(env, &mo->do_lu);
out_rnb:
	rnb->rnb_len = copied;
out:
	/* Don't fail OPEN request if read-on-open is failed, but drop
	 * a message in log about the error.
	 */
	if (rc)
		CDEBUG(D_INFO, "Read-on-open is failed, rc = %d", rc);

	RETURN(0);
}

/**
 * Completion AST for DOM discard locks:
 *
 * CP AST an DOM discard lock is called always right after enqueue or from
 * reprocess if lock was blocked, in the latest case l_ast_data is set to
 * the mdt_object which is kept while there are pending locks on it.
 */
int ldlm_dom_discard_cp_ast(struct ldlm_lock *lock, __u64 flags, void *data)
{
	struct mdt_object *mo;
	struct lustre_handle dom_lh;
	struct lu_env *env;

	ENTRY;

	/* l_ast_data is set when lock was not granted immediately
	 * in mdt_dom_discard_data() below but put into waiting list,
	 * so this CP callback means we are finished and corresponding
	 * MDT object should be released finally as well as lock itself.
	 */
	lock_res_and_lock(lock);
	if (!lock->l_ast_data) {
		unlock_res_and_lock(lock);
		RETURN(0);
	}

	mo = lock->l_ast_data;
	lock->l_ast_data = NULL;
	unlock_res_and_lock(lock);

	ldlm_lock2handle(lock, &dom_lh);
	ldlm_lock_decref(&dom_lh, LCK_PW);

	env = lu_env_find();
	LASSERT(env);
	mdt_object_put(env, mo);

	RETURN(0);
}

void mdt_dom_discard_data(struct mdt_thread_info *info,
			  struct mdt_object *mo)
{
	struct ptlrpc_request *req = mdt_info_req(info);
	struct mdt_device *mdt = mdt_dev(mo->mot_obj.lo_dev);
	union ldlm_policy_data policy;
	struct ldlm_res_id res_id;
	struct lustre_handle dom_lh;
	struct ldlm_lock *lock;
	__u64 flags = LDLM_FL_AST_DISCARD_DATA;
	int rc = 0;
	bool old_client;

	ENTRY;

	if (req && req_is_replay(req))
		RETURN_EXIT;

	policy.l_inodebits.bits = MDS_INODELOCK_DOM;
	policy.l_inodebits.try_bits = 0;
	fid_build_reg_res_name(mdt_object_fid(mo), &res_id);

	/* Keep blocking version of discard for an old client to avoid
	 * crashes on non-patched clients. LU-11359.
	 */
	old_client = req && !(exp_connect_flags2(req->rq_export) &
			      OBD_CONNECT2_ASYNC_DISCARD);

	/* Tell the clients that the object is gone now and that they should
	 * throw away any cached pages. */
	rc = ldlm_cli_enqueue_local(info->mti_env, mdt->mdt_namespace, &res_id,
				    LDLM_IBITS, &policy, LCK_PW, &flags,
				    ldlm_blocking_ast, old_client ?
				    ldlm_completion_ast :
				    ldlm_dom_discard_cp_ast,
				    NULL, NULL, 0, LVB_T_NONE, NULL, &dom_lh);
	if (rc != ELDLM_OK) {
		CDEBUG(D_DLMTRACE,
		       "Failed to issue discard lock, rc = %d\n", rc);
		RETURN_EXIT;
	}

	lock = ldlm_handle2lock(&dom_lh);
	lock_res_and_lock(lock);
	/* if lock is not granted then there are BL ASTs in progress and
	 * lock will be granted in result of reprocessing with CP callback
	 * notifying about that. The mdt object has to be kept until that and
	 * it is saved in l_ast_data of the lock. Lock reference is kept too
	 * until that to prevent it from canceling.
	 */
	if (!is_granted_or_cancelled_nolock(lock)) {
		mdt_object_get(info->mti_env, mo);
		lock->l_ast_data = mo;
		unlock_res_and_lock(lock);
	} else {
		unlock_res_and_lock(lock);
		ldlm_lock_decref_and_cancel(&dom_lh, LCK_PW);
	}
	LDLM_LOCK_PUT(lock);

	RETURN_EXIT;
}
