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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osp/osp_sync.c
 *
 * Lustre OST Proxy Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 * Author: Di Wang <di.wang@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "osp_internal.h"

/*
 * there are two specific states to take care about:
 *
 * = import is disconnected =
 *
 * = import is inactive =
 *   in this case osp_declare_object_create() returns an error
 *
 */

/*
 * statfs
 */
static inline int osp_statfs_need_update(struct osp_device *d)
{
	return !cfs_time_before(cfs_time_current(),
				d->opd_statfs_fresh_till);
}

static void osp_statfs_timer_cb(unsigned long _d)
{
	struct osp_device *d = (struct osp_device *) _d;

	LASSERT(d);
	wake_up(&d->opd_pre_waitq);
}

static int osp_statfs_interpret(const struct lu_env *env,
				struct ptlrpc_request *req,
				union ptlrpc_async_args *aa, int rc)
{
	struct obd_import	*imp = req->rq_import;
	struct obd_statfs	*msfs;
	struct osp_device	*d;

	ENTRY;

	aa = ptlrpc_req_async_args(req);
	d = aa->pointer_arg[0];
	LASSERT(d);

	if (rc != 0)
		GOTO(out, rc);

	msfs = req_capsule_server_get(&req->rq_pill, &RMF_OBD_STATFS);
	if (msfs == NULL)
		GOTO(out, rc = -EPROTO);

	d->opd_statfs = *msfs;

	osp_pre_update_status(d, rc);

	/* schedule next update */
	d->opd_statfs_fresh_till = cfs_time_shift(d->opd_statfs_maxage);
	cfs_timer_arm(&d->opd_statfs_timer, d->opd_statfs_fresh_till);
	d->opd_statfs_update_in_progress = 0;

	CDEBUG(D_CACHE, "updated statfs %p\n", d);

	RETURN(0);
out:
	/* couldn't update statfs, try again as soon as possible */
	wake_up(&d->opd_pre_waitq);
	if (req->rq_import_generation == imp->imp_generation)
		CDEBUG(D_CACHE, "%s: couldn't update statfs: rc = %d\n",
		       d->opd_obd->obd_name, rc);
	RETURN(rc);
}

static int osp_statfs_update(struct osp_device *d)
{
	struct ptlrpc_request	*req;
	struct obd_import	*imp;
	union ptlrpc_async_args	*aa;
	int			 rc;

	ENTRY;

	CDEBUG(D_CACHE, "going to update statfs\n");

	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_STATFS);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_STATFS);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}
	ptlrpc_request_set_replen(req);
	req->rq_request_portal = OST_CREATE_PORTAL;
	ptlrpc_at_set_req_timeout(req);

	req->rq_interpret_reply = (ptlrpc_interpterer_t)osp_statfs_interpret;
	aa = ptlrpc_req_async_args(req);
	aa->pointer_arg[0] = d;

	/*
	 * no updates till reply
	 */
	cfs_timer_disarm(&d->opd_statfs_timer);
	d->opd_statfs_fresh_till = cfs_time_shift(obd_timeout * 1000);
	d->opd_statfs_update_in_progress = 1;

	ptlrpcd_add_req(req, PDL_POLICY_ROUND, -1);

	RETURN(0);
}

/*
 * XXX: there might be a case where removed object(s) do not add free
 * space (empty object). if the number of such deletions is high, then
 * we can start to update statfs too often - a rpc storm
 * TODO: some throttling is needed
 */
void osp_statfs_need_now(struct osp_device *d)
{
	if (!d->opd_statfs_update_in_progress) {
		/*
		 * if current status is -ENOSPC (lack of free space on OST)
		 * then we should poll OST immediately once object destroy
		 * is replied
		 */
		d->opd_statfs_fresh_till = cfs_time_shift(-1);
		cfs_timer_disarm(&d->opd_statfs_timer);
		wake_up(&d->opd_pre_waitq);
	}
}


/*
 * OSP tries to maintain pool of available objects so that calls to create
 * objects don't block most of time
 *
 * each time OSP gets connected to OST, we should start from precreation cleanup
 */
static inline int osp_precreate_running(struct osp_device *d)
{
	return !!(d->opd_pre_thread.t_flags & SVC_RUNNING);
}

static inline int osp_precreate_stopped(struct osp_device *d)
{
	return !!(d->opd_pre_thread.t_flags & SVC_STOPPED);
}

static inline int osp_objs_precreated(const struct lu_env *env,
				      struct osp_device *osp)
{
	return osp_fid_diff(&osp->opd_pre_last_created_fid,
			    &osp->opd_pre_used_fid);
}

static inline int osp_precreate_near_empty_nolock(const struct lu_env *env,
						  struct osp_device *d)
{
	int window = osp_objs_precreated(env, d);

	/* don't consider new precreation till OST is healty and
	 * has free space */
	return ((window - d->opd_pre_reserved < d->opd_pre_grow_count / 2) &&
		(d->opd_pre_status == 0));
}

static inline int osp_precreate_near_empty(const struct lu_env *env,
					   struct osp_device *d)
{
	int rc;

	/* XXX: do we really need locking here? */
	spin_lock(&d->opd_pre_lock);
	rc = osp_precreate_near_empty_nolock(env, d);
	spin_unlock(&d->opd_pre_lock);
	return rc;
}

static inline int osp_create_end_seq(const struct lu_env *env,
				     struct osp_device *osp)
{
	struct lu_fid *fid = &osp->opd_pre_used_fid;
	int rc;

	spin_lock(&osp->opd_pre_lock);
	rc = osp_fid_end_seq(env, fid);
	spin_unlock(&osp->opd_pre_lock);
	return rc;
}

/**
 * Write fid into last_oid/last_seq file.
 **/
int osp_write_last_oid_seq_files(struct lu_env *env, struct osp_device *osp,
				 struct lu_fid *fid, int sync)
{
	struct osp_thread_info  *oti = osp_env_info(env);
	struct lu_buf	   *lb_oid = &oti->osi_lb;
	struct lu_buf	   *lb_oseq = &oti->osi_lb2;
	loff_t		   oid_off;
	loff_t		   oseq_off;
	struct thandle	  *th;
	int		      rc;
	ENTRY;

	/* Note: through f_oid is only 32bits, it will also write
	 * 64 bits for oid to keep compatiblity with the previous
	 * version. */
	lb_oid->lb_buf = &fid->f_oid;
	lb_oid->lb_len = sizeof(obd_id);
	oid_off = sizeof(obd_id) * osp->opd_index;

	lb_oseq->lb_buf = &fid->f_seq;
	lb_oseq->lb_len = sizeof(obd_id);
	oseq_off = sizeof(obd_id) * osp->opd_index;

	th = dt_trans_create(env, osp->opd_storage);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	th->th_sync |= sync;
	rc = dt_declare_record_write(env, osp->opd_last_used_oid_file,
				     lb_oid->lb_len, oid_off, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_declare_record_write(env, osp->opd_last_used_seq_file,
				     lb_oseq->lb_len, oseq_off, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, osp->opd_storage, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_record_write(env, osp->opd_last_used_oid_file, lb_oid,
			     &oid_off, th);
	if (rc != 0) {
		CERROR("%s: can not write to last seq file: rc = %d\n",
			osp->opd_obd->obd_name, rc);
		GOTO(out, rc);
	}
	rc = dt_record_write(env, osp->opd_last_used_seq_file, lb_oseq,
			     &oseq_off, th);
	if (rc) {
		CERROR("%s: can not write to last seq file: rc = %d\n",
			osp->opd_obd->obd_name, rc);
		GOTO(out, rc);
	}
out:
	dt_trans_stop(env, osp->opd_storage, th);
	RETURN(rc);
}

int osp_precreate_rollover_new_seq(struct lu_env *env, struct osp_device *osp)
{
	struct lu_fid	*fid = &osp_env_info(env)->osi_fid;
	struct lu_fid	*last_fid = &osp->opd_last_used_fid;
	int		rc;
	ENTRY;

	rc = seq_client_get_seq(env, osp->opd_obd->u.cli.cl_seq, &fid->f_seq);
	if (rc != 0) {
		CERROR("%s: alloc fid error: rc = %d\n",
		       osp->opd_obd->obd_name, rc);
		RETURN(rc);
	}

	fid->f_oid = 1;
	fid->f_ver = 0;
	LASSERTF(fid_seq(fid) != fid_seq(last_fid),
		 "fid "DFID", last_fid "DFID"\n", PFID(fid),
		 PFID(last_fid));

	rc = osp_write_last_oid_seq_files(env, osp, fid, 1);
	if (rc != 0) {
		CERROR("%s: Can not update oid/seq file: rc = %d\n",
		       osp->opd_obd->obd_name, rc);
		RETURN(rc);
	}

	LCONSOLE_INFO("%s: update sequence from "LPX64" to "LPX64"\n",
		      osp->opd_obd->obd_name, fid_seq(last_fid),
		      fid_seq(fid));
	/* Update last_xxx to the new seq */
	spin_lock(&osp->opd_pre_lock);
	osp->opd_last_used_fid = *fid;
	osp->opd_gap_start_fid = *fid;
	osp->opd_pre_used_fid = *fid;
	osp->opd_pre_last_created_fid = *fid;
	spin_unlock(&osp->opd_pre_lock);

	RETURN(rc);
}

/**
 * alloc fids for precreation.
 * rc = 0 Success, @grow is the count of real allocation.
 * rc = 1 Current seq is used up.
 * rc < 0 Other error.
 **/
static int osp_precreate_fids(const struct lu_env *env, struct osp_device *osp,
			      struct lu_fid *fid, int *grow)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	__u64			end;
	int			i = 0;

	if (fid_is_idif(fid)) {
		struct lu_fid	*last_fid;
		struct ost_id	*oi = &osi->osi_oi;

		spin_lock(&osp->opd_pre_lock);
		last_fid = &osp->opd_pre_last_created_fid;
		fid_to_ostid(last_fid, oi);
		end = min(ostid_id(oi) + *grow, IDIF_MAX_OID);
		*grow = end - ostid_id(oi);
		ostid_set_id(oi, ostid_id(oi) + *grow);
		spin_unlock(&osp->opd_pre_lock);

		if (*grow == 0)
			return 1;

		ostid_to_fid(fid, oi, osp->opd_index);
		return 0;
	}

	spin_lock(&osp->opd_pre_lock);
	*fid = osp->opd_pre_last_created_fid;
	end = fid->f_oid;
	end = min((end + *grow), (__u64)LUSTRE_DATA_SEQ_MAX_WIDTH);
	*grow = end - fid->f_oid;
	fid->f_oid += end - fid->f_oid;
	spin_unlock(&osp->opd_pre_lock);

	CDEBUG(D_INFO, "Expect %d, actual %d ["DFID" -- "DFID"]\n",
	       *grow, i, PFID(fid), PFID(&osp->opd_pre_last_created_fid));

	return *grow > 0 ? 0 : 1;
}

static int osp_precreate_send(const struct lu_env *env, struct osp_device *d)
{
	struct osp_thread_info	*oti = osp_env_info(env);
	struct ptlrpc_request	*req;
	struct obd_import	*imp;
	struct ost_body		*body;
	int			 rc, grow, diff;
	struct lu_fid		*fid = &oti->osi_fid;
	ENTRY;

	/* don't precreate new objects till OST healthy and has free space */
	if (unlikely(d->opd_pre_status)) {
		CDEBUG(D_INFO, "%s: don't send new precreate: rc = %d\n",
		       d->opd_obd->obd_name, d->opd_pre_status);
		RETURN(0);
	}

	/*
	 * if not connection/initialization is compeleted, ignore
	 */
	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_CREATE);
	if (req == NULL)
		RETURN(-ENOMEM);
	req->rq_request_portal = OST_CREATE_PORTAL;
	/* we should not resend create request - anyway we will have delorphan
	 * and kill these objects */
	req->rq_no_delay = req->rq_no_resend = 1;

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_CREATE);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	spin_lock(&d->opd_pre_lock);
	if (d->opd_pre_grow_count > d->opd_pre_max_grow_count / 2)
		d->opd_pre_grow_count = d->opd_pre_max_grow_count / 2;
	grow = d->opd_pre_grow_count;
	spin_unlock(&d->opd_pre_lock);

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);

	*fid = d->opd_pre_last_created_fid;
	rc = osp_precreate_fids(env, d, fid, &grow);
	if (rc == 1) {
		/* Current seq has been used up*/
		if (!osp_is_fid_client(d)) {
			osp_pre_update_status(d, -ENOSPC);
			rc = -ENOSPC;
		}
		wake_up(&d->opd_pre_waitq);
		GOTO(out_req, rc);
	}

	if (!osp_is_fid_client(d)) {
		/* Non-FID client will always send seq 0 because of
		 * compatiblity */
		LASSERTF(fid_is_idif(fid), "Invalid fid "DFID"\n", PFID(fid));
		fid->f_seq = 0;
	}

	fid_to_ostid(fid, &body->oa.o_oi);
	body->oa.o_valid = OBD_MD_FLGROUP;

	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc) {
		CERROR("%s: can't precreate: rc = %d\n", d->opd_obd->obd_name,
		       rc);
		GOTO(out_req, rc);
	}
	LASSERT(req->rq_transno == 0);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out_req, rc = -EPROTO);

	ostid_to_fid(fid, &body->oa.o_oi, d->opd_index);
	LASSERTF(osp_fid_diff(fid, &d->opd_pre_used_fid) > 0,
		 "reply fid "DFID" pre used fid "DFID"\n", PFID(fid),
		 PFID(&d->opd_pre_used_fid));

	diff = osp_fid_diff(fid, &d->opd_pre_last_created_fid);

	spin_lock(&d->opd_pre_lock);
	if (diff < grow) {
		/* the OST has not managed to create all the
		 * objects we asked for */
		d->opd_pre_grow_count = max(diff, OST_MIN_PRECREATE);
		d->opd_pre_grow_slow = 1;
	} else {
		/* the OST is able to keep up with the work,
		 * we could consider increasing grow_count
		 * next time if needed */
		d->opd_pre_grow_slow = 0;
	}

	d->opd_pre_last_created_fid = *fid;
	spin_unlock(&d->opd_pre_lock);

	CDEBUG(D_HA, "%s: current precreated pool: "DFID"-"DFID"\n",
	       d->opd_obd->obd_name, PFID(&d->opd_pre_used_fid),
	       PFID(&d->opd_pre_last_created_fid));
out_req:
	/* now we can wakeup all users awaiting for objects */
	osp_pre_update_status(d, rc);
	wake_up(&d->opd_pre_user_waitq);

	ptlrpc_req_finished(req);
	RETURN(rc);
}

static int osp_get_lastfid_from_ost(const struct lu_env *env,
				    struct osp_device *d)
{
	struct ptlrpc_request	*req = NULL;
	struct obd_import	*imp;
	struct lu_fid		*last_fid;
	char			*tmp;
	int			rc;
	ENTRY;

	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_GET_INFO_LAST_FID);
	if (req == NULL)
		RETURN(-ENOMEM);

	req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_KEY, RCL_CLIENT,
			     sizeof(KEY_LAST_FID));

	req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_VAL, RCL_CLIENT,
			     sizeof(struct lu_fid));

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GET_INFO);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_KEY);
	memcpy(tmp, KEY_LAST_FID, sizeof(KEY_LAST_FID));

	req->rq_no_delay = req->rq_no_resend = 1;
	tmp = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_VAL);
	fid_cpu_to_le((struct lu_fid *)tmp, &d->opd_last_used_fid);
	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc) {
		/* bad-bad OST.. let sysadm sort this out */
		if (rc == -ENOTSUPP) {
			CERROR("%s: server does not support FID: rc = %d\n",
			       d->opd_obd->obd_name, -ENOTSUPP);
		}
		ptlrpc_set_import_active(imp, 0);
		GOTO(out, rc);
	}

	last_fid = req_capsule_server_get(&req->rq_pill, &RMF_FID);
	if (last_fid == NULL) {
		CERROR("%s: Got last_fid failed.\n", d->opd_obd->obd_name);
		GOTO(out, rc = -EPROTO);
	}

	if (!fid_is_sane(last_fid)) {
		CERROR("%s: Got insane last_fid "DFID"\n",
		       d->opd_obd->obd_name, PFID(last_fid));
		GOTO(out, rc = -EPROTO);
	}

	/* Only update the last used fid, if the OST has objects for
	 * this sequence, i.e. fid_oid > 0 */
	if (fid_oid(last_fid) > 0)
		d->opd_last_used_fid = *last_fid;

	CDEBUG(D_HA, "%s: Got last_fid "DFID"\n", d->opd_obd->obd_name,
	       PFID(last_fid));

out:
	ptlrpc_req_finished(req);
	RETURN(rc);
}

/**
 * asks OST to clean precreate orphans
 * and gets next id for new objects
 */
static int osp_precreate_cleanup_orphans(struct lu_env *env,
					 struct osp_device *d)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct lu_fid		*last_fid = &osi->osi_fid;
	struct ptlrpc_request	*req = NULL;
	struct obd_import	*imp;
	struct ost_body		*body;
	struct l_wait_info	 lwi = { 0 };
	int			 update_status = 0;
	int			 rc;
	int			 diff;

	ENTRY;

	/*
	 * wait for local recovery to finish, so we can cleanup orphans
	 * orphans are all objects since "last used" (assigned), but
	 * there might be objects reserved and in some cases they won't
	 * be used. we can't cleanup them till we're sure they won't be
	 * used. also can't we allow new reservations because they may
	 * end up getting orphans being cleaned up below. so we block
	 * new reservations and wait till all reserved objects either
	 * user or released.
	 */
	spin_lock(&d->opd_pre_lock);
	d->opd_pre_recovering = 1;
	spin_unlock(&d->opd_pre_lock);
	/*
	 * The locking above makes sure the opd_pre_reserved check below will
	 * catch all osp_precreate_reserve() calls who find
	 * "!opd_pre_recovering".
	 */
	l_wait_event(d->opd_pre_waitq,
		     (!d->opd_pre_reserved && d->opd_recovery_completed) ||
		     !osp_precreate_running(d) || d->opd_got_disconnected,
		     &lwi);
	if (!osp_precreate_running(d) || d->opd_got_disconnected)
		GOTO(out, rc = -EAGAIN);

	CDEBUG(D_HA, "%s: going to cleanup orphans since "DFID"\n",
	       d->opd_obd->obd_name, PFID(&d->opd_last_used_fid));

	*last_fid = d->opd_last_used_fid;
	/* The OSP should already get the valid seq now */
	LASSERT(!fid_is_zero(last_fid));
	if (fid_oid(&d->opd_last_used_fid) < 2) {
		/* lastfid looks strange... ask OST */
		rc = osp_get_lastfid_from_ost(env, d);
		if (rc)
			GOTO(out, rc);
	}

	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_CREATE);
	if (req == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_CREATE);
	if (rc) {
		ptlrpc_request_free(req);
		req = NULL;
		GOTO(out, rc);
	}

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	body->oa.o_flags = OBD_FL_DELORPHAN;
	body->oa.o_valid = OBD_MD_FLFLAGS | OBD_MD_FLGROUP;

	fid_to_ostid(&d->opd_last_used_fid, &body->oa.o_oi);

	ptlrpc_request_set_replen(req);

	/* Don't resend the delorphan req */
	req->rq_no_resend = req->rq_no_delay = 1;

	rc = ptlrpc_queue_wait(req);
	if (rc) {
		update_status = 1;
		GOTO(out, rc);
	}

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	/*
	 * OST provides us with id new pool starts from in body->oa.o_id
	 */
	ostid_to_fid(last_fid, &body->oa.o_oi, d->opd_index);

	spin_lock(&d->opd_pre_lock);
	diff = osp_fid_diff(&d->opd_last_used_fid, last_fid);
	if (diff > 0) {
		d->opd_pre_grow_count = OST_MIN_PRECREATE + diff;
		d->opd_pre_last_created_fid = d->opd_last_used_fid;
	} else {
		d->opd_pre_grow_count = OST_MIN_PRECREATE;
		d->opd_pre_last_created_fid = *last_fid;
	}
	/*
	 * This empties the pre-creation pool and effectively blocks any new
	 * reservations.
	 */
	LASSERT(fid_oid(&d->opd_pre_last_created_fid) <=
		LUSTRE_DATA_SEQ_MAX_WIDTH);
	d->opd_pre_used_fid = d->opd_pre_last_created_fid;
	d->opd_pre_grow_slow = 0;
	spin_unlock(&d->opd_pre_lock);

	CDEBUG(D_HA, "%s: Got last_id "DFID" from OST, last_created "DFID
	       "last_used is "DFID"\n", d->opd_obd->obd_name, PFID(last_fid),
	       PFID(&d->opd_pre_last_created_fid), PFID(&d->opd_last_used_fid));
out:
	if (req)
		ptlrpc_req_finished(req);

	spin_lock(&d->opd_pre_lock);
	d->opd_pre_recovering = 0;
	spin_unlock(&d->opd_pre_lock);

	/*
	 * If rc is zero, the pre-creation window should have been emptied.
	 * Since waking up the herd would be useless without pre-created
	 * objects, we defer the signal to osp_precreate_send() in that case.
	 */
	if (rc != 0) {
		if (update_status) {
			CERROR("%s: cannot cleanup orphans: rc = %d\n",
			       d->opd_obd->obd_name, rc);
			/* we can't proceed from here, OST seem to
			 * be in a bad shape, better to wait for
			 * a new instance of the server and repeat
			 * from the beginning. notify possible waiters
			 * this OSP isn't quite functional yet */
			osp_pre_update_status(d, rc);
		} else {
			wake_up(&d->opd_pre_user_waitq);
		}
	}

	RETURN(rc);
}

/*
 * the function updates current precreation status used: functional or not
 *
 * rc is a last code from the transport, rc == 0 meaning transport works
 * well and users of lod can use objects from this OSP
 *
 * the status depends on current usage of OST
 */
void osp_pre_update_status(struct osp_device *d, int rc)
{
	struct obd_statfs	*msfs = &d->opd_statfs;
	int			 old = d->opd_pre_status;
	__u64			 used;

	d->opd_pre_status = rc;
	if (rc)
		goto out;

	/* Add a bit of hysteresis so this flag isn't continually flapping,
	 * and ensure that new files don't get extremely fragmented due to
	 * only a small amount of available space in the filesystem.
	 * We want to set the NOSPC flag when there is less than ~0.1% free
	 * and clear it when there is at least ~0.2% free space, so:
	 *                   avail < ~0.1% max          max = avail + used
	 *            1025 * avail < avail + used       used = blocks - free
	 *            1024 * avail < used
	 *            1024 * avail < blocks - free
	 *                   avail < ((blocks - free) >> 10)
	 *
	 * On very large disk, say 16TB 0.1% will be 16 GB. We don't want to
	 * lose that amount of space so in those cases we report no space left
	 * if their is less than 1 GB left.                             */
	if (likely(msfs->os_type)) {
		used = min_t(__u64, (msfs->os_blocks - msfs->os_bfree) >> 10,
				    1 << 30);
		if ((msfs->os_ffree < 32) || (msfs->os_bavail < used)) {
			d->opd_pre_status = -ENOSPC;
			if (old != -ENOSPC)
				CDEBUG(D_INFO, "%s: status: "LPU64" blocks, "
				       LPU64" free, "LPU64" used, "LPU64" "
				       "avail -> %d: rc = %d\n",
				       d->opd_obd->obd_name, msfs->os_blocks,
				       msfs->os_bfree, used, msfs->os_bavail,
				       d->opd_pre_status, rc);
			CDEBUG(D_INFO,
			       "non-commited changes: %lu, in progress: %u\n",
			       d->opd_syn_changes, d->opd_syn_rpc_in_progress);
		} else if (old == -ENOSPC) {
			d->opd_pre_status = 0;
			spin_lock(&d->opd_pre_lock);
			d->opd_pre_grow_slow = 0;
			d->opd_pre_grow_count = OST_MIN_PRECREATE;
			spin_unlock(&d->opd_pre_lock);
			wake_up(&d->opd_pre_waitq);
			CDEBUG(D_INFO, "%s: no space: "LPU64" blocks, "LPU64
			       " free, "LPU64" used, "LPU64" avail -> %d: "
			       "rc = %d\n", d->opd_obd->obd_name,
			       msfs->os_blocks, msfs->os_bfree, used,
			       msfs->os_bavail, d->opd_pre_status, rc);
		}
	}

out:
	wake_up(&d->opd_pre_user_waitq);
}

static int osp_init_pre_fid(struct osp_device *osp)
{
	struct lu_env		env;
	struct osp_thread_info	*osi;
	struct lu_client_seq	*cli_seq;
	struct lu_fid		*last_fid;
	int			rc;
	ENTRY;

	/* Return if last_used fid has been initialized */
	if (!fid_is_zero(&osp->opd_last_used_fid))
		RETURN(0);

	rc = lu_env_init(&env, osp->opd_dt_dev.dd_lu_dev.ld_type->ldt_ctx_tags);
	if (rc) {
		CERROR("%s: init env error: rc = %d\n",
		       osp->opd_obd->obd_name, rc);
		RETURN(rc);
	}

	osi = osp_env_info(&env);
	last_fid = &osi->osi_fid;
	fid_zero(last_fid);
	/* For a freshed fs, it will allocate a new sequence first */
	if (osp_is_fid_client(osp) && osp->opd_group != 0) {
		cli_seq = osp->opd_obd->u.cli.cl_seq;
		rc = seq_client_get_seq(&env, cli_seq, &last_fid->f_seq);
		if (rc != 0) {
			CERROR("%s: alloc fid error: rc = %d\n",
			       osp->opd_obd->obd_name, rc);
			GOTO(out, rc);
		}
	} else {
		last_fid->f_seq = fid_idif_seq(0, osp->opd_index);
	}
	last_fid->f_oid = 1;
	last_fid->f_ver = 0;

	spin_lock(&osp->opd_pre_lock);
	osp->opd_last_used_fid = *last_fid;
	osp->opd_pre_used_fid = *last_fid;
	osp->opd_pre_last_created_fid = *last_fid;
	spin_unlock(&osp->opd_pre_lock);
	rc = osp_write_last_oid_seq_files(&env, osp, last_fid, 1);
	if (rc != 0) {
		CERROR("%s: write fid error: rc = %d\n",
		       osp->opd_obd->obd_name, rc);
		GOTO(out, rc);
	}
out:
	lu_env_fini(&env);
	RETURN(rc);
}

static int osp_precreate_thread(void *_arg)
{
	struct osp_device	*d = _arg;
	struct ptlrpc_thread	*thread = &d->opd_pre_thread;
	struct l_wait_info	 lwi = { 0 };
	struct lu_env		 env;
	int			 rc;

	ENTRY;

	rc = lu_env_init(&env, d->opd_dt_dev.dd_lu_dev.ld_type->ldt_ctx_tags);
	if (rc) {
		CERROR("%s: init env error: rc = %d\n", d->opd_obd->obd_name,
		       rc);
		RETURN(rc);
	}

	spin_lock(&d->opd_pre_lock);
	thread->t_flags = SVC_RUNNING;
	spin_unlock(&d->opd_pre_lock);
	wake_up(&thread->t_ctl_waitq);

	while (osp_precreate_running(d)) {
		/*
		 * need to be connected to OST
		 */
		while (osp_precreate_running(d)) {
			l_wait_event(d->opd_pre_waitq,
				     !osp_precreate_running(d) ||
				     d->opd_new_connection,
				     &lwi);

			if (!d->opd_new_connection)
				continue;

			d->opd_new_connection = 0;
			d->opd_got_disconnected = 0;
			break;
		}

		if (!osp_precreate_running(d))
			break;

		LASSERT(d->opd_obd->u.cli.cl_seq != NULL);
		/* Sigh, fid client is not ready yet */
		if (d->opd_obd->u.cli.cl_seq->lcs_exp == NULL)
			continue;

		/* Init fid for osp_precreate if necessary */
		rc = osp_init_pre_fid(d);
		if (rc != 0) {
			class_export_put(d->opd_exp);
			d->opd_obd->u.cli.cl_seq->lcs_exp = NULL;
			CERROR("%s: init pre fid error: rc = %d\n",
			       d->opd_obd->obd_name, rc);
			continue;
		}

		osp_statfs_update(d);

		/*
		 * Clean up orphans or recreate missing objects.
		 */
		rc = osp_precreate_cleanup_orphans(&env, d);
		if (rc != 0)
			continue;
		/*
		 * connected, can handle precreates now
		 */
		while (osp_precreate_running(d)) {
			l_wait_event(d->opd_pre_waitq,
				     !osp_precreate_running(d) ||
				     osp_precreate_near_empty(&env, d) ||
				     osp_statfs_need_update(d) ||
				     d->opd_got_disconnected, &lwi);

			if (!osp_precreate_running(d))
				break;

			/* something happened to the connection
			 * have to start from the beginning */
			if (d->opd_got_disconnected)
				break;

			if (osp_statfs_need_update(d))
				osp_statfs_update(d);

			/* To avoid handling different seq in precreate/orphan
			 * cleanup, it will hold precreate until current seq is
			 * used up. */
			if (unlikely(osp_precreate_end_seq(&env, d) &&
			    !osp_create_end_seq(&env, d)))
				continue;

			if (unlikely(osp_precreate_end_seq(&env, d) &&
				     osp_create_end_seq(&env, d))) {
				LCONSOLE_INFO("%s:"LPX64" is used up."
					      " Update to new seq\n",
					      d->opd_obd->obd_name,
					 fid_seq(&d->opd_pre_last_created_fid));
				rc = osp_precreate_rollover_new_seq(&env, d);
				if (rc)
					continue;
			}

			if (osp_precreate_near_empty(&env, d)) {
				rc = osp_precreate_send(&env, d);
				/* osp_precreate_send() sets opd_pre_status
				 * in case of error, that prevent the using of
				 * failed device. */
				if (rc < 0 && rc != -ENOSPC &&
				    rc != -ETIMEDOUT && rc != -ENOTCONN)
					CERROR("%s: cannot precreate objects:"
					       " rc = %d\n",
					       d->opd_obd->obd_name, rc);
			}
		}
	}

	thread->t_flags = SVC_STOPPED;
	lu_env_fini(&env);
	wake_up(&thread->t_ctl_waitq);

	RETURN(0);
}

static int osp_precreate_ready_condition(const struct lu_env *env,
					 struct osp_device *d)
{
	if (d->opd_pre_recovering)
		return 0;

	/* ready if got enough precreated objects */
	/* we need to wait for others (opd_pre_reserved) and our object (+1) */
	if (d->opd_pre_reserved + 1 < osp_objs_precreated(env, d))
		return 1;

	/* ready if OST reported no space and no destroys in progress */
	if (d->opd_syn_changes + d->opd_syn_rpc_in_progress == 0 &&
	    d->opd_pre_status == -ENOSPC)
		return 1;

	/* Bail out I/O fails to OST */
	if (d->opd_pre_status != 0 &&
	    d->opd_pre_status != -EAGAIN &&
	    d->opd_pre_status != -ENODEV &&
	    d->opd_pre_status != -ENOSPC) {
		/* DEBUG LU-3230 */
		if (d->opd_pre_status != -EIO)
			CERROR("%s: precreate failed opd_pre_status %d\n",
			       d->opd_obd->obd_name, d->opd_pre_status);
		return 1;
	}

	return 0;
}

static int osp_precreate_timeout_condition(void *data)
{
	struct osp_device *d = data;

	LCONSOLE_WARN("%s: slow creates, last="DFID", next="DFID", "
		      "reserved="LPU64", syn_changes=%lu, "
		      "syn_rpc_in_progress=%d, status=%d\n",
		      d->opd_obd->obd_name, PFID(&d->opd_pre_last_created_fid),
		      PFID(&d->opd_pre_used_fid), d->opd_pre_reserved,
		      d->opd_syn_changes, d->opd_syn_rpc_in_progress,
		      d->opd_pre_status);

	return 1;
}

/*
 * called to reserve object in the pool
 * return codes:
 *  ENOSPC - no space on corresponded OST
 *  EAGAIN - precreation is in progress, try later
 *  EIO    - no access to OST
 */
int osp_precreate_reserve(const struct lu_env *env, struct osp_device *d)
{
	struct l_wait_info	 lwi;
	cfs_time_t		 expire = cfs_time_shift(obd_timeout);
	int			 precreated, rc;

	ENTRY;

	LASSERTF(osp_objs_precreated(env, d) >= 0, "Last created FID "DFID
		 "Next FID "DFID"\n", PFID(&d->opd_pre_last_created_fid),
		 PFID(&d->opd_pre_used_fid));

	/*
	 * wait till:
	 *  - preallocation is done
	 *  - no free space expected soon
	 *  - can't connect to OST for too long (obd_timeout)
	 *  - OST can allocate fid sequence.
	 */
	while ((rc = d->opd_pre_status) == 0 || rc == -ENOSPC ||
		rc == -ENODEV || rc == -EAGAIN || rc == -ENOTCONN) {

		/*
		 * increase number of precreations
		 */
		precreated = osp_objs_precreated(env, d);
		if (d->opd_pre_grow_count < d->opd_pre_max_grow_count &&
		    d->opd_pre_grow_slow == 0 &&
		    precreated <= (d->opd_pre_grow_count / 4 + 1)) {
			spin_lock(&d->opd_pre_lock);
			d->opd_pre_grow_slow = 1;
			d->opd_pre_grow_count *= 2;
			spin_unlock(&d->opd_pre_lock);
		}

		spin_lock(&d->opd_pre_lock);
		precreated = osp_objs_precreated(env, d);
		if (precreated > d->opd_pre_reserved &&
		    !d->opd_pre_recovering) {
			d->opd_pre_reserved++;
			spin_unlock(&d->opd_pre_lock);
			rc = 0;

			/* XXX: don't wake up if precreation is in progress */
			if (osp_precreate_near_empty_nolock(env, d) &&
			   !osp_precreate_end_seq_nolock(env, d))
				wake_up(&d->opd_pre_waitq);

			break;
		}
		spin_unlock(&d->opd_pre_lock);

		/*
		 * all precreated objects have been used and no-space
		 * status leave us no chance to succeed very soon
		 * but if there is destroy in progress, then we should
		 * wait till that is done - some space might be released
		 */
		if (unlikely(rc == -ENOSPC)) {
			if (d->opd_syn_changes) {
				/* force local commit to release space */
				dt_commit_async(env, d->opd_storage);
			}
			if (d->opd_syn_rpc_in_progress) {
				/* just wait till destroys are done */
				/* see l_wait_even() few lines below */
			}
			if (d->opd_syn_changes +
			    d->opd_syn_rpc_in_progress == 0) {
				/* no hope for free space */
				break;
			}
		}

		/* XXX: don't wake up if precreation is in progress */
		wake_up(&d->opd_pre_waitq);

		lwi = LWI_TIMEOUT(expire - cfs_time_current(),
				osp_precreate_timeout_condition, d);
		if (cfs_time_aftereq(cfs_time_current(), expire)) {
			rc = -ETIMEDOUT;
			break;
		}

		l_wait_event(d->opd_pre_user_waitq,
			     osp_precreate_ready_condition(env, d), &lwi);
	}

	RETURN(rc);
}

/*
 * this function relies on reservation made before
 */
int osp_precreate_get_fid(const struct lu_env *env, struct osp_device *d,
			  struct lu_fid *fid)
{
	/* grab next id from the pool */
	spin_lock(&d->opd_pre_lock);

	LASSERTF(osp_fid_diff(&d->opd_pre_used_fid,
			     &d->opd_pre_last_created_fid) < 0,
		 "next fid "DFID" last created fid "DFID"\n",
		 PFID(&d->opd_pre_used_fid),
		 PFID(&d->opd_pre_last_created_fid));

	d->opd_pre_used_fid.f_oid++;
	memcpy(fid, &d->opd_pre_used_fid, sizeof(*fid));
	d->opd_pre_reserved--;
	/*
	 * last_used_id must be changed along with getting new id otherwise
	 * we might miscalculate gap causing object loss or leak
	 */
	osp_update_last_fid(d, fid);
	spin_unlock(&d->opd_pre_lock);

	/*
	 * probably main thread suspended orphan cleanup till
	 * all reservations are released, see comment in
	 * osp_precreate_thread() just before orphan cleanup
	 */
	if (unlikely(d->opd_pre_reserved == 0 && d->opd_pre_status))
		wake_up(&d->opd_pre_waitq);

	return 0;
}

/*
 *
 */
int osp_object_truncate(const struct lu_env *env, struct dt_object *dt,
			__u64 size)
{
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct ptlrpc_request	*req = NULL;
	struct obd_import	*imp;
	struct ost_body		*body;
	struct obdo		*oa = NULL;
	int			 rc;

	ENTRY;

	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_PUNCH);
	if (req == NULL)
		RETURN(-ENOMEM);

	/* XXX: capa support? */
	/* osc_set_capa_size(req, &RMF_CAPA1, capa); */
	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_PUNCH);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	/*
	 * XXX: decide how do we do here with resend
	 * if we don't resend, then client may see wrong file size
	 * if we do resend, then MDS thread can get stuck for quite long
	 */
	req->rq_no_resend = req->rq_no_delay = 1;

	req->rq_request_portal = OST_IO_PORTAL; /* bug 7198 */
	ptlrpc_at_set_req_timeout(req);

	OBD_ALLOC_PTR(oa);
	if (oa == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = fid_to_ostid(lu_object_fid(&dt->do_lu), &oa->o_oi);
	LASSERT(rc == 0);
	oa->o_size = size;
	oa->o_blocks = OBD_OBJECT_EOF;
	oa->o_valid = OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
		      OBD_MD_FLID | OBD_MD_FLGROUP;

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);
	lustre_set_wire_obdo(&req->rq_import->imp_connect_data, &body->oa, oa);

	/* XXX: capa support? */
	/* osc_pack_capa(req, body, capa); */

	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc)
		CERROR("can't punch object: %d\n", rc);
out:
	ptlrpc_req_finished(req);
	if (oa)
		OBD_FREE_PTR(oa);
	RETURN(rc);
}

int osp_init_precreate(struct osp_device *d)
{
	struct l_wait_info	 lwi = { 0 };
	struct task_struct		*task;

	ENTRY;

	/* initially precreation isn't ready */
	d->opd_pre_status = -EAGAIN;
	fid_zero(&d->opd_pre_used_fid);
	d->opd_pre_used_fid.f_oid = 1;
	fid_zero(&d->opd_pre_last_created_fid);
	d->opd_pre_last_created_fid.f_oid = 1;
	d->opd_pre_reserved = 0;
	d->opd_got_disconnected = 1;
	d->opd_pre_grow_slow = 0;
	d->opd_pre_grow_count = OST_MIN_PRECREATE;
	d->opd_pre_min_grow_count = OST_MIN_PRECREATE;
	d->opd_pre_max_grow_count = OST_MAX_PRECREATE;

	spin_lock_init(&d->opd_pre_lock);
	init_waitqueue_head(&d->opd_pre_waitq);
	init_waitqueue_head(&d->opd_pre_user_waitq);
	init_waitqueue_head(&d->opd_pre_thread.t_ctl_waitq);

	/*
	 * Initialize statfs-related things
	 */
	d->opd_statfs_maxage = 5; /* default update interval */
	d->opd_statfs_fresh_till = cfs_time_shift(-1000);
	CDEBUG(D_OTHER, "current %llu, fresh till %llu\n",
	       (unsigned long long)cfs_time_current(),
	       (unsigned long long)d->opd_statfs_fresh_till);
	cfs_timer_init(&d->opd_statfs_timer, osp_statfs_timer_cb, d);

	/*
	 * start thread handling precreation and statfs updates
	 */
	task = kthread_run(osp_precreate_thread, d,
			       "osp-pre-%u", d->opd_index);
	if (IS_ERR(task)) {
		CERROR("can't start precreate thread %ld\n", PTR_ERR(task));
		RETURN(PTR_ERR(task));
	}

	l_wait_event(d->opd_pre_thread.t_ctl_waitq,
		     osp_precreate_running(d) || osp_precreate_stopped(d),
		     &lwi);

	RETURN(0);
}

void osp_precreate_fini(struct osp_device *d)
{
	struct ptlrpc_thread *thread = &d->opd_pre_thread;

	ENTRY;

	cfs_timer_disarm(&d->opd_statfs_timer);

	thread->t_flags = SVC_STOPPING;
	wake_up(&d->opd_pre_waitq);

	wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_STOPPED);

	EXIT;
}

