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
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <lustre_log.h>
#include "osp_internal.h"

static int osp_sync_id_traction_init(struct osp_device *d);
static void osp_sync_id_traction_fini(struct osp_device *d);
static __u32 osp_sync_id_get(struct osp_device *d, __u32 id);
static void osp_sync_remove_from_tracker(struct osp_device *d);

/*
 * this is a components of OSP implementing synchronization between MDS and OST
 * it llogs all interesting changes (currently it's uig/gid change and object
 * destroy) atomically, then makes sure changes hit OST storage
 *
 * we have 4 queues of work:
 *
 * the first queue is llog itself, once read a change is stored in 2nd queue
 * in form of RPC (but RPC isn't fired yet).
 *
 * the second queue (opd_syn_waiting_for_commit) holds changes awaiting local
 * commit. once change is committed locally it migrates onto 3rd queue.
 *
 * the third queue (opd_syn_committed_here) holds changes committed locally,
 * but not sent to OST (as the pipe can be full). once pipe becomes non-full
 * we take a change from the queue and fire corresponded RPC.
 *
 * once RPC is reported committed by OST (using regular last_committed mech.)
 * the change jumps into 4th queue (opd_syn_committed_there), now we can
 * cancel corresponded llog record and release RPC
 *
 * opd_syn_changes is a number of unread llog records (to be processed).
 * notice this number doesn't include llog records from previous boots.
 * with OSP_SYN_THRESHOLD we try to batch processing a bit (TO BE IMPLEMENTED)
 *
 * opd_syn_rpc_in_progress is a number of requests in 2-4 queues.
 * we control this with OSP_MAX_IN_PROGRESS so that OSP don't consume
 * too much memory -- how to deal with 1000th OSTs ? batching could help?
 *
 * opd_syn_rpc_in_flight is a number of RPC in flight.
 * we control this with OSP_MAX_IN_FLIGHT
 */

/* XXX: do math to learn reasonable threshold
 * should it be ~ number of changes fitting bulk? */

#define OSP_SYN_THRESHOLD	10
#define OSP_MAX_IN_FLIGHT	8
#define OSP_MAX_IN_PROGRESS	4096

#define OSP_JOB_MAGIC		0x26112005

static inline int osp_sync_running(struct osp_device *d)
{
	return !!(d->opd_syn_thread.t_flags & SVC_RUNNING);
}

static inline int osp_sync_stopped(struct osp_device *d)
{
	return !!(d->opd_syn_thread.t_flags & SVC_STOPPED);
}

static inline int osp_sync_has_new_job(struct osp_device *d)
{
	return ((d->opd_syn_last_processed_id < d->opd_syn_last_used_id) &&
		(d->opd_syn_last_processed_id < d->opd_syn_last_committed_id))
		|| (d->opd_syn_prev_done == 0);
}

static inline int osp_sync_low_in_progress(struct osp_device *d)
{
	return d->opd_syn_rpc_in_progress < d->opd_syn_max_rpc_in_progress;
}

static inline int osp_sync_low_in_flight(struct osp_device *d)
{
	return d->opd_syn_rpc_in_flight < d->opd_syn_max_rpc_in_flight;
}

static inline int osp_sync_has_work(struct osp_device *d)
{
	/* has new/old changes and low in-progress? */
	if (osp_sync_has_new_job(d) && osp_sync_low_in_progress(d) &&
	    osp_sync_low_in_flight(d) && d->opd_imp_connected)
		return 1;

	/* has remotely committed? */
	if (!cfs_list_empty(&d->opd_syn_committed_there))
		return 1;

	return 0;
}

#define osp_sync_check_for_work(d)                      \
{                                                       \
	if (osp_sync_has_work(d)) {                     \
		wake_up(&d->opd_syn_waitq);    \
	}                                               \
}

void __osp_sync_check_for_work(struct osp_device *d)
{
	osp_sync_check_for_work(d);
}

static inline int osp_sync_can_process_new(struct osp_device *d,
					   struct llog_rec_hdr *rec)
{
	LASSERT(d);

	if (!osp_sync_low_in_progress(d))
		return 0;
	if (!osp_sync_low_in_flight(d))
		return 0;
	if (!d->opd_imp_connected)
		return 0;
	if (d->opd_syn_prev_done == 0)
		return 1;
	if (d->opd_syn_changes == 0)
		return 0;
	if (rec == NULL || rec->lrh_id <= d->opd_syn_last_committed_id)
		return 1;
	return 0;
}

int osp_sync_declare_add(const struct lu_env *env, struct osp_object *o,
			 llog_op_type type, struct thandle *th)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct osp_device	*d = lu2osp_dev(o->opo_obj.do_lu.lo_dev);
	struct llog_ctxt	*ctxt;
	int			 rc;

	ENTRY;

	/* it's a layering violation, to access internals of th,
	 * but we can do this as a sanity check, for a while */
	LASSERT(th->th_dev == d->opd_storage);

	switch (type) {
	case MDS_UNLINK64_REC:
		osi->osi_hdr.lrh_len = sizeof(struct llog_unlink64_rec);
		break;
	case MDS_SETATTR64_REC:
		osi->osi_hdr.lrh_len = sizeof(struct llog_setattr64_rec);
		break;
	default:
		LBUG();
	}

	/* we want ->dt_trans_start() to allocate per-thandle structure */
	th->th_tags |= LCT_OSP_THREAD;

	ctxt = llog_get_context(d->opd_obd, LLOG_MDS_OST_ORIG_CTXT);
	LASSERT(ctxt);

	rc = llog_declare_add(env, ctxt->loc_handle, &osi->osi_hdr, th);
	llog_ctxt_put(ctxt);

	RETURN(rc);
}

static int osp_sync_add_rec(const struct lu_env *env, struct osp_device *d,
			    const struct lu_fid *fid, llog_op_type type,
			    int count, struct thandle *th,
			    const struct lu_attr *attr)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct llog_ctxt	*ctxt;
	struct osp_txn_info	*txn;
	int			 rc;

	ENTRY;

	/* it's a layering violation, to access internals of th,
	 * but we can do this as a sanity check, for a while */
	LASSERT(th->th_dev == d->opd_storage);

	switch (type) {
	case MDS_UNLINK64_REC:
		osi->osi_hdr.lrh_len = sizeof(osi->osi_unlink);
		osi->osi_hdr.lrh_type = MDS_UNLINK64_REC;
		osi->osi_unlink.lur_fid  = *fid;
		osi->osi_unlink.lur_count = count;
		break;
	case MDS_SETATTR64_REC:
		rc = fid_to_ostid(fid, &osi->osi_oi);
		LASSERT(rc == 0);
		osi->osi_hdr.lrh_len = sizeof(osi->osi_setattr);
		osi->osi_hdr.lrh_type = MDS_SETATTR64_REC;
		osi->osi_setattr.lsr_oi  = osi->osi_oi;
		LASSERT(attr);
		osi->osi_setattr.lsr_uid = attr->la_uid;
		osi->osi_setattr.lsr_gid = attr->la_gid;
		break;
	default:
		LBUG();
	}

	txn = osp_txn_info(&th->th_ctx);
	LASSERT(txn);

	txn->oti_current_id = osp_sync_id_get(d, txn->oti_current_id);
	osi->osi_hdr.lrh_id = txn->oti_current_id;

	ctxt = llog_get_context(d->opd_obd, LLOG_MDS_OST_ORIG_CTXT);
	if (ctxt == NULL)
		RETURN(-ENOMEM);
	rc = llog_add(env, ctxt->loc_handle, &osi->osi_hdr, &osi->osi_cookie,
		      NULL, th);
	llog_ctxt_put(ctxt);

	CDEBUG(D_OTHER, "%s: new record "DOSTID":%lu/%lu: %d\n",
	       d->opd_obd->obd_name, POSTID(&osi->osi_cookie.lgc_lgl.lgl_oi),
	       (unsigned long) osi->osi_cookie.lgc_lgl.lgl_ogen,
	       (unsigned long) osi->osi_cookie.lgc_index, rc);

	if (rc > 0)
		rc = 0;

	if (likely(rc == 0)) {
		spin_lock(&d->opd_syn_lock);
		d->opd_syn_changes++;
		spin_unlock(&d->opd_syn_lock);
	}

	RETURN(rc);
}

int osp_sync_add(const struct lu_env *env, struct osp_object *o,
		 llog_op_type type, struct thandle *th,
		 const struct lu_attr *attr)
{
	return osp_sync_add_rec(env, lu2osp_dev(o->opo_obj.do_lu.lo_dev),
				lu_object_fid(&o->opo_obj.do_lu), type, 1,
				th, attr);
}

int osp_sync_gap(const struct lu_env *env, struct osp_device *d,
		 struct lu_fid *fid, int lost, struct thandle *th)
{
	return osp_sync_add_rec(env, d, fid, MDS_UNLINK64_REC, lost, th, NULL);
}

/*
 * it's quite obvious we can't maintain all the structures in the memory:
 * while OST is down, MDS can be processing thousands and thousands of unlinks
 * filling persistent llogs and in-core respresentation
 *
 * this doesn't scale at all. so we need basically the following:
 * a) destroy/setattr append llog records
 * b) once llog has grown to X records, we process first Y committed records
 *
 *  once record R is found via llog_process(), it becomes committed after any
 *  subsequent commit callback (at the most)
 */

/*
 * called for each atomic on-disk change (not once per transaction batch)
 * and goes over the list
 * XXX: should be optimized?
 */

/**
 * called for each RPC reported committed
 */
static void osp_sync_request_commit_cb(struct ptlrpc_request *req)
{
	struct osp_device *d = req->rq_cb_data;

	CDEBUG(D_HA, "commit req %p, transno "LPU64"\n", req, req->rq_transno);

	if (unlikely(req->rq_transno == 0))
		return;

	/* do not do any opd_dyn_rpc_* accounting here
	 * it's done in osp_sync_interpret sooner or later */

	LASSERT(d);
	LASSERT(req->rq_svc_thread == (void *) OSP_JOB_MAGIC);
	LASSERT(cfs_list_empty(&req->rq_exp_list));

	ptlrpc_request_addref(req);

	spin_lock(&d->opd_syn_lock);
	cfs_list_add(&req->rq_exp_list, &d->opd_syn_committed_there);
	spin_unlock(&d->opd_syn_lock);

	/* XXX: some batching wouldn't hurt */
	wake_up(&d->opd_syn_waitq);
}

static int osp_sync_interpret(const struct lu_env *env,
			      struct ptlrpc_request *req, void *aa, int rc)
{
	struct osp_device *d = req->rq_cb_data;

	if (req->rq_svc_thread != (void *) OSP_JOB_MAGIC)
		DEBUG_REQ(D_ERROR, req, "bad magic %p\n", req->rq_svc_thread);
	LASSERT(req->rq_svc_thread == (void *) OSP_JOB_MAGIC);
	LASSERT(d);

	CDEBUG(D_HA, "reply req %p/%d, rc %d, transno %u\n", req,
	       cfs_atomic_read(&req->rq_refcount),
	       rc, (unsigned) req->rq_transno);
	LASSERT(rc || req->rq_transno);

	LASSERT(d->opd_pre != NULL);

	if (rc == -ENOENT) {
		/*
		 * we tried to destroy object or update attributes,
		 * but object doesn't exist anymore - cancell llog record
		 */
		LASSERT(req->rq_transno == 0);
		LASSERT(cfs_list_empty(&req->rq_exp_list));

		ptlrpc_request_addref(req);

		spin_lock(&d->opd_syn_lock);
		cfs_list_add(&req->rq_exp_list, &d->opd_syn_committed_there);
		spin_unlock(&d->opd_syn_lock);

		wake_up(&d->opd_syn_waitq);
	} else if (rc) {
		struct obd_import *imp = req->rq_import;
		/*
		 * error happened, we'll try to repeat on next boot ?
		 */
		LASSERTF(req->rq_transno == 0 ||
			 req->rq_import_generation < imp->imp_generation,
			 "transno "LPU64", rc %d, gen: req %d, imp %d\n",
			 req->rq_transno, rc, req->rq_import_generation,
			 imp->imp_generation);
		if (req->rq_transno == 0) {
			/* this is the last time we see the request
			 * if transno is not zero, then commit cb
			 * will be called at some point */
			LASSERT(d->opd_syn_rpc_in_progress > 0);
			spin_lock(&d->opd_syn_lock);
			d->opd_syn_rpc_in_progress--;
			spin_unlock(&d->opd_syn_lock);
		}

		wake_up(&d->opd_syn_waitq);
	} else if (unlikely(d->opd_pre_status == -ENOSPC)) {
		/*
		 * if current status is -ENOSPC (lack of free space on OST)
		 * then we should poll OST immediately once object destroy
		 * is replied
		 */
		osp_statfs_need_now(d);
	}

	LASSERT(d->opd_syn_rpc_in_flight > 0);
	spin_lock(&d->opd_syn_lock);
	d->opd_syn_rpc_in_flight--;
	spin_unlock(&d->opd_syn_lock);
	CDEBUG(D_OTHER, "%s: %d in flight, %d in progress\n",
	       d->opd_obd->obd_name, d->opd_syn_rpc_in_flight,
	       d->opd_syn_rpc_in_progress);

	osp_sync_check_for_work(d);

	return 0;
}

/*
 * the function walks through list of committed locally changes
 * and send them to RPC until the pipe is full
 */
static void osp_sync_send_new_rpc(struct osp_device *d,
				  struct ptlrpc_request *req)
{
	LASSERT(d->opd_syn_rpc_in_flight <= d->opd_syn_max_rpc_in_flight);
	LASSERT(req->rq_svc_thread == (void *) OSP_JOB_MAGIC);

	ptlrpcd_add_req(req, PDL_POLICY_ROUND, -1);
}

static struct ptlrpc_request *osp_sync_new_job(struct osp_device *d,
					       struct llog_handle *llh,
					       struct llog_rec_hdr *h,
					       ost_cmd_t op,
					       const struct req_format *format)
{
	struct ptlrpc_request	*req;
	struct ost_body		*body;
	struct obd_import	*imp;
	int			 rc;

	/* Prepare the request */
	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);
	req = ptlrpc_request_alloc(imp, format);
	if (req == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, op);
	if (rc) {
		ptlrpc_req_finished(req);
		return ERR_PTR(rc);
	}

	/*
	 * this is a trick: to save on memory allocations we put cookie
	 * into the request, but don't set corresponded flag in o_valid
	 * so that OST doesn't interpret this cookie. once the request
	 * is committed on OST we take cookie from the request and cancel
	 */
	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);
	body->oa.o_lcookie.lgc_lgl = llh->lgh_id;
	body->oa.o_lcookie.lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
	body->oa.o_lcookie.lgc_index = h->lrh_index;
	CFS_INIT_LIST_HEAD(&req->rq_exp_list);
	req->rq_svc_thread = (void *) OSP_JOB_MAGIC;

	req->rq_interpret_reply = osp_sync_interpret;
	req->rq_commit_cb = osp_sync_request_commit_cb;
	req->rq_cb_data = d;

	ptlrpc_request_set_replen(req);

	return req;
}

static int osp_sync_new_setattr_job(struct osp_device *d,
				    struct llog_handle *llh,
				    struct llog_rec_hdr *h)
{
	struct llog_setattr64_rec	*rec = (struct llog_setattr64_rec *)h;
	struct ptlrpc_request		*req;
	struct ost_body			*body;

	ENTRY;
	LASSERT(h->lrh_type == MDS_SETATTR64_REC);

	req = osp_sync_new_job(d, llh, h, OST_SETATTR, &RQF_OST_SETATTR);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);
	body->oa.o_oi = rec->lsr_oi;
	body->oa.o_uid = rec->lsr_uid;
	body->oa.o_gid = rec->lsr_gid;
	body->oa.o_valid = OBD_MD_FLGROUP | OBD_MD_FLID |
			   OBD_MD_FLUID | OBD_MD_FLGID;

	osp_sync_send_new_rpc(d, req);
	RETURN(0);
}

/* Old records may be in old format, so we handle that too */
static int osp_sync_new_unlink_job(struct osp_device *d,
				   struct llog_handle *llh,
				   struct llog_rec_hdr *h)
{
	struct llog_unlink_rec	*rec = (struct llog_unlink_rec *)h;
	struct ptlrpc_request	*req;
	struct ost_body		*body;

	ENTRY;
	LASSERT(h->lrh_type == MDS_UNLINK_REC);

	req = osp_sync_new_job(d, llh, h, OST_DESTROY, &RQF_OST_DESTROY);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);
	ostid_set_seq(&body->oa.o_oi, rec->lur_oseq);
	ostid_set_id(&body->oa.o_oi, rec->lur_oid);
	body->oa.o_misc = rec->lur_count;
	body->oa.o_valid = OBD_MD_FLGROUP | OBD_MD_FLID;
	if (rec->lur_count)
		body->oa.o_valid |= OBD_MD_FLOBJCOUNT;

	osp_sync_send_new_rpc(d, req);
	RETURN(0);
}

static int osp_sync_new_unlink64_job(struct osp_device *d,
				     struct llog_handle *llh,
				     struct llog_rec_hdr *h)
{
	struct llog_unlink64_rec	*rec = (struct llog_unlink64_rec *)h;
	struct ptlrpc_request		*req;
	struct ost_body			*body;
	int				 rc;

	ENTRY;
	LASSERT(h->lrh_type == MDS_UNLINK64_REC);

	req = osp_sync_new_job(d, llh, h, OST_DESTROY, &RQF_OST_DESTROY);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		RETURN(-EFAULT);
	rc = fid_to_ostid(&rec->lur_fid, &body->oa.o_oi);
	if (rc < 0)
		RETURN(rc);
	body->oa.o_misc = rec->lur_count;
	body->oa.o_valid = OBD_MD_FLGROUP | OBD_MD_FLID | OBD_MD_FLOBJCOUNT;

	osp_sync_send_new_rpc(d, req);
	RETURN(0);
}

static int osp_sync_process_record(const struct lu_env *env,
				   struct osp_device *d,
				   struct llog_handle *llh,
				   struct llog_rec_hdr *rec)
{
	struct llog_cookie	 cookie;
	int			 rc = 0;

	cookie.lgc_lgl = llh->lgh_id;
	cookie.lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
	cookie.lgc_index = rec->lrh_index;

	if (unlikely(rec->lrh_type == LLOG_GEN_REC)) {
		struct llog_gen_rec *gen = (struct llog_gen_rec *)rec;

		/* we're waiting for the record generated by this instance */
		LASSERT(d->opd_syn_prev_done == 0);
		if (!memcmp(&d->opd_syn_generation, &gen->lgr_gen,
			    sizeof(gen->lgr_gen))) {
			CDEBUG(D_HA, "processed all old entries\n");
			d->opd_syn_prev_done = 1;
		}

		/* cancel any generation record */
		rc = llog_cat_cancel_records(env, llh->u.phd.phd_cat_handle,
					     1, &cookie);

		return rc;
	}

	/*
	 * now we prepare and fill requests to OST, put them on the queue
	 * and fire after next commit callback
	 */

	/* notice we increment counters before sending RPC, to be consistent
	 * in RPC interpret callback which may happen very quickly */
	spin_lock(&d->opd_syn_lock);
	d->opd_syn_rpc_in_flight++;
	d->opd_syn_rpc_in_progress++;
	spin_unlock(&d->opd_syn_lock);

	switch (rec->lrh_type) {
	/* case MDS_UNLINK_REC is kept for compatibility */
	case MDS_UNLINK_REC:
		rc = osp_sync_new_unlink_job(d, llh, rec);
		break;
	case MDS_UNLINK64_REC:
		rc = osp_sync_new_unlink64_job(d, llh, rec);
		break;
	case MDS_SETATTR64_REC:
		rc = osp_sync_new_setattr_job(d, llh, rec);
		break;
	default:
		CERROR("unknown record type: %x\n", rec->lrh_type);
		       rc = -EINVAL;
		       break;
	}

	if (likely(rc == 0)) {
		spin_lock(&d->opd_syn_lock);
		if (d->opd_syn_prev_done) {
			LASSERT(d->opd_syn_changes > 0);
			LASSERT(rec->lrh_id <= d->opd_syn_last_committed_id);
			/*
			 * NOTE: it's possible to meet same id if
			 * OST stores few stripes of same file
			 */
			if (rec->lrh_id > d->opd_syn_last_processed_id)
				d->opd_syn_last_processed_id = rec->lrh_id;

			d->opd_syn_changes--;
		}
		CDEBUG(D_OTHER, "%s: %d in flight, %d in progress\n",
		       d->opd_obd->obd_name, d->opd_syn_rpc_in_flight,
		       d->opd_syn_rpc_in_progress);
		spin_unlock(&d->opd_syn_lock);
	} else {
		spin_lock(&d->opd_syn_lock);
		d->opd_syn_rpc_in_flight--;
		d->opd_syn_rpc_in_progress--;
		spin_unlock(&d->opd_syn_lock);
	}

	CDEBUG(D_HA, "found record %x, %d, idx %u, id %u: %d\n",
	       rec->lrh_type, rec->lrh_len, rec->lrh_index, rec->lrh_id, rc);
	return rc;
}

static void osp_sync_process_committed(const struct lu_env *env,
				       struct osp_device *d)
{
	struct obd_device	*obd = d->opd_obd;
	struct obd_import	*imp = obd->u.cli.cl_import;
	struct ost_body		*body;
	struct ptlrpc_request	*req, *tmp;
	struct llog_ctxt	*ctxt;
	struct llog_handle	*llh;
	cfs_list_t		 list;
	int			 rc, done = 0;

	ENTRY;

	if (cfs_list_empty(&d->opd_syn_committed_there))
		return;

	/*
	 * if current status is -ENOSPC (lack of free space on OST)
	 * then we should poll OST immediately once object destroy
	 * is committed.
	 * notice: we do this upon commit as well because some backends
	 * (like DMU) do not release space right away.
	 */
	LASSERT(d->opd_pre != NULL);
	if (unlikely(d->opd_pre_status == -ENOSPC))
		osp_statfs_need_now(d);

	/*
	 * now cancel them all
	 * XXX: can we improve this using some batching?
	 *      with batch RPC that'll happen automatically?
	 * XXX: can we store ctxt in lod_device and save few cycles ?
	 */
	ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
	LASSERT(ctxt);

	llh = ctxt->loc_handle;
	LASSERT(llh);

	CFS_INIT_LIST_HEAD(&list);
	spin_lock(&d->opd_syn_lock);
	cfs_list_splice(&d->opd_syn_committed_there, &list);
	CFS_INIT_LIST_HEAD(&d->opd_syn_committed_there);
	spin_unlock(&d->opd_syn_lock);

	cfs_list_for_each_entry_safe(req, tmp, &list, rq_exp_list) {
		LASSERT(req->rq_svc_thread == (void *) OSP_JOB_MAGIC);
		cfs_list_del_init(&req->rq_exp_list);

		body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
		LASSERT(body);

		/* import can be closing, thus all commit cb's are
		 * called we can check committness directly */
		if (req->rq_transno <= imp->imp_peer_committed_transno) {
			rc = llog_cat_cancel_records(env, llh, 1,
						     &body->oa.o_lcookie);
			if (rc)
				CERROR("%s: can't cancel record: %d\n",
				       obd->obd_name, rc);
		} else {
			DEBUG_REQ(D_HA, req, "not committed");
		}

		ptlrpc_req_finished(req);
		done++;
	}

	llog_ctxt_put(ctxt);

	LASSERT(d->opd_syn_rpc_in_progress >= done);
	spin_lock(&d->opd_syn_lock);
	d->opd_syn_rpc_in_progress -= done;
	spin_unlock(&d->opd_syn_lock);
	CDEBUG(D_OTHER, "%s: %d in flight, %d in progress\n",
	       d->opd_obd->obd_name, d->opd_syn_rpc_in_flight,
	       d->opd_syn_rpc_in_progress);

	osp_sync_check_for_work(d);

	/* wake up the thread if requested to stop:
	 * it might be waiting for in-progress to complete */
	if (unlikely(osp_sync_running(d) == 0))
		wake_up(&d->opd_syn_waitq);

	EXIT;
}

/*
 * this is where most of queues processing happens
 */
static int osp_sync_process_queues(const struct lu_env *env,
				   struct llog_handle *llh,
				   struct llog_rec_hdr *rec,
				   void *data)
{
	struct osp_device	*d = data;
	int			 rc;

	do {
		struct l_wait_info lwi = { 0 };

		if (!osp_sync_running(d)) {
			CDEBUG(D_HA, "stop llog processing\n");
			return LLOG_PROC_BREAK;
		}

		/* process requests committed by OST */
		osp_sync_process_committed(env, d);

		/* if we there are changes to be processed and we have
		 * resources for this ... do now */
		if (osp_sync_can_process_new(d, rec)) {
			if (llh == NULL) {
				/* ask llog for another record */
				CDEBUG(D_HA, "%lu changes, %u in progress, %u in flight\n",
				       d->opd_syn_changes,
				       d->opd_syn_rpc_in_progress,
				       d->opd_syn_rpc_in_flight);
				return 0;
			}

			/*
			 * try to send, in case of disconnection, suspend
			 * processing till we can send this request
			 */
			do {
				rc = osp_sync_process_record(env, d, llh, rec);
				/*
				 * XXX: probably different handling is needed
				 * for some bugs, like immediate exit or if
				 * OSP gets inactive
				 */
				if (rc) {
					CERROR("can't send: %d\n", rc);
					l_wait_event(d->opd_syn_waitq,
						     !osp_sync_running(d) ||
						     osp_sync_has_work(d),
						     &lwi);
				}
			} while (rc != 0 && osp_sync_running(d));

			llh = NULL;
			rec = NULL;
		}

		if (d->opd_syn_last_processed_id == d->opd_syn_last_used_id)
			osp_sync_remove_from_tracker(d);

		l_wait_event(d->opd_syn_waitq,
			     !osp_sync_running(d) ||
			     osp_sync_can_process_new(d, rec) ||
			     !cfs_list_empty(&d->opd_syn_committed_there),
			     &lwi);
	} while (1);
}

/*
 * this thread runs llog_cat_process() scanner calling our callback
 * to process llog records. in the callback we implement tricky
 * state machine as we don't want to start scanning of the llog again
 * and again, also we don't want to process too many records and send
 * too many RPCs a time. so, depending on current load (num of changes
 * being synced to OST) the callback can suspend awaiting for some
 * new conditions, like syncs completed.
 *
 * in order to process llog records left by previous boots and to allow
 * llog_process_thread() to find something (otherwise it'd just exit
 * immediately) we add a special GENERATATION record on each boot.
 */
static int osp_sync_thread(void *_arg)
{
	struct osp_device	*d = _arg;
	struct ptlrpc_thread	*thread = &d->opd_syn_thread;
	struct l_wait_info	 lwi = { 0 };
	struct llog_ctxt	*ctxt;
	struct obd_device	*obd = d->opd_obd;
	struct llog_handle	*llh;
	struct lu_env		 env;
	int			 rc, count;

	ENTRY;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc) {
		CERROR("%s: can't initialize env: rc = %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	spin_lock(&d->opd_syn_lock);
	thread->t_flags = SVC_RUNNING;
	spin_unlock(&d->opd_syn_lock);
	wake_up(&thread->t_ctl_waitq);

	ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
	if (ctxt == NULL) {
		CERROR("can't get appropriate context\n");
		GOTO(out, rc = -EINVAL);
	}

	llh = ctxt->loc_handle;
	if (llh == NULL) {
		CERROR("can't get llh\n");
		llog_ctxt_put(ctxt);
		GOTO(out, rc = -EINVAL);
	}

	rc = llog_cat_process(&env, llh, osp_sync_process_queues, d, 0, 0);
	LASSERTF(rc == 0 || rc == LLOG_PROC_BREAK,
		 "%lu changes, %u in progress, %u in flight: %d\n",
		 d->opd_syn_changes, d->opd_syn_rpc_in_progress,
		 d->opd_syn_rpc_in_flight, rc);

	/* we don't expect llog_process_thread() to exit till umount */
	LASSERTF(thread->t_flags != SVC_RUNNING,
		 "%lu changes, %u in progress, %u in flight\n",
		 d->opd_syn_changes, d->opd_syn_rpc_in_progress,
		 d->opd_syn_rpc_in_flight);

	/* wait till all the requests are completed */
	count = 0;
	while (d->opd_syn_rpc_in_progress > 0) {
		osp_sync_process_committed(&env, d);

		lwi = LWI_TIMEOUT(cfs_time_seconds(5), NULL, NULL);
		rc = l_wait_event(d->opd_syn_waitq,
				  d->opd_syn_rpc_in_progress == 0,
				  &lwi);
		if (rc == -ETIMEDOUT)
			count++;
		LASSERTF(count < 10, "%s: %d %d %sempty\n",
			 d->opd_obd->obd_name, d->opd_syn_rpc_in_progress,
			 d->opd_syn_rpc_in_flight,
			 cfs_list_empty(&d->opd_syn_committed_there) ? "" :"!");

	}

	llog_cat_close(&env, llh);
	rc = llog_cleanup(&env, ctxt);
	if (rc)
		CERROR("can't cleanup llog: %d\n", rc);
out:
	LASSERTF(d->opd_syn_rpc_in_progress == 0,
		 "%s: %d %d %sempty\n",
		 d->opd_obd->obd_name, d->opd_syn_rpc_in_progress,
		 d->opd_syn_rpc_in_flight,
		 cfs_list_empty(&d->opd_syn_committed_there) ? "" : "!");

	thread->t_flags = SVC_STOPPED;

	wake_up(&thread->t_ctl_waitq);

	lu_env_fini(&env);

	RETURN(0);
}

static int osp_sync_llog_init(const struct lu_env *env, struct osp_device *d)
{
	struct osp_thread_info *osi = osp_env_info(env);
	struct llog_handle     *lgh = NULL;
	struct obd_device      *obd = d->opd_obd;
	struct llog_ctxt       *ctxt;
	int                     rc;

	ENTRY;

	LASSERT(obd);

	/*
	 * open llog corresponding to our OST
	 */
	OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
	obd->obd_lvfs_ctxt.dt = d->opd_storage;

	rc = llog_osd_get_cat_list(env, d->opd_storage, d->opd_index, 1,
				   &osi->osi_cid);
	if (rc) {
		CERROR("%s: can't get id from catalogs: rc = %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	CDEBUG(D_INFO, "%s: Init llog for %d - catid "DOSTID":%x\n",
	       obd->obd_name, d->opd_index,
	       POSTID(&osi->osi_cid.lci_logid.lgl_oi),
	       osi->osi_cid.lci_logid.lgl_ogen);

	rc = llog_setup(env, obd, &obd->obd_olg, LLOG_MDS_OST_ORIG_CTXT, obd,
			&osp_mds_ost_orig_logops);
	if (rc)
		RETURN(rc);

	ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
	LASSERT(ctxt);

	if (likely(logid_id(&osi->osi_cid.lci_logid) != 0)) {
		rc = llog_open(env, ctxt, &lgh, &osi->osi_cid.lci_logid, NULL,
			       LLOG_OPEN_EXISTS);
		/* re-create llog if it is missing */
		if (rc == -ENOENT)
			logid_set_id(&osi->osi_cid.lci_logid, 0);
		else if (rc < 0)
			GOTO(out_cleanup, rc);
	}

	if (unlikely(logid_id(&osi->osi_cid.lci_logid) == 0)) {
		rc = llog_open_create(env, ctxt, &lgh, NULL, NULL);
		if (rc < 0)
			GOTO(out_cleanup, rc);
		osi->osi_cid.lci_logid = lgh->lgh_id;
	}

	LASSERT(lgh != NULL);
	ctxt->loc_handle = lgh;

	rc = llog_cat_init_and_process(env, lgh);
	if (rc)
		GOTO(out_close, rc);

	rc = llog_osd_put_cat_list(env, d->opd_storage, d->opd_index, 1,
				   &osi->osi_cid);
	if (rc)
		GOTO(out_close, rc);

	/*
	 * put a mark in the llog till which we'll be processing
	 * old records restless
	 */
	d->opd_syn_generation.mnt_cnt = cfs_time_current();
	d->opd_syn_generation.conn_cnt = cfs_time_current();

	osi->osi_hdr.lrh_type = LLOG_GEN_REC;
	osi->osi_hdr.lrh_len = sizeof(osi->osi_gen);

	memcpy(&osi->osi_gen.lgr_gen, &d->opd_syn_generation,
	       sizeof(osi->osi_gen.lgr_gen));

	rc = llog_cat_add(env, lgh, &osi->osi_gen.lgr_hdr, &osi->osi_cookie,
			  NULL);
	if (rc < 0)
		GOTO(out_close, rc);
	llog_ctxt_put(ctxt);
	RETURN(0);
out_close:
	llog_cat_close(env, lgh);
out_cleanup:
	llog_cleanup(env, ctxt);
	RETURN(rc);
}

static void osp_sync_llog_fini(const struct lu_env *env, struct osp_device *d)
{
	struct llog_ctxt *ctxt;

	ctxt = llog_get_context(d->opd_obd, LLOG_MDS_OST_ORIG_CTXT);
	if (ctxt != NULL)
		llog_cat_close(env, ctxt->loc_handle);
	llog_cleanup(env, ctxt);
}

/*
 * initializes sync component of OSP
 */
int osp_sync_init(const struct lu_env *env, struct osp_device *d)
{
	struct l_wait_info	 lwi = { 0 };
	int			 rc;

	ENTRY;

	rc = osp_sync_id_traction_init(d);
	if (rc)
		RETURN(rc);

	/*
	 * initialize llog storing changes
	 */
	rc = osp_sync_llog_init(env, d);
	if (rc) {
		CERROR("%s: can't initialize llog: rc = %d\n",
		       d->opd_obd->obd_name, rc);
		GOTO(err_id, rc);
	}

	/*
	 * Start synchronization thread
	 */
	d->opd_syn_max_rpc_in_flight = OSP_MAX_IN_FLIGHT;
	d->opd_syn_max_rpc_in_progress = OSP_MAX_IN_PROGRESS;
	spin_lock_init(&d->opd_syn_lock);
	init_waitqueue_head(&d->opd_syn_waitq);
	init_waitqueue_head(&d->opd_syn_thread.t_ctl_waitq);
	CFS_INIT_LIST_HEAD(&d->opd_syn_committed_there);

	rc = PTR_ERR(kthread_run(osp_sync_thread, d,
				 "osp-syn-%u", d->opd_index));
	if (IS_ERR_VALUE(rc)) {
		CERROR("%s: can't start sync thread: rc = %d\n",
		       d->opd_obd->obd_name, rc);
		GOTO(err_llog, rc);
	}

	l_wait_event(d->opd_syn_thread.t_ctl_waitq,
		     osp_sync_running(d) || osp_sync_stopped(d), &lwi);

	RETURN(0);
err_llog:
	osp_sync_llog_fini(env, d);
err_id:
	osp_sync_id_traction_fini(d);
	return rc;
}

int osp_sync_fini(struct osp_device *d)
{
	struct ptlrpc_thread *thread = &d->opd_syn_thread;

	ENTRY;

	thread->t_flags = SVC_STOPPING;
	wake_up(&d->opd_syn_waitq);
	wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_STOPPED);

	/*
	 * unregister transaction callbacks only when sync thread
	 * has finished operations with llog
	 */
	osp_sync_id_traction_fini(d);

	RETURN(0);
}

static DEFINE_MUTEX(osp_id_tracker_sem);
static CFS_LIST_HEAD(osp_id_tracker_list);

static void osp_sync_tracker_commit_cb(struct thandle *th, void *cookie)
{
	struct osp_id_tracker	*tr = cookie;
	struct osp_device	*d;
	struct osp_txn_info	*txn;

	LASSERT(tr);

	txn = osp_txn_info(&th->th_ctx);
	if (txn == NULL || txn->oti_current_id < tr->otr_committed_id)
		return;

	spin_lock(&tr->otr_lock);
	if (likely(txn->oti_current_id > tr->otr_committed_id)) {
		CDEBUG(D_OTHER, "committed: %u -> %u\n",
		       tr->otr_committed_id, txn->oti_current_id);
		tr->otr_committed_id = txn->oti_current_id;

		cfs_list_for_each_entry(d, &tr->otr_wakeup_list,
					opd_syn_ontrack) {
			d->opd_syn_last_committed_id = tr->otr_committed_id;
			wake_up(&d->opd_syn_waitq);
		}
	}
	spin_unlock(&tr->otr_lock);
}

static int osp_sync_id_traction_init(struct osp_device *d)
{
	struct osp_id_tracker	*tr, *found = NULL;
	int			 rc = 0;

	LASSERT(d);
	LASSERT(d->opd_storage);
	LASSERT(d->opd_syn_tracker == NULL);
	CFS_INIT_LIST_HEAD(&d->opd_syn_ontrack);

	mutex_lock(&osp_id_tracker_sem);
	cfs_list_for_each_entry(tr, &osp_id_tracker_list, otr_list) {
		if (tr->otr_dev == d->opd_storage) {
			LASSERT(cfs_atomic_read(&tr->otr_refcount));
			cfs_atomic_inc(&tr->otr_refcount);
			d->opd_syn_tracker = tr;
			found = tr;
			break;
		}
	}

	if (found == NULL) {
		rc = -ENOMEM;
		OBD_ALLOC_PTR(tr);
		if (tr) {
			d->opd_syn_tracker = tr;
			spin_lock_init(&tr->otr_lock);
			tr->otr_dev = d->opd_storage;
			tr->otr_next_id = 1;
			tr->otr_committed_id = 0;
			cfs_atomic_set(&tr->otr_refcount, 1);
			CFS_INIT_LIST_HEAD(&tr->otr_wakeup_list);
			cfs_list_add(&tr->otr_list, &osp_id_tracker_list);
			tr->otr_tx_cb.dtc_txn_commit =
						osp_sync_tracker_commit_cb;
			tr->otr_tx_cb.dtc_cookie = tr;
			tr->otr_tx_cb.dtc_tag = LCT_MD_THREAD;
			dt_txn_callback_add(d->opd_storage, &tr->otr_tx_cb);
			rc = 0;
		}
	}
	mutex_unlock(&osp_id_tracker_sem);

	return rc;
}

static void osp_sync_id_traction_fini(struct osp_device *d)
{
	struct osp_id_tracker *tr;

	ENTRY;

	LASSERT(d);
	tr = d->opd_syn_tracker;
	if (tr == NULL) {
		EXIT;
		return;
	}

	osp_sync_remove_from_tracker(d);

	mutex_lock(&osp_id_tracker_sem);
	if (cfs_atomic_dec_and_test(&tr->otr_refcount)) {
		dt_txn_callback_del(d->opd_storage, &tr->otr_tx_cb);
		LASSERT(cfs_list_empty(&tr->otr_wakeup_list));
		cfs_list_del(&tr->otr_list);
		OBD_FREE_PTR(tr);
		d->opd_syn_tracker = NULL;
	}
	mutex_unlock(&osp_id_tracker_sem);

	EXIT;
}

/*
 * generates id for the tracker
 */
static __u32 osp_sync_id_get(struct osp_device *d, __u32 id)
{
	struct osp_id_tracker *tr;

	tr = d->opd_syn_tracker;
	LASSERT(tr);

	/* XXX: we can improve this introducing per-cpu preallocated ids? */
	spin_lock(&tr->otr_lock);
	if (unlikely(tr->otr_next_id <= d->opd_syn_last_used_id)) {
		spin_unlock(&tr->otr_lock);
		CERROR("%s: next %u, last synced %lu\n",
		       d->opd_obd->obd_name, tr->otr_next_id,
		       d->opd_syn_last_used_id);
		LBUG();
	}

	if (id == 0)
		id = tr->otr_next_id++;
	if (id > d->opd_syn_last_used_id)
		d->opd_syn_last_used_id = id;
	if (cfs_list_empty(&d->opd_syn_ontrack))
		cfs_list_add(&d->opd_syn_ontrack, &tr->otr_wakeup_list);
	spin_unlock(&tr->otr_lock);
	CDEBUG(D_OTHER, "new id %u\n", (unsigned) id);

	return id;
}

static void osp_sync_remove_from_tracker(struct osp_device *d)
{
	struct osp_id_tracker *tr;

	tr = d->opd_syn_tracker;
	LASSERT(tr);

	if (cfs_list_empty(&d->opd_syn_ontrack))
		return;

	spin_lock(&tr->otr_lock);
	cfs_list_del_init(&d->opd_syn_ontrack);
	spin_unlock(&tr->otr_lock);
}

