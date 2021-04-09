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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osp/osp_sync.c
 *
 * Lustre OST Proxy Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/kthread.h>
#include <linux/delay.h>
#include <lustre_log.h>
#include <lustre_update.h>
#include "osp_internal.h"

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
 * the second queue (opd_sync_waiting_for_commit) holds changes awaiting local
 * commit. once change is committed locally it migrates onto 3rd queue.
 *
 * the third queue (opd_sync_committed_here) holds changes committed locally,
 * but not sent to OST (as the pipe can be full). once pipe becomes non-full
 * we take a change from the queue and fire corresponded RPC.
 *
 * once RPC is reported committed by OST (using regular last_committed mech.)
 * the change jumps into 4th queue (opd_sync_committed_there), now we can
 * cancel corresponded llog record and release RPC
 *
 * opd_sync_changes is a number of unread llog records (to be processed).
 * notice this number doesn't include llog records from previous boots.
 * with OSP_SYNC_THRESHOLD we try to batch processing a bit (TO BE IMPLEMENTED)
 *
 * opd_sync_rpcs_in_progress is total number of requests in above 2-4 queues.
 * we control this with OSP_MAX_RPCS_IN_PROGRESS so that OSP don't consume
 * too much memory -- how to deal with 1000th OSTs ? batching could help?
 *
 * opd_sync_rpcs_in_flight is a number of RPC in flight.
 * we control this with OSP_MAX_RPCS_IN_FLIGHT
 */

/* XXX: do math to learn reasonable threshold
 * should it be ~ number of changes fitting bulk? */

#define OSP_SYNC_THRESHOLD		10
#define OSP_MAX_RPCS_IN_FLIGHT		8
#define OSP_MAX_RPCS_IN_PROGRESS	4096

#define OSP_JOB_MAGIC		0x26112005

struct osp_job_req_args {
	/** bytes reserved for ptlrpc_replay_req() */
	struct ptlrpc_replay_async_args	jra_raa;
	struct list_head		jra_committed_link;
	struct list_head		jra_in_flight_link;
	struct llog_cookie		jra_lcookie;
	__u32				jra_magic;
};

static int osp_sync_add_commit_cb(const struct lu_env *env,
				  struct osp_device *d, struct thandle *th);

/*
 ** Check for new changes to sync
 *
 * \param[in] d		OSP device
 *
 * \retval 1		there are changes
 * \retval 0		there are no changes
 */
static inline int osp_sync_has_new_job(struct osp_device *d)
{
	return atomic_read(&d->opd_sync_changes) > 0 ||
		d->opd_sync_prev_done == 0;
}

static inline int osp_sync_in_flight_conflict(struct osp_device *d,
					     struct llog_rec_hdr *h)
{
	struct osp_job_req_args	*jra;
	struct ost_id		 ostid;
	int			 conflict = 0;

	if (h == NULL || h->lrh_type == LLOG_GEN_REC ||
	    list_empty(&d->opd_sync_in_flight_list))
		return conflict;

	memset(&ostid, 0, sizeof(ostid));
	switch (h->lrh_type) {
	case MDS_UNLINK_REC: {
		struct llog_unlink_rec *unlink = (struct llog_unlink_rec *)h;

		ostid_set_seq(&ostid, unlink->lur_oseq);
		if (ostid_set_id(&ostid, unlink->lur_oid)) {
			CERROR("Bad %llu to set " DOSTID "\n",
			       (unsigned long long)(unlink->lur_oid),
			       POSTID(&ostid));
			return 1;
		}
		}
		break;
	case MDS_UNLINK64_REC:
		fid_to_ostid(&((struct llog_unlink64_rec *)h)->lur_fid, &ostid);
		break;
	case MDS_SETATTR64_REC:
		ostid = ((struct llog_setattr64_rec *)h)->lsr_oi;
		break;
	default:
		LBUG();
	}

	spin_lock(&d->opd_sync_lock);
	list_for_each_entry(jra, &d->opd_sync_in_flight_list,
			    jra_in_flight_link) {
		struct ptlrpc_request	*req;
		struct ost_body		*body;

		LASSERT(jra->jra_magic == OSP_JOB_MAGIC);

		req = container_of((void *)jra, struct ptlrpc_request,
				   rq_async_args);
		body = req_capsule_client_get(&req->rq_pill,
					      &RMF_OST_BODY);
		LASSERT(body);

		if (memcmp(&ostid, &body->oa.o_oi, sizeof(ostid)) == 0) {
			conflict = 1;
			break;
		}
	}
	spin_unlock(&d->opd_sync_lock);

	return conflict;
}

static inline int osp_sync_rpcs_in_progress_low(struct osp_device *d)
{
	return atomic_read(&d->opd_sync_rpcs_in_progress) <
		d->opd_sync_max_rpcs_in_progress;
}

/**
 * Check for room in the network pipe to OST
 *
 * \param[in] d		OSP device
 *
 * \retval 1		there is room
 * \retval 0		no room, the pipe is full
 */
static inline int osp_sync_rpcs_in_flight_low(struct osp_device *d)
{
	return atomic_read(&d->opd_sync_rpcs_in_flight) <
		d->opd_sync_max_rpcs_in_flight;
}

/**
 * Wake up check for the main sync thread
 *
 * \param[in] d		OSP device
 *
 * \retval 1		time to wake up
 * \retval 0		no need to wake up
 */
static inline int osp_sync_has_work(struct osp_device *osp)
{
	/* has new/old changes and low in-progress? */
	if (osp_sync_has_new_job(osp) && osp_sync_rpcs_in_progress_low(osp) &&
	    osp_sync_rpcs_in_flight_low(osp) && osp->opd_imp_connected)
		return 1;

	/* has remotely committed? */
	if (!list_empty(&osp->opd_sync_committed_there))
		return 1;

	return 0;
}

void osp_sync_check_for_work(struct osp_device *osp)
{
	if (osp_sync_has_work(osp))
		wake_up(&osp->opd_sync_waitq);
}

static inline __u64 osp_sync_correct_id(struct osp_device *d,
					struct llog_rec_hdr *rec)
{
	/*
	 * llog use cyclic store with 32 bit lrh_id
	 * so overflow lrh_id is possible. Range between
	 * last_processed and last_committed is less than
	 * 64745 ^ 2 and less than 2^32 - 1
	 */
	__u64 correct_id = d->opd_sync_last_committed_id;

	if ((correct_id & 0xffffffffULL) < rec->lrh_id)
		correct_id -= 0x100000000ULL;

	correct_id &= ~0xffffffffULL;
	correct_id |= rec->lrh_id;

	return correct_id;
}

/**
 * Check and return ready-for-new status.
 *
 * The thread processing llog record uses this function to check whether
 * it's time to take another record and process it. The number of conditions
 * must be met: the connection should be ready, RPCs in flight not exceeding
 * the limit, the record is committed locally, etc (see the lines below).
 *
 * \param[in] d		OSP device
 * \param[in] rec	next llog record to process
 *
 * \retval 0		not ready
 * \retval 1		ready
 */
static inline int osp_sync_can_process_new(struct osp_device *d,
					   struct llog_rec_hdr *rec)
{
	LASSERT(d);

	if (unlikely(atomic_read(&d->opd_sync_barrier) > 0))
		return 0;
	if (unlikely(osp_sync_in_flight_conflict(d, rec)))
		return 0;
	if (!osp_sync_rpcs_in_progress_low(d))
		return 0;
	if (!osp_sync_rpcs_in_flight_low(d))
		return 0;
	if (!d->opd_imp_connected)
		return 0;
	if (d->opd_sync_prev_done == 0)
		return 1;
	if (atomic_read(&d->opd_sync_changes) == 0)
		return 0;
	if (rec == NULL)
		return 1;
	/* notice "<" not "<=" */
	if (osp_sync_correct_id(d, rec) < d->opd_sync_last_committed_id)
		return 1;
	return 0;
}

/**
 * Declare intention to add a new change.
 *
 * With regard to OSD API, we have to declare any changes ahead. In this
 * case we declare an intention to add a llog record representing the
 * change on the local storage.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] o		OSP object
 * \param[in] type	type of change: MDS_UNLINK64_REC or MDS_SETATTR64_REC
 * \param[in] th	transaction handle (local)
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
int osp_sync_declare_add(const struct lu_env *env, struct osp_object *o,
			 enum llog_op_type type, struct thandle *th)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct osp_device	*d = lu2osp_dev(o->opo_obj.do_lu.lo_dev);
	struct llog_ctxt	*ctxt;
	struct thandle		*storage_th;
	int			 rc;

	ENTRY;

	/* it's a layering violation, to access internals of th,
	 * but we can do this as a sanity check, for a while */
	LASSERT(th->th_top != NULL);
	storage_th = thandle_get_sub_by_dt(env, th->th_top, d->opd_storage);
	if (IS_ERR(storage_th))
		RETURN(PTR_ERR(storage_th));

	switch (type) {
	case MDS_UNLINK64_REC:
		osi->osi_hdr.lrh_len = sizeof(struct llog_unlink64_rec);
		break;
	case MDS_SETATTR64_REC:
		osi->osi_hdr.lrh_len = sizeof(struct llog_setattr64_rec_v2);
		break;
	default:
		LBUG();
	}

	ctxt = llog_get_context(d->opd_obd, LLOG_MDS_OST_ORIG_CTXT);
	if (!ctxt) {
		/* for a reason OSP wasn't able to open llog,
		 * just skip logging this operation and hope
		 * LFSCK will fix it eventually */
		CERROR("logging isn't available, run LFSCK\n");
		RETURN(0);
	}

	rc = llog_declare_add(env, ctxt->loc_handle, &osi->osi_hdr,
			      storage_th);
	llog_ctxt_put(ctxt);

	RETURN(rc);
}

/**
 * Generate a llog record for a given change.
 *
 * Generates a llog record for the change passed. The change can be of two
 * types: unlink and setattr. The record gets an ID which later will be
 * used to track commit status of the change. For unlink changes, the caller
 * can supply a starting FID and the count of the objects to destroy. For
 * setattr the caller should apply attributes to apply.
 *
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 * \param[in] fid	fid of the object the change should be applied to
 * \param[in] type	type of change: MDS_UNLINK64_REC or MDS_SETATTR64_REC
 * \param[in] count	count of objects to destroy
 * \param[in] th	transaction handle (local)
 * \param[in] attr	attributes for setattr
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
static int osp_sync_add_rec(const struct lu_env *env, struct osp_device *d,
			    const struct lu_fid *fid, enum llog_op_type type,
			    int count, struct thandle *th,
			    const struct lu_attr *attr)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct llog_ctxt	*ctxt;
	struct thandle		*storage_th;
	bool			 immediate_commit_cb = false;
	int			 rc;

	ENTRY;

	/* it's a layering violation, to access internals of th,
	 * but we can do this as a sanity check, for a while */
	LASSERT(th->th_top != NULL);
	storage_th = thandle_get_sub_by_dt(env, th->th_top, d->opd_storage);
	if (IS_ERR(storage_th))
		RETURN(PTR_ERR(storage_th));

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
		osi->osi_setattr.lsr_layout_version = attr->la_layout_version;
		osi->osi_setattr.lsr_projid = attr->la_projid;
		osi->osi_setattr.lsr_valid =
			((attr->la_valid & LA_UID) ? OBD_MD_FLUID : 0) |
			((attr->la_valid & LA_GID) ? OBD_MD_FLGID : 0) |
			((attr->la_valid & LA_PROJID) ? OBD_MD_FLPROJID : 0);
		if (attr->la_valid & LA_LAYOUT_VERSION) {
			osi->osi_setattr.lsr_valid |= OBD_MD_LAYOUT_VERSION;

			/* FLR: the layout version has to be transferred to
			 * OST objects ASAP, otherwise clients will have to
			 * experience delay to be able to write OST objects. */
			immediate_commit_cb = true;
		}
		break;
	default:
		LBUG();
	}

	/* we keep the same id, but increment it when the callback
	 * is registered, so that all records upto the one taken
	 * by the callback are subject to processing */
	spin_lock(&d->opd_sync_lock);
	osi->osi_hdr.lrh_id = d->opd_sync_last_used_id;
	spin_unlock(&d->opd_sync_lock);

	ctxt = llog_get_context(d->opd_obd, LLOG_MDS_OST_ORIG_CTXT);
	if (ctxt == NULL) {
		/* see comment in osp_sync_declare_add() */
		RETURN(0);
	}

	rc = llog_add(env, ctxt->loc_handle, &osi->osi_hdr, &osi->osi_cookie,
		      storage_th);
	llog_ctxt_put(ctxt);

	if (likely(rc >= 0)) {
		CDEBUG(D_OTHER, "%s: new record "DFID":%x.%u: rc = %d\n",
		       d->opd_obd->obd_name,
		       PFID(&osi->osi_cookie.lgc_lgl.lgl_oi.oi_fid),
		       osi->osi_cookie.lgc_lgl.lgl_ogen,
		       osi->osi_cookie.lgc_index, rc);
		atomic_inc(&d->opd_sync_changes);
	}

	if (immediate_commit_cb)
		rc = osp_sync_add_commit_cb(env, d, th);
	else
		rc = osp_sync_add_commit_cb_1s(env, d, th);

	/* return 0 always here, error case just cause no llog record */
	RETURN(0);
}

int osp_sync_add(const struct lu_env *env, struct osp_object *o,
		 enum llog_op_type type, struct thandle *th,
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

/**
 * ptlrpc commit callback.
 *
 * The callback is called by PTLRPC when a RPC is reported committed by the
 * target (OST). We register the callback for the every RPC applying a change
 * from the llog. This way we know then the llog records can be cancelled.
 * Notice the callback can be called when OSP is finishing. We can detect this
 * checking that actual transno in the request is less or equal of known
 * committed transno (see osp_sync_process_committed() for the details).
 * XXX: this is pretty expensive and can be improved later using batching.
 *
 * \param[in] req	request
 */
static void osp_sync_request_commit_cb(struct ptlrpc_request *req)
{
	struct osp_device *d = req->rq_cb_data;
	struct osp_job_req_args *jra;

	CDEBUG(D_HA, "commit req %p, transno %llu\n", req, req->rq_transno);

	if (unlikely(req->rq_transno == 0))
		return;

	/* do not do any opd_sync_rpcs_* accounting here
	 * it's done in osp_sync_interpret sooner or later */
	LASSERT(d);

	jra = ptlrpc_req_async_args(jra, req);
	LASSERT(jra->jra_magic == OSP_JOB_MAGIC);
	LASSERT(list_empty(&jra->jra_committed_link));

	ptlrpc_request_addref(req);

	spin_lock(&d->opd_sync_lock);
	list_add(&jra->jra_committed_link, &d->opd_sync_committed_there);
	spin_unlock(&d->opd_sync_lock);

	/* XXX: some batching wouldn't hurt */
	wake_up(&d->opd_sync_waitq);
}

/**
 * RPC interpretation callback.
 *
 * The callback is called by ptlrpc when RPC is replied. Now we have to decide
 * whether we should:
 *  - put request on a special list to wait until it's committed by the target,
 *    if the request is successful
 *  - schedule llog record cancel if no target object is found
 *  - try later (essentially after reboot) in case of unexpected error
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] req	request replied
 * \param[in] aa	callback data
 * \param[in] rc	result of RPC
 *
 * \retval 0		always
 */
static int osp_sync_interpret(const struct lu_env *env,
			      struct ptlrpc_request *req, void *args, int rc)
{
	struct osp_job_req_args *jra = args;
	struct osp_device *d = req->rq_cb_data;

	if (jra->jra_magic != OSP_JOB_MAGIC) {
		DEBUG_REQ(D_ERROR, req, "bad magic %u", jra->jra_magic);
		LBUG();
	}
	LASSERT(d);

	CDEBUG(D_HA, "reply req %p/%d, rc %d, transno %u\n", req,
	       atomic_read(&req->rq_refcount),
	       rc, (unsigned) req->rq_transno);

	if (rc == -ENOENT) {
		/*
		 * we tried to destroy object or update attributes,
		 * but object doesn't exist anymore - cancell llog record
		 */
		LASSERT(req->rq_transno == 0);
		LASSERT(list_empty(&jra->jra_committed_link));

		ptlrpc_request_addref(req);

		spin_lock(&d->opd_sync_lock);
		list_add(&jra->jra_committed_link,
			 &d->opd_sync_committed_there);
		spin_unlock(&d->opd_sync_lock);

		wake_up(&d->opd_sync_waitq);
	} else if (rc) {
		struct obd_import *imp = req->rq_import;
		/*
		 * error happened, we'll try to repeat on next boot ?
		 */
		LASSERTF(req->rq_transno == 0 || rc == -EIO || rc == -EROFS ||
			 req->rq_import_generation < imp->imp_generation,
			 "transno %llu, rc %d, gen: req %d, imp %d\n",
			 req->rq_transno, rc, req->rq_import_generation,
			 imp->imp_generation);
		if (req->rq_transno == 0) {
			/* this is the last time we see the request
			 * if transno is not zero, then commit cb
			 * will be called at some point */
			LASSERT(atomic_read(&d->opd_sync_rpcs_in_progress) > 0);
			atomic_dec(&d->opd_sync_rpcs_in_progress);
		}

		wake_up(&d->opd_sync_waitq);
	} else if (d->opd_pre != NULL &&
		   unlikely(d->opd_pre_status == -ENOSPC)) {
		/*
		 * if current status is -ENOSPC (lack of free space on OST)
		 * then we should poll OST immediately once object destroy
		 * is replied
		 */
		osp_statfs_need_now(d);
	}

	spin_lock(&d->opd_sync_lock);
	list_del_init(&jra->jra_in_flight_link);
	spin_unlock(&d->opd_sync_lock);
	LASSERT(atomic_read(&d->opd_sync_rpcs_in_flight) > 0);
	atomic_dec(&d->opd_sync_rpcs_in_flight);
	if (unlikely(atomic_read(&d->opd_sync_barrier) > 0))
		wake_up(&d->opd_sync_barrier_waitq);
	CDEBUG(D_OTHER, "%s: %d in flight, %d in progress\n",
	       d->opd_obd->obd_name, atomic_read(&d->opd_sync_rpcs_in_flight),
	       atomic_read(&d->opd_sync_rpcs_in_progress));

	osp_sync_check_for_work(d);

	return 0;
}

/*
 ** Add request to ptlrpc queue.
 *
 * This is just a tiny helper function to put the request on the sending list
 *
 * \param[in] d		OSP device
 * \param[in] llh	llog handle where the record is stored
 * \param[in] h		llog record
 * \param[in] req	request
 */
static void osp_sync_send_new_rpc(struct osp_device *d,
				  struct llog_handle *llh,
				  struct llog_rec_hdr *h,
				  struct ptlrpc_request *req)
{
	struct osp_job_req_args *jra;

	LASSERT(atomic_read(&d->opd_sync_rpcs_in_flight) <=
		d->opd_sync_max_rpcs_in_flight);

	jra = ptlrpc_req_async_args(jra, req);
	jra->jra_magic = OSP_JOB_MAGIC;
	jra->jra_lcookie.lgc_lgl = llh->lgh_id;
	jra->jra_lcookie.lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
	jra->jra_lcookie.lgc_index = h->lrh_index;
	INIT_LIST_HEAD(&jra->jra_committed_link);
	spin_lock(&d->opd_sync_lock);
	list_add_tail(&jra->jra_in_flight_link, &d->opd_sync_in_flight_list);
	spin_unlock(&d->opd_sync_lock);

	ptlrpcd_add_req(req);
}


/**
 * Allocate and prepare RPC for a new change.
 *
 * The function allocates and initializes an RPC which will be sent soon to
 * apply the change to the target OST. The request is initialized from the
 * llog record passed. Notice only the fields common to all type of changes
 * are initialized.
 *
 * \param[in] d		OSP device
 * \param[in] op	type of the change
 * \param[in] format	request format to be used
 *
 * \retval pointer		new request on success
 * \retval ERR_PTR(errno)	on error
 */
static struct ptlrpc_request *osp_sync_new_job(struct osp_device *d,
					       enum ost_cmd op,
					       const struct req_format *format)
{
	struct ptlrpc_request	*req;
	struct obd_import	*imp;
	int			 rc;

	/* Prepare the request */
	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	if (OBD_FAIL_CHECK(OBD_FAIL_OSP_CHECK_ENOMEM))
		RETURN(ERR_PTR(-ENOMEM));

	req = ptlrpc_request_alloc(imp, format);
	if (req == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, op);
	if (rc) {
		ptlrpc_req_finished(req);
		return ERR_PTR(rc);
	}

	req->rq_interpret_reply = osp_sync_interpret;
	req->rq_commit_cb = osp_sync_request_commit_cb;
	req->rq_cb_data = d;

	ptlrpc_request_set_replen(req);

	return req;
}

/**
 * Generate a request for setattr change.
 *
 * The function prepares a new RPC, initializes it with setattr specific
 * bits and send the RPC.
 *
 * \param[in] d		OSP device
 * \param[in] llh	llog handle where the record is stored
 * \param[in] h		llog record
 *
 * \retval 0		on success
 * \retval 1		on invalid record
 * \retval negative	negated errno on error
 */
static int osp_sync_new_setattr_job(struct osp_device *d,
				    struct llog_handle *llh,
				    struct llog_rec_hdr *h)
{
	struct llog_setattr64_rec	*rec = (struct llog_setattr64_rec *)h;
	struct ptlrpc_request		*req;
	struct ost_body			*body;

	ENTRY;
	LASSERT(h->lrh_type == MDS_SETATTR64_REC);

	if (OBD_FAIL_CHECK(OBD_FAIL_OSP_CHECK_INVALID_REC))
		RETURN(1);

	/* lsr_valid can only be 0 or HAVE OBD_MD_{FLUID, FLGID, FLPROJID} set,
	 * so no bits other than these should be set. */
	if ((rec->lsr_valid & ~(OBD_MD_FLUID | OBD_MD_FLGID |
	    OBD_MD_FLPROJID | OBD_MD_LAYOUT_VERSION)) != 0) {
		CERROR("%s: invalid setattr record, lsr_valid:%llu\n",
			d->opd_obd->obd_name, rec->lsr_valid);
		/* return 1 on invalid record */
		RETURN(1);
	}

	req = osp_sync_new_job(d, OST_SETATTR, &RQF_OST_SETATTR);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);
	body->oa.o_oi = rec->lsr_oi;
	body->oa.o_uid = rec->lsr_uid;
	body->oa.o_gid = rec->lsr_gid;
	body->oa.o_valid = OBD_MD_FLGROUP | OBD_MD_FLID;
	if (h->lrh_len > sizeof(struct llog_setattr64_rec)) {
		struct llog_setattr64_rec_v2 *rec_v2 = (typeof(rec_v2))rec;
		body->oa.o_projid = rec_v2->lsr_projid;
		body->oa.o_layout_version = rec_v2->lsr_layout_version;
	}

	/* old setattr record (prior 2.6.0) doesn't have 'valid' stored,
	 * we assume that both UID and GID are valid in that case. */
	if (rec->lsr_valid == 0)
		body->oa.o_valid |= (OBD_MD_FLUID | OBD_MD_FLGID);
	else
		body->oa.o_valid |= rec->lsr_valid;

	if (body->oa.o_valid & OBD_MD_LAYOUT_VERSION) {
		OBD_FAIL_TIMEOUT(OBD_FAIL_FLR_LV_DELAY, cfs_fail_val);
		if (unlikely(OBD_FAIL_CHECK(OBD_FAIL_FLR_LV_INC)))
			++body->oa.o_layout_version;
	}

	osp_sync_send_new_rpc(d, llh, h, req);
	RETURN(0);
}

/**
 * Generate a request for unlink change.
 *
 * The function prepares a new RPC, initializes it with unlink(destroy)
 * specific bits and sends the RPC. The function is used to handle
 * llog_unlink_rec which were used in the older versions of Lustre.
 * Current version uses llog_unlink_rec64.
 *
 * \param[in] d		OSP device
 * \param[in] llh	llog handle where the record is stored
 * \param[in] h		llog record
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
static int osp_sync_new_unlink_job(struct osp_device *d,
				   struct llog_handle *llh,
				   struct llog_rec_hdr *h)
{
	struct llog_unlink_rec	*rec = (struct llog_unlink_rec *)h;
	struct ptlrpc_request	*req;
	struct ost_body		*body;
	int rc;

	ENTRY;
	LASSERT(h->lrh_type == MDS_UNLINK_REC);

	req = osp_sync_new_job(d, OST_DESTROY, &RQF_OST_DESTROY);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);
	ostid_set_seq(&body->oa.o_oi, rec->lur_oseq);
	rc = ostid_set_id(&body->oa.o_oi, rec->lur_oid);
	if (rc)
		return rc;
	body->oa.o_misc = rec->lur_count;
	body->oa.o_valid = OBD_MD_FLGROUP | OBD_MD_FLID;
	if (rec->lur_count)
		body->oa.o_valid |= OBD_MD_FLOBJCOUNT;

	osp_sync_send_new_rpc(d, llh, h, req);
	RETURN(0);
}

/**
 * Generate a request for unlink change.
 *
 * The function prepares a new RPC, initializes it with unlink(destroy)
 * specific bits and sends the RPC. Depending on the target (MDT or OST)
 * two different protocols are used. For MDT we use OUT (basically OSD API
 * updates transferred via a network). For OST we still use the old
 * protocol (OBD?), originally for compatibility. Later we can start to
 * use OUT for OST as well, this will allow batching and better code
 * unification.
 *
 * \param[in] d		OSP device
 * \param[in] llh	llog handle where the record is stored
 * \param[in] h		llog record
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
static int osp_sync_new_unlink64_job(struct osp_device *d,
				     struct llog_handle *llh,
				     struct llog_rec_hdr *h)
{
	struct llog_unlink64_rec	*rec = (struct llog_unlink64_rec *)h;
	struct ptlrpc_request		*req = NULL;
	struct ost_body			*body;
	int				 rc;

	ENTRY;
	LASSERT(h->lrh_type == MDS_UNLINK64_REC);
	req = osp_sync_new_job(d, OST_DESTROY, &RQF_OST_DESTROY);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		RETURN(-EFAULT);
	rc = fid_to_ostid(&rec->lur_fid, &body->oa.o_oi);
	if (rc < 0)
		RETURN(rc);
	body->oa.o_misc = rec->lur_count;
	body->oa.o_valid = OBD_MD_FLGROUP | OBD_MD_FLID |
			   OBD_MD_FLOBJCOUNT;
	osp_sync_send_new_rpc(d, llh, h, req);
	RETURN(0);
}

/**
 * Process llog records.
 *
 * This function is called to process the llog records committed locally.
 * In the recovery model used by OSP we can apply a change to a remote
 * target once corresponding transaction (like posix unlink) is committed
 * locally so can't revert.
 * Depending on the llog record type, a given handler is called that is
 * responsible for preparing and sending the RPC to apply the change.
 * Special record type LLOG_GEN_REC marking a reboot is cancelled right away.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 * \param[in] llh	llog handle where the record is stored
 * \param[in] rec	llog record
 */
static void osp_sync_process_record(const struct lu_env *env,
				    struct osp_device *d,
				    struct llog_handle *llh,
				    struct llog_rec_hdr *rec)
{
	struct llog_handle	*cathandle = llh->u.phd.phd_cat_handle;
	struct llog_cookie	 cookie;
	int			 rc = 0;

	ENTRY;

	cookie.lgc_lgl = llh->lgh_id;
	cookie.lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
	cookie.lgc_index = rec->lrh_index;

	d->opd_sync_last_catalog_idx = llh->lgh_hdr->llh_cat_idx;

	if (unlikely(rec->lrh_type == LLOG_GEN_REC)) {
		struct llog_gen_rec *gen = (struct llog_gen_rec *)rec;

		/* we're waiting for the record generated by this instance */
		LASSERT(d->opd_sync_prev_done == 0);
		if (!memcmp(&d->opd_sync_generation, &gen->lgr_gen,
			    sizeof(gen->lgr_gen))) {
			CDEBUG(D_HA, "processed all old entries\n");
			d->opd_sync_prev_done = 1;
		}

		/* cancel any generation record */
		rc = llog_cat_cancel_records(env, cathandle, 1, &cookie);

		/* flush all pending records ASAP */
		osp_sync_force(env, d);

		RETURN_EXIT;
	}

	/*
	 * now we prepare and fill requests to OST, put them on the queue
	 * and fire after next commit callback
	 */

	/* notice we increment counters before sending RPC, to be consistent
	 * in RPC interpret callback which may happen very quickly */
	atomic_inc(&d->opd_sync_rpcs_in_flight);
	atomic_inc(&d->opd_sync_rpcs_in_progress);

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
		CERROR("%s: unknown record type: %x\n", d->opd_obd->obd_name,
		       rec->lrh_type);
		/* treat "unknown record type" as "invalid" */
		rc = 1;
		break;
	}

	/* For all kinds of records, not matter successful or not,
	 * we should decrease changes and bump last_processed_id.
	 */
	if (d->opd_sync_prev_done) {
		LASSERT(atomic_read(&d->opd_sync_changes) > 0);
		atomic_dec(&d->opd_sync_changes);
		wake_up(&d->opd_sync_barrier_waitq);
	}
	atomic64_inc(&d->opd_sync_processed_recs);
	if (rc != 0) {
		atomic_dec(&d->opd_sync_rpcs_in_flight);
		atomic_dec(&d->opd_sync_rpcs_in_progress);
	}

	CDEBUG(D_OTHER, "%s: %d in flight, %d in progress\n",
	       d->opd_obd->obd_name, atomic_read(&d->opd_sync_rpcs_in_flight),
	       atomic_read(&d->opd_sync_rpcs_in_progress));

	/* Delete the invalid record */
	if (rc == 1) {
		rc = llog_cat_cancel_records(env, cathandle, 1, &cookie);
		if (rc != 0)
			CERROR("%s: can't delete invalid record: "
			       "fid = "DFID", rec_id = %u, rc = %d\n",
			       d->opd_obd->obd_name,
			       PFID(lu_object_fid(&cathandle->lgh_obj->do_lu)),
			       rec->lrh_id, rc);
	}

	CDEBUG(D_OTHER, "found record %x, %d, idx %u, id %u\n",
	       rec->lrh_type, rec->lrh_len, rec->lrh_index, rec->lrh_id);

	RETURN_EXIT;
}

/**
 * Cancel llog records for the committed changes.
 *
 * The function walks through the list of the committed RPCs and cancels
 * corresponding llog records. see osp_sync_request_commit_cb() for the
 * details.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 */
static void osp_sync_process_committed(const struct lu_env *env,
				       struct osp_device *d)
{
	struct obd_device	*obd = d->opd_obd;
	struct obd_import	*imp = obd->u.cli.cl_import;
	struct ost_body		*body;
	struct ptlrpc_request	*req;
	struct llog_ctxt	*ctxt;
	struct llog_handle	*llh;
	int			*arr, arr_size;
	LIST_HEAD(list);
	struct list_head	 *le;
	struct llog_logid	 lgid;
	int			 rc, i, count = 0, done = 0;

	ENTRY;

	if (list_empty(&d->opd_sync_committed_there))
		return;

	/*
	 * if current status is -ENOSPC (lack of free space on OST)
	 * then we should poll OST immediately once object destroy
	 * is committed.
	 * notice: we do this upon commit as well because some backends
	 * (like DMU) do not release space right away.
	 */
	if (d->opd_pre != NULL && unlikely(d->opd_pre_status == -ENOSPC))
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

	spin_lock(&d->opd_sync_lock);
	list_splice(&d->opd_sync_committed_there, &list);
	INIT_LIST_HEAD(&d->opd_sync_committed_there);
	spin_unlock(&d->opd_sync_lock);

	list_for_each(le, &list)
		count++;
	if (count > 2) {
		arr_size = sizeof(int) * count;
		/* limit cookie array to order 2 */
		arr_size = arr_size < (PAGE_SIZE * 4) ? arr_size :
			(PAGE_SIZE * 4);
		OBD_ALLOC_LARGE(arr, arr_size);
	} else {
		arr = NULL;
		arr_size = 0;
	}
	i = 0;
	while (!list_empty(&list)) {
		struct osp_job_req_args	*jra;

		jra = list_entry(list.next, struct osp_job_req_args,
				 jra_committed_link);
		LASSERT(jra->jra_magic == OSP_JOB_MAGIC);
		list_del_init(&jra->jra_committed_link);

		req = container_of((void *)jra, struct ptlrpc_request,
				   rq_async_args);
		body = req_capsule_client_get(&req->rq_pill,
					      &RMF_OST_BODY);
		LASSERT(body);
		/* import can be closing, thus all commit cb's are
		 * called we can check committness directly */
		if (req->rq_import_generation == imp->imp_generation) {
			if (arr && (!i ||
				    !memcmp(&jra->jra_lcookie.lgc_lgl, &lgid,
					   sizeof(lgid)))) {
				if (unlikely(!i))
					lgid = jra->jra_lcookie.lgc_lgl;

				arr[i++] = jra->jra_lcookie.lgc_index;
			} else {
				rc = llog_cat_cancel_records(env, llh, 1,
							     &jra->jra_lcookie);
				if (rc)
					CERROR("%s: can't cancel record: rc = %d\n",
					       obd->obd_name, rc);
			}
		} else {
			DEBUG_REQ(D_OTHER, req, "imp_committed = %llu",
				  imp->imp_peer_committed_transno);
		}
		ptlrpc_req_finished(req);
		done++;
		if (arr &&
		    ((i * sizeof(int)) == arr_size ||
		     (list_empty(&list) && i > 0))) {
			rc = llog_cat_cancel_arr_rec(env, llh, &lgid, i, arr);

			if (rc)
				CERROR("%s: can't cancel %d records: rc = %d\n",
				       obd->obd_name, i, rc);
			else
				CDEBUG(D_OTHER, "%s: massive records cancel id "DFID" num %d\n",
				       obd->obd_name, PFID(&lgid.lgl_oi.oi_fid),
				       i);
			i = 0;
		}

	}

	if (arr)
		OBD_FREE_LARGE(arr, arr_size);

	llog_ctxt_put(ctxt);

	LASSERT(atomic_read(&d->opd_sync_rpcs_in_progress) >= done);
	atomic_sub(done, &d->opd_sync_rpcs_in_progress);
	CDEBUG((done > 2 ? D_HA : D_OTHER), "%s: %u changes, %u in progress,"
				     " %u in flight, %u done\n",
				     d->opd_obd->obd_name,
				     atomic_read(&d->opd_sync_changes),
				     atomic_read(&d->opd_sync_rpcs_in_progress),
				     atomic_read(&d->opd_sync_rpcs_in_flight),
				     done);

	osp_sync_check_for_work(d);

	/* wake up the thread if requested to stop:
	 * it might be waiting for in-progress to complete
	 */
	if (atomic_read(&d->opd_sync_rpcs_in_progress) == 0)
		wake_up(&d->opd_sync_waitq);

	EXIT;
}

/**
 * The core of the syncing mechanism.
 *
 * This is a callback called by the llog processing function. Essentially it
 * suspends llog processing until there is a record to process (it's supposed
 * to be committed locally). The function handles RPCs committed by the target
 * and cancels corresponding llog records.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] llh	llog handle we're processing
 * \param[in] rec	current llog record
 * \param[in] data	callback data containing a pointer to the device
 *
 * \retval 0			to ask the caller (llog_process()) to continue
 * \retval LLOG_PROC_BREAK	to ask the caller to break
 */
static int osp_sync_process_queues(const struct lu_env *env,
				   struct llog_handle *llh,
				   struct llog_rec_hdr *rec,
				   void *data)
{
	struct osp_device	*d = data;

	do {
		if (!d->opd_sync_task) {
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
				return 0;
			}
			osp_sync_process_record(env, d, llh, rec);
			llh = NULL;
			rec = NULL;
		}
		if (OBD_FAIL_PRECHECK(OBD_FAIL_CATALOG_FULL_CHECK) &&
			    cfs_fail_val != 1)
			msleep(1 * MSEC_PER_SEC);

		wait_event_idle(d->opd_sync_waitq,
				!d->opd_sync_task ||
				osp_sync_can_process_new(d, rec) ||
				!list_empty(&d->opd_sync_committed_there));
	} while (1);
}

struct osp_sync_args {
	struct osp_device	*osa_dev;
	struct lu_env		 osa_env;
	struct completion	*osa_started;
};

/**
 * OSP sync thread.
 *
 * This thread runs llog_cat_process() scanner calling our callback
 * to process llog records. in the callback we implement tricky
 * state machine as we don't want to start scanning of the llog again
 * and again, also we don't want to process too many records and send
 * too many RPCs a time. so, depending on current load (num of changes
 * being synced to OST) the callback can suspend awaiting for some
 * new conditions, like syncs completed.
 *
 * In order to process llog records left by previous boots and to allow
 * llog_process_thread() to find something (otherwise it'd just exit
 * immediately) we add a special GENERATATION record on each boot.
 *
 * \param[in] _arg	a pointer to thread's arguments
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
static int osp_sync_thread(void *_args)
{
	struct osp_sync_args	*args = _args;
	struct osp_device	*d = args->osa_dev;
	struct llog_ctxt	*ctxt;
	struct obd_device	*obd = d->opd_obd;
	struct llog_handle	*llh;
	struct lu_env		*env = &args->osa_env;
	int			 rc, count;
	bool			 wrapped;

	ENTRY;

	complete(args->osa_started);
again:
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

	/*
	 * Catalog processing stops when it processed last catalog record
	 * with index equal to the end of catalog bitmap. Or if it is wrapped,
	 * processing stops with index equal to the lgh_last_idx. We need to
	 * continue processing.
	 */
	d->opd_sync_last_catalog_idx = 0;
	do {
		int	size;

		wrapped = (llh->lgh_hdr->llh_cat_idx >= llh->lgh_last_idx &&
			   llh->lgh_hdr->llh_count > 1);

		if (OBD_FAIL_CHECK(OBD_FAIL_OSP_CANT_PROCESS_LLOG)) {
			rc = -EINPROGRESS;
			goto next;
		}
		rc = llog_cat_process(env, llh, osp_sync_process_queues, d,
				      d->opd_sync_last_catalog_idx, 0);

next:
		size = OBD_FAIL_PRECHECK(OBD_FAIL_CAT_RECORDS) ?
		       cfs_fail_val : (LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr) - 1);
		/* processing reaches catalog bottom */
		if (d->opd_sync_last_catalog_idx == size)
			d->opd_sync_last_catalog_idx = LLOG_CAT_FIRST;
		/* If catalog is wrapped we can`t predict last index of
		 * processing because lgh_last_idx could be changed.
		 * Starting form the next one. Index would be increased
		 * at llog_process_thread
		 */
	} while (rc == 0 && (wrapped ||
			     d->opd_sync_last_catalog_idx == LLOG_CAT_FIRST));

	if (rc < 0) {
		if (rc == -EINPROGRESS) {
			/* can't access the llog now - OI scrub is trying to fix
			 * underlying issue. let's wait and try again */
			llog_cat_close(env, llh);
			rc = llog_cleanup(env, ctxt);
			if (rc)
				GOTO(out, rc);
			schedule_timeout_interruptible(cfs_time_seconds(5));
			goto again;
		}

		CERROR("%s: llog process with osp_sync_process_queues "
		       "failed: %d\n", d->opd_obd->obd_name, rc);
		GOTO(wait, rc);
	}
	LASSERTF(rc == 0 || rc == LLOG_PROC_BREAK,
		 "%u changes, %u in progress, %u in flight: %d\n",
		 atomic_read(&d->opd_sync_changes),
		 atomic_read(&d->opd_sync_rpcs_in_progress),
		 atomic_read(&d->opd_sync_rpcs_in_flight), rc);

	/* we don't expect llog_process_thread() to exit till umount */
	LASSERTF(kthread_should_stop(),
		 "%u changes, %u in progress, %u in flight\n",
		 atomic_read(&d->opd_sync_changes),
		 atomic_read(&d->opd_sync_rpcs_in_progress),
		 atomic_read(&d->opd_sync_rpcs_in_flight));

wait:
	/* wait till all the requests are completed */
	count = 0;
	while (atomic_read(&d->opd_sync_rpcs_in_progress) > 0) {
		osp_sync_process_committed(env, d);

		rc = wait_event_idle_timeout(
			d->opd_sync_waitq,
			atomic_read(&d->opd_sync_rpcs_in_progress) == 0,
			cfs_time_seconds(5));
		if (rc == 0)
			count++;
		LASSERTF(count < 10, "%s: %d %d %sempty\n",
			 d->opd_obd->obd_name,
			 atomic_read(&d->opd_sync_rpcs_in_progress),
			 atomic_read(&d->opd_sync_rpcs_in_flight),
			 list_empty(&d->opd_sync_committed_there) ? "" : "!");

	}

	llog_cat_close(env, llh);
	rc = llog_cleanup(env, ctxt);
	if (rc)
		CERROR("can't cleanup llog: %d\n", rc);
out:
	LASSERTF(atomic_read(&d->opd_sync_rpcs_in_progress) == 0,
		 "%s: %d %d %sempty\n", d->opd_obd->obd_name,
		 atomic_read(&d->opd_sync_rpcs_in_progress),
		 atomic_read(&d->opd_sync_rpcs_in_flight),
		 list_empty(&d->opd_sync_committed_there) ? "" : "!");

	lu_env_fini(env);

	if (xchg(&d->opd_sync_task, NULL) == NULL)
		/* already being waited for */
		wait_event_interruptible(d->opd_sync_waitq,
					 kthread_should_stop());
	OBD_FREE_PTR(args);

	RETURN(0);
}

/**
 * Initialize llog.
 *
 * Initializes the llog. Specific llog to be used depends on the type of the
 * target OSP represents (OST or MDT). The function adds appends a new llog
 * record to mark the place where the records associated with this boot
 * start.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
static int osp_sync_llog_init(const struct lu_env *env, struct osp_device *d)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct lu_fid		*fid = &osi->osi_fid;
	struct llog_handle	*lgh = NULL;
	struct obd_device	*obd = d->opd_obd;
	struct llog_ctxt	*ctxt;
	int			rc;

	ENTRY;

	LASSERT(obd);

	/*
	 * open llog corresponding to our OST
	 */
	OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
	obd->obd_lvfs_ctxt.dt = d->opd_storage;

	lu_local_obj_fid(fid, LLOG_CATALOGS_OID);

	rc = llog_osd_get_cat_list(env, d->opd_storage, d->opd_index, 1,
				   &osi->osi_cid, fid);
	if (rc < 0) {
		if (rc != -EFAULT) {
			CERROR("%s: can't get id from catalogs: rc = %d\n",
			       obd->obd_name, rc);
			RETURN(rc);
		}

		/* After sparse OST indices is supported, the CATALOG file
		 * may become a sparse file that results in failure on
		 * reading. Skip this error as the llog will be created
		 * later */
		memset(&osi->osi_cid, 0, sizeof(osi->osi_cid));
		rc = 0;
	}

	CDEBUG(D_INFO, "%s: Init llog for %d - catid "DFID":%x\n",
	       obd->obd_name, d->opd_index,
	       PFID(&osi->osi_cid.lci_logid.lgl_oi.oi_fid),
	       osi->osi_cid.lci_logid.lgl_ogen);

	rc = llog_setup(env, obd, &obd->obd_olg, LLOG_MDS_OST_ORIG_CTXT,
			d->opd_storage->dd_lu_dev.ld_obd,
			&llog_common_cat_ops);
	if (rc)
		RETURN(rc);

	ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
	LASSERT(ctxt);

	if (likely(logid_id(&osi->osi_cid.lci_logid) != 0)) {
		struct lu_fid fid_temp;

		if (CFS_FAIL_CHECK(OBD_FAIL_OSP_INVALID_LOGID)) {
			memset(&osi->osi_cid, 0, sizeof(osi->osi_cid));
			logid_set_id(&osi->osi_cid.lci_logid, cfs_fail_val);
		}

		logid_to_fid(&osi->osi_cid.lci_logid, &fid_temp);
		if (fid_is_sane(&fid_temp)) {
			rc = llog_open(env, ctxt, &lgh, &osi->osi_cid.lci_logid,
				       NULL, LLOG_OPEN_EXISTS);

			/* re-create llog if it is missing */
			if (rc == -ENOENT)
				logid_set_id(&osi->osi_cid.lci_logid, 0);
			else if (rc < 0)
				GOTO(out_cleanup, rc);
		} else {
			CERROR("%s: the catid "DFID" for init llog %d is bad\n",
			       obd->obd_name, PFID(&fid_temp), d->opd_index);

			/* it will be recreated later */
			logid_set_id(&osi->osi_cid.lci_logid, 0);
		}
	}

	if (unlikely(logid_id(&osi->osi_cid.lci_logid) == 0)) {
		rc = llog_open_create(env, ctxt, &lgh, NULL, NULL);
		if (rc < 0)
			GOTO(out_cleanup, rc);
		osi->osi_cid.lci_logid = lgh->lgh_id;
	}

	LASSERT(lgh != NULL);
	ctxt->loc_handle = lgh;

	rc = llog_init_handle(env, lgh, LLOG_F_IS_CAT | LLOG_F_RM_ON_ERR, NULL);
	if (rc)
		GOTO(out_close, rc);

	rc = llog_osd_put_cat_list(env, d->opd_storage, d->opd_index, 1,
				   &osi->osi_cid, fid);
	if (rc)
		GOTO(out_close, rc);

	/*
	 * put a mark in the llog till which we'll be processing
	 * old records restless
	 */
	d->opd_sync_generation.mnt_cnt = ktime_get_ns();
	d->opd_sync_generation.conn_cnt = ktime_get_ns();

	osi->osi_hdr.lrh_type = LLOG_GEN_REC;
	osi->osi_hdr.lrh_len = sizeof(osi->osi_gen);

	memcpy(&osi->osi_gen.lgr_gen, &d->opd_sync_generation,
	       sizeof(osi->osi_gen.lgr_gen));

	rc = llog_cat_add(env, lgh, &osi->osi_gen.lgr_hdr, &osi->osi_cookie);
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

/**
 * Cleanup llog used for syncing.
 *
 * Closes and cleanups the llog. The function is called when the device is
 * shutting down.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 */
static void osp_sync_llog_fini(const struct lu_env *env, struct osp_device *d)
{
	struct llog_ctxt *ctxt;

	ctxt = llog_get_context(d->opd_obd, LLOG_MDS_OST_ORIG_CTXT);
	if (ctxt) {
		llog_cat_close(env, ctxt->loc_handle);
		llog_cleanup(env, ctxt);
	}
}

/**
 * Initialization of the sync component of OSP.
 *
 * Initializes the llog and starts a new thread to handle the changes to
 * the remote target (OST or MDT).
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
int osp_sync_init(const struct lu_env *env, struct osp_device *d)
{
	struct task_struct	*task;
	struct osp_sync_args	*args;
	DECLARE_COMPLETION_ONSTACK(started);
	int			 rc;

	ENTRY;

	d->opd_sync_max_rpcs_in_flight = OSP_MAX_RPCS_IN_FLIGHT;
	d->opd_sync_max_rpcs_in_progress = OSP_MAX_RPCS_IN_PROGRESS;
	spin_lock_init(&d->opd_sync_lock);
	init_waitqueue_head(&d->opd_sync_waitq);
	init_waitqueue_head(&d->opd_sync_barrier_waitq);
	INIT_LIST_HEAD(&d->opd_sync_in_flight_list);
	INIT_LIST_HEAD(&d->opd_sync_committed_there);

	if (d->opd_storage->dd_rdonly)
		RETURN(0);

	OBD_ALLOC_PTR(args);
	if (!args)
		GOTO(err_id, rc = -ENOMEM);
	args->osa_dev = d;
	args->osa_started = &started;
	/*
	 * initialize llog storing changes
	 */
	rc = osp_sync_llog_init(env, d);
	if (rc) {
		CERROR("%s: can't initialize llog: rc = %d\n",
		       d->opd_obd->obd_name, rc);
		GOTO(err_id, rc);
	}

	rc = lu_env_init(&args->osa_env, LCT_LOCAL);
	if (rc) {
		CERROR("%s: can't initialize env: rc = %d\n",
		       d->opd_obd->obd_name, rc);
		GOTO(err_llog, rc);
	}

	/*
	 * Start synchronization thread
	 */
	task = kthread_create(osp_sync_thread, args, "osp-syn-%u-%u",
			   d->opd_index, d->opd_group);
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start sync thread: rc = %d\n",
		       d->opd_obd->obd_name, rc);
		lu_env_fini(&args->osa_env);
		GOTO(err_llog, rc);
	}
	d->opd_sync_task = task;
	wake_up_process(task);
	wait_for_completion(&started);

	RETURN(0);
err_llog:
	osp_sync_llog_fini(env, d);
err_id:
	if (args)
		OBD_FREE_PTR(args);
	return rc;
}

/**
 * Stop the syncing thread.
 *
 * Asks the syncing thread to stop and wait until it's stopped.
 *
 * \param[in] d		OSP device
 *
 * \retval		0
 */
int osp_sync_fini(struct osp_device *d)
{
	struct task_struct *task;

	ENTRY;

	task = xchg(&d->opd_sync_task, NULL);
	if (task)
		kthread_stop(task);

	RETURN(0);
}

struct osp_last_committed_cb {
	struct dt_txn_commit_cb	 ospc_cb;
	struct osp_device	*ospc_dev;
	__u64			 ospc_transno;
};

void osp_sync_local_commit_cb(struct lu_env *env, struct thandle *th,
			      struct dt_txn_commit_cb *dcb, int err)
{
	struct osp_last_committed_cb	*cb;
	struct osp_device		*d;

	cb = container_of(dcb, struct osp_last_committed_cb, ospc_cb);
	d = cb->ospc_dev;

	CDEBUG(D_HA, "%s: %llu committed\n", d->opd_obd->obd_name,
	       cb->ospc_transno);

	spin_lock(&d->opd_sync_lock);
	if (cb->ospc_transno > d->opd_sync_last_committed_id)
		d->opd_sync_last_committed_id = cb->ospc_transno;
	spin_unlock(&d->opd_sync_lock);

	osp_sync_check_for_work(d);
	lu_device_put(osp2lu_dev(d));
	if (atomic_dec_and_test(&d->opd_commits_registered))
		wake_up(&d->opd_sync_waitq);

	OBD_FREE_PTR(cb);
}

static int osp_sync_add_commit_cb(const struct lu_env *env,
				  struct osp_device *d, struct thandle *th)
{
	struct osp_last_committed_cb	*cb;
	struct dt_txn_commit_cb		*dcb;
	int				 rc = 0;

	OBD_ALLOC_PTR(cb);
	if (cb == NULL)
		return -ENOMEM;
	cb->ospc_dev = d;
	dcb = &cb->ospc_cb;
	dcb->dcb_func = osp_sync_local_commit_cb;
	spin_lock(&d->opd_sync_lock);
	cb->ospc_transno = ++d->opd_sync_last_used_id;
	spin_unlock(&d->opd_sync_lock);

	rc = dt_trans_cb_add(th, dcb);
	CDEBUG(D_HA, "%s: add commit cb at %lluns, next at %lluns, rc = %d\n",
	       d->opd_obd->obd_name, ktime_get_ns(),
	       ktime_to_ns(d->opd_sync_next_commit_cb), rc);

	if (likely(rc == 0)) {
		lu_device_get(osp2lu_dev(d));
		atomic_inc(&d->opd_commits_registered);
	} else
		OBD_FREE_PTR(cb);

	return rc;
}

/* add the commit callback every second */
int osp_sync_add_commit_cb_1s(const struct lu_env *env, struct osp_device *d,
			      struct thandle *th)
{
	ktime_t now = ktime_get();
	bool add = false;

	/* fast path */
	if (ktime_before(now, d->opd_sync_next_commit_cb))
		return 0;

	spin_lock(&d->opd_sync_lock);
	if (ktime_before(d->opd_sync_next_commit_cb, now)) {
		add = true;
		d->opd_sync_next_commit_cb = ktime_add_ns(now, NSEC_PER_SEC);
	}
	spin_unlock(&d->opd_sync_lock);

	if (!add)
		return 0;

	return osp_sync_add_commit_cb(env, d, th);
}

/*
 * generate an empty transaction and hook the commit callback in
 * then force transaction commit
 */
void osp_sync_force(const struct lu_env *env, struct osp_device *d)
{
	struct thandle *th;
	int rc;

	th = dt_trans_create(env, d->opd_storage);
	if (IS_ERR(th)) {
		CERROR("%s: can't sync\n", d->opd_obd->obd_name);
		return;
	}
	rc = dt_trans_start_local(env, d->opd_storage, th);
	if (rc == 0) {
		CDEBUG(D_OTHER, "%s: sync forced, %d changes\n",
		       d->opd_obd->obd_name,
		       atomic_read(&d->opd_sync_changes));
		rc = osp_sync_add_commit_cb(env, d, th);
		dt_trans_stop(env, d->opd_storage, th);
	}

	dt_commit_async(env, d->opd_storage);
}
