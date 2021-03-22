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
 * lustre/osp/osp_precreate.c
 *
 * Lustre OST Proxy Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 * Author: Di Wang <di.wang@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/kthread.h>

#include <lustre_obdo.h>

#include "osp_internal.h"

/*
 * there are two specific states to take care about:
 *
 * = import is disconnected =
 *
 * = import is inactive =
 *   in this case osp_declare_create() returns an error
 *
 */

/**
 * Check whether statfs data is expired
 *
 * OSP device caches statfs data for the target, the function checks
 * whether the data is expired or not.
 *
 * \param[in] d		OSP device
 *
 * \retval		0 - not expired, 1 - expired
 */
static inline int osp_statfs_need_update(struct osp_device *d)
{
	return !ktime_before(ktime_get(), d->opd_statfs_fresh_till);
}

/*
 * OSP tries to maintain pool of available objects so that calls to create
 * objects don't block most of time
 *
 * each time OSP gets connected to OST, we should start from precreation cleanup
 */
static void osp_statfs_timer_cb(cfs_timer_cb_arg_t data)
{
	struct osp_device *d = cfs_from_timer(d, data, opd_statfs_timer);

	LASSERT(d);
	if (d->opd_pre_task)
		wake_up(&d->opd_pre_waitq);
}

static void osp_pre_update_msfs(struct osp_device *d, struct obd_statfs *msfs);

/*
 * The function updates current precreation status if broken, and
 * updates that cached statfs state if functional, then wakes up waiters.
 * We don't clear opd_pre_status directly here, but rather leave this
 * to osp_pre_update_msfs() to do if everything is OK so that we don't
 * have a race to clear opd_pre_status and then set it to -ENOSPC again.
 *
 * \param[in] d		OSP device
 * \param[in] msfs	statfs data
 * \param[in] rc	new precreate status for device \a d
 */
static void osp_pre_update_status_msfs(struct osp_device *d,
				       struct obd_statfs *msfs, int rc)
{
	if (rc)
		d->opd_pre_status = rc;
	else
		osp_pre_update_msfs(d, msfs);

	wake_up(&d->opd_pre_user_waitq);
}

/* Pass in the old statfs data in case the limits have changed */
void osp_pre_update_status(struct osp_device *d, int rc)
{
	osp_pre_update_status_msfs(d, &d->opd_statfs, rc);
}


/**
 * RPC interpret callback for OST_STATFS RPC
 *
 * An interpretation callback called by ptlrpc for OST_STATFS RPC when it is
 * replied by the target. It's used to maintain statfs cache for the target.
 * The function fills data from the reply if successful and schedules another
 * update.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] req	RPC replied
 * \param[in] aa	callback data
 * \param[in] rc	RPC result
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
static int osp_statfs_interpret(const struct lu_env *env,
				struct ptlrpc_request *req, void *args, int rc)
{
	union ptlrpc_async_args *aa = args;
	struct obd_import *imp = req->rq_import;
	struct obd_statfs *msfs;
	struct obd_statfs *sfs;
	struct osp_device *d;
	u64 maxage_ns;

	ENTRY;

	aa = ptlrpc_req_async_args(aa, req);
	d = aa->pointer_arg[0];
	LASSERT(d);

	if (rc != 0)
		GOTO(out, rc);

	msfs = req_capsule_server_get(&req->rq_pill, &RMF_OBD_STATFS);
	if (msfs == NULL)
		GOTO(out, rc = -EPROTO);

	if (d->opd_pre)
		osp_pre_update_status_msfs(d, msfs, 0);
	else
		d->opd_statfs = *msfs;

	/* schedule next update */
	maxage_ns = d->opd_statfs_maxage * NSEC_PER_SEC;
	d->opd_statfs_fresh_till = ktime_add_ns(ktime_get(), maxage_ns);
	mod_timer(&d->opd_statfs_timer,
		  jiffies + cfs_time_seconds(d->opd_statfs_maxage));
	d->opd_statfs_update_in_progress = 0;

	sfs = &d->opd_statfs;
	CDEBUG(D_CACHE, "%s (%p): %llu blocks, %llu free, %llu avail, "
	       "%u bsize, %u reserved mb low, %u reserved mb high,"
	       "%llu files, %llu free files\n", d->opd_obd->obd_name, d,
	       sfs->os_blocks, sfs->os_bfree, sfs->os_bavail, sfs->os_bsize,
	       d->opd_reserved_mb_low, d->opd_reserved_mb_high,
	       sfs->os_files, sfs->os_ffree);

	RETURN(0);
out:
	/* couldn't update statfs, try again with a small delay */
	d->opd_statfs_fresh_till = ktime_add_ns(ktime_get(), 10 * NSEC_PER_SEC);
	d->opd_statfs_update_in_progress = 0;
	if (d->opd_pre && d->opd_pre_task)
		wake_up(&d->opd_pre_waitq);

	if (req->rq_import_generation == imp->imp_generation)
		CDEBUG(D_CACHE, "%s: couldn't update statfs: rc = %d\n",
		       d->opd_obd->obd_name, rc);
	RETURN(rc);
}

/**
 * Send OST_STATFS RPC
 *
 * Sends OST_STATFS RPC to refresh cached statfs data for the target.
 * Also disables scheduled updates as times OSP may need to refresh
 * statfs data before expiration. The function doesn't block, instead
 * an interpretation callback osp_statfs_interpret() is used.
 *
 * \param[in] d		OSP device
 */
static int osp_statfs_update(const struct lu_env *env, struct osp_device *d)
{
	u64 expire = obd_timeout * 1000 * NSEC_PER_SEC;
	struct ptlrpc_request	*req;
	struct obd_import	*imp;
	union ptlrpc_async_args	*aa;
	int rc;

	ENTRY;

	CDEBUG(D_CACHE, "going to update statfs\n");

	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp,
			   d->opd_pre ? &RQF_OST_STATFS : &RQF_MDS_STATFS);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req,
			 d->opd_pre ? LUSTRE_OST_VERSION : LUSTRE_MDS_VERSION,
			 d->opd_pre ? OST_STATFS : MDS_STATFS);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}
	ptlrpc_request_set_replen(req);
	if (d->opd_pre)
		req->rq_request_portal = OST_CREATE_PORTAL;
	ptlrpc_at_set_req_timeout(req);

	req->rq_interpret_reply = osp_statfs_interpret;
	aa = ptlrpc_req_async_args(aa, req);
	aa->pointer_arg[0] = d;

	/*
	 * no updates till reply
	 */
	del_timer(&d->opd_statfs_timer);
	d->opd_statfs_fresh_till = ktime_add_ns(ktime_get(), expire);
	d->opd_statfs_update_in_progress = 1;

	ptlrpcd_add_req(req);

	/* we still want to sync changes if no new changes are coming */
	if (ktime_before(ktime_get(), d->opd_sync_next_commit_cb))
		GOTO(out, rc);

	if (atomic_read(&d->opd_sync_changes)) {
		struct thandle *th;

		th = dt_trans_create(env, d->opd_storage);
		if (IS_ERR(th)) {
			CERROR("%s: can't sync\n", d->opd_obd->obd_name);
			GOTO(out, rc);
		}
		rc = dt_trans_start_local(env, d->opd_storage, th);
		if (rc == 0) {
			CDEBUG(D_OTHER, "%s: sync forced, %d changes\n",
			       d->opd_obd->obd_name,
			       atomic_read(&d->opd_sync_changes));
			osp_sync_add_commit_cb_1s(env, d, th);
			dt_trans_stop(env, d->opd_storage, th);
		}
	}

out:
	RETURN(0);
}

/**
 * Schedule an immediate update for statfs data
 *
 * If cached statfs data claim no free space, but OSP has got a request to
 * destroy an object (so release some space probably), then we may need to
 * refresh cached statfs data sooner than planned. The function checks there
 * is no statfs update going and schedules immediate update if so.
 * XXX: there might be a case where removed object(s) do not add free space (empty
 * object). If the number of such deletions is high, then we can start to update
 * statfs too often causing a RPC storm. some throttling is needed...
 *
 * \param[in] d		OSP device where statfs data needs to be refreshed
 */
void osp_statfs_need_now(struct osp_device *d)
{
	if (!d->opd_statfs_update_in_progress) {
		/*
		 * if current status is -ENOSPC (lack of free space on OST)
		 * then we should poll OST immediately once object destroy
		 * is replied
		 */
		d->opd_statfs_fresh_till = ktime_sub_ns(ktime_get(), NSEC_PER_SEC);
		del_timer(&d->opd_statfs_timer);
		wake_up(&d->opd_pre_waitq);
	}
}

/**
 * Return number of precreated objects
 *
 * A simple helper to calculate the number of precreated objects on the device.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] osp	OSP device
 *
 * \retval		the number of the precreated objects
 */
static inline int osp_objs_precreated(const struct lu_env *env,
				      struct osp_device *osp)
{
	return osp_fid_diff(&osp->opd_pre_last_created_fid,
			    &osp->opd_pre_used_fid);
}

/**
 * Check pool of precreated objects is nearly empty
 *
 * We should not wait till the pool of the precreated objects is exhausted,
 * because then there will be a long period of OSP being unavailable for the
 * new creations due to lenghty precreate RPC. Instead we ask for another
 * precreation ahead and hopefully have it ready before the current pool is
 * empty. Notice this function relies on an external locking.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 *
 * \retval		0 - current pool is good enough, 1 - time to precreate
 */
static inline int osp_precreate_near_empty_nolock(const struct lu_env *env,
						  struct osp_device *d)
{
	int window = osp_objs_precreated(env, d);

	/* don't consider new precreation till OST is healty and
	 * has free space */
	return ((window - d->opd_pre_reserved < d->opd_pre_create_count / 2) &&
		(d->opd_pre_status == 0));
}

/**
 * Check pool of precreated objects
 *
 * This is protected version of osp_precreate_near_empty_nolock(), check that
 * for the details.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 *
 * \retval		0 - current pool is good enough, 1 - time to precreate
 */
static inline int osp_precreate_near_empty(const struct lu_env *env,
					   struct osp_device *d)
{
	int rc;

	if (d->opd_pre == NULL)
		return 0;

	/* XXX: do we really need locking here? */
	spin_lock(&d->opd_pre_lock);
	rc = osp_precreate_near_empty_nolock(env, d);
	spin_unlock(&d->opd_pre_lock);
	return rc;
}

/**
 * Check given sequence is empty
 *
 * Returns a binary result whether the given sequence has some IDs left
 * or not. Find the details in osp_fid_end_seq(). This is a lock protected
 * version of that function.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] osp	OSP device
 *
 * \retval		0 - current sequence has no IDs, 1 - otherwise
 */
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
 * Write FID into into last_oid/last_seq file
 *
 * The function stores the sequence and the in-sequence id into two dedicated
 * files. The sync argument can be used to request synchronous commit, so the
 * function won't return until the updates are committed.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] osp	OSP device
 * \param[in] fid	fid where sequence/id is taken
 * \param[in] sync	update mode: 0 - asynchronously, 1 - synchronously
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 **/
int osp_write_last_oid_seq_files(struct lu_env *env, struct osp_device *osp,
				 struct lu_fid *fid, int sync)
{
	struct osp_thread_info  *oti = osp_env_info(env);
	struct lu_buf	   *lb_oid = &oti->osi_lb;
	struct lu_buf	   *lb_oseq = &oti->osi_lb2;
	loff_t		   oid_off;
	u64		   oid;
	loff_t		   oseq_off;
	struct thandle	  *th;
	int		      rc;
	ENTRY;

	if (osp->opd_storage->dd_rdonly)
		RETURN(0);

	/* Note: through f_oid is only 32 bits, it will also write 64 bits
	 * for oid to keep compatibility with the previous version. */
	oid = fid->f_oid;
	osp_objid_buf_prep(lb_oid, &oid_off,
			   &oid, osp->opd_index);

	osp_objseq_buf_prep(lb_oseq, &oseq_off,
			    &fid->f_seq, osp->opd_index);

	th = dt_trans_create(env, osp->opd_storage);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	th->th_sync |= sync;
	rc = dt_declare_record_write(env, osp->opd_last_used_oid_file,
				     lb_oid, oid_off, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_declare_record_write(env, osp->opd_last_used_seq_file,
				     lb_oseq, oseq_off, th);
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

/**
 * Switch to another sequence
 *
 * When a current sequence has no available IDs left, OSP has to switch to
 * another new sequence. OSP requests it using the regular FLDB protocol
 * and stores synchronously before that is used in precreated. This is needed
 * to basically have the sequences referenced (not orphaned), otherwise it's
 * possible that OST has some objects precreated and the clients have data
 * written to it, but after MDT failover nobody refers those objects and OSP
 * has no idea that the sequence need cleanup to be done.
 * While this is very expensive operation, it's supposed to happen very very
 * infrequently because sequence has 2^32 or 2^48 objects (depending on type)
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] osp	OSP device
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
static int osp_precreate_rollover_new_seq(struct lu_env *env,
					  struct osp_device *osp)
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

	LCONSOLE_INFO("%s: update sequence from %#llx to %#llx\n",
		      osp->opd_obd->obd_name, fid_seq(last_fid),
		      fid_seq(fid));
	/* Update last_xxx to the new seq */
	spin_lock(&osp->opd_pre_lock);
	osp->opd_last_used_fid = *fid;
	osp_fid_to_obdid(fid, &osp->opd_last_id);
	osp->opd_gap_start_fid = *fid;
	osp->opd_pre_used_fid = *fid;
	osp->opd_pre_last_created_fid = *fid;
	spin_unlock(&osp->opd_pre_lock);

	RETURN(rc);
}

/**
 * Find IDs available in current sequence
 *
 * The function calculates the highest possible ID and the number of IDs
 * available in the current sequence OSP is using. The number is limited
 * artifically by the caller (grow param) and the number of IDs available
 * in the sequence by nature. The function doesn't require an external
 * locking.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] osp	OSP device
 * \param[in] fid	FID the caller wants to start with
 * \param[in] grow	how many the caller wants
 * \param[out] fid	the highest calculated FID
 * \param[out] grow	the number of available IDs calculated
 *
 * \retval		0 on success, 1 - the sequence is empty
 */
static int osp_precreate_fids(const struct lu_env *env, struct osp_device *osp,
			      struct lu_fid *fid, int *grow)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	__u64			end;
	int			i = 0;

	if (fid_is_idif(fid)) {
		struct lu_fid	*last_fid;
		struct ost_id	*oi = &osi->osi_oi;
		int rc;

		spin_lock(&osp->opd_pre_lock);
		last_fid = &osp->opd_pre_last_created_fid;
		fid_to_ostid(last_fid, oi);
		end = min(ostid_id(oi) + *grow, IDIF_MAX_OID);
		*grow = end - ostid_id(oi);
		rc = ostid_set_id(oi, ostid_id(oi) + *grow);
		spin_unlock(&osp->opd_pre_lock);

		if (*grow == 0 || rc)
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

/**
 * Prepare and send precreate RPC
 *
 * The function finds how many objects should be precreated.  Then allocates,
 * prepares and schedules precreate RPC synchronously. Upon reply the function
 * wakes up the threads waiting for the new objects on this target. If the
 * target wasn't able to create all the objects requested, then the next
 * precreate will be asking for fewer objects (i.e. slow precreate down).
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 **/
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
	if (d->opd_pre_create_count > d->opd_pre_max_create_count / 2)
		d->opd_pre_create_count = d->opd_pre_max_create_count / 2;
	grow = d->opd_pre_create_count;
	spin_unlock(&d->opd_pre_lock);

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);

	*fid = d->opd_pre_last_created_fid;
	rc = osp_precreate_fids(env, d, fid, &grow);
	if (rc == 1)
		/* Current seq has been used up*/
		GOTO(out_req, rc = -ENOSPC);

	if (!osp_is_fid_client(d)) {
		/* Non-FID client will always send seq 0 because of
		 * compatiblity */
		LASSERTF(fid_is_idif(fid), "Invalid fid "DFID"\n", PFID(fid));
		fid->f_seq = 0;
	}

	fid_to_ostid(fid, &body->oa.o_oi);
	body->oa.o_valid = OBD_MD_FLGROUP;

	ptlrpc_request_set_replen(req);

	if (OBD_FAIL_CHECK(OBD_FAIL_OSP_FAKE_PRECREATE))
		GOTO(ready, rc = 0);

	rc = ptlrpc_queue_wait(req);
	if (rc) {
		CERROR("%s: can't precreate: rc = %d\n", d->opd_obd->obd_name,
		       rc);
		if (req->rq_net_err)
			/* have osp_precreate_reserve() to wait for repeat */
			rc = -ENOTCONN;
		GOTO(out_req, rc);
	}
	LASSERT(req->rq_transno == 0);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out_req, rc = -EPROTO);

	ostid_to_fid(fid, &body->oa.o_oi, d->opd_index);

ready:
	if (osp_fid_diff(fid, &d->opd_pre_used_fid) <= 0) {
		CERROR("%s: precreate fid "DFID" <= local used fid "DFID
		       ": rc = %d\n", d->opd_obd->obd_name,
		       PFID(fid), PFID(&d->opd_pre_used_fid), -ESTALE);
		GOTO(out_req, rc = -ESTALE);
	}

	diff = osp_fid_diff(fid, &d->opd_pre_last_created_fid);

	spin_lock(&d->opd_pre_lock);
	if (diff < grow) {
		/* the OST has not managed to create all the
		 * objects we asked for */
		d->opd_pre_create_count = max(diff, OST_MIN_PRECREATE);
		d->opd_pre_create_slow = 1;
	} else {
		/* the OST is able to keep up with the work,
		 * we could consider increasing create_count
		 * next time if needed */
		d->opd_pre_create_slow = 0;
	}

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	fid_to_ostid(fid, &body->oa.o_oi);

	d->opd_pre_last_created_fid = *fid;
	spin_unlock(&d->opd_pre_lock);

	CDEBUG(D_HA, "%s: current precreated pool: "DFID"-"DFID"\n",
	       d->opd_obd->obd_name, PFID(&d->opd_pre_used_fid),
	       PFID(&d->opd_pre_last_created_fid));
out_req:
	/* now we can wakeup all users awaiting for objects */
	osp_pre_update_status(d, rc);
	wake_up(&d->opd_pre_user_waitq);

	/* pause to let osp_precreate_reserve to go first */
	CFS_FAIL_TIMEOUT(OBD_FAIL_OSP_PRECREATE_PAUSE, 2);

	ptlrpc_req_finished(req);
	RETURN(rc);
}

/**
 * Get last precreated object from target (OST)
 *
 * Sends synchronous RPC to the target (OST) to learn the last precreated
 * object. This later is used to remove all unused objects (cleanup orphan
 * procedure). Also, the next object after one we got will be used as a
 * starting point for the new precreates.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 **/
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

	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_KEY, RCL_CLIENT,
			     sizeof(KEY_LAST_FID));

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GET_INFO);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_GETINFO_KEY);
	memcpy(tmp, KEY_LAST_FID, sizeof(KEY_LAST_FID));

	req->rq_no_delay = req->rq_no_resend = 1;
	last_fid = req_capsule_client_get(&req->rq_pill, &RMF_FID);
	fid_cpu_to_le(last_fid, &d->opd_last_used_fid);

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
 * Cleanup orphans on OST
 *
 * This function is called in a contex of a dedicated thread handling
 * all the precreation suff. The function waits till local recovery
 * is complete, then identify all the unreferenced objects (orphans)
 * using the highest ID referenced by a local and the highest object
 * precreated by the target. The found range is a subject to removal
 * using specially flagged RPC. During this process OSP is marked
 * unavailable for new objects.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
static int osp_precreate_cleanup_orphans(struct lu_env *env,
					 struct osp_device *d)
{
	struct osp_thread_info	*osi = osp_env_info(env);
	struct lu_fid		*last_fid = &osi->osi_fid;
	struct ptlrpc_request	*req = NULL;
	struct obd_import	*imp;
	struct ost_body		*body;
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
	wait_event_idle(d->opd_pre_waitq,
			(!d->opd_pre_reserved && d->opd_recovery_completed) ||
			!d->opd_pre_task || d->opd_got_disconnected);
	if (!d->opd_pre_task || d->opd_got_disconnected)
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
		d->opd_pre_create_count = OST_MIN_PRECREATE + diff;
		d->opd_pre_last_created_fid = d->opd_last_used_fid;
	} else {
		d->opd_pre_create_count = OST_MIN_PRECREATE;
		d->opd_pre_last_created_fid = *last_fid;
	}
	/*
	 * This empties the pre-creation pool and effectively blocks any new
	 * reservations.
	 */
	LASSERT(fid_oid(&d->opd_pre_last_created_fid) <=
		LUSTRE_DATA_SEQ_MAX_WIDTH);
	d->opd_pre_used_fid = d->opd_pre_last_created_fid;
	d->opd_pre_create_slow = 0;
	spin_unlock(&d->opd_pre_lock);

	CDEBUG(D_HA, "%s: Got last_id "DFID" from OST, last_created "DFID
	       "last_used is "DFID"\n", d->opd_obd->obd_name, PFID(last_fid),
	       PFID(&d->opd_pre_last_created_fid), PFID(&d->opd_last_used_fid));
out:
	if (req)
		ptlrpc_req_finished(req);

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
	} else {
		spin_lock(&d->opd_pre_lock);
		d->opd_pre_recovering = 0;
		spin_unlock(&d->opd_pre_lock);
	}

	RETURN(rc);
}

/**
 * Update precreate status using statfs data
 *
 * The function decides whether this OSP should be used for new objects.
 * IOW, whether this OST is used up or has some free space. Cached statfs
 * data is used to make this decision. If the latest result of statfs
 * request (rc argument) is not success, then just mark OSP unavailable
 * right away.
 *
 * The new statfs data is passed in \a msfs and needs to be stored into
 * opd_statfs, but only after the various flags in os_state are set, so
 * that the new statfs data is not visible without appropriate flags set.
 * As such, there is no need to clear the flags here, since this is called
 * with new statfs data, and they should not be cleared if sent from OST.
 *
 * Add a bit of hysteresis so this flag isn't continually flapping, and
 * ensure that new files don't get extremely fragmented due to only a
 * small amount of available space in the filesystem.  We want to set
 * the ENOSPC/ENOINO flags unconditionally when there is less than the
 * reserved size free, and still copy them from the old state when there
 * is less than 2*reserved size free space or inodes.
 *
 * \param[in] d		OSP device
 * \param[in] msfs	statfs data
 */
static void osp_pre_update_msfs(struct osp_device *d, struct obd_statfs *msfs)
{
	u32 old_state = d->opd_statfs.os_state;
	u32 reserved_ino_low = 32;	/* could be tunable in the future */
	u32 reserved_ino_high = reserved_ino_low * 2;
	u64 available_mb;

	/* statfs structure not initialized yet */
	if (unlikely(!msfs->os_type))
		return;

	/* if the low and high watermarks have not been initialized yet */
	if (unlikely(d->opd_reserved_mb_high == 0 &&
		     d->opd_reserved_mb_low == 0)) {
		/* Use ~0.1% by default to disable object allocation,
		 * and ~0.2% to enable, size in MB, set both watermark
		 */
		spin_lock(&d->opd_pre_lock);
		if (d->opd_reserved_mb_high == 0 &&
		    d->opd_reserved_mb_low == 0) {
			d->opd_reserved_mb_low = ((msfs->os_bsize >> 10) *
						  msfs->os_blocks) >> 20;
			if (d->opd_reserved_mb_low == 0)
				d->opd_reserved_mb_low = 1;
			d->opd_reserved_mb_high =
				(d->opd_reserved_mb_low << 1) + 1;
		}
		spin_unlock(&d->opd_pre_lock);
	}

	available_mb = (msfs->os_bavail * (msfs->os_bsize >> 10)) >> 10;
	if (msfs->os_ffree < reserved_ino_low)
		msfs->os_state |= OS_STATFS_ENOINO;
	else if (msfs->os_ffree <= reserved_ino_high)
		msfs->os_state |= old_state & OS_STATFS_ENOINO;
	/* else don't clear flags in new msfs->os_state sent from OST */

	CDEBUG(D_INFO,
	       "%s: blocks=%llu free=%llu avail=%llu avail_mb=%llu hwm_mb=%u files=%llu ffree=%llu state=%x: rc = %d\n",
	       d->opd_obd->obd_name, msfs->os_blocks, msfs->os_bfree,
	       msfs->os_bavail, available_mb, d->opd_reserved_mb_high,
	       msfs->os_files, msfs->os_ffree, msfs->os_state,
	       d->opd_pre_status);
	if (available_mb < d->opd_reserved_mb_low)
		msfs->os_state |= OS_STATFS_ENOSPC;
	else if (available_mb <= d->opd_reserved_mb_high)
		msfs->os_state |= old_state & OS_STATFS_ENOSPC;
	/* else don't clear flags in new msfs->os_state sent from OST */

	if (msfs->os_state & (OS_STATFS_ENOINO | OS_STATFS_ENOSPC)) {
		d->opd_pre_status = -ENOSPC;
		if (!(old_state & (OS_STATFS_ENOINO | OS_STATFS_ENOSPC)))
			CDEBUG(D_INFO, "%s: full: state=%x: rc = %x\n",
			       d->opd_obd->obd_name, msfs->os_state,
			       d->opd_pre_status);
		CDEBUG(D_INFO, "uncommitted changes=%u in_progress=%u\n",
		       atomic_read(&d->opd_sync_changes),
		       atomic_read(&d->opd_sync_rpcs_in_progress));
	} else if (old_state & (OS_STATFS_ENOINO | OS_STATFS_ENOSPC)) {
		d->opd_pre_status = 0;
		spin_lock(&d->opd_pre_lock);
		d->opd_pre_create_slow = 0;
		d->opd_pre_create_count = OST_MIN_PRECREATE;
		spin_unlock(&d->opd_pre_lock);
		wake_up(&d->opd_pre_waitq);

		CDEBUG(D_INFO,
		       "%s: available: state=%x: rc = %d\n",
		       d->opd_obd->obd_name, msfs->os_state,
		       d->opd_pre_status);
	} else {
		/* we only get here if rc == 0 in the caller */
		d->opd_pre_status = 0;
	}

	/* Object precreation skipped on OST if manually disabled */
	if (d->opd_pre_max_create_count == 0)
		msfs->os_state |= OS_STATFS_NOPRECREATE;
	/* else don't clear flags in new msfs->os_state sent from OST */

	/* copy only new statfs state to make it visible to MDS threads */
	if (&d->opd_statfs != msfs)
		d->opd_statfs = *msfs;
}

/**
 * Initialize FID for precreation
 *
 * For a just created new target, a new sequence should be taken.
 * The function checks there is no IDIF in use (if the target was
 * added with the older version of Lustre), then requests a new
 * sequence from FLDB using the regular protocol. Then this new
 * sequence is stored on a persisten storage synchronously to prevent
 * possible object leakage (for the detail see the description for
 * osp_precreate_rollover_new_seq()).
 *
 * \param[in] osp	OSP device
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
int osp_init_pre_fid(struct osp_device *osp)
{
	struct lu_env		env;
	struct osp_thread_info	*osi;
	struct lu_client_seq	*cli_seq;
	struct lu_fid		*last_fid;
	int			rc;
	ENTRY;

	LASSERT(osp->opd_pre != NULL);

	/* Let's check if the current last_seq/fid is valid,
	 * otherwise request new sequence from the controller */
	if (osp_is_fid_client(osp) && osp->opd_group != 0) {
		/* Non-MDT0 can only use normal sequence for
		 * OST objects */
		if (fid_is_norm(&osp->opd_last_used_fid))
			RETURN(0);
	} else {
		/* Initially MDT0 will start with IDIF, after
		 * that it will request new sequence from the
		 * controller */
		if (fid_is_idif(&osp->opd_last_used_fid) ||
		    fid_is_norm(&osp->opd_last_used_fid))
			RETURN(0);
	}

	if (!fid_is_zero(&osp->opd_last_used_fid))
		CWARN("%s: invalid last used fid "DFID
		      ", try to get new sequence.\n",
		      osp->opd_obd->obd_name,
		      PFID(&osp->opd_last_used_fid));

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

struct opt_args {
	struct osp_device	*opta_dev;
	struct lu_env		opta_env;
	struct completion	*opta_started;
};
/**
 * The core of precreate functionality
 *
 * The function implements the main precreation loop. Basically it
 * involves connecting to the target, precerate FID initialization,
 * identifying and removing orphans, then serving precreation. As
 * part of the latter, the thread is responsible for statfs data
 * updates. The precreation is mostly driven by another threads
 * asking for new OST objects - those askers wake the thread when
 * the number of precreated objects reach low watermark.
 * After a disconnect, the sequence above repeats. This is keep going
 * until the thread is requested to stop.
 *
 * \param[in] _arg	private data the thread (OSP device to handle)
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
static int osp_precreate_thread(void *_args)
{
	struct opt_args		*args = _args;
	struct osp_device	*d = args->opta_dev;
	struct lu_env		*env = &args->opta_env;
	int			 rc;

	ENTRY;

	complete(args->opta_started);
	while (!kthread_should_stop()) {
		/*
		 * need to be connected to OST
		 */
		while (!kthread_should_stop()) {
			if ((d->opd_pre == NULL || d->opd_pre_recovering) &&
			    d->opd_imp_connected &&
			    !d->opd_got_disconnected)
				break;
			wait_event_idle(d->opd_pre_waitq,
					kthread_should_stop() ||
					d->opd_new_connection);

			if (!d->opd_new_connection)
				continue;

			OBD_FAIL_TIMEOUT(OBD_FAIL_OSP_CON_EVENT_DELAY,
					 cfs_fail_val);
			d->opd_new_connection = 0;
			d->opd_got_disconnected = 0;
			break;
		}

		if (kthread_should_stop())
			break;

		if (d->opd_pre) {
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
		}

		if (osp_statfs_update(env, d)) {
			if (wait_event_idle_timeout(d->opd_pre_waitq,
						    kthread_should_stop(),
						    cfs_time_seconds(5)) == 0)
				l_wait_event_abortable(
					d->opd_pre_waitq,
					kthread_should_stop());
			continue;
		}

		if (d->opd_pre) {
			/*
			 * Clean up orphans or recreate missing objects.
			 */
			rc = osp_precreate_cleanup_orphans(env, d);
			if (rc != 0) {
				schedule_timeout_interruptible(cfs_time_seconds(1));
				continue;
			}
		}

		/*
		 * connected, can handle precreates now
		 */
		while (!kthread_should_stop()) {
			wait_event_idle(d->opd_pre_waitq,
					kthread_should_stop() ||
					osp_precreate_near_empty(env, d) ||
					osp_statfs_need_update(d) ||
					d->opd_got_disconnected);

			if (kthread_should_stop())
				break;

			/* something happened to the connection
			 * have to start from the beginning */
			if (d->opd_got_disconnected)
				break;

			if (osp_statfs_need_update(d))
				if (osp_statfs_update(env, d))
					break;

			if (d->opd_pre == NULL)
				continue;

			/* To avoid handling different seq in precreate/orphan
			 * cleanup, it will hold precreate until current seq is
			 * used up. */
			if (unlikely(osp_precreate_end_seq(env, d) &&
			    !osp_create_end_seq(env, d)))
				continue;

			if (unlikely(osp_precreate_end_seq(env, d) &&
				     osp_create_end_seq(env, d))) {
				LCONSOLE_INFO("%s:%#llx is used up."
					      " Update to new seq\n",
					      d->opd_obd->obd_name,
					 fid_seq(&d->opd_pre_last_created_fid));
				rc = osp_precreate_rollover_new_seq(env, d);
				if (rc)
					continue;
			}

			if (osp_precreate_near_empty(env, d)) {
				rc = osp_precreate_send(env, d);
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

	lu_env_fini(env);
	OBD_FREE_PTR(args);

	RETURN(0);
}

/**
 * Check when to stop to wait for precreate objects.
 *
 * The caller wanting a new OST object can't wait undefinitely. The
 * function checks for few conditions including available new OST
 * objects, disconnected OST, lack of space with no pending destroys,
 * etc. IOW, it checks whether the current OSP state is good to keep
 * waiting or it's better to give up.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 *
 * \retval		0 - keep waiting, 1 - no luck
 */
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
	if (atomic_read(&d->opd_sync_changes) +
	    atomic_read(&d->opd_sync_rpcs_in_progress) == 0 &&
	    d->opd_pre_status == -ENOSPC)
		return 1;

	/* Bail out I/O fails to OST */
	if (d->opd_pre_status != 0 &&
	    d->opd_pre_status != -EAGAIN &&
	    d->opd_pre_status != -ENODEV &&
	    d->opd_pre_status != -ENOTCONN &&
	    d->opd_pre_status != -ENOSPC) {
		/* DEBUG LU-3230 */
		if (d->opd_pre_status != -EIO)
			CERROR("%s: precreate failed opd_pre_status %d\n",
			       d->opd_obd->obd_name, d->opd_pre_status);
		return 1;
	}

	return 0;
}

/**
 * Reserve object in precreate pool
 *
 * When the caller wants to create a new object on this target (target
 * represented by the given OSP), it should declare this intention using
 * a regular ->dt_declare_create() OSD API method. Then OSP will be trying
 * to reserve an object in the existing precreated pool or wait up to
 * obd_timeout for the available object to appear in the pool (a dedicated
 * thread will be doing real precreation in background). The object can be
 * consumed later with osp_precreate_get_fid() or be released with call to
 * lu_object_put(). Notice the function doesn't reserve a specific ID, just
 * some ID. The actual ID assignment happen in osp_precreate_get_fid().
 * If the space on the target is short and there is a pending object destroy,
 * then the function forces local commit to speedup space release (see
 * osp_sync.c for the details).
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 *
 * \retval		0 on success
 * \retval		-ENOSPC when no space on OST
 * \retval		-EAGAIN try later, slow precreation in progress
 * \retval		-EIO when no access to OST
 */
int osp_precreate_reserve(const struct lu_env *env, struct osp_device *d,
			  bool can_block)
{
	time64_t expire = ktime_get_seconds() + obd_timeout;
	int precreated, rc, synced = 0;

	ENTRY;

	LASSERTF(osp_objs_precreated(env, d) >= 0, "Last created FID "DFID
		 "Next FID "DFID"\n", PFID(&d->opd_pre_last_created_fid),
		 PFID(&d->opd_pre_used_fid));

	/* opd_pre_max_create_count 0 to not use specified OST. */
	if (d->opd_pre_max_create_count == 0)
		RETURN(-ENOBUFS);

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
		if (d->opd_pre_create_count < d->opd_pre_max_create_count &&
		    d->opd_pre_create_slow == 0 &&
		    precreated <= (d->opd_pre_create_count / 4 + 1)) {
			spin_lock(&d->opd_pre_lock);
			d->opd_pre_create_slow = 1;
			d->opd_pre_create_count *= 2;
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
			if (atomic_read(&d->opd_sync_changes) && synced == 0) {
				/* force local commit to release space */
				dt_commit_async(env, d->opd_storage);
				osp_sync_check_for_work(d);
				synced = 1;
			}
			if (atomic_read(&d->opd_sync_rpcs_in_progress)) {
				/* just wait till destroys are done
				 * see wait_event_idle_timeout() below
				 */
			}
			if (atomic_read(&d->opd_sync_changes) +
			    atomic_read(&d->opd_sync_rpcs_in_progress) == 0) {
				/* no hope for free space */
				break;
			}
		}

		/* XXX: don't wake up if precreation is in progress */
		wake_up(&d->opd_pre_waitq);

		if (ktime_get_seconds() >= expire) {
			rc = -ETIMEDOUT;
			break;
		}

		if (!can_block) {
			LASSERT(d->opd_pre);
			rc = -ENOBUFS;
			break;
		}

		if (wait_event_idle_timeout(
			    d->opd_pre_user_waitq,
			    osp_precreate_ready_condition(env, d),
			    cfs_time_seconds(obd_timeout)) == 0) {
			CDEBUG(D_HA,
			       "%s: slow creates, last="DFID", next="DFID", "
			       "reserved=%llu, sync_changes=%u, "
			       "sync_rpcs_in_progress=%d, status=%d\n",
			       d->opd_obd->obd_name,
			       PFID(&d->opd_pre_last_created_fid),
			       PFID(&d->opd_pre_used_fid), d->opd_pre_reserved,
			       atomic_read(&d->opd_sync_changes),
			       atomic_read(&d->opd_sync_rpcs_in_progress),
			       d->opd_pre_status);
		}
	}

	RETURN(rc);
}

/**
 * Get a FID from precreation pool
 *
 * The function is a companion for osp_precreate_reserve() - it assigns
 * a specific FID from the precreate. The function should be called only
 * if the call to osp_precreate_reserve() was successful. The function
 * updates a local storage to remember the highest object ID referenced
 * by the node in the given sequence.
 *
 * A very importan details: this is supposed to be called once the
 * transaction is started, so on-disk update will be atomic with the
 * data (like LOVEA) refering this object. Then the object won't be leaked:
 * either it's referenced by the committed transaction or it's a subject
 * to the orphan cleanup procedure.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] d		OSP device
 * \param[out] fid	generated FID
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
int osp_precreate_get_fid(const struct lu_env *env, struct osp_device *d,
			  struct lu_fid *fid)
{
	struct lu_fid *pre_used_fid = &d->opd_pre_used_fid;
	/* grab next id from the pool */
	spin_lock(&d->opd_pre_lock);

	LASSERTF(osp_fid_diff(&d->opd_pre_used_fid,
			     &d->opd_pre_last_created_fid) < 0,
		 "next fid "DFID" last created fid "DFID"\n",
		 PFID(&d->opd_pre_used_fid),
		 PFID(&d->opd_pre_last_created_fid));

	/*
	 * When sequence is used up, new one should be allocated in
	 * osp_precreate_rollover_new_seq. So ASSERT here to avoid
	 * objid overflow.
	 */
	LASSERTF(osp_fid_end_seq(env, pre_used_fid) == 0,
		 "next fid "DFID" last created fid "DFID"\n",
		 PFID(&d->opd_pre_used_fid),
		 PFID(&d->opd_pre_last_created_fid));
	/* Non IDIF fids shoulnd't get here with oid == 0xFFFFFFFF. */
	if (fid_is_idif(pre_used_fid) &&
	    unlikely(fid_oid(pre_used_fid) == LUSTRE_DATA_SEQ_MAX_WIDTH))
		pre_used_fid->f_seq++;

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
	if (unlikely(d->opd_pre_reserved == 0 &&
		     (d->opd_pre_recovering || d->opd_pre_status)))
		wake_up(&d->opd_pre_waitq);

	return 0;
}

/*
 * Set size regular attribute on an object
 *
 * When a striping is created late, it's possible that size is already
 * initialized on the file. Then the new striping should inherit size
 * from the file. The function sets size on the object using the regular
 * protocol (OST_PUNCH).
 * XXX: should be re-implemented using OUT ?
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] dt	object
 * \param[in] size	size to set.
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
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

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_PUNCH);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	/*
	 * XXX: decide how do we do here with resend
	 * if we don't resend, then client may see wrong file size
	 * if we do resend, then MDS thread can get stuck for quite long
	 * and if we don't resend, then client will also get -EAGAIN !!
	 * (see LU-7975 and sanity/test_27F use cases)
	 * but let's decide not to resend/delay this truncate request to OST
	 * and allow Client to decide to resend, in a less agressive way from
	 * after_reply(), by returning -EINPROGRESS instead of
	 * -EAGAIN/-EAGAIN upon return from ptlrpc_queue_wait() at the
	 * end of this routine
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
	if (rc) {
		/* -EAGAIN/-EWOULDBLOCK means OST is unreachable at the moment
		 * since we have decided not to resend/delay, but this could
		 * lead to wrong size to be seen at Client side and even process
		 * trying to open to exit/fail if not itself handling -EAGAIN.
		 * So it should be better to return -EINPROGRESS instead and
		 * leave the decision to resend at Client side in after_reply()
		 */
		if (rc == -EAGAIN) {
			rc = -EINPROGRESS;
			CDEBUG(D_HA, "returning -EINPROGRESS instead of "
			       "-EWOULDBLOCK/-EAGAIN to allow Client to "
			       "resend\n");
		} else {
			CERROR("can't punch object: %d\n", rc);
		}
	}
out:
	ptlrpc_req_finished(req);
	if (oa)
		OBD_FREE_PTR(oa);
	RETURN(rc);
}

/**
 * Initialize precreation functionality of OSP
 *
 * Prepares all the internal structures and starts the precreate thread
 *
 * \param[in] d		OSP device
 *
 * \retval 0		on success
 * \retval negative	negated errno on error
 */
int osp_init_precreate(struct osp_device *d)
{
	ENTRY;

	OBD_ALLOC_PTR(d->opd_pre);
	if (d->opd_pre == NULL)
		RETURN(-ENOMEM);

	/* initially precreation isn't ready */
	init_waitqueue_head(&d->opd_pre_user_waitq);
	d->opd_pre_status = -EAGAIN;
	fid_zero(&d->opd_pre_used_fid);
	d->opd_pre_used_fid.f_oid = 1;
	fid_zero(&d->opd_pre_last_created_fid);
	d->opd_pre_last_created_fid.f_oid = 1;
	d->opd_last_id = 0;
	d->opd_pre_reserved = 0;
	d->opd_got_disconnected = 1;
	d->opd_pre_create_slow = 0;
	d->opd_pre_create_count = OST_MIN_PRECREATE;
	d->opd_pre_min_create_count = OST_MIN_PRECREATE;
	d->opd_pre_max_create_count = OST_MAX_PRECREATE;
	d->opd_reserved_mb_high = 0;
	d->opd_reserved_mb_low = 0;

	RETURN(0);
}

/**
 * Finish precreate functionality of OSP
 *
 *
 * Asks all the activity (the thread, update timer) to stop, then
 * wait till that is done.
 *
 * \param[in] d		OSP device
 */
void osp_precreate_fini(struct osp_device *d)
{
	ENTRY;

	if (d->opd_pre == NULL)
		RETURN_EXIT;

	OBD_FREE_PTR(d->opd_pre);
	d->opd_pre = NULL;

	EXIT;
}

int osp_init_statfs(struct osp_device *d)
{
	struct task_struct	*task;
	struct opt_args		*args;
	DECLARE_COMPLETION_ONSTACK(started);
	int			rc;

	ENTRY;

	spin_lock_init(&d->opd_pre_lock);
	init_waitqueue_head(&d->opd_pre_waitq);

	/*
	 * Initialize statfs-related things
	 */
	d->opd_statfs_maxage = 5; /* defaultupdate interval */
	d->opd_statfs_fresh_till = ktime_sub_ns(ktime_get(),
						1000 * NSEC_PER_SEC);
	CDEBUG(D_OTHER, "current %lldns, fresh till %lldns\n",
	       ktime_get_ns(),
	       ktime_to_ns(d->opd_statfs_fresh_till));
	cfs_timer_setup(&d->opd_statfs_timer, osp_statfs_timer_cb,
			(unsigned long)d, 0);

	if (d->opd_storage->dd_rdonly)
		RETURN(0);

	OBD_ALLOC_PTR(args);
	if (!args)
		RETURN(0);
	args->opta_dev = d;
	args->opta_started = &started;
	rc = lu_env_init(&args->opta_env,
			 d->opd_dt_dev.dd_lu_dev.ld_type->ldt_ctx_tags);
	if (rc) {
		CERROR("%s: init env error: rc = %d\n", d->opd_obd->obd_name,
		       rc);
		OBD_FREE_PTR(args);
		RETURN(0);
	}

	/*
	 * start thread handling precreation and statfs updates
	 */
	task = kthread_create(osp_precreate_thread, args,
			      "osp-pre-%u-%u", d->opd_index, d->opd_group);
	if (IS_ERR(task)) {
		CERROR("can't start precreate thread %ld\n", PTR_ERR(task));
		lu_env_fini(&args->opta_env);
		OBD_FREE_PTR(args);
		RETURN(PTR_ERR(task));
	}
	d->opd_pre_task = task;
	wake_up_process(task);
	wait_for_completion(&started);

	RETURN(0);
}

void osp_statfs_fini(struct osp_device *d)
{
	struct task_struct *task = d->opd_pre_task;
	ENTRY;

	del_timer(&d->opd_statfs_timer);

	d->opd_pre_task = NULL;
	if (task)
		kthread_stop(task);

	EXIT;
}
