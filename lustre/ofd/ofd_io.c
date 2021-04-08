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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ofd/ofd_io.c
 *
 * This file provides functions to handle IO requests from clients and
 * also LFSCK routines to check parent file identifier (PFID) consistency.
 *
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Fan Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/kthread.h>
#include "ofd_internal.h"
#include <lustre_nodemap.h>

struct ofd_inconsistency_item {
	struct list_head	 oii_list;
	struct ofd_object	*oii_obj;
	struct filter_fid	 oii_ff;
};

/**
 * Verify single object for parent FID consistency.
 *
 * Part of LFSCK processing which checks single object PFID stored in extended
 * attribute (XATTR) against real FID of MDT parent object received by LFSCK.
 * This verifies that the OST object is being referenced by only a single MDT
 * object.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] oii	object-related local data
 * \param[in] lrl	LFSCK request data
 */
static void ofd_inconsistency_verify_one(const struct lu_env *env,
					 struct ofd_device *ofd,
					 struct ofd_inconsistency_item *oii,
					 struct lfsck_req_local *lrl)
{
	struct ofd_object *fo = oii->oii_obj;
	struct filter_fid *client_ff = &oii->oii_ff;
	struct filter_fid *local_ff = &fo->ofo_ff;
	int rc;

	LASSERT(fo->ofo_pfid_checking);
	LASSERT(!fo->ofo_pfid_verified);

	lrl->lrl_fid = fo->ofo_header.loh_fid; /* OST-object itself FID. */
	lrl->lrl_ff_client = *client_ff; /* client given PFID. */
	lrl->lrl_ff_local = *local_ff; /* OST local stored PFID. */

	rc = lfsck_in_notify_local(env, ofd->ofd_osd, lrl, NULL);
	ofd_write_lock(env, fo);
	switch (lrl->lrl_status) {
	case LPVS_INIT:
		LASSERT(rc <= 0);

		if (rc < 0)
			CDEBUG(D_LFSCK, "%s: fail to verify OST local stored "
			       "PFID xattr for "DFID", the client given PFID "
			       DFID", OST local stored PFID "DFID": rc = %d\n",
			       ofd_name(ofd), PFID(&fo->ofo_header.loh_fid),
			       PFID(&client_ff->ff_parent),
			       PFID(&local_ff->ff_parent), rc);
		else
			fo->ofo_pfid_verified = 1;
		break;
	case LPVS_INCONSISTENT:
		LASSERT(rc != 0);

		ofd->ofd_inconsistency_self_detected++;
		if (rc < 0)
			CDEBUG(D_LFSCK, "%s: fail to verify the client given "
			       "PFID for "DFID", the client given PFID "DFID
			       ", local stored PFID "DFID": rc = %d\n",
			       ofd_name(ofd), PFID(&fo->ofo_header.loh_fid),
			       PFID(&client_ff->ff_parent),
			       PFID(&local_ff->ff_parent), rc);
		else
			CDEBUG(D_LFSCK, "%s: both the client given PFID and "
			       "the OST local stored PFID are stale for the "
			       "OST-object "DFID", client given PFID is "DFID
			       ", local stored PFID is "DFID"\n",
			       ofd_name(ofd), PFID(&fo->ofo_header.loh_fid),
			       PFID(&client_ff->ff_parent),
			       PFID(&local_ff->ff_parent));
		break;
	case LPVS_INCONSISTENT_TOFIX:
		ofd->ofd_inconsistency_self_detected++;
		if (rc == 0) {
			ofd->ofd_inconsistency_self_repaired++;
			CDEBUG(D_LFSCK, "%s: fixed the staled OST PFID xattr "
			       "for "DFID", with the client given PFID "DFID
			       ", the old stored PFID "DFID"\n",
			       ofd_name(ofd), PFID(&fo->ofo_header.loh_fid),
			       PFID(&client_ff->ff_parent),
			       PFID(&local_ff->ff_parent));
		} else if (rc < 0) {
			CDEBUG(D_LFSCK, "%s: fail to fix the OST PFID xattr "
			       "for "DFID", client given PFID "DFID", local "
			       "stored PFID "DFID": rc = %d\n",
			       ofd_name(ofd), PFID(&fo->ofo_header.loh_fid),
			       PFID(&client_ff->ff_parent),
			       PFID(&local_ff->ff_parent), rc);
		}
		local_ff->ff_parent = client_ff->ff_parent;
		fo->ofo_pfid_verified = 1;
		break;
	default:
		break;
	}
	fo->ofo_pfid_checking = 0;
	ofd_write_unlock(env, fo);

	ofd_object_put(env, fo);
	OBD_FREE_PTR(oii);
}

struct oivm_args {
	struct ofd_device	*od_ofd;
	struct lu_env		od_env;
	struct lfsck_req_local	od_lrl;
	struct completion	*od_started;
};

#ifndef TASK_IDLE
#define TASK_IDLE TASK_INTERRUPTIBLE
#endif

/**
 * Verification thread to check parent FID consistency.
 *
 * Kernel thread to check consistency of parent FID for any
 * new item added for checking by ofd_add_inconsistency_item().
 *
 * \param[in] args	OFD device
 *
 * \retval		0 on successful thread termination
 * \retval		negative value if thread can't start
 */
static int ofd_inconsistency_verification_main(void *_args)
{
	struct oivm_args *args = _args;
	struct lu_env *env = &args->od_env;
	struct ofd_device *ofd = args->od_ofd;
	struct ofd_inconsistency_item *oii;
	struct lfsck_req_local *lrl = &args->od_lrl;
	ENTRY;

	lrl->lrl_event = LEL_PAIRS_VERIFY_LOCAL;
	lrl->lrl_active = LFSCK_TYPE_LAYOUT;
	complete(args->od_started);

	spin_lock(&ofd->ofd_inconsistency_lock);
	while (({set_current_state(TASK_IDLE);
		 !kthread_should_stop(); })) {

		while (!list_empty(&ofd->ofd_inconsistency_list)) {
			__set_current_state(TASK_RUNNING);
			oii = list_entry(ofd->ofd_inconsistency_list.next,
					 struct ofd_inconsistency_item,
					 oii_list);
			list_del_init(&oii->oii_list);
			spin_unlock(&ofd->ofd_inconsistency_lock);
			ofd_inconsistency_verify_one(env, ofd, oii, lrl);
			spin_lock(&ofd->ofd_inconsistency_lock);
		}

		spin_unlock(&ofd->ofd_inconsistency_lock);
		schedule();
		spin_lock(&ofd->ofd_inconsistency_lock);
	}
	__set_current_state(TASK_RUNNING);

	while (!list_empty(&ofd->ofd_inconsistency_list)) {
		struct ofd_object *fo;

		oii = list_entry(ofd->ofd_inconsistency_list.next,
				 struct ofd_inconsistency_item,
				 oii_list);
		list_del_init(&oii->oii_list);
		fo = oii->oii_obj;
		spin_unlock(&ofd->ofd_inconsistency_lock);

		ofd_write_lock(env, fo);
		fo->ofo_pfid_checking = 0;
		ofd_write_unlock(env, fo);

		ofd_object_put(env, fo);
		OBD_FREE_PTR(oii);
		spin_lock(&ofd->ofd_inconsistency_lock);
	}

	spin_unlock(&ofd->ofd_inconsistency_lock);

	lu_env_fini(&args->od_env);
	OBD_FREE_PTR(args);
	return 0;
}

/**
 * Start parent FID verification thread.
 *
 * See ofd_inconsistency_verification_main().
 *
 * \param[in] ofd	OFD device
 *
 * \retval		0 on successful start of thread
 * \retval		negative value on error
 */
int ofd_start_inconsistency_verification_thread(struct ofd_device *ofd)
{
	struct task_struct	*task;
	struct oivm_args	*args;
	DECLARE_COMPLETION_ONSTACK(started);
	int			 rc;

	if (ofd->ofd_inconsistency_task)
		return -EALREADY;

	OBD_ALLOC_PTR(args);
	if (!args)
		return -ENOMEM;
	rc = lu_env_init(&args->od_env, LCT_DT_THREAD);
	if (rc) {
		OBD_FREE_PTR(args);
		return rc;
	}

	args->od_ofd = ofd;
	args->od_started = &started;
	task = kthread_create(ofd_inconsistency_verification_main, args,
			      "inconsistency_verification");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start self_repair thread: rc = %d\n",
		       ofd_name(ofd), rc);
	} else {
		rc = 0;
		spin_lock(&ofd->ofd_inconsistency_lock);
		if (ofd->ofd_inconsistency_task)
			rc = -EALREADY;
		else
			ofd->ofd_inconsistency_task = task;
		spin_unlock(&ofd->ofd_inconsistency_lock);

		if (rc)
			kthread_stop(task);
		else {
			wake_up_process(task);
			wait_for_completion(&started);
		}
	}
	if (rc) {
		lu_env_fini(&args->od_env);
		OBD_FREE_PTR(args);
	}

	return rc;
}

/**
 * Stop parent FID verification thread.
 *
 * \param[in] ofd	OFD device
 *
 * \retval		0 on successful start of thread
 * \retval		-EALREADY if thread is already stopped
 */
int ofd_stop_inconsistency_verification_thread(struct ofd_device *ofd)
{
	struct task_struct *task;

	spin_lock(&ofd->ofd_inconsistency_lock);
	task = ofd->ofd_inconsistency_task;
	ofd->ofd_inconsistency_task = NULL;
	spin_unlock(&ofd->ofd_inconsistency_lock);

	if (!task)
		return -EALREADY;
	kthread_stop(task);

	return 0;
}

/**
 * Add new item for parent FID verification.
 *
 * Prepare new verification item and pass it to the dedicated
 * verification thread for further processing.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] oa	OBDO structure with PFID
 */
static void ofd_add_inconsistency_item(const struct lu_env *env,
				       struct ofd_object *fo, struct obdo *oa)
{
	struct ofd_device *ofd = ofd_obj2dev(fo);
	struct ofd_inconsistency_item *oii;
	struct filter_fid *ff;
	bool wakeup = false;

	OBD_ALLOC_PTR(oii);
	if (oii == NULL)
		return;

	INIT_LIST_HEAD(&oii->oii_list);
	lu_object_get(&fo->ofo_obj.do_lu);
	oii->oii_obj = fo;
	ff = &oii->oii_ff;
	ff->ff_parent.f_seq = oa->o_parent_seq;
	ff->ff_parent.f_oid = oa->o_parent_oid;
	ff->ff_parent.f_stripe_idx = oa->o_stripe_idx;
	ff->ff_layout = oa->o_layout;

	spin_lock(&ofd->ofd_inconsistency_lock);
	if (fo->ofo_pfid_checking || fo->ofo_pfid_verified) {
		spin_unlock(&ofd->ofd_inconsistency_lock);
		OBD_FREE_PTR(oii);

		return;
	}

	fo->ofo_pfid_checking = 1;
	if (list_empty(&ofd->ofd_inconsistency_list))
		wakeup = true;
	list_add_tail(&oii->oii_list, &ofd->ofd_inconsistency_list);
	if (wakeup && ofd->ofd_inconsistency_task)
		wake_up_process(ofd->ofd_inconsistency_task);
	spin_unlock(&ofd->ofd_inconsistency_lock);

	/* XXX: When the found inconsistency exceeds some threshold,
	 *	we can trigger the LFSCK to scan part of the system
	 *	or the whole system, which depends on how to define
	 *	the threshold, a simple way maybe like that: define
	 *	the absolute value of how many inconsisteny allowed
	 *	to be repaired via self detect/repair mechanism, if
	 *	exceeded, then trigger the LFSCK to scan the layout
	 *	inconsistency within the whole system. */
}

/**
 * Verify parent FID of an object.
 *
 * Check the parent FID is sane and start extended
 * verification procedure otherwise.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] oa	OBDO structure with PFID
 *
 * \retval		0 on successful verification
 * \retval		-EINPROGRESS if PFID is being repaired
 * \retval		-EPERM if PFID was verified but still insane
 */
int ofd_verify_ff(const struct lu_env *env, struct ofd_object *fo,
		  struct obdo *oa)
{
	struct lu_fid *pfid = &fo->ofo_ff.ff_parent;
	int rc = 0;
	ENTRY;

	if (fid_is_sane(pfid)) {
		if (likely(oa->o_parent_seq == pfid->f_seq &&
			   oa->o_parent_oid == pfid->f_oid &&
			   oa->o_stripe_idx == pfid->f_stripe_idx))
			RETURN(0);

		if (fo->ofo_pfid_verified)
			RETURN(-EPERM);
	}

	/* The OST-object may be inconsistent, and we need further verification.
	 * To avoid block the RPC service thread, return -EINPROGRESS to client
	 * and make it retry later. */
	if (fo->ofo_pfid_checking)
		RETURN(-EINPROGRESS);

	rc = ofd_object_ff_load(env, fo);
	if (rc == -ENODATA)
		RETURN(0);

	if (rc < 0)
		RETURN(rc);

	if (likely(oa->o_parent_seq == pfid->f_seq &&
		   oa->o_parent_oid == pfid->f_oid &&
		   oa->o_stripe_idx == pfid->f_stripe_idx))
		RETURN(0);

	/* Push it to the dedicated thread for further verification. */
	ofd_add_inconsistency_item(env, fo, oa);

	RETURN(-EINPROGRESS);
}

/**
 * FLR: verify the layout version of object.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] oa	OBDO structure with layout version
 *
 * \retval		0 on successful verification
 * \retval		-EINPROGRESS layout version is in transfer
 * \retval		-ESTALE the layout version on client is stale
 */
int ofd_verify_layout_version(const struct lu_env *env,
			      struct ofd_object *fo, const struct obdo *oa)
{
	__u32 layout_version;
	int rc;
	ENTRY;

	if (unlikely(OBD_FAIL_CHECK(OBD_FAIL_OST_SKIP_LV_CHECK)))
		GOTO(out, rc = 0);

	rc = ofd_object_ff_load(env, fo);
	if (rc < 0) {
		if (rc == -ENODATA)
			rc = -EINPROGRESS;
		GOTO(out, rc);
	}

	layout_version = fo->ofo_ff.ff_layout_version;
	if (oa->o_layout_version >= layout_version &&
	    oa->o_layout_version <= layout_version + fo->ofo_ff.ff_range)
		GOTO(out, rc = 0);

	/* normal traffic, decide if to return ESTALE or EINPROGRESS */
	layout_version &= ~LU_LAYOUT_RESYNC;

	/* this update is not legitimate */
	if ((oa->o_layout_version & ~LU_LAYOUT_RESYNC) <= layout_version)
		GOTO(out, rc = -ESTALE);

	/* layout version may not be transmitted yet */
	if ((oa->o_layout_version & ~LU_LAYOUT_RESYNC) > layout_version)
		GOTO(out, rc = -EINPROGRESS);

	EXIT;

out:
	CDEBUG(D_INODE, DFID " verify layout version: %u vs. %u/%u, rc: %d\n",
	       PFID(lu_object_fid(&fo->ofo_obj.do_lu)),
	       oa->o_layout_version, fo->ofo_ff.ff_layout_version,
	       fo->ofo_ff.ff_range, rc);
	return rc;

}

/*
 * Lazy ATIME update to refresh atime every ofd_atime_diff
 * seconds so that external scanning tool can see it actual
 * within that period and be able to identify accessed files
 */
static void ofd_handle_atime(const struct lu_env *env, struct ofd_device *ofd,
			     struct ofd_object *fo, time64_t atime)
{
	struct lu_attr *la;
	struct dt_object *o;
	struct thandle *th;
	int rc;

	if (ofd->ofd_atime_diff == 0)
		return;

	la = &ofd_info(env)->fti_attr2;
	o = ofd_object_child(fo);

	if (unlikely(fo->ofo_atime_ondisk == 0)) {
		rc = dt_attr_get(env, o, la);
		if (unlikely(rc))
			return;
		LASSERT(la->la_valid & LA_ATIME);
		if (la->la_atime == 0)
			la->la_atime = la->la_mtime;
		fo->ofo_atime_ondisk = la->la_atime;
	}
	if (atime - fo->ofo_atime_ondisk < ofd->ofd_atime_diff)
		return;

	/* atime hasn't been updated too long, update it */
	fo->ofo_atime_ondisk = atime;

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th)) {
		CERROR("%s: cannot create transaction: rc = %d\n",
		       ofd_name(ofd), (int)PTR_ERR(th));
		return;
	}

	la->la_valid = LA_ATIME;
	rc = dt_declare_attr_set(env, o, la, th);
	if (rc)
		GOTO(out_tx, rc);

	rc = dt_trans_start_local(env, ofd->ofd_osd , th);
	if (rc) {
		CERROR("%s: cannot start transaction: rc = %d\n",
		       ofd_name(ofd), rc);
		GOTO(out_tx, rc);
	}

	ofd_read_lock(env, fo);
	if (ofd_object_exists(fo)) {
		la->la_atime = fo->ofo_atime_ondisk;
		rc = dt_attr_set(env, o, la, th);
	}

	ofd_read_unlock(env, fo);

out_tx:
	ofd_trans_stop(env, ofd, th, rc);
}

/**
 * Prepare buffers for read request processing.
 *
 * This function converts remote buffers from client to local buffers
 * and prepares the latter.
 *
 * \param[in] env	execution environment
 * \param[in] exp	OBD export of client
 * \param[in] ofd	OFD device
 * \param[in] fid	FID of object
 * \param[in] la	object attributes
 * \param[in] oa	OBDO structure from client
 * \param[in] niocount	number of remote buffers
 * \param[in] rnb	remote buffers
 * \param[in] nr_local	number of local buffers
 * \param[in] lnb	local buffers
 * \param[in] jobid	job ID name
 *
 * \retval		0 on successful prepare
 * \retval		negative value on error
 */
static int ofd_preprw_read(const struct lu_env *env, struct obd_export *exp,
			   struct ofd_device *ofd, const struct lu_fid *fid,
			   struct lu_attr *la, struct obdo *oa, int niocount,
			   struct niobuf_remote *rnb, int *nr_local,
			   struct niobuf_local *lnb, char *jobid)
{
	struct ofd_object *fo;
	int i, j, rc, tot_bytes = 0;
	enum dt_bufs_type dbt = DT_BUFS_TYPE_READ;
	int maxlnb = *nr_local;
	__u64 begin, end;
	ktime_t kstart = ktime_get();

	ENTRY;
	LASSERT(env != NULL);

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));
	LASSERT(fo != NULL);

	ofd_info(env)->fti_obj = fo;

	if (oa->o_valid & OBD_MD_FLATIME)
		ofd_handle_atime(env, ofd, fo, oa->o_atime);

	ofd_read_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	if (ofd->ofd_lfsck_verify_pfid && oa->o_valid & OBD_MD_FLFID) {
		rc = ofd_verify_ff(env, fo, oa);
		if (rc != 0)
			GOTO(unlock, rc);
	}

	if (ptlrpc_connection_is_local(exp->exp_connection))
		dbt |= DT_BUFS_TYPE_LOCAL;

	begin = -1;
	end = 0;

	for (*nr_local = 0, i = 0, j = 0; i < niocount; i++) {
		begin = min_t(__u64, begin, rnb[i].rnb_offset);
		end = max_t(__u64, end, rnb[i].rnb_offset + rnb[i].rnb_len);

		if (OBD_FAIL_CHECK(OBD_FAIL_OST_2BIG_NIOBUF))
			rnb[i].rnb_len = 100 * 1024 * 1024;

		rc = dt_bufs_get(env, ofd_object_child(fo), rnb + i,
				 lnb + j, maxlnb, dbt);
		if (unlikely(rc < 0))
			GOTO(buf_put, rc);
		LASSERT(rc <= PTLRPC_MAX_BRW_PAGES);
		/* correct index for local buffers to continue with */
		j += rc;
		*nr_local += rc;
		maxlnb -= rc;
		LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
		tot_bytes += rnb[i].rnb_len;
	}

	LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);
	rc = dt_read_prep(env, ofd_object_child(fo), lnb, *nr_local);
	if (unlikely(rc))
		GOTO(buf_put, rc);

	ofd_access(env, ofd,
		&(struct lu_fid) {
			.f_seq = oa->o_parent_seq,
			.f_oid = oa->o_parent_oid,
			.f_ver = oa->o_stripe_idx,
		},
		begin, end,
		tot_bytes,
		niocount,
		READ);

	ofd_counter_incr(exp, LPROC_OFD_STATS_READ_BYTES, jobid, tot_bytes);
	ofd_counter_incr(exp, LPROC_OFD_STATS_READ, jobid,
			 ktime_us_delta(ktime_get(), kstart));
	RETURN(0);

buf_put:
	dt_bufs_put(env, ofd_object_child(fo), lnb, *nr_local);
unlock:
	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);
	return rc;
}

/**
 * Prepare buffers for write request processing.
 *
 * This function converts remote buffers from client to local buffers
 * and prepares the latter. If there is recovery in progress and required
 * object is missing then it can be re-created before write.
 *
 * \param[in] env	execution environment
 * \param[in] exp	OBD export of client
 * \param[in] ofd	OFD device
 * \param[in] fid	FID of object
 * \param[in] la	object attributes
 * \param[in] oa	OBDO structure from client
 * \param[in] objcount	always 1
 * \param[in] obj	object data
 * \param[in] rnb	remote buffers
 * \param[in] nr_local	number of local buffers
 * \param[in] lnb	local buffers
 * \param[in] jobid	job ID name
 *
 * \retval		0 on successful prepare
 * \retval		negative value on error
 */
static int ofd_preprw_write(const struct lu_env *env, struct obd_export *exp,
			    struct ofd_device *ofd, const struct lu_fid *fid,
			    struct lu_attr *la, struct obdo *oa,
			    int objcount, struct obd_ioobj *obj,
			    struct niobuf_remote *rnb, int *nr_local,
			    struct niobuf_local *lnb, char *jobid)
{
	struct ofd_object *fo;
	int i, j, k, rc = 0, tot_bytes = 0;
	enum dt_bufs_type dbt = DT_BUFS_TYPE_WRITE;
	int maxlnb = *nr_local;
	__u64 begin, end;
	ktime_t kstart = ktime_get();
	struct range_lock *range = &ofd_info(env)->fti_write_range;

	ENTRY;
	LASSERT(env != NULL);
	LASSERT(objcount == 1);

	if (unlikely(exp->exp_obd->obd_recovering)) {
		u64 seq = ostid_seq(&oa->o_oi);
		u64 oid = ostid_id(&oa->o_oi);
		struct ofd_seq *oseq;

		oseq = ofd_seq_load(env, ofd, seq);
		if (IS_ERR(oseq)) {
			CERROR("%s: Can't find FID Sequence %#llx: rc = %d\n",
			       ofd_name(ofd), seq, (int)PTR_ERR(oseq));
			GOTO(out, rc = -EINVAL);
		}

		if (oid > ofd_seq_last_oid(oseq)) {
			int sync = 0;
			int diff;

			mutex_lock(&oseq->os_create_lock);
			diff = oid - ofd_seq_last_oid(oseq);

			/* Do sync create if the seq is about to used up */
			if (fid_seq_is_idif(seq) || fid_seq_is_mdt0(seq)) {
				if (unlikely(oid >= IDIF_MAX_OID - 1))
					sync = 1;
			} else if (fid_seq_is_norm(seq)) {
				if (unlikely(oid >=
					     LUSTRE_DATA_SEQ_MAX_WIDTH - 1))
					sync = 1;
			} else {
				CERROR("%s : invalid o_seq "DOSTID"\n",
				       ofd_name(ofd), POSTID(&oa->o_oi));
				mutex_unlock(&oseq->os_create_lock);
				ofd_seq_put(env, oseq);
				GOTO(out, rc = -EINVAL);
			}

			while (diff > 0) {
				u64 next_id = ofd_seq_last_oid(oseq) + 1;
				int count = ofd_precreate_batch(ofd, diff);

				rc = ofd_precreate_objects(env, ofd, next_id,
							   oseq, count, sync);
				if (rc < 0) {
					mutex_unlock(&oseq->os_create_lock);
					ofd_seq_put(env, oseq);
					GOTO(out, rc);
				}

				diff -= rc;
			}

			mutex_unlock(&oseq->os_create_lock);
		}

		ofd_seq_put(env, oseq);
	}

	/* Process incoming grant info, set OBD_BRW_GRANTED flag and grant some
	 * space back if possible, we have to do this outside of the lock as
	 * grant preparation may need to sync whole fs thus wait for all the
	 * transactions to complete. */
	tgt_grant_prepare_write(env, exp, oa, rnb, obj->ioo_bufcnt);

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));
	LASSERT(fo != NULL);

	ofd_info(env)->fti_obj = fo;

	ofd_read_lock(env, fo);
	if (!ofd_object_exists(fo)) {
		CERROR("%s: BRW to missing obj "DOSTID"\n",
		       exp->exp_obd->obd_name, POSTID(&obj->ioo_oid));
		ofd_read_unlock(env, fo);
		ofd_object_put(env, fo);
		GOTO(out, rc = -ENOENT);
	}

	if (ofd->ofd_lfsck_verify_pfid && oa->o_valid & OBD_MD_FLFID) {
		rc = ofd_verify_ff(env, fo, oa);
		if (rc != 0) {
			ofd_read_unlock(env, fo);
			ofd_object_put(env, fo);
			GOTO(out, rc);
		}
	}

	/* need to verify layout version */
	if (oa->o_valid & OBD_MD_LAYOUT_VERSION) {
		rc = ofd_verify_layout_version(env, fo, oa);
		if (rc) {
			ofd_read_unlock(env, fo);
			ofd_object_put(env, fo);
			GOTO(out, rc);
		}

		oa->o_valid &= ~OBD_MD_LAYOUT_VERSION;
	}

	if (ptlrpc_connection_is_local(exp->exp_connection))
		dbt |= DT_BUFS_TYPE_LOCAL;

	begin = -1;
	end = 0;

	/* parse remote buffers to local buffers and prepare the latter */
	for (*nr_local = 0, i = 0, j = 0; i < obj->ioo_bufcnt; i++) {
		begin = min_t(__u64, begin, rnb[i].rnb_offset);
		end = max_t(__u64, end, rnb[i].rnb_offset + rnb[i].rnb_len);

		if (OBD_FAIL_CHECK(OBD_FAIL_OST_2BIG_NIOBUF))
			rnb[i].rnb_len += PAGE_SIZE;
		rc = dt_bufs_get(env, ofd_object_child(fo),
				 rnb + i, lnb + j, maxlnb, dbt);
		if (unlikely(rc < 0))
			GOTO(err, rc);
		LASSERT(rc <= PTLRPC_MAX_BRW_PAGES);
		/* correct index for local buffers to continue with */
		for (k = 0; k < rc; k++) {
			lnb[j+k].lnb_flags = rnb[i].rnb_flags;
			lnb[j+k].lnb_flags &= ~OBD_BRW_LOCALS;
			if (!(rnb[i].rnb_flags & OBD_BRW_GRANTED))
				lnb[j+k].lnb_rc = -ENOSPC;
		}
		j += rc;
		*nr_local += rc;
		maxlnb -= rc;
		LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
		tot_bytes += rnb[i].rnb_len;
	}
	LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);

	rc = dt_write_prep(env, ofd_object_child(fo), lnb, *nr_local);
	if (unlikely(rc != 0))
		GOTO(err, rc);

	ofd_read_unlock(env, fo);

	ofd_access(env, ofd,
		&(struct lu_fid) {
			.f_seq = oa->o_parent_seq,
			.f_oid = oa->o_parent_oid,
			.f_ver = oa->o_stripe_idx,
		},
		begin, end,
		tot_bytes,
		obj->ioo_bufcnt,
		WRITE);

	/*
	 * Reordering precautions: make sure that request processing that
	 * was able to receive its bulk data should not get reordered with
	 * overlapping BRW requests, e.g.
	 *  1) BRW1 sent, bulk data received, but disk I/O delayed
	 *  2) BRW1 resent and fully processed
	 *  3) the page was unlocked on the client and its writeback bit reset
	 *  4) BRW2 sent and fully processed
	 *  5) BRW1 processing wakes up and writes stale data to disk
	 * If on step 1 bulk data was not received, client resend will invalidate
	 * its bulk descriptor and the RPC will be dropped due to failed bulk
	 * transfer, which is just fine.
	 */
	range_lock_init(range,
			rnb[0].rnb_offset,
			rnb[obj->ioo_bufcnt - 1].rnb_offset +
			rnb[obj->ioo_bufcnt - 1].rnb_len - 1);
	range_lock(&fo->ofo_write_tree, range);
	ofd_info(env)->fti_range_locked = 1;

	ofd_counter_incr(exp, LPROC_OFD_STATS_WRITE_BYTES, jobid, tot_bytes);
	ofd_counter_incr(exp, LPROC_OFD_STATS_WRITE, jobid,
			 ktime_us_delta(ktime_get(), kstart));
	RETURN(0);
err:
	dt_bufs_put(env, ofd_object_child(fo), lnb, *nr_local);
	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);
	/* tgt_grant_prepare_write() was called, so we must commit */
	tgt_grant_commit(exp, oa->o_grant_used, rc);
out:
	/* let's still process incoming grant information packed in the oa,
	 * but without enforcing grant since we won't proceed with the write.
	 * Just like a read request actually. */
	tgt_grant_prepare_read(env, exp, oa);
	return rc;
}

/**
 * Prepare bulk IO requests for processing.
 *
 * This function does initial checks of IO and calls corresponding
 * functions for read/write processing.
 *
 * \param[in] env	execution environment
 * \param[in] cmd	IO type (read/write)
 * \param[in] exp	OBD export of client
 * \param[in] oa	OBDO structure from request
 * \param[in] objcount	always 1
 * \param[in] obj	object data
 * \param[in] rnb	remote buffers
 * \param[in] nr_local	number of local buffers
 * \param[in] lnb	local buffers
 *
 * \retval		0 on successful prepare
 * \retval		negative value on error
 */
int ofd_preprw(const struct lu_env *env, int cmd, struct obd_export *exp,
	       struct obdo *oa, int objcount, struct obd_ioobj *obj,
	       struct niobuf_remote *rnb, int *nr_local,
	       struct niobuf_local *lnb)
{
	struct tgt_session_info	*tsi = tgt_ses_info(env);
	struct ofd_device	*ofd = ofd_exp(exp);
	struct ofd_thread_info	*info;
	char			*jobid;
	const struct lu_fid	*fid = &oa->o_oi.oi_fid;
	int			 rc = 0;

	if (*nr_local > PTLRPC_MAX_BRW_PAGES) {
		CERROR("%s: bulk has too many pages %d, which exceeds the maximum pages per RPC of %d\n",
		       exp->exp_obd->obd_name, *nr_local, PTLRPC_MAX_BRW_PAGES);
		RETURN(-EPROTO);
	}

	if (tgt_ses_req(tsi) == NULL) { /* echo client case */
		info = ofd_info_init(env, exp);
		jobid = NULL;
	} else {
		info = tsi2ofd_info(tsi);
		jobid = tsi->tsi_jobid;
	}

	LASSERT(oa != NULL);

	if (OBD_FAIL_CHECK(OBD_FAIL_SRV_ENOENT)) {
		struct ofd_seq		*oseq;

		oseq = ofd_seq_load(env, ofd, ostid_seq(&oa->o_oi));
		if (IS_ERR(oseq)) {
			CERROR("%s: Can not find seq for "DOSTID
			       ": rc = %ld\n", ofd_name(ofd), POSTID(&oa->o_oi),
			       PTR_ERR(oseq));
			RETURN(-EINVAL);
		}

		if (oseq->os_destroys_in_progress == 0) {
			/* don't fail lookups for orphan recovery, it causes
			 * later LBUGs when objects still exist during
			 * precreate */
			ofd_seq_put(env, oseq);
			RETURN(-ENOENT);
		}
		ofd_seq_put(env, oseq);
	}

	LASSERT(objcount == 1);
	LASSERT(obj->ioo_bufcnt > 0);

	if (cmd == OBD_BRW_WRITE) {
		la_from_obdo(&info->fti_attr, oa, OBD_MD_FLGETATTR);
		rc = ofd_preprw_write(env, exp, ofd, fid, &info->fti_attr, oa,
				      objcount, obj, rnb, nr_local, lnb, jobid);
	} else if (cmd == OBD_BRW_READ) {
		tgt_grant_prepare_read(env, exp, oa);
		rc = ofd_preprw_read(env, exp, ofd, fid, &info->fti_attr, oa,
				     obj->ioo_bufcnt, rnb, nr_local, lnb,
				     jobid);
	} else {
		CERROR("%s: wrong cmd %d received!\n",
		       exp->exp_obd->obd_name, cmd);
		rc = -EPROTO;
	}
	RETURN(rc);
}

/**
 * Drop reference on local buffers for read bulk IO.
 *
 * This will free all local buffers use by this read request.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] fid	object FID
 * \param[in] objcount	always 1
 * \param[in] niocount	number of local buffers
 * \param[in] lnb	local buffers
 *
 * \retval		0 on successful execution
 * \retval		negative value on error
 */
static int
ofd_commitrw_read(const struct lu_env *env, struct ofd_device *ofd,
		  const struct lu_fid *fid, int objcount, int niocount,
		  struct niobuf_local *lnb)
{
	struct ofd_object *fo;

	ENTRY;

	LASSERT(niocount > 0);

	fo = ofd_info(env)->fti_obj;
	LASSERT(fo != NULL);
	LASSERT(ofd_object_exists(fo));
	dt_bufs_put(env, ofd_object_child(fo), lnb, niocount);

	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);

	RETURN(0);
}

/**
 * Set attributes of object during write bulk IO processing.
 *
 * Change object attributes and write parent FID into extended
 * attributes when needed.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] ofd_obj	OFD object
 * \param[in] la	object attributes
 * \param[in] oa	obdo
 *
 * \retval		0 on successful attributes update
 * \retval		negative value on error
 */
static int
ofd_write_attr_set(const struct lu_env *env, struct ofd_device *ofd,
		   struct ofd_object *ofd_obj, struct lu_attr *la,
		   struct obdo *oa)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct filter_fid	*ff = &info->fti_mds_fid;
	__u64			 valid = la->la_valid;
	struct thandle		*th;
	struct dt_object	*dt_obj;
	int			 fl = 0;
	int			 rc;

	ENTRY;

	LASSERT(la);

	dt_obj = ofd_object_child(ofd_obj);
	LASSERT(dt_obj != NULL);

	la->la_valid &= LA_UID | LA_GID | LA_PROJID;

	rc = ofd_attr_handle_id(env, ofd_obj, la, 0 /* !is_setattr */);
	if (rc != 0)
		GOTO(out, rc);

	if (!la->la_valid && !(oa->o_valid &
	    (OBD_MD_FLFID | OBD_MD_FLOSTLAYOUT | OBD_MD_LAYOUT_VERSION)))
		/* no attributes to set */
		GOTO(out, rc = 0);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	if (la->la_valid) {
		rc = dt_declare_attr_set(env, dt_obj, la, th);
		if (rc)
			GOTO(out_tx, rc);
	}

	if (oa->o_valid & (OBD_MD_FLFID | OBD_MD_FLOSTLAYOUT |
			   OBD_MD_LAYOUT_VERSION)) {
		rc = dt_declare_xattr_set(env, dt_obj, &info->fti_buf,
					  XATTR_NAME_FID, 0, th);
		if (rc)
			GOTO(out_tx, rc);
	}
	/* We don't need a transno for this operation which will be re-executed
	 * anyway when the OST_WRITE (with a transno assigned) is replayed */
	rc = dt_trans_start_local(env, ofd->ofd_osd , th);
	if (rc)
		GOTO(out_tx, rc);

	ofd_read_lock(env, ofd_obj);

	rc = ofd_attr_handle_id(env, ofd_obj, la, 0 /* !is_setattr */);
	if (rc != 0)
		GOTO(out_unlock, rc);

	if (!la->la_valid && !(oa->o_valid &
	    (OBD_MD_FLFID | OBD_MD_FLOSTLAYOUT | OBD_MD_LAYOUT_VERSION)))
		/* no attributes to set */
		GOTO(out_unlock, rc = 0);



	/* set uid/gid/projid */
	if (la->la_valid) {
		rc = dt_attr_set(env, dt_obj, la, th);
		if (rc)
			GOTO(out_unlock, rc);
	}

	fl = ofd_object_ff_update(env, ofd_obj, oa, ff);
	if (fl <= 0)
		GOTO(out_unlock, rc = fl);

	/* set filter fid EA.
	 * FIXME: it holds read lock of ofd object to modify the XATTR_NAME_FID
	 * while the write lock should be held. However, it should work because
	 * write RPCs only modify ff_{parent,layout} and those information will
	 * be the same from all the write RPCs. The reason that fl is not used
	 * in dt_xattr_set() is to allow this race. */
	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NOPFID))
		GOTO(out_unlock, rc);
	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR1))
		ff->ff_parent.f_oid = cpu_to_le32(1UL << 31);
	else if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR2))
		le32_add_cpu(&ff->ff_parent.f_oid, -1);

	info->fti_buf.lb_buf = ff;
	info->fti_buf.lb_len = sizeof(*ff);
	rc = dt_xattr_set(env, dt_obj, &info->fti_buf, XATTR_NAME_FID, 0, th);
	if (rc == 0)
		filter_fid_le_to_cpu(&ofd_obj->ofo_ff, ff, sizeof(*ff));

	GOTO(out_unlock, rc);

out_unlock:
	ofd_read_unlock(env, ofd_obj);
out_tx:
	dt_trans_stop(env, ofd->ofd_osd, th);
out:
	la->la_valid = valid;
	return rc;
}

struct ofd_soft_sync_callback {
	struct dt_txn_commit_cb	 ossc_cb;
	struct obd_export	*ossc_exp;
};

/**
 * Callback function for "soft sync" update.
 *
 * Reset fed_soft_sync_count upon committing the "soft_sync" update.
 * See ofd_soft_sync_cb_add() below for more details on soft sync.
 *
 * \param[in] env	execution environment
 * \param[in] th	transaction handle
 * \param[in] cb	callback data
 * \param[in] err	error code
 */
static void ofd_cb_soft_sync(struct lu_env *env, struct thandle *th,
			     struct dt_txn_commit_cb *cb, int err)
{
	struct ofd_soft_sync_callback	*ossc;

	ossc = container_of(cb, struct ofd_soft_sync_callback, ossc_cb);

	CDEBUG(D_INODE, "export %p soft sync count is reset\n", ossc->ossc_exp);
	atomic_set(&ossc->ossc_exp->exp_filter_data.fed_soft_sync_count, 0);

	class_export_cb_put(ossc->ossc_exp);
	OBD_FREE_PTR(ossc);
}

/**
 * Add callback for "soft sync" processing.
 *
 * The "soft sync" mechanism does asynchronous commit when OBD_BRW_SOFT_SYNC
 * flag is set in client buffers. The intention is for this operation to
 * commit pages belonging to a client which has "too many" outstanding
 * unstable pages in its cache. See LU-2139 for details.
 *
 * This function adds callback to be called when commit is done.
 *
 * \param[in] th	transaction handle
 * \param[in] exp	OBD export of client
 *
 * \retval		0 on successful callback adding
 * \retval		negative value on error
 */
static int ofd_soft_sync_cb_add(struct thandle *th, struct obd_export *exp)
{
	struct ofd_soft_sync_callback		*ossc;
	struct dt_txn_commit_cb			*dcb;
	int					 rc;

	OBD_ALLOC_PTR(ossc);
	if (ossc == NULL)
		return -ENOMEM;

	ossc->ossc_exp = class_export_cb_get(exp);

	dcb = &ossc->ossc_cb;
	dcb->dcb_func = ofd_cb_soft_sync;
	INIT_LIST_HEAD(&dcb->dcb_linkage);
	strlcpy(dcb->dcb_name, "ofd_cb_soft_sync", sizeof(dcb->dcb_name));

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		class_export_cb_put(exp);
		OBD_FREE_PTR(ossc);
	}

	return rc;
}

/**
 * Commit bulk IO buffers to the storage.
 *
 * This function finalizes write IO processing by writing data to the disk.
 * That write can be synchronous or asynchronous depending on buffers flags.
 *
 * \param[in] env	execution environment
 * \param[in] exp	OBD export of client
 * \param[in] ofd	OFD device
 * \param[in] fid	FID of object
 * \param[in] la	object attributes
 * \param[in] ff	parent FID of object
 * \param[in] objcount	always 1
 * \param[in] niocount	number of local buffers
 * \param[in] lnb	local buffers
 * \param[in] granted	grant space consumed for the bulk I/O
 * \param[in] old_rc	result of processing at this point
 *
 * \retval		0 on successful commit
 * \retval		negative value on error
 */
static int
ofd_commitrw_write(const struct lu_env *env, struct obd_export *exp,
		   struct ofd_device *ofd, const struct lu_fid *fid,
		   struct lu_attr *la, struct obdo *oa, int objcount,
		   int niocount, struct niobuf_local *lnb,
		   unsigned long granted, int old_rc)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct filter_export_data *fed = &exp->exp_filter_data;
	struct ofd_object *fo;
	struct dt_object *o;
	struct thandle *th;
	int rc = 0;
	int rc2 = 0;
	int retries = 0;
	int i, restart = 0;
	bool soft_sync = false;
	bool cb_registered = false;
	bool fake_write = false;
	struct range_lock *range = &ofd_info(env)->fti_write_range;

	ENTRY;

	LASSERT(objcount == 1);

	fo = ofd_info(env)->fti_obj;
	LASSERT(fo != NULL);

	o = ofd_object_child(fo);
	LASSERT(o != NULL);

	if (old_rc)
		GOTO(out, rc = old_rc);
	if (!ofd_object_exists(fo))
		GOTO(out, rc = -ENOENT);

	/*
	 * The first write to each object must set some attributes.  It is
	 * important to set the uid/gid before calling
	 * dt_declare_write_commit() since quota enforcement is now handled in
	 * declare phases.
	 */
	rc = ofd_write_attr_set(env, ofd, fo, la, oa);
	if (rc)
		GOTO(out, rc);

	la->la_valid &= LA_ATIME | LA_MTIME | LA_CTIME;

	/* do fake write, to simulate the write case for performance testing */
	if (OBD_FAIL_CHECK(OBD_FAIL_OST_FAKE_RW)) {
		struct niobuf_local *last = &lnb[niocount - 1];
		__u64 file_size = last->lnb_file_offset + last->lnb_len;
		__u64 valid = la->la_valid;

		la->la_valid = LA_SIZE;
		la->la_size = 0;
		rc = dt_attr_get(env, o, la);
		if (rc < 0 && rc != -ENOENT)
			GOTO(out, rc);

		if (file_size < la->la_size)
			file_size = la->la_size;

		/* dirty inode by setting file size */
		la->la_valid = valid | LA_SIZE;
		la->la_size = file_size;

		fake_write = true;
	}

retry:
	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	th->th_sync |= ofd->ofd_sync_journal;
	if (th->th_sync == 0) {
		for (i = 0; i < niocount; i++) {
			if (!(lnb[i].lnb_flags & OBD_BRW_ASYNC)) {
				th->th_sync = 1;
				break;
			}
			if (lnb[i].lnb_flags & OBD_BRW_SOFT_SYNC)
				soft_sync = true;
		}
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_DQACQ_NET))
		GOTO(out_stop, rc = -EINPROGRESS);

	if (likely(!fake_write)) {
		rc = dt_declare_write_commit(env, o, lnb, niocount, th);
		if (rc)
			GOTO(out_stop, rc);
	}

	/* don't update atime on disk if it is older */
	if (la->la_valid & LA_ATIME && la->la_atime <= fo->ofo_atime_ondisk)
		la->la_valid &= ~LA_ATIME;

	if (la->la_valid) {
		/* update [mac]time if needed */
		rc = dt_declare_attr_set(env, o, la, th);
		if (rc)
			GOTO(out_stop, rc);
	}

	rc = ofd_trans_start(env, ofd, fo, th);
	if (rc)
		GOTO(out_stop, rc);

	ofd_read_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(out_unlock, rc = -ENOENT);

	/* Don't update timestamps if this write is older than a
	 * setattr which modifies the timestamps. b=10150 */
	if (la->la_valid && tgt_fmd_check(exp, fid, info->fti_xid)) {
		rc = dt_attr_set(env, o, la, th);
		if (rc)
			GOTO(out_unlock, rc);
		if (la->la_valid & LA_ATIME)
			fo->ofo_atime_ondisk = la->la_atime;
	}

	if (likely(!fake_write)) {
		OBD_FAIL_TIMEOUT_ORSET(OBD_FAIL_OST_WR_ATTR_DELAY,
				       OBD_FAIL_ONCE, cfs_fail_val);
		rc = dt_write_commit(env, o, lnb, niocount, th, oa->o_size);
		if (rc) {
			restart = th->th_restart_tran;
			GOTO(out_unlock, rc);
		}
	}

	/* get attr to return */
	rc = dt_attr_get(env, o, la);

out_unlock:
	ofd_read_unlock(env, fo);
out_stop:
	/* Force commit to make the just-deleted blocks
	 * reusable. LU-456 */
	if (rc == -ENOSPC)
		th->th_sync = 1;

	/* do this before trans stop in case commit has finished */
	if (!th->th_sync && soft_sync && !cb_registered) {
		ofd_soft_sync_cb_add(th, exp);
		cb_registered = true;
	}

	if (rc == 0 && granted > 0) {
		if (tgt_grant_commit_cb_add(th, exp, granted) == 0)
			granted = 0;
	}

	rc2 = ofd_trans_stop(env, ofd, th, restart ? 0 : rc);
	if (!rc)
		rc = rc2;
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
				ofd_name(ofd), retries);
		CDEBUG(D_INODE, "retry transaction, retries:%d\n",
		       retries);
		goto retry;
	}
	if (!soft_sync)
		/* reset fed_soft_sync_count upon non-SOFT_SYNC RPC */
		atomic_set(&fed->fed_soft_sync_count, 0);
	else if (atomic_inc_return(&fed->fed_soft_sync_count) ==
		 ofd->ofd_soft_sync_limit)
		dt_commit_async(env, ofd->ofd_osd);

out:
	if (info->fti_range_locked) {
		range_unlock(&fo->ofo_write_tree, range);
		info->fti_range_locked = 0;
	}
	dt_bufs_put(env, o, lnb, niocount);
	ofd_object_put(env, fo);
	if (granted > 0)
		tgt_grant_commit(exp, granted, old_rc);
	RETURN(rc);
}

/**
 * Commit bulk IO to the storage.
 *
 * This is companion function to the ofd_preprw(). It finishes bulk IO
 * request processing by committing buffers to the storage (WRITE) and/or
 * freeing those buffers (read/write). See ofd_commitrw_read() and
 * ofd_commitrw_write() for details about each type of IO.
 *
 * \param[in] env	execution environment
 * \param[in] cmd	IO type (READ/WRITE)
 * \param[in] exp	OBD export of client
 * \param[in] oa	OBDO structure from client
 * \param[in] objcount	always 1
 * \param[in] obj	object data
 * \param[in] rnb	remote buffers
 * \param[in] npages	number of local buffers
 * \param[in] lnb	local buffers
 * \param[in] old_rc	result of processing at this point
 *
 * \retval		0 on successful commit
 * \retval		negative value on error
 */
int ofd_commitrw(const struct lu_env *env, int cmd, struct obd_export *exp,
		 struct obdo *oa, int objcount, struct obd_ioobj *obj,
		 struct niobuf_remote *rnb, int npages,
		 struct niobuf_local *lnb, int old_rc)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct ofd_device *ofd = ofd_exp(exp);
	const struct lu_fid *fid = &oa->o_oi.oi_fid;
	struct ldlm_namespace *ns = ofd->ofd_namespace;
	struct ldlm_resource *rs = NULL;
	__u64 valid;
	int rc = 0;

	LASSERT(npages > 0);

	if (cmd == OBD_BRW_WRITE) {
		struct lu_nodemap *nodemap;

		valid = OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLPROJID |
			OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME;
		la_from_obdo(&info->fti_attr, oa, valid);

		rc = ofd_commitrw_write(env, exp, ofd, fid, &info->fti_attr,
					oa, objcount, npages, lnb,
					oa->o_grant_used, old_rc);
		if (rc == 0)
			obdo_from_la(oa, &info->fti_attr,
				     OFD_VALID_FLAGS | LA_GID | LA_UID |
				     LA_PROJID);
		else
			obdo_from_la(oa, &info->fti_attr, LA_GID | LA_UID |
				     LA_PROJID);

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

			oa->o_valid |= OBD_MD_FLFLAGS;
			oa->o_valid |= OBD_MD_FLALLQUOTA;
		}

		/**
		 * Update LVB after writing finish for server lock, see
		 * comments in ldlm_lock_decref_internal(), If this is a
		 * local lock on a server namespace and this was the last
		 * reference, lock will be destroyed directly thus there
		 * is no chance for ldlm_request_cancel() to update lvb.
		 */
		if (rc == 0 && (rnb[0].rnb_flags & OBD_BRW_SRVLOCK)) {
			ost_fid_build_resid(fid, &info->fti_resid);
			rs = ldlm_resource_get(ns, NULL, &info->fti_resid,
					       LDLM_EXTENT, 0);
			if (!IS_ERR(rs)) {
				ldlm_res_lvbo_update(rs, NULL, 1);
				ldlm_resource_putref(rs);
			}
		}

		/* Convert back to client IDs. LU-9671.
		 * nodemap_get_from_exp() may fail due to nodemap deactivated,
		 * server ID will be returned back to client in that case. */
		nodemap = nodemap_get_from_exp(exp);
		if (nodemap != NULL && !IS_ERR(nodemap)) {
			oa->o_uid = nodemap_map_id(nodemap, NODEMAP_UID,
						   NODEMAP_FS_TO_CLIENT,
						   oa->o_uid);
			oa->o_gid = nodemap_map_id(nodemap, NODEMAP_GID,
						   NODEMAP_FS_TO_CLIENT,
						   oa->o_gid);
			nodemap_putref(nodemap);
		}
	} else if (cmd == OBD_BRW_READ) {
		rc = ofd_commitrw_read(env, ofd, fid, objcount,
				       npages, lnb);
		if (old_rc)
			rc = old_rc;
	} else {
		LBUG();
		rc = -EPROTO;
	}

	RETURN(rc);
}
