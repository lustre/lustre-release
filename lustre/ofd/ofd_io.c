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
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
static int ofd_inconsistency_verification_main(void *args)
{
	struct lu_env env;
	struct ofd_device *ofd = args;
	struct ptlrpc_thread *thread = &ofd->ofd_inconsistency_thread;
	struct ofd_inconsistency_item *oii;
	struct lfsck_req_local *lrl = NULL;
	struct l_wait_info lwi = { 0 };
	int rc;
	ENTRY;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	spin_lock(&ofd->ofd_inconsistency_lock);
	thread_set_flags(thread, rc ? SVC_STOPPED : SVC_RUNNING);
	wake_up_all(&thread->t_ctl_waitq);
	spin_unlock(&ofd->ofd_inconsistency_lock);
	if (rc)
		RETURN(rc);

	OBD_ALLOC_PTR(lrl);
	if (unlikely(!lrl))
		GOTO(out_unlocked, rc = -ENOMEM);

	lrl->lrl_event = LEL_PAIRS_VERIFY_LOCAL;
	lrl->lrl_active = LFSCK_TYPE_LAYOUT;

	spin_lock(&ofd->ofd_inconsistency_lock);
	while (1) {
		if (unlikely(!thread_is_running(thread)))
			break;

		while (!list_empty(&ofd->ofd_inconsistency_list)) {
			oii = list_entry(ofd->ofd_inconsistency_list.next,
					 struct ofd_inconsistency_item,
					 oii_list);
			list_del_init(&oii->oii_list);
			spin_unlock(&ofd->ofd_inconsistency_lock);
			ofd_inconsistency_verify_one(&env, ofd, oii, lrl);
			spin_lock(&ofd->ofd_inconsistency_lock);
		}

		spin_unlock(&ofd->ofd_inconsistency_lock);
		l_wait_event(thread->t_ctl_waitq,
			     !list_empty(&ofd->ofd_inconsistency_list) ||
			     !thread_is_running(thread),
			     &lwi);
		spin_lock(&ofd->ofd_inconsistency_lock);
	}

	while (!list_empty(&ofd->ofd_inconsistency_list)) {
		struct ofd_object *fo;

		oii = list_entry(ofd->ofd_inconsistency_list.next,
				 struct ofd_inconsistency_item,
				 oii_list);
		list_del_init(&oii->oii_list);
		fo = oii->oii_obj;
		spin_unlock(&ofd->ofd_inconsistency_lock);

		ofd_write_lock(&env, fo);
		fo->ofo_pfid_checking = 0;
		ofd_write_unlock(&env, fo);

		ofd_object_put(&env, fo);
		OBD_FREE_PTR(oii);
		spin_lock(&ofd->ofd_inconsistency_lock);
	}

	OBD_FREE_PTR(lrl);

	GOTO(out, rc = 0);

out_unlocked:
	spin_lock(&ofd->ofd_inconsistency_lock);
out:
	thread_set_flags(thread, SVC_STOPPED);
	wake_up_all(&thread->t_ctl_waitq);
	spin_unlock(&ofd->ofd_inconsistency_lock);
	lu_env_fini(&env);

	return rc;
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
	struct ptlrpc_thread	*thread = &ofd->ofd_inconsistency_thread;
	struct l_wait_info	 lwi	= { 0 };
	struct task_struct	*task;
	int			 rc;

	spin_lock(&ofd->ofd_inconsistency_lock);
	if (unlikely(thread_is_running(thread))) {
		spin_unlock(&ofd->ofd_inconsistency_lock);

		return -EALREADY;
	}

	thread_set_flags(thread, 0);
	spin_unlock(&ofd->ofd_inconsistency_lock);
	task = kthread_run(ofd_inconsistency_verification_main, ofd,
			   "inconsistency_verification");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start self_repair thread: rc = %d\n",
		       ofd_name(ofd), rc);
	} else {
		rc = 0;
		l_wait_event(thread->t_ctl_waitq,
			     thread_is_running(thread) ||
			     thread_is_stopped(thread),
			     &lwi);
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
	struct ptlrpc_thread	*thread = &ofd->ofd_inconsistency_thread;
	struct l_wait_info	 lwi	= { 0 };

	spin_lock(&ofd->ofd_inconsistency_lock);
	if (thread_is_init(thread) || thread_is_stopped(thread)) {
		spin_unlock(&ofd->ofd_inconsistency_lock);

		return -EALREADY;
	}

	thread_set_flags(thread, SVC_STOPPING);
	spin_unlock(&ofd->ofd_inconsistency_lock);
	wake_up_all(&thread->t_ctl_waitq);
	l_wait_event(thread->t_ctl_waitq,
		     thread_is_stopped(thread),
		     &lwi);

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
	spin_unlock(&ofd->ofd_inconsistency_lock);
	if (wakeup)
		wake_up_all(&ofd->ofd_inconsistency_thread.t_ctl_waitq);

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

	ENTRY;
	LASSERT(env != NULL);

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));
	LASSERT(fo != NULL);

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

	for (*nr_local = 0, i = 0, j = 0; i < niocount; i++) {
		rc = dt_bufs_get(env, ofd_object_child(fo), rnb + i,
				 lnb + j, dbt);
		if (unlikely(rc < 0))
			GOTO(buf_put, rc);
		LASSERT(rc <= PTLRPC_MAX_BRW_PAGES);
		/* correct index for local buffers to continue with */
		j += rc;
		*nr_local += rc;
		LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
		tot_bytes += rnb[i].rnb_len;
	}

	LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);
	rc = dt_attr_get(env, ofd_object_child(fo), la);
	if (unlikely(rc))
		GOTO(buf_put, rc);

	rc = dt_read_prep(env, ofd_object_child(fo), lnb, *nr_local);
	if (unlikely(rc))
		GOTO(buf_put, rc);

	ofd_counter_incr(exp, LPROC_OFD_STATS_READ, jobid, tot_bytes);
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

	ENTRY;
	LASSERT(env != NULL);
	LASSERT(objcount == 1);

	if (unlikely(exp->exp_obd->obd_recovering)) {
		u64 seq = fid_seq(fid);
		u64 oid = fid_oid(fid);
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

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));
	LASSERT(fo != NULL);

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

	/* Process incoming grant info, set OBD_BRW_GRANTED flag and grant some
	 * space back if possible */
	tgt_grant_prepare_write(env, exp, oa, rnb, obj->ioo_bufcnt);

	if (ptlrpc_connection_is_local(exp->exp_connection))
		dbt |= DT_BUFS_TYPE_LOCAL;

	/* parse remote buffers to local buffers and prepare the latter */
	for (*nr_local = 0, i = 0, j = 0; i < obj->ioo_bufcnt; i++) {
		rc = dt_bufs_get(env, ofd_object_child(fo),
				 rnb + i, lnb + j, dbt);
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
		LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
		tot_bytes += rnb[i].rnb_len;
	}
	LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);

	rc = dt_write_prep(env, ofd_object_child(fo), lnb, *nr_local);
	if (unlikely(rc != 0))
		GOTO(err, rc);

	ofd_counter_incr(exp, LPROC_OFD_STATS_WRITE, jobid, tot_bytes);
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
		CERROR("%s: bulk has too many pages %d, which exceeds the"
		       "maximum pages per RPC of %d\n",
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
		obdo_from_la(oa, &info->fti_attr, LA_ATIME);
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

	fo = ofd_object_find(env, ofd, fid);
	if (IS_ERR(fo))
		RETURN(PTR_ERR(fo));
	LASSERT(fo != NULL);
	LASSERT(ofd_object_exists(fo));
	dt_bufs_put(env, ofd_object_child(fo), lnb, niocount);

	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);
	/* second put is pair to object_get in ofd_preprw_read */
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
 * \param[in] ff	parent FID
 *
 * \retval		0 on successful attributes update
 * \retval		negative value on error
 */
static int
ofd_write_attr_set(const struct lu_env *env, struct ofd_device *ofd,
		   struct ofd_object *ofd_obj, struct lu_attr *la,
		   struct filter_fid *ff)
{
	struct ofd_thread_info	*info = ofd_info(env);
	__u64			 valid = la->la_valid;
	int			 rc;
	struct thandle		*th;
	struct dt_object	*dt_obj;
	int			 ff_needed = 0;

	ENTRY;

	LASSERT(la);

	dt_obj = ofd_object_child(ofd_obj);
	LASSERT(dt_obj != NULL);

	la->la_valid &= LA_UID | LA_GID | LA_PROJID;

	rc = ofd_attr_handle_id(env, ofd_obj, la, 0 /* !is_setattr */);
	if (rc != 0)
		GOTO(out, rc);

	if (ff != NULL) {
		rc = ofd_object_ff_load(env, ofd_obj);
		if (rc == -ENODATA)
			ff_needed = 1;
		else if (rc < 0)
			GOTO(out, rc);
	}

	if (!la->la_valid && !ff_needed)
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

	if (ff_needed) {
		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR1))
			ff->ff_parent.f_oid = cpu_to_le32(1UL << 31);
		else if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR2))
			le32_add_cpu(&ff->ff_parent.f_oid, -1);

		info->fti_buf.lb_buf = ff;
		info->fti_buf.lb_len = sizeof(*ff);
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

	/* set uid/gid/projid */
	if (la->la_valid) {
		rc = dt_attr_set(env, dt_obj, la, th);
		if (rc)
			GOTO(out_tx, rc);
	}

	/* set filter fid EA */
	if (ff_needed) {
		if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_NOPFID))
			GOTO(out_tx, rc);

		rc = dt_xattr_set(env, dt_obj, &info->fti_buf, XATTR_NAME_FID,
				  0, th);
		if (!rc)
			filter_fid_le_to_cpu(&ofd_obj->ofo_ff, ff, sizeof(*ff));
	}

	GOTO(out_tx, rc);

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
		   struct lu_attr *la, struct filter_fid *ff, int objcount,
		   int niocount, struct niobuf_local *lnb,
		   unsigned long granted, int old_rc)
{
	struct filter_export_data *fed = &exp->exp_filter_data;
	struct ofd_object *fo;
	struct dt_object *o;
	struct thandle *th;
	int rc = 0;
	int rc2 = 0;
	int retries = 0;
	int i;
	bool soft_sync = false;
	bool cb_registered = false;
	bool fake_write = false;

	ENTRY;

	LASSERT(objcount == 1);

	fo = ofd_object_find(env, ofd, fid);
	LASSERT(fo != NULL);
	LASSERT(ofd_object_exists(fo));

	o = ofd_object_child(fo);
	LASSERT(o != NULL);

	if (old_rc)
		GOTO(out, rc = old_rc);

	/*
	 * The first write to each object must set some attributes.  It is
	 * important to set the uid/gid before calling
	 * dt_declare_write_commit() since quota enforcement is now handled in
	 * declare phases.
	 */
	rc = ofd_write_attr_set(env, ofd, fo, la, ff);
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

	th->th_sync |= ofd->ofd_syncjournal;
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

	if (la->la_valid) {
		/* update [mac]time if needed */
		rc = dt_declare_attr_set(env, o, la, th);
		if (rc)
			GOTO(out_stop, rc);
	}

	rc = ofd_trans_start(env, ofd, fo, th);
	if (rc)
		GOTO(out_stop, rc);

	if (likely(!fake_write)) {
		rc = dt_write_commit(env, o, lnb, niocount, th);
		if (rc)
			GOTO(out_stop, rc);
	}

	if (la->la_valid) {
		rc = dt_attr_set(env, o, la, th);
		if (rc)
			GOTO(out_stop, rc);
	}

	/* get attr to return */
	rc = dt_attr_get(env, o, la);

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

	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (!rc)
		rc = rc2;
	if (rc == -ENOSPC && retries++ < 3) {
		CDEBUG(D_INODE, "retry after force commit, retries:%d\n",
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
	dt_bufs_put(env, o, lnb, niocount);
	ofd_read_unlock(env, fo);
	ofd_object_put(env, fo);
	/* second put is pair to object_get in ofd_preprw_write */
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
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_mod_data	*fmd;
	__u64			 valid;
	struct ofd_device	*ofd = ofd_exp(exp);
	struct filter_fid	*ff = NULL;
	const struct lu_fid	*fid = &oa->o_oi.oi_fid;
	int			 rc = 0;

	LASSERT(npages > 0);

	if (cmd == OBD_BRW_WRITE) {
		struct lu_nodemap *nodemap;

		/* Don't update timestamps if this write is older than a
		 * setattr which modifies the timestamps. b=10150 */

		/* XXX when we start having persistent reservations this needs
		 * to be changed to ofd_fmd_get() to create the fmd if it
		 * doesn't already exist so we can store the reservation handle
		 * there. */
		valid = OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLPROJID;
		fmd = ofd_fmd_find(exp, fid);
		if (!fmd || fmd->fmd_mactime_xid < info->fti_xid)
			valid |= OBD_MD_FLATIME | OBD_MD_FLMTIME |
				 OBD_MD_FLCTIME;
		ofd_fmd_put(exp, fmd);
		la_from_obdo(&info->fti_attr, oa, valid);

		if (oa->o_valid & OBD_MD_FLFID) {
			ff = &info->fti_mds_fid;
			ofd_prepare_fidea(ff, oa);
		}

		rc = ofd_commitrw_write(env, exp, ofd, fid, &info->fti_attr,
					ff, objcount, npages, lnb,
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
		struct ldlm_namespace *ns = ofd->ofd_namespace;

		/* If oa != NULL then ofd_preprw_read updated the inode
		 * atime and we should update the lvb so that other glimpses
		 * will also get the updated value. bug 5972 */
		if (oa && ns && ns->ns_lvbo && ns->ns_lvbo->lvbo_update) {
			 struct ldlm_resource *rs = NULL;

			ost_fid_build_resid(fid, &info->fti_resid);
			rs = ldlm_resource_get(ns, NULL, &info->fti_resid,
					       LDLM_EXTENT, 0);
			if (!IS_ERR(rs)) {
				ldlm_res_lvbo_update(rs, NULL, 1);
				ldlm_resource_putref(rs);
			}
		}
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
