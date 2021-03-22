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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/mdd/mdd_trans.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/kthread.h>

#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_mds.h>
#include <lustre_barrier.h>

#include "mdd_internal.h"

struct thandle *mdd_trans_create(const struct lu_env *env,
                                 struct mdd_device *mdd)
{
	struct thandle *th;
	struct lu_ucred *uc = lu_ucred_check(env);

	/* If blocked by the write barrier, then return "-EINPROGRESS"
	 * to the caller. Usually, such error will be forwarded to the
	 * client, and the expected behaviour is to re-try such modify
	 * RPC some time later until the barrier is thawed or expired. */
	if (unlikely(!barrier_entry(mdd->mdd_bottom)))
		return ERR_PTR(-EINPROGRESS);

	th = mdd_child_ops(mdd)->dt_trans_create(env, mdd->mdd_child);
	if (!IS_ERR(th) && uc)
		th->th_ignore_quota = !!md_capable(uc, CAP_SYS_RESOURCE);

	return th;
}

int mdd_trans_start(const struct lu_env *env, struct mdd_device *mdd,
                    struct thandle *th)
{
        return mdd_child_ops(mdd)->dt_trans_start(env, mdd->mdd_child, th);
}

struct mdd_changelog_gc {
	struct mdd_device *mcgc_mdd;
	__u32 mcgc_id;
	__u32 mcgc_maxtime;
	__u64 mcgc_maxindexes;
	bool mcgc_found;
};

/* return first registered ChangeLog user idle since too long
 * use ChangeLog's user plain LLOG mtime for this */
static int mdd_changelog_gc_cb(const struct lu_env *env,
			       struct llog_handle *llh,
			       struct llog_rec_hdr *hdr, void *data)
{
	struct llog_changelog_user_rec *rec;
	struct mdd_changelog_gc *mcgc = (struct mdd_changelog_gc *)data;
	struct mdd_device *mdd = mcgc->mcgc_mdd;
	ENTRY;

	if ((llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN) == 0)
		RETURN(-ENXIO);

	rec = container_of(hdr, struct llog_changelog_user_rec,
			   cur_hdr);

	/* find oldest idle user, based on last record update/cancel time (new
	 * behavior), or for old user records, last record index vs current
	 * ChangeLog index. Late users with old record format will be treated
	 * first as we assume they could be idle since longer
	 */
	if (rec->cur_time != 0) {
		/* FIXME !!!! cur_time is a timestamp but only 32 bit in
		 * in size. This is not 2038 safe !!!!
		 */
		u32 time_now = (u32)ktime_get_real_seconds();
		timeout_t time_out = rec->cur_time +
				     mdd->mdd_changelog_max_idle_time;
		timeout_t idle_time = time_now - rec->cur_time;

		/* treat oldest idle user first, and if no old format user
		 * has been already selected
		 */
		if (time_after32(time_now, time_out) &&
		    idle_time > mcgc->mcgc_maxtime &&
		    mcgc->mcgc_maxindexes == 0) {
			mcgc->mcgc_maxtime = idle_time;
			mcgc->mcgc_id = rec->cur_id;
			mcgc->mcgc_found = true;
		}
	} else {
		/* old user record with no idle time stamp, so use empirical
		 * method based on its current index/position
		 */
		__u64 idle_indexes;

		idle_indexes = mdd->mdd_cl.mc_index - rec->cur_endrec;

		/* treat user with the oldest/smallest current index first */
		if (idle_indexes >= mdd->mdd_changelog_max_idle_indexes &&
		    idle_indexes > mcgc->mcgc_maxindexes) {
			mcgc->mcgc_maxindexes = idle_indexes;
			mcgc->mcgc_id = rec->cur_id;
			mcgc->mcgc_found = true;
		}

	}
	RETURN(0);
}

/* recover space from long-term inactive ChangeLog users */
static int mdd_chlg_garbage_collect(void *data)
{
	struct mdd_device *mdd = (struct mdd_device *)data;
	struct lu_env		  *env = NULL;
	int			   rc;
	struct llog_ctxt *ctxt;
	struct mdd_changelog_gc mcgc = {
		.mcgc_mdd = mdd,
		.mcgc_found = false,
		.mcgc_maxtime = 0,
		.mcgc_maxindexes = 0,
	};
	ENTRY;

	mdd->mdd_cl.mc_gc_task = current;

	CDEBUG(D_HA, "%s: ChangeLog garbage collect thread start with PID %d\n",
	       mdd2obd_dev(mdd)->obd_name, current->pid);

	OBD_ALLOC_PTR(env);
	if (env == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = lu_env_init(env, LCT_MD_THREAD);
	if (rc)
		GOTO(out, rc);

	for (;;) {
		ctxt = llog_get_context(mdd2obd_dev(mdd),
					LLOG_CHANGELOG_USER_ORIG_CTXT);
		if (ctxt == NULL ||
		    (ctxt->loc_handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT) == 0)
			GOTO(out_ctxt, rc = -ENXIO);

		rc = llog_cat_process(env, ctxt->loc_handle,
				      mdd_changelog_gc_cb, &mcgc, 0, 0);
		if (rc != 0 || mcgc.mcgc_found == false)
			break;
		llog_ctxt_put(ctxt);

		if (mcgc.mcgc_maxindexes != 0)
			CWARN("%s: Force deregister of ChangeLog user cl%d "
			      "idle with more than %llu unprocessed records\n",
			      mdd2obd_dev(mdd)->obd_name, mcgc.mcgc_id,
			      mcgc.mcgc_maxindexes);
		else
			CWARN("%s: Force deregister of ChangeLog user cl%d "
			      "idle since more than %us\n",
			      mdd2obd_dev(mdd)->obd_name, mcgc.mcgc_id,
			      mcgc.mcgc_maxtime);

		mdd_changelog_user_purge(env, mdd, mcgc.mcgc_id);

		if (kthread_should_stop())
			GOTO(out_env, rc = 0);

		/* try again to search for another candidate */
		mcgc.mcgc_found = false;
		mcgc.mcgc_maxtime = 0;
		mcgc.mcgc_maxindexes = 0;
	}

out_ctxt:
	if (ctxt != NULL)
		llog_ctxt_put(ctxt);

out_env:
	lu_env_fini(env);
	GOTO(out, rc);
out:
	if (env)
		OBD_FREE_PTR(env);

	spin_lock(&mdd->mdd_cl.mc_lock);
	mdd->mdd_cl.mc_gc_task = MDD_CHLG_GC_NONE;
	spin_unlock(&mdd->mdd_cl.mc_lock);

	return rc;
}

int mdd_trans_stop(const struct lu_env *env, struct mdd_device *mdd,
		   int result, struct thandle *handle)
{
	int rc;

	handle->th_result = result;
	rc = mdd_child_ops(mdd)->dt_trans_stop(env, mdd->mdd_child, handle);
	barrier_exit(mdd->mdd_bottom);

	/* bottom half of changelog garbage-collection mechanism, started
	 * from mdd_changelog_store(). This is required, as running a
	 * kthead can't occur during a journal transaction is being filled
	 * because otherwise a deadlock can happen if memory reclaim is
	 * triggered by kthreadd when forking the new thread, and thus
	 * I/Os could be attempted to the same device from shrinkers
	 * requiring a new journal transaction to be started when current
	 * could never complete (LU-10680).
	 */
	if (unlikely(mdd->mdd_cl.mc_flags & CLM_ON &&
		     cmpxchg(&mdd->mdd_cl.mc_gc_task, MDD_CHLG_GC_NEED,
			     MDD_CHLG_GC_START) == MDD_CHLG_GC_NEED)) {
		/* XXX we may want to cmpxchg() only if MDD_CHLG_GC_NEED
		 * to save its cost in the frequent case and have an extra
		 * if/test cost in the rare case where we need to spawn?
		 */
		struct task_struct *gc_task;
		struct obd_device *obd = mdd2obd_dev(mdd);

		gc_task = kthread_run(mdd_chlg_garbage_collect, mdd,
				      "chlg_gc_thread");
		if (IS_ERR(gc_task)) {
			CERROR("%s: cannot start ChangeLog garbage collection "
			       "thread: rc = %ld\n", obd->obd_name,
			       PTR_ERR(gc_task));
			mdd->mdd_cl.mc_gc_task = MDD_CHLG_GC_NONE;
		} else {
			CDEBUG(D_HA, "%s: a ChangeLog garbage collection "
			       "thread has been started\n", obd->obd_name);
		}
	}

	/* if operation failed, return \a result, otherwise return status of
	 * dt_trans_stop */
	return result ?: rc;
}
