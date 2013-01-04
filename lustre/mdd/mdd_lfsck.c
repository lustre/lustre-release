/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * lustre/mdd/mdd_lfsck.c
 *
 * Top-level entry points into mdd module
 *
 * LFSCK controller, which scans the whole device through low layer
 * iteration APIs, drives all lfsck compeonents, controls the speed.
 *
 * Author: Fan Yong <yong.fan@whamcloud.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <lustre/lustre_idl.h>
#include <lustre_fid.h>

#include "mdd_internal.h"

static inline char *mdd_lfsck2name(struct md_lfsck *lfsck)
{
	struct mdd_device *mdd;

	mdd = container_of0(lfsck, struct mdd_device, mdd_lfsck);
	return mdd2obd_dev(mdd)->obd_name;
}

void mdd_lfsck_set_speed(struct md_lfsck *lfsck, __u32 limit)
{
	spin_lock(&lfsck->ml_lock);
	lfsck->ml_speed_limit = limit;
	if (limit != LFSCK_SPEED_NO_LIMIT) {
		if (limit > CFS_HZ) {
			lfsck->ml_sleep_rate = limit / CFS_HZ;
			lfsck->ml_sleep_jif = 1;
		} else {
			lfsck->ml_sleep_rate = 1;
			lfsck->ml_sleep_jif = CFS_HZ / limit;
		}
	} else {
		lfsck->ml_sleep_jif = 0;
		lfsck->ml_sleep_rate = 0;
	}
	spin_unlock(&lfsck->ml_lock);
}

static void mdd_lfsck_control_speed(struct md_lfsck *lfsck)
{
	struct ptlrpc_thread *thread = &lfsck->ml_thread;
	struct l_wait_info    lwi;

	if (lfsck->ml_sleep_jif > 0 &&
	    lfsck->ml_new_scanned >= lfsck->ml_sleep_rate) {
		spin_lock(&lfsck->ml_lock);
		if (likely(lfsck->ml_sleep_jif > 0 &&
			   lfsck->ml_new_scanned >= lfsck->ml_sleep_rate)) {
			lwi = LWI_TIMEOUT_INTR(lfsck->ml_sleep_jif, NULL,
					       LWI_ON_SIGNAL_NOOP, NULL);
			spin_unlock(&lfsck->ml_lock);

			l_wait_event(thread->t_ctl_waitq,
				     !thread_is_running(thread),
				     &lwi);
			lfsck->ml_new_scanned = 0;
		} else {
			spin_unlock(&lfsck->ml_lock);
		}
	}
}

static int mdd_lfsck_main(void *args)
{
	struct lu_env		 env;
	struct md_lfsck		*lfsck  = (struct md_lfsck *)args;
	struct ptlrpc_thread	*thread = &lfsck->ml_thread;
	struct dt_object	*obj    = lfsck->ml_it_obj;
	const struct dt_it_ops	*iops   = &obj->do_index_ops->dio_it;
	struct dt_it		*di;
	struct lu_fid		*fid;
	int			 rc;
	ENTRY;

	cfs_daemonize("lfsck");
	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0) {
		CERROR("%s: LFSCK, fail to init env, rc = %d\n",
		       mdd_lfsck2name(lfsck), rc);
		GOTO(noenv, rc);
	}

	di = iops->init(&env, obj, lfsck->ml_args, BYPASS_CAPA);
	if (IS_ERR(di)) {
		rc = PTR_ERR(di);
		CERROR("%s: LFSCK, fail to init iteration, rc = %d\n",
		       mdd_lfsck2name(lfsck), rc);
		GOTO(fini_env, rc);
	}

	CDEBUG(D_LFSCK, "LFSCK: flags = 0x%x, pid = %d\n",
	       lfsck->ml_args, cfs_curproc_pid());

	/* XXX: Prepare before wakeup the sponsor.
	 *      Each lfsck component should call iops->get() API with
	 *      every bookmark, then low layer module can decide the
	 *      start point for current iteration. */

	spin_lock(&lfsck->ml_lock);
	thread_set_flags(thread, SVC_RUNNING);
	spin_unlock(&lfsck->ml_lock);
	cfs_waitq_broadcast(&thread->t_ctl_waitq);

	/* Call iops->load() to finish the choosing start point. */
	rc = iops->load(&env, di, 0);
	if (rc != 0)
		GOTO(out, rc);

	CDEBUG(D_LFSCK, "LFSCK: iteration start: pos = %s\n",
	       (char *)iops->key(&env, di));

	lfsck->ml_new_scanned = 0;
	fid = &mdd_env_info(&env)->mti_fid;
	while (rc == 0) {
		iops->rec(&env, di, (struct dt_rec *)fid, 0);

		/* XXX: here, perform LFSCK when some LFSCK component(s)
		 *      introduced in the future. */
		lfsck->ml_new_scanned++;

		/* XXX: here, make checkpoint when some LFSCK component(s)
		 *      introduced in the future. */

		/* Rate control. */
		mdd_lfsck_control_speed(lfsck);
		if (unlikely(!thread_is_running(thread)))
			GOTO(out, rc = 0);

		rc = iops->next(&env, di);
	}

	GOTO(out, rc);

out:
	if (lfsck->ml_paused) {
		/* XXX: It is hack here: if the lfsck is still running when MDS
		 *	umounts, it should be restarted automatically after MDS
		 *	remounts up.
		 *
		 *	To support that, we need to record the lfsck status in
		 *	the lfsck on-disk bookmark file. But now, there is not
		 *	lfsck component under the lfsck framework. To avoid to
		 *	introduce unnecessary bookmark incompatibility issues,
		 *	we write nothing to the lfsck bookmark file now.
		 *
		 *	Instead, we will reuse dt_it_ops::put() method to notify
		 *	low layer iterator to process such case.
		 *
		 * 	It is just temporary solution, and will be replaced when
		 * 	some lfsck component is introduced in the future. */
		iops->put(&env, di);
		CDEBUG(D_LFSCK, "LFSCK: iteration pasued: pos = %s, rc = %d\n",
		       (char *)iops->key(&env, di), rc);
	} else {
		CDEBUG(D_LFSCK, "LFSCK: iteration stop: pos = %s, rc = %d\n",
		       (char *)iops->key(&env, di), rc);
	}
	iops->fini(&env, di);

fini_env:
	lu_env_fini(&env);

noenv:
	spin_lock(&lfsck->ml_lock);
	thread_set_flags(thread, SVC_STOPPED);
	cfs_waitq_broadcast(&thread->t_ctl_waitq);
	spin_unlock(&lfsck->ml_lock);
	return rc;
}

int mdd_lfsck_start(const struct lu_env *env, struct md_lfsck *lfsck,
		    struct lfsck_start *start)
{
	struct ptlrpc_thread *thread  = &lfsck->ml_thread;
	struct l_wait_info    lwi     = { 0 };
	int		      rc      = 0;
	__u16		      valid   = 0;
	__u16		      flags   = 0;
	ENTRY;

	if (lfsck->ml_it_obj == NULL)
		RETURN(-ENOTSUPP);

	mutex_lock(&lfsck->ml_mutex);
	spin_lock(&lfsck->ml_lock);
	if (thread_is_running(thread)) {
		spin_unlock(&lfsck->ml_lock);
		mutex_unlock(&lfsck->ml_mutex);
		RETURN(-EALREADY);
	}

	spin_unlock(&lfsck->ml_lock);
	if (start->ls_valid & LSV_SPEED_LIMIT)
		mdd_lfsck_set_speed(lfsck, start->ls_speed_limit);

	if (start->ls_valid & LSV_ERROR_HANDLE) {
		valid |= DOIV_ERROR_HANDLE;
		if (start->ls_flags & LPF_FAILOUT)
			flags |= DOIF_FAILOUT;
	}

	/* XXX: 1. low layer does not care 'dryrun'.
	 *      2. will process 'ls_active' when introduces LFSCK for layout
	 *	   consistency, DNE consistency, and so on in the future. */
	start->ls_active = 0;

	if (start->ls_flags & LPF_RESET)
		flags |= DOIF_RESET;

	if (start->ls_active != 0)
		flags |= DOIF_OUTUSED;

	lfsck->ml_args = (flags << DT_OTABLE_IT_FLAGS_SHIFT) | valid;
	thread_set_flags(thread, 0);
	rc = cfs_create_thread(mdd_lfsck_main, lfsck, 0);
	if (rc < 0)
		CERROR("%s: cannot start LFSCK thread, rc = %d\n",
		       mdd_lfsck2name(lfsck), rc);
	else
		l_wait_event(thread->t_ctl_waitq,
			     thread_is_running(thread) ||
			     thread_is_stopped(thread),
			     &lwi);
	mutex_unlock(&lfsck->ml_mutex);

	RETURN(rc < 0 ? rc : 0);
}

int mdd_lfsck_stop(const struct lu_env *env, struct md_lfsck *lfsck)
{
	struct ptlrpc_thread *thread = &lfsck->ml_thread;
	struct l_wait_info    lwi    = { 0 };
	ENTRY;

	mutex_lock(&lfsck->ml_mutex);
	spin_lock(&lfsck->ml_lock);
	if (thread_is_init(thread) || thread_is_stopped(thread)) {
		spin_unlock(&lfsck->ml_lock);
		mutex_unlock(&lfsck->ml_mutex);
		RETURN(-EALREADY);
	}

	thread_set_flags(thread, SVC_STOPPING);
	spin_unlock(&lfsck->ml_lock);

	cfs_waitq_broadcast(&thread->t_ctl_waitq);
	l_wait_event(thread->t_ctl_waitq,
		     thread_is_stopped(thread),
		     &lwi);
	mutex_unlock(&lfsck->ml_mutex);

	RETURN(0);
}

const char lfsck_bookmark_name[] = "lfsck_bookmark";

static const struct lu_fid lfsck_it_fid = { .f_seq = FID_SEQ_LOCAL_FILE,
					    .f_oid = OTABLE_IT_OID,
					    .f_ver = 0 };

int mdd_lfsck_setup(const struct lu_env *env, struct mdd_device *mdd)
{
	struct md_lfsck  *lfsck = &mdd->mdd_lfsck;
	struct dt_object *obj;
	int		  rc;

	memset(lfsck, 0, sizeof(*lfsck));
	lfsck->ml_version = LFSCK_VERSION_V1;
	cfs_waitq_init(&lfsck->ml_thread.t_ctl_waitq);
	mutex_init(&lfsck->ml_mutex);
	spin_lock_init(&lfsck->ml_lock);

	obj = dt_store_open(env, mdd->mdd_child, "", lfsck_bookmark_name,
			    &mdd_env_info(env)->mti_fid);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	lfsck->ml_bookmark_obj = obj;

	obj = dt_locate(env, mdd->mdd_child, &lfsck_it_fid);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	rc = obj->do_ops->do_index_try(env, obj, &dt_otable_features);
	if (rc != 0) {
		lu_object_put(env, &obj->do_lu);
		if (rc == -ENOTSUPP)
			rc = 0;
		return rc;
	}

	lfsck->ml_it_obj = obj;

	return 0;
}

void mdd_lfsck_cleanup(const struct lu_env *env, struct mdd_device *mdd)
{
	struct md_lfsck *lfsck = &mdd->mdd_lfsck;

	if (lfsck->ml_it_obj != NULL) {
		lfsck->ml_paused = 1;
		mdd_lfsck_stop(env, lfsck);
		lu_object_put(env, &lfsck->ml_it_obj->do_lu);
		lfsck->ml_it_obj = NULL;
	}

	if (lfsck->ml_bookmark_obj != NULL) {
		lu_object_put(env, &lfsck->ml_bookmark_obj->do_lu);
		lfsck->ml_bookmark_obj = NULL;
	}
}
