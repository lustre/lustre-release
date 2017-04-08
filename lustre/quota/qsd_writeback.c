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
 * Copyright (c) 2012, 2014, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <linux/kthread.h>
#include "qsd_internal.h"

extern struct kmem_cache *upd_kmem;

/*
 * Allocate and fill an qsd_upd_rec structure to be processed by the writeback
 * thread.
 *
 * \param qqi - is the qsd_qtype_info structure relevant to the update
 * \param lqe - is the lquota entry subject to the update
 * \param qid - is the identifier subject to the update
 * \param rec - is the record storing the new quota settings
 * \param ver - is the version associated with the update
 * \param global - is a boolean set to true if this is an update of the global
 *                 index and false for a slave index.
 */
static struct qsd_upd_rec *qsd_upd_alloc(struct qsd_qtype_info *qqi,
					 struct lquota_entry *lqe,
					 union lquota_id *qid,
					 union lquota_rec *rec, __u64 ver,
					 bool global)
{
	struct qsd_upd_rec	*upd;

	OBD_SLAB_ALLOC_PTR_GFP(upd, upd_kmem, GFP_NOFS);
	if (upd == NULL) {
		return NULL;
	}

	/* fill it */
	INIT_LIST_HEAD(&upd->qur_link);
	upd->qur_qqi = qqi;
	upd->qur_lqe = lqe;
	if (lqe)
		lqe_getref(lqe);
	upd->qur_qid	= *qid;
	upd->qur_rec	= *rec;
	upd->qur_ver	= ver;
	upd->qur_global	= global;

	return upd;
}

static void qsd_upd_free(struct qsd_upd_rec *upd)
{
	if (upd->qur_lqe)
		lqe_putref(upd->qur_lqe);
	OBD_SLAB_FREE_PTR(upd, upd_kmem);
}

/* must hold the qsd_lock */
static void qsd_upd_add(struct qsd_instance *qsd, struct qsd_upd_rec *upd)
{
	if (!qsd->qsd_stopping) {
		list_add_tail(&upd->qur_link, &qsd->qsd_upd_list);
		/* wake up the upd thread */
		wake_up(&qsd->qsd_upd_thread.t_ctl_waitq);
	} else {
		CWARN("%s: discard update.\n", qsd->qsd_svname);
		if (upd->qur_lqe)
			LQUOTA_WARN(upd->qur_lqe, "discard update.");
		qsd_upd_free(upd);
	}
}

/* must hold the qsd_lock */
static void qsd_add_deferred(struct qsd_instance *qsd, struct list_head *list,
			     struct qsd_upd_rec *upd)
{
	struct qsd_upd_rec	*tmp, *n;

	if (qsd->qsd_stopping) {
		CWARN("%s: discard deferred udpate.\n", qsd->qsd_svname);
		if (upd->qur_lqe)
			LQUOTA_WARN(upd->qur_lqe, "discard deferred update.");
		qsd_upd_free(upd);
		return;
	}

	/* Sort the updates in ascending order */
	list_for_each_entry_safe_reverse(tmp, n, list, qur_link) {

		/* There could be some legacy records which have duplicated
		 * version. Imagine following scenario: slave received global
		 * glimpse and queued a record in the deferred list, then
		 * master crash and rollback to an ealier version, then the
		 * version of queued record will be conflicting with later
		 * updates. We should just delete the legacy record in such
		 * case. */
		if (upd->qur_ver == tmp->qur_ver) {
			if (tmp->qur_lqe)
				LQUOTA_WARN(tmp->qur_lqe, "Found a conflict "
					    "record with ver:%llu",
					    tmp->qur_ver);
			else
				CWARN("%s: Found a conflict record with ver: "
				      "%llu\n", qsd->qsd_svname, tmp->qur_ver);

			list_del_init(&tmp->qur_link);
			qsd_upd_free(tmp);
		} else if (upd->qur_ver < tmp->qur_ver) {
			continue;
		} else {
			list_add_tail(&upd->qur_link, &tmp->qur_link);
			return;
		}
	}
	list_add(&upd->qur_link, list);
}

/* must hold the qsd_lock */
static void qsd_kickoff_deferred(struct qsd_qtype_info *qqi,
				 struct list_head *list, __u64 ver)
{
	struct qsd_upd_rec	*upd, *tmp;
	ENTRY;

	/* Get the first update record in the list, which has the smallest
	 * version, discard all records with versions smaller than the current
	 * one */
	list_for_each_entry_safe(upd, tmp, list, qur_link) {
		if (upd->qur_ver <= ver) {
			/* drop this update */
			list_del_init(&upd->qur_link);
			CDEBUG(D_QUOTA, "%s: skipping deferred update ver:"
			       "%llu/%llu, global:%d, qid:%llu\n",
			       qqi->qqi_qsd->qsd_svname, upd->qur_ver, ver,
			       upd->qur_global, upd->qur_qid.qid_uid);
			qsd_upd_free(upd);
		} else {
			break;
		}
	}

	/* No remaining deferred update */
	if (list_empty(list))
		RETURN_EXIT;

	CDEBUG(D_QUOTA, "%s: found deferred update record. "
	       "version:%llu/%llu, global:%d, qid:%llu\n",
	       qqi->qqi_qsd->qsd_svname, upd->qur_ver, ver,
	       upd->qur_global, upd->qur_qid.qid_uid);

	LASSERTF(upd->qur_ver > ver, "lur_ver:%llu, cur_ver:%llu\n",
		 upd->qur_ver, ver);

	/* Kick off the deferred udpate */
	if (upd->qur_ver == ver + 1) {
		list_del_init(&upd->qur_link);
		qsd_upd_add(qqi->qqi_qsd, upd);
	}
	EXIT;
}

/* Bump version of global or slave index copy
 *
 * \param qqi    - qsd_qtype_info
 * \param ver    - version to be bumped to
 * \param global - global or slave index copy?
 */
void qsd_bump_version(struct qsd_qtype_info *qqi, __u64 ver, bool global)
{
	struct list_head *list;
	__u64		 *idx_ver;

	idx_ver = global ? &qqi->qqi_glb_ver : &qqi->qqi_slv_ver;
	list    = global ? &qqi->qqi_deferred_glb : &qqi->qqi_deferred_slv;

	write_lock(&qqi->qqi_qsd->qsd_lock);
	*idx_ver = ver;
	if (global)
		qqi->qqi_glb_uptodate = 1;
	else
		qqi->qqi_slv_uptodate = 1;
	qsd_kickoff_deferred(qqi, list, ver);
	write_unlock(&qqi->qqi_qsd->qsd_lock);
}

/*
 * Schedule a commit of a lquota entry
 *
 * \param  qqi   - qsd_qtype_info
 * \param  lqe   - lquota_entry
 * \param  qid   - quota id
 * \param  rec   - global or slave record to be updated to disk
 * \param  ver   - new index file version
 * \param  global- true: master record; false: slave record
 */
void qsd_upd_schedule(struct qsd_qtype_info *qqi, struct lquota_entry *lqe,
		      union lquota_id *qid, union lquota_rec *rec, __u64 ver,
		      bool global)
{
	struct qsd_upd_rec	*upd;
	struct qsd_instance	*qsd = qqi->qqi_qsd;
	__u64			 cur_ver;
	ENTRY;

	CDEBUG(D_QUOTA, "%s: schedule update. global:%s, version:%llu\n",
	       qsd->qsd_svname, global ? "true" : "false", ver);

	upd = qsd_upd_alloc(qqi, lqe, qid, rec, ver, global);
	if (upd == NULL)
		RETURN_EXIT;

	/* If we don't want update index version, no need to sort the
	 * records in version order, just schedule the updates instantly. */
	if (ver == 0) {
		write_lock(&qsd->qsd_lock);
		qsd_upd_add(qsd, upd);
		write_unlock(&qsd->qsd_lock);
		RETURN_EXIT;
	}

	write_lock(&qsd->qsd_lock);

	cur_ver = global ? qqi->qqi_glb_ver : qqi->qqi_slv_ver;

	if (ver <= cur_ver) {
		if (global)
			/* legitimate race between glimpse AST and
			 * reintegration */
			CDEBUG(D_QUOTA, "%s: discarding glb update from glimpse"
			       " ver:%llu local ver:%llu\n",
			       qsd->qsd_svname, ver, cur_ver);
		else
			CERROR("%s: discard slv update, ver:%llu local ver:"
			       "%llu\n", qsd->qsd_svname, ver, cur_ver);
		qsd_upd_free(upd);
	} else if ((ver == cur_ver + 1) && qqi->qqi_glb_uptodate &&
		   qqi->qqi_slv_uptodate) {
		/* In order update, and reintegration has been done. */
		qsd_upd_add(qsd, upd);
	} else {
		/* Out of order update (the one with smaller version hasn't
		 * reached slave or hasn't been flushed to disk yet), or
		 * the reintegration is in progress. Defer the update. */
		struct list_head *list = global ? &qqi->qqi_deferred_glb :
						  &qqi->qqi_deferred_slv;
		qsd_add_deferred(qsd, list, upd);
	}

	write_unlock(&qsd->qsd_lock);

	EXIT;
}

static int qsd_process_upd(const struct lu_env *env, struct qsd_upd_rec *upd)
{
	struct lquota_entry	*lqe = upd->qur_lqe;
	struct qsd_qtype_info	*qqi = upd->qur_qqi;
	int			 rc;
	ENTRY;

	if (lqe == NULL) {
		lqe = lqe_locate(env, qqi->qqi_site, &upd->qur_qid);
		if (IS_ERR(lqe))
			GOTO(out, rc = PTR_ERR(lqe));
	}

	/* The in-memory lqe update for slave index copy isn't deferred,
	 * we shouldn't touch it here. */
	if (upd->qur_global) {
		rc = qsd_update_lqe(env, lqe, upd->qur_global, &upd->qur_rec);
		if (rc)
			GOTO(out, rc);
		/* refresh usage */
		qsd_refresh_usage(env, lqe);
		/* Report usage asynchronously */
		rc = qsd_adjust(env, lqe);
		if (rc)
			LQUOTA_ERROR(lqe, "failed to report usage, rc:%d", rc);
	}

	rc = qsd_update_index(env, qqi, &upd->qur_qid, upd->qur_global,
			      upd->qur_ver, &upd->qur_rec);
out:
	if (lqe && !IS_ERR(lqe)) {
		lqe_putref(lqe);
		upd->qur_lqe = NULL;
	}
	RETURN(rc);
}

void qsd_adjust_schedule(struct lquota_entry *lqe, bool defer, bool cancel)
{
	struct qsd_instance	*qsd = lqe2qqi(lqe)->qqi_qsd;
	bool			 added = false;

	read_lock(&qsd->qsd_lock);
	if (qsd->qsd_stopping) {
		read_unlock(&qsd->qsd_lock);
		return;
	}
	read_unlock(&qsd->qsd_lock);

	lqe_getref(lqe);
	spin_lock(&qsd->qsd_adjust_lock);

	/* the lqe is being queued for the per-ID lock cancel, we should
	 * cancel the lock cancel and re-add it for quota adjust */
	if (!list_empty(&lqe->lqe_link) &&
	    lqe->lqe_adjust_time == 0) {
		list_del_init(&lqe->lqe_link);
		lqe_putref(lqe);
	}

	if (list_empty(&lqe->lqe_link)) {
		if (!cancel) {
			lqe->lqe_adjust_time = ktime_get_seconds();
			if (defer)
				lqe->lqe_adjust_time += QSD_WB_INTERVAL;
		} else {
			lqe->lqe_adjust_time = 0;
		}

		/* lqe reference transferred to list */
		if (defer)
			list_add_tail(&lqe->lqe_link,
					  &qsd->qsd_adjust_list);
		else
			list_add(&lqe->lqe_link, &qsd->qsd_adjust_list);
		added = true;
	}
	spin_unlock(&qsd->qsd_adjust_lock);

	if (added)
		wake_up(&qsd->qsd_upd_thread.t_ctl_waitq);
	else
		lqe_putref(lqe);
}

/* return true if there is pending writeback records or the pending
 * adjust requests */
static bool qsd_job_pending(struct qsd_instance *qsd, struct list_head *upd,
			    bool *uptodate)
{
	bool	job_pending = false;
	int	qtype;

	LASSERT(list_empty(upd));
	*uptodate = true;

	spin_lock(&qsd->qsd_adjust_lock);
	if (!list_empty(&qsd->qsd_adjust_list)) {
		struct lquota_entry *lqe;
		lqe = list_entry(qsd->qsd_adjust_list.next,
				     struct lquota_entry, lqe_link);
		if (ktime_get_seconds() > lqe->lqe_adjust_time)
			job_pending = true;
	}
	spin_unlock(&qsd->qsd_adjust_lock);

	write_lock(&qsd->qsd_lock);
	if (!list_empty(&qsd->qsd_upd_list)) {
		list_splice_init(&qsd->qsd_upd_list, upd);
		job_pending = true;
	}

	for (qtype = USRQUOTA; qtype < LL_MAXQUOTAS; qtype++) {
		struct qsd_qtype_info *qqi = qsd->qsd_type_array[qtype];

		/* don't bother kicking off reintegration if space accounting
		 * failed to be enabled */
		if (qqi->qqi_acct_failed)
			continue;

		if (!qsd_type_enabled(qsd, qtype))
			continue;

		if ((!qqi->qqi_glb_uptodate || !qqi->qqi_slv_uptodate) &&
		     !qqi->qqi_reint)
			/* global or slave index not up to date and reint
			 * thread not running */
			*uptodate = false;
	}

	write_unlock(&qsd->qsd_lock);
	return job_pending;
}

static int qsd_upd_thread(void *arg)
{
	struct qsd_instance	*qsd = (struct qsd_instance *)arg;
	struct ptlrpc_thread	*thread = &qsd->qsd_upd_thread;
	struct l_wait_info	 lwi;
	struct list_head	 queue;
	struct qsd_upd_rec	*upd, *n;
	struct lu_env		*env;
	int			 qtype, rc = 0;
	bool			 uptodate;
	struct lquota_entry	*lqe;
	time64_t cur_time;
	ENTRY;

	OBD_ALLOC_PTR(env);
	if (env == NULL)
		RETURN(-ENOMEM);

	rc = lu_env_init(env, LCT_DT_THREAD);
	if (rc) {
		CERROR("%s: cannot init env: rc = %d\n", qsd->qsd_svname, rc);
		OBD_FREE_PTR(env);
		RETURN(rc);
	}

	thread_set_flags(thread, SVC_RUNNING);
	wake_up(&thread->t_ctl_waitq);

	INIT_LIST_HEAD(&queue);
	lwi = LWI_TIMEOUT(cfs_time_seconds(QSD_WB_INTERVAL), NULL, NULL);
	while (1) {
		l_wait_event(thread->t_ctl_waitq,
			     qsd_job_pending(qsd, &queue, &uptodate) ||
			     !thread_is_running(thread), &lwi);

		list_for_each_entry_safe(upd, n, &queue, qur_link) {
			list_del_init(&upd->qur_link);
			qsd_process_upd(env, upd);
			qsd_upd_free(upd);
		}

		spin_lock(&qsd->qsd_adjust_lock);
		cur_time = ktime_get_seconds();
		while (!list_empty(&qsd->qsd_adjust_list)) {
			lqe = list_entry(qsd->qsd_adjust_list.next,
					 struct lquota_entry, lqe_link);
			/* deferred items are sorted by time */
			if (lqe->lqe_adjust_time > cur_time)
				break;

			list_del_init(&lqe->lqe_link);
			spin_unlock(&qsd->qsd_adjust_lock);

			if (thread_is_running(thread) && uptodate) {
				qsd_refresh_usage(env, lqe);
				if (lqe->lqe_adjust_time == 0)
					qsd_id_lock_cancel(env, lqe);
				else
					qsd_adjust(env, lqe);
			}

			lqe_putref(lqe);
			spin_lock(&qsd->qsd_adjust_lock);
		}
		spin_unlock(&qsd->qsd_adjust_lock);

		if (!thread_is_running(thread))
			break;

		if (uptodate)
			continue;

		for (qtype = USRQUOTA; qtype < LL_MAXQUOTAS; qtype++)
			qsd_start_reint_thread(qsd->qsd_type_array[qtype]);
	}
	lu_env_fini(env);
	OBD_FREE_PTR(env);
	thread_set_flags(thread, SVC_STOPPED);
	wake_up(&thread->t_ctl_waitq);
	RETURN(rc);
}

int qsd_start_upd_thread(struct qsd_instance *qsd)
{
	struct ptlrpc_thread	*thread = &qsd->qsd_upd_thread;
	struct l_wait_info	 lwi = { 0 };
	struct task_struct		*task;
	ENTRY;

	task = kthread_run(qsd_upd_thread, (void *)qsd,
			   "lquota_wb_%s", qsd->qsd_svname);
	if (IS_ERR(task)) {
		CERROR("fail to start quota update thread: rc = %ld\n",
			PTR_ERR(task));
		thread_set_flags(thread, SVC_STOPPED);
		RETURN(PTR_ERR(task));
	}

	l_wait_event(thread->t_ctl_waitq,
		     thread_is_running(thread) || thread_is_stopped(thread),
		     &lwi);
	RETURN(0);
}

static void qsd_cleanup_deferred(struct qsd_instance *qsd)
{
	int	qtype;

	for (qtype = USRQUOTA; qtype < LL_MAXQUOTAS; qtype++) {
		struct qsd_upd_rec	*upd, *tmp;
		struct qsd_qtype_info	*qqi = qsd->qsd_type_array[qtype];

		if (qqi == NULL)
			continue;

		write_lock(&qsd->qsd_lock);
		list_for_each_entry_safe(upd, tmp, &qqi->qqi_deferred_glb,
					 qur_link) {
			CWARN("%s: Free global deferred upd: ID:%llu, "
			      "ver:%llu/%llu\n", qsd->qsd_svname,
			      upd->qur_qid.qid_uid, upd->qur_ver,
			      qqi->qqi_glb_ver);
			list_del_init(&upd->qur_link);
			qsd_upd_free(upd);
		}
		list_for_each_entry_safe(upd, tmp, &qqi->qqi_deferred_slv,
					 qur_link) {
			CWARN("%s: Free slave deferred upd: ID:%llu, "
			      "ver:%llu/%llu\n", qsd->qsd_svname,
			      upd->qur_qid.qid_uid, upd->qur_ver,
			      qqi->qqi_slv_ver);
			list_del_init(&upd->qur_link);
			qsd_upd_free(upd);
		}
		write_unlock(&qsd->qsd_lock);
	}
}

static void qsd_cleanup_adjust(struct qsd_instance *qsd)
{
	struct lquota_entry	*lqe;

	spin_lock(&qsd->qsd_adjust_lock);
	while (!list_empty(&qsd->qsd_adjust_list)) {
		lqe = list_entry(qsd->qsd_adjust_list.next,
				 struct lquota_entry, lqe_link);
		list_del_init(&lqe->lqe_link);
		lqe_putref(lqe);
	}
	spin_unlock(&qsd->qsd_adjust_lock);
}

void qsd_stop_upd_thread(struct qsd_instance *qsd)
{
	struct ptlrpc_thread	*thread = &qsd->qsd_upd_thread;
	struct l_wait_info	 lwi    = { 0 };

	if (!thread_is_stopped(thread)) {
		thread_set_flags(thread, SVC_STOPPING);
		wake_up(&thread->t_ctl_waitq);

		l_wait_event(thread->t_ctl_waitq, thread_is_stopped(thread),
			     &lwi);
	}
	qsd_cleanup_deferred(qsd);
	qsd_cleanup_adjust(qsd);
}
