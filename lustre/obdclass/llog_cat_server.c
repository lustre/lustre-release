// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * OST<->MDS recovery logging infrastructure.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <obd_class.h>

#include "llog_internal.h"

/* Create a new log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 */
static int llog_cat_new_log(const struct lu_env *env,
			    struct llog_handle *cathandle,
			    struct llog_handle *loghandle,
			    struct thandle *th)
{
	struct llog_thread_info	*lgi = llog_info(env);
	struct llog_logid_rec *rec = &lgi->lgi_logid;
	struct thandle *handle = NULL;
	struct dt_device *dt = NULL;
	struct llog_log_hdr *llh = cathandle->lgh_hdr;
	int rc, index;

	ENTRY;
	index = (cathandle->lgh_last_idx + 1) % (llog_max_idx(cathandle) + 1);

	/* check that new llog index will not overlap with the first one.
	 * - llh_cat_idx is the index just before the first/oldest still in-use
	 *	index in catalog
	 * - lgh_last_idx is the last/newest used index in catalog
	 *
	 * When catalog is not wrapped yet then lgh_last_idx is always larger
	 * than llh_cat_idx. After the wrap around lgh_last_idx re-starts
	 * from 0 and llh_cat_idx becomes the upper limit for it
	 *
	 * Check if catalog has already wrapped around or not by comparing
	 * last_idx and cat_idx
	 */
	if ((index == llh->llh_cat_idx + 1 && llh->llh_count > 1) ||
	    (index == 0 && llh->llh_cat_idx == 0)) {
		if (!cathandle->lgh_name) {
			CWARN("%s: there are no more free slots in catalog "DFID"\n",
			      loghandle2name(loghandle),
			      PLOGID(&cathandle->lgh_id));
		} else {
			CWARN("%s: there are no more free slots in catalog %s\n",
			      loghandle2name(loghandle), cathandle->lgh_name);
		}
		RETURN(-ENOSPC);
	}

	if (CFS_FAIL_CHECK(OBD_FAIL_MDS_LLOG_CREATE_FAILED))
		RETURN(-ENOSPC);

	if (loghandle->lgh_hdr) {
		/* If llog object is remote and creation is failed, lgh_hdr
		 * might be left over here, free it first
		 */
		LASSERT(!llog_exist(loghandle));
		OBD_FREE_LARGE(loghandle->lgh_hdr, loghandle->lgh_hdr_size);
		loghandle->lgh_hdr = NULL;
	}

	if (!th) {
		dt = lu2dt_dev(cathandle->lgh_obj->do_lu.lo_dev);
		if (IS_ERR(dt))
			RETURN(PTR_ERR(dt));

		handle = dt_trans_create(env, dt);
		if (IS_ERR(handle))
			RETURN(PTR_ERR(handle));

		/* Create update llog object synchronously, which
		 * happens during inialization process see
		 * lod_sub_prep_llog(), to make sure the update
		 * llog object is created before corss-MDT writing
		 * updates into the llog object
		 */
		if (cathandle->lgh_ctxt->loc_flags & LLOG_CTXT_FLAG_NORMAL_FID)
			handle->th_sync = 1;

		handle->th_wait_submit = 1;

		rc = llog_declare_create(env, loghandle, handle);
		if (rc != 0)
			GOTO(out, rc);

		rec->lid_hdr.lrh_len = sizeof(*rec);
		rec->lid_hdr.lrh_type = LLOG_LOGID_MAGIC;
		rec->lid_id = loghandle->lgh_id;
		rc = llog_declare_write_rec(env, cathandle, &rec->lid_hdr, -1,
					    handle);
		if (rc != 0)
			GOTO(out, rc);
		dt_declare_attr_set(env, cathandle->lgh_obj, NULL, handle);

		rc = dt_trans_start_local(env, dt, handle);
		if (rc != 0)
			GOTO(out, rc);

		th = handle;
	}

	rc = llog_create(env, loghandle, th);
	/* if llog is already created, no need to initialize it */
	if (rc == -EEXIST) {
		GOTO(out, rc);
	} else if (rc != 0) {
		CERROR("%s: can't create new plain llog in catalog: rc = %d\n",
		       loghandle2name(loghandle), rc);
		GOTO(out, rc);
	}

	rc = llog_init_handle(env, loghandle, (cathandle->lgh_hdr->llh_flags &
			      LLOG_F_EXT_MASK) |
			      LLOG_F_IS_PLAIN | LLOG_F_ZAP_WHEN_EMPTY,
			      &cathandle->lgh_hdr->llh_tgtuuid);
	if (rc < 0)
		GOTO(out, rc);

	/* build the record for this log in the catalog */
	rec->lid_hdr.lrh_len = sizeof(*rec);
	rec->lid_hdr.lrh_type = LLOG_LOGID_MAGIC;
	rec->lid_id = loghandle->lgh_id;

	/* append the new record into catalog. The new index will be
	 * assigned to the record and updated in rec header
	 */
	rc = llog_write_rec(env, cathandle, &rec->lid_hdr,
			    &loghandle->u.phd.phd_cookie, LLOG_NEXT_IDX, th);
	if (rc < 0)
		GOTO(out_destroy, rc);
	/* update for catalog which doesn't happen very often */
	lgi->lgi_attr.la_valid = LA_MTIME;
	lgi->lgi_attr.la_mtime = ktime_get_real_seconds();
	dt_attr_set(env, cathandle->lgh_obj, &lgi->lgi_attr, th);

	CDEBUG(D_OTHER, "new plain log "DFID".%u of catalog "DFID"\n",
	       PLOGID(&loghandle->lgh_id), rec->lid_hdr.lrh_index,
	       PLOGID(&cathandle->lgh_id));

	if (loghandle->lgh_hdr)
		loghandle->lgh_hdr->llh_cat_idx = rec->lid_hdr.lrh_index;

	/* limit max size of plain llog so that space can be
	 * released sooner, especially on small filesystems
	 * 2MB for the cases when free space hasn't been learned yet
	 */
	loghandle->lgh_max_size = 2 << 20;
	dt = lu2dt_dev(cathandle->lgh_obj->do_lu.lo_dev);
	if (IS_ERR(dt))
		GOTO(out_destroy, rc = PTR_ERR(dt));

	rc = dt_statfs(env, dt, &lgi->lgi_statfs);
	if (rc == 0 && lgi->lgi_statfs.os_bfree > 0) {
		u64 freespace = (lgi->lgi_statfs.os_bfree *
				 lgi->lgi_statfs.os_bsize) >> 6;

		if (freespace < loghandle->lgh_max_size)
			loghandle->lgh_max_size = freespace;
		/* shouldn't be > 128MB in any case?
		 * it's 256K records of 512 bytes each
		 */
		if (freespace > (128 << 20))
			loghandle->lgh_max_size = 128 << 20;
	}
	if (unlikely(CFS_FAIL_PRECHECK(OBD_FAIL_PLAIN_RECORDS) ||
		     CFS_FAIL_PRECHECK(OBD_FAIL_CATALOG_FULL_CHECK))) {
		/* limit the numer of plain records for test */
		loghandle->lgh_max_size = loghandle->lgh_hdr_size +
					  cfs_fail_val * 64;
	}
	rc = 0;
out:
	if (handle) {
		handle->th_result = (rc >= 0 || rc == -EEXIST) ? 0 : rc;
		if (!IS_ERR_OR_NULL(dt))
			dt_trans_stop(env, dt, handle);
	}
	RETURN(rc);

out_destroy:
	/* to signal llog_cat_close() it shouldn't try to destroy the llog,
	 * we want to destroy it in this transaction, otherwise the object
	 * becomes an orphan
	 */
	loghandle->lgh_hdr->llh_flags &= ~LLOG_F_ZAP_WHEN_EMPTY;
	/* this is to mimic full log, so another llog_cat_current_log()
	 * can skip it and ask for another one
	 */
	loghandle->lgh_last_idx = llog_max_idx(loghandle) + 1;
	llog_trans_destroy(env, loghandle, th);
	if (handle)
		dt_trans_stop(env, dt, handle);
	RETURN(rc);
}

static int llog_cat_refresh(const struct lu_env *env,
			    struct llog_handle *cathandle)
{
	struct llog_handle *loghandle;
	int rc;

	LASSERT(rwsem_is_locked(&cathandle->lgh_lock));

	list_for_each_entry(loghandle, &cathandle->u.chd.chd_head,
			    u.phd.phd_entry) {
		if (!llog_exist(loghandle))
			continue;

		down_write(&loghandle->lgh_lock);
		rc = llog_read_header(env, loghandle, NULL);
		up_write(&loghandle->lgh_lock);
		if (rc)
			goto out;
	}

	rc = llog_read_header(env, cathandle, NULL);
out:
	return rc;
}

static inline int llog_cat_declare_create(const struct lu_env *env,
					  struct llog_handle *cathandle,
					  struct llog_handle *loghandle,
					  struct thandle *th)
{

	struct llog_thread_info	*lgi = llog_info(env);
	struct llog_logid_rec *lirec = &lgi->lgi_logid;
	int rc;

	if (dt_object_remote(cathandle->lgh_obj)) {
		down_write(&loghandle->lgh_lock);
		if (!llog_exist(loghandle))
			rc = llog_cat_new_log(env, cathandle, loghandle, NULL);
		else
			rc = 0;
		up_write(&loghandle->lgh_lock);
	} else {

		rc = llog_declare_create(env, loghandle, th);
		if (rc)
			return rc;

		lirec->lid_hdr.lrh_len = sizeof(*lirec);
		rc = llog_declare_write_rec(env, cathandle, &lirec->lid_hdr, -1,
					    th);
		if (!rc)
			dt_declare_attr_set(env, cathandle->lgh_obj, NULL, th);
	}
	return rc;
}
/*
 * prepare current/next log for catalog.
 *
 * if \a *ploghandle is NULL, open it, and declare create, NB, if \a
 * *ploghandle is remote, create it synchronously here, see comments
 * below.
 *
 * \a cathandle->lgh_lock is down_read-ed, it gets down_write-ed if \a
 * *ploghandle has to be opened.
 */
static int llog_cat_prep_log(const struct lu_env *env,
			     struct llog_handle *cathandle,
			     struct llog_handle **ploghandle,
			     struct thandle *th)
{
	struct llog_handle *loghandle;
	int rc;

	rc = 0;
	loghandle = *ploghandle;
	if (!IS_ERR_OR_NULL(loghandle)) {
		loghandle = llog_handle_get(loghandle);
		if (loghandle && loghandle->lgh_destroyed) {
			llog_handle_put(env, loghandle);
		} else if (loghandle) {
			if (!llog_exist(loghandle))
				rc = llog_cat_declare_create(env, cathandle,
							     loghandle, th);
			llog_handle_put(env, loghandle);
			return rc;
		}
	}

	down_write(&cathandle->lgh_lock);
	if (!IS_ERR_OR_NULL(*ploghandle)) {
		loghandle = llog_handle_get(*ploghandle);
		if (loghandle && loghandle->lgh_destroyed) {
			llog_handle_put(env, loghandle);
		} else if (loghandle) {
			up_write(&cathandle->lgh_lock);
			if (!llog_exist(loghandle))
				rc = llog_cat_declare_create(env, cathandle,
							     loghandle, th);
			llog_handle_put(env, loghandle);
			return rc;
		}
	}

	/* Slow path with open/create declare, only one thread do all stuff
	 * and share loghandle at the end
	 */
	rc = llog_open(env, cathandle->lgh_ctxt, &loghandle, NULL, NULL,
		       LLOG_OPEN_NEW);
	if (rc) {
		up_write(&cathandle->lgh_lock);
		CDEBUG(D_OTHER, "%s: failed to open log, catalog "DFID" %d\n",
		       loghandle2name(cathandle), PLOGID(&cathandle->lgh_id),
		       rc);
		return rc;
	}

	rc = llog_cat_declare_create(env, cathandle, loghandle, th);
	if (!rc) {
		list_add(&loghandle->u.phd.phd_entry,
			 &cathandle->u.chd.chd_head);
		*ploghandle = loghandle;
	}

	up_write(&cathandle->lgh_lock);
	CDEBUG(D_OTHER, "%s: open log "DFID" for catalog "DFID" rc=%d\n",
	       loghandle2name(cathandle), PLOGID(&loghandle->lgh_id),
	       PLOGID(&cathandle->lgh_id), rc);

	if (rc)
		llog_close(env, loghandle);

	return rc;
}

/** Return the currently active log handle.  If the current log handle doesn't
 * have enough space left for the current record, start a new one.
 *
 * If reclen is 0, we only want to know what the currently active log is,
 * otherwise we get a lock on this log so nobody can steal our space.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 *
 * NOTE: loghandle is write-locked and referenced upon successful return
 */
static struct llog_handle *llog_cat_current_log(const struct lu_env *env,
						struct llog_handle *cathandle,
						struct thandle *th)
{
	struct llog_handle *loghandle;
	struct llog_logid lid = {
		.lgl_oi.oi.oi_id = 0,
		.lgl_oi.oi.oi_seq = 0,
		.lgl_ogen = 0
	};

	ENTRY;
	if (CFS_FAIL_CHECK(OBD_FAIL_MDS_LLOG_CREATE_FAILED2)) {
		loghandle = cathandle->u.chd.chd_current_log;
		GOTO(next, loghandle);
	}

retry:
	loghandle = cathandle->u.chd.chd_current_log;
	if (!IS_ERR_OR_NULL(loghandle) && llog_handle_get(loghandle)) {
		down_write_nested(&loghandle->lgh_lock, LLOGH_LOG);
		if (!loghandle->lgh_destroyed && !llog_is_full(loghandle))
			RETURN(loghandle);
		up_write(&loghandle->lgh_lock);
		lid = loghandle->lgh_id;
		llog_handle_put(env, loghandle);
	}

	/* time to use next log */
next:
	/* first, we have to make sure the state hasn't changed */
	down_write_nested(&cathandle->lgh_lock, LLOGH_CAT);
	if (unlikely(loghandle == cathandle->u.chd.chd_current_log)) {
		/* Sigh, the chd_next_log and chd_current_log is initialized
		 * in declare phase, and we do not serialize the catlog
		 * accessing, so it might be possible the llog creation
		 * thread (see llog_cat_declare_add_rec()) did not create
		 * llog successfully, then the following thread might
		 * meet this situation.
		 */
		if (IS_ERR_OR_NULL(cathandle->u.chd.chd_next_log)) {
			CERROR("%s: next log does not exist, catalog "DFID" rc=%d\n",
			       loghandle2name(cathandle),
			       PLOGID(&cathandle->lgh_id), -EIO);
			loghandle = ERR_PTR(-EIO);
			if (!cathandle->u.chd.chd_next_log) {
				/* Store the error in chd_next_log, so
				 * the following process can get correct
				 * failure value
				 */
				cathandle->u.chd.chd_next_log = loghandle;
			}
			GOTO(out_unlock, loghandle);
		}

		CDEBUG(D_OTHER,
		       "%s: use next log "DFID"->"DFID" catalog "DFID"\n",
		       loghandle2name(cathandle), PLOGID(&lid),
		       PLOGID(&cathandle->u.chd.chd_next_log->lgh_id),
		       PLOGID(&cathandle->lgh_id));
		loghandle = cathandle->u.chd.chd_next_log;
		cathandle->u.chd.chd_current_log = loghandle;
		cathandle->u.chd.chd_next_log = NULL;
	}
	up_write(&cathandle->lgh_lock);
	GOTO(retry, loghandle);

out_unlock:
	up_write(&cathandle->lgh_lock);
	RETURN(loghandle);
}

/* Add a single record to the recovery log(s) using a catalog
 * Returns as llog_write_record
 *
 * Assumes caller has already pushed us into the kernel context.
 */
int llog_cat_add_rec(const struct lu_env *env, struct llog_handle *cathandle,
		     struct llog_rec_hdr *rec, struct llog_cookie *reccookie,
		     struct thandle *th)
{
	struct llog_handle *loghandle;
	struct llog_thread_info *lgi = llog_info(env);
	int rc, retried = 0;

	ENTRY;
	LASSERT(rec->lrh_len <= cathandle->lgh_ctxt->loc_chunk_size);
retry:
	loghandle = llog_cat_current_log(env, cathandle, th);
	if (IS_ERR(loghandle))
		RETURN(PTR_ERR(loghandle));

	LASSERT(loghandle);
	LASSERT(!loghandle->lgh_destroyed);
	/* loghandle is already locked by llog_cat_current_log() for us */
	if (!llog_exist(loghandle)) {
		rc = llog_cat_new_log(env, cathandle, loghandle, th);
		if (rc < 0) {
			up_write(&loghandle->lgh_lock);
			llog_handle_put(env, loghandle);
			if (rc == -EEXIST && retried++ == 0)
				goto retry;
			/* When ENOSPC happened no need to drop loghandle
			 * a new one would be allocated anyway for next llog_add
			 * so better to stay with the old.
			 */
			if (rc != -ENOSPC) {
				/* nobody should be trying to use this llog */
				down_write(&cathandle->lgh_lock);
				if (cathandle->u.chd.chd_current_log ==
				    loghandle)
					cathandle->u.chd.chd_current_log = NULL;
				list_del_init(&loghandle->u.phd.phd_entry);
				up_write(&cathandle->lgh_lock);
				llog_close(env, loghandle);
			}
			CERROR("%s: initialization error: rc = %d\n",
			       loghandle2name(cathandle), rc);
			RETURN(rc);
		}
	}

	/* now let's try to add the record */
	rc = llog_write_rec(env, loghandle, rec, reccookie, LLOG_NEXT_IDX, th);
	if (rc < 0) {
		CDEBUG_LIMIT(rc == -ENOSPC ? D_HA : D_ERROR,
			     "llog_write_rec %d: lh=%p\n", rc, loghandle);
		/* -ENOSPC is returned if no empty records left
		 * and when it's lack of space on the stogage.
		 * there is no point to try again if it's the second
		 * case. many callers (like llog test) expect ENOSPC,
		 * so we preserve this error code, but look for the
		 * actual cause here
		 */
		if (rc == -ENOSPC && llog_is_full(loghandle))
			rc = -ENOBUFS;
	} else {
		unsigned long timestamp = ktime_get_real_seconds();

		if (timestamp != loghandle->lgh_timestamp) {
			loghandle->lgh_timestamp = timestamp;
			lgi->lgi_attr.la_valid = LA_MTIME;
			lgi->lgi_attr.la_mtime = timestamp;
			dt_attr_set(env, loghandle->lgh_obj, &lgi->lgi_attr,
			th);
		}
	}
	/* llog_write_rec could unlock a semaphore */
	if (!(loghandle->lgh_hdr->llh_flags & LLOG_F_UNLCK_SEM))
		up_write(&loghandle->lgh_lock);
	llog_handle_put(env, loghandle);

	if (rc == -ENOBUFS) {
		if (retried++ == 0)
			GOTO(retry, rc);
		CERROR("%s: error on 2nd llog: rc = %d\n",
		       loghandle2name(cathandle), rc);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_add_rec);

int llog_cat_declare_add_rec(const struct lu_env *env,
			     struct llog_handle *cathandle,
			     struct llog_rec_hdr *rec, struct thandle *th)
{
	struct llog_handle *loghandle = NULL;
	int retries = 5;
	int rc;

	ENTRY;
start:
	CDEBUG(D_INFO, "Declare adding to "DOSTID" flags %x count %d\n",
	       POSTID(&cathandle->lgh_id.lgl_oi),
	       cathandle->lgh_hdr->llh_flags, cathandle->lgh_hdr->llh_count);

	rc = llog_cat_prep_log(env, cathandle,
			       &cathandle->u.chd.chd_current_log, th);
	if (rc)
		GOTO(estale, rc);

	loghandle = cathandle->u.chd.chd_current_log;
	if (IS_ERR_OR_NULL(loghandle)) { /* low chance race, repeat */
		GOTO(estale, rc = -ESTALE);
	} else {
		loghandle = llog_handle_get(loghandle);
		if (!loghandle)
			GOTO(estale, rc = -ESTALE);
	}

	/* For local llog this would always reserves credits for creation */
	rc = llog_cat_prep_log(env, cathandle, &cathandle->u.chd.chd_next_log,
			       th);
	if (!rc) {
		rc = llog_declare_write_rec(env, loghandle, rec, -1, th);
		if (!rc)
			dt_declare_attr_set(env, loghandle->lgh_obj, NULL, th);
	}

	llog_handle_put(env, loghandle);
estale:
	if (rc == -ESTALE) {
		if (dt_object_remote(cathandle->lgh_obj)) {
			down_write(&cathandle->lgh_lock);
			rc = llog_cat_refresh(env, cathandle);
			up_write(&cathandle->lgh_lock);
			if (rc)
				RETURN(rc);
		}
		retries--;
		if (retries > 0)
			goto start;
	}

	if (rc)
		CWARN("%s: declaration failed, catalog "DFID": rc = %d\n",
		      loghandle2name(cathandle),
		      PLOGID(&cathandle->lgh_id), rc);

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_declare_add_rec);

int llog_cat_add(const struct lu_env *env, struct llog_handle *cathandle,
		 struct llog_rec_hdr *rec, struct llog_cookie *reccookie)
{
	struct llog_ctxt *ctxt;
	struct dt_device *dt;
	struct thandle *th = NULL;
	int rc;

	ctxt = cathandle->lgh_ctxt;
	LASSERT(ctxt);
	LASSERT(ctxt->loc_exp);

	LASSERT(cathandle->lgh_obj);
	dt = lu2dt_dev(cathandle->lgh_obj->do_lu.lo_dev);
	if (IS_ERR(dt))
		RETURN(PTR_ERR(dt));

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = llog_cat_declare_add_rec(env, cathandle, rec, th);
	if (rc)
		GOTO(out_trans, rc);

	rc = dt_trans_start_local(env, dt, th);
	if (rc)
		GOTO(out_trans, rc);
	rc = llog_cat_add_rec(env, cathandle, rec, reccookie, th);
out_trans:
	dt_trans_stop(env, dt, th);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_add);

int llog_cat_cancel_arr_rec(const struct lu_env *env,
			    struct llog_handle *cathandle,
			    struct llog_logid *lgl, int count, int *index)
{
	struct llog_handle *loghandle;
	int  rc;

	ENTRY;
	rc = llog_cat_id2handle(env, cathandle, &loghandle, lgl);
	if (rc) {
		CDEBUG(D_HA, "%s: can't find llog handle for "DFID": rc = %d\n",
		       loghandle2name(cathandle), PLOGID(lgl), rc);
		RETURN(rc);
	}

	if ((cathandle->lgh_ctxt->loc_flags &
	     LLOG_CTXT_FLAG_NORMAL_FID) && !llog_exist(loghandle)) {
		/* For update log, some of loghandles of cathandle
		 * might not exist because remote llog creation might
		 * be failed, so let's skip the record cancellation
		 * for these non-exist llogs.
		 */
		rc = -ENOENT;
		CDEBUG(D_HA, "%s: llog "DFID" does not exist: rc = %d\n",
		       loghandle2name(cathandle), PLOGID(lgl), rc);
		llog_handle_put(env, loghandle);
		RETURN(rc);
	}

	rc = llog_cancel_arr_rec(env, loghandle, count, index);
	if (rc == LLOG_DEL_PLAIN) { /* log has been destroyed */
		int cat_index;

		cat_index = loghandle->u.phd.phd_cookie.lgc_index;
		rc = llog_cat_cleanup(env, cathandle, loghandle, cat_index);
		if (rc)
			CDEBUG(D_HA,
			       "%s: fail to cancel catalog record: rc = %d\n",
			       loghandle2name(cathandle), rc);
		rc = 0;

	}
	llog_handle_put(env, loghandle);
	if (rc && rc != -ENOENT && rc != -ESTALE && rc != -EIO)
		CWARN("%s: fail to cancel %d records in "DFID": rc = %d\n",
		      loghandle2name(cathandle), count, PLOGID(lgl), rc);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_cancel_arr_rec);

/* For each cookie in the cookie array, we clear the log in-use bit and either:
 * - the log is empty, so mark it free in the catalog header and delete it
 * - the log is not empty, just write out the log header
 *
 * The cookies may be in different log files, so we need to get new logs
 * each time.
 *
 * Assumes caller has already pushed us into the kernel context.
 */
int llog_cat_cancel_records(const struct lu_env *env,
			    struct llog_handle *cathandle, int count,
			    struct llog_cookie *cookies)
{
	int i, rc = 0;

	ENTRY;

	for (i = 0; i < count; i++, cookies++) {
		int lrc;

		lrc = llog_cat_cancel_arr_rec(env, cathandle, &cookies->lgc_lgl,
					      1, &cookies->lgc_index);
		if (lrc && !rc)
			rc = lrc;
	}

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_cancel_records);

/* Get size of llog */
static u64 llog_size(const struct lu_env *env, struct llog_handle *llh)
{
	struct lu_attr la;
	int rc;

	rc = llh->lgh_obj->do_ops->do_attr_get(env, llh->lgh_obj, &la);
	if (rc) {
		CERROR("%s: attr_get failed for "DFID": rc = %d\n",
		       loghandle2name(llh), PLOGID(&llh->lgh_id), rc);
		return 0;
	}

	return la.la_size;
}

static int llog_cat_size_cb(const struct lu_env *env,
			     struct llog_handle *cat_llh,
			     struct llog_rec_hdr *rec, void *data)
{
	struct llog_process_data *d = data;
	struct llog_handle *llh = NULL;
	u64 *cum_size = d->lpd_data;
	u64 size;
	int rc;

	ENTRY;
	rc = llog_cat_process_common(env, cat_llh, rec, &llh);

	if (rc == LLOG_DEL_PLAIN) {
		/* empty log was deleted, don't count it */
		rc = llog_cat_cleanup(env, cat_llh, llh,
				      llh->u.phd.phd_cookie.lgc_index);
	} else if (rc == LLOG_DEL_RECORD) {
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat_llh, NULL, rec->lrh_index);
	} else {
		size = llog_size(env, llh);
		*cum_size += size;

		CDEBUG(D_INFO, "Add llog entry "DFID" size=%llu, tot=%llu\n",
		       PLOGID(&llh->lgh_id), size, *cum_size);
	}

	if (llh)
		llog_handle_put(env, llh);

	RETURN(0);
}

u64 llog_cat_size(const struct lu_env *env, struct llog_handle *cat_llh)
{
	u64 size = llog_size(env, cat_llh);

	llog_cat_process_or_fork(env, cat_llh, llog_cat_size_cb,
				 NULL, &size, 0, 0, false);

	return size;
}
EXPORT_SYMBOL(llog_cat_size);

/* currently returns the number of "free" entries in catalog,
 * ie the available entries for a new plain LLOG file creation,
 * even if catalog has wrapped
 */
u32 llog_cat_free_space(struct llog_handle *cat_llh)
{
	/* simulate almost full Catalog */
	if (CFS_FAIL_CHECK(OBD_FAIL_CAT_FREE_RECORDS))
		return cfs_fail_val;

	if (cat_llh->lgh_hdr->llh_count == 1)
		return llog_max_idx(cat_llh);

	if (cat_llh->lgh_last_idx > cat_llh->lgh_hdr->llh_cat_idx)
		return llog_max_idx(cat_llh) +
		       cat_llh->lgh_hdr->llh_cat_idx - cat_llh->lgh_last_idx;

	/* catalog is presently wrapped */
	return cat_llh->lgh_hdr->llh_cat_idx - cat_llh->lgh_last_idx;
}
EXPORT_SYMBOL(llog_cat_free_space);

static int llog_cat_reverse_process_cb(const struct lu_env *env,
				       struct llog_handle *cat_llh,
				       struct llog_rec_hdr *rec, void *data)
{
	struct llog_process_data *d = data;
	struct llog_handle *llh = NULL;
	int rc;

	ENTRY;
	rc = llog_cat_process_common(env, cat_llh, rec, &llh);
	if (rc)
		GOTO(out, rc);

	rc = llog_reverse_process(env, llh, d->lpd_cb, d->lpd_data, NULL);
out:
	/* The empty plain log was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN) {
		rc = llog_cat_cleanup(env, cat_llh, llh,
				      llh->u.phd.phd_cookie.lgc_index);
	} else if (rc == LLOG_DEL_RECORD) {
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat_llh, NULL, rec->lrh_index);
	} else if (rc == LLOG_SKIP_PLAIN) {
		/* processing callback ask to skip the llog -> continue */
		rc = 0;
	}

	if (llh)
		llog_handle_put(env, llh);
	RETURN(rc);
}

int llog_cat_reverse_process(const struct lu_env *env,
			     struct llog_handle *cat_llh,
			     llog_cb_t cb, void *data)
{
	struct llog_process_data d;
	struct llog_process_cat_data cd;
	struct llog_log_hdr *llh = cat_llh->lgh_hdr;
	int rc;

	ENTRY;
	LASSERT(llh->llh_flags & LLOG_F_IS_CAT);
	cd.lpcd_read_mode = LLOG_READ_MODE_NORMAL;
	d.lpd_data = data;
	d.lpd_cb = cb;

	if (llh->llh_cat_idx >= cat_llh->lgh_last_idx &&
	    llh->llh_count > 1) {
		CWARN("%s: catalog "DFID" crosses index zero\n",
		      loghandle2name(cat_llh),
		      PLOGID(&cat_llh->lgh_id));

		cd.lpcd_first_idx = 0;
		cd.lpcd_last_idx = cat_llh->lgh_last_idx;
		rc = llog_reverse_process(env, cat_llh,
					  llog_cat_reverse_process_cb,
					  &d, &cd);
		if (rc != 0)
			RETURN(rc);

		cd.lpcd_first_idx = le32_to_cpu(llh->llh_cat_idx);
		cd.lpcd_last_idx = 0;
		rc = llog_reverse_process(env, cat_llh,
					  llog_cat_reverse_process_cb,
					  &d, &cd);
	} else {
		rc = llog_reverse_process(env, cat_llh,
					  llog_cat_reverse_process_cb,
					  &d, NULL);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_reverse_process);

/* Cleanup deleted plain llog traces from catalog */
int llog_cat_cleanup(const struct lu_env *env, struct llog_handle *cathandle,
		     struct llog_handle *loghandle, int index)
{
	int rc;

	LASSERT(index);
	if (loghandle) {
		/* remove destroyed llog from catalog list and
		 * chd_current_log variable
		 */
		down_write(&cathandle->lgh_lock);
		if (cathandle->u.chd.chd_current_log == loghandle)
			cathandle->u.chd.chd_current_log = NULL;
		list_del_init(&loghandle->u.phd.phd_entry);
		up_write(&cathandle->lgh_lock);
		LASSERT(index == loghandle->u.phd.phd_cookie.lgc_index ||
			loghandle->u.phd.phd_cookie.lgc_index == 0);
		/* llog was opened and keep in a list, close it now */
		llog_close(env, loghandle);
	}

	/* do not attempt to cleanup on-disk llog if on client side */
	if (!cathandle->lgh_obj)
		return 0;

	/* cancel record and decrease count, then move llh_cat_idx
	 * llog_cat_set_first_idx() is called inside llog_cancel_arr_rec()
	 */
	/* remove plain llog entry from catalog by index */
	rc = llog_cancel_rec(env, cathandle, index);
	if (rc < 0)
		return rc;

	if (loghandle)
		CDEBUG(D_HA,
		       "cancel plain log "DFID" at index %u of catalog "DFID"\n",
		       PLOGID(&loghandle->lgh_id), index,
		       PLOGID(&cathandle->lgh_id));
	return rc;
}

/* retain log in catalog, and zap it if log is empty */
int llog_cat_retain_cb(const struct lu_env *env, struct llog_handle *cat,
		       struct llog_rec_hdr *rec, void *data)
{
	struct llog_handle *log = NULL;
	int rc;

	rc = llog_cat_process_common(env, cat, rec, &log);

	/* The empty plain log was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN || rc == LLOG_DEL_RECORD)
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat, log, rec->lrh_index);
	else if (!rc)
		llog_retain(env, log);

	if (log)
		llog_handle_put(env, log);

	return rc;
}
EXPORT_SYMBOL(llog_cat_retain_cb);

/* Modify a llog record base on llog_logid and record cookie,
 * with valid offset.
 */
int llog_cat_modify_rec(const struct lu_env *env, struct llog_handle *cathandle,
			struct llog_logid *lid, struct llog_rec_hdr *rec,
			struct llog_cookie *cookie)
{
	struct llog_handle *llh;
	int rc;

	ENTRY;

	rc = llog_cat_id2handle(env, cathandle, &llh, lid);
	if (rc) {
		CDEBUG(D_OTHER, "%s: failed to find log file "DFID": rc = %d\n",
		       loghandle2name(llh), PLOGID(lid), rc);

		RETURN(rc);
	}

	rc = llog_write_cookie(env, llh, rec, cookie, rec->lrh_index);
	if (rc < 0) {
		CDEBUG(D_OTHER,
		       "%s: failed to modify record "DFID".%d: rc = %d\n",
		       loghandle2name(llh), PLOGID(lid), rec->lrh_index, rc);
	} else {
		rc = 0;
	}
	llog_handle_put(env, llh);

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_modify_rec);
