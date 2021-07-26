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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/llog_cat.c
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
	struct llog_logid_rec	*rec = &lgi->lgi_logid;
	struct thandle *handle = NULL;
	struct dt_device *dt = NULL;
	struct llog_log_hdr	*llh = cathandle->lgh_hdr;
	int			 rc, index;

	ENTRY;

	index = (cathandle->lgh_last_idx + 1) %
		(OBD_FAIL_PRECHECK(OBD_FAIL_CAT_RECORDS) ? (cfs_fail_val + 1) :
						LLOG_HDR_BITMAP_SIZE(llh));

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
	 * last_idx and cat_idx */
	if ((index == llh->llh_cat_idx + 1 && llh->llh_count > 1) ||
	    (index == 0 && llh->llh_cat_idx == 0)) {
		if (cathandle->lgh_name == NULL) {
			CWARN("%s: there are no more free slots in catalog "
			      DFID":%x\n",
			      loghandle2name(loghandle),
			      PFID(&cathandle->lgh_id.lgl_oi.oi_fid),
			      cathandle->lgh_id.lgl_ogen);
		} else {
			CWARN("%s: there are no more free slots in "
			      "catalog %s\n", loghandle2name(loghandle),
			      cathandle->lgh_name);
		}
		RETURN(-ENOSPC);
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_LLOG_CREATE_FAILED))
		RETURN(-ENOSPC);

	if (loghandle->lgh_hdr != NULL) {
		/* If llog object is remote and creation is failed, lgh_hdr
		 * might be left over here, free it first */
		LASSERT(!llog_exist(loghandle));
		OBD_FREE_LARGE(loghandle->lgh_hdr, loghandle->lgh_hdr_size);
		loghandle->lgh_hdr = NULL;
	}

	if (th == NULL) {
		dt = lu2dt_dev(cathandle->lgh_obj->do_lu.lo_dev);

		handle = dt_trans_create(env, dt);
		if (IS_ERR(handle))
			RETURN(PTR_ERR(handle));

		/* Create update llog object synchronously, which
		 * happens during inialization process see
		 * lod_sub_prep_llog(), to make sure the update
		 * llog object is created before corss-MDT writing
		 * updates into the llog object */
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

		rc = dt_trans_start_local(env, dt, handle);
		if (rc != 0)
			GOTO(out, rc);

		th = handle;
	}

	rc = llog_create(env, loghandle, th);
	/* if llog is already created, no need to initialize it */
	if (rc == -EEXIST) {
		GOTO(out, rc = 0);
	} else if (rc != 0) {
		CERROR("%s: can't create new plain llog in catalog: rc = %d\n",
		       loghandle2name(loghandle), rc);
		GOTO(out, rc);
	}

	rc = llog_init_handle(env, loghandle,
			      LLOG_F_IS_PLAIN | LLOG_F_ZAP_WHEN_EMPTY,
			      &cathandle->lgh_hdr->llh_tgtuuid);
	if (rc < 0)
		GOTO(out, rc);

	/* build the record for this log in the catalog */
	rec->lid_hdr.lrh_len = sizeof(*rec);
	rec->lid_hdr.lrh_type = LLOG_LOGID_MAGIC;
	rec->lid_id = loghandle->lgh_id;

	/* append the new record into catalog. The new index will be
	 * assigned to the record and updated in rec header */
	rc = llog_write_rec(env, cathandle, &rec->lid_hdr,
			    &loghandle->u.phd.phd_cookie, LLOG_NEXT_IDX, th);
	if (rc < 0)
		GOTO(out_destroy, rc);

	CDEBUG(D_OTHER, "new plain log "DFID".%u of catalog "DFID"\n",
	       PFID(&loghandle->lgh_id.lgl_oi.oi_fid), rec->lid_hdr.lrh_index,
	       PFID(&cathandle->lgh_id.lgl_oi.oi_fid));

	loghandle->lgh_hdr->llh_cat_idx = rec->lid_hdr.lrh_index;

	/* limit max size of plain llog so that space can be
	 * released sooner, especially on small filesystems */
	/* 2MB for the cases when free space hasn't been learned yet */
	loghandle->lgh_max_size = 2 << 20;
	dt = lu2dt_dev(cathandle->lgh_obj->do_lu.lo_dev);
	rc = dt_statfs(env, dt, &lgi->lgi_statfs);
	if (rc == 0 && lgi->lgi_statfs.os_bfree > 0) {
		__u64 freespace = (lgi->lgi_statfs.os_bfree *
				  lgi->lgi_statfs.os_bsize) >> 6;
		if (freespace < loghandle->lgh_max_size)
			loghandle->lgh_max_size = freespace;
		/* shouldn't be > 128MB in any case?
		 * it's 256K records of 512 bytes each */
		if (freespace > (128 << 20))
			loghandle->lgh_max_size = 128 << 20;
	}
	rc = 0;

out:
	if (handle != NULL) {
		handle->th_result = rc >= 0 ? 0 : rc;
		dt_trans_stop(env, dt, handle);
	}
	RETURN(rc);

out_destroy:
	/* to signal llog_cat_close() it shouldn't try to destroy the llog,
	 * we want to destroy it in this transaction, otherwise the object
	 * becomes an orphan */
	loghandle->lgh_hdr->llh_flags &= ~LLOG_F_ZAP_WHEN_EMPTY;
	/* this is to mimic full log, so another llog_cat_current_log()
	 * can skip it and ask for another onet */
	loghandle->lgh_last_idx = LLOG_HDR_BITMAP_SIZE(loghandle->lgh_hdr) + 1;
	llog_trans_destroy(env, loghandle, th);
	if (handle != NULL)
		dt_trans_stop(env, dt, handle);
	RETURN(rc);
}

static int llog_cat_refresh(const struct lu_env *env,
			    struct llog_handle *cathandle)
{
	struct llog_handle *loghandle;
	int rc;

	down_write(&cathandle->lgh_lock);
	list_for_each_entry(loghandle, &cathandle->u.chd.chd_head,
			    u.phd.phd_entry) {
		if (!llog_exist(loghandle))
			continue;

		rc = llog_read_header(env, loghandle, NULL);
		if (rc)
			goto unlock;
	}

	rc = llog_read_header(env, cathandle, NULL);
unlock:
	up_write(&loghandle->lgh_lock);

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
	int rc;
	int sem_upgraded;

start:
	rc = 0;
	sem_upgraded = 0;
	if (IS_ERR_OR_NULL(*ploghandle)) {
		up_read(&cathandle->lgh_lock);
		down_write(&cathandle->lgh_lock);
		sem_upgraded = 1;
		if (IS_ERR_OR_NULL(*ploghandle)) {
			struct llog_handle *loghandle;

			rc = llog_open(env, cathandle->lgh_ctxt, &loghandle,
				       NULL, NULL, LLOG_OPEN_NEW);
			if (!rc) {
				*ploghandle = loghandle;
				list_add_tail(&loghandle->u.phd.phd_entry,
					      &cathandle->u.chd.chd_head);
			}
		}
		if (rc)
			GOTO(out, rc);
	}

	rc = llog_exist(*ploghandle);
	if (rc < 0)
		GOTO(out, rc);
	if (rc)
		GOTO(out, rc = 0);

	if (dt_object_remote(cathandle->lgh_obj)) {
		down_write_nested(&(*ploghandle)->lgh_lock, LLOGH_LOG);
		if (!llog_exist(*ploghandle)) {
			/* For remote operation, if we put the llog object
			 * creation in the current transaction, then the
			 * llog object will not be created on the remote
			 * target until the transaction stop, if other
			 * operations start before the transaction stop,
			 * and use the same llog object, will be dependent
			 * on the success of this transaction. So let's
			 * create the llog object synchronously here to
			 * remove the dependency. */
			rc = llog_cat_new_log(env, cathandle, *ploghandle,
					      NULL);
			if (rc == -ESTALE) {
				up_write(&(*ploghandle)->lgh_lock);
				if (sem_upgraded)
					up_write(&cathandle->lgh_lock);
				else
					up_read(&cathandle->lgh_lock);

				rc = llog_cat_refresh(env, cathandle);
				down_read_nested(&cathandle->lgh_lock,
						 LLOGH_CAT);
				if (rc)
					return rc;
				/* *ploghandle might become NULL, restart */
				goto start;
			}
		}
		up_write(&(*ploghandle)->lgh_lock);
	} else {
		struct llog_thread_info	*lgi = llog_info(env);
		struct llog_logid_rec *lirec = &lgi->lgi_logid;

		rc = llog_declare_create(env, *ploghandle, th);
		if (rc)
			GOTO(out, rc);

		lirec->lid_hdr.lrh_len = sizeof(*lirec);
		rc = llog_declare_write_rec(env, cathandle, &lirec->lid_hdr, -1,
					    th);
	}

out:
	if (sem_upgraded) {
		up_write(&cathandle->lgh_lock);
		down_read_nested(&cathandle->lgh_lock, LLOGH_CAT);
		if (rc == 0)
			goto start;
	}
	return rc;
}

/* Open an existent log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 * We return a lock on the handle to ensure nobody yanks it from us.
 *
 * This takes extra reference on llog_handle via llog_handle_get() and require
 * this reference to be put by caller using llog_handle_put()
 */
int llog_cat_id2handle(const struct lu_env *env, struct llog_handle *cathandle,
		       struct llog_handle **res, struct llog_logid *logid)
{
	struct llog_handle	*loghandle;
	enum llog_flag		 fmt;
	int			 rc = 0;

	ENTRY;

	if (cathandle == NULL)
		RETURN(-EBADF);

	fmt = cathandle->lgh_hdr->llh_flags & LLOG_F_EXT_MASK;
	down_write(&cathandle->lgh_lock);
	list_for_each_entry(loghandle, &cathandle->u.chd.chd_head,
			    u.phd.phd_entry) {
		struct llog_logid *cgl = &loghandle->lgh_id;

		if (ostid_id(&cgl->lgl_oi) == ostid_id(&logid->lgl_oi) &&
		    ostid_seq(&cgl->lgl_oi) == ostid_seq(&logid->lgl_oi)) {
			if (cgl->lgl_ogen != logid->lgl_ogen) {
				CWARN("%s: log "DFID" generation %x != %x\n",
				      loghandle2name(loghandle),
				      PFID(&logid->lgl_oi.oi_fid),
				      cgl->lgl_ogen, logid->lgl_ogen);
				continue;
			}
			*res = llog_handle_get(loghandle);
			if (!*res) {
				CERROR("%s: log "DFID" refcount is zero!\n",
				       loghandle2name(loghandle),
				       PFID(&logid->lgl_oi.oi_fid));
				continue;
			}
			loghandle->u.phd.phd_cat_handle = cathandle;
			up_write(&cathandle->lgh_lock);
			RETURN(rc);
		}
	}
	up_write(&cathandle->lgh_lock);

	rc = llog_open(env, cathandle->lgh_ctxt, &loghandle, logid, NULL,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		CERROR("%s: error opening log id "DFID":%x: rc = %d\n",
		       loghandle2name(cathandle), PFID(&logid->lgl_oi.oi_fid),
		       logid->lgl_ogen, rc);
		RETURN(rc);
	}

	rc = llog_init_handle(env, loghandle, LLOG_F_IS_PLAIN | fmt, NULL);
	if (rc < 0) {
		llog_close(env, loghandle);
		*res = NULL;
		RETURN(rc);
	}

	*res = llog_handle_get(loghandle);
	LASSERT(*res);
	down_write(&cathandle->lgh_lock);
	list_add_tail(&loghandle->u.phd.phd_entry, &cathandle->u.chd.chd_head);
	up_write(&cathandle->lgh_lock);

	loghandle->u.phd.phd_cat_handle = cathandle;
	loghandle->u.phd.phd_cookie.lgc_lgl = cathandle->lgh_id;
	loghandle->u.phd.phd_cookie.lgc_index =
				loghandle->lgh_hdr->llh_cat_idx;
	RETURN(0);
}

int llog_cat_close(const struct lu_env *env, struct llog_handle *cathandle)
{
	struct llog_handle	*loghandle, *n;
	int			 rc;

	ENTRY;

	list_for_each_entry_safe(loghandle, n, &cathandle->u.chd.chd_head,
				 u.phd.phd_entry) {
		struct llog_log_hdr	*llh = loghandle->lgh_hdr;
		int			 index;

		/* unlink open-not-created llogs */
		list_del_init(&loghandle->u.phd.phd_entry);
		llh = loghandle->lgh_hdr;
		if (loghandle->lgh_obj != NULL && llh != NULL &&
		    (llh->llh_flags & LLOG_F_ZAP_WHEN_EMPTY) &&
		    (llh->llh_count == 1)) {
			rc = llog_destroy(env, loghandle);
			if (rc)
				CERROR("%s: failure destroying log during "
				       "cleanup: rc = %d\n",
				       loghandle2name(loghandle), rc);

			index = loghandle->u.phd.phd_cookie.lgc_index;
			llog_cat_cleanup(env, cathandle, NULL, index);
		}
		llog_close(env, loghandle);
	}
	/* if handle was stored in ctxt, remove it too */
	if (cathandle->lgh_ctxt->loc_handle == cathandle)
		cathandle->lgh_ctxt->loc_handle = NULL;
	rc = llog_close(env, cathandle);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_close);

/**
 * lockdep markers for nested struct llog_handle::lgh_lock locking.
 */
enum {
        LLOGH_CAT,
        LLOGH_LOG
};

/** Return the currently active log handle.  If the current log handle doesn't
 * have enough space left for the current record, start a new one.
 *
 * If reclen is 0, we only want to know what the currently active log is,
 * otherwise we get a lock on this log so nobody can steal our space.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 *
 * NOTE: loghandle is write-locked upon successful return
 */
static struct llog_handle *llog_cat_current_log(struct llog_handle *cathandle,
						struct thandle *th)
{
        struct llog_handle *loghandle = NULL;
        ENTRY;


	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_LLOG_CREATE_FAILED2)) {
		down_write_nested(&cathandle->lgh_lock, LLOGH_CAT);
		GOTO(next, loghandle);
	}

	down_read_nested(&cathandle->lgh_lock, LLOGH_CAT);
        loghandle = cathandle->u.chd.chd_current_log;
        if (loghandle) {
		struct llog_log_hdr *llh;

		down_write_nested(&loghandle->lgh_lock, LLOGH_LOG);
		llh = loghandle->lgh_hdr;
		if (llh == NULL || !llog_is_full(loghandle)) {
			up_read(&cathandle->lgh_lock);
                        RETURN(loghandle);
                } else {
			up_write(&loghandle->lgh_lock);
                }
        }
	up_read(&cathandle->lgh_lock);

	/* time to use next log */

	/* first, we have to make sure the state hasn't changed */
	down_write_nested(&cathandle->lgh_lock, LLOGH_CAT);
	loghandle = cathandle->u.chd.chd_current_log;
	if (loghandle) {
		struct llog_log_hdr *llh;

		down_write_nested(&loghandle->lgh_lock, LLOGH_LOG);
		llh = loghandle->lgh_hdr;
		if (llh == NULL || !llog_is_full(loghandle))
			GOTO(out_unlock, loghandle);
		else
			up_write(&loghandle->lgh_lock);
	}

next:
	/* Sigh, the chd_next_log and chd_current_log is initialized
	 * in declare phase, and we do not serialize the catlog
	 * accessing, so it might be possible the llog creation
	 * thread (see llog_cat_declare_add_rec()) did not create
	 * llog successfully, then the following thread might
	 * meet this situation. */
	if (IS_ERR_OR_NULL(cathandle->u.chd.chd_next_log)) {
		CERROR("%s: next log does not exist!\n",
		       loghandle2name(cathandle));
		loghandle = ERR_PTR(-EIO);
		if (cathandle->u.chd.chd_next_log == NULL) {
			/* Store the error in chd_next_log, so
			 * the following process can get correct
			 * failure value */
			cathandle->u.chd.chd_next_log = loghandle;
		}
		GOTO(out_unlock, loghandle);
	}

	CDEBUG(D_INODE, "use next log\n");

	loghandle = cathandle->u.chd.chd_next_log;
	cathandle->u.chd.chd_current_log = loghandle;
	cathandle->u.chd.chd_next_log = NULL;
	down_write_nested(&loghandle->lgh_lock, LLOGH_LOG);

out_unlock:
	up_write(&cathandle->lgh_lock);
	LASSERT(loghandle);
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
	int rc, retried = 0;
	ENTRY;

	LASSERT(rec->lrh_len <= cathandle->lgh_ctxt->loc_chunk_size);

retry:
	loghandle = llog_cat_current_log(cathandle, th);
	if (IS_ERR(loghandle))
		RETURN(PTR_ERR(loghandle));

	/* loghandle is already locked by llog_cat_current_log() for us */
	if (!llog_exist(loghandle)) {
		rc = llog_cat_new_log(env, cathandle, loghandle, th);
		if (rc < 0) {
			up_write(&loghandle->lgh_lock);
			/* nobody should be trying to use this llog */
			down_write(&cathandle->lgh_lock);
			if (cathandle->u.chd.chd_current_log == loghandle)
				cathandle->u.chd.chd_current_log = NULL;
			up_write(&cathandle->lgh_lock);
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
		 * actual cause here */
		if (rc == -ENOSPC && llog_is_full(loghandle))
			rc = -ENOBUFS;
	}
	up_write(&loghandle->lgh_lock);

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
	int rc;

	ENTRY;

start:
	down_read_nested(&cathandle->lgh_lock, LLOGH_CAT);
	rc = llog_cat_prep_log(env, cathandle,
			       &cathandle->u.chd.chd_current_log, th);
	if (rc)
		GOTO(unlock, rc);

	rc = llog_cat_prep_log(env, cathandle, &cathandle->u.chd.chd_next_log,
			       th);
	if (rc)
		GOTO(unlock, rc);

	rc = llog_declare_write_rec(env, cathandle->u.chd.chd_current_log,
				    rec, -1, th);
	if (rc == -ESTALE && dt_object_remote(cathandle->lgh_obj)) {
		up_read(&cathandle->lgh_lock);
		rc = llog_cat_refresh(env, cathandle);
		if (rc)
			RETURN(rc);
		goto start;
	}

#if 0
	/*
	 * XXX: we hope for declarations made for existing llog this might be
	 * not correct with some backends where declarations are expected
	 * against specific object like ZFS with full debugging enabled.
	 */
	rc = llog_declare_write_rec(env, cathandle->u.chd.chd_next_log, rec, -1,
				    th);
#endif
unlock:
	up_read(&cathandle->lgh_lock);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_declare_add_rec);

int llog_cat_add(const struct lu_env *env, struct llog_handle *cathandle,
		 struct llog_rec_hdr *rec, struct llog_cookie *reccookie)
{
	struct llog_ctxt	*ctxt;
	struct dt_device	*dt;
	struct thandle		*th = NULL;
	int			 rc;

	ctxt = cathandle->lgh_ctxt;
	LASSERT(ctxt);
	LASSERT(ctxt->loc_exp);

	LASSERT(cathandle->lgh_obj != NULL);
	dt = lu2dt_dev(cathandle->lgh_obj->do_lu.lo_dev);

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
	int i, index, rc = 0, failed = 0;

	ENTRY;

	for (i = 0; i < count; i++, cookies++) {
		struct llog_handle *loghandle;
		struct llog_logid *lgl = &cookies->lgc_lgl;
		int  lrc;

		rc = llog_cat_id2handle(env, cathandle, &loghandle, lgl);
		if (rc) {
			CDEBUG(D_HA, "%s: cannot find llog for handle "DFID":%x"
			       ": rc = %d\n", loghandle2name(cathandle),
			       PFID(&lgl->lgl_oi.oi_fid), lgl->lgl_ogen, rc);
			failed++;
			continue;
		}

		if ((cathandle->lgh_ctxt->loc_flags &
		     LLOG_CTXT_FLAG_NORMAL_FID) && !llog_exist(loghandle)) {
			/* For update log, some of loghandles of cathandle
			 * might not exist because remote llog creation might
			 * be failed, so let's skip the record cancellation
			 * for these non-exist llogs.
			 */
			lrc = -ENOENT;
			CDEBUG(D_HA, "%s: llog "DFID":%x does not exist"
			       ": rc = %d\n", loghandle2name(cathandle),
			       PFID(&lgl->lgl_oi.oi_fid), lgl->lgl_ogen, lrc);
			failed++;
			if (rc == 0)
				rc = lrc;
			continue;
		}

		lrc = llog_cancel_rec(env, loghandle, cookies->lgc_index);
		if (lrc == LLOG_DEL_PLAIN) { /* log has been destroyed */
			index = loghandle->u.phd.phd_cookie.lgc_index;
			lrc = llog_cat_cleanup(env, cathandle, loghandle,
					       index);
			if (rc == 0)
				rc = lrc;
		} else if (lrc == -ENOENT) {
			if (rc == 0) /* ENOENT shouldn't rewrite any error */
				rc = lrc;
		} else if (lrc < 0) {
			failed++;
			if (rc == 0)
				rc = lrc;
		}
		llog_handle_put(env, loghandle);
	}
	if (rc)
		CERROR("%s: fail to cancel %d of %d llog-records: rc = %d\n",
		       loghandle2name(cathandle), failed, count, rc);

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_cancel_records);

static int llog_cat_process_common(const struct lu_env *env,
				   struct llog_handle *cat_llh,
				   struct llog_rec_hdr *rec,
				   struct llog_handle **llhp)
{
	struct llog_logid_rec *lir = container_of(rec, typeof(*lir), lid_hdr);
	struct llog_log_hdr *hdr;
	int rc;

	ENTRY;
	if (rec->lrh_type != le32_to_cpu(LLOG_LOGID_MAGIC)) {
		rc = -EINVAL;
		CWARN("%s: invalid record in catalog "DFID":%x: rc = %d\n",
		      loghandle2name(cat_llh),
		      PFID(&cat_llh->lgh_id.lgl_oi.oi_fid),
		      cat_llh->lgh_id.lgl_ogen, rc);
		RETURN(rc);
	}
	CDEBUG(D_HA, "processing log "DFID":%x at index %u of catalog "DFID"\n",
	       PFID(&lir->lid_id.lgl_oi.oi_fid), lir->lid_id.lgl_ogen,
	       le32_to_cpu(rec->lrh_index),
	       PFID(&cat_llh->lgh_id.lgl_oi.oi_fid));

	rc = llog_cat_id2handle(env, cat_llh, llhp, &lir->lid_id);
	if (rc) {
		/* After a server crash, a stub of index record in catlog could
		 * be kept, because plain log destroy + catlog index record
		 * deletion are not atomic. So we end up with an index but no
		 * actual record. Destroy the index and move on. */
		if (rc == -ENOENT || rc == -ESTALE)
			rc = LLOG_DEL_RECORD;
		else if (rc)
			CWARN("%s: can't find llog handle "DFID":%x: rc = %d\n",
			      loghandle2name(cat_llh),
			      PFID(&lir->lid_id.lgl_oi.oi_fid),
			      lir->lid_id.lgl_ogen, rc);

		RETURN(rc);
	}

	/* clean old empty llogs, do not consider current llog in use */
	/* ignore remote (lgh_obj == NULL) llogs */
	hdr = (*llhp)->lgh_hdr;
	if ((hdr->llh_flags & LLOG_F_ZAP_WHEN_EMPTY) &&
	    hdr->llh_count == 1 && cat_llh->lgh_obj != NULL &&
	    *llhp != cat_llh->u.chd.chd_current_log) {
		rc = llog_destroy(env, *llhp);
		if (rc)
			CWARN("%s: can't destroy empty log "DFID": rc = %d\n",
			      loghandle2name((*llhp)),
			      PFID(&lir->lid_id.lgl_oi.oi_fid), rc);
		rc = LLOG_DEL_PLAIN;
	}

	RETURN(rc);
}

static int llog_cat_process_cb(const struct lu_env *env,
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

	if (rec->lrh_index < d->lpd_startcat) {
		/* Skip processing of the logs until startcat */
		rc = 0;
	} else if (d->lpd_startidx > 0) {
                struct llog_process_cat_data cd;

                cd.lpcd_first_idx = d->lpd_startidx;
                cd.lpcd_last_idx = 0;
		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  &cd, false);
		/* Continue processing the next log from idx 0 */
		d->lpd_startidx = 0;
	} else {
		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  NULL, false);
	}
	if (rc == -ENOENT && (cat_llh->lgh_hdr->llh_flags & LLOG_F_RM_ON_ERR)) {
		/*
		 * plain llog is reported corrupted, so better to just remove
		 * it if the caller is fine with that.
		 */
		CERROR("%s: remove corrupted/missing llog "DFID"\n",
		       loghandle2name(cat_llh),
		       PFID(&llh->lgh_id.lgl_oi.oi_fid));
		rc = LLOG_DEL_PLAIN;
	}

out:
	/* The empty plain log was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN) {
		rc = llog_cat_cleanup(env, cat_llh, llh,
				      llh->u.phd.phd_cookie.lgc_index);
	} else if (rc == LLOG_DEL_RECORD) {
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat_llh, NULL, rec->lrh_index);
	}

	if (llh)
		llog_handle_put(env, llh);

	RETURN(rc);
}

int llog_cat_process_or_fork(const struct lu_env *env,
			     struct llog_handle *cat_llh, llog_cb_t cat_cb,
			     llog_cb_t cb, void *data, int startcat,
			     int startidx, bool fork)
{
	struct llog_process_data d;
	struct llog_log_hdr *llh = cat_llh->lgh_hdr;
	int rc;

	ENTRY;

	LASSERT(llh->llh_flags & LLOG_F_IS_CAT);
	d.lpd_data = data;
	d.lpd_cb = cb;
	d.lpd_startcat = (startcat == LLOG_CAT_FIRST ? 0 : startcat);
	d.lpd_startidx = startidx;

	if (llh->llh_cat_idx >= cat_llh->lgh_last_idx &&
	    llh->llh_count > 1) {
		struct llog_process_cat_data cd;

		CWARN("%s: catlog "DFID" crosses index zero\n",
		      loghandle2name(cat_llh),
		      PFID(&cat_llh->lgh_id.lgl_oi.oi_fid));
		/*startcat = 0 is default value for general processing */
		if ((startcat != LLOG_CAT_FIRST &&
		    startcat >= llh->llh_cat_idx) || !startcat) {
			/* processing the catalog part at the end */
			cd.lpcd_first_idx = (startcat ? startcat :
					     llh->llh_cat_idx);
			if (OBD_FAIL_PRECHECK(OBD_FAIL_CAT_RECORDS))
				cd.lpcd_last_idx = cfs_fail_val;
			else
				cd.lpcd_last_idx = 0;
			rc = llog_process_or_fork(env, cat_llh, cat_cb,
						  &d, &cd, fork);
			/* Reset the startcat becasue it has already reached
			 * catalog bottom.
			 */
			startcat = 0;
			if (rc != 0)
				RETURN(rc);
		}
		/* processing the catalog part at the begining */
		cd.lpcd_first_idx = (startcat == LLOG_CAT_FIRST) ? 0 : startcat;
		/* Note, the processing will stop at the lgh_last_idx value,
		 * and it could be increased during processing. So records
		 * between current lgh_last_idx and lgh_last_idx in future
		 * would left unprocessed.
		 */
		cd.lpcd_last_idx = cat_llh->lgh_last_idx;
		rc = llog_process_or_fork(env, cat_llh, cat_cb,
					  &d, &cd, fork);
	} else {
		rc = llog_process_or_fork(env, cat_llh, cat_cb,
					  &d, NULL, fork);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_process_or_fork);

int llog_cat_process(const struct lu_env *env, struct llog_handle *cat_llh,
		     llog_cb_t cb, void *data, int startcat, int startidx)
{
	return llog_cat_process_or_fork(env, cat_llh, llog_cat_process_cb,
					cb, data, startcat, startidx, false);
}
EXPORT_SYMBOL(llog_cat_process);

static int llog_cat_size_cb(const struct lu_env *env,
			     struct llog_handle *cat_llh,
			     struct llog_rec_hdr *rec, void *data)
{
	struct llog_process_data *d = data;
	struct llog_handle *llh = NULL;
	__u64 *cum_size = d->lpd_data;
	__u64 size;
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
		       PFID(&llh->lgh_id.lgl_oi.oi_fid), size, *cum_size);
	}

	if (llh != NULL)
		llog_handle_put(env, llh);

	RETURN(0);
}

__u64 llog_cat_size(const struct lu_env *env, struct llog_handle *cat_llh)
{
	__u64 size = llog_size(env, cat_llh);

	llog_cat_process_or_fork(env, cat_llh, llog_cat_size_cb,
				 NULL, &size, 0, 0, false);

	return size;
}
EXPORT_SYMBOL(llog_cat_size);

/* currently returns the number of "free" entries in catalog,
 * ie the available entries for a new plain LLOG file creation,
 * even if catalog has wrapped
 */
__u32 llog_cat_free_space(struct llog_handle *cat_llh)
{
	/* simulate almost full Catalog */
	if (OBD_FAIL_CHECK(OBD_FAIL_CAT_FREE_RECORDS))
		return cfs_fail_val;

	if (cat_llh->lgh_hdr->llh_count == 1)
		return LLOG_HDR_BITMAP_SIZE(cat_llh->lgh_hdr) - 1;

	if (cat_llh->lgh_last_idx > cat_llh->lgh_hdr->llh_cat_idx)
		return LLOG_HDR_BITMAP_SIZE(cat_llh->lgh_hdr) - 1 +
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
	struct llog_handle *llh;
	int rc;

	ENTRY;
	rc = llog_cat_process_common(env, cat_llh, rec, &llh);

	/* The empty plain log was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN) {
		rc = llog_cat_cleanup(env, cat_llh, llh,
				      llh->u.phd.phd_cookie.lgc_index);
	} else if (rc == LLOG_DEL_RECORD) {
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat_llh, NULL, rec->lrh_index);
	}
	if (rc)
		RETURN(rc);

	rc = llog_reverse_process(env, llh, d->lpd_cb, d->lpd_data, NULL);

	/* The empty plain was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN)
		rc = llog_cat_cleanup(env, cat_llh, llh,
				      llh->u.phd.phd_cookie.lgc_index);

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
        d.lpd_data = data;
        d.lpd_cb = cb;

	if (llh->llh_cat_idx >= cat_llh->lgh_last_idx &&
	    llh->llh_count > 1) {
		CWARN("%s: catalog "DFID" crosses index zero\n",
		      loghandle2name(cat_llh),
		      PFID(&cat_llh->lgh_id.lgl_oi.oi_fid));

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

static int llog_cat_set_first_idx(struct llog_handle *cathandle, int idx)
{
	struct llog_log_hdr *llh = cathandle->lgh_hdr;
	int bitmap_size;

	ENTRY;

	bitmap_size = LLOG_HDR_BITMAP_SIZE(llh);
	/*
	 * The llh_cat_idx equals to the first used index minus 1
	 * so if we canceled the first index then llh_cat_idx
	 * must be renewed.
	 */
	if (llh->llh_cat_idx == (idx - 1)) {
		llh->llh_cat_idx = idx;

		while (idx != cathandle->lgh_last_idx) {
			idx = (idx + 1) % bitmap_size;
			if (!ext2_test_bit(idx, LLOG_HDR_BITMAP(llh))) {
				/* update llh_cat_idx for each unset bit,
				 * expecting the next one is set */
				llh->llh_cat_idx = idx;
			} else if (idx == 0) {
				/* skip header bit */
				llh->llh_cat_idx = 0;
				continue;
			} else {
				/* the first index is found */
				break;
			}
		}

		CDEBUG(D_HA, "catlog "DFID" first idx %u, last_idx %u\n",
		       PFID(&cathandle->lgh_id.lgl_oi.oi_fid),
		       llh->llh_cat_idx, cathandle->lgh_last_idx);
	}

	RETURN(0);
}

/* Cleanup deleted plain llog traces from catalog */
int llog_cat_cleanup(const struct lu_env *env, struct llog_handle *cathandle,
		     struct llog_handle *loghandle, int index)
{
	int rc;
	struct lu_fid fid = {.f_seq = 0, .f_oid = 0, .f_ver = 0};

	LASSERT(index);
	if (loghandle != NULL) {
		/* remove destroyed llog from catalog list and
		 * chd_current_log variable */
		fid = loghandle->lgh_id.lgl_oi.oi_fid;
		down_write(&cathandle->lgh_lock);
		if (cathandle->u.chd.chd_current_log == loghandle)
			cathandle->u.chd.chd_current_log = NULL;
		list_del_init(&loghandle->u.phd.phd_entry);
		up_write(&cathandle->lgh_lock);
		LASSERT(index == loghandle->u.phd.phd_cookie.lgc_index);
		/* llog was opened and keep in a list, close it now */
		llog_close(env, loghandle);
	}

	/* do not attempt to cleanup on-disk llog if on client side */
	if (cathandle->lgh_obj == NULL)
		return 0;

	/* remove plain llog entry from catalog by index */
	llog_cat_set_first_idx(cathandle, index);
	rc = llog_cancel_rec(env, cathandle, index);
	if (rc == 0)
		CDEBUG(D_HA,
		       "cancel plain log "DFID" at index %u of catalog "DFID"\n",
		       PFID(&fid), index,
		       PFID(&cathandle->lgh_id.lgl_oi.oi_fid));
	return rc;
}
