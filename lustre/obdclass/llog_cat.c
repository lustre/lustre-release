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

/* Open an existent log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 * We return a lock on the handle to ensure nobody yanks it from us.
 *
 * This takes extra reference on llog_handle via llog_handle_get() and require
 * this reference to be put by caller using llog_handle_put()
 */
SERVER_ONLY int
llog_cat_id2handle(const struct lu_env *env, struct llog_handle *cathandle,
		   struct llog_handle **res, struct llog_logid *logid)
{
	struct llog_handle	*loghandle;
	enum llog_flag		 fmt;
	int			 rc = 0;

	ENTRY;

	if (cathandle == NULL)
		RETURN(-EBADF);

	fmt = cathandle->lgh_hdr->llh_flags & LLOG_F_EXT_MASK;
	down_read(&cathandle->lgh_lock);
	list_for_each_entry(loghandle, &cathandle->u.chd.chd_head,
			    u.phd.phd_entry) {
		struct llog_logid *cgl = &loghandle->lgh_id;

		if (ostid_id(&cgl->lgl_oi) == ostid_id(&logid->lgl_oi) &&
		    ostid_seq(&cgl->lgl_oi) == ostid_seq(&logid->lgl_oi)) {
			*res = llog_handle_get(loghandle);
			if (!*res) {
				CERROR("%s: log "DFID" refcount is zero!\n",
				       loghandle2name(loghandle),
				       PLOGID(logid));
				continue;
			}
			loghandle->u.phd.phd_cat_handle = cathandle;
			up_read(&cathandle->lgh_lock);
			RETURN(rc);
		}
	}
	up_read(&cathandle->lgh_lock);

	rc = llog_open(env, cathandle->lgh_ctxt, &loghandle, logid, NULL,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		CERROR("%s: error opening log id "DFID": rc = %d\n",
		       loghandle2name(cathandle), PLOGID(logid), rc);
		RETURN(rc);
	}

	rc = llog_init_handle(env, loghandle, LLOG_F_IS_PLAIN |
			      LLOG_F_ZAP_WHEN_EMPTY | fmt, NULL);
	if (rc < 0) {
		llog_close(env, loghandle);
		*res = NULL;
		RETURN(rc);
	}

	*res = llog_handle_get(loghandle);
	LASSERT(*res);
	down_write(&cathandle->lgh_lock);
	list_add(&loghandle->u.phd.phd_entry, &cathandle->u.chd.chd_head);
	up_write(&cathandle->lgh_lock);

	loghandle->u.phd.phd_cat_handle = cathandle;
	loghandle->u.phd.phd_cookie.lgc_lgl = cathandle->lgh_id;
	loghandle->u.phd.phd_cookie.lgc_index =
				loghandle->lgh_hdr->llh_cat_idx;
	RETURN(0);
}

int llog_cat_close(const struct lu_env *env, struct llog_handle *cathandle)
{
	struct llog_handle *loghandle, *n;
	int rc = 0;

	ENTRY;
	list_for_each_entry_safe(loghandle, n, &cathandle->u.chd.chd_head,
				 u.phd.phd_entry) {
#ifdef CONFIG_LUSTRE_FS_SERVER
		struct llog_log_hdr *llh = loghandle->lgh_hdr;
		int index;
#endif
		/* unlink open-not-created llogs */
		list_del_init(&loghandle->u.phd.phd_entry);
#ifdef CONFIG_LUSTRE_FS_SERVER
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
#endif
		llog_close(env, loghandle);
	}
#ifdef CONFIG_LUSTRE_FS_SERVER
	/* if handle was stored in ctxt, remove it too */
	if (cathandle->lgh_ctxt->loc_handle == cathandle)
		cathandle->lgh_ctxt->loc_handle = NULL;
#endif
	rc = llog_close(env, cathandle);

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_close);

SERVER_ONLY int
llog_cat_process_common(const struct lu_env *env, struct llog_handle *cat_llh,
			struct llog_rec_hdr *rec, struct llog_handle **llhp)
{
	struct llog_logid_rec *lir = container_of(rec, typeof(*lir), lid_hdr);
#ifdef CONFIG_LUSTRE_FS_SERVER
	struct llog_log_hdr *hdr;
#endif
	int rc;

	ENTRY;
	if (rec->lrh_type != le32_to_cpu(LLOG_LOGID_MAGIC)) {
		rc = -EINVAL;
		CWARN("%s: invalid record in catalog "DFID": rc = %d\n",
		      loghandle2name(cat_llh), PLOGID(&cat_llh->lgh_id), rc);
		RETURN(rc);
	}
	CDEBUG(D_HA, "processing log "DFID" at index %u of catalog "DFID"\n",
	       PLOGID(&lir->lid_id), le32_to_cpu(rec->lrh_index),
	       PLOGID(&cat_llh->lgh_id));

	rc = llog_cat_id2handle(env, cat_llh, llhp, &lir->lid_id);
	if (rc) {
#ifdef CONFIG_LUSTRE_FS_SERVER
		/* After a server crash, a stub of index record in catlog could
		 * be kept, because plain log destroy + catlog index record
		 * deletion are not atomic. So we end up with an index but no
		 * actual record. Destroy the index and move on.
		 */
		if (rc == -ENOENT || rc == -ESTALE)
			rc = LLOG_DEL_RECORD;
		else if (rc)
			CWARN("%s: can't find llog handle "DFID": rc = %d\n",
			      loghandle2name(cat_llh), PLOGID(&lir->lid_id),
			      rc);
#endif
		RETURN(rc);
	}
#ifdef CONFIG_LUSTRE_FS_SERVER
	/* clean old empty llogs, do not consider current llog in use */
	/* ignore remote (lgh_obj == NULL) llogs */
	hdr = (*llhp)->lgh_hdr;
	if ((hdr->llh_flags & LLOG_F_ZAP_WHEN_EMPTY) &&
	    hdr->llh_count == 1 && cat_llh->lgh_obj != NULL &&
	    *llhp != cat_llh->u.chd.chd_current_log &&
	    *llhp != cat_llh->u.chd.chd_next_log) {
		rc = llog_destroy(env, *llhp);
		if (rc)
			CWARN("%s: can't destroy empty log "DFID": rc = %d\n",
			      loghandle2name((*llhp)), PLOGID(&lir->lid_id),
			      rc);
		rc = LLOG_DEL_PLAIN;
	}
#endif /* CONFIG_LUSTRE_FS_SERVER */

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
	/* Skip processing of the logs until startcat */
	if (rec->lrh_index < d->lpd_startcat)
		RETURN(0);

	rc = llog_cat_process_common(env, cat_llh, rec, &llh);
	if (rc)
		GOTO(out, rc);

	if (d->lpd_startidx > 0) {
		struct llog_process_cat_data cd = {
			.lpcd_first_idx = 0,
			.lpcd_last_idx = 0,
			.lpcd_read_mode = LLOG_READ_MODE_NORMAL,
		};

		/* startidx is always associated with a catalog index */
		if (d->lpd_startcat == rec->lrh_index)
			cd.lpcd_first_idx = d->lpd_startidx;

		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  &cd, false);
		/* Continue processing the next log from idx 0 */
		d->lpd_startidx = 0;
	} else {
		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  NULL, false);
	}
#ifdef CONFIG_LUSTRE_FS_SERVER
	if (rc == -ENOENT && (cat_llh->lgh_hdr->llh_flags & LLOG_F_RM_ON_ERR)) {
		/*
		 * plain llog is reported corrupted, so better to just remove
		 * it if the caller is fine with that.
		 */
		CERROR("%s: remove corrupted/missing llog "DFID"\n",
		       loghandle2name(cat_llh), PLOGID(&llh->lgh_id));
		rc = LLOG_DEL_PLAIN;
	}
#endif
out:
#ifdef CONFIG_LUSTRE_FS_SERVER
	/* The empty plain log was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN || rc == LLOG_DEL_RECORD)
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat_llh, llh, rec->lrh_index);
	else if (rc == LLOG_SKIP_PLAIN)
		/* processing callback ask to skip the llog -> continue */
		rc = 0;
#endif
	if (llh)
		llog_handle_put(env, llh);

	RETURN(rc);
}

SERVER_ONLY int
llog_cat_process_or_fork(const struct lu_env *env,
			 struct llog_handle *cat_llh, llog_cb_t cat_cb,
			 llog_cb_t cb, void *data, int startcat,
			 int startidx, bool fork)
{
	struct llog_log_hdr *llh = cat_llh->lgh_hdr;
	struct llog_process_data d;
	struct llog_process_cat_data cd;
	int rc;

	ENTRY;
	LASSERT(llh->llh_flags & LLOG_F_IS_CAT);
	d.lpd_data = data;
	d.lpd_cb = cb;

	/* default: start from the oldest record */
	d.lpd_startidx = 0;
	d.lpd_startcat = llh->llh_cat_idx + 1;
	cd.lpcd_first_idx = llh->llh_cat_idx;
	cd.lpcd_last_idx = 0;
	cd.lpcd_read_mode = LLOG_READ_MODE_NORMAL;

	if (startcat > 0 && startcat <= llog_max_idx(cat_llh)) {
		/* start from a custom catalog/llog plain indexes*/
		d.lpd_startidx = startidx;
		d.lpd_startcat = startcat;
		cd.lpcd_first_idx = startcat - 1;
	} else if (startcat != 0) {
		CWARN("%s: startcat %d out of range for catlog "DFID"\n",
		      loghandle2name(cat_llh), startcat,
		      PLOGID(&cat_llh->lgh_id));
		RETURN(-EINVAL);
	}

	startcat = d.lpd_startcat;

	/* if startcat <= lgh_last_idx, we only need to process the first part
	 * of the catalog (from startcat).
	 */
	if (llog_cat_is_wrapped(cat_llh) && startcat > cat_llh->lgh_last_idx) {
		int cat_idx_origin = llh->llh_cat_idx;

		CWARN("%s: catlog "DFID" crosses index zero\n",
		      loghandle2name(cat_llh),
		      PLOGID(&cat_llh->lgh_id));

		/* processing the catalog part at the end */
		rc = llog_process_or_fork(env, cat_llh, cat_cb, &d, &cd, fork);
		if (rc)
			RETURN(rc);

		/* Reset the startcat because it has already reached catalog
		 * bottom.
		 * lgh_last_idx value could be increased during processing. So
		 * we process the remaining of catalog entries to be sure.
		 */
		d.lpd_startcat = 1;
		d.lpd_startidx = 0;
		cd.lpcd_first_idx = 0;
		cd.lpcd_last_idx = max(cat_idx_origin, cat_llh->lgh_last_idx);
	} else if (llog_cat_is_wrapped(cat_llh)) {
		/* only process 1st part -> stop before reaching 2sd part */
		cd.lpcd_last_idx = llh->llh_cat_idx;
	}

	/* processing the catalog part at the begining */
	rc = llog_process_or_fork(env, cat_llh, cat_cb, &d, &cd, fork);

	RETURN(rc);
}
SERVER_ONLY_EXPORT_SYMBOL(llog_cat_process_or_fork);

/**
 * Process catalog records with a callback
 *
 * \note
 * If "starcat = 0", this is the default processing. "startidx" argument is
 * ignored and processing begin from the oldest record.
 * If "startcat > 0", this is a custom starting point. Processing begin with
 * the llog plain defined in the catalog record at index "startcat". The first
 * llog plain record to process is at index "startidx + 1".
 *
 * \param env		Lustre environnement
 * \param cat_llh	Catalog llog handler
 * \param cb		Callback executed for each records (in llog plain files)
 * \param data		Callback data argument
 * \param startcat	Catalog index of the llog plain to start with.
 * \param startidx	Index of the llog plain to start processing. The first
 *			record to process is at startidx + 1.
 *
 * \retval 0 processing successfully completed
 * \retval LLOG_PROC_BREAK processing was stopped by the callback.
 * \retval -errno on error.
 */
int llog_cat_process(const struct lu_env *env, struct llog_handle *cat_llh,
		     llog_cb_t cb, void *data, int startcat, int startidx)
{
	return llog_cat_process_or_fork(env, cat_llh, llog_cat_process_cb,
					cb, data, startcat, startidx, false);
}
EXPORT_SYMBOL(llog_cat_process);

int llog_cat_set_first_idx(struct llog_handle *cathandle, int newidx)
{
	struct llog_log_hdr *llh = cathandle->lgh_hdr;
	int max, idx = llh->llh_cat_idx;

	ENTRY;

	max = llog_max_idx(cathandle) + 1;
	if (find_next_bit_le((void *)LLOG_HDR_BITMAP(llh), max, 1) == max)
		RETURN(0);
	/*
	 * The llh_cat_idx equals to the first used index minus 1.
	 * We scan from llh_cat_idx + 1 disregard which index
	 * was canceled to avoid llh_cat_idx cannot go forward in
	 * abnormal case.
	 */
	do {
		idx = (idx + 1) % (llog_max_idx(cathandle) + 1);
		if (newidx == idx || !test_bit_le(idx, LLOG_HDR_BITMAP(llh))) {
			/* update llh_cat_idx for each unset bit,
			 * expecting the next one is set
			 */
			llh->llh_cat_idx = idx;
		} else if (idx == 0) {
			/* skip header bit */
			llh->llh_cat_idx = 0;
			continue;
		} else {
			/* the first index is found */
			break;
		}
	} while (idx != cathandle->lgh_last_idx);

	CDEBUG(D_HA, "catlog "DFID" first idx %u, last_idx %u\n",
	       PLOGID(&cathandle->lgh_id), llh->llh_cat_idx,
	       cathandle->lgh_last_idx);

	RETURN(0);
}
EXPORT_SYMBOL(llog_cat_set_first_idx);
