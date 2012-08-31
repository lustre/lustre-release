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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mds/mds_log.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/version.h>

#include <libcfs/list.h>
#include <obd_class.h>
#include <lustre_fsfilt.h>
#include <lustre_mds.h>
#include <lustre_log.h>

#include "mds_internal.h"

static int mds_llog_origin_add(const struct lu_env *env,
			       struct llog_ctxt *ctxt,
			       struct llog_rec_hdr *rec,
			       struct lov_stripe_md *lsm,
			       struct llog_cookie *logcookies, int numcookies)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_device *lov_obd = obd->u.mds.mds_lov_obd;
        struct llog_ctxt *lctxt;
        int rc;
        ENTRY;

        lctxt = llog_get_context(lov_obd, ctxt->loc_idx);
	rc = llog_obd_add(env, lctxt, rec, lsm, logcookies, numcookies);
        llog_ctxt_put(lctxt);

        RETURN(rc);
}

static int mds_llog_origin_connect(struct llog_ctxt *ctxt,
                                   struct llog_logid *logid,
                                   struct llog_gen *gen,
                                   struct obd_uuid *uuid)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_device *lov_obd = obd->u.mds.mds_lov_obd;
        struct llog_ctxt *lctxt;
        int rc;
        ENTRY;

        lctxt = llog_get_context(lov_obd, ctxt->loc_idx);
        rc = llog_connect(lctxt, logid, gen, uuid);
        llog_ctxt_put(lctxt);
        RETURN(rc);
}

static struct llog_operations mds_ost_orig_logops = {
	.lop_obd_add	= mds_llog_origin_add,
	.lop_connect	= mds_llog_origin_connect,
};

static int mds_llog_repl_cancel(const struct lu_env *env,
				struct llog_ctxt *ctxt,
				struct lov_stripe_md *lsm,
				int count, struct llog_cookie *cookies,
				int flags)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_device *lov_obd = obd->u.mds.mds_lov_obd;
        struct llog_ctxt *lctxt;
        int rc;
        ENTRY;

        lctxt = llog_get_context(lov_obd, ctxt->loc_idx);
	rc = llog_cancel(env, lctxt, lsm, count, cookies, flags);
        llog_ctxt_put(lctxt);
        RETURN(rc);
}

static struct llog_operations mds_size_repl_logops = {
        lop_cancel:     mds_llog_repl_cancel,
};

static struct llog_operations changelog_orig_logops;

static int llog_changelog_cancel_cb(const struct lu_env *env,
				    struct llog_handle *llh,
				    struct llog_rec_hdr *hdr, void *data)
{
        struct llog_changelog_rec *rec = (struct llog_changelog_rec *)hdr;
        struct llog_cookie cookie;
        long long endrec = *(long long *)data;
        int rc, err;
        struct obd_device *obd;
        void *trans_h;
        struct inode *inode;
        ENTRY;

        /* This is always a (sub)log, not the catalog */
        LASSERT(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN);

        if (rec->cr.cr_index > endrec)
                /* records are in order, so we're done */
                RETURN(LLOG_PROC_BREAK);

        cookie.lgc_lgl = llh->lgh_id;
        cookie.lgc_index = hdr->lrh_index;
        obd = llh->lgh_ctxt->loc_exp->exp_obd;
        inode = llh->lgh_file->f_dentry->d_inode;

        /* XXX This is a workaround for the deadlock of changelog adding vs.
         * changelog cancelling. Changelog adding always start transaction
         * before acquiring the catlog lock (lgh_lock), whereas, changelog
         * cancelling do start transaction after holding catlog lock.
         *
         * We start the transaction earlier here to keep the locking ordering:
         * 'start transaction -> catlog lock'. LU-81. */
        trans_h = fsfilt_start_log(obd, inode, FSFILT_OP_CANCEL_UNLINK,
                                   NULL, 1);
        if (IS_ERR(trans_h)) {
                CERROR("fsfilt_start_log failed: %ld\n", PTR_ERR(trans_h));
                RETURN(PTR_ERR(trans_h));
        }

        /* cancel them one at a time.  I suppose we could store up the cookies
           and cancel them all at once; probably more efficient, but this is
           done as a user call, so who cares... */
	rc = llog_cat_cancel_records(env, llh->u.phd.phd_cat_handle, 1,
				     &cookie);

        err = fsfilt_commit(obd, inode, trans_h, 0);
        if (err) {
                CERROR("fsfilt_commit failed: %d\n", err);
                rc = (rc >= 0) ? err : rc;
        }

        RETURN(rc < 0 ? rc : 0);
}

static int llog_changelog_cancel(const struct lu_env *env,
				 struct llog_ctxt *ctxt,
				 struct lov_stripe_md *lsm, int count,
				 struct llog_cookie *cookies, int flags)
{
        struct llog_handle *cathandle = ctxt->loc_handle;
        int rc;
        ENTRY;

        /* This should only be called with the catalog handle */
        LASSERT(cathandle->lgh_hdr->llh_flags & LLOG_F_IS_CAT);

	rc = llog_cat_process(env, cathandle, llog_changelog_cancel_cb,
			      (void *)cookies, 0, 0);
        if (rc >= 0)
                /* 0 or 1 means we're done */
                rc = 0;
        else
                CERROR("cancel idx %u of catalog "LPX64" rc=%d\n",
                       cathandle->lgh_last_idx, cathandle->lgh_id.lgl_oid, rc);

        RETURN(rc);
}

int mds_changelog_llog_init(struct obd_device *obd, struct obd_device *tgt)
{
	struct llog_ctxt	*ctxt = NULL, *uctxt = NULL;
	int			 rc;

	/* see osc_llog_init */
	changelog_orig_logops = llog_lvfs_ops;
	changelog_orig_logops.lop_obd_add = llog_obd_origin_add;
	changelog_orig_logops.lop_cancel = llog_changelog_cancel;

	rc = llog_setup(NULL, obd, &obd->obd_olg, LLOG_CHANGELOG_ORIG_CTXT,
			tgt, &changelog_orig_logops);
	if (rc) {
		CERROR("%s: changelog llog setup failed: rc = %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
	LASSERT(ctxt);

	rc = llog_open_create(NULL, ctxt, &ctxt->loc_handle, NULL,
			      CHANGELOG_CATALOG);
	if (rc)
		GOTO(out_cleanup, rc);

	rc = llog_cat_init_and_process(NULL, ctxt->loc_handle);
	if (rc)
		GOTO(out_close, rc);

	/* setup user changelog */
	rc = llog_setup(NULL, obd, &obd->obd_olg,
			LLOG_CHANGELOG_USER_ORIG_CTXT, tgt,
			&changelog_orig_logops);
	if (rc) {
		CERROR("%s: changelog users llog setup failed: rc = %d\n",
		       obd->obd_name, rc);
		GOTO(out_close, rc);
	}

	uctxt = llog_get_context(obd, LLOG_CHANGELOG_USER_ORIG_CTXT);
	LASSERT(uctxt);

	rc = llog_open_create(NULL, uctxt, &uctxt->loc_handle, NULL,
			      CHANGELOG_USERS);
	if (rc)
		GOTO(out_ucleanup, rc);

	rc = llog_cat_init_and_process(NULL, uctxt->loc_handle);
	if (rc)
		GOTO(out_uclose, rc);

	llog_ctxt_put(ctxt);
	llog_ctxt_put(uctxt);
	RETURN(0);
out_uclose:
	llog_cat_close(NULL, uctxt->loc_handle);
out_ucleanup:
	llog_cleanup(NULL, uctxt);
out_close:
	llog_cat_close(NULL, ctxt->loc_handle);
out_cleanup:
	llog_cleanup(NULL, ctxt);
	return rc;
}
EXPORT_SYMBOL(mds_changelog_llog_init);

int mds_llog_init(struct obd_device *obd, struct obd_llog_group *olg,
                  struct obd_device *disk_obd, int *index)
{
        struct obd_device *lov_obd = obd->u.mds.mds_lov_obd;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        LASSERT(olg == &obd->obd_olg);
	rc = llog_setup(NULL, obd, &obd->obd_olg, LLOG_MDS_OST_ORIG_CTXT,
			disk_obd, &mds_ost_orig_logops);
	if (rc)
		RETURN(rc);

	rc = llog_setup(NULL, obd, &obd->obd_olg, LLOG_SIZE_REPL_CTXT,
			disk_obd, &mds_size_repl_logops);
        if (rc)
                GOTO(err_llog, rc);

        rc = obd_llog_init(lov_obd, &lov_obd->obd_olg, disk_obd, index);
        if (rc) {
                CERROR("lov_llog_init err %d\n", rc);
                GOTO(err_cleanup, rc);
        }

        RETURN(rc);
err_cleanup:
	ctxt = llog_get_context(obd, LLOG_SIZE_REPL_CTXT);
	if (ctxt)
		llog_cleanup(NULL, ctxt);
err_llog:
	ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
	if (ctxt)
		llog_cleanup(NULL, ctxt);
	return rc;
}

int mds_llog_finish(struct obd_device *obd, int count)
{
	struct llog_ctxt *ctxt;

	ENTRY;

	ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
	if (ctxt)
		llog_cleanup(NULL, ctxt);

	ctxt = llog_get_context(obd, LLOG_SIZE_REPL_CTXT);
	if (ctxt)
		llog_cleanup(NULL, ctxt);

	ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
	if (ctxt) {
		llog_cat_close(NULL, ctxt->loc_handle);
		llog_cleanup(NULL, ctxt);
	}

	ctxt = llog_get_context(obd, LLOG_CHANGELOG_USER_ORIG_CTXT);
	if (ctxt) {
		llog_cat_close(NULL, ctxt->loc_handle);
		llog_cleanup(NULL, ctxt);
	}
	RETURN(0);
}

static int mds_llog_add_unlink(struct obd_device *obd,
                               struct lov_stripe_md *lsm, obd_count count,
                               struct llog_cookie *logcookie, int cookies)
{
        struct llog_unlink_rec *lur;
        struct llog_ctxt *ctxt;
        int rc;

        if (cookies < lsm->lsm_stripe_count)
                RETURN(rc = -EFBIG);

        /* first prepare unlink log record */
        OBD_ALLOC_PTR(lur);
        if (!lur)
                RETURN(rc = -ENOMEM);
        lur->lur_hdr.lrh_len = lur->lur_tail.lrt_len = sizeof(*lur);
        lur->lur_hdr.lrh_type = MDS_UNLINK_REC;
        lur->lur_count = count;

        ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
	rc = llog_obd_add(NULL, ctxt, &lur->lur_hdr, lsm, logcookie, cookies);
        llog_ctxt_put(ctxt);

        OBD_FREE_PTR(lur);
        RETURN(rc);
}

int mds_log_op_unlink(struct obd_device *obd,
                      struct lov_mds_md *lmm, int lmm_size,
                      struct llog_cookie *logcookies, int cookies_size)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_stripe_md *lsm = NULL;
        int rc;
        ENTRY;

        if (IS_ERR(mds->mds_lov_obd))
                RETURN(PTR_ERR(mds->mds_lov_obd));

        rc = obd_unpackmd(mds->mds_lov_exp, &lsm, lmm, lmm_size);
        if (rc < 0)
                RETURN(rc);
        rc = mds_llog_add_unlink(obd, lsm, 0, logcookies,
                                 cookies_size / sizeof(struct llog_cookie));
        obd_free_memmd(mds->mds_lov_exp, &lsm);
        RETURN(rc);
}
EXPORT_SYMBOL(mds_log_op_unlink);

int mds_log_op_orphan(struct obd_device *obd, struct lov_stripe_md *lsm,
                      obd_count count)
{
        struct mds_obd *mds = &obd->u.mds;
        struct llog_cookie logcookie;
        int rc;
        ENTRY;

        if (IS_ERR(mds->mds_lov_obd))
                RETURN(PTR_ERR(mds->mds_lov_obd));

        rc = mds_llog_add_unlink(obd, lsm, count - 1, &logcookie, 1);
        RETURN(rc);
}

