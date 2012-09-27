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

