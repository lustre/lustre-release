/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
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

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/version.h>

#include <libcfs/list.h>
#include <obd_class.h>
#include <lustre_fsfilt.h>
#include <lustre_mds.h>
#include <lustre_log.h>
#include "mds_internal.h"

static int mds_llog_origin_add(struct llog_ctxt *ctxt, struct llog_rec_hdr *rec,
                               struct lov_stripe_md *lsm,
                               struct llog_cookie *logcookies, int numcookies)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        struct llog_ctxt *lctxt;
        int rc;
        ENTRY;

        lctxt = llog_get_context(lov_obd, ctxt->loc_idx);
        rc = llog_add(lctxt, rec, lsm, logcookies, numcookies);
        llog_ctxt_put(lctxt);

        RETURN(rc);
}

static int mds_llog_origin_connect(struct llog_ctxt *ctxt,
                                   struct llog_logid *logid,
                                   struct llog_gen *gen,
                                   struct obd_uuid *uuid)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        struct llog_ctxt *lctxt;
        int rc;
        ENTRY;

        lctxt = llog_get_context(lov_obd, ctxt->loc_idx);
        rc = llog_connect(lctxt, logid, gen, uuid);
        llog_ctxt_put(lctxt);
        RETURN(rc);
}

static struct llog_operations mds_ost_orig_logops = {
        lop_add:        mds_llog_origin_add,
        lop_connect:    mds_llog_origin_connect,
};

static int mds_llog_repl_cancel(struct llog_ctxt *ctxt, struct lov_stripe_md *lsm,
                          int count, struct llog_cookie *cookies, int flags)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        struct llog_ctxt *lctxt;
        int rc;
        ENTRY;

        lctxt = llog_get_context(lov_obd, ctxt->loc_idx);
        rc = llog_cancel(lctxt, lsm, count, cookies, flags);
        llog_ctxt_put(lctxt);
        RETURN(rc);
}

static struct llog_operations mds_size_repl_logops = {
        lop_cancel:     mds_llog_repl_cancel,
};

static struct llog_operations changelog_orig_logops;

static int llog_changelog_cancel_cb(struct llog_handle *llh,
                                    struct llog_rec_hdr *hdr, void *data)
{
        struct llog_changelog_rec *rec = (struct llog_changelog_rec *)hdr;
        struct llog_cookie cookie;
        long long endrec = *(long long *)data;
        int rc;
        ENTRY;

        /* This is always a (sub)log, not the catalog */
        LASSERT(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN);

        if (rec->cr_index > endrec)
                /* records are in order, so we're done */
                RETURN(LLOG_PROC_BREAK);

        cookie.lgc_lgl = llh->lgh_id;
        cookie.lgc_index = hdr->lrh_index;

        /* cancel them one at a time.  I suppose we could store up the cookies
           and cancel them all at once; probably more efficient, but this is
           done as a user call, so who cares... */
        rc = llog_cat_cancel_records(llh->u.phd.phd_cat_handle, 1, &cookie);
        RETURN(rc < 0 ? rc : 0);
}

static int llog_changelog_cancel(struct llog_ctxt *ctxt,
                                 struct lov_stripe_md *lsm, int count,
                                 struct llog_cookie *cookies, int flags)
{
        struct llog_handle *cathandle = ctxt->loc_handle;
        int rc;
        ENTRY;

        /* This should only be called with the catalog handle */
        LASSERT(cathandle->lgh_hdr->llh_flags & LLOG_F_IS_CAT);

        rc = llog_cat_process(cathandle, llog_changelog_cancel_cb,
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
        int rc;

        /* see osc_llog_init */
        changelog_orig_logops = llog_lvfs_ops;
        changelog_orig_logops.lop_setup = llog_obd_origin_setup;
        changelog_orig_logops.lop_cleanup = llog_obd_origin_cleanup;
        changelog_orig_logops.lop_add = llog_obd_origin_add;
        changelog_orig_logops.lop_cancel = llog_changelog_cancel;

        rc = llog_setup_named(obd, &obd->obd_olg, LLOG_CHANGELOG_ORIG_CTXT,
                              tgt, 1, NULL, CHANGELOG_CATALOG,
                              &changelog_orig_logops);
        if (rc) {
                CERROR("changelog llog setup failed %d\n", rc);
                RETURN(rc);
        }

        rc = llog_setup_named(obd, &obd->obd_olg, LLOG_CHANGELOG_USER_ORIG_CTXT,
                              tgt, 1, NULL, CHANGELOG_USERS,
                              &changelog_orig_logops);
        if (rc) {
                CERROR("changelog users llog setup failed %d\n", rc);
                RETURN(rc);
        }

        RETURN(rc);
}
EXPORT_SYMBOL(mds_changelog_llog_init);

int mds_llog_init(struct obd_device *obd, struct obd_llog_group *olg,
                  struct obd_device *tgt, int count, struct llog_catid *logid,
                  struct obd_uuid *uuid)
{
        struct obd_device *lov_obd = obd->u.mds.mds_osc_obd;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        LASSERT(olg == &obd->obd_olg);
        rc = llog_setup(obd, &obd->obd_olg, LLOG_MDS_OST_ORIG_CTXT, tgt,
                        0, NULL, &mds_ost_orig_logops);
        if (rc)
                RETURN(rc);

        rc = llog_setup(obd, &obd->obd_olg, LLOG_SIZE_REPL_CTXT, tgt,
                        0, NULL, &mds_size_repl_logops);
        if (rc)
                GOTO(err_llog, rc);

        rc = obd_llog_init(lov_obd, &lov_obd->obd_olg, tgt, count, logid, uuid);
        if (rc) {
                CERROR("lov_llog_init err %d\n", rc);
                GOTO(err_cleanup, rc);
        }

        RETURN(rc);
err_cleanup:
        ctxt = llog_get_context(obd, LLOG_SIZE_REPL_CTXT);
        if (ctxt)
                llog_cleanup(ctxt);
err_llog:
        ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
        if (ctxt)
                llog_cleanup(ctxt);
        return rc;
}

int mds_llog_finish(struct obd_device *obd, int count)
{
        struct llog_ctxt *ctxt;
        int rc = 0, rc2 = 0;
        ENTRY;

        ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
        if (ctxt)
                rc = llog_cleanup(ctxt);

        ctxt = llog_get_context(obd, LLOG_SIZE_REPL_CTXT);
        if (ctxt)
                rc2 = llog_cleanup(ctxt);
        if (!rc)
                rc = rc2;

        ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
        if (ctxt)
                rc2 = llog_cleanup(ctxt);
        if (!rc)
                rc = rc2;

        ctxt = llog_get_context(obd, LLOG_CHANGELOG_USER_ORIG_CTXT);
        if (ctxt)
                rc2 = llog_cleanup(ctxt);
        if (!rc)
                rc = rc2;

        RETURN(rc);
}
