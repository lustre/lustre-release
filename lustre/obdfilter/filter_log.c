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
 * Copyright (c) 2011, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdfilter/filter_log.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/module.h>
#include <linux/version.h>

#include <libcfs/list.h>
#include <obd_class.h>
#include <lustre_log.h>
#include <lustre_fsfilt.h>
#include "filter_internal.h"

int filter_log_sz_change(struct llog_handle *cathandle,
                         struct ll_fid *mds_fid,
                         __u32 ioepoch,
                         struct llog_cookie *logcookie,
                         struct inode *inode)
{
        struct llog_size_change_rec *lsc;
        int rc;
        struct ost_filterdata *ofd;
        ENTRY;

	mutex_lock(&inode->i_mutex);
	ofd = inode->i_private;

	if (ofd && ofd->ofd_epoch >= ioepoch) {
		if (ofd->ofd_epoch > ioepoch)
			CERROR("client sent old epoch %d for obj ino %ld\n",
			       ioepoch, inode->i_ino);
		mutex_unlock(&inode->i_mutex);
		RETURN(0);
	}

	if (ofd && ofd->ofd_epoch < ioepoch) {
		ofd->ofd_epoch = ioepoch;
	} else if (!ofd) {
		OBD_ALLOC(ofd, sizeof(*ofd));
		if (!ofd)
			GOTO(out, rc = -ENOMEM);
		igrab(inode);
		inode->i_private = ofd;
		ofd->ofd_epoch = ioepoch;
	}
	/* the decision to write a record is now made, unlock */
	mutex_unlock(&inode->i_mutex);

        OBD_ALLOC(lsc, sizeof(*lsc));
        if (lsc == NULL)
                RETURN(-ENOMEM);
        lsc->lsc_hdr.lrh_len = lsc->lsc_tail.lrt_len = sizeof(*lsc);
        lsc->lsc_hdr.lrh_type =  OST_SZ_REC;
        lsc->lsc_fid = *mds_fid;
        lsc->lsc_ioepoch = ioepoch;

        rc = llog_cat_add_rec(cathandle, &lsc->lsc_hdr, logcookie, NULL);
        OBD_FREE(lsc, sizeof(*lsc));

        if (rc > 0) {
                LASSERT(rc == sizeof(*logcookie));
                rc = 0;
        }

        out:
        RETURN(rc);
}

/* When this (destroy) operation is committed, return the cancel cookie */
void filter_cancel_cookies_cb(struct obd_device *obd, __u64 transno,
                              void *cb_data, int error)
{
        struct llog_cookie *cookie = cb_data;
        struct obd_llog_group *olg;
        struct llog_ctxt *ctxt;
        int rc;

        /* we have to find context for right group */
        if (error != 0 || obd->obd_stopping) {
                CDEBUG(D_INODE, "not cancel logcookie err %d stopping %d \n",
                       error, obd->obd_stopping);
                GOTO (out, rc = 0);
        }

        olg = filter_find_olg(obd, cookie->lgc_lgl.lgl_oseq);
        if (!olg) {
                CDEBUG(D_HA, "unknown group "LPU64"!\n", cookie->lgc_lgl.lgl_oseq);
                GOTO(out, rc = 0);
        }

        ctxt = llog_group_get_ctxt(olg, cookie->lgc_subsys + 1);
        if (!ctxt) {
                CERROR("no valid context for group "LPU64"\n",
                        cookie->lgc_lgl.lgl_oseq);
                GOTO(out, rc = 0);
        }

        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_CANCEL_COOKIE_TIMEOUT, 30);

        rc = llog_cancel(ctxt, NULL, 1, cookie, 0);
        if (rc)
                CERROR("error cancelling log cookies: rc = %d\n", rc);
        llog_ctxt_put(ctxt);
out:
        OBD_FREE(cookie, sizeof(*cookie));
}

/* Callback for processing the unlink log record received from MDS by
 * llog_client_api. */
static int filter_recov_log_unlink_cb(struct llog_ctxt *ctxt,
                                      struct llog_rec_hdr *rec,
                                      struct llog_cookie *cookie)
{
        struct obd_export *exp = ctxt->loc_obd->obd_self_export;
        struct llog_unlink_rec *lur;
        struct obdo *oa;
        obd_id oid;
        obd_count count;
        int rc = 0;
        ENTRY;

        lur = (struct llog_unlink_rec *)rec;
        OBDO_ALLOC(oa);
        if (oa == NULL)
                RETURN(-ENOMEM);
        oa->o_valid |= OBD_MD_FLCOOKIE;
        oa->o_id = lur->lur_oid;
        oa->o_seq = lur->lur_oseq;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        oa->o_lcookie = *cookie;
        oid = oa->o_id;
        /* objid gap may require to destroy several objects in row */
        count = lur->lur_count + 1;

        /* This check is only valid before FID-on-OST and it should
         * be removed after FID-on-OST is implemented */
        if (oa->o_seq > FID_SEQ_OST_MAX) {
                CERROR("%s: invalid group number "LPU64" > MAX_CMD_GROUP %u\n",
                        exp->exp_obd->obd_name, oa->o_seq, FID_SEQ_OST_MAX);
                RETURN(-EINVAL);
        }

        while (count > 0) {
                rc = filter_destroy(NULL, exp, oa, NULL, NULL, NULL, NULL);
                if (rc == 0)
                        CDEBUG(D_RPCTRACE, "object "LPU64" is destroyed\n",
                               oid);
                else if (rc != -ENOENT)
                        CEMERG("error destroying object "LPU64": %d\n",
                               oid, rc);
                else
                        rc = 0;
                count--;
                oid++;
        }
        OBDO_FREE(oa);

        RETURN(rc);
}

/* Callback for processing the setattr log record received from MDS by
 * llog_client_api. */
static int filter_recov_log_setattr_cb(struct llog_ctxt *ctxt,
                                       struct llog_rec_hdr *rec,
                                       struct llog_cookie *cookie)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_export *exp = obd->obd_self_export;
        struct obd_info oinfo = { { { 0 } } };
        obd_id oid;
        int rc = 0;
        ENTRY;

        OBDO_ALLOC(oinfo.oi_oa);
        if (oinfo.oi_oa == NULL)
                RETURN(-ENOMEM);

	if (rec->lrh_type == MDS_SETATTR64_REC) {
                struct llog_setattr64_rec *lsr = (struct llog_setattr64_rec *)rec;

                oinfo.oi_oa->o_id = lsr->lsr_oid;
                oinfo.oi_oa->o_seq = lsr->lsr_oseq;
                oinfo.oi_oa->o_uid = lsr->lsr_uid;
                oinfo.oi_oa->o_gid = lsr->lsr_gid;
	} else {
		CERROR("%s: wrong llog type %#x\n", obd->obd_name,
		       rec->lrh_type);
		RETURN(-EINVAL);
	}

        oinfo.oi_oa->o_valid |= (OBD_MD_FLID | OBD_MD_FLUID | OBD_MD_FLGID |
                                 OBD_MD_FLCOOKIE);
        oinfo.oi_oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        oinfo.oi_oa->o_lcookie = *cookie;
        oid = oinfo.oi_oa->o_id;

        rc = filter_setattr(NULL, exp, &oinfo, NULL);
        OBDO_FREE(oinfo.oi_oa);

        if (rc == -ENOENT) {
                CDEBUG(D_RPCTRACE, "object already removed, send cookie\n");
                llog_cancel(ctxt, NULL, 1, cookie, 0);
                RETURN(0);
        }

        if (rc == 0)
                CDEBUG(D_RPCTRACE, "object "LPU64" is chown/chgrp\n", oid);

        RETURN(rc);
}

int filter_recov_log_mds_ost_cb(const struct lu_env *env,
				struct llog_handle *llh,
				struct llog_rec_hdr *rec, void *data)
{
        struct llog_ctxt *ctxt = llh->lgh_ctxt;
        struct llog_cookie cookie;
        int rc = 0;
        ENTRY;

        if (ctxt->loc_obd->obd_stopping)
                RETURN(LLOG_PROC_BREAK);

        if (rec == NULL) {
                cfs_spin_lock(&ctxt->loc_obd->u.filter.fo_flags_lock);
                ctxt->loc_obd->u.filter.fo_mds_ost_sync = 0;
                cfs_spin_unlock(&ctxt->loc_obd->u.filter.fo_flags_lock);
                RETURN(0);
        }

        if (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }

        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_LLOG_RECOVERY_TIMEOUT, 30);
        cookie.lgc_lgl = llh->lgh_id;
        cookie.lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
        cookie.lgc_index = rec->lrh_index;

        switch (rec->lrh_type) {
        case MDS_UNLINK_REC:
                rc = filter_recov_log_unlink_cb(ctxt, rec, &cookie);
                break;
        case MDS_SETATTR64_REC:
                rc = filter_recov_log_setattr_cb(ctxt, rec, &cookie);
                break;
        case LLOG_GEN_REC: {
                struct llog_gen_rec *lgr = (struct llog_gen_rec *)rec;

                if (llog_gen_lt(lgr->lgr_gen, ctxt->loc_gen))
                        rc = 0;
                else
                        rc = LLOG_PROC_BREAK;
                CDEBUG(D_HA, "fetch generation log, send cookie\n");
                llog_cancel(ctxt, NULL, 1, &cookie, 0);
                RETURN(rc);
                }
                break;
        default:
                CERROR("log record type %08x unknown\n", rec->lrh_type);
                RETURN(-EINVAL);
                break;
        }

        RETURN(rc);
}
