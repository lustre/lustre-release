/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter_log.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>

#include <libcfs/list.h>
#include <obd_class.h>
#include <lustre_fsfilt.h>
#include <lustre_commit_confd.h>

#include "filter_internal.h"

int filter_log_sz_change(struct llog_handle *cathandle,
                         struct ll_fid *mds_fid,
                         __u32 io_epoch,
                         struct llog_cookie *logcookie,
                         struct inode *inode)
{
        struct llog_size_change_rec *lsc;
        int rc;
        struct ost_filterdata *ofd;
        ENTRY;

        LOCK_INODE_MUTEX(inode);
        ofd = inode->i_filterdata;

        if (ofd && ofd->ofd_epoch >= io_epoch) {
                if (ofd->ofd_epoch > io_epoch)
                        CERROR("client sent old epoch %d for obj ino %ld\n",
                               io_epoch, inode->i_ino);
                UNLOCK_INODE_MUTEX(inode);
                RETURN(0);
        }

        if (ofd && ofd->ofd_epoch < io_epoch) {
                ofd->ofd_epoch = io_epoch;
        } else if (!ofd) {
                OBD_ALLOC(ofd, sizeof(*ofd));
                if (!ofd)
                        GOTO(out, rc = -ENOMEM);
                igrab(inode);
                inode->i_filterdata = ofd;
                ofd->ofd_epoch = io_epoch;
        }
        /* the decision to write a record is now made, unlock */
        UNLOCK_INODE_MUTEX(inode);

        OBD_ALLOC(lsc, sizeof(*lsc));
        if (lsc == NULL)
                RETURN(-ENOMEM);
        lsc->lsc_hdr.lrh_len = lsc->lsc_tail.lrt_len = sizeof(*lsc);
        lsc->lsc_hdr.lrh_type =  OST_SZ_REC;
        lsc->lsc_fid = *mds_fid;
        lsc->lsc_io_epoch = io_epoch;

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
        int rc;

        if (error != 0) {
                CDEBUG(D_INODE, "not cancelling llog cookie on error %d\n",
                       error);
                return;
        }

        rc = llog_cancel(llog_get_context(obd, cookie->lgc_subsys + 1),
                         NULL, 1, cookie, 0);
        if (rc)
                CERROR("error cancelling log cookies: rc = %d\n", rc);
        OBD_FREE(cookie, sizeof(*cookie));
}

/* Callback for processing the unlink log record received from MDS by 
 * llog_client_api. */
static int filter_recov_log_unlink_cb(struct llog_ctxt *ctxt,
                                      struct llog_rec_hdr *rec,
                                      struct llog_cookie *cookie)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_export *exp = obd->obd_self_export;
        struct llog_unlink_rec *lur;
        struct obdo *oa;
        obd_id oid;
        int rc = 0;
        ENTRY;

        lur = (struct llog_unlink_rec *)rec;
        oa = obdo_alloc();
        if (oa == NULL) 
                RETURN(-ENOMEM);
        oa->o_valid |= OBD_MD_FLCOOKIE;
        oa->o_id = lur->lur_oid;
        oa->o_gr = lur->lur_ogen;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        memcpy(obdo_logcookie(oa), cookie, sizeof(*cookie));
        oid = oa->o_id;

        rc = filter_destroy(exp, oa, NULL, NULL, NULL);
        obdo_free(oa);
        if (rc == -ENOENT) {
                CDEBUG(D_HA, "object already removed, send cookie\n");
                llog_cancel(ctxt, NULL, 1, cookie, 0);
                RETURN(0);
        }

        if (rc == 0)
                CDEBUG(D_HA, "object: "LPU64" in record is destroyed\n", oid);

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
        struct llog_setattr_rec *lsr;
        struct obd_info oinfo = { { { 0 } } };
        obd_id oid;
        int rc = 0;
        ENTRY;

        lsr = (struct llog_setattr_rec *)rec;
        oinfo.oi_oa = obdo_alloc();

        oinfo.oi_oa->o_valid |= (OBD_MD_FLID | OBD_MD_FLUID | OBD_MD_FLGID |
                                 OBD_MD_FLCOOKIE);
        oinfo.oi_oa->o_id = lsr->lsr_oid;
        oinfo.oi_oa->o_gr = lsr->lsr_ogen;
        oinfo.oi_oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        oinfo.oi_oa->o_uid = lsr->lsr_uid;
        oinfo.oi_oa->o_gid = lsr->lsr_gid;
        memcpy(obdo_logcookie(oinfo.oi_oa), cookie, sizeof(*cookie));
        oid = oinfo.oi_oa->o_id;

        rc = filter_setattr(exp, &oinfo, NULL);
        obdo_free(oinfo.oi_oa);

        if (rc == -ENOENT) {
                CDEBUG(D_HA, "object already removed, send cookie\n");
                llog_cancel(ctxt, NULL, 1, cookie, 0);
                RETURN(0);
        }

        if (rc == 0)
                CDEBUG(D_HA, "object: "LPU64" in record is chown/chgrp\n", oid);

        RETURN(rc);
}

int filter_recov_log_mds_ost_cb(struct llog_handle *llh,
                               struct llog_rec_hdr *rec, void *data)
{
        struct llog_ctxt *ctxt = llh->lgh_ctxt;
        struct llog_cookie cookie;
        int rc = 0;
        ENTRY;

        if (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }

        cookie.lgc_lgl = llh->lgh_id;
        cookie.lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
        cookie.lgc_index = rec->lrh_index;

        switch (rec->lrh_type) {
        case MDS_UNLINK_REC:
                rc = filter_recov_log_unlink_cb(ctxt, rec, &cookie);
                break;
        case MDS_SETATTR_REC:
                rc = filter_recov_log_setattr_cb(ctxt, rec, &cookie);
                break;
        case LLOG_GEN_REC: {
                struct llog_gen_rec *lgr = (struct llog_gen_rec *)rec;
                if (llog_gen_lt(lgr->lgr_gen, ctxt->loc_gen))
                        rc = 0;
                else
                        rc = LLOG_PROC_BREAK;
                CWARN("fetch generation log, send cookie\n");
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
