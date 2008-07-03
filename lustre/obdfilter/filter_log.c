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

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/version.h>

#include <libcfs/list.h>
#include <obd_class.h>
#include <lustre_fsfilt.h>
#include <lustre_commit_confd.h>

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

        LOCK_INODE_MUTEX(inode);
        ofd = inode->i_filterdata;

        if (ofd && ofd->ofd_epoch >= ioepoch) {
                if (ofd->ofd_epoch > ioepoch)
                        CERROR("client sent old epoch %d for obj ino %ld\n",
                               ioepoch, inode->i_ino);
                UNLOCK_INODE_MUTEX(inode);
                RETURN(0);
        }

        if (ofd && ofd->ofd_epoch < ioepoch) {
                ofd->ofd_epoch = ioepoch;
        } else if (!ofd) {
                OBD_ALLOC(ofd, sizeof(*ofd));
                if (!ofd)
                        GOTO(out, rc = -ENOMEM);
                igrab(inode);
                inode->i_filterdata = ofd;
                ofd->ofd_epoch = ioepoch;
        }
        /* the decision to write a record is now made, unlock */
        UNLOCK_INODE_MUTEX(inode);

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

        olg = filter_find_olg(obd, cookie->lgc_lgl.lgl_ogr);
        if (!olg) { 
                CDEBUG(D_HA, "unknown group "LPU64"!\n", cookie->lgc_lgl.lgl_ogr);
                GOTO(out, rc = 0);
        }
        
        ctxt = llog_group_get_ctxt(olg, cookie->lgc_subsys + 1);
        if (!ctxt) {
                CERROR("no valid context for group "LPU64"\n",
                        cookie->lgc_lgl.lgl_ogr);
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
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_export *exp = obd->obd_self_export;
        struct llog_unlink_rec *lur;
        struct obdo *oa;
        obd_id oid;
        int rc = 0;
        ENTRY;

        lur = (struct llog_unlink_rec *)rec;
        OBDO_ALLOC(oa);
        if (oa == NULL) 
                RETURN(-ENOMEM);
        oa->o_valid |= OBD_MD_FLCOOKIE;
        oa->o_id = lur->lur_oid;
        oa->o_gr = lur->lur_ogen;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        memcpy(obdo_logcookie(oa), cookie, sizeof(*cookie));
        oid = oa->o_id;

        rc = filter_destroy(exp, oa, NULL, NULL, NULL);
        OBDO_FREE(oa);
        if (rc == -ENOENT) {
                CDEBUG(D_RPCTRACE, "object already removed, send cookie\n");
                llog_cancel(ctxt, NULL, 1, cookie, 0);
                RETURN(0);
        }

        if (rc == 0)
                CDEBUG(D_RPCTRACE, "object "LPU64" is destroyed\n", oid);

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
        OBDO_ALLOC(oinfo.oi_oa);
        if (oinfo.oi_oa == NULL)
                RETURN(-ENOMEM);

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

int filter_recov_log_mds_ost_cb(struct llog_handle *llh,
                               struct llog_rec_hdr *rec, void *data)
{
        struct llog_ctxt *ctxt = llh->lgh_ctxt;
        struct llog_cookie cookie;
        int rc = 0;
        ENTRY;

        if (ctxt->loc_obd->obd_stopping)
                RETURN(LLOG_PROC_BREAK);

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
        case MDS_SETATTR_REC:
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
