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
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>

#include <portals/list.h>
#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_commit_confd.h>

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

        down(&inode->i_sem);
        ofd = inode->i_filterdata;
        
        if (ofd && ofd->ofd_epoch >= io_epoch) {
                if (ofd->ofd_epoch > io_epoch)
                        CERROR("client sent old epoch %d for obj ino %ld\n", 
                               io_epoch, inode->i_ino);
                up(&inode->i_sem);
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
        up(&inode->i_sem);

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
        llog_cancel(llog_get_context(obd, cookie->lgc_subsys + 1),
                             NULL, 1, cookie, 0);
                             //NULL, 1, cookie, OBD_LLOG_FL_SENDNOW);
        OBD_FREE(cb_data, sizeof(struct llog_cookie));
}

/* Callback for processing the unlink log record received from MDS by 
 * llog_client_api.
 */
int filter_recov_log_unlink_cb(struct llog_handle *llh, 
                               struct llog_rec_hdr *rec, void *data)
{
        struct llog_ctxt *ctxt = llh->lgh_ctxt;
        struct obd_device *obd = ctxt->loc_obd;
        struct obd_export *exp = obd->obd_self_export;
        struct llog_cookie cookie;
        struct llog_unlink_rec *lur;
        struct obdo *oa;
        struct obd_trans_info oti = { 0 };
        obd_id oid;
        int rc = 0;
        ENTRY;
                                                                                                                             
        if (!le32_to_cpu(llh->lgh_hdr->llh_flags) & LLOG_F_IS_PLAIN) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }
        if (rec->lrh_type != MDS_UNLINK_REC) {
                CERROR("log record type error\n");
                RETURN(-EINVAL);
        }
 
        cookie.lgc_lgl = llh->lgh_id;
        cookie.lgc_subsys = LLOG_UNLINK_ORIG_CTXT;
        cookie.lgc_index = le32_to_cpu(rec->lrh_index);
                                                                                                                             
        lur = (struct llog_unlink_rec *)rec;
        
        oa = obdo_alloc();
        if (oa == NULL) 
                RETURN(-ENOMEM);
        oa->o_valid |= OBD_MD_FLCOOKIE;
        oa->o_id = lur->lur_oid;
        oa->o_gr = lur->lur_ogen;
        memcpy(obdo_logcookie(oa), &cookie, sizeof(cookie));
        oid = oa->o_id;

        rc = obd_destroy(exp, oa, NULL, &oti);
        obdo_free(oa);
        if (rc == -ENOENT) {
                CERROR("object already removed: send cookie\n");
                llog_cancel(ctxt, NULL, 1, &cookie, 0);
                RETURN(0);
        }

        if (rc == 0)
                CERROR("object: "LPU64" in record destroyed successful\n", oid);

        RETURN(rc);
}
