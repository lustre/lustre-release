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

#if 0

/* This is called from filter_setup() and should be single threaded */
int filter_get_catalog(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct filter_server_data *fsd = filter->fo_fsd;
        struct obd_run_ctxt saved;
        struct llog_handle *cathandle = NULL;
        struct llog_logid logid;
        struct llog_obd_ctxt *ctxt;
        int rc;
        ENTRY;

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        if (fsd->fsd_catalog_oid) {
                logid.lgl_oid = le64_to_cpu(fsd->fsd_catalog_oid);
                logid.lgl_ogen = 0;
                logid.lgl_ogr = le64_to_cpu(fsd->fsd_catalog_ogr);
                rc = llog_create(obd, &cathandle, &logid, NULL);
                if (rc) {
                        CERROR("error opening catalog "LPX64"/"LPX64": rc %d\n",
                               logid.lgl_oid, logid.lgl_ogr, 
                               (int)PTR_ERR(cathandle));
                        fsd->fsd_catalog_oid = 0;
                        fsd->fsd_catalog_ogr = 0;
                        RETURN(rc);
                }
        }

        if (!fsd->fsd_catalog_oid) {
                rc = llog_create(obd, &cathandle, NULL, NULL);
                if (rc) {
                        CERROR("error creating new catalog: rc %d\n", rc);
                        cathandle = ERR_PTR(rc);
                        GOTO(out, cathandle);
                }
                logid = cathandle->lgh_id;
                fsd->fsd_catalog_oid = cpu_to_le64(logid.lgl_oid);
                fsd->fsd_catalog_ogr = cpu_to_le64(logid.lgl_ogr);
                rc = filter_update_server_data(obd, filter->fo_rcvd_filp,
                                               fsd, 0);
                if (rc) {
                        CERROR("error writing new catalog to disk: rc %d\n",rc);
                        GOTO(out_handle, rc);
                }
        }

        rc = llog_init_handle(cathandle, LLOG_F_IS_CAT, &obd->obd_uuid);
        if (rc)
                GOTO(out_handle, rc);
        OBD_ALLOC(ctxt, sizeof(*ctxt));
        if (!ctxt)
                GOTO(out_handle, rc = -ENOMEM);
        LASSERT(obd->obd_llog_ctxt == NULL);
        obd->obd_llog_ctxt = ctxt;
        obd->obd_llog_ctxt->loc_obd = obd;
        obd->obd_llog_ctxt->loc_handles[LLOG_OBD_SZ_LOG_HANDLE] = cathandle;

out:
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        RETURN(rc);

out_handle:
        llog_close(cathandle);
        goto out;
}
#endif


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
        llog_obd_repl_cancel(obd, NULL, 1, cookie, OBD_LLOG_FL_SENDNOW);
        OBD_FREE(cb_data, sizeof(struct llog_cookie));
}
