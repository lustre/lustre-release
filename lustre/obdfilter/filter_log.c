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

/* This is called from filter_setup() and should be single threaded */
struct llog_handle *filter_get_catalog(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct filter_server_data *fsd = filter->fo_fsd;
        struct obd_run_ctxt saved;
        struct llog_handle *cathandle = NULL;
        struct llog_logid logid;
        int rc;
        ENTRY;

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        if (fsd->fsd_catalog_oid) {
                logid.lgl_oid = le64_to_cpu(fsd->fsd_catalog_oid);
                logid.lgl_ogen = le32_to_cpu(fsd->fsd_catalog_ogen);
                rc = llog_create(obd, &cathandle, &logid, NULL);
                if (rc) {
                        CERROR("error opening catalog "LPX64":%x: rc %d\n",
                               logid.lgl_oid, logid.lgl_ogen,
                               (int)PTR_ERR(cathandle));
                        fsd->fsd_catalog_oid = 0;
                        fsd->fsd_catalog_ogen = 0;
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
                fsd->fsd_catalog_ogen = cpu_to_le32(logid.lgl_ogen);
                rc = filter_update_server_data(obd, filter->fo_rcvd_filp,fsd,0);
                if (rc) {
                        CERROR("error writing new catalog to disk: rc %d\n",rc);
                        GOTO(out_handle, rc);
                }
        }

        rc = llog_init_handle(cathandle, LLOG_F_IS_CAT, &obd->u.filter.fo_mdc_uuid);
        if (rc)
                GOTO(out_handle, rc);
out:
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        RETURN(cathandle);

out_handle:
        llog_close(cathandle);
        cathandle = ERR_PTR(rc);
        goto out;
}


int filter_log_op_create(struct llog_handle *cathandle, struct ll_fid *mds_fid,
                         obd_id oid, obd_count ogen,
                         struct llog_cookie *logcookie)
{
        struct llog_create_rec *lcr;
        int rc;
        ENTRY;

        OBD_ALLOC(lcr, sizeof(*lcr));
        if (lcr == NULL)
                RETURN(-ENOMEM);
        lcr->lcr_hdr.lrh_len = lcr->lcr_tail.lrt_len = sizeof(*lcr);
        lcr->lcr_hdr.lrh_type = OST_CREATE_REC;
        lcr->lcr_fid.id = mds_fid->id;
        lcr->lcr_fid.generation = mds_fid->generation;
        lcr->lcr_fid.f_type = mds_fid->f_type;
        lcr->lcr_oid = oid;
        lcr->lcr_ogen = ogen;

        rc = llog_cat_add_rec(cathandle, &lcr->lcr_hdr, logcookie, NULL);
        OBD_FREE(lcr, sizeof(*lcr));

        if (rc > 0) {
                LASSERT(rc == sizeof(*logcookie));
                rc = 0;
        }
        RETURN(rc);
}

int filter_log_op_orphan(struct llog_handle *cathandle, obd_id oid,
                         obd_count ogen, struct llog_cookie *logcookie)
{
        struct llog_orphan_rec *lor;
        int rc;
        ENTRY;

        OBD_ALLOC(lor, sizeof(*lor));
        if (lor == NULL)
                RETURN(-ENOMEM);
        lor->lor_hdr.lrh_len = lor->lor_tail.lrt_len = sizeof(*lor);
        lor->lor_hdr.lrh_type = OST_ORPHAN_REC;
        lor->lor_oid = oid;
        lor->lor_ogen = ogen;

        rc = llog_cat_add_rec(cathandle, &lor->lor_hdr, logcookie, NULL);

        if (rc > 0) {
                LASSERT(rc == sizeof(*logcookie));
                rc = 0;
        }
        RETURN(rc);
}
