 /* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 * Author: Phil Schwan <phil@clusterfs.com>
 *         Peter Braam <braam@clusterfs.com>
 *         Mike Shaver <shaver@clusterfs.com>
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LOV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <asm/div64.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lite.h> /* for LL_IOC_LOV_[GS]ETSTRIPE */
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/obd_ost.h>
#include <linux/seq_file.h>
#include <linux/lprocfs_status.h>

#include "lov_internal.h"

/* For LOV catalogs, we "nest" catalogs from the parent catalog.  What this
 * means is that the parent catalog has a bunch of log cookies that are
 * pointing at one catalog for each OSC.  The OSC catalogs in turn hold
 * cookies for actual log files. */
int lov_llog_open(struct obd_device *obd, struct obd_device *disk_obd,
                  int index, int named, int flags, struct obd_uuid *log_uuid)

{
        struct lov_obd *lov = &obd->u.lov;
        int i, rc;

        ENTRY;
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                struct obd_device *child = lov->tgts[i].ltd_exp->exp_obd;
                rc = obd_llog_open(child, disk_obd, 
                                   index, named, flags, log_uuid);
                CERROR("error lov_llog_open %d\n", i);
                if (rc) 
                        break;
        }
        RETURN(rc);
}

int lov_get_catalogs(struct lov_obd *lov, struct llog_handle *cathandle)
{
        struct obd_device *obd = cathandle->lgh_obd;
        struct lustre_handle conn;
        struct obd_export *exp;
        struct obd_uuid cluuid = { "MDS_OSC_UUID" }; 
        int rc = 0, i;
        ENTRY;

        for (i = 0; i < lov->desc.ld_active_tgt_count; i ++) {
                rc = class_connect(&conn, obd, &cluuid);
                if (rc) {
                        CERROR("failed %d: \n", rc);
                        GOTO(out, rc);
                }
                exp = class_conn2export(&conn);
                lov->tgts[i].ltd_exp->exp_obd->obd_log_exp = exp;
                lov->tgts[i].ltd_cathandle = cathandle;
        }
                
        lov->lo_catalog_loaded = 1;
        RETURN(rc);

out:
        while (--i > 0) {
                class_disconnect(lov->tgts[i].ltd_exp->exp_obd->obd_log_exp, 0);
                lov->tgts[i].ltd_cathandle = cathandle;
        }
        RETURN(rc);
}

/* Add log records for each OSC that this object is striped over, and return
 * cookies for each one.  We _would_ have nice abstraction here, except that
 * we need to keep cookies in stripe order, even if some are NULL, so that
 * the right cookies are passed back to the right OSTs at the client side.
 * Unset cookies should be all-zero (which will never occur naturally). */
int lov_log_add(struct obd_export *exp,
                       struct llog_handle *cathandle,
                       struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                       struct llog_cookie *logcookies, int numcookies)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_oinfo *loi;
        int i, rc = 0;
        ENTRY;

        LASSERT(logcookies && numcookies >= lsm->lsm_stripe_count);

        if (unlikely(!lov->lo_catalog_loaded))
                lov_get_catalogs(lov, cathandle);

        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                rc += obd_log_add(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                  lov->tgts[loi->loi_ost_idx].ltd_cathandle,
                                  rec, NULL, logcookies + rc, numcookies - rc);
        }

        RETURN(rc);
}

int lov_log_cancel(struct obd_export *exp, struct lov_stripe_md *lsm,
                          int count, struct llog_cookie *cookies, int flags)
{
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        LASSERT(lsm != NULL);
        if (exp == NULL || exp->exp_obd == NULL)
                RETURN(-ENODEV);

        LASSERT(count == lsm->lsm_stripe_count);

        loi = lsm->lsm_oinfo;
        lov = &exp->exp_obd->u.lov;
        for (i = 0; i < count; i++, cookies++, loi++) {
                int err;

                err = obd_log_cancel(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                     lov->tgts[loi->loi_ost_idx].ltd_cathandle,
                                     NULL, 1, cookies, flags);

                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        RETURN(rc);
}

