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

int lov_llog_setup(struct obd_device *obd, struct obd_device *disk_obd,
                   int index, int count ,struct llog_logid *logids)
{
        struct lov_obd *lov = &obd->u.lov;
        int i, rc = 0;
        ENTRY;

        LASSERT(lov->desc.ld_tgt_count  == count);
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                struct obd_device *child = lov->tgts[i].ltd_exp->exp_obd;
                rc = obd_llog_setup(child, disk_obd, index, 1, logids + i);
                CERROR("error lov_llog_open %d\n", i);
                if (rc) 
                        break;
        }
        RETURN(rc);
}

int lov_llog_cleanup(struct obd_device *obd)
{
        struct lov_obd *lov = &obd->u.lov;
        int i, rc;

        ENTRY;
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                struct obd_device *child = lov->tgts[i].ltd_exp->exp_obd;
                rc = obd_llog_cleanup(child);
                CERROR("error lov_llog_open %d\n", i);
                if (rc) 
                        break;
        }
        RETURN(rc);
}

/* Add log records for each OSC that this object is striped over, and return
 * cookies for each one.  We _would_ have nice abstraction here, except that
 * we need to keep cookies in stripe order, even if some are NULL, so that
 * the right cookies are passed back to the right OSTs at the client side.
 * Unset cookies should be all-zero (which will never occur naturally). */
int lov_llog_origin_add(struct obd_export *exp,
                        int index,
                        struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                        struct llog_cookie *logcookies, int numcookies)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_oinfo *loi;
        int i, rc = 0;
        ENTRY;

        LASSERT(logcookies && numcookies >= lsm->lsm_stripe_count);

        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                rc += obd_llog_origin_add(lov->tgts[loi->loi_ost_idx].ltd_exp, index,
                                          rec, NULL, logcookies + rc, numcookies - rc);
        }

        RETURN(rc);
}

/* the replicators commit callback */
int lov_llog_repl_cancel(struct obd_device *obd, struct lov_stripe_md *lsm,
                          int count, struct llog_cookie *cookies, int flags)
{
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        LASSERT(lsm != NULL);
        LASSERT(count == lsm->lsm_stripe_count);

        loi = lsm->lsm_oinfo;
        lov = &obd->u.lov;
        for (i = 0; i < count; i++, cookies++, loi++) {
                int err;


                err = obd_llog_repl_cancel(lov->tgts[loi->loi_ost_idx].ltd_exp->exp_obd,
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
