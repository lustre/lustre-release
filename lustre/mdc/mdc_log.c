/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mdc/mdc_log.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.

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

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>

#include <portals/list.h>
#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_commit_confd.h>

#include "mdc_internal.h"

static int mdc_llog_cleanup(struct llog_obd_ctxt *ctxt, int ctxt_idx)
{
        struct obd_device *obd = ctxt->loc_obd;
        int rc = 0;
        ENTRY;

        LASSERT(obd->obd_llog_ctxt[ctxt_idx]); 
        class_unlink_export(ctxt->loc_exp);
        class_export_put(ctxt->loc_exp);

        obd->obd_llog_ctxt[ctxt_idx] = NULL;
        OBD_FREE(ctxt, sizeof(*ctxt));
        RETURN(rc);
}

struct llog_operations mdc_llog_ops;
int mdc_llog_setup(struct obd_device *obd, int ctxt_idx, 
                   struct obd_device *disk_obd, struct obd_uuid uuid,
                   struct llog_logid *logid)
{
        struct llog_obd_ctxt *ctxt;
        int rc = 0;
        ENTRY;

        if (obd->obd_llog_ctxt[ctxt_idx]) {
                CERROR("obd_llog_ctxt %d already allocated\n", ctxt_idx);
                LBUG();
        }

        OBD_ALLOC(ctxt, sizeof(*ctxt));
        if (!ctxt)
                RETURN(-ENOMEM);
        obd->obd_llog_ctxt[ctxt_idx] = ctxt;
        sema_init(&ctxt->loc_sem, 1);
        ctxt->loc_idx = ctxt_idx;
        ctxt->loc_obd = obd;

        ctxt->loc_exp = class_new_export(disk_obd);

        mdc_llog_ops = llog_lvfs_ops;
        mdc_llog_ops.lop_setup = mdc_llog_setup;
        mdc_llog_ops.lop_cleanup = mdc_llog_cleanup;
        mdc_llog_ops.lop_add = NULL;
        mdc_llog_ops.lop_cancel = NULL;

        ctxt->loc_logops = &mdc_llog_ops;
        RETURN(rc);
}
