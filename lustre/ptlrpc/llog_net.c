/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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
 *
 * OST<->MDS recovery logging infrastructure.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/fs.h>
#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <portals/list.h>
#include <linux/lvfs.h>


#ifdef ENABLE_ORPHANS
int llog_origin_handle_cancel(struct llog_obd_ctxt *ctxt, 
                              struct ptlrpc_request *req)
{
        struct obd_device *obd = ctxt->loc_exp->exp_obd;
        struct llog_cookie *logcookies;
        int num_cookies, rc = 0;
        struct obd_run_ctxt saved;
        struct llog_handle *cathandle;
        ENTRY;

        logcookies = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*logcookies));
        num_cookies = req->rq_reqmsg->buflens[0]/sizeof(*logcookies);
        if (logcookies == NULL || num_cookies == 0) {
                DEBUG_REQ(D_HA, req, "no cookies sent");
                RETURN(-EFAULT);
        }

        cathandle = ctxt->loc_handle;
        LASSERT(cathandle);

        push_ctxt(&saved, &obd->obd_ctxt, NULL); 
        rc = llog_cat_cancel_records(cathandle, num_cookies, logcookies);
        if (rc)
                CERROR("cancel %d llog-records failed: %d\n", num_cookies, rc);
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        RETURN(rc);
}
EXPORT_SYMBOL(llog_origin_handle_cancel);
#endif

int llog_receptor_accept(struct llog_obd_ctxt *ctxt, struct obd_import *imp)
{
        ENTRY;
        LASSERT(ctxt);
        ctxt->loc_imp = imp;
        RETURN(0);
}
EXPORT_SYMBOL(llog_receptor_accept);

int llog_initiator_connect(struct llog_obd_ctxt *ctxt)
{
        ENTRY;
        LASSERT(ctxt);
        ctxt->loc_imp = ctxt->loc_obd->u.cli.cl_import;
        RETURN(0);
}
EXPORT_SYMBOL(llog_initiator_connect);

