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

#ifdef __KERNEL__
#include <linux/fs.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <portals/list.h>
#include <linux/lvfs.h>

#ifdef __KERNEL__

#ifdef ENABLE_ORPHANS
int llog_origin_handle_cancel(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_device *disk_obd;
        struct llog_cookie *logcookies;
        struct llog_ctxt *ctxt;
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

        ctxt = llog_get_context(obd, logcookies->lgc_subsys);
        if (ctxt == NULL) {
                CERROR("llog subsys not setup or already cleanup\n");
                RETURN(-ENOENT);
        }
        down(&ctxt->loc_sem);
        disk_obd = ctxt->loc_exp->exp_obd;
        cathandle = ctxt->loc_handle;
        LASSERT(cathandle);

        push_ctxt(&saved, &disk_obd->obd_ctxt, NULL); 
        rc = llog_cat_cancel_records(cathandle, num_cookies, logcookies);
        if (rc)
                CERROR("cancel %d llog-records failed: %d\n", num_cookies, rc);
        else
                CERROR("cancel %d llog-records successful\n", num_cookies);

        pop_ctxt(&saved, &disk_obd->obd_ctxt, NULL);
        up(&ctxt->loc_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(llog_origin_handle_cancel);
#endif
                                                                                                                             
int llog_origin_connect(struct llog_ctxt *ctxt, int count,
                        struct llog_logid *logid,
                        struct llog_ctxt_gen *gen)
{
        struct obd_import *imp;
        struct ptlrpc_request *request;
        struct llogd_conn_body *req_body;
        int size = sizeof(struct llogd_conn_body);
        int rc;
        ENTRY;

        LASSERT(ctxt->loc_imp);
        imp = ctxt->loc_imp;

        request = ptlrpc_prep_req(imp, LLOG_ORIGIN_CONNECT, 1, &size, NULL);
        if (!request) 
                RETURN(-ENOMEM);

        req_body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof(*req_body));

        req_body->lgdc_gen = ctxt->loc_gen;
        req_body->lgdc_logid = ctxt->loc_handle->lgh_id;
        req_body->lgdc_ctxt_idx = ctxt->loc_idx + 1;
        request->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(request);
        ptlrpc_req_finished(request);

        RETURN(rc);
}
EXPORT_SYMBOL(llog_origin_connect);

int llog_handle_connect(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct llogd_conn_body *req_body;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;
                                                                                                                             
        req_body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*req_body));
                                                                                                                             
        ctxt = llog_get_context(obd, req_body->lgdc_ctxt_idx);
        rc = llog_connect(ctxt, 1, &req_body->lgdc_logid, 
                          &req_body->lgdc_gen);
        if (rc != 0) 
                CERROR("failed at llog_relp_connect\n");

        RETURN(rc);
}
EXPORT_SYMBOL(llog_handle_connect);

int llog_receptor_accept(struct llog_ctxt *ctxt, struct obd_import *imp)
{
        ENTRY;
        LASSERT(ctxt);
        ctxt->loc_imp = imp;
        RETURN(0);
}
EXPORT_SYMBOL(llog_receptor_accept);

int llog_initiator_connect(struct llog_ctxt *ctxt)
{
        ENTRY;
        LASSERT(ctxt);
        ctxt->loc_imp = ctxt->loc_obd->u.cli.cl_import;
        RETURN(0);
}
EXPORT_SYMBOL(llog_initiator_connect);
#else /* !__KERNEL__ */

int llog_initiator_connect(struct llog_ctxt *ctxt)
{
        return 0;
}
#endif
