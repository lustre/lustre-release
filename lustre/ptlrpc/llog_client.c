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
 *  remote api for llog - client side
 *
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/fs.h>
#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <linux/lustre_net.h>
#include <portals/list.h>

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static int llog_client_create(struct llog_ctxt *ctxt, struct llog_handle **res,
                            struct llog_logid *logid, char *name)
{
        struct obd_import *imp; 
        struct llogd_body req_body;
        struct llogd_body *body;
        struct llog_handle *handle;
        struct ptlrpc_request *req = NULL;
        int size[2] = {sizeof(req_body)};
        char *tmp[2] = {(char*) &req_body};
        int bufcount = 1;
        int repsize[] = {sizeof (req_body)};
        int rc;
        ENTRY;

        LASSERT(ctxt->loc_imp);
        imp = ctxt->loc_imp;

        handle = llog_alloc_handle();
        if (handle == NULL)
                RETURN(-ENOMEM);
        *res = handle;

        memset(&req_body, 0, sizeof(req_body));
        if (logid) 
                req_body.lgd_logid = *logid;
        req_body.lgd_ctxt_idx = ctxt->loc_idx - 1;
        
        if (name) {
                size[bufcount] = strlen(name) + 1;
                tmp[bufcount] = name;
                bufcount++;
        }

        req = ptlrpc_prep_req(imp, LLOG_ORIGIN_HANDLE_CREATE, bufcount, size, tmp);
        if (!req)
                GOTO(err_free, rc = -ENOMEM);

        req->rq_replen = lustre_msg_size(1, repsize);
        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(err_free, rc);
        
	body = lustre_swab_repbuf(req, 0, sizeof(*body),
                                 lustre_swab_llogd_body);
	if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                GOTO(err_free, rc =-EFAULT);
	}

        handle->lgh_id = body->lgd_logid;
        handle->lgh_ctxt = ctxt;

out:
        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);

err_free:
        llog_free_handle(handle);
        goto out;
}


static int llog_client_next_block(struct llog_handle *loghandle, 
                                         int *cur_idx, int next_idx,
                                         __u64 *cur_offset, void *buf, int len)
{
        struct obd_import *imp = loghandle->lgh_ctxt->loc_imp;
        struct ptlrpc_request *req = NULL;
        struct llogd_body *body;
        void * ptr;
        int size = sizeof(*body);
        int repsize[2] = {sizeof (*body)};
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(imp, LLOG_ORIGIN_HANDLE_NEXT_BLOCK, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);
        
        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        body->lgd_logid = loghandle->lgh_id;
        body->lgd_ctxt_idx = loghandle->lgh_ctxt->loc_idx - 1;
        body->lgd_llh_flags = loghandle->lgh_hdr->llh_flags;
        body->lgd_cur_offset = *cur_offset;
        body->lgd_index = next_idx;
        body->lgd_saved_index = *cur_idx;
        body->lgd_len = len;
        repsize[1] = len;

        req->rq_replen = lustre_msg_size(2, repsize);
        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);
        
	body = lustre_swab_repbuf(req, 0, sizeof(*body),
                                 lustre_swab_llogd_body);
	if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                GOTO(out, rc =-EFAULT);
	}
        
        ptr = lustre_msg_buf(req->rq_repmsg, 1, len);
	if (ptr == NULL) {
                CERROR ("Can't unpack bitmap\n");
                GOTO(out, rc =-EFAULT);
	}

        *cur_idx = body->lgd_saved_index;
        *cur_offset = body->lgd_cur_offset;
        
        memcpy(buf, ptr, len);

out:
        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}


static int llog_client_read_header(struct llog_handle *handle)
{
        struct obd_import *imp = handle->lgh_ctxt->loc_imp;
        struct ptlrpc_request *req = NULL;
        struct llogd_body *body;
        struct llog_log_hdr *hdr;
        int size = sizeof(*body);
        int repsize = sizeof (*hdr);
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(imp, LLOG_ORIGIN_HANDLE_READ_HEADER, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);
        
        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        body->lgd_logid = handle->lgh_id;
        body->lgd_ctxt_idx = handle->lgh_ctxt->loc_idx - 1;
        body->lgd_llh_flags = handle->lgh_hdr->llh_flags;

        req->rq_replen = lustre_msg_size(1, &repsize);
        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);
        
	hdr = lustre_swab_repbuf(req, 0, sizeof(*hdr),
                                 lustre_swab_llog_hdr);
	if (hdr == NULL) {
                CERROR ("Can't unpack llog_hdr\n");
                GOTO(out, rc =-EFAULT);
	}
        memcpy(handle->lgh_hdr, hdr, sizeof (*hdr));

out:
        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

static int llog_client_close(struct llog_handle *handle)
{
        int rc = 0;

        RETURN(rc);
}


struct llog_operations llog_client_ops = {
        lop_next_block:  llog_client_next_block,
        lop_read_header: llog_client_read_header,
        lop_create:      llog_client_create,
        lop_close:       llog_client_close,
};
