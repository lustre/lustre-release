/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
n *
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
 * remote api for llog
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

int llog_origin_handle_create(struct llog_obd_ctxt * lctxt,
                              struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
	struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct obd_run_ctxt saved;
        struct llog_logid *logid = NULL;
	char * name = NULL;
        int size = sizeof (*body);
	int rc, rc2;
	ENTRY;

        body = lustre_swab_reqbuf(req, 0, sizeof(*body),
                                 lustre_swab_llogd_body);
	if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                GOTO(out, rc =-EFAULT);
	}

        if (body->lgd_logid.lgl_oid > 0) 
                logid = &body->lgd_logid;

        if (req->rq_reqmsg->bufcount > 1) {
                name = lustre_msg_string(req->rq_reqmsg, 1, 0);
                if (name == NULL) {
                        CERROR("Can't unpack name\n");
                        GOTO(out, rc = -EFAULT);
                }
        } 

	push_ctxt(&saved, &obd->obd_ctxt, NULL);
        
	rc = llog_create(lctxt, &loghandle, logid, name);
	if (rc)
		GOTO(out_pop, rc);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
	if (rc) 
                GOTO(out_close, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
	body->lgd_logid = loghandle->lgh_id;

out_close:
	rc2 = llog_close(loghandle);
        if (!rc) 
                rc = rc2;
out_pop:
	pop_ctxt(&saved, &obd->obd_ctxt, NULL);
out:
	RETURN(rc);
}

int llog_origin_handle_next_block(struct llog_obd_ctxt *lctxt,
                                  struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
	struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct obd_run_ctxt saved;
        __u8 *buf;
        void * ptr;
        int size[] = {sizeof (*body),
                      LLOG_CHUNK_SIZE};
	int rc, rc2;
	ENTRY;

	body = lustre_swab_reqbuf(req, 0, sizeof(*body),
				  lustre_swab_llogd_body);
	if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                GOTO(out, rc =-EFAULT);
	}

        OBD_ALLOC(buf, LLOG_CHUNK_SIZE);
        if (!buf)
                GOTO(out, rc = -ENOMEM);

	push_ctxt(&saved, &obd->obd_ctxt, NULL);
	rc = llog_create(lctxt, &loghandle, &body->lgd_logid, NULL);
	if (rc)
		GOTO(out_pop, rc);

	rc = llog_init_handle(loghandle, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	memset(buf, 0, LLOG_CHUNK_SIZE);
	rc = llog_next_block(loghandle, &body->lgd_saved_index, 
                             body->lgd_index, 
			     &body->lgd_cur_offset, buf, LLOG_CHUNK_SIZE);
	if (rc)
		GOTO(out_close, rc);


        rc = lustre_pack_msg(2, size, NULL, &req->rq_replen, &req->rq_repmsg);
	if (rc) 
                GOTO(out_close, rc = -ENOMEM);

        ptr = lustre_msg_buf(req->rq_repmsg, 0, sizeof (body));
	memcpy(ptr, body, sizeof(*body));

        ptr = lustre_msg_buf(req->rq_repmsg, 1, LLOG_CHUNK_SIZE);
	memcpy(ptr, buf, LLOG_CHUNK_SIZE);

out_close:
	rc2 = llog_close(loghandle);
	if (!rc)
                rc = rc2;

out_pop:
	pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        OBD_FREE(buf, LLOG_CHUNK_SIZE);
out:
	RETURN(rc);
}

int llog_origin_handle_read_header(struct llog_obd_ctxt *lctxt,
                                   struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
	struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct llog_log_hdr *hdr;
        struct obd_run_ctxt saved;
        __u8 *buf;
        int size[] = {sizeof (*hdr)};
	int rc, rc2;
	ENTRY;

	body = lustre_swab_reqbuf(req, 0, sizeof(*body),
				  lustre_swab_llogd_body);
	if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                GOTO(out, rc =-EFAULT);
	}

        OBD_ALLOC(buf, LLOG_CHUNK_SIZE);
        if (!buf)
                GOTO(out, rc = -ENOMEM);

	push_ctxt(&saved, &obd->obd_ctxt, NULL);
	rc = llog_create(lctxt, &loghandle, &body->lgd_logid, NULL);
	if (rc)
		GOTO(out_pop, rc);

        /* init_handle reads the header */
	rc = llog_init_handle(loghandle, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);


        rc = lustre_pack_msg(1, size, NULL, &req->rq_replen, &req->rq_repmsg);
	if (rc) 
                GOTO(out_close, rc = -ENOMEM);

        hdr = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*hdr));
	memcpy(hdr, loghandle->lgh_hdr, sizeof(*hdr));

out_close:
	rc2 = llog_close(loghandle);
	if (!rc)
                rc = rc2;

out_pop:
	pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        OBD_FREE(buf, LLOG_CHUNK_SIZE);

out:
	RETURN(rc);
}

int llog_origin_handle_close(struct llog_obd_ctxt *lctxt, 
                             struct ptlrpc_request *req)
{
	int rc;

        rc = 0;

	RETURN(rc);
}


/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
int llog_client_create(struct llog_obd_ctxt *ctxt, struct llog_handle **res,
                            struct llog_logid *logid, char *name)
{
        struct obd_device *obd = ctxt->loc_obd;
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
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

        handle = llog_alloc_handle();
        if (handle == NULL)
                RETURN(-ENOMEM);
        *res = handle;

        memset(&req_body, 0, sizeof(req_body));
        if (logid) 
                req_body.lgd_logid = *logid;
        
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
        handle->lgh_obd = obd;
        handle->lgh_ctxt = ctxt;

out:
        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);

err_free:
        llog_free_handle(handle);
        goto out;
}


struct obd_import *llog_lgh2imp(struct llog_handle *lgh) 
{
        struct client_obd *cli = &lgh->lgh_obd->u.cli;
        return cli->cl_import;
}

int llog_client_next_block(struct llog_handle *loghandle, 
                                         int *cur_idx, int next_idx,
                                         __u64 *cur_offset, void *buf, int len)
{
        struct obd_import *imp = llog_lgh2imp(loghandle);
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


int llog_client_read_header(struct llog_handle *handle)
{
        struct obd_import *imp = llog_lgh2imp(handle);
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

int llog_client_close(struct llog_handle *handle)
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
