/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ptlrpc/llog_server.c
 *
 * remote api for llog - server side
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <obd_class.h>
#include <lu_target.h>
#include <lustre_log.h>
#include <lustre_net.h>

static int llog_origin_close(const struct lu_env *env, struct llog_handle *lgh)
{
	if (lgh->lgh_hdr != NULL && lgh->lgh_hdr->llh_flags & LLOG_F_IS_CAT)
		return llog_cat_close(env, lgh);
	else
		return llog_close(env, lgh);
}

/* Only open is supported, no new llog can be created remotely */
int llog_origin_handle_open(struct ptlrpc_request *req)
{
	struct obd_export	*exp = req->rq_export;
	struct obd_device	*obd = exp->exp_obd;
	struct llog_handle	*loghandle;
	struct llogd_body	*body;
	struct llog_logid	*logid = NULL;
	struct llog_ctxt	*ctxt;
	char			*name = NULL;
	int			 rc;

	ENTRY;

	body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
	if (body == NULL)
		RETURN(err_serious(-EFAULT));

	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc)
		RETURN(err_serious(-ENOMEM));

	if (ostid_id(&body->lgd_logid.lgl_oi) > 0)
		logid = &body->lgd_logid;

	if (req_capsule_field_present(&req->rq_pill, &RMF_NAME, RCL_CLIENT)) {
		name = req_capsule_client_get(&req->rq_pill, &RMF_NAME);
		if (name == NULL)
			RETURN(-EFAULT);
		CDEBUG(D_INFO, "%s: opening log %s\n", obd->obd_name, name);
	}

	if (body->lgd_ctxt_idx >= LLOG_MAX_CTXTS) {
		CDEBUG(D_WARNING, "%s: bad ctxt ID: idx=%d name=%s\n",
		       obd->obd_name, body->lgd_ctxt_idx, name);
		RETURN(-EPROTO);
	}

	ctxt = llog_get_context(obd, body->lgd_ctxt_idx);
	if (ctxt == NULL) {
		CDEBUG(D_WARNING, "%s: no ctxt. group=%p idx=%d name=%s\n",
		       obd->obd_name, &obd->obd_olg, body->lgd_ctxt_idx, name);
		RETURN(-ENODEV);
	}

	rc = llog_open(req->rq_svc_thread->t_env, ctxt, &loghandle, logid,
		       name, LLOG_OPEN_EXISTS);
	if (rc)
		GOTO(out_ctxt, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_LLOGD_BODY);
	body->lgd_logid = loghandle->lgh_id;

	llog_origin_close(req->rq_svc_thread->t_env, loghandle);
	EXIT;
out_ctxt:
	llog_ctxt_put(ctxt);
	return rc;
}

int llog_origin_handle_destroy(struct ptlrpc_request *req)
{
	struct llogd_body	*body;
	struct llog_logid	*logid = NULL;
	struct llog_ctxt	*ctxt;
	int			 rc;

	ENTRY;

	body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
	if (body == NULL)
		RETURN(err_serious(-EFAULT));

	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc < 0)
		RETURN(err_serious(-ENOMEM));

	if (ostid_id(&body->lgd_logid.lgl_oi) > 0)
		logid = &body->lgd_logid;

	if (!(body->lgd_llh_flags & LLOG_F_IS_PLAIN))
		CERROR("%s: wrong llog flags %x\n",
		       req->rq_export->exp_obd->obd_name, body->lgd_llh_flags);

	if (body->lgd_ctxt_idx >= LLOG_MAX_CTXTS) {
		CDEBUG(D_WARNING, "%s: bad ctxt ID: idx=%d\n",
		       req->rq_export->exp_obd->obd_name, body->lgd_ctxt_idx);
		RETURN(-EPROTO);
	}

	ctxt = llog_get_context(req->rq_export->exp_obd, body->lgd_ctxt_idx);
	if (ctxt == NULL)
		RETURN(-ENODEV);

	rc = llog_erase(req->rq_svc_thread->t_env, ctxt, logid, NULL);
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

int llog_origin_handle_next_block(struct ptlrpc_request *req)
{
	struct llog_handle	*loghandle;
	struct llogd_body	*body;
	struct llogd_body	*repbody;
	struct llog_ctxt	*ctxt;
	__u32			 flags;
	void			*ptr;
	int			 rc;

	ENTRY;

	body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
	if (body == NULL)
		RETURN(err_serious(-EFAULT));

	req_capsule_set_size(&req->rq_pill, &RMF_EADATA, RCL_SERVER,
			     LLOG_MIN_CHUNK_SIZE);
	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc)
		RETURN(err_serious(-ENOMEM));

	if (body->lgd_ctxt_idx >= LLOG_MAX_CTXTS) {
		CDEBUG(D_WARNING, "%s: bad ctxt ID: idx=%d\n",
		       req->rq_export->exp_obd->obd_name, body->lgd_ctxt_idx);
		RETURN(-EPROTO);
	}

	ctxt = llog_get_context(req->rq_export->exp_obd, body->lgd_ctxt_idx);
	if (ctxt == NULL)
		RETURN(-ENODEV);

	rc = llog_open(req->rq_svc_thread->t_env, ctxt, &loghandle,
		       &body->lgd_logid, NULL, LLOG_OPEN_EXISTS);
	if (rc)
		GOTO(out_ctxt, rc);

	flags = body->lgd_llh_flags;
	rc = llog_init_handle(req->rq_svc_thread->t_env, loghandle, flags,
			      NULL);
	if (rc)
		GOTO(out_close, rc);

	repbody = req_capsule_server_get(&req->rq_pill, &RMF_LLOGD_BODY);
	*repbody = *body;

	ptr = req_capsule_server_get(&req->rq_pill, &RMF_EADATA);
	rc = llog_next_block(req->rq_svc_thread->t_env, loghandle,
			     &repbody->lgd_saved_index, repbody->lgd_index,
			     &repbody->lgd_cur_offset, ptr,
			     LLOG_MIN_CHUNK_SIZE);
	if (rc)
		GOTO(out_close, rc);
	EXIT;
out_close:
	llog_origin_close(req->rq_svc_thread->t_env, loghandle);
out_ctxt:
	llog_ctxt_put(ctxt);
	return rc;
}

int llog_origin_handle_prev_block(struct ptlrpc_request *req)
{
	struct llog_handle	*loghandle;
	struct llogd_body	*body;
	struct llogd_body	*repbody;
	struct llog_ctxt	*ctxt;
	__u32			 flags;
	void			*ptr;
	int			 rc;

	ENTRY;

	body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
	if (body == NULL)
		RETURN(err_serious(-EFAULT));

	req_capsule_set_size(&req->rq_pill, &RMF_EADATA, RCL_SERVER,
			     LLOG_MIN_CHUNK_SIZE);
	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc)
		RETURN(err_serious(-ENOMEM));

	if (body->lgd_ctxt_idx >= LLOG_MAX_CTXTS) {
		CDEBUG(D_WARNING, "%s: bad ctxt ID: idx=%d\n",
		       req->rq_export->exp_obd->obd_name, body->lgd_ctxt_idx);
		RETURN(-EPROTO);
	}

	ctxt = llog_get_context(req->rq_export->exp_obd, body->lgd_ctxt_idx);
	if (ctxt == NULL)
		RETURN(-ENODEV);

	rc = llog_open(req->rq_svc_thread->t_env, ctxt, &loghandle,
			 &body->lgd_logid, NULL, LLOG_OPEN_EXISTS);
	if (rc)
		GOTO(out_ctxt, rc);

	flags = body->lgd_llh_flags;
	rc = llog_init_handle(req->rq_svc_thread->t_env, loghandle, flags,
			      NULL);
	if (rc)
		GOTO(out_close, rc);

	repbody = req_capsule_server_get(&req->rq_pill, &RMF_LLOGD_BODY);
	*repbody = *body;

	ptr = req_capsule_server_get(&req->rq_pill, &RMF_EADATA);
	rc = llog_prev_block(req->rq_svc_thread->t_env, loghandle,
			     body->lgd_index, ptr, LLOG_MIN_CHUNK_SIZE);
	if (rc)
		GOTO(out_close, rc);

	EXIT;
out_close:
	llog_origin_close(req->rq_svc_thread->t_env, loghandle);
out_ctxt:
	llog_ctxt_put(ctxt);
	return rc;
}

int llog_origin_handle_read_header(struct ptlrpc_request *req)
{
	struct llog_handle	*loghandle;
	struct llogd_body	*body;
	struct llog_log_hdr	*hdr;
	struct llog_ctxt	*ctxt;
	__u32			 flags;
	int			 rc;

	ENTRY;

	body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_BODY);
	if (body == NULL)
		RETURN(err_serious(-EFAULT));

	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc)
		RETURN(err_serious(-ENOMEM));

	if (body->lgd_ctxt_idx >= LLOG_MAX_CTXTS) {
		CDEBUG(D_WARNING, "%s: bad ctxt ID: idx=%d\n",
		       req->rq_export->exp_obd->obd_name, body->lgd_ctxt_idx);
		RETURN(-EPROTO);
	}

	ctxt = llog_get_context(req->rq_export->exp_obd, body->lgd_ctxt_idx);
	if (ctxt == NULL)
		RETURN(-ENODEV);

	rc = llog_open(req->rq_svc_thread->t_env, ctxt, &loghandle,
		       &body->lgd_logid, NULL, LLOG_OPEN_EXISTS);
	if (rc)
		GOTO(out_ctxt, rc);

	/*
	 * llog_init_handle() reads the llog header
	 */
	flags = body->lgd_llh_flags;
	rc = llog_init_handle(req->rq_svc_thread->t_env, loghandle, flags,
			      NULL);
	if (rc)
		GOTO(out_close, rc);
	flags = loghandle->lgh_hdr->llh_flags;

	hdr = req_capsule_server_get(&req->rq_pill, &RMF_LLOG_LOG_HDR);
	*hdr = *loghandle->lgh_hdr;
	EXIT;
out_close:
	llog_origin_close(req->rq_svc_thread->t_env, loghandle);
out_ctxt:
	llog_ctxt_put(ctxt);
	return rc;
}

int llog_origin_handle_close(struct ptlrpc_request *req)
{
	int	 rc;

	ENTRY;

	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc)
		RETURN(err_serious(-ENOMEM));
	RETURN(0);
}
