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
 * remote api for llog
 *
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
#include <linux/lustre_net.h>
#include <portals/list.h>

#ifdef __KERNEL__

int llogd_init(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
	struct llog_handle  *loghandle;
        struct llog_desc desc;
        struct obd_run_ctxt saved;
        void * ptr;
	char * name;
        int size[] = {sizeof (desc), 
                      LLOG_BITMAP_BYTES};
	int rc, rc2;
	ENTRY;

        LASSERT(obd->obd_log_exp == NULL);

	name = lustre_msg_string(req->rq_reqmsg, 0, 0);
        if (name == NULL) {
                CERROR("Can't unpack name\n");
                GOTO(out, rc = -EFAULT);
        }

	memset(&desc, 0, sizeof(desc));
	
	push_ctxt(&saved, &obd->obd_ctxt, NULL);
        obd->obd_log_exp = class_export_get(exp);
        
	rc = llog_create(obd, &loghandle, NULL, name);
	if (rc)
		GOTO(out_pop, rc);
	desc.lgd_logid = loghandle->lgh_id;
        desc.lgd_cur_offset = LLOG_CHUNK_SIZE; /* skip header block */

	rc = llog_init_handle(loghandle, LLOG_F_IS_PLAIN, 
			      NULL);
	if (rc)
		GOTO(out_close, rc);

        rc = lustre_pack_reply(req, 2, size, NULL);
	if (rc) 
                GOTO(out_close, rc = -ENOMEM);

        ptr = lustre_msg_buf(req->rq_repmsg, 0, sizeof (desc));
	memcpy(ptr, &desc, sizeof(desc));

        ptr = lustre_msg_buf(req->rq_repmsg, 1, LLOG_BITMAP_BYTES);
        memcpy(ptr, loghandle->lgh_hdr->llh_bitmap, LLOG_BITMAP_BYTES);

out_close:
	rc2 = llog_close(loghandle);
        class_export_put(obd->obd_log_exp);
        obd->obd_log_exp = NULL;
        if (!rc) 
                rc = rc2;
out_pop:
	pop_ctxt(&saved, &obd->obd_ctxt, NULL);
out:
	RETURN(rc);
}

int llogd_next_block(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
	struct llog_handle  *loghandle;
        struct llog_desc *desc;
        struct obd_run_ctxt saved;
        __u8 *buf;
        void * ptr;
        int size[] = {sizeof (*desc),
                      LLOG_CHUNK_SIZE};
	int rc, rc2;
	ENTRY;

        LASSERT(obd->obd_log_exp == NULL);

	desc = lustre_swab_reqbuf(req, 0, sizeof(*desc),
				  lustre_swab_llog_desc);
	if (desc == NULL) {
                CERROR ("Can't unpack llog_desc\n");
                GOTO(out, rc =-EFAULT);
	}

        OBD_ALLOC(buf, LLOG_CHUNK_SIZE);
        if (!buf)
                GOTO(out, rc = -ENOMEM);

	push_ctxt(&saved, &obd->obd_ctxt, NULL);
        obd->obd_log_exp = class_export_get(exp);

	rc = llog_create(obd, &loghandle, &desc->lgd_logid, NULL);
	if (rc)
		GOTO(out_pop, rc);

	rc = llog_init_handle(loghandle, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	memset(buf, 0, LLOG_CHUNK_SIZE);
	rc = llog_next_block(loghandle, &desc->lgd_saved_index, 
                             desc->lgd_index, 
			     &desc->lgd_cur_offset, buf, LLOG_CHUNK_SIZE);
	if (rc)
		GOTO(out_close, rc);


        rc = lustre_pack_reply(req, 2, size, NULL);
	if (rc) 
                GOTO(out_close, rc = -ENOMEM);

        ptr = lustre_msg_buf(req->rq_repmsg, 0, sizeof (desc));
	memcpy(ptr, desc, sizeof(*desc));

        ptr = lustre_msg_buf(req->rq_repmsg, 1, LLOG_CHUNK_SIZE);
	memcpy(ptr, buf, LLOG_CHUNK_SIZE);

out_close:
	rc2 = llog_close(loghandle);
        class_export_put(obd->obd_log_exp);
        obd->obd_log_exp = NULL;
	if (!rc)
                rc = rc2;

out_pop:
	pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        OBD_FREE(buf, LLOG_CHUNK_SIZE);
out:
	RETURN(rc);
}

int llogd_close(struct ptlrpc_request *req)
{
	int rc;

        rc = 0;

	RETURN(rc);
}


int llogd_client_init(struct obd_export *exp, char * logname, 
                      struct llog_desc **desc, __u32 **bitmap)
{
        struct obd_import *imp = class_exp2cliimp(exp);
        struct ptlrpc_request *req = NULL;
        void * ptr;
        int size;
        int repsize[] = {sizeof (**desc),
                         LLOG_BITMAP_BYTES};
        int rc;
        ENTRY;

        LASSERT(*desc == NULL);
        LASSERT(*bitmap == NULL);
        
        size = strlen(logname) + 1;
        req = ptlrpc_prep_req(imp, LLOG_INIT, 1, &size, &logname);
        if (!req)
                GOTO(out, rc = -ENOMEM);
        
        req->rq_replen = lustre_msg_size(2, repsize);
        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);
        
        OBD_ALLOC(*desc, sizeof (**desc));
        if (*desc == NULL)
                GOTO(out, rc = -ENOMEM);

        OBD_ALLOC(*bitmap, LLOG_BITMAP_BYTES);
        if (*bitmap == NULL)
                GOTO(err_free, rc = -ENOMEM);


	ptr = lustre_swab_repbuf(req, 0, sizeof(**desc),
                                 lustre_swab_llog_desc);
	if (ptr == NULL) {
                CERROR ("Can't unpack llog_desc\n");
                GOTO(err_free, rc =-EFAULT);
	}
        memcpy(*desc, ptr, sizeof(**desc));
        
        ptr = lustre_msg_buf(req->rq_repmsg, 1, LLOG_BITMAP_BYTES);
	if (ptr == NULL) {
                CERROR ("Can't unpack bitmap\n");
                GOTO(err_free, rc =-EFAULT);
	}
        memcpy(*bitmap, ptr, LLOG_BITMAP_BYTES);

out:
        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);

err_free:
        if (*bitmap)
                OBD_FREE(*bitmap, LLOG_BITMAP_BYTES);
        if (*desc)
                OBD_FREE(*desc, sizeof (**desc));
        goto out;
}

int llogd_client_next_block(struct obd_export *exp, struct llog_desc *desc, 
                            char * buf, int buf_size)
{
        struct obd_import *imp = class_exp2cliimp(exp);
        struct ptlrpc_request *req = NULL;
        void * ptr;
        int size = sizeof(*desc);
        int repsize[] = {sizeof (*desc),
                         LLOG_CHUNK_SIZE};
        int rc;
        ENTRY;

        LASSERT (buf_size == LLOG_CHUNK_SIZE);
        
        req = ptlrpc_prep_req(imp, LLOG_NEXT_BLOCK, 1, &size, (char **) &desc);
        if (!req)
                GOTO(out, rc = -ENOMEM);
        
        req->rq_replen = lustre_msg_size(2, repsize);
        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);
        
	ptr = lustre_swab_repbuf(req, 0, sizeof(*desc),
                                 lustre_swab_llog_desc);
	if (ptr == NULL) {
                CERROR ("Can't unpack llog_desc\n");
                GOTO(out, rc =-EFAULT);
	}
        memcpy(desc, ptr, sizeof(*desc));
        
        ptr = lustre_msg_buf(req->rq_repmsg, 1, LLOG_CHUNK_SIZE);
	if (ptr == NULL) {
                CERROR ("Can't unpack bitmap\n");
                GOTO(out, rc =-EFAULT);
	}
        memcpy(buf, ptr, buf_size);

out:
        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}


int llogd_client_close(struct obd_export *exp, struct llog_desc **desc, 
                       __u32 **bitmap)
{
        OBD_FREE(*desc, sizeof (**desc));
        OBD_FREE(*bitmap, LLOG_BITMAP_BYTES);
        RETURN(0);
}

#else /* !__KERNEL__ */

int llogd_client_init(struct obd_export *exp, char * logname, 
                      struct llog_desc **desc, __u32 **bitmap)
{
        return 0;
}
int llogd_client_close(struct obd_export *exp, struct llog_desc **desc, 
                       __u32 **bitmap)
{
        return 0;
}
int llogd_client_next_block(struct obd_export *exp, struct llog_desc *desc, 
                            char * buf, int buf_size)
{
        return 0;
}

#endif
