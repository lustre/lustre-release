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
 *  remote api for llog - server side
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

int llog_origin_handle_create(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct obd_device *disk_obd;
        struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct obd_run_ctxt saved;
        struct llog_logid *logid = NULL;
        struct llog_ctxt *ctxt;
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

        ctxt = llog_get_context(obd, body->lgd_ctxt_idx);
        LASSERT(ctxt != NULL);
        disk_obd = ctxt->loc_exp->exp_obd;
        push_ctxt(&saved, &disk_obd->obd_ctxt, NULL);

        rc = llog_create(ctxt, &loghandle, logid, name);
        if (rc)
                GOTO(out_pop, rc);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                GOTO(out_close, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        body->lgd_logid = loghandle->lgh_id;

out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;
out_pop:
        pop_ctxt(&saved, &disk_obd->obd_ctxt, NULL);
out:
        RETURN(rc);
}

int llog_origin_handle_next_block(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct obd_device *disk_obd;
        struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct obd_run_ctxt saved;
        struct llog_ctxt *ctxt;
        __u32 flags;
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

        ctxt = llog_get_context(obd, body->lgd_ctxt_idx);
        LASSERT(ctxt != NULL);
        disk_obd = ctxt->loc_exp->exp_obd;
        push_ctxt(&saved, &disk_obd->obd_ctxt, NULL);

        rc = llog_create(ctxt, &loghandle, &body->lgd_logid, NULL);
        if (rc)
                GOTO(out_pop, rc);

        flags = body->lgd_llh_flags;
        rc = llog_init_handle(loghandle, flags, NULL);
        if (rc)
                GOTO(out_close, rc);

        memset(buf, 0, LLOG_CHUNK_SIZE);
        rc = llog_next_block(loghandle, &body->lgd_saved_index,
                             body->lgd_index,
                             &body->lgd_cur_offset, buf, LLOG_CHUNK_SIZE);
        if (rc)
                GOTO(out_close, rc);


        rc = lustre_pack_reply(req, 2, size, NULL);
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
        pop_ctxt(&saved, &disk_obd->obd_ctxt, NULL);
        OBD_FREE(buf, LLOG_CHUNK_SIZE);
out:
        RETURN(rc);
}

int llog_origin_handle_read_header(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct obd_device *disk_obd;
        struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct llog_log_hdr *hdr;
        struct obd_run_ctxt saved;
        struct llog_ctxt *ctxt;
        __u32 flags;
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

        ctxt = llog_get_context(obd, body->lgd_ctxt_idx);
        LASSERT(ctxt != NULL);
        disk_obd = ctxt->loc_exp->exp_obd;
        push_ctxt(&saved, &disk_obd->obd_ctxt, NULL);

        rc = llog_create(ctxt, &loghandle, &body->lgd_logid, NULL);
        if (rc)
                GOTO(out_pop, rc);

        /* init_handle reads the header */
        flags = body->lgd_llh_flags;
        rc = llog_init_handle(loghandle, flags, NULL);
        if (rc)
                GOTO(out_close, rc);


        rc = lustre_pack_reply(req, 1, size, NULL);
        if (rc)
                GOTO(out_close, rc = -ENOMEM);

        hdr = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*hdr));
        memcpy(hdr, loghandle->lgh_hdr, sizeof(*hdr));

out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;

out_pop:
        pop_ctxt(&saved, &disk_obd->obd_ctxt, NULL);
        OBD_FREE(buf, LLOG_CHUNK_SIZE);

out:
        RETURN(rc);
}

int llog_origin_handle_close(struct ptlrpc_request *req)
{
        int rc;

        rc = 0;

        RETURN(rc);
}

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
                CWARN("llog subsys not setup or already cleanup\n");
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
                CWARN("cancel %d llog-records\n", num_cookies);

        pop_ctxt(&saved, &disk_obd->obd_ctxt, NULL);
        up(&ctxt->loc_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(llog_origin_handle_cancel);
#endif
