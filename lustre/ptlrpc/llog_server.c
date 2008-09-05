/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
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

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#ifndef __KERNEL__
#include <liblustre.h>
#endif

#include <obd_class.h>
#include <lustre_log.h>
#include <lustre_net.h>
#include <libcfs/list.h>
#include <lustre_fsfilt.h>

#if defined(__KERNEL__) && defined(LUSTRE_LOG_SERVER)

int llog_origin_handle_create(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct obd_device *disk_obd;
        struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct lvfs_run_ctxt saved;
        struct llog_logid *logid = NULL;
        struct llog_ctxt *ctxt;
        char * name = NULL;
        int size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int rc, rc2;
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                 lustre_swab_llogd_body);
        if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                RETURN(-EFAULT);
        }

        if (body->lgd_logid.lgl_oid > 0)
                logid = &body->lgd_logid;

        if (lustre_msg_bufcount(req->rq_reqmsg) > 2) {
                name = lustre_msg_string(req->rq_reqmsg, REQ_REC_OFF + 1, 0);
                if (name == NULL) {
                        CERROR("Can't unpack name\n");
                        RETURN(-EFAULT);
                }
                CDEBUG(D_INFO, "opening log %s\n", name);
        }

        ctxt = llog_get_context(obd, body->lgd_ctxt_idx);
        if (ctxt == NULL)
                RETURN(-EINVAL);
        disk_obd = ctxt->loc_exp->exp_obd;
        push_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(ctxt, &loghandle, logid, name);
        if (rc)
                GOTO(out_pop, rc);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out_close, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*body));
        body->lgd_logid = loghandle->lgh_id;

out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;
out_pop:
        pop_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

int llog_origin_handle_destroy(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct obd_device *disk_obd;
        struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct lvfs_run_ctxt saved;
        struct llog_logid *logid = NULL;
        struct llog_ctxt *ctxt;
        int size[] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int rc;
        __u32 flags;
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                 lustre_swab_llogd_body);
        if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                RETURN(-EFAULT);
        }

        if (body->lgd_logid.lgl_oid > 0)
                logid = &body->lgd_logid;

        ctxt = llog_get_context(obd, body->lgd_ctxt_idx);
        if (ctxt == NULL)
                RETURN(-EINVAL);

        disk_obd = ctxt->loc_exp->exp_obd;
        push_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(ctxt, &loghandle, logid, NULL);
        if (rc)
                GOTO(out_pop, rc);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out_close, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof (*body));
        body->lgd_logid = loghandle->lgh_id;
        flags = body->lgd_llh_flags;
        rc = llog_init_handle(loghandle, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out_close, rc);
        rc = llog_destroy(loghandle);
        if (rc)
                GOTO(out_close, rc);
        llog_free_handle(loghandle);

out_close:
        if (rc)
                llog_close(loghandle);
out_pop:
        pop_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

int llog_origin_handle_next_block(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct obd_device *disk_obd;
        struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        __u32 flags;
        __u8 *buf;
        void * ptr;
        int size[3] = { sizeof(struct ptlrpc_body),
                        sizeof(*body),
                        LLOG_CHUNK_SIZE };
        int rc, rc2;
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_llogd_body);
        if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                RETURN(-EFAULT);
        }

        OBD_ALLOC(buf, LLOG_CHUNK_SIZE);
        if (!buf)
                RETURN(-ENOMEM);

        ctxt = llog_get_context(obd, body->lgd_ctxt_idx);
        if (ctxt == NULL)
                GOTO(out_free, rc = -EINVAL);
        disk_obd = ctxt->loc_exp->exp_obd;
        push_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);

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


        rc = lustre_pack_reply(req, 3, size, NULL);
        if (rc)
                GOTO(out_close, rc = -ENOMEM);

        ptr = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof (body));
        memcpy(ptr, body, sizeof(*body));

        ptr = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF+1, LLOG_CHUNK_SIZE);
        memcpy(ptr, buf, LLOG_CHUNK_SIZE);

out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;

out_pop:
        pop_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        llog_ctxt_put(ctxt);
out_free:
        OBD_FREE(buf, LLOG_CHUNK_SIZE);
        RETURN(rc);
}

int llog_origin_handle_prev_block(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct llog_handle  *loghandle;
        struct llogd_body *body;
        struct obd_device *disk_obd;
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        __u32 flags;
        __u8 *buf;
        void * ptr;
        int size[] = { sizeof(struct ptlrpc_body),
                       sizeof(*body),
                       LLOG_CHUNK_SIZE };
        int rc, rc2;
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_llogd_body);
        if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                RETURN(-EFAULT);
        }

        OBD_ALLOC(buf, LLOG_CHUNK_SIZE);
        if (!buf)
                RETURN(-ENOMEM);

        ctxt = llog_get_context(obd, body->lgd_ctxt_idx);
        LASSERT(ctxt != NULL);
        disk_obd = ctxt->loc_exp->exp_obd;
        push_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(ctxt, &loghandle, &body->lgd_logid, NULL);
        if (rc)
                GOTO(out_pop, rc);

        flags = body->lgd_llh_flags;
        rc = llog_init_handle(loghandle, flags, NULL);
        if (rc)
                GOTO(out_close, rc);

        memset(buf, 0, LLOG_CHUNK_SIZE);
        rc = llog_prev_block(loghandle, body->lgd_index,
                             buf, LLOG_CHUNK_SIZE);
        if (rc)
                GOTO(out_close, rc);

        rc = lustre_pack_reply(req, 3, size, NULL);
        if (rc)
                GOTO(out_close, rc = -ENOMEM);

        ptr = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(body));
        memcpy(ptr, body, sizeof(*body));

        ptr = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF+1, LLOG_CHUNK_SIZE);
        memcpy(ptr, buf, LLOG_CHUNK_SIZE);

out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;

out_pop:
        pop_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        llog_ctxt_put(ctxt);
        OBD_FREE(buf, LLOG_CHUNK_SIZE);
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
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        __u32 flags;
        int size[2] = { sizeof(struct ptlrpc_body), sizeof(*hdr) };
        int rc, rc2;
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_llogd_body);
        if (body == NULL) {
                CERROR ("Can't unpack llogd_body\n");
                RETURN(-EFAULT);
        }

        ctxt = llog_get_context(obd, body->lgd_ctxt_idx);
        if (ctxt == NULL)
                RETURN(-EINVAL);
        disk_obd = ctxt->loc_exp->exp_obd;
        push_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(ctxt, &loghandle, &body->lgd_logid, NULL);
        if (rc)
                GOTO(out_pop, rc);

        /* init_handle reads the header */
        flags = body->lgd_llh_flags;
        rc = llog_init_handle(loghandle, flags, NULL);
        if (rc)
                GOTO(out_close, rc);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out_close, rc = -ENOMEM);

        hdr = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*hdr));
        memcpy(hdr, loghandle->lgh_hdr, sizeof(*hdr));

out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;
out_pop:
        pop_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

int llog_origin_handle_close(struct ptlrpc_request *req)
{
        int rc;

        rc = 0;

        RETURN(rc);
}

int llog_origin_handle_cancel(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_device *disk_obd;
        struct llog_cookie *logcookies;
        struct llog_ctxt *ctxt = NULL;
        int num_cookies, rc = 0, err, i;
        struct lvfs_run_ctxt saved;
        struct llog_handle *cathandle;
        struct inode *inode;
        void *handle;
        ENTRY;

        logcookies = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF,
                                    sizeof(*logcookies));
        num_cookies = lustre_msg_buflen(req->rq_reqmsg, REQ_REC_OFF) /
                      sizeof(*logcookies);
        if (logcookies == NULL || num_cookies == 0) {
                DEBUG_REQ(D_HA, req, "no cookies sent");
                RETURN(-EFAULT);
        }

        ctxt = llog_get_context(obd, logcookies->lgc_subsys);
        if (ctxt == NULL) {
                CWARN("llog subsys not setup or already cleanup\n");
                RETURN(-ENOENT);
        }

        disk_obd = ctxt->loc_exp->exp_obd;
        push_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        for (i = 0; i < num_cookies; i++, logcookies++) {
                cathandle = ctxt->loc_handle;
                LASSERT(cathandle != NULL);
                inode = cathandle->lgh_file->f_dentry->d_inode;

                handle = fsfilt_start_log(disk_obd, inode,
                                          FSFILT_OP_CANCEL_UNLINK, NULL, 1);
                if (IS_ERR(handle)) {
                        CERROR("fsfilt_start failed: %ld\n", PTR_ERR(handle));
                        GOTO(pop_ctxt, rc = PTR_ERR(handle));
                }

                rc = llog_cat_cancel_records(cathandle, 1, logcookies);

                err = fsfilt_commit(disk_obd, inode, handle, 0);
                if (err) {
                        CERROR("error committing transaction: %d\n", err);
                        if (!rc)
                                rc = err;
                        GOTO(pop_ctxt, rc);
                }
        }
pop_ctxt:
        pop_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        if (rc)
                CERROR("cancel %d llog-records failed: %d\n", num_cookies, rc);
        else
                CDEBUG(D_RPCTRACE, "cancel %d llog-records\n", num_cookies);

        llog_ctxt_put(ctxt);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_origin_handle_cancel);

static int llog_catinfo_config(struct obd_device *obd, char *buf, int buf_len,
                               char *client)
{
        struct mds_obd *mds = &obd->u.mds;
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
        struct lvfs_run_ctxt saved;
        struct llog_handle *handle = NULL;
        char name[4][64];
        int rc, i, l, remains = buf_len;
        char *out = buf;

        if (ctxt == NULL || mds == NULL)
                GOTO(release_ctxt, rc = -EOPNOTSUPP);

        push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);

        sprintf(name[0], "%s", mds->mds_profile);
        sprintf(name[1], "%s-clean", mds->mds_profile);
        sprintf(name[2], "%s", client);
        sprintf(name[3], "%s-clean", client);

        for (i = 0; i < 4; i++) {
                int index, uncanceled = 0;
                rc = llog_create(ctxt, &handle, NULL, name[i]);
                if (rc)
                        GOTO(out_pop, rc);
                rc = llog_init_handle(handle, 0, NULL);
                if (rc) {
                        llog_close(handle);
                        GOTO(out_pop, rc = -ENOENT);
                }

                for (index = 1; index < (LLOG_BITMAP_BYTES * 8); index ++) {
                        if (ext2_test_bit(index, handle->lgh_hdr->llh_bitmap))
                                uncanceled++;
                }

                l = snprintf(out, remains, "[Log Name]: %s\nLog Size: %llu\n"
                             "Last Index: %d\nUncanceled Records: %d\n\n",
                             name[i],
                             i_size_read(handle->lgh_file->f_dentry->d_inode),
                             handle->lgh_last_idx, uncanceled);
                out += l;
                remains -= l;

                llog_close(handle);
                if (remains <= 0)
                        break;
        }
out_pop:
        pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
release_ctxt:
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

struct cb_data {
        struct llog_ctxt *ctxt;
        char *out;
        int  remains;
        int  init;
};

static int llog_catinfo_cb(struct llog_handle *cat,
                           struct llog_rec_hdr *rec, void *data)
{
        static char *out = NULL;
        static int remains = 0;
        struct llog_ctxt *ctxt = NULL;
        struct llog_handle *handle;
        struct llog_logid *logid;
        struct llog_logid_rec *lir;
        int l, rc, index, count = 0;
        struct cb_data *cbd = (struct cb_data*)data;

        if (cbd->init) {
                out = cbd->out;
                remains = cbd->remains;
                cbd->init = 0;
        }

        if (!(cat->lgh_hdr->llh_flags & LLOG_F_IS_CAT)) 
                RETURN(-EINVAL);

        if (!cbd->ctxt)
                RETURN(-EINVAL);
        
        lir = (struct llog_logid_rec *)rec;
        logid = &lir->lid_id;
        rc = llog_create(ctxt, &handle, logid, NULL);
        if (rc)
                RETURN(-EINVAL);
        rc = llog_init_handle(handle, 0, NULL);
        if (rc)
                GOTO(out_close, rc);

        for (index = 1; index < (LLOG_BITMAP_BYTES * 8); index++) {
                if (ext2_test_bit(index, handle->lgh_hdr->llh_bitmap))
                        count++;
        }

        l = snprintf(out, remains, "\t[Log ID]: #"LPX64"#"LPX64"#%08x\n"
                     "\tLog Size: %llu\n\tLast Index: %d\n"
                     "\tUncanceled Records: %d\n",
                     logid->lgl_oid, logid->lgl_ogr, logid->lgl_ogen,
                     i_size_read(handle->lgh_file->f_dentry->d_inode),
                     handle->lgh_last_idx, count);
        out += l;
        remains -= l;
        cbd->out = out;
        cbd->remains = remains;
        if (remains <= 0) {
                CWARN("Not enough memory\n");
                rc = -ENOMEM;
        }

out_close:
        llog_close(handle);
        RETURN(rc);
}

static int llog_catinfo_deletions(struct obd_device *obd, char *buf,
                                  int buf_len)
{
        struct mds_obd *mds = &obd->u.mds;
        struct llog_handle *handle;
        struct lvfs_run_ctxt saved;
        int size, i, count;
        struct llog_catid *idarray;
        char name[32] = CATLIST;
        int rc;
        struct cb_data data;
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);

        if (ctxt == NULL || mds == NULL)
                GOTO(release_ctxt, rc = -EOPNOTSUPP);
       
        count = mds->mds_lov_desc.ld_tgt_count;
        size = sizeof(*idarray) * count;

        OBD_VMALLOC(idarray, size);
        if (!idarray)
                GOTO(release_ctxt, rc = -ENOMEM);

        rc = llog_get_cat_list(obd, obd, name, 0, count, idarray);
        if (rc)
                GOTO(out_free, rc);

        push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);

        data.ctxt = ctxt;
        data.out = buf;
        data.remains = buf_len;
        for (i = 0; i < count; i++) {
                int l, index, uncanceled = 0;

                rc = llog_create(ctxt, &handle, &idarray[i].lci_logid, NULL);
                if (rc)
                        GOTO(out_pop, rc);
                rc = llog_init_handle(handle, 0, NULL);
                if (rc) {
                        llog_close(handle);
                        GOTO(out_pop, rc = -ENOENT);
                }
                for (index = 1; index < (LLOG_BITMAP_BYTES * 8); index++) {
                        if (ext2_test_bit(index, handle->lgh_hdr->llh_bitmap))
                                uncanceled++;
                }
                l = snprintf(data.out, data.remains,
                             "\n[Catlog ID]: #"LPX64"#"LPX64"#%08x  "
                             "[Log Count]: %d\n",
                             idarray[i].lci_logid.lgl_oid,
                             idarray[i].lci_logid.lgl_ogr,
                             idarray[i].lci_logid.lgl_ogen, uncanceled);

                data.out += l;
                data.remains -= l;
                data.init = 1;

                llog_process(handle, llog_catinfo_cb, &data, NULL);
                llog_close(handle);

                if (data.remains <= 0)
                        break;
        }
out_pop:
        pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
out_free:
        OBD_VFREE(idarray, size);
release_ctxt:
        llog_ctxt_put(ctxt);

        RETURN(rc);
}

int llog_catinfo(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        char *keyword;
        char *buf, *reply;
        int rc, buf_len = LLOG_CHUNK_SIZE;
        int size[2] = { sizeof(struct ptlrpc_body), buf_len };

        OBD_ALLOC(buf, buf_len);
        if (buf == NULL)
                return -ENOMEM;
        memset(buf, 0, buf_len);

        keyword = lustre_msg_string(req->rq_reqmsg, REQ_REC_OFF, 0);

        if (strcmp(keyword, "config") == 0) {
                char *client = lustre_msg_string(req->rq_reqmsg,
                                                 REQ_REC_OFF + 1, 0);
                rc = llog_catinfo_config(obd, buf, buf_len, client);
        } else if (strcmp(keyword, "deletions") == 0) {
                rc = llog_catinfo_deletions(obd, buf, buf_len);
        } else {
                rc = -EOPNOTSUPP;
        }

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out_free, rc = -ENOMEM);

        reply = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, buf_len);
        if (strlen(buf) == 0)
                sprintf(buf, "%s", "No log informations\n");
        memcpy(reply, buf, buf_len);

out_free:
        OBD_FREE(buf, buf_len);
        return rc;
}

#else /* !__KERNEL__ */
int llog_origin_handle_create(struct ptlrpc_request *req)
{
        LBUG();
        return 0;
}

int llog_origin_handle_destroy(struct ptlrpc_request *req)
{
        LBUG();
        return 0;
}

int llog_origin_handle_next_block(struct ptlrpc_request *req)
{
        LBUG();
        return 0;
}
int llog_origin_handle_prev_block(struct ptlrpc_request *req)
{
        LBUG();
        return 0;
}
int llog_origin_handle_read_header(struct ptlrpc_request *req)
{
        LBUG();
        return 0;
}
int llog_origin_handle_close(struct ptlrpc_request *req)
{
        LBUG();
        return 0;
}
int llog_origin_handle_cancel(struct ptlrpc_request *req)
{
        LBUG();
        return 0;
}
#endif
