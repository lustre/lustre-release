/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
# include <linux/miscdevice.h>
# include <linux/init.h>
#else
# include <liblustre.h>
#endif

#include <linux/lustre_acl.h>
#include <obd_class.h>
#include <lustre_dlm.h>
#include <lustre_fid.h>
#include <md_object.h>
#include <lprocfs_status.h>
#include <lustre_param.h>
#include "mdc_internal.h"

static quota_interface_t *quota_interface;

#define REQUEST_MINOR 244

static int mdc_cleanup(struct obd_device *obd);

extern int mds_queue_req(struct ptlrpc_request *);
/* Helper that implements most of mdc_getstatus and signal_completed_replay. */
/* XXX this should become mdc_get_info("key"), sending MDS_GET_INFO RPC */
static int send_getstatus(struct obd_import *imp, struct lu_fid *rootfid,
                          int level, int msg_flags)
{
        struct ptlrpc_request *req;
        struct mdt_body *body;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        ENTRY;

        req = ptlrpc_prep_req(imp, LUSTRE_MDS_VERSION, MDS_GETSTATUS, 2, size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        req->rq_send_state = level;
        ptlrpc_req_set_repsize(req, 2, size);

        mdc_pack_req_body(req, REQ_REC_OFF, 0, NULL, 0, 0);
        lustre_msg_add_flags(req->rq_reqmsg, msg_flags);
        rc = ptlrpc_queue_wait(req);

        if (!rc) {
                body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                          lustre_swab_mdt_body);
                if (body == NULL) {
                        CERROR ("Can't extract mdt_body\n");
                        GOTO (out, rc = -EPROTO);
                }

                *rootfid = body->fid1;

                CDEBUG(D_NET, "root fid="DFID", last_committed="LPU64
                       ", last_xid="LPU64"\n",
                       PFID(rootfid),
                       lustre_msg_get_last_committed(req->rq_repmsg),
                       lustre_msg_get_last_xid(req->rq_repmsg));
        }

        EXIT;
 out:
        ptlrpc_req_finished(req);
        return rc;
}

/* This should be mdc_get_info("rootfid") */
int mdc_getstatus(struct obd_export *exp, struct lu_fid *rootfid)
{
        return send_getstatus(class_exp2cliimp(exp), rootfid,
                              LUSTRE_IMP_FULL, 0);
}

static
int mdc_getattr_common(struct obd_export *exp, unsigned int ea_size,
                       unsigned int acl_size, struct ptlrpc_request *req)
{
        struct mdt_body *body;
        void *eadata;
        int size[4] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int bufcount = 2, rc;
        ENTRY;
        
        /* request message already built */
        if (ea_size != 0) {
                size[bufcount++] = ea_size;
                CDEBUG(D_INODE, "reserved %u bytes for MD/symlink in packet\n",
                       ea_size);
        }
        if (acl_size) {
                size[bufcount++] = acl_size;
                CDEBUG(D_INODE, "reserved %u bytes for ACL\n", acl_size);
        }

        ptlrpc_req_set_repsize(req, bufcount, size);

        rc = ptlrpc_queue_wait(req);
        if (rc != 0)
                RETURN (rc);

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_mdt_body);
        if (body == NULL) {
                CERROR ("Can't unpack mdt_body\n");
                RETURN (-EPROTO);
        }

        CDEBUG(D_NET, "mode: %o\n", body->mode);

        LASSERT_REPSWAB(req, REPLY_REC_OFF + 1);
        if (body->eadatasize != 0) {
                /* reply indicates presence of eadata; check it's there... */
                eadata = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1,
                                        body->eadatasize);
                if (eadata == NULL) {
                        CERROR ("Missing/short eadata\n");
                        RETURN (-EPROTO);
                }
        }

        if (body->valid & OBD_MD_FLMODEASIZE) {
                if (exp->exp_obd->u.cli.cl_max_mds_easize < body->max_mdsize)
                        exp->exp_obd->u.cli.cl_max_mds_easize =
                                                body->max_mdsize;
                if (exp->exp_obd->u.cli.cl_max_mds_cookiesize <
                                                body->max_cookiesize)
                        exp->exp_obd->u.cli.cl_max_mds_cookiesize =
                                                body->max_cookiesize;
        }

        RETURN (0);
}

int mdc_getattr(struct obd_export *exp, const struct lu_fid *fid,
                obd_valid valid, int ea_size, struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        int size[2] = { sizeof(struct ptlrpc_body), sizeof(struct mdt_body) };
        int acl_size = 0, rc;
        ENTRY;

        /* XXX do we need to make another request here?  We just did a getattr
         *     to do the lookup in the first place.
         */
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_GETATTR, 2, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        mdc_pack_req_body(req, REQ_REC_OFF, valid, fid, ea_size,
                          MDS_BFLAG_EXT_FLAGS/*request "new" flags(bug 9486)*/);

        /* currently only root inode will call us with FLACL */

        /* FIXME:XXX:reserve enough space regardless the flag temporarily.
         * server will do lustre_shrink_reply();
         * 
         *if (valid & OBD_MD_FLACL)
         */
        acl_size = LUSTRE_POSIX_ACL_MAX_SIZE;

         
        rc = mdc_getattr_common(exp, ea_size, acl_size, req);
        if (rc != 0) {
                ptlrpc_req_finished (req);
                req = NULL;
        }
 out:
        *request = req;
        RETURN (rc);
}

int mdc_getattr_name(struct obd_export *exp, const struct lu_fid *fid,
                     const char *filename, int namelen, obd_valid valid,
                     int ea_size, struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mdt_body *body;
        int rc, size[3] = { sizeof(struct ptlrpc_body), sizeof(*body), namelen};
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_GETATTR_NAME, 3, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        mdc_pack_req_body(req, REQ_REC_OFF, valid, fid, ea_size,
                          MDS_BFLAG_EXT_FLAGS/*request "new" flags(bug 9486)*/);
 
        LASSERT(strnlen(filename, namelen) == namelen - 1);
        memcpy(lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 1, namelen),
               filename, namelen);

        rc = mdc_getattr_common(exp, ea_size, 0, req);
        if (rc != 0) {
                ptlrpc_req_finished (req);
                req = NULL;
        }
 out:
        *request = req;
        RETURN(rc);
}

static
int mdc_xattr_common(struct obd_export *exp, const struct lu_fid *fid,
                     int opcode, obd_valid valid, const char *xattr_name,
                     const char *input, int input_size, int output_size,
                     int flags, struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        int size[4] = { sizeof(struct ptlrpc_body), sizeof(struct mdt_body) };
        // int size[3] = {sizeof(struct mdt_body)}, bufcnt = 1;
        int rc, xattr_namelen = 0, bufcnt = 2, offset;
        void *tmp;
        ENTRY;

        if (xattr_name) {
                xattr_namelen = strlen(xattr_name) + 1;
                size[bufcnt++] = xattr_namelen;
        }
        if (input_size) {
                LASSERT(input);
                size[bufcnt++] = input_size;
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              opcode, bufcnt, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        /* request data */
        mdc_pack_req_body(req, REQ_REC_OFF, valid, fid, output_size, flags);

        offset = REQ_REC_OFF + 1;

        if (xattr_name) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset++, xattr_namelen);
                memcpy(tmp, xattr_name, xattr_namelen);
        }
        if (input_size) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset++, input_size);
                memcpy(tmp, input, input_size);
        }

        /* reply buffers */
        if (opcode == MDS_GETXATTR) {
                size[REPLY_REC_OFF] = sizeof(struct mdt_body);
                bufcnt = 2;
        } else {
                bufcnt = 1;
        }

        /* we do this even output_size is 0, because server is doing that */
        size[bufcnt++] = output_size;
        ptlrpc_req_set_repsize(req, bufcnt, size);

        /* make rpc */
        if (opcode == MDS_SETXATTR)
                mdc_get_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);

        rc = ptlrpc_queue_wait(req);

        if (opcode == MDS_SETXATTR)
                mdc_put_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);

        if (rc != 0)
                GOTO(err_out, rc);

        if (opcode == MDS_GETXATTR) {
                struct mdt_body * body = lustre_swab_repbuf(req, REPLY_REC_OFF,
                                          sizeof(*body), lustre_swab_mdt_body);
                if (body == NULL) {
                        CERROR ("Can't unpack mdt_body\n");
                        GOTO(err_out, rc = -EPROTO);
                }
        }
out:
        *request = req;
        RETURN (rc);
err_out:
        ptlrpc_req_finished(req);
        req = NULL;
        goto out;
}

int mdc_setxattr(struct obd_export *exp, const struct lu_fid *fid,
                 obd_valid valid, const char *xattr_name,
                 const char *input, int input_size,
                 int output_size, int flags,
                 struct ptlrpc_request **request)
{
        return mdc_xattr_common(exp, fid, MDS_SETXATTR, valid, xattr_name,
                                input, input_size, output_size, flags, request);
}

int mdc_getxattr(struct obd_export *exp, const struct lu_fid *fid,
                 obd_valid valid, const char *xattr_name,
                 const char *input, int input_size,
                 int output_size, int flags, struct ptlrpc_request **request)
{
        return mdc_xattr_common(exp, fid, MDS_GETXATTR, valid, xattr_name,
                                input, input_size, output_size, flags, request);
}

#ifdef CONFIG_FS_POSIX_ACL
static
int mdc_unpack_acl(struct obd_export *exp, struct ptlrpc_request *req,
                   struct lustre_md *md, unsigned int offset)
{
        struct mdt_body  *body = md->body;
        struct posix_acl *acl;
        void             *buf;
        int               rc;

        if (!body->aclsize)
                return 0;

        buf = lustre_msg_buf(req->rq_repmsg, offset, body->aclsize);
        if (!buf) {
                CERROR("aclsize %u, bufcount %u, bufsize %u\n",
                       body->aclsize, lustre_msg_bufcount(req->rq_repmsg),
                       (lustre_msg_bufcount(req->rq_repmsg) <= offset) ?
                                -1 : lustre_msg_buflen(req->rq_repmsg, offset));
                return -EPROTO;
        }

        acl = posix_acl_from_xattr(buf, body->aclsize);
        if (IS_ERR(acl)) {
                rc = PTR_ERR(acl);
                CERROR("convert xattr to acl: %d\n", rc);
                return rc;
        }

        rc = posix_acl_valid(acl);
        if (rc) {
                CERROR("validate acl: %d\n", rc);
                posix_acl_release(acl);
                return rc;
        }

        md->posix_acl = acl;
        return 0;
}
#else
#define mdc_unpack_acl(exp, req, md, offset) 0
#endif

int mdc_get_lustre_md(struct obd_export *exp, struct ptlrpc_request *req,
                      int offset, struct obd_export *dt_exp, 
                      struct obd_export *md_exp, 
                      struct lustre_md *md)
{
        int rc = 0;
        ENTRY;

        LASSERT(md);
        memset(md, 0, sizeof(*md));

        md->body = lustre_msg_buf(req->rq_repmsg, offset, sizeof (*md->body));
        LASSERT (md->body != NULL);
        LASSERT_REPSWABBED(req, offset);
        offset++;

        if (!(md->body->valid & OBD_MD_FLEASIZE) &&
            !(md->body->valid & OBD_MD_FLDIREA))
                RETURN(0);

        if (md->body->valid & OBD_MD_FLEASIZE) {
                int lmmsize;
                struct lov_mds_md *lmm;

                LASSERT(S_ISREG(md->body->mode));

                if (md->body->eadatasize == 0) {
                        CERROR ("OBD_MD_FLEASIZE set, but eadatasize 0\n");
                        RETURN(-EPROTO);
                }
                lmmsize = md->body->eadatasize;
                lmm = lustre_msg_buf(req->rq_repmsg, offset, lmmsize);
                LASSERT (lmm != NULL);
                LASSERT_REPSWABBED(req, offset);

                rc = obd_unpackmd(dt_exp, &md->lsm, lmm, lmmsize);
                if (rc < 0)
                        RETURN(rc);

                LASSERT (rc >= sizeof (*md->lsm));
                rc = 0;

                offset++;
        } else if (md->body->valid & OBD_MD_FLDIREA) {
                int lmvsize;
                struct lov_mds_md *lmv;
                LASSERT(S_ISDIR(md->body->mode));
        
                if (md->body->eadatasize == 0) {
                        RETURN(0);
                }
                if (md->body->valid & OBD_MD_MEA) {
                        lmvsize = md->body->eadatasize;
                        lmv = lustre_msg_buf(req->rq_repmsg, offset, lmvsize);
                        LASSERT (lmv != NULL);
                        LASSERT_REPSWABBED(req, offset);

                        rc = obd_unpackmd(md_exp, (void *)&md->mea, lmv, 
                                          lmvsize);
                        if (rc < 0)
                                RETURN(rc);

                        LASSERT (rc >= sizeof (*md->mea));
                }
                rc = 0;
                offset ++; 
        }

        /* for ACL, it's possible that FLACL is set but aclsize is zero.  only
         * when aclsize != 0 there's an actual segment for ACL in reply
         * buffer. */
        if ((md->body->valid & OBD_MD_FLACL) && md->body->aclsize) {
                rc = mdc_unpack_acl(dt_exp, req, md, offset);
                if (rc)
                        GOTO(err_out, rc);
                offset++;
        }
out:
        RETURN(rc);

err_out:
        if (md->lsm)
                obd_free_memmd(dt_exp, &md->lsm);
        goto out;
}

int mdc_free_lustre_md(struct obd_export *exp, struct lustre_md *md)
{
        ENTRY;
        if (md->lsm)
                obd_free_memmd(exp, &md->lsm);

#ifdef CONFIG_FS_POSIX_ACL
        if (md->posix_acl) {
                posix_acl_release(md->posix_acl);
                md->posix_acl = NULL;
        }
#endif
        RETURN(0);
}

static void mdc_commit_open(struct ptlrpc_request *req)
{
        struct mdc_open_data *mod = req->rq_cb_data;
        if (mod == NULL)
                return;

        if (mod->mod_close_req != NULL)
                mod->mod_close_req->rq_cb_data = NULL;

        if (mod->mod_och != NULL)
                mod->mod_och->och_mod = NULL;

        OBD_FREE(mod, sizeof(*mod));
        req->rq_cb_data = NULL;
}

static void mdc_replay_open(struct ptlrpc_request *req)
{
        struct mdc_open_data *mod = req->rq_cb_data;
        struct obd_client_handle *och;
        struct ptlrpc_request *close_req;
        struct lustre_handle old;
        struct mdt_body *body;
        ENTRY;

        body = lustre_swab_repbuf(req, DLM_REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_mdt_body);
        LASSERT (body != NULL);

        if (mod == NULL) {
                DEBUG_REQ(D_ERROR, req,
                          "can't properly replay without open data");
                EXIT;
                return;
        }

        och = mod->mod_och;
        if (och != NULL) {
                struct lustre_handle *file_fh;
                LASSERT(och->och_magic == OBD_CLIENT_HANDLE_MAGIC);
                file_fh = &och->och_fh;
                CDEBUG(D_HA, "updating handle from "LPX64" to "LPX64"\n",
                       file_fh->cookie, body->handle.cookie);
                memcpy(&old, file_fh, sizeof(old));
                memcpy(file_fh, &body->handle, sizeof(*file_fh));
        }

        close_req = mod->mod_close_req;
        if (close_req != NULL) {
                struct mdt_body *close_body;
                LASSERT(lustre_msg_get_opc(close_req->rq_reqmsg) == MDS_CLOSE);
                close_body = lustre_msg_buf(close_req->rq_reqmsg, REQ_REC_OFF,
                                            sizeof(*close_body));
                if (och != NULL)
                        LASSERT(!memcmp(&old, &close_body->handle, sizeof old));
                DEBUG_REQ(D_HA, close_req, "updating close body with new fh");
                memcpy(&close_body->handle, &body->handle,
                       sizeof(close_body->handle));
        }

        EXIT;
}

int mdc_set_open_replay_data(struct obd_export *exp,
                             struct obd_client_handle *och,
                             struct ptlrpc_request *open_req)
{
        struct mdc_open_data *mod;
        struct mdt_rec_create *rec = lustre_msg_buf(open_req->rq_reqmsg,
                                                    DLM_INTENT_REC_OFF,
                                                    sizeof(*rec));
        struct mdt_body *body = lustre_msg_buf(open_req->rq_repmsg,
                                               DLM_REPLY_REC_OFF,
                                               sizeof(*body));
        ENTRY;

        /* incoming message in my byte order (it's been swabbed) */
        LASSERT(rec != NULL);
        LASSERT_REPSWABBED(open_req, DLM_REPLY_REC_OFF);
        /* outgoing messages always in my byte order */
        LASSERT(body != NULL);

        if (och) {
                OBD_ALLOC(mod, sizeof(*mod));
                if (mod == NULL) {
                        DEBUG_REQ(D_ERROR, open_req, "can't allocate mdc_open_data");
                        RETURN(0);
                }

                och->och_mod = mod;
                mod->mod_och = och;
                mod->mod_open_req = open_req;
                open_req->rq_cb_data = mod;
                open_req->rq_commit_cb = mdc_commit_open;
        }

        rec->cr_fid2 = body->fid1;
        open_req->rq_replay_cb = mdc_replay_open;
        if (!fid_is_sane(&body->fid1)) {
                DEBUG_REQ(D_ERROR, open_req, "saving replay request with "
                          "insane fid");
                LBUG();
        }

        DEBUG_REQ(D_HA, open_req, "set up replay data");
        RETURN(0);
}

int mdc_clear_open_replay_data(struct obd_export *exp,
                               struct obd_client_handle *och)
{
        struct mdc_open_data *mod = och->och_mod;
        ENTRY;

        /* Don't free the structure now (it happens in mdc_commit_open, after
         * we're sure we won't need to fix up the close request in the future),
         * but make sure that replay doesn't poke at the och, which is about to
         * be freed. */
        LASSERT(mod != LP_POISON);
        if (mod != NULL)
                mod->mod_och = NULL;
        och->och_mod = NULL;
        RETURN(0);
}

static void mdc_commit_close(struct ptlrpc_request *req)
{
        struct mdc_open_data *mod = req->rq_cb_data;
        struct ptlrpc_request *open_req;
        struct obd_import *imp = req->rq_import;

        DEBUG_REQ(D_HA, req, "close req committed");
        if (mod == NULL)
                return;

        mod->mod_close_req = NULL;
        req->rq_cb_data = NULL;
        req->rq_commit_cb = NULL;

        open_req = mod->mod_open_req;
        LASSERT(open_req != NULL);
        LASSERT(open_req != LP_POISON);
        LASSERT(open_req->rq_type != LI_POISON);

        DEBUG_REQ(D_HA, open_req, "open req balanced");
        LASSERT(open_req->rq_transno != 0);
        LASSERT(open_req->rq_import == imp);

        /* We no longer want to preserve this for transno-unconditional
         * replay. */
        spin_lock(&open_req->rq_lock);
        open_req->rq_replay = 0;
        spin_unlock(&open_req->rq_lock);
}

int mdc_close(struct obd_export *exp, struct md_op_data *op_data,
              struct obd_client_handle *och, struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        int reqsize[2] = { sizeof(struct ptlrpc_body),
                           sizeof(struct mdt_body) };
        int rc, repsize[4] = { sizeof(struct ptlrpc_body),
                               sizeof(struct mdt_body),
                               obd->u.cli.cl_max_mds_easize,
                               obd->u.cli.cl_max_mds_cookiesize };
        struct ptlrpc_request *req;
        struct mdc_open_data *mod;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_CLOSE, 2, reqsize, NULL);
        if (req == NULL)
                GOTO(out, rc = -ENOMEM);

        /* To avoid a livelock (bug 7034), we need to send CLOSE RPCs to a
         * portal whose threads are not taking any DLM locks and are therefore
         * always progressing */
        /* XXX FIXME bug 249 */
        req->rq_request_portal = MDS_READPAGE_PORTAL;

        /* Ensure that this close's handle is fixed up during replay. */
        LASSERT(och != NULL);
        LASSERT(och->och_magic == OBD_CLIENT_HANDLE_MAGIC);
        mod = och->och_mod;
        if (likely(mod != NULL)) {
                mod->mod_close_req = req;
                if (mod->mod_open_req->rq_type == LI_POISON) {
                        /* FIXME This should be an ASSERT, but until we
                           figure out why it can be poisoned here, give
                           a reasonable return. bug 6155 */
                        CERROR("LBUG POISONED open %p!\n", mod->mod_open_req);
                        ptlrpc_req_finished(req);
                        req = NULL;
                        GOTO(out, rc = -EIO);
                }
                DEBUG_REQ(D_HA, mod->mod_open_req, "matched open");
        } else {
                CDEBUG(D_HA, "couldn't find open req; expecting close error\n");
        }

        mdc_close_pack(req, REQ_REC_OFF, op_data, op_data->valid, och);

        ptlrpc_req_set_repsize(req, 4, repsize);
        req->rq_commit_cb = mdc_commit_close;
        LASSERT(req->rq_cb_data == NULL);
        req->rq_cb_data = mod;

        mdc_get_rpc_lock(obd->u.cli.cl_close_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(obd->u.cli.cl_close_lock, NULL);

        if (req->rq_repmsg == NULL) {
                CDEBUG(D_HA, "request failed to send: %p, %d\n", req,
                       req->rq_status);
                if (rc == 0)
                        rc = req->rq_status ? req->rq_status : -EIO;
        } else if (rc == 0) {
                rc = lustre_msg_get_status(req->rq_repmsg);
                if (lustre_msg_get_type(req->rq_repmsg) == PTL_RPC_MSG_ERR) {
                        DEBUG_REQ(D_ERROR, req, "type == PTL_RPC_MSG_ERR, err "
                                  "= %d", rc);
                        if (rc > 0)
                                rc = -rc;
                } else if (mod == NULL) {
                        CERROR("Unexpected: can't find mdc_open_data, but the "
                               "close succeeded.  Please tell CFS.\n");
                }
                if (!lustre_swab_repbuf(req, REPLY_REC_OFF,
                                        sizeof(struct mdt_body),
                                        lustre_swab_mdt_body)) {
                        CERROR("Error unpacking mdt_body\n");
                        rc = -EPROTO;
                }
        }

        EXIT;
        *request = req;
 out:
        if (rc != 0 && req && req->rq_commit_cb)
                req->rq_commit_cb(req);

        return rc;
}

int mdc_done_writing(struct obd_export *exp, struct md_op_data *op_data)
{
        struct ptlrpc_request *req;
        struct mdt_body *body;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_DONE_WRITING, 2, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        body->fid1 = op_data->fid1;
        body->size = op_data->size;
        body->blocks = op_data->blocks;
        body->flags = op_data->flags;
        body->valid = op_data->valid;

        ptlrpc_req_set_repsize(req, 2, size);

        rc = ptlrpc_queue_wait(req);
        ptlrpc_req_finished(req);
        RETURN(rc);
}

#ifdef HAVE_SPLIT_SUPPORT
int mdc_sendpage(struct obd_export *exp, const struct lu_fid *fid,
                 const struct page *page, int offset)
{
        struct obd_import *imp = class_exp2cliimp(exp);
        struct ptlrpc_request *req = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct mdt_body *body;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        ENTRY;

        CDEBUG(D_INODE, "object: "DFID"\n", PFID(fid));

        req = ptlrpc_prep_req(imp, LUSTRE_MDS_VERSION, MDS_WRITEPAGE, 2, size,
                              NULL);
        if (req == NULL)
                GOTO(out, rc = -ENOMEM);

        req->rq_request_portal = MDS_READPAGE_PORTAL;

        desc = ptlrpc_prep_bulk_imp(req, 1, BULK_GET_SOURCE, MDS_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);
        /* NB req now owns desc and will free it when it gets freed */
        ptlrpc_prep_bulk_page(desc, (struct page*)page, 0, offset);

        mdc_readdir_pack(req, REQ_REC_OFF, 0, offset, fid);

        ptlrpc_req_set_repsize(req, 2, size);
        rc = ptlrpc_queue_wait(req);
out:
        ptlrpc_req_finished(req);
        RETURN(rc);
}
EXPORT_SYMBOL(mdc_sendpage);
#endif

int mdc_readpage(struct obd_export *exp, const struct lu_fid *fid,
                 __u64 offset, struct page *page,
                 struct ptlrpc_request **request)
{
        struct obd_import *imp = class_exp2cliimp(exp);
        struct ptlrpc_request *req = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct mdt_body *body;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        ENTRY;

        CDEBUG(D_INODE, "object: "DFID"\n", PFID(fid));

        req = ptlrpc_prep_req(imp, LUSTRE_MDS_VERSION, MDS_READPAGE, 2, size,
                              NULL);
        if (req == NULL)
                GOTO(out, rc = -ENOMEM);

        /* XXX FIXME bug 249 */
        req->rq_request_portal = MDS_READPAGE_PORTAL;

        desc = ptlrpc_prep_bulk_imp(req, 1, BULK_PUT_SINK, MDS_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);
        /* NB req now owns desc and will free it when it gets freed */

        ptlrpc_prep_bulk_page(desc, page, 0, PAGE_CACHE_SIZE);

        mdc_readdir_pack(req, REQ_REC_OFF, offset, PAGE_CACHE_SIZE, fid);

        ptlrpc_req_set_repsize(req, 2, size);
        rc = ptlrpc_queue_wait(req);

        if (rc == 0) {
                body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                          lustre_swab_mdt_body);
                if (body == NULL) {
                        CERROR("Can't unpack mdt_body\n");
                        GOTO(out, rc = -EPROTO);
                }

                if (req->rq_bulk->bd_nob_transferred != PAGE_CACHE_SIZE) {
                        CERROR ("Unexpected # bytes transferred: %d"
                                " (%ld expected)\n",
                                req->rq_bulk->bd_nob_transferred,
                                PAGE_CACHE_SIZE);
                        GOTO (out, rc = -EPROTO);
                }
        }

        EXIT;
 out:
        *request = req;
        return rc;
}


static int mdc_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_ioctl_data *data = karg;
        struct obd_import *imp = obd->u.cli.cl_import;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        MOD_INC_USE_COUNT;
#else
        if (!try_module_get(THIS_MODULE)) {
                CERROR("Can't get module. Is it alive?");
                return -EINVAL;
        }
#endif
        switch (cmd) {
        case OBD_IOC_CLIENT_RECOVER:
                rc = ptlrpc_recover_import(imp, data->ioc_inlbuf1);
                if (rc < 0)
                        GOTO(out, rc);
                GOTO(out, rc = 0);
        case IOC_OSC_SET_ACTIVE:
                rc = ptlrpc_set_import_active(imp, data->ioc_offset);
                GOTO(out, rc);
        case OBD_IOC_PARSE: {
                ctxt = llog_get_context(exp->exp_obd, LLOG_CONFIG_REPL_CTXT);
                rc = class_config_parse_llog(ctxt, data->ioc_inlbuf1, NULL);
                GOTO(out, rc);
        }
#ifdef __KERNEL__
        case OBD_IOC_LLOG_INFO:
        case OBD_IOC_LLOG_PRINT: {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                rc = llog_ioctl(ctxt, cmd, data);

                GOTO(out, rc);
        }
#endif
        case OBD_IOC_POLL_QUOTACHECK:
                rc = lquota_poll_check(quota_interface, exp,
                                       (struct if_quotacheck *)karg);
                GOTO(out, rc);
        default:
                CERROR("mdc_ioctl(): unrecognised ioctl %#x\n", cmd);
                GOTO(out, rc = -ENOTTY);
        }
out:
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        MOD_DEC_USE_COUNT;
#else
        module_put(THIS_MODULE);
#endif

        return rc;
}

int mdc_set_info_async(struct obd_export *exp, obd_count keylen,
                       void *key, obd_count vallen, void *val,
                       struct ptlrpc_request_set *set)
{
        struct obd_import *imp = class_exp2cliimp(exp);
        int rc = -EINVAL;

        if (KEY_IS(KEY_INIT_RECOV)) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                imp->imp_initial_recov = *(int *)val;
                CDEBUG(D_HA, "%s: set imp_initial_recov = %d\n",
                       exp->exp_obd->obd_name, imp->imp_initial_recov);
                RETURN(0);
        }
        /* Turn off initial_recov after we try all backup servers once */
        if (KEY_IS(KEY_INIT_RECOV_BACKUP)) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                imp->imp_initial_recov_bk = *(int *)val;
                if (imp->imp_initial_recov_bk)
                        imp->imp_initial_recov = 1;
                CDEBUG(D_HA, "%s: set imp_initial_recov_bk = %d\n",
                       exp->exp_obd->obd_name, imp->imp_initial_recov_bk);
                RETURN(0);
        }
        if (KEY_IS("read-only")) {
                struct ptlrpc_request *req;
                int size[3] = { sizeof(struct ptlrpc_body), keylen, vallen };
                char *bufs[3] = { NULL, key, val };

                if (vallen != sizeof(int))
                        RETURN(-EINVAL);

                if (*((int *)val)) {
                        imp->imp_connect_flags_orig |= OBD_CONNECT_RDONLY;
                        imp->imp_connect_data.ocd_connect_flags |=
                                OBD_CONNECT_RDONLY;
                } else {
                        imp->imp_connect_flags_orig &= ~OBD_CONNECT_RDONLY;
                        imp->imp_connect_data.ocd_connect_flags &=
                                ~OBD_CONNECT_RDONLY;
                }

                req = ptlrpc_prep_req(imp, LUSTRE_MDS_VERSION, MDS_SET_INFO,
                                      3, size, bufs);
                if (req == NULL)
                        RETURN(-ENOMEM);

                ptlrpc_req_set_repsize(req, 1, NULL);
                if (set) {
                        rc = 0;
                        ptlrpc_set_add_req(set, req);
                        ptlrpc_check_set(set);
                } else {
                        rc = ptlrpc_queue_wait(req);
                        ptlrpc_req_finished(req);
                }

                RETURN(rc);
        }

        if (KEY_IS(KEY_FLUSH_CTX)) {
                sptlrpc_import_flush_my_ctx(imp);
                RETURN(0);
        }

        RETURN(rc);
}

int mdc_get_info(struct obd_export *exp, __u32 keylen, void *key,
                 __u32 *vallen, void *val)
{
        int rc = -EINVAL;

        if (keylen == strlen("max_easize") &&
            memcmp(key, "max_easize", strlen("max_easize")) == 0) {
                int mdsize, *max_easize;

                if (*vallen != sizeof(int))
                        RETURN(-EINVAL);
                mdsize = *(int*)val;
                if (mdsize > exp->exp_obd->u.cli.cl_max_mds_easize)
                        exp->exp_obd->u.cli.cl_max_mds_easize = mdsize;
                max_easize = val;
                *max_easize = exp->exp_obd->u.cli.cl_max_mds_easize;
                RETURN(0);
        }
        RETURN(rc);
}

static int mdc_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                      __u64 max_age)
{
        struct ptlrpc_request *req;
        struct obd_statfs *msfs;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*msfs) };
        ENTRY;

        /* We could possibly pass max_age in the request (as an absolute
         * timestamp or a "seconds.usec ago") so the target can avoid doing
         * extra calls into the filesystem if that isn't necessary (e.g.
         * during mount that would help a bit).  Having relative timestamps
         * is not so great if request processing is slow, while absolute
         * timestamps are not ideal because they need time synchronization. */
        req = ptlrpc_prep_req(obd->u.cli.cl_import, LUSTRE_MDS_VERSION,
                              MDS_STATFS, 1, NULL, NULL);
        if (!req)
                RETURN(-ENOMEM);

        ptlrpc_req_set_repsize(req, 2, size);

        rc = ptlrpc_queue_wait(req);

        if (rc)
                GOTO(out, rc);

        msfs = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*msfs),
                                  lustre_swab_obd_statfs);
        if (msfs == NULL) {
                CERROR("Can't unpack obd_statfs\n");
                GOTO(out, rc = -EPROTO);
        }

        memcpy(osfs, msfs, sizeof(*msfs));
        EXIT;
out:
        ptlrpc_req_finished(req);

        return rc;
}

static int mdc_pin(struct obd_export *exp, const struct lu_fid *fid,
                   struct obd_client_handle *handle, int flag)
{
        struct ptlrpc_request *req;
        struct mdt_body *body;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_PIN, 2, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof (*body));
        body->fid1 = *fid;
        body->flags = flag;

        ptlrpc_req_set_repsize(req, 2, size);

        mdc_get_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        if (rc) {
                CERROR("pin failed: %d\n", rc);
                ptlrpc_req_finished(req);
                RETURN(rc);
        }

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_mdt_body);
        if (body == NULL) {
                ptlrpc_req_finished(req);
                RETURN(rc);
        }

        memcpy(&handle->och_fh, &body->handle, sizeof(body->handle));
        handle->och_magic = OBD_CLIENT_HANDLE_MAGIC;

        OBD_ALLOC(handle->och_mod, sizeof(*handle->och_mod));
        if (handle->och_mod == NULL) {
                DEBUG_REQ(D_ERROR, req, "can't allocate mdc_open_data");
                RETURN(-ENOMEM);
        }
        handle->och_mod->mod_open_req = req; /* will be dropped by unpin */

        RETURN(rc);
}

static int mdc_unpin(struct obd_export *exp,
                     struct obd_client_handle *handle, int flag)
{
        struct ptlrpc_request *req;
        struct mdt_body *body;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        ENTRY;

        if (handle->och_magic != OBD_CLIENT_HANDLE_MAGIC)
                RETURN(0);

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_CLOSE, 2, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        memcpy(&body->handle, &handle->och_fh, sizeof(body->handle));
        body->flags = flag;

        ptlrpc_req_set_repsize(req, 1, NULL);
        mdc_get_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);

        if (rc != 0)
                CERROR("unpin failed: %d\n", rc);

        ptlrpc_req_finished(req);
        ptlrpc_req_finished(handle->och_mod->mod_open_req);
        OBD_FREE(handle->och_mod, sizeof(*handle->och_mod));
        RETURN(rc);
}

int mdc_sync(struct obd_export *exp, const struct lu_fid *fid,
             struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        int size[2] = { sizeof(struct ptlrpc_body), sizeof(struct mdt_body) };
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_SYNC, 2, size, NULL);
        if (!req)
                RETURN(rc = -ENOMEM);

        mdc_pack_req_body(req, REQ_REC_OFF, 0, fid, 0, 0);

        ptlrpc_req_set_repsize(req, 2, size);

        rc = ptlrpc_queue_wait(req);
        if (rc || request == NULL)
                ptlrpc_req_finished(req);
        else
                *request = req;

        RETURN(rc);
}

static int mdc_import_event(struct obd_device *obd, struct obd_import *imp,
                            enum obd_import_event event)
{
        int rc = 0;

        LASSERT(imp->imp_obd == obd);

        switch (event) {
        case IMP_EVENT_DISCON: {
                break;
        }
        case IMP_EVENT_INACTIVE: {
                rc = obd_notify_observer(obd, obd, OBD_NOTIFY_INACTIVE, NULL);
                break;
        }
        case IMP_EVENT_INVALIDATE: {
                struct ldlm_namespace *ns = obd->obd_namespace;

                ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);

                break;
        }
        case IMP_EVENT_ACTIVE: {
                rc = obd_notify_observer(obd, obd, OBD_NOTIFY_ACTIVE, NULL);
                break;
        }
        case IMP_EVENT_OCD:
                rc = obd_notify_observer(obd, obd, OBD_NOTIFY_OCD, NULL);
                break;

        default:
                CERROR("Unknown import event %x\n", event);
                LBUG();
        }
        RETURN(rc);
}

static int mdc_fid_init(struct obd_export *exp)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        char *prefix;
        int rc;
        ENTRY;

        OBD_ALLOC_PTR(cli->cl_seq);
        if (cli->cl_seq == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
        if (prefix == NULL)
                GOTO(out_free_seq, rc = -ENOMEM);

        snprintf(prefix, MAX_OBD_NAME + 5, "srv-%s",
                 exp->exp_obd->obd_name);

        /* init client side sequence-manager */
        rc = seq_client_init(cli->cl_seq, exp, 
                             LUSTRE_SEQ_METADATA,
                             prefix, NULL, NULL);
        OBD_FREE(prefix, MAX_OBD_NAME + 5);
        if (rc)
                GOTO(out_free_seq, rc);

        /* pre-allocate meta-sequence */
        rc = seq_client_alloc_meta(cli->cl_seq);
        if (rc) {
                CERROR("can't allocate new mata-sequence, "
                       "rc %d\n", rc);
                GOTO(out_free_seq, rc);
        }
        RETURN(rc);

out_free_seq:
        OBD_FREE_PTR(cli->cl_seq);
        cli->cl_seq = NULL;
        return rc;
}

static int mdc_fid_fini(struct obd_export *exp)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        ENTRY;

        if (cli->cl_seq != NULL) {
                seq_client_fini(cli->cl_seq);
                OBD_FREE_PTR(cli->cl_seq);
                cli->cl_seq = NULL;
        }
        
        RETURN(0);
}

static int mdc_fid_alloc(struct obd_export *exp, struct lu_fid *fid,
                         struct lu_placement_hint *hint)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct lu_client_seq *seq = cli->cl_seq;

        ENTRY;
        RETURN(seq_client_alloc_fid(seq, fid));
}

static int mdc_setup(struct obd_device *obd, struct lustre_cfg *cfg)
{
        struct client_obd *cli = &obd->u.cli;
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        OBD_ALLOC(cli->cl_rpc_lock, sizeof (*cli->cl_rpc_lock));
        if (!cli->cl_rpc_lock)
                RETURN(-ENOMEM);
        mdc_init_rpc_lock(cli->cl_rpc_lock);

        ptlrpcd_addref();

        OBD_ALLOC(cli->cl_setattr_lock, sizeof (*cli->cl_setattr_lock));
        if (!cli->cl_setattr_lock)
                GOTO(err_rpc_lock, rc = -ENOMEM);
        mdc_init_rpc_lock(cli->cl_setattr_lock);

        OBD_ALLOC(cli->cl_close_lock, sizeof (*cli->cl_close_lock));
        if (!cli->cl_close_lock)
                GOTO(err_setattr_lock, rc = -ENOMEM);
        mdc_init_rpc_lock(cli->cl_close_lock);

        rc = client_obd_setup(obd, cfg);
        if (rc)
                GOTO(err_close_lock, rc);
        lprocfs_init_vars(mdc, &lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        rc = obd_llog_init(obd, obd, 0, NULL, NULL);
        if (rc) {
                mdc_cleanup(obd);
                CERROR("failed to setup llogging subsystems\n");
        }

        RETURN(rc);

err_close_lock:
        OBD_FREE(cli->cl_close_lock, sizeof (*cli->cl_close_lock));
err_setattr_lock:
        OBD_FREE(cli->cl_setattr_lock, sizeof (*cli->cl_setattr_lock));
err_rpc_lock:
        OBD_FREE(cli->cl_rpc_lock, sizeof (*cli->cl_rpc_lock));
        ptlrpcd_decref();
        RETURN(rc);
}

/* Initialize the default and maximum LOV EA and cookie sizes.  This allows
 * us to make MDS RPCs with large enough reply buffers to hold the
 * maximum-sized (= maximum striped) EA and cookie without having to
 * calculate this (via a call into the LOV + OSCs) each time we make an RPC. */
int mdc_init_ea_size(struct obd_export *exp, int easize,
                     int def_easize, int cookiesize)
{
        struct obd_device *obd = exp->exp_obd;
        struct client_obd *cli = &obd->u.cli;
        ENTRY;

        if (cli->cl_max_mds_easize < easize)
                cli->cl_max_mds_easize = easize;

        if (cli->cl_default_mds_easize < def_easize)
                cli->cl_default_mds_easize = def_easize;

        if (cli->cl_max_mds_cookiesize < cookiesize)
                cli->cl_max_mds_cookiesize = cookiesize;

        RETURN(0);
}

static int mdc_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        int rc = 0;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_EARLY:
        case OBD_CLEANUP_EXPORTS:
                break;
        case OBD_CLEANUP_SELF_EXP:
                rc = obd_llog_finish(obd, 0);
                if (rc != 0)
                        CERROR("failed to cleanup llogging subsystems\n");
        case OBD_CLEANUP_OBD:
                break;
        }
        RETURN(rc);
}

static int mdc_cleanup(struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;

        OBD_FREE(cli->cl_rpc_lock, sizeof (*cli->cl_rpc_lock));
        OBD_FREE(cli->cl_setattr_lock, sizeof (*cli->cl_setattr_lock));
        OBD_FREE(cli->cl_close_lock, sizeof (*cli->cl_close_lock));

        lprocfs_obd_cleanup(obd);
        ptlrpcd_decref();

        return client_obd_cleanup(obd);
}


static int mdc_llog_init(struct obd_device *obd, struct obd_device *tgt,
                         int count, struct llog_catid *logid, 
                         struct obd_uuid *uuid)
{
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        rc = llog_setup(obd, LLOG_CONFIG_REPL_CTXT, tgt, 0, NULL,
                        &llog_client_ops);
        if (rc == 0) {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                ctxt->loc_imp = obd->u.cli.cl_import;
        }

        rc = llog_setup(obd, LLOG_LOVEA_REPL_CTXT, tgt, 0, NULL,
                       &llog_client_ops);
        if (rc == 0) {
                ctxt = llog_get_context(obd, LLOG_LOVEA_REPL_CTXT);
                ctxt->loc_imp = obd->u.cli.cl_import;
        }

        RETURN(rc);
}

static int mdc_llog_finish(struct obd_device *obd, int count)
{
        int rc;
        ENTRY;

        rc = llog_cleanup(llog_get_context(obd, LLOG_LOVEA_REPL_CTXT));
        if (rc) {
                CERROR("can not cleanup LLOG_CONFIG_REPL_CTXT rc %d\n", rc);
        }
        rc = llog_cleanup(llog_get_context(obd, LLOG_CONFIG_REPL_CTXT));
        RETURN(rc);
}

static int mdc_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct lprocfs_static_vars lvars;
        int rc = 0;

        lprocfs_init_vars(mdc, &lvars);
        
        rc = class_process_proc_param(PARAM_MDC, lvars.obd_vars, lcfg, obd);
        return(rc);
}

struct obd_ops mdc_obd_ops = {
        .o_owner            = THIS_MODULE,
        .o_setup            = mdc_setup,
        .o_precleanup       = mdc_precleanup,
        .o_cleanup          = mdc_cleanup,
        .o_add_conn         = client_import_add_conn,
        .o_del_conn         = client_import_del_conn,
        .o_connect          = client_connect_import,
        .o_disconnect       = client_disconnect_export,
        .o_iocontrol        = mdc_iocontrol,
        .o_set_info_async   = mdc_set_info_async,
        .o_statfs           = mdc_statfs,
        .o_pin              = mdc_pin,
        .o_unpin            = mdc_unpin,
        .o_fid_init         = mdc_fid_init,
        .o_fid_fini         = mdc_fid_fini,
        .o_fid_alloc        = mdc_fid_alloc,
        .o_import_event     = mdc_import_event,
        .o_llog_init        = mdc_llog_init,
        .o_llog_finish      = mdc_llog_finish,
        .o_get_info         = mdc_get_info,
        .o_process_config  = mdc_process_config,
};

struct md_ops mdc_md_ops = {
        .m_getstatus        = mdc_getstatus,
        .m_change_cbdata    = mdc_change_cbdata,
        .m_close            = mdc_close,
        .m_create           = mdc_create,
        .m_done_writing     = mdc_done_writing,
        .m_enqueue          = mdc_enqueue,
        .m_getattr          = mdc_getattr,
        .m_getattr_name     = mdc_getattr_name,
        .m_intent_lock      = mdc_intent_lock,
        .m_link             = mdc_link,
        .m_rename           = mdc_rename,
        .m_setattr          = mdc_setattr,
        .m_setxattr         = mdc_setxattr,
        .m_getxattr         = mdc_getxattr,
        .m_sync             = mdc_sync,
        .m_readpage         = mdc_readpage,
        .m_unlink           = mdc_unlink,
        .m_cancel_unused    = mdc_cancel_unused,
        .m_init_ea_size     = mdc_init_ea_size,
        .m_set_lock_data    = mdc_set_lock_data,
        .m_lock_match       = mdc_lock_match,
        .m_get_lustre_md    = mdc_get_lustre_md,
        .m_free_lustre_md   = mdc_free_lustre_md,
        .m_set_open_replay_data = mdc_set_open_replay_data,
        .m_clear_open_replay_data = mdc_clear_open_replay_data
};

extern quota_interface_t mdc_quota_interface;

int __init mdc_init(void)
{
        int rc;
        struct lprocfs_static_vars lvars;
        lprocfs_init_vars(mdc, &lvars);
        
        request_module("lquota");
        quota_interface = PORTAL_SYMBOL_GET(mdc_quota_interface);
        init_obd_quota_ops(quota_interface, &mdc_obd_ops);

        rc = class_register_type(&mdc_obd_ops, &mdc_md_ops, lvars.module_vars,
                                 LUSTRE_MDC_NAME, NULL);
        if (rc && quota_interface)
                PORTAL_SYMBOL_PUT(mdc_quota_interface);

        RETURN(rc);
}

#ifdef __KERNEL__
static void /*__exit*/ mdc_exit(void)
{
        if (quota_interface)
                PORTAL_SYMBOL_PUT(mdc_quota_interface);

        class_unregister_type(LUSTRE_MDC_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Client");
MODULE_LICENSE("GPL");

module_init(mdc_init);
module_exit(mdc_exit);
#endif
