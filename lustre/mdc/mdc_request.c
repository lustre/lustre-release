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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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

#include <obd_class.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>
#include <lustre_param.h>
#include "mdc_internal.h"

static quota_interface_t *quota_interface;

#define REQUEST_MINOR 244

static quota_interface_t *quota_interface;
extern quota_interface_t mdc_quota_interface;

static int mdc_cleanup(struct obd_device *obd);

extern int mds_queue_req(struct ptlrpc_request *);
/* Helper that implements most of mdc_getstatus and signal_completed_replay. */
/* XXX this should become mdc_get_info("key"), sending MDS_GET_INFO RPC */
static int send_getstatus(struct obd_export *exp, struct ll_fid *rootfid,
                          int level, int msg_flags)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        __u32 size[3] = { sizeof(struct ptlrpc_body),
                          sizeof(struct mdt_body),
                          sizeof(struct lustre_capa) };
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION, MDS_GETSTATUS, 2, size,
                              NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        req->rq_export = class_export_get(exp);
        req->rq_send_state = level;
        ptlrpc_req_set_repsize(req, 3, size);

        mdc_pack_req_body(req, REQ_REC_OFF, 0, NULL, 0, 0);
        lustre_msg_add_flags(req->rq_reqmsg, msg_flags);
        rc = ptlrpc_queue_wait(req);

        if (!rc) {
                body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                          lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR ("Can't extract mds_body\n");
                        GOTO (out, rc = -EPROTO);
                }

                memcpy(rootfid, &body->fid1, sizeof(*rootfid));

                CDEBUG(D_NET, "root ino="LPU64", last_committed="LPU64
                       ", last_xid="LPU64"\n",
                       rootfid->id,
                       lustre_msg_get_last_committed(req->rq_repmsg),
                       lustre_msg_get_last_xid(req->rq_repmsg));
        }

        EXIT;
 out:
        ptlrpc_req_finished(req);
        return rc;
}

/* This should be mdc_get_info("ROOT") */
int mdc_getstatus(struct obd_export *exp, struct ll_fid *rootfid)
{
        return send_getstatus(exp, rootfid, LUSTRE_IMP_FULL, 0);
}

static
int mdc_getattr_common(struct obd_export *exp, unsigned int ea_size,
                       unsigned int acl_size, struct ptlrpc_request *req)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct mds_body *body;
        void *eadata;
        __u32 size[6] = { sizeof(struct ptlrpc_body),
                          sizeof(struct mdt_body) };
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

        if (mdc_exp_is_2_0_server(exp)) {
                bufcount = 6;
        }

        ptlrpc_req_set_repsize(req, bufcount, size);

        rc = mdc_enter_request(&obddev->u.cli);
        if (rc != 0)
                RETURN(rc);
        rc = ptlrpc_queue_wait(req);
        mdc_exit_request(&obddev->u.cli);
        if (rc != 0)
                RETURN (rc);

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR ("Can't unpack mds_body\n");
                RETURN (-EPROTO);
        }

        CDEBUG(D_NET, "mode: %o\n", body->mode);

        lustre_set_rep_swabbed(req, REPLY_REC_OFF + 1);
        mdc_update_max_ea_from_body(exp, body);

        if (body->eadatasize != 0) {
                /* reply indicates presence of eadata; check it's there... */
                eadata = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1,
                                        body->eadatasize);
                if (eadata == NULL) {
                        CERROR ("Missing/short eadata\n");
                        RETURN (-EPROTO);
                }
        }

        RETURN (0);
}

int mdc_getattr(struct obd_export *exp, struct ll_fid *fid,
                obd_valid valid, unsigned int ea_size,
                struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        __u32 size[2] = { sizeof(struct ptlrpc_body),
                          sizeof(struct mdt_body) };
        int acl_size = 0, rc;
        ENTRY;

        /* XXX do we need to make another request here?  We just did a getattr
         *     to do the lookup in the first place.
         */
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_GETATTR, 2, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        req->rq_export = class_export_get(exp);
        mdc_pack_req_body(req, REQ_REC_OFF, valid, fid, ea_size,
                          MDS_BFLAG_EXT_FLAGS/*request "new" flags(bug 9486)*/);

        /* currently only root inode will call us with FLACL */
        if (valid & OBD_MD_FLACL)
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

int mdc_getattr_name(struct obd_export *exp, struct ll_fid *fid,
                     const char *filename, int namelen, unsigned long valid,
                     unsigned int ea_size, struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        __u32 size[4] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                          [REQ_REC_OFF] = sizeof(struct mdt_body),
                          [REQ_REC_OFF + 1] = namelen };
        int rc;
        int bufcount = 3;
        int nameoffset = REQ_REC_OFF + 1;
        ENTRY;

        if (mdc_exp_is_2_0_server(exp)) {
                size[REQ_REC_OFF + 1] = 0;
                size[REQ_REC_OFF + 2] = namelen;
                bufcount ++;
                nameoffset ++;
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_GETATTR_NAME, bufcount, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        req->rq_export = class_export_get(exp);
        mdc_pack_req_body(req, REQ_REC_OFF, valid, fid, ea_size,
                          MDS_BFLAG_EXT_FLAGS/*request "new" flags(bug 9486)*/);

        LASSERT(strnlen(filename, namelen) == namelen - 1);
        memcpy(lustre_msg_buf(req->rq_reqmsg, nameoffset, namelen),
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
int mdc_xattr_common(struct obd_export *exp, struct ll_fid *fid,
                     int opcode, obd_valid valid, const char *xattr_name,
                     const char *input, int input_size, int output_size,
                     int flags, struct ptlrpc_request **request)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct ptlrpc_request *req;
        __u32 size[5] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [REQ_REC_OFF] = sizeof(struct mdt_body),
                        [REQ_REC_OFF + 1] = 0, /* capa */
                        [REQ_REC_OFF + 2] = 0, /* name */
                        [REQ_REC_OFF + 3] = 0 };
        int rc = 0, xattr_namelen = 0, bufcnt = 2, offset = REQ_REC_OFF + 1;
        void *tmp;
        ENTRY;

        if (mdc_exp_is_2_0_server(exp)) {
                bufcnt++;
                offset++;
                if (opcode == MDS_SETXATTR) {
                        size[REQ_REC_OFF] = sizeof (struct mdt_rec_setxattr);
                        opcode = MDS_REINT;
                }
        }

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

        req->rq_export = class_export_get(exp);

        if (opcode == MDS_REINT && mdc_exp_is_2_0_server(exp)) {
                struct mdt_rec_setxattr *rec;
                rec = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF,
                                     sizeof(struct mdt_rec_setxattr));
                rec->sx_opcode = REINT_SETXATTR;
                rec->sx_fsuid  = cfs_curproc_fsuid();
                rec->sx_fsgid  = cfs_curproc_fsgid();
                rec->sx_cap    = cfs_curproc_cap_pack();
                rec->sx_suppgid1 = -1;
                rec->sx_suppgid2 = -1;
                rec->sx_fid    = *((struct lu_fid*)fid);
                rec->sx_valid  = valid;
                rec->sx_size   = output_size;
                rec->sx_flags  = flags;
        } else {
                /* request data */
                mdc_pack_req_body(req, REQ_REC_OFF, valid, fid, output_size, flags);
        }

        if (xattr_name) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset++, xattr_namelen);
                memcpy(tmp, xattr_name, xattr_namelen);
        }
        if (input_size) {
                tmp = lustre_msg_buf(req->rq_reqmsg, offset++, input_size);
                memcpy(tmp, input, input_size);
        }

        size[REPLY_REC_OFF] = sizeof(struct mdt_body);
        if (mdc_exp_is_2_0_server(exp)) {
                bufcnt = 2;
        } else {
                /* reply buffers */
                if (opcode == MDS_GETXATTR) {
                        bufcnt = 2;
                } else {
                        bufcnt = 1;
                }

        }

        /* we do this even output_size is 0, because server is doing that */
        size[bufcnt++] = output_size;
        ptlrpc_req_set_repsize(req, bufcnt, size);

        /* make rpc */
        if (opcode == MDS_SETXATTR || opcode == MDS_REINT)
                mdc_get_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        else {
                rc = mdc_enter_request(&obddev->u.cli);
                if (rc != 0)
                        GOTO(err_out, rc);
        }

        rc = ptlrpc_queue_wait(req);

        if (opcode == MDS_SETXATTR || opcode == MDS_REINT)
                mdc_put_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        else
                mdc_exit_request(&obddev->u.cli);

        if (rc != 0)
                GOTO(err_out, rc);

        if (opcode == MDS_GETXATTR) {
                struct mds_body * body = lustre_swab_repbuf(req, REPLY_REC_OFF,
                                          sizeof(*body),
                                          lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR ("Can't unpack mds_body\n");
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

int mdc_setxattr(struct obd_export *exp, struct ll_fid *fid,
                 obd_valid valid, const char *xattr_name,
                 const char *input, int input_size,
                 int output_size, int flags,
                 struct ptlrpc_request **request)
{
        return mdc_xattr_common(exp, fid, MDS_SETXATTR, valid, xattr_name,
                                input, input_size, output_size, flags, request);
}

int mdc_getxattr(struct obd_export *exp, struct ll_fid *fid,
                 obd_valid valid, const char *xattr_name,
                 const char *input, int input_size,
                 int output_size, struct ptlrpc_request **request)
{
        return mdc_xattr_common(exp, fid, MDS_GETXATTR, valid, xattr_name,
                                input, input_size, output_size, 0, request);
}

/* For the fid-less server */
static void mdc_store_inode_generation_18(struct ptlrpc_request *req,
                                          int reqoff, int repoff)
{
        struct mds_rec_create *rec = lustre_msg_buf(req->rq_reqmsg, reqoff,
                                                    sizeof(*rec));
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, repoff,
                                               sizeof(*body));

        LASSERT (rec != NULL);
        LASSERT (body != NULL);

        memcpy(&rec->cr_replayfid, &body->fid1, sizeof rec->cr_replayfid);
        if (body->fid1.id == 0) {
                DEBUG_REQ(D_ERROR, req, "saving replay request with id = 0 "
                          "gen = %u", body->fid1.generation);
                LBUG();
        }

        DEBUG_REQ(D_INODE, req, "storing generation %u for ino "LPU64,
                  rec->cr_replayfid.generation, rec->cr_replayfid.id);
}

static void mdc_store_inode_generation_20(struct ptlrpc_request *req,
                                          int reqoff, int repoff)
{
        struct mdt_rec_create *rec = lustre_msg_buf(req->rq_reqmsg, reqoff,
                                                    sizeof(*rec));
        struct mdt_body *body = lustre_msg_buf(req->rq_repmsg, repoff,
                                               sizeof(*body));

        LASSERT (rec != NULL);
        LASSERT (body != NULL);

        rec->cr_fid2 = body->fid1;
        rec->cr_ioepoch = body->ioepoch;
        rec->cr_old_handle.cookie = body->handle.cookie;

        if (!fid_is_sane(&body->fid1)) {
                DEBUG_REQ(D_ERROR, req, "saving replay request with"
                          "insane fid");
                LBUG();
        }

        DEBUG_REQ(D_INODE, req, "storing generation %u for ino "LPU64,
                  rec->cr_fid1.f_oid, rec->cr_fid2.f_seq);
}

/* This should be called with both the request and the reply still packed. */
void mdc_store_inode_generation(struct ptlrpc_request *req, int reqoff,
                                int repoff)
{
        if (mdc_req_is_2_0_server(req))
                mdc_store_inode_generation_20(req, reqoff, repoff);
        else
                mdc_store_inode_generation_18(req, reqoff, repoff);
}

#ifdef CONFIG_FS_POSIX_ACL
static
int mdc_unpack_acl(struct obd_export *exp, struct ptlrpc_request *req,
                   struct lustre_md *md, unsigned int offset)
{
        struct mds_body  *body = md->body;
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

int mdc_req2lustre_md(struct ptlrpc_request *req, int offset,
                      struct obd_export *exp,
                      struct lustre_md *md)
{
        int rc = 0;
        int iop = mdc_req_is_2_0_server(req);
        ENTRY;

        LASSERT(md);
        memset(md, 0, sizeof(*md));

        md->body = lustre_msg_buf(req->rq_repmsg, offset, sizeof (*md->body));
        LASSERT (md->body != NULL);
        LASSERT(lustre_rep_swabbed(req, offset));
        offset++;

        if (md->body->valid & OBD_MD_FLEASIZE) {
                int lmmsize;
                struct lov_mds_md *lmm;

                if (!S_ISREG(md->body->mode)) {
                        CERROR("OBD_MD_FLEASIZE set, should be a regular file, "
                               "but is not\n");
                        GOTO(err_out, rc = -EPROTO);
                }

                if (md->body->eadatasize == 0) {
                        CERROR ("OBD_MD_FLEASIZE set, but eadatasize 0\n");
                        GOTO(err_out, rc = -EPROTO);
                }
                lmmsize = md->body->eadatasize;
                lmm = lustre_msg_buf(req->rq_repmsg, offset, lmmsize);
                if (!lmm) {
                        CERROR ("incorrect message: lmm == 0\n");
                        GOTO(err_out, rc = -EPROTO);
                }
                LASSERT(lustre_rep_swabbed(req, offset));

                rc = obd_unpackmd(exp, &md->lsm, lmm, lmmsize);
                if (rc < 0)
                        GOTO(err_out, rc);

                if (rc < sizeof(*md->lsm)) {
                        CERROR ("lsm size too small:  rc < sizeof (*md->lsm) "
                                "(%d < %d)\n", rc, (int)sizeof(*md->lsm));
                        GOTO(err_out, rc = -EPROTO);
                }
                rc = 0;

                if (!iop)
                        offset++;
        } else if (md->body->valid & OBD_MD_FLDIREA) {
                if(!S_ISDIR(md->body->mode)) {
                        CERROR("OBD_MD_FLDIREA set, should be a directory, but "
                               "is not\n");
                        GOTO(err_out, rc = -EPROTO);
                }
                if (!iop)
                        offset++;
        }
        if (iop)
                offset++;

        /* for ACL, it's possible that FLACL is set but aclsize is zero.
         * only when aclsize != 0 there's an actual segment for ACL in
         * reply buffer.
         */
        if ((md->body->valid & OBD_MD_FLACL) && md->body->aclsize) {
                rc = mdc_unpack_acl(exp, req, md, offset);
                if (rc)
                        GOTO(err_out, rc);
                offset++;
        }
out:
        RETURN(rc);

err_out:
        if (md->lsm)
                obd_free_memmd(exp, &md->lsm);
        goto out;
}

void mdc_free_lustre_md(struct obd_export *exp, struct lustre_md *md)
{
        if (md->lsm)
                obd_free_memmd(exp, &md->lsm);

#ifdef CONFIG_FS_POSIX_ACL
        if (md->posix_acl) {
                posix_acl_release(md->posix_acl);
                md->posix_acl = NULL;
        }
#endif
}

static void mdc_commit_open(struct ptlrpc_request *req)
{
        struct mdc_open_data *mod = req->rq_cb_data;
        if (mod == NULL)
                return;

        if (mod->mod_och != NULL)
                mod->mod_och->och_mod = NULL;

        OBD_FREE_PTR(mod);
        req->rq_cb_data = NULL;
}

static void mdc_replay_open(struct ptlrpc_request *req)
{
        struct mdc_open_data *mod = req->rq_cb_data;
        struct obd_client_handle *och;
        struct ptlrpc_request *close_req;
        struct lustre_handle old;
        struct mds_body *body;
        ENTRY;

        body = lustre_swab_repbuf(req, DLM_REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_mds_body);
        LASSERT (body != NULL);

        if (mod == NULL) {
                DEBUG_REQ(D_ERROR, req,
                          "can't properly replay without open data");
                EXIT;
                return;
        }
        DEBUG_REQ(D_HA, req, "mdc open data found");

        och = mod->mod_och;
        if (och != NULL) {
                struct lustre_handle *file_fh;
                LASSERT(och->och_magic == OBD_CLIENT_HANDLE_MAGIC);
                file_fh = &och->och_fh;
                CDEBUG(D_RPCTRACE, "updating handle from "LPX64" to "LPX64"\n",
                       file_fh->cookie, body->handle.cookie);
                old = *file_fh;
                *file_fh = body->handle;
        }

        close_req = mod->mod_close_req;

        if (close_req != NULL) {
                LASSERT(lustre_msg_get_opc(close_req->rq_reqmsg) == MDS_CLOSE);
                if (mdc_req_is_2_0_server(close_req)) {
                        struct mdt_epoch *epoch = NULL;

                        epoch = lustre_msg_buf(close_req->rq_reqmsg,
                                               REQ_REC_OFF, sizeof(*epoch));
                        LASSERT(epoch);
                        if (och != NULL)
                                LASSERT(!memcmp(&old, &epoch->handle,
                                        sizeof(old)));
                        DEBUG_REQ(D_RPCTRACE, close_req,
                                  "updating close with new fh");
                        epoch->handle = body->handle;
                 } else {
                        struct mds_body *close_body = NULL;

                        close_body = lustre_msg_buf(close_req->rq_reqmsg,
                                                    REQ_REC_OFF,
                                                    sizeof(*close_body));
                        if (och != NULL)
                                LASSERT(!memcmp(&old, &close_body->handle,
                                        sizeof(old)));
                        DEBUG_REQ(D_RPCTRACE, close_req,
                                  "updating close with new fh");
                        close_body->handle = body->handle;
                 }
        }

        EXIT;
}

static void mdc_set_open_replay_data_20(struct obd_client_handle *och,
                                        struct ptlrpc_request *open_req)
{
        struct mdc_open_data  *mod;
        struct obd_import     *imp = open_req->rq_import;
        struct mdt_rec_create *rec = lustre_msg_buf(open_req->rq_reqmsg,
                                                    DLM_INTENT_REC_OFF,
                                                    sizeof(*rec));
        struct mdt_body       *body = lustre_msg_buf(open_req->rq_repmsg,
                                                     DLM_REPLY_REC_OFF,
                                                     sizeof(*body));

        /* If request is not eligible for replay, just bail out */
        if (!open_req->rq_replay)
                return;

        /* incoming message in my byte order (it's been swabbed) */
        LASSERT(rec != NULL);
        LASSERT(lustre_rep_swabbed(open_req, DLM_REPLY_REC_OFF));
        /* outgoing messages always in my byte order */
        LASSERT(body != NULL);

        /* Only if the import is replayable, we set replay_open data */
        if (och && imp->imp_replayable) {
                OBD_ALLOC_PTR(mod);
                if (mod == NULL) {
                        DEBUG_REQ(D_ERROR, open_req,
                                  "can't allocate mdc_open_data");
                        return;
                }

                spin_lock(&open_req->rq_lock);
                och->och_mod = mod;
                mod->mod_och = och;
                mod->mod_open_req = open_req;
                open_req->rq_cb_data = mod;
                open_req->rq_commit_cb = mdc_commit_open;
                spin_unlock(&open_req->rq_lock);
        }

        rec->cr_fid2 = body->fid1;
        rec->cr_ioepoch = body->ioepoch;
        rec->cr_old_handle.cookie = body->handle.cookie;
        open_req->rq_replay_cb = mdc_replay_open;
        if (!fid_is_sane(&body->fid1)) {
                DEBUG_REQ(D_ERROR, open_req, "saving replay request with "
                          "insane fid");
                LBUG();
        }

        DEBUG_REQ(D_RPCTRACE, open_req, "set up replay data");
}

static void mdc_set_open_replay_data_18(struct obd_client_handle *och,
                                        struct ptlrpc_request *open_req)
{
        struct mdc_open_data *mod;
        struct mds_rec_create *rec = lustre_msg_buf(open_req->rq_reqmsg,
                                                    DLM_INTENT_REC_OFF,
                                                    sizeof(*rec));
        struct mds_body *body = lustre_msg_buf(open_req->rq_repmsg,
                                               DLM_REPLY_REC_OFF,
                                               sizeof(*body));

        /* If request is not eligible for replay, just bail out */
        if (!open_req->rq_replay)
                return;

        /* incoming message in my byte order (it's been swabbed) */
        LASSERT(rec != NULL);
        LASSERT(lustre_rep_swabbed(open_req, DLM_REPLY_REC_OFF));
        /* outgoing messages always in my byte order */
        LASSERT(body != NULL);

        if (och) {
                OBD_ALLOC(mod, sizeof(*mod));
                if (mod == NULL) {
                        DEBUG_REQ(D_ERROR, open_req, "can't allocate mdc_open_data");
                        return;
                }

                spin_lock(&open_req->rq_lock);
                och->och_mod = mod;
                mod->mod_och = och;
                mod->mod_open_req = open_req;
                open_req->rq_cb_data = mod;
                open_req->rq_commit_cb = mdc_commit_open;
                spin_unlock(&open_req->rq_lock);
        }

        memcpy(&rec->cr_replayfid, &body->fid1, sizeof rec->cr_replayfid);
        open_req->rq_replay_cb = mdc_replay_open;
        if (body->fid1.id == 0) {
                DEBUG_REQ(D_ERROR, open_req, "saving replay request with "
                          "id = 0 gen = %u", body->fid1.generation);
                LBUG();
        }

        DEBUG_REQ(D_RPCTRACE, open_req, "set up replay data");
}

void mdc_set_open_replay_data(struct obd_client_handle *och,
                              struct ptlrpc_request *open_req)
{
        if (mdc_req_is_2_0_server(open_req))
                mdc_set_open_replay_data_20(och, open_req);
        else
                mdc_set_open_replay_data_18(och, open_req);
}

void mdc_clear_open_replay_data(struct obd_client_handle *och)
{
        struct mdc_open_data *mod = och->och_mod;

        /* Don't free the structure now (it happens in mdc_commit_open, after
         * we're sure we won't need to fix up the close request in the future),
         * but make sure that replay doesn't poke at the och, which is about to
         * be freed. */
        LASSERT(mod != LP_POISON);
        if (mod != NULL)
                mod->mod_och = NULL;
        och->och_mod = NULL;
}

int mdc_close(struct obd_export *exp, struct mdc_op_data *data, struct obdo *oa,
              struct obd_client_handle *och, struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        __u32 reqsize[4] = { sizeof(struct ptlrpc_body),
                             sizeof(struct mdt_body) };
        __u32 repsize[6] = { sizeof(struct ptlrpc_body),
                             sizeof(struct mdt_body),
                             obd->u.cli.cl_max_mds_easize,
                             obd->u.cli.cl_max_mds_cookiesize,
                             sizeof(struct lustre_capa),
                             sizeof(struct lustre_capa) };
        int rc;
        struct ptlrpc_request *req;
        int bufcount = 2;
        ENTRY;

        if (mdc_exp_is_2_0_server(exp)) {
                reqsize[1] = sizeof(struct mdt_epoch);
                reqsize[2] = sizeof(struct mdt_rec_create);
                reqsize[3] = 0; /* capa */
                bufcount = 4;
        }
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_CLOSE, bufcount, reqsize, NULL);
        if (req == NULL)
                GOTO(out, rc = -ENOMEM);
        req->rq_export = class_export_get(exp);

        /* To avoid a livelock (bug 7034), we need to send CLOSE RPCs to a
         * portal whose threads are not taking any DLM locks and are therefore
         * always progressing */
        req->rq_request_portal = MDS_READPAGE_PORTAL;
        ptlrpc_at_set_req_timeout(req);

        /* Ensure that this close's handle is fixed up during replay. */
        LASSERT(och != NULL);
        LASSERT(och->och_magic == OBD_CLIENT_HANDLE_MAGIC);
        if (likely(och->och_mod != NULL)) {
                struct ptlrpc_request *open_req = och->och_mod->mod_open_req;

                if (open_req->rq_type == LI_POISON) {
                        CERROR("LBUG POISONED open %p!\n", open_req);
                        LBUG();
                        ptlrpc_req_finished(req);
                        req = NULL;
                        GOTO(out, rc = -EIO);
                }
                och->och_mod->mod_close_req = req;
                DEBUG_REQ(D_RPCTRACE, req, "close req");
                DEBUG_REQ(D_RPCTRACE, open_req, "clear open replay");

                /* We no longer want to preserve this open for replay even
                 * though the open was committed. b=3632, b=3633 */
                spin_lock(&open_req->rq_lock);
                open_req->rq_replay = 0;
                spin_unlock(&open_req->rq_lock);
        } else {
                CDEBUG(D_RPCTRACE, "couldn't find open req; expecting error\n");
        }

        mdc_close_pack(req, REQ_REC_OFF, data, oa, oa->o_valid, och);

        ptlrpc_req_set_repsize(req, 6, repsize);

        mdc_get_rpc_lock(obd->u.cli.cl_close_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(obd->u.cli.cl_close_lock, NULL);

        if (req->rq_repmsg == NULL) {
                CDEBUG(D_RPCTRACE, "request failed to send: %p, %d\n", req,
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
                }

                if (!lustre_swab_repbuf(req, REPLY_REC_OFF,
                                        sizeof(struct mds_body),
                                        lustre_swab_mds_body)) {
                        CERROR("Error unpacking mds_body\n");
                        rc = -EPROTO;
                }
        }

        EXIT;
        *request = req;
 out:
        if (rc != 0 && och->och_mod)
                 och->och_mod->mod_close_req = NULL;

        return rc;
}

int mdc_done_writing(struct obd_export *exp, struct mdc_op_data *data,
                     struct obdo *obdo)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        __u32 size[2] = { sizeof(struct ptlrpc_body),
                          sizeof(struct mdt_body) };
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_DONE_WRITING, 2, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        req->rq_export = class_export_get(exp);
        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        body->fid1 = data->fid1;
        body->size = obdo->o_size;
        body->blocks = obdo->o_blocks;
        body->flags = obdo->o_flags;
        body->valid = obdo->o_valid;
//        memcpy(&body->handle, &och->och_fh, sizeof(body->handle));

        ptlrpc_req_set_repsize(req, 2, size);

        rc = ptlrpc_queue_wait(req);
        ptlrpc_req_finished(req);
        RETURN(rc);
}

int mdc_readpage(struct obd_export *exp, struct ll_fid *fid, __u64 offset,
                 struct page *page, struct ptlrpc_request **request)
{
        struct obd_import *imp = class_exp2cliimp(exp);
        struct ptlrpc_request *req = NULL;
        struct ptlrpc_bulk_desc *desc = NULL;
        struct mds_body *body;
        __u32 size[2] = { sizeof(struct ptlrpc_body),
                          sizeof(struct mdt_body) };
        int rc;
        ENTRY;

        CDEBUG(D_INODE, "inode: "LPU64"\n", fid->id);

        req = ptlrpc_prep_req(imp, LUSTRE_MDS_VERSION, MDS_READPAGE, 2, size,
                              NULL);
        if (req == NULL)
                GOTO(out, rc = -ENOMEM);

        req->rq_export = class_export_get(exp);
        req->rq_request_portal = MDS_READPAGE_PORTAL;
        ptlrpc_at_set_req_timeout(req);

        desc = ptlrpc_prep_bulk_imp(req, 1, BULK_PUT_SINK, MDS_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);
        /* NB req now owns desc and will free it when it gets freed */

        ptlrpc_prep_bulk_page(desc, page, 0, CFS_PAGE_SIZE);

        mdc_readdir_pack(req, REQ_REC_OFF, offset, CFS_PAGE_SIZE, fid);

        ptlrpc_req_set_repsize(req, 2, size);
        rc = ptlrpc_queue_wait(req);

        if (rc == 0) {
                body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                          lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR("Can't unpack mds_body\n");
                        GOTO(out, rc = -EPROTO);
                }

                if (req->rq_bulk->bd_nob_transferred != CFS_PAGE_SIZE) {
                        CERROR ("Unexpected # bytes transferred: %d"
                                " (%lu expected)\n",
                                req->rq_bulk->bd_nob_transferred,
                                CFS_PAGE_SIZE);
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

        if (!try_module_get(THIS_MODULE)) {
                CERROR("Can't get module. Is it alive?");
                return -EINVAL;
        }
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
                llog_ctxt_put(ctxt);
                GOTO(out, rc);
        }
#ifdef __KERNEL__
        case OBD_IOC_LLOG_INFO:
        case OBD_IOC_LLOG_PRINT: {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                rc = llog_ioctl(ctxt, cmd, data);
                llog_ctxt_put(ctxt);
                GOTO(out, rc);
        }
#endif
        case OBD_IOC_POLL_QUOTACHECK:
                rc = lquota_poll_check(quota_interface, exp,
                                       (struct if_quotacheck *)karg);
                GOTO(out, rc);
        case OBD_IOC_PING_TARGET:
                rc = ptlrpc_obd_ping(obd);
                GOTO(out, rc);
        default:
                CERROR("mdc_ioctl(): unrecognised ioctl %#x\n", cmd);
                GOTO(out, rc = -ENOTTY);
        }
out:
        module_put(THIS_MODULE);
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
                spin_lock(&imp->imp_lock);
                imp->imp_initial_recov = *(int *)val;
                spin_unlock(&imp->imp_lock);

                CDEBUG(D_HA, "%s: set imp_initial_recov = %d\n",
                       exp->exp_obd->obd_name, imp->imp_initial_recov);
                RETURN(0);
        }
        /* Turn off initial_recov after we try all backup servers once */
        if (KEY_IS(KEY_INIT_RECOV_BACKUP)) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);

                spin_lock(&imp->imp_lock);
                imp->imp_initial_recov_bk = *(int *)val;
                if (imp->imp_initial_recov_bk)
                        imp->imp_initial_recov = 1;
                spin_unlock(&imp->imp_lock);

                CDEBUG(D_HA, "%s: set imp_initial_recov_bk = %d\n",
                       exp->exp_obd->obd_name, imp->imp_initial_recov_bk);
                RETURN(0);
        }
        /* Accept the broken "read-only" key for 1.6.6 servers. b=17493 */
        if (KEY_IS(KEY_READONLY) || KEY_IS(KEY_READONLY_166COMPAT)) {
                struct ptlrpc_request *req;
                __u32 size[3] = { sizeof(struct ptlrpc_body), keylen, vallen };
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

                req->rq_export = class_export_get(exp);
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

        RETURN(rc);
}

int mdc_get_info(struct obd_export *exp, __u32 keylen, void *key,
                 __u32 *vallen, void *val, struct lov_stripe_md *lsm)
{
        int rc = -EINVAL;

        if (KEY_IS(KEY_MAX_EASIZE)) {
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
                      __u64 max_age, __u32 flags)
{
        struct ptlrpc_request *req;
        struct obd_statfs *msfs;
        struct obd_import     *imp = NULL;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*msfs) };
        int rc;
        ENTRY;

        /*Since the request might also come from lprocfs, so we need
         *sync this with client_disconnect_export Bug15684*/
        down_read(&obd->u.cli.cl_sem);
        if (obd->u.cli.cl_import)
                imp = class_import_get(obd->u.cli.cl_import);
        up_read(&obd->u.cli.cl_sem);
        if (!imp)
                RETURN(-ENODEV);


        /* We could possibly pass max_age in the request (as an absolute
         * timestamp or a "seconds.usec ago") so the target can avoid doing
         * extra calls into the filesystem if that isn't necessary (e.g.
         * during mount that would help a bit).  Having relative timestamps
         * is not so great if request processing is slow, while absolute
         * timestamps are not ideal because they need time synchronization. */
        req = ptlrpc_prep_req(imp, LUSTRE_MDS_VERSION, MDS_STATFS, 1, NULL,
                              NULL);
        if (!req)
                GOTO(output, rc = -ENOMEM);

        ptlrpc_req_set_repsize(req, 2, size);

        if (flags & OBD_STATFS_NODELAY) {
                /* procfs requests not want stay in wait for avoid deadlock */
                req->rq_no_resend = 1;
                req->rq_no_delay = 1;
        }

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
output:
        class_import_put(imp);
        return rc;
}

static int mdc_pin(struct obd_export *exp, struct ll_fid *fid,
                   struct obd_client_handle *handle, int flag)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        __u32 size[3] = { sizeof(struct ptlrpc_body),
                          sizeof(struct mdt_body), 0 };
        int rc;
        int bufcount = 2;
        ENTRY;

        if (mdc_exp_is_2_0_server(exp))
                bufcount = 3;
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_PIN, bufcount, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        req->rq_export = class_export_get(exp);
        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
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
                                  lustre_swab_mds_body);
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
        struct mds_body *body;
        __u32 size[2] = { sizeof(struct ptlrpc_body),
                          sizeof(struct mdt_body) };
        int rc;
        ENTRY;

        if (handle->och_magic != OBD_CLIENT_HANDLE_MAGIC)
                RETURN(0);

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_CLOSE, 2, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        req->rq_export = class_export_get(exp);
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

int mdc_sync(struct obd_export *exp, struct ll_fid *fid,
             struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        __u32 size[3] = { sizeof(struct ptlrpc_body),
                          sizeof(struct mdt_body), 0 };
        int bufcount = 2;
        int rc;
        ENTRY;


        if (mdc_exp_is_2_0_server(exp))
                bufcount = 3;
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_SYNC, bufcount, size, NULL);
        if (!req)
                RETURN(rc = -ENOMEM);

        req->rq_export = class_export_get(exp);
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
                ptlrpc_import_setasync(imp, -obd->obd_namespace->ns_max_unused);
                break;
        }
        case IMP_EVENT_INACTIVE: {
                struct client_obd *cli = &obd->u.cli;
                /* Flush current sequence to make client obtain new one
                 * from server in case of disconnect/reconnect.
                 * If range is already empty then no need to flush it. */
                if (cli->cl_seq != NULL)
                        seq_client_flush(cli->cl_seq);

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
                ptlrpc_import_setasync(imp, obd->obd_namespace->ns_max_unused);
                break;
        case IMP_EVENT_DEACTIVATE:
        case IMP_EVENT_ACTIVATE:
                break;
        default:
                CERROR("Unknown import event %x\n", event);
                LBUG();
        }
        RETURN(rc);
}

/* determine whether the lock can be canceled before replaying it during
 * recovery, non zero value will be return if the lock can be canceled, 
 * or zero returned for not */
static int mdc_cancel_for_recovery(struct ldlm_lock *lock)
{
        if (lock->l_resource->lr_type != LDLM_IBITS)
                RETURN(0);

	/* FIXME: if we ever get into a situation where there are too many
	 * opened files with open locks on a single node, then we really
	 * should replay these open locks to reget it */
        if (lock->l_policy_data.l_inodebits.bits & MDS_INODELOCK_OPEN)
                RETURN(0);

        RETURN(1);
}

static int mdc_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct client_obd *cli = &obd->u.cli;
        struct lprocfs_static_vars lvars = { 0 };
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

        rc = client_obd_setup(obd, len, buf);
        if (rc)
                GOTO(err_close_lock, rc);
        lprocfs_mdc_init_vars(&lvars);
        if (lprocfs_obd_setup(obd, lvars.obd_vars) == 0)
                ptlrpc_lprocfs_register_obd(obd);

        ns_register_cancel(obd->obd_namespace, mdc_cancel_for_recovery);

        rc = obd_llog_init(obd, obd, NULL);
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
int mdc_init_ea_size(struct obd_export *mdc_exp, struct obd_export *lov_exp)
{
        struct obd_device *obd = mdc_exp->exp_obd;
        struct client_obd *cli = &obd->u.cli;
        struct lov_stripe_md lsm = { .lsm_magic = LOV_MAGIC_V3 };
        struct lov_desc desc;
        __u32 valsize = sizeof(desc);
        __u32 stripes;
        int rc, size;
        ENTRY;

        rc = obd_get_info(lov_exp, sizeof(KEY_LOVDESC), KEY_LOVDESC,
                          &valsize, &desc, NULL);
        if (rc)
                RETURN(rc);

        stripes = min(desc.ld_tgt_count, (__u32)LOV_MAX_STRIPE_COUNT);
        lsm.lsm_stripe_count = stripes;
        size = obd_size_diskmd(lov_exp, &lsm);

        if (cli->cl_max_mds_easize < size)
                cli->cl_max_mds_easize = size;

        lsm.lsm_stripe_count = desc.ld_default_stripe_count;
        size = obd_size_diskmd(lov_exp, &lsm);

        if (cli->cl_default_mds_easize < size)
                cli->cl_default_mds_easize = size;

        size = stripes * sizeof(struct llog_cookie);
        if (cli->cl_max_mds_cookiesize < size)
                cli->cl_max_mds_cookiesize = size;

        CDEBUG(D_HA, "updating max_mdsize/max_cookiesize: %d/%d\n",
               cli->cl_max_mds_easize, cli->cl_max_mds_cookiesize);

        RETURN(0);
}

static int mdc_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        int rc = 0;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_EARLY:
        case OBD_CLEANUP_EXPORTS:
                /* If we set up but never connected, the
                   client import will not have been cleaned. */
                down_write(&obd->u.cli.cl_sem);
                if (obd->u.cli.cl_import) {
                        struct obd_import *imp;
                        imp = obd->u.cli.cl_import;
                        CERROR("client import never connected\n");
                        ptlrpc_invalidate_import(imp);
                        class_destroy_import(imp);
                        obd->u.cli.cl_import = NULL;
                }
                up_write(&obd->u.cli.cl_sem);

                rc = obd_llog_finish(obd, 0);
                if (rc != 0)
                        CERROR("failed to cleanup llogging subsystems\n");
                break;
        case OBD_CLEANUP_SELF_EXP:
                break;
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

        ptlrpc_lprocfs_unregister_obd(obd);
        lprocfs_obd_cleanup(obd);
        ptlrpcd_decref();

        return client_obd_cleanup(obd);
}


static int mdc_llog_init(struct obd_device *obd, struct obd_device *disk_obd,
                         int *index)
{
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        rc = llog_setup(obd, LLOG_CONFIG_REPL_CTXT, disk_obd, 0, NULL,
                        &llog_client_ops);
        if (rc == 0) {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                llog_initiator_connect(ctxt);
                llog_ctxt_put(ctxt);
        }

        rc = llog_setup(obd, LLOG_LOVEA_REPL_CTXT, disk_obd, 0, NULL,
                       &llog_client_ops);
        if (rc == 0) {
                ctxt = llog_get_context(obd, LLOG_LOVEA_REPL_CTXT);
                llog_initiator_connect(ctxt);
                llog_ctxt_put(ctxt);
        } else {
                GOTO(err_cleanup, rc);
        }

        RETURN(rc);
err_cleanup:
        ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
        if (ctxt)
                llog_cleanup(ctxt);
        ctxt = llog_get_context(obd, LLOG_LOVEA_REPL_CTXT);
        if (ctxt)
                llog_cleanup(ctxt);
        return rc;
}

static int mdc_llog_finish(struct obd_device *obd, int count)
{
        struct llog_ctxt *ctxt;
        int rc = 0;
        ENTRY;

        ctxt = llog_get_context(obd, LLOG_LOVEA_REPL_CTXT);
        if (ctxt) {
                rc = llog_cleanup(ctxt);
                if (rc) {
                        CERROR("Can not cleanup LLOG_CONFIG_REPL_CTXT "
                               "rc %d\n", rc);
                }
        }
        ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
        if (ctxt)
                rc = llog_cleanup(ctxt);
        RETURN(rc);
}

static int mdc_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct lprocfs_static_vars lvars = { 0 };
        int rc = 0;

        lprocfs_mdc_init_vars(&lvars);

        rc = class_process_proc_param(PARAM_MDC, lvars.obd_vars, lcfg, obd);
        return(rc);
}

static int mdc_fid_init(struct obd_export *exp)
{
        struct client_obd *cli;
        char              *prefix;
        int                rc;
        ENTRY;

        cli = &exp->exp_obd->u.cli;

        OBD_ALLOC_PTR(cli->cl_seq);
        if (cli->cl_seq == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
        if (prefix == NULL)
                GOTO(out_free_seq, rc = -ENOMEM);

        snprintf(prefix, MAX_OBD_NAME + 5, "srv-%s", exp->exp_obd->obd_name);

        /* Init client side sequence-manager */
        rc = seq_client_init(cli->cl_seq, exp,
                             LUSTRE_SEQ_METADATA,
                             LUSTRE_SEQ_MAX_WIDTH,
                             prefix);
        OBD_FREE(prefix, MAX_OBD_NAME + 5);
        if (rc)
                GOTO(out_free_seq, rc);

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
                LASSERT(cli->cl_seq->lcs_exp == exp);
                seq_client_fini(cli->cl_seq);
                OBD_FREE_PTR(cli->cl_seq);
                cli->cl_seq = NULL;
        }

        RETURN(0);
}

struct obd_ops mdc_obd_ops = {
        .o_owner        = THIS_MODULE,
        .o_setup        = mdc_setup,
        .o_precleanup   = mdc_precleanup,
        .o_cleanup      = mdc_cleanup,
        .o_add_conn     = client_import_add_conn,
        .o_del_conn     = client_import_del_conn,
        .o_connect      = client_connect_import,
        .o_disconnect   = client_disconnect_export,
        .o_fid_init     = mdc_fid_init,
        .o_fid_fini     = mdc_fid_fini,
        .o_iocontrol    = mdc_iocontrol,
        .o_set_info_async = mdc_set_info_async,
        .o_get_info     = mdc_get_info,
        .o_statfs       = mdc_statfs,
        .o_pin          = mdc_pin,
        .o_unpin        = mdc_unpin,
        .o_import_event = mdc_import_event,
        .o_llog_init    = mdc_llog_init,
        .o_llog_finish  = mdc_llog_finish,
        .o_process_config = mdc_process_config,
};

int __init mdc_init(void)
{
        int rc;
        struct lprocfs_static_vars lvars = { 0 };
        lprocfs_mdc_init_vars(&lvars);
        request_module("lquota");
        quota_interface = PORTAL_SYMBOL_GET(mdc_quota_interface);
        init_obd_quota_ops(quota_interface, &mdc_obd_ops);

        rc = class_register_type(&mdc_obd_ops, lvars.module_vars,
                                 LUSTRE_MDC_NAME);
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

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Metadata Client");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mdc_req2lustre_md);
EXPORT_SYMBOL(mdc_free_lustre_md);
EXPORT_SYMBOL(mdc_change_cbdata);
EXPORT_SYMBOL(mdc_find_cbdata);
EXPORT_SYMBOL(mdc_getstatus);
EXPORT_SYMBOL(mdc_getattr);
EXPORT_SYMBOL(mdc_getattr_name);
EXPORT_SYMBOL(mdc_create);
EXPORT_SYMBOL(mdc_unlink);
EXPORT_SYMBOL(mdc_rename);
EXPORT_SYMBOL(mdc_link);
EXPORT_SYMBOL(mdc_readpage);
EXPORT_SYMBOL(mdc_setattr);
EXPORT_SYMBOL(mdc_close);
EXPORT_SYMBOL(mdc_done_writing);
EXPORT_SYMBOL(mdc_sync);
EXPORT_SYMBOL(mdc_set_open_replay_data);
EXPORT_SYMBOL(mdc_clear_open_replay_data);
EXPORT_SYMBOL(mdc_store_inode_generation);
EXPORT_SYMBOL(mdc_init_ea_size);
EXPORT_SYMBOL(mdc_getxattr);
EXPORT_SYMBOL(mdc_setxattr);

module_init(mdc_init);
module_exit(mdc_exit);
#endif
