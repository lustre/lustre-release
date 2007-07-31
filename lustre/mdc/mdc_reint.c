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
#ifdef HAVE_KERNEL_CONFIG_H
# include <linux/config.h>
#endif
# include <linux/module.h>
# include <linux/kernel.h>
#else
# include <liblustre.h>
#endif

#include <obd_class.h>
#include "mdc_internal.h"
#include <lustre_fid.h>

/* mdc_setattr does its own semaphore handling */
static int mdc_reint(struct ptlrpc_request *request,
                     struct mdc_rpc_lock *rpc_lock, int level)
{
        int rc;

        request->rq_send_state = level;

        mdc_get_rpc_lock(rpc_lock, NULL);
        rc = ptlrpc_queue_wait(request);
        mdc_put_rpc_lock(rpc_lock, NULL);
        if (rc)
                CDEBUG(D_INFO, "error in handling %d\n", rc);
        else if (!lustre_swab_repbuf(request, REPLY_REC_OFF,
                                     sizeof(struct mdt_body),
                                     lustre_swab_mdt_body)) {
                CERROR ("Can't unpack mdt_body\n");
                rc = -EPROTO;
        }
        return rc;
}

/* Find and cancel locally locks matched by inode @bits & @mode in the resource
 * found by @fid. Found locks are added into @cancel list. Returns the amount of
 * locks added to @cancels list. */
int mdc_resource_get_unused(struct obd_export *exp, struct lu_fid *fid,
                            struct list_head *cancels, ldlm_mode_t mode,
                            __u64 bits)
{
        ldlm_policy_data_t policy = {{0}};
        struct ldlm_res_id res_id;
        struct ldlm_resource *res;
        int count;
        ENTRY;

        fid_build_reg_res_name(fid, &res_id);
        res = ldlm_resource_get(exp->exp_obd->obd_namespace,
                                NULL, &res_id, 0, 0);
        if (res == NULL)
                RETURN(0);

        /* Initialize ibits lock policy. */
        policy.l_inodebits.bits = bits;
        count = ldlm_cancel_resource_local(res, cancels, &policy,
                                           mode, 0, 0, NULL);
        ldlm_resource_putref(res);
        RETURN(count);
}

/* If mdc_setattr is called with an 'iattr', then it is a normal RPC that
 * should take the normal semaphore and go to the normal portal.
 *
 * If it is called with iattr->ia_valid & ATTR_FROM_OPEN, then it is a
 * magic open-path setattr that should take the setattr semaphore and
 * go to the setattr portal. */
int mdc_setattr(struct obd_export *exp, struct md_op_data *op_data,
                void *ea, int ealen, void *ea2, int ea2len,
                struct ptlrpc_request **request)
{
        CFS_LIST_HEAD(cancels);
        struct ptlrpc_request *req;
        struct mdt_rec_setattr *rec;
        struct mdc_rpc_lock *rpc_lock;
        struct obd_device *obd = exp->exp_obd;
        int size[7] = { sizeof(struct ptlrpc_body),
                        sizeof(*rec), 0, 0, ealen, ea2len, 0 };
        int count = 0, bufcount = 4, rc;
        __u64 bits;
        ENTRY;

        LASSERT(op_data != NULL);

        size[REQ_REC_OFF + 1] = op_data->op_capa1 ?
                sizeof(struct lustre_capa) : 0;

        if (op_data->op_flags & (MF_SOM_CHANGE | MF_EPOCH_OPEN))
                size[REQ_REC_OFF + 2] = sizeof(struct mdt_epoch);

        if (ealen > 0) {
                bufcount++;
                if (ea2len > 0)
                        bufcount++;
        }

        bits = MDS_INODELOCK_UPDATE;
        if (op_data->op_attr.ia_valid & (ATTR_MODE|ATTR_UID|ATTR_GID))
                bits |= MDS_INODELOCK_LOOKUP;
        if ((op_data->op_flags & MF_MDC_CANCEL_FID1) && 
            (fid_is_sane(&op_data->op_fid1)))
                count = mdc_resource_get_unused(exp, &op_data->op_fid1,
                                                &cancels, LCK_EX, bits);
        if (exp_connect_cancelset(exp) && count) {
                bufcount = 7;
                size[REQ_REC_OFF + 5] = ldlm_request_bufsize(count, MDS_REINT);
        }
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, bufcount, size, NULL);
        if (req)
                ldlm_cli_cancel_list(&cancels, count, req, REQ_REC_OFF + 5, 0);
        else
                ldlm_lock_list_put(&cancels, l_bl_ast, count);

        if (req == NULL)
                RETURN(-ENOMEM);

        if (op_data->op_attr.ia_valid & ATTR_FROM_OPEN) {
                req->rq_request_portal = MDS_SETATTR_PORTAL; //XXX FIXME bug 249
                rpc_lock = obd->u.cli.cl_setattr_lock;
        } else {
                rpc_lock = obd->u.cli.cl_rpc_lock;
        }

        if (op_data->op_attr.ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu\n",
                       LTIME_S(op_data->op_attr.ia_mtime),
                       LTIME_S(op_data->op_attr.ia_ctime));
        mdc_setattr_pack(req, REQ_REC_OFF, op_data, ea, ealen, ea2, ea2len);

        size[REPLY_REC_OFF] = sizeof(struct mdt_body);
        size[REPLY_REC_OFF + 1] = sizeof(struct lustre_capa);
        ptlrpc_req_set_repsize(req, 3, size);

        rc = mdc_reint(req, rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int mdc_create(struct obd_export *exp, struct md_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid, __u32 gid,
               __u32 cap_effective, __u64 rdev, struct ptlrpc_request **request)
{
        int size[6] = { sizeof(struct ptlrpc_body),
                        sizeof(struct mdt_rec_create),
                        0, op_data->op_namelen + 1, 0, 0 };
        struct obd_device *obd = exp->exp_obd;
        int level, bufcount = 4, rc;
        struct ptlrpc_request *req;
        int count = 0;
        CFS_LIST_HEAD(cancels);
        ENTRY;

        /* For case if upper layer did not alloc fid, do it now. */
        if (!fid_is_sane(&op_data->op_fid2)) {
                /*
                 * mdc_fid_alloc() may return errno 1 in case of switch to new
                 * sequence, handle this.
                 */
                rc = mdc_fid_alloc(exp, &op_data->op_fid2, op_data);
                if (rc < 0) {
                        CERROR("Can't alloc new fid, rc %d\n", rc);
                        RETURN(rc);
                }
        }

        size[REQ_REC_OFF + 1] = op_data->op_capa1 ?
                sizeof(struct lustre_capa) : 0;
        
        if (data && datalen) {
                size[bufcount] = datalen;
                bufcount++;
        }

        if ((op_data->op_flags & MF_MDC_CANCEL_FID1) && 
            (fid_is_sane(&op_data->op_fid1)))
                count = mdc_resource_get_unused(exp, &op_data->op_fid1,
                                                &cancels, LCK_EX,
                                                MDS_INODELOCK_UPDATE);
        if (exp_connect_cancelset(exp) && count) {
                bufcount = 6;
                size[REQ_REC_OFF + 4] = ldlm_request_bufsize(count, MDS_REINT);
        }
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, bufcount, size, NULL);
        if (req)
                ldlm_cli_cancel_list(&cancels, count, req, REQ_REC_OFF + 4, 0);
        else
                ldlm_lock_list_put(&cancels, l_bl_ast, count);

        if (req == NULL)
                RETURN(-ENOMEM);

        /*
         * mdc_create_pack() fills msg->bufs[1] with name and msg->bufs[2] with
         * tgt, for symlinks or lov MD data.
         */
        mdc_create_pack(req, REQ_REC_OFF, op_data, data, datalen, mode, uid,
                        gid, cap_effective, rdev);

        size[REPLY_REC_OFF] = sizeof(struct mdt_body);
        size[REPLY_REC_OFF + 1] = sizeof(struct lustre_capa);
        ptlrpc_req_set_repsize(req, 3, size);

        level = LUSTRE_IMP_FULL;
 resend:
        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, level);
        
        /* Resend if we were told to. */
        if (rc == -ERESTARTSYS) {
                level = LUSTRE_IMP_RECOVER;
                goto resend;
        } else if (rc == 0) {
                struct mdt_body *body;
                struct lustre_capa *capa;

                body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*body));
                LASSERT(body);
                if (body->valid & OBD_MD_FLMDSCAPA) {
                        capa = lustre_unpack_capa(req->rq_repmsg,
                                                  REPLY_REC_OFF + 1);
                        if (capa == NULL) {
                                CERROR("Missing/short MDS capability\n");
                                rc = -EPROTO;
                        }
                }
        }

        *request = req;
        RETURN(rc);
}

int mdc_unlink(struct obd_export *exp, struct md_op_data *op_data,
               struct ptlrpc_request **request)
{
        CFS_LIST_HEAD(cancels);
        struct obd_device *obd = class_exp2obd(exp);
        struct ptlrpc_request *req = *request;
        int size[5] = { sizeof(struct ptlrpc_body),
                        sizeof(struct mdt_rec_unlink),
                        0, op_data->op_namelen + 1, 0 };
        int count = 0, rc, bufcount = 4;
        ENTRY;

        LASSERT(req == NULL);

        size[REQ_REC_OFF + 1] = op_data->op_capa1 ?
                sizeof(struct lustre_capa) : 0;

        if ((op_data->op_flags & MF_MDC_CANCEL_FID1) && 
            (fid_is_sane(&op_data->op_fid1)))
                count = mdc_resource_get_unused(exp, &op_data->op_fid1,
                                                &cancels, LCK_EX,
                                                MDS_INODELOCK_UPDATE);
        if ((op_data->op_flags & MF_MDC_CANCEL_FID3) && 
            (fid_is_sane(&op_data->op_fid3)))
                count += mdc_resource_get_unused(exp, &op_data->op_fid3,
                                                 &cancels, LCK_EX,
                                                 MDS_INODELOCK_FULL);
        if (exp_connect_cancelset(exp) && count) {
                bufcount = 5;
                size[REQ_REC_OFF + 3] = ldlm_request_bufsize(count, MDS_REINT);
        }
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, bufcount, size, NULL);
        if (req)
                ldlm_cli_cancel_list(&cancels, count, req, REQ_REC_OFF + 3, 0);
        else
                ldlm_lock_list_put(&cancels, l_bl_ast, count);

        if (req == NULL)
                RETURN(-ENOMEM);
        *request = req;

        size[REPLY_REC_OFF] = sizeof(struct mdt_body);
        size[REPLY_REC_OFF + 1] = obd->u.cli.cl_max_mds_easize;
        size[REPLY_REC_OFF + 2] = obd->u.cli.cl_max_mds_cookiesize;
        ptlrpc_req_set_repsize(req, 4, size);

        mdc_unlink_pack(req, REQ_REC_OFF, op_data);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        if (rc == -ERESTARTSYS)
                rc = 0;
        RETURN(rc);
}

int mdc_link(struct obd_export *exp, struct md_op_data *op_data,
             struct ptlrpc_request **request)
{
        CFS_LIST_HEAD(cancels);
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *req;
        int size[6] = { sizeof(struct ptlrpc_body),
                        sizeof(struct mdt_rec_link),
                        0, 0, op_data->op_namelen + 1, 0 };
        int count = 0, rc, bufcount = 5;
        ENTRY;

        size[REQ_REC_OFF + 1] = op_data->op_capa1 ?
                sizeof(struct lustre_capa) : 0;
        size[REQ_REC_OFF + 2] = op_data->op_capa2 ?
                sizeof(struct lustre_capa) : 0;

        if ((op_data->op_flags & MF_MDC_CANCEL_FID2) &&
            (fid_is_sane(&op_data->op_fid2)))
                count = mdc_resource_get_unused(exp, &op_data->op_fid2,
                                                &cancels, LCK_EX,
                                                MDS_INODELOCK_UPDATE);
        if ((op_data->op_flags & MF_MDC_CANCEL_FID1) &&
            (fid_is_sane(&op_data->op_fid1)))
                count += mdc_resource_get_unused(exp, &op_data->op_fid1,
                                                 &cancels, LCK_EX,
                                                 MDS_INODELOCK_UPDATE);
        if (exp_connect_cancelset(exp) && count) {
                bufcount = 6;
                size[REQ_REC_OFF + 4] = ldlm_request_bufsize(count, MDS_REINT);
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, bufcount, size, NULL);
        if (req)
                ldlm_cli_cancel_list(&cancels, count, req, REQ_REC_OFF + 4, 0);
        else
                ldlm_lock_list_put(&cancels, l_bl_ast, count);

        if (req == NULL)
                RETURN(-ENOMEM);

        mdc_link_pack(req, REQ_REC_OFF, op_data);

        size[REPLY_REC_OFF] = sizeof(struct mdt_body);
        ptlrpc_req_set_repsize(req, 2, size);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int mdc_rename(struct obd_export *exp, struct md_op_data *op_data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request)
{
        CFS_LIST_HEAD(cancels);
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *req;
        int size[7] = { sizeof(struct ptlrpc_body),
                        sizeof(struct mdt_rec_rename),
                        0, 0, oldlen + 1, newlen + 1, 0 };
        int count = 0, rc, bufcount = 6;
        ENTRY;

        size[REQ_REC_OFF + 1] = op_data->op_capa1 ?
                                        sizeof(struct lustre_capa) : 0;
        size[REQ_REC_OFF + 2] = op_data->op_capa2 ?
                                        sizeof(struct lustre_capa) : 0;

        if ((op_data->op_flags & MF_MDC_CANCEL_FID1) &&
            (fid_is_sane(&op_data->op_fid1)))
                count = mdc_resource_get_unused(exp, &op_data->op_fid1,
                                                &cancels, LCK_EX,
                                                MDS_INODELOCK_UPDATE);
        if ((op_data->op_flags & MF_MDC_CANCEL_FID2) &&
            (fid_is_sane(&op_data->op_fid2)))
                count += mdc_resource_get_unused(exp, &op_data->op_fid2,
                                                 &cancels, LCK_EX,
                                                 MDS_INODELOCK_UPDATE);
        if ((op_data->op_flags & MF_MDC_CANCEL_FID3) && 
            (fid_is_sane(&op_data->op_fid3)))
                count += mdc_resource_get_unused(exp, &op_data->op_fid3,
                                                 &cancels, LCK_EX,
                                                 MDS_INODELOCK_LOOKUP);
        if ((op_data->op_flags & MF_MDC_CANCEL_FID4) &&
             (fid_is_sane(&op_data->op_fid4)))
                count += mdc_resource_get_unused(exp, &op_data->op_fid4,
                                                 &cancels, LCK_EX,
                                                 MDS_INODELOCK_FULL);
        if (exp_connect_cancelset(exp) && count) {
                bufcount = 7;
                size[REQ_REC_OFF + 5] = ldlm_request_bufsize(count, MDS_REINT);
        }
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, bufcount, size, NULL);
        if (req)
                ldlm_cli_cancel_list(&cancels, count, req, REQ_REC_OFF + 5, 0);
        else
                ldlm_lock_list_put(&cancels, l_bl_ast, count);

        if (req == NULL)
                RETURN(-ENOMEM);

        mdc_rename_pack(req, REQ_REC_OFF, op_data, old, oldlen, new, newlen);

        size[REPLY_REC_OFF] = sizeof(struct mdt_body);
        size[REPLY_REC_OFF + 1] = obd->u.cli.cl_max_mds_easize;
        size[REPLY_REC_OFF + 2] = obd->u.cli.cl_max_mds_cookiesize;
        ptlrpc_req_set_repsize(req, 4, size);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}
