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
#ifndef AUTOCONF_INCLUDED
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
                     struct mdc_rpc_lock *rpc_lock,
                     int level)
{
        int rc;

        request->rq_send_state = level;

        mdc_get_rpc_lock(rpc_lock, NULL);
        rc = ptlrpc_queue_wait(request);
        mdc_put_rpc_lock(rpc_lock, NULL);
        if (rc)
                CDEBUG(D_INFO, "error in handling %d\n", rc);
        else if (!req_capsule_server_get(&request->rq_pill, &RMF_MDT_BODY)) {
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

static int mdc_prep_elc_req(struct obd_export *exp, struct ptlrpc_request *req,
                            struct list_head *cancels, int count)
{
        return ldlm_prep_elc_req(exp, req, LUSTRE_MDS_VERSION, MDS_REINT,
                                 0, cancels, count);
}

/* If mdc_setattr is called with an 'iattr', then it is a normal RPC that
 * should take the normal semaphore and go to the normal portal.
 *
 * If it is called with iattr->ia_valid & ATTR_FROM_OPEN, then it is a
 * magic open-path setattr that should take the setattr semaphore and
 * go to the setattr portal. */
int mdc_setattr(struct obd_export *exp, struct md_op_data *op_data,
                void *ea, int ealen, void *ea2, int ea2len,
                struct ptlrpc_request **request, struct md_open_data **mod)
{
        CFS_LIST_HEAD(cancels);
        struct ptlrpc_request *req;
        struct mdc_rpc_lock *rpc_lock;
        struct obd_device *obd = exp->exp_obd;
        int count = 0, rc;
        __u64 bits;
        ENTRY;

        LASSERT(op_data != NULL);

        bits = MDS_INODELOCK_UPDATE;
        if (op_data->op_attr.ia_valid & (ATTR_MODE|ATTR_UID|ATTR_GID))
                bits |= MDS_INODELOCK_LOOKUP;
        if ((op_data->op_flags & MF_MDC_CANCEL_FID1) && 
            (fid_is_sane(&op_data->op_fid1)))
                count = mdc_resource_get_unused(exp, &op_data->op_fid1,
                                                &cancels, LCK_EX, bits);
        req = ptlrpc_request_alloc(class_exp2cliimp(exp),
                                   &RQF_MDS_REINT_SETATTR);
        if (req == NULL) {
                ldlm_lock_list_put(&cancels, l_bl_ast, count);
                RETURN(-ENOMEM);
        }
        mdc_set_capa_size(req, &RMF_CAPA1, op_data->op_capa1);
        if ((op_data->op_flags & (MF_SOM_CHANGE | MF_EPOCH_OPEN)) == 0)
                req_capsule_set_size(&req->rq_pill, &RMF_MDT_EPOCH, RCL_CLIENT,
                                     0);
        req_capsule_set_size(&req->rq_pill, &RMF_EADATA, RCL_CLIENT, ealen);
        req_capsule_set_size(&req->rq_pill, &RMF_LOGCOOKIES, RCL_CLIENT,
                             ea2len);

        rc = mdc_prep_elc_req(exp, req, &cancels, count);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        if (op_data->op_attr.ia_valid & ATTR_FROM_OPEN) {
                req->rq_request_portal = MDS_SETATTR_PORTAL;
                ptlrpc_at_set_req_timeout(req);
                rpc_lock = obd->u.cli.cl_setattr_lock;
        } else {
                rpc_lock = obd->u.cli.cl_rpc_lock;
        }

        if (op_data->op_attr.ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime "CFS_TIME_T
		       ", ctime "CFS_TIME_T"\n",
                       LTIME_S(op_data->op_attr.ia_mtime),
                       LTIME_S(op_data->op_attr.ia_ctime));
        mdc_setattr_pack(req, op_data, ea, ealen, ea2, ea2len);

        ptlrpc_request_set_replen(req);
        if (mod && (op_data->op_flags & MF_EPOCH_OPEN) &&
            req->rq_import->imp_replayable)
        {
                LASSERT(*mod == NULL);

                OBD_ALLOC_PTR(*mod);
                if (*mod == NULL) {
                        DEBUG_REQ(D_ERROR, req, "Can't allocate "
                                  "md_open_data");
                } else {
                        CFS_INIT_LIST_HEAD(&(*mod)->mod_replay_list);
                }
        }
        if (mod && *mod) {
                req->rq_cb_data = *mod;
                req->rq_commit_cb = mdc_commit_delayed;
                list_add_tail(&req->rq_mod_list, &(*mod)->mod_replay_list);
                /* This is not the last request in sequence for truncate. */
                if (op_data->op_flags & MF_EPOCH_OPEN)
                        req->rq_replay = 1;
                else
                        req->rq_sequence = 1;
        }

        rc = mdc_reint(req, rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;
        if (rc && req->rq_commit_cb)
                req->rq_commit_cb(req);
        RETURN(rc);
}

int mdc_create(struct obd_export *exp, struct md_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid, __u32 gid,
               __u32 cap_effective, __u64 rdev, struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        int level, rc;
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

        if ((op_data->op_flags & MF_MDC_CANCEL_FID1) && 
            (fid_is_sane(&op_data->op_fid1)))
                count = mdc_resource_get_unused(exp, &op_data->op_fid1,
                                                &cancels, LCK_EX,
                                                MDS_INODELOCK_UPDATE);

        req = ptlrpc_request_alloc(class_exp2cliimp(exp),
                                   &RQF_MDS_REINT_CREATE_RMT_ACL);
        if (req == NULL) {
                ldlm_lock_list_put(&cancels, l_bl_ast, count);
                RETURN(-ENOMEM);
        }
        mdc_set_capa_size(req, &RMF_CAPA1, op_data->op_capa1);
        req_capsule_set_size(&req->rq_pill, &RMF_NAME, RCL_CLIENT,
                             op_data->op_namelen + 1);
        req_capsule_set_size(&req->rq_pill, &RMF_EADATA, RCL_CLIENT,
                             data && datalen ? datalen : 0);

        rc = mdc_prep_elc_req(exp, req, &cancels, count);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        /*
         * mdc_create_pack() fills msg->bufs[1] with name and msg->bufs[2] with
         * tgt, for symlinks or lov MD data.
         */
        mdc_create_pack(req, op_data, data, datalen, mode, uid,
                        gid, cap_effective, rdev);

        ptlrpc_request_set_replen(req);

        level = LUSTRE_IMP_FULL;
 resend:
        rc = mdc_reint(req, exp->exp_obd->u.cli.cl_rpc_lock, level);
        
        /* Resend if we were told to. */
        if (rc == -ERESTARTSYS) {
                level = LUSTRE_IMP_RECOVER;
                goto resend;
        } else if (rc == 0) {
                struct mdt_body *body;
                struct lustre_capa *capa;

                body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
                LASSERT(body);
                if (body->valid & OBD_MD_FLMDSCAPA) {
                        capa = req_capsule_server_get(&req->rq_pill,
                                                      &RMF_CAPA1);
                        if (capa == NULL)
                                rc = -EPROTO;
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
        int count = 0, rc;
        ENTRY;

        LASSERT(req == NULL);

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
        req = ptlrpc_request_alloc(class_exp2cliimp(exp),
                                   &RQF_MDS_REINT_UNLINK);
        if (req == NULL) {
                ldlm_lock_list_put(&cancels, l_bl_ast, count);
                RETURN(-ENOMEM);
        }
        mdc_set_capa_size(req, &RMF_CAPA1, op_data->op_capa1);
        req_capsule_set_size(&req->rq_pill, &RMF_NAME, RCL_CLIENT,
                             op_data->op_namelen + 1);

        rc = mdc_prep_elc_req(exp, req, &cancels, count);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        mdc_unlink_pack(req, op_data);

        req_capsule_set_size(&req->rq_pill, &RMF_MDT_MD, RCL_SERVER,
                             obd->u.cli.cl_max_mds_easize);
        req_capsule_set_size(&req->rq_pill, &RMF_LOGCOOKIES, RCL_SERVER,
                             obd->u.cli.cl_max_mds_cookiesize);
        ptlrpc_request_set_replen(req);

        *request = req;

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
        int count = 0, rc;
        ENTRY;

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

        req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_MDS_REINT_LINK);
        if (req == NULL) {
                ldlm_lock_list_put(&cancels, l_bl_ast, count);
                RETURN(-ENOMEM);
        }
        mdc_set_capa_size(req, &RMF_CAPA1, op_data->op_capa1);
        mdc_set_capa_size(req, &RMF_CAPA2, op_data->op_capa2);
        req_capsule_set_size(&req->rq_pill, &RMF_NAME, RCL_CLIENT,
                             op_data->op_namelen + 1);

        rc = mdc_prep_elc_req(exp, req, &cancels, count);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        mdc_link_pack(req, op_data);
        ptlrpc_request_set_replen(req);

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
        int count = 0, rc;
        ENTRY;

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

        req = ptlrpc_request_alloc(class_exp2cliimp(exp),
                                   &RQF_MDS_REINT_RENAME);
        if (req == NULL) {
                ldlm_lock_list_put(&cancels, l_bl_ast, count);
                RETURN(-ENOMEM);
        }

        mdc_set_capa_size(req, &RMF_CAPA1, op_data->op_capa1);
        mdc_set_capa_size(req, &RMF_CAPA2, op_data->op_capa2);
        req_capsule_set_size(&req->rq_pill, &RMF_NAME, RCL_CLIENT, oldlen + 1);
        req_capsule_set_size(&req->rq_pill, &RMF_SYMTGT, RCL_CLIENT, newlen+1);

        rc = mdc_prep_elc_req(exp, req, &cancels, count);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        if (exp_connect_cancelset(exp) && req)
                ldlm_cli_cancel_list(&cancels, count, req, 0);

        mdc_rename_pack(req, op_data, old, oldlen, new, newlen);

        req_capsule_set_size(&req->rq_pill, &RMF_MDT_MD, RCL_SERVER,
                             obd->u.cli.cl_max_mds_easize);
        req_capsule_set_size(&req->rq_pill, &RMF_LOGCOOKIES, RCL_SERVER,
                             obd->u.cli.cl_max_mds_cookiesize);
        ptlrpc_request_set_replen(req);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}
