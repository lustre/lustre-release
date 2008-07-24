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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
                                     sizeof(struct mds_body),
                                     lustre_swab_mds_body)) {
                CERROR ("Can't unpack mds_body\n");
                rc = -EPROTO;
        }
        return rc;
}

/* Find and cancel locally locks matched by inode @bits & @mode in the resource
 * found by @fid. Found locks are added into @cancel list. Returns the amount of
 * locks added to @cancels list. */
int mdc_resource_get_unused(struct obd_export *exp, struct ll_fid *fid,
                            struct list_head *cancels, ldlm_mode_t mode,
                            __u64 bits)
{
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        struct ldlm_res_id res_id = { .name = {fid->id, fid->generation} };
        struct ldlm_resource *res = ldlm_resource_get(ns, NULL, res_id, 0, 0);
        ldlm_policy_data_t policy = {{0}};
        int count;
        ENTRY;

        if (res == NULL)
                RETURN(0);

        /* Initialize ibits lock policy. */
        policy.l_inodebits.bits = bits;
        count = ldlm_cancel_resource_local(res, cancels, &policy,
                                           mode, 0, 0, NULL);
        ldlm_resource_putref(res);
        RETURN(count);
}

struct ptlrpc_request *mdc_prep_elc_req(struct obd_export *exp,
                                        int bufcount, int *size, int off,
                                        struct list_head *cancels, int count)
{
        return ldlm_prep_elc_req(exp, LUSTRE_MDS_VERSION, MDS_REINT,
                                 bufcount, size, off, 0, cancels, count);
}

/* If mdc_setattr is called with an 'iattr', then it is a normal RPC that
 * should take the normal semaphore and go to the normal portal.
 *
 * If it is called with iattr->ia_valid & ATTR_FROM_OPEN, then it is a
 * magic open-path setattr that should take the setattr semaphore and
 * go to the setattr portal. */
int mdc_setattr(struct obd_export *exp, struct mdc_op_data *op_data,
                struct iattr *iattr, void *ea, int ealen, void *ea2, int ea2len,
                struct ptlrpc_request **request)
{
        CFS_LIST_HEAD(cancels);
        struct ptlrpc_request *req;
        struct mds_rec_setattr *rec;
        struct mdc_rpc_lock *rpc_lock;
        struct obd_device *obd = exp->exp_obd;
        int size[5] = { sizeof(struct ptlrpc_body),
                        sizeof(*rec), ealen, ea2len,
                        sizeof(struct ldlm_request) };
        int count, bufcount = 2, rc;
        __u64 bits;
        ENTRY;

        LASSERT(iattr != NULL);

        if (ealen > 0) {
                bufcount++;
                if (ea2len > 0)
                        bufcount++;
        }

        bits = MDS_INODELOCK_UPDATE;
        if (iattr->ia_valid & (ATTR_MODE|ATTR_UID|ATTR_GID))
                bits |= MDS_INODELOCK_LOOKUP;
        count = mdc_resource_get_unused(exp, &op_data->fid1,
                                        &cancels, LCK_EX, bits);
        if (exp_connect_cancelset(exp))
                bufcount = 5;
        req = mdc_prep_elc_req(exp, bufcount, size,
                               REQ_REC_OFF + 3, &cancels, count);
        if (req == NULL)
                RETURN(-ENOMEM);

        if (iattr->ia_valid & ATTR_FROM_OPEN) {
                req->rq_request_portal = MDS_SETATTR_PORTAL;
                ptlrpc_at_set_req_timeout(req);
                rpc_lock = obd->u.cli.cl_setattr_lock;
        } else {
                rpc_lock = obd->u.cli.cl_rpc_lock;
        }

        if (iattr->ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu\n",
                       LTIME_S(iattr->ia_mtime), LTIME_S(iattr->ia_ctime));
        mdc_setattr_pack(req, REQ_REC_OFF, op_data, iattr,
                         ea, ealen, ea2, ea2len);

        size[REPLY_REC_OFF] = sizeof(struct mds_body);
        ptlrpc_req_set_repsize(req, 2, size);

        rc = mdc_reint(req, rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int mdc_create(struct obd_export *exp, struct mdc_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid, __u32 gid,
               __u32 cap_effective, __u64 rdev, struct ptlrpc_request **request)
{
        CFS_LIST_HEAD(cancels);
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *req;
        int level, bufcount = 3, rc;
        int size[5] = { sizeof(struct ptlrpc_body),
                        sizeof(struct mds_rec_create),
                        op_data->namelen + 1, 0, sizeof(struct ldlm_request) };
        int count;
        ENTRY;

        if (data && datalen) {
                size[bufcount] = datalen;
                bufcount++;
        }

        count = mdc_resource_get_unused(exp, &op_data->fid1, &cancels,
                                        LCK_EX, MDS_INODELOCK_UPDATE);
        if (exp_connect_cancelset(exp))
                bufcount = 5;
        req = mdc_prep_elc_req(exp, bufcount, size,
                               REQ_REC_OFF + 3, &cancels, count);
        if (req == NULL)
                RETURN(-ENOMEM);

        /* mdc_create_pack fills msg->bufs[1] with name
         * and msg->bufs[2] with tgt, for symlinks or lov MD data */
        mdc_create_pack(req, REQ_REC_OFF, op_data, data, datalen, mode, uid,
                        gid, cap_effective, rdev);

        size[REPLY_REC_OFF] = sizeof(struct mds_body);
        ptlrpc_req_set_repsize(req, 2, size);

        level = LUSTRE_IMP_FULL;
 resend:
        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, level);
        /* Resend if we were told to. */
        if (rc == -ERESTARTSYS) {
                level = LUSTRE_IMP_RECOVER;
                goto resend;
        }

        if (!rc)
                mdc_store_inode_generation(req, REQ_REC_OFF, REPLY_REC_OFF);

        *request = req;
        RETURN(rc);
}

int mdc_unlink(struct obd_export *exp, struct mdc_op_data *op_data,
               struct ptlrpc_request **request)
{
        CFS_LIST_HEAD(cancels);
        struct obd_device *obd = class_exp2obd(exp);
        struct ptlrpc_request *req = *request;
        int size[4] = { sizeof(struct ptlrpc_body),
                        sizeof(struct mds_rec_unlink),
                        op_data->namelen + 1, sizeof(struct ldlm_request) };
        int count, rc, bufcount = 3;
        ENTRY;

        LASSERT(req == NULL);
        count = mdc_resource_get_unused(exp, &op_data->fid1, &cancels,
                                        LCK_EX, MDS_INODELOCK_UPDATE);
        if (op_data->fid3.id)
                count += mdc_resource_get_unused(exp, &op_data->fid3, &cancels,
                                                 LCK_EX, MDS_INODELOCK_FULL);
        if (exp_connect_cancelset(exp))
                bufcount = 4;
        req = mdc_prep_elc_req(exp, bufcount, size,
                               REQ_REC_OFF + 2, &cancels, count);
        if (req == NULL)
                RETURN(-ENOMEM);
        *request = req;

        size[REPLY_REC_OFF] = sizeof(struct mds_body);
        size[REPLY_REC_OFF + 1] = obd->u.cli.cl_max_mds_easize;
        size[REPLY_REC_OFF + 2] = obd->u.cli.cl_max_mds_cookiesize;
        ptlrpc_req_set_repsize(req, 4, size);

        mdc_unlink_pack(req, REQ_REC_OFF, op_data);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        if (rc == -ERESTARTSYS)
                rc = 0;
        RETURN(rc);
}

int mdc_link(struct obd_export *exp, struct mdc_op_data *op_data,
             struct ptlrpc_request **request)
{
        CFS_LIST_HEAD(cancels);
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *req;
        int size[4] = { sizeof(struct ptlrpc_body),
                        sizeof(struct mds_rec_link),
                        op_data->namelen + 1, sizeof(struct ldlm_request) };
        int count, rc, bufcount = 3;
        ENTRY;

        count = mdc_resource_get_unused(exp, &op_data->fid1, &cancels,
                                        LCK_EX, MDS_INODELOCK_UPDATE);
        count += mdc_resource_get_unused(exp, &op_data->fid2, &cancels,
                                         LCK_EX, MDS_INODELOCK_UPDATE);
        if (exp_connect_cancelset(exp))
                bufcount = 4;
        req = mdc_prep_elc_req(exp, bufcount, size,
                               REQ_REC_OFF + 2, &cancels, count);
        if (req == NULL)
                RETURN(-ENOMEM);

        mdc_link_pack(req, REQ_REC_OFF, op_data);

        size[REPLY_REC_OFF] = sizeof(struct mds_body);
        ptlrpc_req_set_repsize(req, 2, size);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int mdc_rename(struct obd_export *exp, struct mdc_op_data *op_data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request)
{
        CFS_LIST_HEAD(cancels);
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *req;
        int size[5] = { sizeof(struct ptlrpc_body),
                        sizeof(struct mds_rec_rename),
                        oldlen + 1, newlen + 1, sizeof(struct ldlm_request) };
        int count, rc, bufcount = 4;
        ENTRY;

        count = mdc_resource_get_unused(exp, &op_data->fid1, &cancels,
                                        LCK_EX, MDS_INODELOCK_UPDATE);
        count += mdc_resource_get_unused(exp, &op_data->fid2, &cancels,
                                         LCK_EX, MDS_INODELOCK_UPDATE);
        if (op_data->fid3.id)
                count += mdc_resource_get_unused(exp, &op_data->fid3, &cancels,
                                                 LCK_EX, MDS_INODELOCK_LOOKUP);
        if (op_data->fid4.id)
                count += mdc_resource_get_unused(exp, &op_data->fid4, &cancels,
                                                 LCK_EX, MDS_INODELOCK_FULL);
        if (exp_connect_cancelset(exp))
                bufcount = 5;
        req = mdc_prep_elc_req(exp, bufcount, size,
                               REQ_REC_OFF + 3, &cancels, count);
        if (req == NULL)
                RETURN(-ENOMEM);

        mdc_rename_pack(req, REQ_REC_OFF, op_data, old, oldlen, new, newlen);

        size[REPLY_REC_OFF] = sizeof(struct mds_body);
        size[REPLY_REC_OFF + 1] = obd->u.cli.cl_max_mds_easize;
        size[REPLY_REC_OFF + 2] = obd->u.cli.cl_max_mds_cookiesize;
        ptlrpc_req_set_repsize(req, 4, size);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}
