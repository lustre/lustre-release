/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
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
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDC

#ifdef __KERNEL__
# include <linux/config.h>
# include <linux/module.h>
# include <linux/kernel.h>
#else
# include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_acl.h>
#include "mdc_internal.h"

/* this function actually sends request to desired target. */
static int mdc_reint(struct ptlrpc_request *request,
                     struct mdc_rpc_lock *rpc_lock,
                     int level)
{
        int rc;

        request->rq_send_state = level;
       
        if (rpc_lock)
                mdc_get_rpc_lock(rpc_lock, NULL);
       
        rc = ptlrpc_queue_wait(request);
        
        if (rpc_lock)
                mdc_put_rpc_lock(rpc_lock, NULL);
        if (rc)
                CDEBUG(D_INFO, "error in handling %d\n", rc);
        else if (!lustre_swab_repbuf(request, 0, sizeof(struct mds_body),
                                     lustre_swab_mds_body)) {
                CERROR ("Can't unpack mds_body\n");
                rc = -EPROTO;
        }
        return rc;
}

/* If mdc_setattr is called with an 'iattr', then it is a normal RPC that should
 * take the normal semaphore and go to the normal portal.
 *
 * If it is called with iattr->ia_valid & ATTR_FROM_OPEN, then it is a magic
 * open-path setattr that should take the setattr semaphore and go to the
 * setattr portal. */
int mdc_setattr(struct obd_export *exp, struct mdc_op_data *data,
                struct iattr *iattr, void *ea, int ealen, void *ea2,
                int ea2len, void *ea3, int ea3len, 
                struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_rec_setattr *rec;
        struct mdc_rpc_lock *rpc_lock;
        struct obd_device *obd = exp->exp_obd;
        int rc, bufcount = 2, size[5] = {0, sizeof(*rec), ealen, ea2len, 
                                         ea3len};
        ENTRY;

        LASSERT(iattr != NULL);

        size[0] = lustre_secdesc_size();
        if (ealen > 0) {
                bufcount++;
                if (ea2len > 0)
                        bufcount++;
                if (ea3len > 0)
                        bufcount++;
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, bufcount, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        lustre_pack_secdesc(req, size[0]);

        if (iattr->ia_valid & ATTR_FROM_OPEN) {
                req->rq_request_portal = MDS_SETATTR_PORTAL; //XXX FIXME bug 249
                rpc_lock = obd->u.cli.cl_setattr_lock;
        } else {
                rpc_lock = obd->u.cli.cl_rpc_lock;
        }

        if (iattr->ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu\n",
                       LTIME_S(iattr->ia_mtime), LTIME_S(iattr->ia_ctime));
        mdc_setattr_pack(req->rq_reqmsg, 1, data, iattr, ea, ealen,
                         ea2, ea2len, ea3, ea3len);

        /* prepare the reply buffer
         */
        bufcount = 1;
        size[0] = sizeof(struct mds_body);

        /* This is a hack for setfacl remotely. XXX */
        if (ealen == sizeof(XATTR_NAME_LUSTRE_ACL) &&
            !strncmp((char *) ea, XATTR_NAME_LUSTRE_ACL, ealen)) {
                size[bufcount++] = LUSTRE_ACL_SIZE_MAX;
        } else if (iattr->ia_valid & ATTR_SIZE) {
                size[bufcount++] = sizeof(struct lustre_capa);
        }

        req->rq_replen = lustre_msg_size(bufcount, size);

        rc = mdc_reint(req, rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int mdc_create(struct obd_export *exp, struct mdc_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid,
               __u32 gid, __u64 rdev, struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *req;
        int rc, size[4] = {0, sizeof(struct mds_rec_create),
                           op_data->namelen + 1};
        int level, bufcount = 3;
        ENTRY;

        size[0] = lustre_secdesc_size();
        if (data && datalen) {
                size[bufcount] = datalen;
                bufcount++;
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, bufcount, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        lustre_pack_secdesc(req, size[0]);

        /*
         * mdc_create_pack() fills msg->bufs[1] with name and msg->bufs[2] with
         * tgt, for symlinks or lov MD data.
         */
        mdc_create_pack(req->rq_reqmsg, 1, op_data, mode, rdev, data, datalen);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        level = LUSTRE_IMP_FULL;
 resend:
        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, level);

        /* resend if we were told to. */
        if (rc == -ERESTARTSYS) {
                level = LUSTRE_IMP_RECOVER;
                goto resend;
        }

        if (!rc)
                mdc_store_inode_generation(exp, req, MDS_REQ_REC_OFF, 0);

        *request = req;
        RETURN(rc);
}

int mdc_unlink(struct obd_export *exp, struct mdc_op_data *data,
               struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct ptlrpc_request *req = *request;
        int rc, size[4] = {0, sizeof(struct mds_rec_unlink),
                           data->namelen + 1,
                           obd->u.cli.cl_max_mds_cookiesize};
        ENTRY;
        LASSERT(req == NULL);

        size[0] = lustre_secdesc_size();

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, 4, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        lustre_pack_secdesc(req, size[0]);
        *request = req;

        size[0] = sizeof(struct mds_body);
        size[1] = obd->u.cli.cl_max_mds_easize;
        size[2] = obd->u.cli.cl_max_mds_cookiesize;

        req->rq_replen = lustre_msg_size(3, size);

        mdc_unlink_pack(req->rq_reqmsg, 1, data);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        if (rc == -ERESTARTSYS)
                rc = 0;
        RETURN(rc);
}

int mdc_link(struct obd_export *exp, struct mdc_op_data *data,
             struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *req;
        int rc, size[3] = {0, sizeof(struct mds_rec_link), data->namelen + 1};
        ENTRY;

        size[0] = lustre_secdesc_size();

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, 3, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        lustre_pack_secdesc(req, size[0]);

        mdc_link_pack(req->rq_reqmsg, 1, data);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int mdc_rename(struct obd_export *exp, struct mdc_op_data *data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *req;
        int rc, size[5] = {0, sizeof(struct mds_rec_rename), oldlen + 1,
                           newlen + 1, obd->u.cli.cl_max_mds_cookiesize};
        ENTRY;

        size[0] = lustre_secdesc_size();

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              MDS_REINT, 5, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        lustre_pack_secdesc(req, size[0]);

        mdc_rename_pack(req->rq_reqmsg, 1, data, old, oldlen, new, newlen);

        size[0] = sizeof(struct mds_body);
        size[1] = obd->u.cli.cl_max_mds_easize;
        size[2] = obd->u.cli.cl_max_mds_cookiesize;
        req->rq_replen = lustre_msg_size(3, size);

        rc = mdc_reint(req, obd->u.cli.cl_rpc_lock, LUSTRE_IMP_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}
