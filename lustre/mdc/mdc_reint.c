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

#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/obd_class.h>
#include <linux/lustre_mds.h>

/* mdc_setattr does its own semaphore handling */
static int mdc_reint(struct ptlrpc_request *request, int level)
{
        int rc;
        __u32 *opcodeptr = lustre_msg_buf(request->rq_reqmsg, 0);

        request->rq_level = level;

        if (!(*opcodeptr == REINT_SETATTR))
                mdc_get_rpc_lock(&mdc_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(request);
        if (!(*opcodeptr == REINT_SETATTR))
                mdc_put_rpc_lock(&mdc_rpc_lock, NULL);

        if (rc) {
                CDEBUG(D_INFO, "error in handling %d\n", rc);
        } else {
                /* For future resend/replays. */
                *opcodeptr |= REINT_REPLAYING;
        }
        return rc;
}

/* If mdc_setattr is called with an 'iattr', then it is a normal RPC that
 * should take the normal semaphore and go to the normal portal.
 *
 * If it is called with iattr->ia_valid & ATTR_FROM_OPEN, then it is a
 * magic open-path setattr that should take the setattr semaphore and
 * go to the setattr portal. */
int mdc_setattr(struct lustre_handle *conn, struct inode *inode,
                struct iattr *iattr, void *ea, int ealen,
                struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_rec_setattr *rec;
        struct mdc_rpc_lock *rpc_lock;
        int rc, bufcount = 1, size[2] = {sizeof(*rec), ealen};
        ENTRY;

        LASSERT(iattr != NULL);

        if (ealen > 0)
                bufcount = 2;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_REINT, bufcount,
                              size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        if (iattr->ia_valid & ATTR_FROM_OPEN) {
                req->rq_request_portal = MDS_SETATTR_PORTAL; //XXX FIXME bug 249
                rpc_lock = &mdc_setattr_lock;
        } else
                rpc_lock = &mdc_rpc_lock;

        mds_setattr_pack(req, inode, iattr, ea, ealen);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        mdc_get_rpc_lock(rpc_lock, NULL);
        rc = mdc_reint(req, LUSTRE_CONN_FULL);
        mdc_put_rpc_lock(rpc_lock, NULL);

        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int mdc_create(struct lustre_handle *conn, struct inode *dir,
               const char *name, int namelen, const void *data, int datalen,
               int mode, __u32 uid, __u32 gid, __u64 time, __u64 rdev,
               struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        int rc, size[3] = {sizeof(struct mds_rec_create), namelen + 1, 0};
        int level, bufcount = 2;
        ENTRY;

        if (data && datalen) {
                size[bufcount] = datalen;
                bufcount++;
        }

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_REINT, bufcount,
                              size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        /* mds_create_pack fills msg->bufs[1] with name
         * and msg->bufs[2] with tgt, for symlinks or lov MD data */
        mds_create_pack(req, 0, dir, mode, rdev, uid, gid, time,
                        name, namelen, data, datalen);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        level = LUSTRE_CONN_FULL;
 resend:
        rc = mdc_reint(req, level);
        /* Resend if we were told to. */
        if (rc == -ERESTARTSYS) {
                level = LUSTRE_CONN_RECOVD;
                req->rq_flags = 0;
                goto resend;
        }

        if (!rc)
                mdc_store_inode_generation(req, 0, 0);

        *request = req;
        RETURN(rc);
}

int mdc_unlink(struct lustre_handle *conn, struct inode *dir,
               struct inode *child, __u32 mode, const char *name, int namelen,
               struct ptlrpc_request **request)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct ptlrpc_request *req = *request;
        int rc, size[2] = {sizeof(struct mds_rec_unlink), namelen + 1};
        ENTRY;

        LASSERT(req == NULL);

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_REINT, 2, size,
                              NULL);
        if (!req)
                RETURN(-ENOMEM);
        *request = req;

        size[0] = sizeof(struct mds_body);
        size[1] = obddev->u.cli.cl_max_mds_easize;
        req->rq_replen = lustre_msg_size(2, size);

        mds_unlink_pack(req, 0, dir, child, mode, name, namelen);

        rc = mdc_reint(req, LUSTRE_CONN_FULL);
        if (rc == -ERESTARTSYS)
                rc = 0;
        RETURN(rc);
}

int mdc_link(struct lustre_handle *conn,
             struct inode *src, struct inode *dir, const char *name,
             int namelen, struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        int rc, size[2] = {sizeof(struct mds_rec_link), namelen + 1};
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_REINT, 2, size,
                              NULL);
        if (!req)
                RETURN(-ENOMEM);

        mds_link_pack(req, 0, src, dir, name, namelen);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(req, LUSTRE_CONN_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}

int mdc_rename(struct lustre_handle *conn,
               struct inode *src, struct inode *tgt, const char *old,
               int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        int rc, size[3] = {sizeof(struct mds_rec_rename), oldlen + 1,
                           newlen + 1};
        ENTRY;

        req = ptlrpc_prep_req(class_conn2cliimp(conn), MDS_REINT, 3, size,
                              NULL);
        if (!req)
                RETURN(-ENOMEM);

        mds_rename_pack(req, 0, src, tgt, old, oldlen, new, newlen);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(req, LUSTRE_CONN_FULL);
        *request = req;
        if (rc == -ERESTARTSYS)
                rc = 0;

        RETURN(rc);
}
