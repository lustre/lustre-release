/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
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
 *
 */

#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/obd_class.h>
#include <linux/lustre_mds.h>

static int mdc_reint(struct ptlrpc_request *request, int level)
{
        int rc;
        request->rq_level = level;

        rc = ptlrpc_queue_wait(request);
        rc = ptlrpc_check_status(request, rc);

        if (rc)
                CERROR("error in handling %d\n", rc);

        return rc;
}

int mdc_setattr(struct lustre_handle *conn,
                struct inode *inode, struct iattr *iattr,
                struct ptlrpc_request **request)
{
        struct mdc_obd *mdc = mdc_conn2mdc(conn);
        struct mds_rec_setattr *rec;
        struct ptlrpc_request *req;
        int rc, size = sizeof(*rec);
        ENTRY;

        req = ptlrpc_prep_req2(mdc->mdc_client, mdc->mdc_conn, &mdc->mdc_connh,
                              MDS_REINT, 1, &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        mds_setattr_pack(req, 0, inode, iattr, NULL, 0);

        size = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, &size);

        rc = mdc_reint(req, LUSTRE_CONN_FULL);
        *request = req;
        if (rc == -ERESTARTSYS )
                rc = 0;

        RETURN(rc);
}

int mdc_create(struct lustre_handle *conn,
               struct inode *dir, const char *name, int namelen,
               const char *tgt, int tgtlen, int mode, __u32 uid,
               __u32 gid, __u64 time, __u64 rdev, struct obdo *obdo,
               struct ptlrpc_request **request)
{
        struct mds_rec_create *rec;
        struct mdc_obd *mdc = mdc_conn2mdc(conn);
        struct ptlrpc_request *req;
        int rc, size[3] = {sizeof(struct mds_rec_create), namelen + 1, 0};
        char *tmp, *bufs[3] = {NULL, NULL, NULL};
        int level, bufcount = 2;
        ENTRY;

        if (S_ISREG(mode)) {
                size[2] = sizeof(*obdo);
                bufs[2] = (char *)obdo;
                bufcount = 3;
        } else if (S_ISLNK(mode)) {
                size[2] = tgtlen + 1;
                bufcount = 3;
        }

        req = ptlrpc_prep_req2(mdc->mdc_client, mdc->mdc_conn, &mdc->mdc_connh,
                              MDS_REINT,
                              bufcount, size, bufs);
        if (!req)
                RETURN(-ENOMEM);

        rec = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_create_pack(req, 0, dir, mode, rdev, uid, gid, time,
                        name, namelen, NULL, 0);

        if (S_ISREG(mode)) {
                tmp = lustre_msg_buf(req->rq_reqmsg, 2);
                memcpy(tmp, obdo, sizeof(*obdo));
        } else if (S_ISLNK(mode)) {
                tmp = lustre_msg_buf(req->rq_reqmsg, 2);
                LOGL0(tgt, tgtlen, tmp);
        }

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        level = LUSTRE_CONN_FULL;
 resend:
        rc = mdc_reint(req, level);
        if (rc == -ERESTARTSYS) {
                struct mds_update_record_hdr *hdr =
                        lustre_msg_buf(req->rq_reqmsg, 0);
                level = LUSTRE_CONN_RECOVD;
                CERROR("Lost reply: re-create rep.\n");
                req->rq_flags = 0;
                hdr->ur_opcode = NTOH__u32(REINT_RECREATE);
                goto resend;
        }

        *request = req;
        RETURN(rc);
}

int mdc_unlink(struct lustre_handle *conn,
               struct inode *dir, struct inode *child, const char *name,
               int namelen, struct ptlrpc_request **request)
{
        struct mdc_obd *mdc = mdc_conn2mdc(conn);
        struct ptlrpc_request *req;
        int rc, size[2] = {sizeof(struct mds_rec_unlink), namelen + 1};
        ENTRY;

        req = ptlrpc_prep_req2(mdc->mdc_client, mdc->mdc_conn, &mdc->mdc_connh,
                              MDS_REINT, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        mds_unlink_pack(req, 0, dir, child, name, namelen);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(req, LUSTRE_CONN_FULL);
        *request = req;
        if (rc == -ERESTARTSYS )
                rc = 0;

        RETURN(rc);
}

int mdc_link(struct lustre_handle *conn,
             struct dentry *src, struct inode *dir, const char *name,
             int namelen, struct ptlrpc_request **request)
{
        struct mdc_obd *mdc = mdc_conn2mdc(conn);
        struct ptlrpc_request *req;
        int rc, size[2] = {sizeof(struct mds_rec_link), namelen + 1};
        ENTRY;

        req = ptlrpc_prep_req2(mdc->mdc_client, mdc->mdc_conn, &mdc->mdc_connh,
                              MDS_REINT, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        mds_link_pack(req, 0, src->d_inode, dir, name, namelen);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(req, LUSTRE_CONN_FULL);
        *request = req;
        if (rc == -ERESTARTSYS )
                rc = 0;

        RETURN(rc);
}

int mdc_rename(struct lustre_handle *conn,
               struct inode *src, struct inode *tgt, const char *old,
               int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request)
{
        struct mdc_obd *mdc = mdc_conn2mdc(conn);
        struct ptlrpc_request *req;
        int rc, size[3] = {sizeof(struct mds_rec_rename), oldlen + 1,
                           newlen + 1};
        ENTRY;

        req = ptlrpc_prep_req2(mdc->mdc_client, mdc->mdc_conn, &mdc->mdc_connh, 
                              MDS_REINT, 3, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        mds_rename_pack(req, 0, src, tgt, old, oldlen, new, newlen);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(req, LUSTRE_CONN_FULL);
        *request = req;
        if (rc == -ERESTARTSYS )
                rc = 0;

        RETURN(rc);
}
