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

static int mdc_reint(struct ptlrpc_client *cl, struct ptlrpc_request *request)
{
        int rc;

        rc = ptlrpc_queue_wait(cl, request);
        rc = ptlrpc_check_status(request, rc);
        if (rc)
                CERROR("error in handling %d\n", rc);

        return rc;
}

int mdc_setattr(struct ptlrpc_client *cl, struct lustre_peer *peer,
                struct inode *inode, struct iattr *iattr,
                struct ptlrpc_request **request)
{
        struct mds_rec_setattr *rec;
        struct ptlrpc_request *req;
        int rc, size = sizeof(*rec);
        ENTRY;

        req = ptlrpc_prep_req(cl, peer, MDS_REINT, 1, &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        rec = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_setattr_pack(rec, inode, iattr);

        size = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, &size);

        rc = mdc_reint(cl, req);
        *request = req;

        RETURN(rc);
}

int mdc_create(struct ptlrpc_client *cl, struct lustre_peer *peer,
               struct inode *dir, const char *name, int namelen,
               const char *tgt, int tgtlen, int mode, __u64 id, __u32 uid,
               __u32 gid, __u64 time, struct ptlrpc_request **request)
{
        struct mds_rec_create *rec;
        struct ptlrpc_request *req;
        int rc, size[3] = {sizeof(*rec), namelen + 1, tgtlen + 1};
        char *tmp;
        ENTRY;

        req = ptlrpc_prep_req(cl, peer, MDS_REINT, 3, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        rec = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_create_pack(rec, dir, mode, id, uid, gid, time);

        tmp = lustre_msg_buf(req->rq_reqmsg, 1);
        LOGL0(name, namelen, tmp);

        if (tgt) {
                tmp = lustre_msg_buf(req->rq_reqmsg, 2);
                LOGL0(tgt, tgtlen, tmp);
        }

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(cl, req);
        *request = req;

        RETURN(rc);
}

int mdc_unlink(struct ptlrpc_client *cl, struct lustre_peer *peer,
               struct inode *dir, struct inode *child, const char *name,
               int namelen, struct ptlrpc_request **request)
{
        struct mds_rec_unlink *rec;
        struct ptlrpc_request *req;
        int rc, size[2] = {sizeof(*rec), namelen + 1};
        char *tmp;
        ENTRY;

        req = ptlrpc_prep_req(cl, peer, MDS_REINT, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        rec = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_unlink_pack(rec, dir, child);

        tmp = lustre_msg_buf(req->rq_reqmsg, 1);
        LOGL0(name, namelen, tmp);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(cl, req);
        *request = req;

        RETURN(rc);
}

int mdc_link(struct ptlrpc_client *cl, struct lustre_peer *peer,
             struct dentry *src, struct inode *dir, const char *name,
             int namelen, struct ptlrpc_request **request)
{
        struct mds_rec_link *rec;
        struct ptlrpc_request *req;
        int rc, size[2] = {sizeof(*rec), namelen + 1};
        char *tmp;
        ENTRY;

        req = ptlrpc_prep_req(cl, peer, MDS_REINT, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        rec = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_link_pack(rec, src->d_inode, dir);

        tmp = lustre_msg_buf(req->rq_reqmsg, 1);
        LOGL0(name, namelen, tmp);

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(cl, req);
        *request = req;

        RETURN(rc);
}

int mdc_rename(struct ptlrpc_client *cl, struct lustre_peer *peer,
               struct inode *src, struct inode *tgt, const char *old,
               int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request)
{
        struct mds_rec_rename *rec;
        struct ptlrpc_request *req;
        int rc, size[3] = {sizeof(*rec), oldlen + 1, newlen + 1};
        char *tmp;
        ENTRY;

        req = ptlrpc_prep_req(cl, peer, MDS_REINT, 3, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        rec = lustre_msg_buf(req->rq_reqmsg, 0);
        mds_rename_pack(rec, src, tgt);

        tmp = lustre_msg_buf(req->rq_reqmsg, 1);
        LOGL0(old, oldlen, tmp);

        if (tgt) {
                tmp = lustre_msg_buf(req->rq_reqmsg, 2);
                LOGL0(new, newlen, tmp);
        }

        size[0] = sizeof(struct mds_body);
        req->rq_replen = lustre_msg_size(1, size);

        rc = mdc_reint(cl, req);
        *request = req;

        RETURN(rc);
}
