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

#include <linux/module.h>
#include <linux/miscdevice.h>

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>

#define REQUEST_MINOR 244

extern int mds_queue_req(struct ptlrpc_request *);

int mdc_connect(struct ptlrpc_client *cl, struct ptlrpc_connection *conn,
                struct ll_fid *rootfid, __u64 *last_committed, __u64 *last_rcvd,
                __u32 *last_xid, struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        req = ptlrpc_prep_req(cl, conn, MDS_CONNECT, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        req->rq_level = LUSTRE_CONN_CON;
        req->rq_replen = lustre_msg_size(1, &size);

        mds_pack_req_body(req);
        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

        if (!rc) {
                mds_unpack_rep_body(req);
                body = lustre_msg_buf(req->rq_repmsg, 0);
                memcpy(rootfid, &body->fid1, sizeof(*rootfid));
                *last_committed = req->rq_repmsg->last_committed;
                *last_rcvd = req->rq_repmsg->last_rcvd;
                *last_xid = body->last_xid;

                CDEBUG(D_NET, "root ino=%ld, last_committed=%Lu, last_rcvd=%Lu,"
                       " last_xid=%d\n",
                       (unsigned long)rootfid->id,
                       (unsigned long long)*last_committed,
                       (unsigned long long)*last_rcvd,
                       body->last_xid);
        }

        EXIT;
 out:
        ptlrpc_free_req(req); 
        return rc;
}


int mdc_getattr(struct ptlrpc_client *cl, struct ptlrpc_connection *conn,
                ino_t ino, int type, unsigned long valid,
                struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        req = ptlrpc_prep_req(cl, conn, MDS_GETATTR, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ll_ino2fid(&body->fid1, ino, 0, type);
        body->valid = valid;

        req->rq_replen = lustre_msg_size(1, &size);
        req->rq_level = LUSTRE_CONN_FULL;

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

        if (!rc) {
                mds_unpack_rep_body(req);
                body = lustre_msg_buf(req->rq_repmsg, 0);
                CDEBUG(D_NET, "mode: %o\n", body->mode);
        }

        EXIT;
 out:
        *request = req;
        return rc;
}

int mdc_open(struct ptlrpc_client *cl, struct ptlrpc_connection *conn,
             ino_t ino, int type, int flags, __u64 cookie, __u64 *fh,
             struct ptlrpc_request **request)
{
        struct mds_body *body;
        int rc, size = sizeof(*body);
        struct ptlrpc_request *req;

        req = ptlrpc_prep_req(cl, conn, MDS_OPEN, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        req->rq_flags |= PTL_RPC_FL_REPLAY;
        req->rq_level = LUSTRE_CONN_FULL;
        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ll_ino2fid(&body->fid1, ino, 0, type);
        body->flags = HTON__u32(flags);
        body->objid = cookie; 

        req->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

        if (!rc) {
                mds_unpack_rep_body(req);
                body = lustre_msg_buf(req->rq_repmsg, 0);
                *fh = body->objid;
        }

        EXIT;
 out:
        *request = req;
        return rc;
}

int mdc_close(struct ptlrpc_client *cl, struct ptlrpc_connection *conn,
              ino_t ino, int type, __u64 fh, struct ptlrpc_request **request)
{
        struct mds_body *body;
        int rc, size = sizeof(*body);
        struct ptlrpc_request *req;

        req = ptlrpc_prep_req(cl, conn, MDS_CLOSE, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        ll_ino2fid(&body->fid1, ino, 0, type);
        body->objid = fh;

        req->rq_level = LUSTRE_CONN_FULL;
        req->rq_replen = lustre_msg_size(0, NULL);

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

        EXIT;
 out:
        *request = req;
        return rc;
}

int mdc_readpage(struct ptlrpc_client *cl, struct ptlrpc_connection *conn,
                 ino_t ino, int type, __u64 offset, char *addr,
                 struct ptlrpc_request **request)
{
        struct ptlrpc_request *req = NULL;
        struct ptlrpc_bulk_desc *bulk = NULL;
        struct niobuf niobuf;
        struct mds_body *body;
        int rc, size[2] = {sizeof(*body), sizeof(struct niobuf)};
        char *bufs[2] = {NULL, (char *)&niobuf};

        niobuf.addr = (__u64) (long) addr;

        CDEBUG(D_INODE, "inode: %ld\n", (long)ino);

        bulk = ptlrpc_prep_bulk(conn);
        if (bulk == NULL) {
                CERROR("%s: cannot init bulk desc\n", __FUNCTION__);
                rc = -ENOMEM;
                goto out;
        }

        req = ptlrpc_prep_req(cl, conn, MDS_READPAGE, 2, size, bufs);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        bulk->b_buflen = PAGE_SIZE;
        bulk->b_buf = (void *)(long)niobuf.addr;
        bulk->b_portal = MDS_BULK_PORTAL;
        bulk->b_xid = req->rq_reqmsg->xid;

        rc = ptlrpc_register_bulk(bulk);
        if (rc) {
                CERROR("couldn't setup bulk sink: error %d.\n", rc);
                GOTO(out, rc);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        body->fid1.id = ino;
        body->fid1.f_type = type;
        body->size = offset;

        req->rq_replen = lustre_msg_size(1, size);
        req->rq_level = LUSTRE_CONN_FULL;
        rc = ptlrpc_queue_wait(req);
        if (rc) {
                CERROR("error in handling %d\n", rc);
                ptlrpc_abort_bulk(bulk);
                GOTO(out, rc);
        }

        mds_unpack_rep_body(req);
        EXIT;

 out:
        *request = req;
        ptlrpc_free_bulk(bulk);
        return rc;
}

static int request_ioctl(struct inode *inode, struct file *file,
                         unsigned int cmd, unsigned long arg)
{
        int err = 0;
        struct ptlrpc_client cl;
        struct ptlrpc_connection *conn;
        struct ptlrpc_request *request;

        ENTRY;

        if (MINOR(inode->i_rdev) != REQUEST_MINOR)
                RETURN(-EINVAL);

        if (_IOC_TYPE(cmd) != IOC_REQUEST_TYPE ||
            _IOC_NR(cmd) < IOC_REQUEST_MIN_NR  ||
            _IOC_NR(cmd) > IOC_REQUEST_MAX_NR ) {
                CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
                       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
                RETURN(-EINVAL);
        }

        ptlrpc_init_client(NULL, NULL, 
                           MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL, &cl);
        conn = ptlrpc_uuid_to_connection("mds");
        if (!conn) {
                CERROR("cannot create client\n");
                RETURN(-EINVAL);
        }

        switch (cmd) {
        case IOC_REQUEST_GETATTR: {
                CERROR("-- getting attr for ino %lu\n", arg);
                err = mdc_getattr(&cl, conn, arg, S_IFDIR, ~0, &request);
                CERROR("-- done err %d\n", err);

                GOTO(out, err);
        }

        case IOC_REQUEST_READPAGE: {
                char *buf;
                OBD_ALLOC(buf, PAGE_SIZE);
                if (!buf) {
                        err = -ENOMEM;
                        GOTO(out, err);
                }
                CERROR("-- readpage 0 for ino %lu\n", arg);
                err = mdc_readpage(&cl, conn, arg, S_IFDIR, 0, buf, &request);
                CERROR("-- done err %d\n", err);
                OBD_FREE(buf, PAGE_SIZE);

                GOTO(out, err);
        }

        case IOC_REQUEST_SETATTR: {
                struct inode inode;
                struct iattr iattr;

                inode.i_ino = arg;
                inode.i_generation = 0;
                iattr.ia_mode = 040777;
                iattr.ia_atime = 0;
                iattr.ia_valid = ATTR_MODE | ATTR_ATIME;

                err = mdc_setattr(&cl, conn, &inode, &iattr, &request);
                CERROR("-- done err %d\n", err);

                GOTO(out, err);
        }

        case IOC_REQUEST_CREATE: {
                struct inode inode;
                struct iattr iattr;

                inode.i_ino = arg;
                inode.i_generation = 0;
                iattr.ia_mode = 040777;
                iattr.ia_atime = 0;
                iattr.ia_valid = ATTR_MODE | ATTR_ATIME;

                err = mdc_create(&cl, conn, &inode,
                                 "foofile", strlen("foofile"),
                                 NULL, 0, 0100707, 47114711,
                                 11, 47, 0, &request);
                CERROR("-- done err %d\n", err);

                GOTO(out, err);
        }

        case IOC_REQUEST_OPEN: {
                __u64 fh, ino;
                copy_from_user(&ino, (__u64 *)arg, sizeof(ino));
                CERROR("-- opening ino %llu\n", (unsigned long long)ino);
                err = mdc_open(&cl, conn, ino, S_IFDIR, O_RDONLY, 4711, &fh, 
                               &request);
                copy_to_user((__u64 *)arg, &fh, sizeof(fh));
                CERROR("-- done err %d (fh=%Lu)\n", err,
                       (unsigned long long)fh);

                GOTO(out, err);
        }

        case IOC_REQUEST_CLOSE: {
                CERROR("-- closing ino 2, filehandle %lu\n", arg);
                err = mdc_close(&cl, conn, 2, S_IFDIR, arg, &request);
                CERROR("-- done err %d\n", err);

                GOTO(out, err);
        }

        default:
                GOTO(out, err = -EINVAL);
        }

 out:
        ptlrpc_free_req(request);
        ptlrpc_put_connection(conn);
        ptlrpc_cleanup_client(&cl);

        RETURN(err);
}


static struct file_operations requestdev_fops = {
        ioctl: request_ioctl,
};

static struct miscdevice request_dev = {
        REQUEST_MINOR,
        "request",
        &requestdev_fops
};

static int __init ptlrpc_request_init(void)
{
        misc_register(&request_dev);
        return 0;
}

static void __exit ptlrpc_request_exit(void)
{
        misc_deregister(&request_dev);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre MDS Request Tester v1.0");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mdc_connect);
EXPORT_SYMBOL(mdc_getattr);
EXPORT_SYMBOL(mdc_create);
EXPORT_SYMBOL(mdc_unlink);
EXPORT_SYMBOL(mdc_rename);
EXPORT_SYMBOL(mdc_link);
EXPORT_SYMBOL(mdc_readpage);
EXPORT_SYMBOL(mdc_setattr);
EXPORT_SYMBOL(mdc_close);
EXPORT_SYMBOL(mdc_open);

module_init(ptlrpc_request_init);
module_exit(ptlrpc_request_exit);
