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
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/module.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/miscdevice.h>

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>

#define REQUEST_MINOR 244

extern int mds_queue_req(struct ptlrpc_request *);


int mdc_getattr(struct ptlrpc_client *cl, ino_t ino, int type, int valid,
                struct ptlrpc_request **req)
{
        int rc;
        struct ptlrpc_request *request;

        ENTRY;

        request = ptlrpc_prep_req(cl, MDS_GETATTR, 0, NULL, 0, NULL);
        if (!request) {
                CERROR("llight request: cannot pack\n");
                GOTO(out, rc = -ENOMEM);
        }

        ll_ino2fid(&request->rq_req.mds->fid1, ino, 0, type);

        request->rq_req.mds->valid = valid;
        request->rq_replen =
                sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

        rc = ptlrpc_queue_wait(cl, request);
        rc = ptlrpc_check_status(request, rc);

        if (!rc)
                CDEBUG(D_NET, "mode: %o\n", request->rq_rep.mds->mode);

        GOTO(out, rc);
 out:
        *req = request;
        return rc;
}

int mdc_open(struct ptlrpc_client *cl, ino_t ino, int type, int flags,
             __u64 *fh, struct ptlrpc_request **req)
{
        struct ptlrpc_request *request;
        int rc;

        request = ptlrpc_prep_req(cl, MDS_OPEN, 0, NULL, 0, NULL);
        if (!request) {
                CERROR("llight request: cannot pack\n");
                rc = -ENOMEM;
                goto out;
        }

        ll_ino2fid(&request->rq_req.mds->fid1, ino, 0, type);
        request->rq_req.mds->flags = HTON__u32(flags);
        request->rq_replen =
                sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

        rc = ptlrpc_queue_wait(cl, request);
        rc = ptlrpc_check_status(request, rc);

        if (rc) {
                CERROR("llight request: error in handling %d\n", rc);
                goto out;
        }

        *fh = request->rq_rep.mds->objid;
 out:
        *req = request;
        return rc;
}


int mdc_close(struct ptlrpc_client *cl, ino_t ino, int type, __u64 fh,
              struct ptlrpc_request **req)
{
        struct ptlrpc_request *request;
        int rc;

        request = ptlrpc_prep_req(cl, MDS_CLOSE, 0, NULL, 0, NULL);
        if (!request) {
                CERROR("llight request: cannot pack\n");
                rc = -ENOMEM;
                goto out;
        }

        ll_ino2fid(&request->rq_req.mds->fid1, ino, 0, type);
        request->rq_req.mds->objid = fh;
        request->rq_replen =
                sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

        rc = ptlrpc_queue_wait(cl, request);
        rc = ptlrpc_check_status(request, rc);

        if (rc) {
                CERROR("llight request: error in handling %d\n", rc);
                goto out;
        }

 out:
        *req = request;
        return rc;
}

int mdc_readpage(struct ptlrpc_client *cl, ino_t ino, int type, __u64 offset,
                 char *addr, struct ptlrpc_request **req)
{
        struct ptlrpc_request *request = NULL;
        struct ptlrpc_bulk_desc *bulk = NULL;
        struct niobuf niobuf;
        int rc;

        niobuf.addr = (__u64) (long) addr;

        CDEBUG(D_INODE, "inode: %ld\n", ino);

        bulk = ptlrpc_prep_bulk(&cl->cli_server);
        if (bulk == NULL) {
                CERROR("%s: cannot init bulk desc\n", __FUNCTION__);
                rc = -ENOMEM;
                goto out;
        }

        request = ptlrpc_prep_req(cl, MDS_READPAGE, 0, NULL,
                                  sizeof(struct niobuf), (char *)&niobuf);
        if (!request) {
                CERROR("%s: cannot pack\n", __FUNCTION__);
                rc = -ENOMEM;
                goto out;
        }

        bulk->b_buflen = PAGE_SIZE;
        bulk->b_buf = (void *)(long)niobuf.addr;
        bulk->b_portal = MDS_BULK_PORTAL;
        bulk->b_xid = request->rq_xid;

        rc = ptlrpc_register_bulk(bulk);
        if (rc) {
                CERROR("%s: couldn't setup bulk sink: error %d.\n",
                       __FUNCTION__, rc);
                goto out;
        }

        request->rq_req.mds->fid1.id = ino;
        request->rq_req.mds->fid1.f_type = type;
        request->rq_req.mds->size = offset;
        request->rq_req.mds->tgtlen = sizeof(niobuf);
        request->rq_replen = sizeof(struct ptlrep_hdr) + sizeof(struct mds_rep);

        rc = ptlrpc_queue_wait(cl, request);
        if (rc) {
                CERROR("mdc request: error in handling %d\n", rc);
                ptlrpc_abort_bulk(bulk);
                goto out;
        }

        CDEBUG(D_INODE, "mode: %o\n", request->rq_rep.mds->mode);

 out:
        *req = request;
        if (bulk != NULL)
                OBD_FREE(bulk, sizeof(*bulk));
        return rc;
}

static int request_ioctl(struct inode *inode, struct file *file,
                         unsigned int cmd, unsigned long arg)
{
        int err;
        struct ptlrpc_client cl;
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

        err = ptlrpc_connect_client(-1, "mds",
                                    MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,
                                    mds_pack_req, mds_unpack_rep, &cl);
        if (err) {
                CERROR("cannot create client\n");
                RETURN(-EINVAL);
        }

        switch (cmd) {
        case IOC_REQUEST_GETATTR: {
                CERROR("-- getting attr for ino %lu\n", arg);
                err = mdc_getattr(&cl, arg, S_IFDIR, ~0, &request);
                CERROR("-- done err %d\n", err);

                GOTO(out, err);
        }

        case IOC_REQUEST_READPAGE: {
                char *buf;
                OBD_ALLOC(buf, PAGE_SIZE);
                if (!buf) {
                        err = -ENOMEM;
                        break;
                }
                CERROR("-- readpage 0 for ino %lu\n", arg);
                err = mdc_readpage(&cl, arg, S_IFDIR, 0, buf, &request);
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

                err = mdc_setattr(&cl, &inode, &iattr, &request);
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

                err = mdc_create(&cl, &inode,
                                 "foofile", strlen("foofile"),
                                 NULL, 0, 0100707, 47114711,
                                 11, 47, 0, &request);
                CERROR("-- done err %d\n", err);

                GOTO(out, err);
        }

        case IOC_REQUEST_OPEN: {
                __u64 fh, ino;
                copy_from_user(&ino, (__u64 *)arg, sizeof(ino));
                CERROR("-- opening ino %llu\n", ino);
                err = mdc_open(&cl, ino, S_IFDIR, O_RDONLY, &fh, &request);
                copy_to_user((__u64 *)arg, &fh, sizeof(fh));
                CERROR("-- done err %d (fh=%Lu)\n", err, fh);

                GOTO(out, err);
        }

        case IOC_REQUEST_CLOSE: {
                CERROR("-- closing ino 2, filehandle %lu\n", arg);
                err = mdc_close(&cl, 2, S_IFDIR, arg, &request);
                CERROR("-- done err %d\n", err);

                GOTO(out, err);
        }

        default:
                RETURN(-EINVAL);
        }

 out:
        ptlrpc_free_req(request);

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

EXPORT_SYMBOL(mdc_create);
EXPORT_SYMBOL(mdc_unlink);
EXPORT_SYMBOL(mdc_rename);
EXPORT_SYMBOL(mdc_link);
EXPORT_SYMBOL(mdc_getattr);
EXPORT_SYMBOL(mdc_readpage);
EXPORT_SYMBOL(mdc_setattr);
EXPORT_SYMBOL(mdc_close);
EXPORT_SYMBOL(mdc_open);

module_init(ptlrpc_request_init);
module_exit(ptlrpc_request_exit);
